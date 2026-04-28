/**
 * Event-bus emission tests for `agenticScan`.
 *
 * `agenticScan()` has multiple exit paths (MCP fast-path, cost-ceiling partial
 * report, normal success return, catch re-throw). Each must emit exactly one
 * `scan_completed` event so the cloud worker-controller and dashboard tracer
 * can transition the scan to a terminal state.
 *
 * These tests also verify that a single `agenticScan` invocation does NOT
 * double-emit, and that it does NOT collide with `scanner.ts::scan()` — the
 * two are independent entry points, not nested, so the top-level emit lives
 * in both places.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { agenticScan } from "./agentic-scanner.js";
import { eventBus, type EventType } from "./events/bus.js";
import { LlmApiRuntime } from "./runtime/llm-api.js";
import type { ScanConfig } from "@pwnkit/shared";
import type { NativeRuntimeResult } from "./runtime/types.js";

/** Make a fresh tmp DB path for each test run so scans don't collide. */
function tmpDbPath(): string {
  return path.join(
    os.tmpdir(),
    `pwnkit-agentic-events-${Date.now()}-${Math.random().toString(36).slice(2)}.db`,
  );
}

function baseConfig(overrides: Partial<ScanConfig> = {}): ScanConfig {
  return {
    target: "https://target.example.invalid",
    depth: "quick",
    format: "json",
    runtime: "api",
    ...overrides,
  } as ScanConfig;
}

describe("agenticScan: scan_completed emission", () => {
  let dbPath: string;
  const events: Array<{ type: EventType; payload: Record<string, unknown> }> = [];
  let unsubscribe: (() => void) | null = null;

  beforeEach(() => {
    eventBus.clear();
    events.length = 0;
    unsubscribe = eventBus.subscribe({
      emit: (type, payload) => {
        events.push({ type, payload });
      },
    });
    dbPath = tmpDbPath();
  });

  afterEach(() => {
    if (unsubscribe) unsubscribe();
    eventBus.clear();
    try { fs.unlinkSync(dbPath); } catch { /* ignore */ }
  });

  it("emits a single `scan_completed{exit_reason:\"failed\"}` when the scan throws on the early codex-incompatibility path", async () => {
    // `runtime: "codex"` with useNative=false hits the first `throw new Error`
    // inside the top-level try block, which is caught by the agenticScan catch
    // and re-thrown. The catch MUST fire `scan_completed("failed")` before
    // rethrowing so the cloud relay gets a terminal event.
    const config = baseConfig({ runtime: "codex" });

    await expect(agenticScan({ config, dbPath })).rejects.toThrow(/Codex CLI is not compatible/);

    const completedEvents = events.filter((e) => e.type === "scan_completed");
    expect(completedEvents).toHaveLength(1);
    expect(completedEvents[0]!.payload.exit_reason).toBe("failed");
    expect(typeof completedEvents[0]!.payload.findings_count).toBe("number");
    expect(typeof completedEvents[0]!.payload.duration_ms).toBe("number");
  });

  it("guards against double-emit — the latch fires the event exactly once even across catch + finally", async () => {
    // Drive the same failing path; if the catch branch AND the finally
    // safety-net both emitted, we'd see two events. The `emittedScanCompleted`
    // flag must prevent that.
    const config = baseConfig({ runtime: "codex" });
    await expect(agenticScan({ config, dbPath })).rejects.toThrow();

    expect(events.filter((e) => e.type === "scan_completed")).toHaveLength(1);
  });
});

describe("agenticScan: planner LLM error mid-scan", () => {
  // Reproducer for the bug behind cloud scan
  // 3abdf5b7-873d-449b-ab3f-e9a38f05a778: when the planner LLM returns a
  // 5xx mid-scan, the native loop bails with `state.summary = "Error: ..."`
  // and breaks out of the while-loop on the SAME path as a normal
  // completion. Pre-fix, the scanner emitted `scan_completed` with
  // `exit_reason: "completed"` and the raw error string in `summary`,
  // so cloud users saw "complete · Clean" with the API error in the card
  // description. The fix surfaces a structured `errorExit` on the loop
  // state, propagates it through `AgentOutput`, and flips the exit_reason
  // to "failed" before emitting.
  let dbPath: string;
  const events: Array<{ type: EventType; payload: Record<string, unknown> }> = [];
  let unsubscribe: (() => void) | null = null;
  // Stash every provider env var so the test runs the same way regardless
  // of what the developer has exported in their shell.
  const ENV_KEYS_TO_STASH = [
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "OPENAI_API_KEY",
  ] as const;
  const stashedEnv: Partial<Record<(typeof ENV_KEYS_TO_STASH)[number], string | undefined>> = {};
  let originalSkipBanner: string | undefined;

  beforeEach(() => {
    eventBus.clear();
    events.length = 0;
    unsubscribe = eventBus.subscribe({
      emit: (type, payload) => {
        events.push({ type, payload });
      },
    });
    dbPath = tmpDbPath();
    // The native API runtime needs *some* key configured for diagnostics
    // to come back valid (otherwise `useNative=false` and the loop never
    // runs). The mock below intercepts every API call before any HTTP
    // happens, so the key value itself is never read. We force the
    // anthropic provider by clearing higher-priority keys first.
    for (const k of ENV_KEYS_TO_STASH) {
      stashedEnv[k] = process.env[k];
      delete process.env[k];
    }
    process.env.ANTHROPIC_API_KEY = "sk-ant-fake-test-key-not-real";
    originalSkipBanner = process.env.PWNKIT_SKIP_PROVIDER_BANNER;
    process.env.PWNKIT_SKIP_PROVIDER_BANNER = "1";
  });

  afterEach(() => {
    if (unsubscribe) unsubscribe();
    eventBus.clear();
    try { fs.unlinkSync(dbPath); } catch { /* ignore */ }
    for (const k of ENV_KEYS_TO_STASH) {
      const v = stashedEnv[k];
      if (v === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = v;
      }
    }
    if (originalSkipBanner === undefined) {
      delete process.env.PWNKIT_SKIP_PROVIDER_BANNER;
    } else {
      process.env.PWNKIT_SKIP_PROVIDER_BANNER = originalSkipBanner;
    }
    vi.restoreAllMocks();
  });

  it("emits scan_completed{exit_reason:\"failed\"} when the planner returns an error result", async () => {
    // Mock `executeNative` to return the same shape the runtime produces
    // when Azure OpenAI returns a 5xx — a `NativeRuntimeResult` with
    // `error` set and no usable content. This is the exact wire shape
    // the native loop's error branch (native-loop.ts ~line 422) keys on.
    const errorMessage =
      'Azure OpenAI API error 500: {"error":{"code":"InternalServerError","message":"transient upstream failure"}}';
    const mockResult: NativeRuntimeResult = {
      content: [],
      stopReason: "error",
      error: errorMessage,
      usage: { inputTokens: 0, outputTokens: 0 },
      durationMs: 0,
    };
    vi.spyOn(LlmApiRuntime.prototype, "executeNative").mockResolvedValue(mockResult);

    // `mode: "probe"` skips `normalizeScanConfig`'s outbound HTML probe
    // (the test target doesn't resolve), and keeps the scan on the
    // discovery → attack → report path that exercises the fix.
    const config = baseConfig({ mode: "probe" });

    // The scan should drain cleanly (no throw) — the loop already
    // handles the error internally; we only care that the bus event
    // surfaces "failed" rather than "completed".
    await agenticScan({ config, dbPath });

    const completedEvents = events.filter((e) => e.type === "scan_completed");
    expect(completedEvents).toHaveLength(1);
    expect(completedEvents[0]!.payload.exit_reason).toBe("failed");
    // The summary should carry the planner error string verbatim so the
    // cloud relay can surface it as the failure reason.
    expect(completedEvents[0]!.payload.summary).toBe(errorMessage);
  });
});
