import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { ScanEvent } from "../scanner.js";
import {
  eventBus,
  cloudEventSink,
  scanListenerSink,
  maybeSubscribeCloudEventSink,
  isCloudEventSinkActive,
  _resetCloudSinkSubscriptionForTests,
  type EventSink,
  type EventType,
} from "./bus.js";
import { runNativeAgentLoop, summarizeReasoning } from "../agent/native-loop.js";
import { runAgentLoop } from "../agent/loop.js";
import type {
  NativeRuntime,
  NativeRuntimeResult,
  Runtime,
  RuntimeResult,
} from "../runtime/types.js";

describe("EventBus", () => {
  beforeEach(() => {
    eventBus.clear();
  });

  afterEach(() => {
    eventBus.clear();
    _resetCloudSinkSubscriptionForTests();
  });

  it("fans out one event to every subscribed sink", () => {
    const a = vi.fn();
    const b = vi.fn();
    eventBus.subscribe({ emit: a });
    eventBus.subscribe({ emit: b });
    eventBus.emit("step_started", { step: "recon", n: 1 });
    expect(a).toHaveBeenCalledTimes(1);
    expect(a).toHaveBeenCalledWith("step_started", { step: "recon", n: 1 });
    expect(b).toHaveBeenCalledTimes(1);
  });

  it("swallows exceptions thrown by a sink so one bad sink can't kill the scan", () => {
    const bad: EventSink = {
      emit: () => {
        throw new Error("boom");
      },
    };
    const good = vi.fn();
    eventBus.subscribe(bad);
    eventBus.subscribe({ emit: good });

    // Silence the diagnostic stderr write
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    expect(() =>
      eventBus.emit("step_started", { step: "attack" }),
    ).not.toThrow();

    // The good sink still sees the event even though the bad one threw.
    expect(good).toHaveBeenCalledWith("step_started", { step: "attack" });
    expect(stderrSpy).toHaveBeenCalled();
  });

  it("unsubscribe() stops delivery to that sink", () => {
    const sink = vi.fn();
    const unsubscribe = eventBus.subscribe({ emit: sink });
    eventBus.emit("step_started", { step: "a" });
    unsubscribe();
    eventBus.emit("step_started", { step: "b" });
    expect(sink).toHaveBeenCalledTimes(1);
  });

  it("clear() removes every subscriber", () => {
    eventBus.subscribe({ emit: vi.fn() });
    eventBus.subscribe({ emit: vi.fn() });
    expect(eventBus.size).toBe(2);
    eventBus.clear();
    expect(eventBus.size).toBe(0);
  });
});

describe("scanListenerSink", () => {
  it("maps step_started → stage:start with the step as stage", () => {
    const listener = vi.fn();
    const sink = scanListenerSink(listener);
    sink.emit("step_started", { step: "discovery", n: 1 });
    expect(listener).toHaveBeenCalledTimes(1);
    const event = listener.mock.calls[0][0] as ScanEvent;
    expect(event.type).toBe("stage:start");
    expect(event.stage).toBe("discovery");
  });

  it("maps step_completed → stage:end", () => {
    const listener = vi.fn();
    const sink = scanListenerSink(listener);
    sink.emit("step_completed", { step: "discovery", duration_ms: 123 });
    expect(listener.mock.calls[0][0].type).toBe("stage:end");
    expect(listener.mock.calls[0][0].stage).toBe("discovery");
  });

  it("maps finding_ingested → finding with severity prefix in message", () => {
    const listener = vi.fn();
    const sink = scanListenerSink(listener);
    sink.emit("finding_ingested", {
      finding_id: "f-1",
      severity: "high",
      title: "RCE in /admin",
    });
    const event = listener.mock.calls[0][0] as ScanEvent;
    expect(event.type).toBe("finding");
    expect(event.message).toContain("HIGH");
    expect(event.message).toContain("RCE in /admin");
  });

  it("maps cost_update → usage", () => {
    const listener = vi.fn();
    const sink = scanListenerSink(listener);
    sink.emit("cost_update", {
      cost_usd: 0.05,
      input_tokens: 100,
      output_tokens: 50,
    });
    expect(listener.mock.calls[0][0].type).toBe("usage");
  });

  it("drops events with no legacy equivalent (agent_turn_*, tool_call_*, …)", () => {
    const listener = vi.fn();
    const sink = scanListenerSink(listener);
    sink.emit("agent_turn_started", { turn: 1, max_turns: 10 });
    sink.emit("agent_turn_completed", { turn: 1, duration_ms: 200, reason: "continue" });
    sink.emit("tool_call_started", { tool: "curl", turn: 1, args_preview: "curl /" });
    sink.emit("tool_call_completed", { tool: "curl", turn: 1, duration_ms: 50, status: "ok" });
    sink.emit("llm_planner_invoked", { turn: 1 });
    sink.emit("reasoning_summary", { turn: 1, summary: "looking for auth bypass" });
    sink.emit("scan_completed", { exit_reason: "completed" });
    expect(listener).not.toHaveBeenCalled();
  });
});

describe("cloudEventSink", () => {
  it("emits PWNKIT_EVENT_<TYPE_UPPER> lines to stdout with JSON payload", () => {
    const writeSpy = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);

    cloudEventSink.emit("step_started", { step: "recon", n: 1 });
    cloudEventSink.emit("tool_call_completed", {
      tool: "curl",
      turn: 3,
      duration_ms: 420,
      status: "ok",
    });

    expect(writeSpy).toHaveBeenCalledTimes(2);
    const firstLine = writeSpy.mock.calls[0][0] as string;
    const secondLine = writeSpy.mock.calls[1][0] as string;

    expect(firstLine.startsWith("PWNKIT_EVENT_STEP_STARTED ")).toBe(true);
    expect(firstLine.endsWith("\n")).toBe(true);
    const firstPayload = JSON.parse(
      firstLine.slice("PWNKIT_EVENT_STEP_STARTED ".length).trim(),
    );
    expect(firstPayload).toEqual({ step: "recon", n: 1 });

    expect(secondLine.startsWith("PWNKIT_EVENT_TOOL_CALL_COMPLETED ")).toBe(
      true,
    );
    const secondPayload = JSON.parse(
      secondLine.slice("PWNKIT_EVENT_TOOL_CALL_COMPLETED ".length).trim(),
    );
    expect(secondPayload).toEqual({
      tool: "curl",
      turn: 3,
      duration_ms: 420,
      status: "ok",
    });

    writeSpy.mockRestore();
  });

  it("emits a degraded line when the payload is unserializable", () => {
    const writeSpy = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);

    const circular: Record<string, unknown> = { n: 1 };
    circular.self = circular;

    cloudEventSink.emit(
      "cost_update",
      circular as unknown as Record<string, unknown>,
    );

    expect(writeSpy).toHaveBeenCalledTimes(1);
    const line = writeSpy.mock.calls[0][0] as string;
    expect(line.startsWith("PWNKIT_EVENT_COST_UPDATE ")).toBe(true);
    expect(line).toContain("_unserializable");

    writeSpy.mockRestore();
  });
});

describe("maybeSubscribeCloudEventSink", () => {
  const savedEnv = process.env.PWNKIT_CLOUD_EVENTS;

  beforeEach(() => {
    eventBus.clear();
    _resetCloudSinkSubscriptionForTests();
    delete process.env.PWNKIT_CLOUD_EVENTS;
  });

  afterEach(() => {
    eventBus.clear();
    _resetCloudSinkSubscriptionForTests();
    if (savedEnv === undefined) delete process.env.PWNKIT_CLOUD_EVENTS;
    else process.env.PWNKIT_CLOUD_EVENTS = savedEnv;
  });

  it("does NOT subscribe by default (env var unset)", () => {
    maybeSubscribeCloudEventSink();
    expect(eventBus.size).toBe(0);
  });

  it("does NOT subscribe when env var is '0'", () => {
    process.env.PWNKIT_CLOUD_EVENTS = "0";
    maybeSubscribeCloudEventSink();
    expect(eventBus.size).toBe(0);
  });

  it("subscribes when PWNKIT_CLOUD_EVENTS=1", () => {
    process.env.PWNKIT_CLOUD_EVENTS = "1";
    maybeSubscribeCloudEventSink();
    expect(eventBus.size).toBe(1);
  });

  it("is idempotent — multiple calls subscribe only once", () => {
    process.env.PWNKIT_CLOUD_EVENTS = "1";
    maybeSubscribeCloudEventSink();
    maybeSubscribeCloudEventSink();
    maybeSubscribeCloudEventSink();
    expect(eventBus.size).toBe(1);
  });

  it("end-to-end: env var set → emit → PWNKIT_EVENT_ line on stdout", () => {
    process.env.PWNKIT_CLOUD_EVENTS = "1";
    maybeSubscribeCloudEventSink();
    const writeSpy = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);

    eventBus.emit("agent_turn_started", {
      turn: 2,
      max_turns: 10,
      role: "attack",
    });

    expect(writeSpy).toHaveBeenCalledTimes(1);
    const line = writeSpy.mock.calls[0][0] as string;
    expect(line.startsWith("PWNKIT_EVENT_AGENT_TURN_STARTED ")).toBe(true);
    const payload = JSON.parse(
      line.slice("PWNKIT_EVENT_AGENT_TURN_STARTED ".length).trim(),
    );
    expect(payload).toEqual({ turn: 2, max_turns: 10, role: "attack" });

    writeSpy.mockRestore();
  });
});

// ── Integration: agent-loop emits the expected event sequence ───────────────
//
// Runs a minimal one-turn agent loop against a mocked runtime that calls the
// `done` tool, subscribing a spy sink to the bus and asserting we see a
// complete agent_turn_started → llm_planner_invoked → tool_call_{started,
// completed} → agent_turn_completed sequence.

function createMockRuntime(responses: NativeRuntimeResult[]): NativeRuntime {
  let idx = 0;
  return {
    type: "api" as const,
    async executeNative() {
      const r = responses[idx] ?? responses[responses.length - 1];
      idx++;
      return r;
    },
    async isAvailable() {
      return true;
    },
  };
}

describe("agent loop bus instrumentation", () => {
  beforeEach(() => {
    eventBus.clear();
  });

  afterEach(() => {
    eventBus.clear();
  });

  it("emits agent_turn_started, llm_planner_invoked, tool_call_*, agent_turn_completed in order", async () => {
    const events: Array<{ type: EventType; payload: Record<string, unknown> }> = [];
    eventBus.subscribe({
      emit: (type, payload) => {
        events.push({ type, payload });
      },
    });

    const runtime = createMockRuntime([
      {
        content: [
          {
            type: "tool_use",
            id: "tc1",
            name: "done",
            input: { summary: "mocked complete" },
          },
        ],
        stopReason: "tool_use",
        usage: { inputTokens: 42, outputTokens: 7 },
        durationMs: 50,
      },
    ]);

    await runNativeAgentLoop({
      config: {
        role: "discovery",
        systemPrompt: "test",
        tools: [],
        maxTurns: 3,
        target: "https://example.com",
        scanId: "test-scan",
      },
      runtime,
      db: null,
    });

    const types = events.map((e) => e.type);
    expect(types).toContain("agent_turn_started");
    expect(types).toContain("llm_planner_invoked");
    expect(types).toContain("tool_call_started");
    expect(types).toContain("tool_call_completed");
    expect(types).toContain("cost_update");
    expect(types).toContain("agent_turn_completed");

    const turnStart = events.find((e) => e.type === "agent_turn_started")!;
    expect(turnStart.payload).toEqual({
      turn: 1,
      max_turns: 3,
      role: "discovery",
    });

    const toolStart = events.find((e) => e.type === "tool_call_started")!;
    expect(toolStart.payload.tool).toBe("done");
    expect(toolStart.payload.turn).toBe(1);

    const toolDone = events.find((e) => e.type === "tool_call_completed")!;
    expect(toolDone.payload.tool).toBe("done");
    expect(toolDone.payload.status).toBe("ok");
    expect(typeof toolDone.payload.duration_ms).toBe("number");

    // Turn completed must come AFTER both tool_call events
    const turnCompleteIdx = events.findIndex(
      (e) => e.type === "agent_turn_completed",
    );
    const toolCompleteIdx = events.findIndex(
      (e) => e.type === "tool_call_completed",
    );
    expect(turnCompleteIdx).toBeGreaterThan(toolCompleteIdx);

    const turnComplete = events[turnCompleteIdx]!;
    expect(turnComplete.payload.reason).toBe("finished");
    expect(turnComplete.payload.turn).toBe(1);
  });
});

// ── Reasoning-summary heuristic: unit tests ──

describe("summarizeReasoning (heuristic)", () => {
  it("returns empty string for empty / nullish inputs", () => {
    expect(summarizeReasoning("")).toBe("");
    expect(summarizeReasoning("   ")).toBe("");
    expect(summarizeReasoning(undefined)).toBe("");
    expect(summarizeReasoning(null)).toBe("");
  });

  it("prefers the first sentence after a `Thought:` prefix", () => {
    const s = summarizeReasoning(
      "Thought: I should probe /admin for auth bypass. Then I will try IDOR.",
    );
    expect(s).toBe("I should probe /admin for auth bypass.");
  });

  it("recognizes `Reasoning:` and `Plan:` prefixes too, case-insensitive", () => {
    expect(
      summarizeReasoning("reasoning: Check for SSRF on /redirect. It's suspicious."),
    ).toBe("Check for SSRF on /redirect.");
    expect(
      summarizeReasoning("PLAN: Map the surface first. Then attack."),
    ).toBe("Map the surface first.");
  });

  it("falls back to the first sentence when no prefix matches", () => {
    expect(
      summarizeReasoning(
        "I notice the target leaks a stack trace. I will enumerate endpoints.",
      ),
    ).toBe("I notice the target leaks a stack trace.");
  });

  it("collapses internal whitespace / newlines into single spaces", () => {
    expect(
      summarizeReasoning(
        "Thought: inspect\n the\t   response   headers carefully.",
      ),
    ).toBe("inspect the response headers carefully.");
  });

  it("truncates summaries longer than ~140 chars with an ellipsis", () => {
    const long =
      "Thought: " + "very long reasoning ".repeat(20) + "end.";
    const out = summarizeReasoning(long);
    expect(out.length).toBeLessThanOrEqual(140);
    expect(out.endsWith("…")).toBe(true);
  });
});

// ── reasoning_summary: integration via runNativeAgentLoop ──

/** Mock runtime that invokes `onThinking` once before returning the result. */
function createMockRuntimeWithThinking(
  responses: NativeRuntimeResult[],
  thinkingTexts: Array<string | undefined>,
): NativeRuntime {
  let idx = 0;
  return {
    type: "api" as const,
    async executeNative(_system, _messages, _tools, callbacks) {
      const thinking = thinkingTexts[idx];
      if (thinking && callbacks?.onThinking) {
        callbacks.onThinking(thinking);
      }
      const r = responses[idx] ?? responses[responses.length - 1];
      idx++;
      return r;
    },
    async isAvailable() {
      return true;
    },
  };
}

describe("reasoning_summary bus event", () => {
  beforeEach(() => {
    eventBus.clear();
  });
  afterEach(() => {
    eventBus.clear();
  });

  it("fires exactly once per turn with a non-empty summary", async () => {
    const events: Array<{ type: EventType; payload: Record<string, unknown> }> = [];
    eventBus.subscribe({
      emit: (type, payload) => {
        events.push({ type, payload });
      },
    });

    const runtime = createMockRuntimeWithThinking(
      [
        {
          content: [
            {
              type: "tool_use",
              id: "tc1",
              name: "done",
              input: { summary: "done" },
            },
          ],
          stopReason: "tool_use",
          usage: { inputTokens: 10, outputTokens: 5 },
          durationMs: 10,
        },
      ],
      [
        "Thought: Probing /admin for broken auth. Then IDOR.",
      ],
    );

    await runNativeAgentLoop({
      config: {
        role: "attack",
        systemPrompt: "test",
        tools: [],
        maxTurns: 2,
        target: "https://example.com",
        scanId: "rs-test",
      },
      runtime,
      db: null,
    });

    const reasoningEvents = events.filter((e) => e.type === "reasoning_summary");
    expect(reasoningEvents).toHaveLength(1);
    expect(reasoningEvents[0]!.payload.turn).toBe(1);
    expect(reasoningEvents[0]!.payload.summary).toBe(
      "Probing /admin for broken auth.",
    );
  });

  it("does NOT fire when the thinking text is empty", async () => {
    const events: Array<{ type: EventType }> = [];
    eventBus.subscribe({
      emit: (type) => {
        events.push({ type });
      },
    });

    const runtime = createMockRuntimeWithThinking(
      [
        {
          content: [
            {
              type: "tool_use",
              id: "tc1",
              name: "done",
              input: { summary: "done" },
            },
          ],
          stopReason: "tool_use",
          usage: { inputTokens: 1, outputTokens: 1 },
          durationMs: 10,
        },
      ],
      [undefined], // no thinking stream
    );

    await runNativeAgentLoop({
      config: {
        role: "attack",
        systemPrompt: "test",
        tools: [],
        maxTurns: 2,
        target: "https://example.com",
        scanId: "rs-none",
      },
      runtime,
      db: null,
    });

    expect(events.filter((e) => e.type === "reasoning_summary")).toHaveLength(0);
  });
});

// ── Legacy runAgentLoop bus instrumentation ──

function createMockLegacyRuntime(responses: RuntimeResult[]): Runtime {
  let idx = 0;
  return {
    type: "api" as const,
    async execute() {
      const r = responses[idx] ?? responses[responses.length - 1];
      idx++;
      return r;
    },
    async isAvailable() {
      return true;
    },
  };
}

describe("runAgentLoop (legacy) bus instrumentation", () => {
  beforeEach(() => {
    eventBus.clear();
  });
  afterEach(() => {
    eventBus.clear();
  });

  it("emits agent_turn_started → llm_planner_invoked → tool_call_{started,completed} → cost_update → agent_turn_completed", async () => {
    const events: Array<{ type: EventType; payload: Record<string, unknown> }> = [];
    eventBus.subscribe({
      emit: (type, payload) => {
        events.push({ type, payload });
      },
    });

    // Assistant text that calls `done` via the legacy TOOL_CALL format.
    const runtime = createMockLegacyRuntime([
      {
        output: 'TOOL_CALL: done {"summary": "mock-done"}',
        exitCode: 0,
        timedOut: false,
        durationMs: 20,
        usage: { inputTokens: 30, outputTokens: 4 },
      },
    ]);

    await runAgentLoop({
      config: {
        role: "discovery",
        systemPrompt: "test",
        tools: [],
        maxTurns: 3,
        target: "https://example.test",
        scanId: "legacy-bus",
      },
      runtime,
      db: null,
    });

    const types = events.map((e) => e.type);
    expect(types).toContain("agent_turn_started");
    expect(types).toContain("llm_planner_invoked");
    expect(types).toContain("tool_call_started");
    expect(types).toContain("tool_call_completed");
    expect(types).toContain("cost_update");
    expect(types).toContain("agent_turn_completed");

    const turnStart = events.find((e) => e.type === "agent_turn_started")!;
    expect(turnStart.payload).toEqual({
      turn: 1,
      max_turns: 3,
      role: "discovery",
    });

    const toolStart = events.find((e) => e.type === "tool_call_started")!;
    expect(toolStart.payload.tool).toBe("done");
    expect(toolStart.payload.turn).toBe(1);

    const toolDone = events.find((e) => e.type === "tool_call_completed")!;
    expect(toolDone.payload.tool).toBe("done");
    expect(toolDone.payload.status).toBe("ok");
    expect(typeof toolDone.payload.duration_ms).toBe("number");

    const costUpdate = events.find((e) => e.type === "cost_update")!;
    expect(costUpdate.payload.input_tokens).toBe(30);
    expect(costUpdate.payload.output_tokens).toBe(4);

    const turnCompleteIdx = events.findIndex((e) => e.type === "agent_turn_completed");
    const toolCompleteIdx = events.findIndex((e) => e.type === "tool_call_completed");
    expect(turnCompleteIdx).toBeGreaterThan(toolCompleteIdx);

    const turnComplete = events[turnCompleteIdx]!;
    expect(turnComplete.payload.reason).toBe("finished");
  });

  it("emits finding_ingested when save_finding succeeds (legacy loop)", async () => {
    const events: Array<{ type: EventType; payload: Record<string, unknown> }> = [];
    eventBus.subscribe({
      emit: (type, payload) => {
        events.push({ type, payload });
      },
    });

    // One call with save_finding + done. The legacy executor requires
    // title/severity/category for save_finding; after that we call done so the
    // loop exits on turn 1.
    const output = [
      'TOOL_CALL: save_finding {"title":"XSS in /search","severity":"high","category":"xss","evidence_request":"GET /search?q=<x>","evidence_response":"<x> echoed"}',
      'TOOL_CALL: done {"summary":"one finding"}',
    ].join("\n");

    const runtime = createMockLegacyRuntime([
      {
        output,
        exitCode: 0,
        timedOut: false,
        durationMs: 15,
      },
    ]);

    await runAgentLoop({
      config: {
        role: "attack",
        systemPrompt: "test",
        tools: [],
        maxTurns: 2,
        target: "https://example.test",
        scanId: "legacy-finding",
      },
      runtime,
      db: null,
    });

    const findingEvents = events.filter((e) => e.type === "finding_ingested");
    expect(findingEvents).toHaveLength(1);
    expect(findingEvents[0]!.payload.title).toBe("XSS in /search");
    expect(findingEvents[0]!.payload.severity).toBe("high");
    expect(findingEvents[0]!.payload.category).toBe("xss");
  });
});

// ── delta event (NEW: token-level streaming for cloud Live Trace) ─────────

describe("delta bus event", () => {
  beforeEach(() => {
    eventBus.clear();
    _resetCloudSinkSubscriptionForTests();
  });

  afterEach(() => {
    eventBus.clear();
    _resetCloudSinkSubscriptionForTests();
  });

  it("fan-out delivers delta events with the documented payload shape", () => {
    const sink = vi.fn();
    eventBus.subscribe({ emit: sink });

    eventBus.emit("delta", {
      turn: 3,
      role: "attack",
      scope: "assistant_response",
      text: "Hel",
      seq: 0,
    });
    eventBus.emit("delta", {
      turn: 3,
      role: "attack",
      scope: "assistant_response",
      text: "lo",
      seq: 1,
    });

    expect(sink).toHaveBeenCalledTimes(2);
    expect(sink).toHaveBeenNthCalledWith(1, "delta", {
      turn: 3,
      role: "attack",
      scope: "assistant_response",
      text: "Hel",
      seq: 0,
    });
    expect(sink).toHaveBeenNthCalledWith(2, "delta", {
      turn: 3,
      role: "attack",
      scope: "assistant_response",
      text: "lo",
      seq: 1,
    });
  });

  it("cloudEventSink emits PWNKIT_EVENT_DELTA lines for delta events", () => {
    const writeSpy = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);

    cloudEventSink.emit("delta", {
      turn: 5,
      role: "recon",
      scope: "reasoning",
      text: " thinking…",
      seq: 17,
    });

    expect(writeSpy).toHaveBeenCalledTimes(1);
    const line = writeSpy.mock.calls[0][0] as string;
    expect(line.startsWith("PWNKIT_EVENT_DELTA ")).toBe(true);
    expect(line.endsWith("\n")).toBe(true);
    const payload = JSON.parse(line.slice("PWNKIT_EVENT_DELTA ".length).trim());
    expect(payload).toEqual({
      turn: 5,
      role: "recon",
      scope: "reasoning",
      text: " thinking…",
      seq: 17,
    });

    writeSpy.mockRestore();
  });

  it("isCloudEventSinkActive flips true once the cloud sink subscribes", () => {
    expect(isCloudEventSinkActive()).toBe(false);

    process.env.PWNKIT_CLOUD_EVENTS = "1";
    try {
      maybeSubscribeCloudEventSink();
      expect(isCloudEventSinkActive()).toBe(true);
    } finally {
      delete process.env.PWNKIT_CLOUD_EVENTS;
    }
  });
});
