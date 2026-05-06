import type {
  ScanConfig,
  ScanReport,
  Finding,
  LayerVerdict,
  LayerVerdictKind,
  PocStep,
  Severity,
  TriageLayerName,
} from "@pwnkit/shared";
import { loadTemplates } from "@pwnkit/templates";
import { createRuntime } from "./runtime/index.js";
import { LlmApiRuntime } from "./runtime/llm-api.js";
import type { ApiRuntimeDiagnostics } from "./runtime/llm-api.js";
import { detectAvailableRuntimes } from "./runtime/registry.js";
// DB lazy-loaded to avoid native module issues
import { runAgentLoop } from "./agent/loop.js";
import { runNativeAgentLoop } from "./agent/native-loop.js";
import { toolCallPreview } from "./agent/tool-preview.js";
import { getToolsForRole, TOOL_DEFINITIONS, parsePocStepsArg } from "./agent/tools.js";
import {
  discoveryPrompt,
  attackPrompt,
  verifyPrompt,
  reportPrompt,
  webPentestDiscoveryPrompt,
  webPentestAttackPrompt,
  shellPentestPrompt,
} from "./agent/prompts.js";
import { features } from "./agent/features.js";
import type { ScanEvent, ScanListener } from "./scanner.js";
import type { NativeRuntime, NativeMessage, NativeContentBlock } from "./runtime/types.js";
import { isMcpTarget } from "./http.js";
import { discoverMcpTarget, runMcpSecurityChecks } from "./mcp.js";
import { createScanContext, finalize } from "./context.js";
import { generateRemediation } from "./remediation.js";
import { parseApiSpec } from "./api-spec.js";
import { raceWithDefaults } from "./racing.js";
import type { RaceResult } from "./racing.js";
import { runEGATSWithDefaults } from "./agent/egats.js";
import {
  isHoldingItWrong,
  extractFeatures,
  FEATURE_NAMES,
  verifyOracleByCategory,
  checkMultiModalAgreement,
  fuseTriageSignals,
  checkReachability,
  routeFinding,
} from "./triage/index.js";
import { runSelfConsistencyVerify } from "./triage/verify-pipeline.js";
import { generatePov } from "./triage/pov-gate.js";
import { getCloudSinkConfig, postFinding, postFinalReport } from "./cloud-sink.js";
import { eventBus } from "./events/bus.js";
import { loadScope, type ScopePolicy } from "./scope/scope.js";

export interface AgenticScanOptions {
  config: ScanConfig;
  dbPath?: string;
  onEvent?: ScanListener;
  /** Poll for user-injected messages from the TUI at turn boundaries. */
  getPendingUserMessages?: () => string[];
  /** Optional hint/description for benchmark challenges */
  challengeHint?: string;
  /** Resume from a previous scan (uses persisted sessions) */
  resumeScanId?: string;
}

/**
 * Append a triage-layer verdict to a finding's `layerVerdicts` log. The
 * array is created lazily so existing call sites that don't construct
 * findings via the scanner (tests, importers) keep working.
 *
 * Each entry is the per-layer telemetry that #112 was designed to surface
 * and that the dynamic-routing model in #113 trains on. Append-only,
 * ordered by execution.
 */
function pushLayerVerdict(
  finding: Finding,
  entry: {
    layer: TriageLayerName;
    verdict: LayerVerdictKind;
    confidence?: number;
    reason: string;
    startedAt: number;
    costUsd?: number;
    changedSeverity?: { from: Severity; to: Severity };
  },
): void {
  if (!finding.layerVerdicts) finding.layerVerdicts = [];
  const verdict: LayerVerdict = {
    layer: entry.layer,
    verdict: entry.verdict,
    reason: entry.reason,
    durationMs: Date.now() - entry.startedAt,
    costUsd: entry.costUsd ?? 0,
  };
  if (entry.confidence !== undefined) verdict.confidence = entry.confidence;
  if (entry.changedSeverity) verdict.changedSeverity = entry.changedSeverity;
  finding.layerVerdicts.push(verdict);
}

function assertApiRuntimeSelection(
  requestedRuntime: ScanConfig["runtime"] | undefined,
  diagnostics: ApiRuntimeDiagnostics,
): void {
  if (requestedRuntime === "api" && !diagnostics.valid) {
    throw new Error(diagnostics.fatalError ?? `${diagnostics.providerLabel} runtime is not available.`);
  }

  if ((requestedRuntime === "auto" || requestedRuntime === undefined) && diagnostics.reason === "invalid_config") {
    throw new Error(diagnostics.fatalError ?? `${diagnostics.providerLabel} runtime is misconfigured.`);
  }
}

/**
 * Auto-detect whether an HTTP target is a web app vs an AI/API endpoint.
 * If the target serves HTML and the user requested "deep" mode,
 * automatically switch to "web" mode for better coverage.
 */
async function normalizeScanConfig(config: ScanConfig): Promise<ScanConfig> {
  // Normalize target URL first — if the user gave a bare hostname like
  // `doruk.ch`, every URL-using tool downstream (`crawl`, `http_request`,
  // playwright `goto`) blows up with "Invalid URL" on `new URL(input,
  // ctx.target)` because the base must be absolute. Auto-prefix `https://`
  // when no scheme is present so the rest of the pipeline gets a
  // well-formed URL. Skips package targets (npm/pypi/cargo names like
  // "lodash") — those don't have `.` or `://` in a way that triggers
  // this branch, and audit-mode targets aren't URLs anyway.
  if (
    config.target &&
    /\./.test(config.target) &&
    !/^[a-z][a-z0-9+.-]*:\/\//i.test(config.target)
  ) {
    config = { ...config, target: `https://${config.target.trim()}` };
  }

  // Only auto-route for default/deep mode on HTTP targets
  const requestedMode = config.mode ?? "deep";
  if (requestedMode !== "deep") return config;
  if (!config.target.startsWith("http://") && !config.target.startsWith("https://")) return config;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(config.timeout ?? 30_000, 8_000));
    try {
      const response = await fetch(config.target, {
        method: "GET",
        headers: {
          Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        },
        signal: controller.signal,
      });
      const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
      const body = await response.text();

      // Check if response is HTML (web app)
      const looksHtml =
        contentType.includes("text/html")
        || /^\s*<!doctype html/i.test(body)
        || /<html[\s>]/i.test(body);

      if (looksHtml) {
        return { ...config, mode: "web" };
      }

      // Check if response looks like an AI/LLM API endpoint
      // Common patterns: /v1/chat/completions, /v1/messages, /completions, /generate
      const url = new URL(config.target);
      const aiPathPatterns = [
        /\/v\d+\/chat/,
        /\/v\d+\/messages/,
        /\/completions/,
        /\/generate/,
        /\/inference/,
      ];
      const looksLikeAiEndpoint = aiPathPatterns.some((p) => p.test(url.pathname));

      // If it's a JSON API that doesn't match AI patterns, still use deep mode
      // but if it returned 405 on GET, it's likely a POST-only API
      if (response.status === 405 && !looksLikeAiEndpoint) {
        // POST-only endpoint that's not an AI API — likely a web API, keep deep mode
        return config;
      }

      // If JSON response with common AI indicators, keep deep mode (AI scanning)
      if (contentType.includes("application/json")) {
        try {
          const json = JSON.parse(body);
          const hasAiIndicators =
            json.model || json.choices || json.content || json.completion
            || json.object === "chat.completion" || json.object === "message";
          if (hasAiIndicators) return config; // Confirmed AI endpoint
        } catch {
          // Not valid JSON, proceed with default
        }
      }
    } finally {
      clearTimeout(timer);
    }
  } catch {
    // Keep the requested mode if preflight fails
  }

  return config;
}

/**
 * Run a full agentic scan with multi-turn agents, tool use, and persistent state.
 *
 * Pipeline:
 * - Discovery Agent: probes target, maps endpoints, builds profile
 * - Attack Agent: runs attacks with adaptation and multi-turn escalation
 * - Verification Agent: replays and confirms findings
 * - Report Agent: generates summary
 *
 * When ANTHROPIC_API_KEY is set, uses the native Claude Messages API with
 * structured tool_use for reliable tool execution. Otherwise, falls back to
 * the legacy text-based agent loop via subprocess runtimes.
 *
 * All findings persist to SQLite between stages and across scans.
 * Sessions are saved so interrupted scans can be resumed.
 */
export async function agenticScan(opts: AgenticScanOptions): Promise<ScanReport> {
  const { dbPath, onEvent, getPendingUserMessages, resumeScanId } = opts;
  const emit = onEvent ?? (() => {});
  const config = await normalizeScanConfig(opts.config);

  // Programmatic scope ingestion (pwnkit#215). Load once at the top and
  // pass the parsed `ScopePolicy` to every agent config below. The CLI
  // is responsible for catching ENOENT / parse errors before this point;
  // here we just propagate. Pre-validate the configured target so an
  // out-of-scope `--target` fails the scan loudly instead of being
  // refused silently by every tool call.
  let scope: ScopePolicy | undefined;
  if (config.scopeFile) {
    scope = loadScope(config.scopeFile);
    const verdict = scope.match(config.target);
    if (!verdict.allowed) {
      throw new Error(
        `--target ${config.target} is out of scope per ${config.scopeFile}: ${verdict.reason}`,
      );
    }
  }

  const db = await (async () => {
    try {
      const { pwnkitDB } = await import("@pwnkit/db");
      return new pwnkitDB(dbPath);
    } catch (err) {
      const cause = err instanceof Error ? err.message : String(err);
      throw new Error(
        `pwnkit: failed to initialize the local database (@pwnkit/db). ` +
        `Agentic scans require SQLite persistence. Underlying error: ${cause}`,
      );
    }
  })();

  // Resume or create new scan
  const scanId = resumeScanId ?? db.createScan(config);

  if (resumeScanId) {
    const existing = db.getScan(resumeScanId);
    if (!existing) throw new Error(`Scan ${resumeScanId} not found`);
    db.logEvent({
      scanId,
      stage: "discovery",
      eventType: "scan_resumed",
      payload: { originalScanId: resumeScanId },
      timestamp: Date.now(),
    });
    emit({ type: "stage:start", stage: "discovery", message: "Resuming scan..." });
  }

  // Determine runtime mode
  const requestedRuntime = config.runtime ?? "api";

  // Native API runtime is only valid for explicit API mode, or for auto mode
  // when we intentionally choose the native API strategy.
  const nativeApiRuntime = new LlmApiRuntime({
    type: "api",
    timeout: config.timeout ?? 120_000,
    model: config.model,
    apiKey: config.apiKey,
  });
  const nativeApiDiagnostics = nativeApiRuntime.getConfigurationDiagnostics();
  assertApiRuntimeSelection(config.runtime, nativeApiDiagnostics);
  const nativeApiAvailable = nativeApiDiagnostics.valid;

  let selectedRuntimeType: "api" | "claude" | "codex" | "gemini" = "api";
  let useNative = false;

  if (requestedRuntime === "api") {
    selectedRuntimeType = "api";
    useNative = nativeApiAvailable;
  } else if (requestedRuntime === "auto") {
    if (nativeApiAvailable) {
      selectedRuntimeType = "api";
      useNative = true;
    } else {
      const availableCli = await detectAvailableRuntimes();
      // Claude is the supported local adapter for live target scanning.
      // Codex and Gemini are experimental and limited to source-analysis workflows.
      if (availableCli.has("claude")) {
        selectedRuntimeType = "claude";
      } else if (availableCli.has("codex")) {
        selectedRuntimeType = "codex";
        emit({ type: "stage:start", stage: "discovery", message: "Warning: codex is experimental for live targets. Prefer runtime=api or install Claude Code CLI for full tool-loop support." });
      } else if (availableCli.has("gemini")) {
        selectedRuntimeType = "gemini";
        emit({ type: "stage:start", stage: "discovery", message: "Warning: gemini is experimental for live targets. Prefer runtime=api or install Claude Code CLI for full tool-loop support." });
      } else {
        selectedRuntimeType = "api";
      }
      useNative = false;
    }
  } else {
    selectedRuntimeType = requestedRuntime;
    useNative = false;
  }

  const legacyRuntime = createRuntime({
    type: selectedRuntimeType,
    timeout: config.timeout ?? 60_000,
    model: config.model,
    apiKey: config.apiKey,
    // Route tool calls through the event system so they don't write
    // directly to stderr (which disrupts the Ink TUI)
    onToolCall: (name, detail) => {
      emit({ type: "stage:start", stage: "discovery", message: `${name}${detail ? `: ${detail}` : ""}` });
    },
  });

  const templates = loadTemplates(config.depth);
  const categories = [...new Set(templates.map((t) => t.category))];

  let allFindings: Finding[] = [];

  // Parse API spec if provided
  let apiSpecPromptText = "";
  if (config.apiSpecPath) {
    try {
      const specSummary = await parseApiSpec(config.apiSpecPath);
      apiSpecPromptText = specSummary.promptText;
      emit({ type: "stage:start", stage: "discovery", message: `Loaded API spec: ${specSummary.title} (${specSummary.endpoints.length} endpoints)` });
    } catch (err) {
      emit({ type: "stage:start", stage: "discovery", message: `Warning: failed to parse API spec: ${err instanceof Error ? err.message : String(err)}` });
    }
  }

  db.ensureCaseWorkPlan?.(scanId);

  // Log scan start
  db.logEvent({
    scanId,
    stage: "discovery",
    eventType: "scan_start",
    payload: {
      target: config.target,
      depth: config.depth,
      mode: config.mode ?? "probe",
      requestedRuntime,
      selectedRuntime: selectedRuntimeType,
      useNative,
      templateCount: templates.length,
      categoryCount: categories.length,
    },
    timestamp: Date.now(),
  });

  // Event-bus instrumentation: `agenticScan` has multiple exit paths (MCP
  // short-circuit, cost-ceiling partial report, normal report return, and the
  // catch re-throw). Each must emit a single `scan_completed` event so the
  // cloud worker-controller / dashboard tracer can transition the scan to a
  // terminal state. `scan()` in scanner.ts does NOT call agenticScan(), so
  // there is no double-emit risk from nesting — but we still guard against
  // double-fire from sloppy refactors via the `emittedScanCompleted` latch.
  let emittedScanCompleted = false;
  const scanStartedAt = Date.now();

  // ── Per-scan metrics tracked off the bus ─────────────────────────
  // `tool_calls_total` and `summary` (the agent's final narrative) get
  // surfaced on the cloud scan card / detail page so a no-findings scan
  // still tells the operator how much work happened. Tracked here in
  // the scanner (the producer) so the cloud doesn't re-derive these
  // from raw scan_events on every page load — see
  // pwnkit-cloud/services/dashboard/src/routes/_authed/$orgSlug/scans/index.tsx.
  let toolCallsTotal = 0;
  let lastDoneSummary = "";
  const unsubscribeMetrics = eventBus.subscribe({
    emit(type, payload) {
      if (type === "tool_call_completed") {
        toolCallsTotal += 1;
        return;
      }
      if (type === "tool_call_started") {
        // Capture the `done` tool's args_preview verbatim — it's the
        // model's final 1-2 sentence narrative ("Audited lodash, no
        // exploitable sinks found"). Last write wins so a `done` call
        // in a retry loop overwrites the first-attempt summary.
        const tool = payload.tool;
        const argsPreview = payload.args_preview;
        if (
          tool === "done" &&
          typeof argsPreview === "string"
        ) {
          const stripped = argsPreview
            .replace(/^done\s*:\s*/i, "")
            .trim();
          if (stripped) lastDoneSummary = stripped;
        }
      }
    },
  });

  const emitScanCompleted = (
    exit_reason: "completed" | "failed" | "cost_exceeded" | "max_turns" | "early_stop",
    findings_count: number,
    metrics?: { turnsUsed?: number; summary?: string },
  ): void => {
    if (emittedScanCompleted) return;
    emittedScanCompleted = true;
    try {
      // Caller-provided summary (from the loop's `state.summary` field)
      // wins over the bus-derived `lastDoneSummary` because the loop's
      // version may aggregate retries; fall back to the bus capture for
      // exit paths that don't surface a state object (e.g. early-fail).
      const summary =
        (metrics?.summary && metrics.summary.trim()) ||
        lastDoneSummary ||
        undefined;
      eventBus.emit("scan_completed", {
        exit_reason,
        findings: findings_count,
        findings_count,
        duration_ms: Date.now() - scanStartedAt,
        turns_used: metrics?.turnsUsed,
        tool_calls_total: toolCallsTotal,
        summary,
      });
    } catch {
      /* bus is fail-soft, but be defensive */
    } finally {
      unsubscribeMetrics();
    }
  };

  try {
    if (!useNative && selectedRuntimeType === "codex") {
      throw new Error(
        "Codex CLI is not compatible with pwnkit's target-interaction tool loop. " +
        "Use runtime=api for live target scanning, or reserve codex for source-analysis/code-review workflows.",
      );
    }

    // ── MCP fast-path: use deterministic MCP security checks ──
    // The agentic agent loops are designed for LLM API targets. For MCP targets,
    // delegate to the structured MCP discovery + security checks which directly
    // speak JSON-RPC to the MCP server.
    if (config.mode === "mcp" || isMcpTarget(config.target)) {
      emit({ type: "stage:start", stage: "discovery", message: "MCP discovery starting..." });
      const mcpCtx = createScanContext(config);
      mcpCtx.scanId = scanId;

      try {
        const targetInfo = await discoverMcpTarget(config.target, config.timeout);
        mcpCtx.target = targetInfo;
      } catch (err) {
        mcpCtx.target = { url: config.target, type: "mcp" };
      }
      emit({ type: "stage:end", stage: "discovery", message: `MCP target discovered: ${mcpCtx.target.type}` });

      emit({ type: "stage:start", stage: "attack", message: "Running MCP security checks..." });
      const { results, findings } = await runMcpSecurityChecks(mcpCtx);
      mcpCtx.attacks.push(...results);
      for (const finding of findings) {
        mcpCtx.findings.push(finding);
      }
      allFindings = [...findings];

      // Attach remediation guidance to MCP findings
      for (const finding of allFindings) {
        finding.remediation = generateRemediation(finding);
      }

      emit({ type: "stage:end", stage: "attack", message: `MCP checks complete: ${findings.length} findings` });

      // Persist findings
      if (db) {
        db.upsertTarget(mcpCtx.target);
        for (const finding of findings) {
          db.saveFinding(scanId, finding);
        }
        for (const result of results) {
          db.saveAttackResult(scanId, result);
        }
      }

      finalize(mcpCtx);

      const summary = {
        totalAttacks: results.length,
        totalFindings: allFindings.length,
        critical: allFindings.filter((f) => f.severity === "critical").length,
        high: allFindings.filter((f) => f.severity === "high").length,
        medium: allFindings.filter((f) => f.severity === "medium").length,
        low: allFindings.filter((f) => f.severity === "low").length,
        info: allFindings.filter((f) => f.severity === "info").length,
      };

      db.completeScan(scanId, summary);

      const report: ScanReport = {
        target: config.target,
        scanDepth: config.depth,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 0,
        summary,
        findings: allFindings,
        warnings: [],
      };

      const dbScan = db.getScan(scanId);
      if (dbScan) {
        report.startedAt = dbScan.startedAt;
        report.completedAt = dbScan.completedAt ?? report.completedAt;
        report.durationMs = dbScan.durationMs ?? 0;
      }

      emit({ type: "stage:end", stage: "report", message: `Report: ${summary.totalFindings} findings` });
      // Stream final report to the opt-in webhook sink (no-op when unset).
      await postFinalReport(report);
      emitScanCompleted("completed", allFindings.length);
      return report;
    }

    // ── Stage 1: Discovery Agent ──
    emit({ type: "stage:start", stage: "discovery", message: "Discovery agent starting..." });
    db.transitionCaseWorkItem?.(scanId, "surface_map", "in_progress", {
      owner: "attack-surface-agent",
      summary: "Discovery agent is mapping the target surface and initial context.",
    });
    db.logEvent({
      scanId,
      stage: "discovery",
      eventType: "stage_start",
      agentRole: "discovery",
      payload: {},
      timestamp: Date.now(),
    });

    const discoveryState = useNative
      ? await runNativeDiscovery(nativeApiRuntime, db, config, scanId, emit, apiSpecPromptText, getPendingUserMessages)
      : await runLegacyDiscovery(legacyRuntime, db, config, scanId, emit, dbPath, apiSpecPromptText);

    // Persist target profile
    if (discoveryState.targetInfo.type) {
      db.upsertTarget({
        url: config.target,
        type: discoveryState.targetInfo.type ?? "unknown",
        model: discoveryState.targetInfo.model,
        systemPrompt: discoveryState.targetInfo.systemPrompt,
        endpoints: discoveryState.targetInfo.endpoints,
        detectedFeatures: discoveryState.targetInfo.detectedFeatures,
      });
    }

    db.logEvent({
      scanId,
      stage: "discovery",
      eventType: "stage_complete",
      agentRole: "discovery",
      payload: { summary: discoveryState.summary.slice(0, 500) },
      timestamp: Date.now(),
    });
    db.transitionCaseWorkItem?.(scanId, "surface_map", "done", {
      owner: "attack-surface-agent",
      summary: discoveryState.summary.slice(0, 500) || "Discovery completed.",
    });
    db.transitionCaseWorkItem?.(scanId, "hypothesis", "todo", {
      owner: "research-agent",
      summary: "Surface mapping completed. Exploit hypothesis is ready to start.",
    });
    emit({
      type: "stage:end",
      stage: "discovery",
      message: `Discovery complete: ${discoveryState.summary}`,
    });

    // ── Stage 2: Attack Agent ──
    const maxAttackTurns = config.depth === "deep" ? 100 : config.depth === "default" ? 40 : 20;

    emit({
      type: "stage:start",
      stage: "attack",
      message: `Attack agent starting (${categories.length} categories)...`,
    });
    db.transitionCaseWorkItem?.(scanId, "hypothesis", "in_progress", {
      owner: "research-agent",
      summary: "Attack agent is developing the exploit hypothesis and artifact path.",
    });
    db.transitionCaseWorkItem?.(scanId, "poc_build", "in_progress", {
      owner: "research-agent",
      summary: "Attack agent is building exploit requests, responses, and reproduction artifacts.",
    });
    db.logEvent({
      scanId,
      stage: "attack",
      eventType: "stage_start",
      agentRole: "attack",
      payload: { categories, maxTurns: maxAttackTurns },
      timestamp: Date.now(),
    });

    // ── Best-of-N Racing (--race flag) ──
    // When enabled, run multiple attack strategies in parallel and take the first success.
    let attackState: AgentOutput;

    if (config.egats && useNative) {
      emit({
        type: "stage:start",
        stage: "attack",
        message: "Running EGATS (Evidence-Gated Attack Tree Search)...",
      });

      const egatsResult = await runEGATSWithDefaults(
        config.target,
        scanId,
        nativeApiRuntime,
        db,
        {
          repoPath: config.repoPath,
          challengeHint: opts.challengeHint,
          onEvent: (eventType, payload) => {
            emit({
              type: "stage:start",
              stage: "attack",
              message: `[egats] ${eventType}`,
              data: payload,
            });
          },
        },
      );

      attackState = {
        findings: egatsResult.findings,
        targetInfo: discoveryState.targetInfo,
        summary: `[egats:${egatsResult.terminationReason}] explored ${egatsResult.allNodes.length} nodes, ${egatsResult.findings.length} findings`,
        turnCount: egatsResult.totalTurns,
        estimatedCostUsd: egatsResult.totalCostUsd,
      };
    } else if (config.race && useNative) {
      emit({
        type: "stage:start",
        stage: "attack",
        message: "Racing 5 strategies in parallel (best-of-N)...",
      });

      const raceResult = await raceWithDefaults(
        config.target,
        scanId,
        nativeApiRuntime,
        db,
        {
          maxConcurrency: config.maxConcurrency ?? 3,
          repoPath: config.repoPath,
          challengeHint: opts.challengeHint,
        },
      );

      // Convert RaceResult to AgentOutput
      if (raceResult.winner) {
        attackState = {
          findings: raceResult.winner.findings,
          targetInfo: discoveryState.targetInfo,
          summary: `[race:${raceResult.winner.strategyName}] ${raceResult.winner.summary}`,
          turnCount: raceResult.totalTurns,
          estimatedCostUsd: raceResult.totalCostUsd,
        };
      } else {
        // All strategies failed — combine findings from all attempts
        const combinedFindings = raceResult.allResults.flatMap((r) => r.findings);
        const summaryParts = raceResult.allResults.map(
          (r) => `${r.strategyName}: ${r.succeeded ? "success" : "failed"} (${r.turnCount} turns)`,
        );
        attackState = {
          findings: combinedFindings,
          targetInfo: discoveryState.targetInfo,
          summary: `All ${raceResult.allResults.length} strategies failed. ${summaryParts.join("; ")}`,
          turnCount: raceResult.totalTurns,
          estimatedCostUsd: raceResult.totalCostUsd,
        };
      }
    } else {
      attackState = useNative
        ? await runNativeAttack(nativeApiRuntime, db, config, scanId, discoveryState.targetInfo, categories, maxAttackTurns, emit, opts.challengeHint, apiSpecPromptText, getPendingUserMessages)
        : await runLegacyAttack(legacyRuntime, db, config, scanId, discoveryState.targetInfo, categories, maxAttackTurns, emit, dbPath, apiSpecPromptText);
    }

    allFindings = [...attackState.findings];

    db.logEvent({
      scanId,
      stage: "attack",
      eventType: "stage_complete",
      agentRole: "attack",
      payload: { findingCount: allFindings.length, summary: attackState.summary.slice(0, 500) },
      timestamp: Date.now(),
    });
    db.transitionCaseWorkItem?.(scanId, "hypothesis", "done", {
      owner: "research-agent",
      summary: attackState.summary.slice(0, 500) || "Exploit hypothesis completed.",
    });
    db.transitionCaseWorkItem?.(scanId, "poc_build", allFindings.length > 0 ? "done" : "blocked", {
      owner: "research-agent",
      summary: allFindings.length > 0
        ? `PoC build completed with ${allFindings.length} finding${allFindings.length > 1 ? "s" : ""}.`
        : "Attack stage finished without actionable exploit artifacts.",
    });
    if (allFindings.length > 0) {
      db.transitionCaseWorkItem?.(scanId, "blind_verify", "todo", {
        owner: "verify-agent",
        summary: "Exploit artifacts are ready for an independent verification pass.",
      });
    }
    emit({
      type: "stage:end",
      stage: "attack",
      message: `Attack complete: ${attackState.findings.length} findings, ${attackState.summary}`,
    });

    // ── Cost ceiling short-circuit ──
    // If the attack stage was aborted because the per-scan cost ceiling was
    // exceeded, skip triage/verify/remediation and emit a partial report
    // immediately. Findings collected so far are preserved in the DB and
    // returned on the report. Callers (CLI) can detect this via the
    // `costCeilingExceeded` flag on the returned report.
    if (attackState.costCeilingExceeded) {
      // Persist any findings collected so far so they're not lost.
      for (const f of allFindings) {
        try { db.saveFinding(scanId, f); } catch { /* may already be persisted */ }
      }

      const summary = {
        totalAttacks: attackState.turnCount,
        totalFindings: allFindings.length,
        critical: allFindings.filter((f) => f.severity === "critical").length,
        high: allFindings.filter((f) => f.severity === "high").length,
        medium: allFindings.filter((f) => f.severity === "medium").length,
        low: allFindings.filter((f) => f.severity === "low").length,
        info: allFindings.filter((f) => f.severity === "info").length,
      };
      try { db.completeScan(scanId, summary); } catch { /* best effort */ }

      const partialTraceMessages = [
        ...(discoveryState.messages ?? []),
        ...(attackState.messages ?? []),
      ];
      const partialReport: ScanReport = {
        target: config.target,
        scanDepth: config.depth,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 0,
        summary,
        findings: allFindings,
        warnings: [
          {
            stage: "attack",
            message: `Scan aborted: cost ceiling of $${(config.costCeilingUsd ?? 0).toFixed(4)} exceeded after ${attackState.turnCount} turns. Partial findings preserved.`,
          },
        ],
        benchmarkMeta: {
          attackTurns: attackState.turnCount,
          estimatedCostUsd: attackState.estimatedCostUsd,
          model: config.model,
        },
        exitReason: "cost_ceiling_exceeded",
        costCeilingExceeded: true,
        ...(partialTraceMessages.length > 0 ? { trace: partialTraceMessages } : {}),
      };

      const dbScan = db.getScan(scanId);
      if (dbScan) {
        partialReport.startedAt = dbScan.startedAt;
        partialReport.completedAt = dbScan.completedAt ?? partialReport.completedAt;
        partialReport.durationMs = dbScan.durationMs ?? 0;
      }

      emit({
        type: "stage:end",
        stage: "report",
        message: `cost_ceiling_exceeded: aborted with ${allFindings.length} partial finding(s)`,
      });

      db.logEvent({
        scanId,
        stage: "report",
        eventType: "scan_aborted",
        payload: { reason: "cost_ceiling_exceeded", ...summary },
        timestamp: Date.now(),
      });

      emitScanCompleted("cost_exceeded", allFindings.length, {
        turnsUsed:
          (discoveryState?.turnCount ?? 0) + (attackState?.turnCount ?? 0),
        summary: attackState?.summary ?? discoveryState?.summary,
      });
      return partialReport;
    }

    // ── Stage 2.5: Triage (holding-it-wrong + feature extraction) ──
    // For every finding saved by the attack agent:
    //   1. Run `isHoldingItWrong` — if true, downgrade severity to `info`,
    //      mark triage_status=rejected, and skip further verification.
    //   2. Extract the 45-element feature vector and log it (the trained
    //      triage model is not yet wired in; we log for future training).
    //   3. Only findings that pass holding-it-wrong AND have
    //      evidence_completeness > 0.5 get sent to the blind verify agent.
    const verifyCandidates: Finding[] = [];
    const evidenceCompletenessIdx = FEATURE_NAMES.indexOf("cross_evidence_completeness");
    for (const finding of allFindings) {
      // Always run isHoldingItWrong + extractFeatures for telemetry, but
      // only enforce the rejection when the feature flags are enabled.
      // Both default ON to preserve existing v0.6.0 behavior; setting
      // PWNKIT_FEATURE_HOLDING_IT_WRONG=0 / PWNKIT_FEATURE_EVIDENCE_GATE=0
      // turns the gates off so we can A/B test what they actually cost.
      const hiwStartedAt = Date.now();
      const hiw = isHoldingItWrong(finding);
      const featureVector = extractFeatures(finding);
      const evidenceCompleteness =
        evidenceCompletenessIdx >= 0 ? featureVector[evidenceCompletenessIdx] ?? 0 : 0;

      // Layer telemetry: holding-it-wrong always runs (just may not enforce).
      // pwnkit#112 — feeds the dynamic routing model in #113.
      if (hiw.isHoldingItWrong && features.holdingItWrong) {
        pushLayerVerdict(finding, {
          layer: "holding_it_wrong",
          verdict: "reject",
          reason: hiw.reason ?? "matched holding-it-wrong blocklist",
          startedAt: hiwStartedAt,
          changedSeverity: { from: finding.severity, to: "info" },
        });
      } else {
        pushLayerVerdict(finding, {
          layer: "holding_it_wrong",
          verdict: hiw.isHoldingItWrong ? "skip" : "pass",
          reason: hiw.isHoldingItWrong
            ? `would have rejected (${hiw.reason}) but PWNKIT_FEATURE_HOLDING_IT_WRONG=0`
            : "no holding-it-wrong pattern matched",
          startedAt: hiwStartedAt,
        });
      }

      // Log the feature vector for future training
      db.logEvent?.({
        scanId,
        stage: "verify",
        eventType: "triage_features",
        agentRole: "triage",
        payload: {
          findingId: finding.id,
          featureVector,
          featureNames: FEATURE_NAMES,
          evidenceCompleteness,
          holdingItWrong: hiw.isHoldingItWrong,
          holdingItWrongReason: hiw.reason,
        },
        timestamp: Date.now(),
      });

      if (hiw.isHoldingItWrong && features.holdingItWrong) {
        // Downgrade severity to info and mark rejected. Skip further verify.
        finding.severity = "info";
        finding.triageStatus = "suppressed";
        finding.triageNote = `rejected: holding-it-wrong — ${hiw.reason}`;
        db.updateFindingStatus?.(finding.id, "false-positive");
        finding.status = "false-positive";
        db.saveFinding?.(scanId, finding);
        emit({
          type: "stage:end",
          stage: "attack",
          message: `Triage rejected ${finding.id}: ${hiw.reason}`,
        });
        continue;
      }

      const evidenceGateStartedAt = Date.now();
      const evidenceGateRejects = evidenceCompleteness <= 0.5;
      if (evidenceGateRejects && features.evidenceGate) {
        pushLayerVerdict(finding, {
          layer: "evidence_gate",
          verdict: "reject",
          confidence: 1 - evidenceCompleteness,
          reason: `evidence_completeness=${evidenceCompleteness.toFixed(2)} <= 0.5`,
          startedAt: evidenceGateStartedAt,
        });
        finding.triageStatus = "suppressed";
        finding.triageNote = `rejected: evidence_completeness=${evidenceCompleteness.toFixed(2)} <= 0.5`;
        db.updateFindingStatus?.(finding.id, "false-positive");
        finding.status = "false-positive";
        db.saveFinding?.(scanId, finding);
        emit({
          type: "stage:end",
          stage: "attack",
          message: `Triage rejected ${finding.id}: insufficient evidence (completeness=${evidenceCompleteness.toFixed(2)})`,
        });
        continue;
      }
      pushLayerVerdict(finding, {
        layer: "evidence_gate",
        verdict: evidenceGateRejects ? "skip" : "pass",
        confidence: evidenceCompleteness,
        reason: evidenceGateRejects
          ? `would have rejected (completeness=${evidenceCompleteness.toFixed(2)}) but PWNKIT_FEATURE_EVIDENCE_GATE=0`
          : `evidence_completeness=${evidenceCompleteness.toFixed(2)} > 0.5`,
        startedAt: evidenceGateStartedAt,
      });

      // ── Learned router (pwnkit#113) ──
      // When enabled, the XGBoost model decides per-finding whether to
      // auto-accept, auto-reject, or run a subset of layers. This runs
      // AFTER the two free always-on filters (holding-it-wrong +
      // evidence_gate) and BEFORE any expensive layer. The model loads
      // once from triage-router-v1.json and evaluates in sub-millisecond.
      if (features.learnedRouter) {
        const routerResult = routeFinding(finding);
        db.logEvent?.({
          scanId,
          stage: "verify",
          eventType: "learned_router",
          agentRole: "triage",
          payload: {
            findingId: finding.id,
            decision: routerResult.decision,
            tpProbability: routerResult.tpProbability,
            reason: routerResult.reason,
            layersToRun: routerResult.layersToRun,
            layersToSkip: routerResult.layersToSkip,
          },
          timestamp: Date.now(),
        });

        if (routerResult.decision === "auto_accept") {
          finding.confidence = Math.max(finding.confidence ?? 0, routerResult.tpProbability);
          finding.triageStatus = "accepted";
          finding.triageNote = `router_auto_accept: ${routerResult.reason}`;
          db.saveFinding?.(scanId, finding);
          verifyCandidates.push(finding);
          continue;
        }

        if (routerResult.decision === "auto_reject") {
          finding.triageStatus = "suppressed";
          finding.triageNote = `router_auto_reject: ${routerResult.reason}`;
          db.updateFindingStatus?.(finding.id, "false-positive");
          finding.status = "false-positive";
          db.saveFinding?.(scanId, finding);
          emit({
            type: "stage:end",
            stage: "attack",
            message: `Router rejected ${finding.id}: ${routerResult.reason}`,
          });
          continue;
        }

        // decision === "run_layers" — continue to the layers below,
        // but the router's layersToSkip list is available for future
        // per-layer gating (not wired yet — the static feature flags
        // still control which layers run for now).
      }

      // ── Reachability gate ("Endor Labs moat") ──
      // Opt-in via PWNKIT_FEATURE_REACHABILITY_GATE. Only runs in white-box
      // mode when we have source code. For each finding, check whether the
      // vulnerable sink is actually reachable from an application entry
      // point (HTTP handler, CLI main, route file). Dead code and test-only
      // paths are suppressed before we spend any LLM tokens on verify.
      if (features.reachabilityGate && config.repoPath) {
        const reachStartedAt = Date.now();
        try {
          const reach = await checkReachability(finding, config.repoPath);
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "reachability_check",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              reachable: reach.reachable,
              confidence: reach.confidence,
              entryPoints: reach.entryPoints,
              callPath: reach.callPath,
              reason: reach.reason,
            },
            timestamp: Date.now(),
          });
          if (!reach.reachable && reach.confidence >= 0.7) {
            pushLayerVerdict(finding, {
              layer: "reachability",
              verdict: "reject",
              confidence: reach.confidence,
              reason: `unreachable: ${reach.reason}`,
              startedAt: reachStartedAt,
            });
            finding.triageStatus = "suppressed";
            finding.triageNote = `unreachable: ${reach.reason}`;
            db.updateFindingStatus?.(finding.id, "false-positive");
            finding.status = "false-positive";
            db.saveFinding?.(scanId, finding);
            emit({
              type: "stage:end",
              stage: "attack",
              message: `Reachability gate rejected ${finding.id}: ${reach.reason}`,
            });
            continue;
          }
          pushLayerVerdict(finding, {
            layer: "reachability",
            verdict: "pass",
            confidence: reach.confidence,
            reason: reach.reachable
              ? `reachable from ${reach.entryPoints.length} entry point(s): ${reach.reason}`
              : `low-confidence unreachable verdict (${reach.confidence.toFixed(2)} < 0.7), kept`,
            startedAt: reachStartedAt,
          });
        } catch (err) {
          // Reachability check errors must not drop findings silently —
          // let the rest of the pipeline continue.
          pushLayerVerdict(finding, {
            layer: "reachability",
            verdict: "error",
            reason: `reachability check threw: ${(err as Error).message}`,
            startedAt: reachStartedAt,
          });
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "reachability_check_error",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              error: (err as Error).message,
            },
            timestamp: Date.now(),
          });
        }
      } else {
        pushLayerVerdict(finding, {
          layer: "reachability",
          verdict: "skip",
          reason: features.reachabilityGate
            ? "no repoPath available (black-box mode)"
            : "PWNKIT_FEATURE_REACHABILITY_GATE=0",
          startedAt: Date.now(),
        });
      }

      // ── Multi-modal agreement (foxguard cross-validation) ──
      // Opt-in via PWNKIT_FEATURE_MULTIMODAL. Only runs when we have source
      // code (white-box mode). Cross-checks every finding against the
      // foxguard Rust pattern scanner — if both agents agree, the finding is
      // almost certainly real; if foxguard disagrees and the evidence is
      // thin, we auto-reject. This is the "opensoar-hq trinity" validation.
      if (features.multiModalAgreement && config.repoPath) {
        const mmStartedAt = Date.now();
        try {
          const mm = await checkMultiModalAgreement(finding, config.repoPath);
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "multi_modal_agreement",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              agreement: mm.agreement,
              confidence: mm.confidence,
              foxguardMatches: mm.foxguardFindings.length,
              reasoning: mm.reasoning,
            },
            timestamp: Date.now(),
          });

          const fused = fuseTriageSignals({
            multiModal: mm,
            holdingItWrong: false,
            evidenceCompleteness,
          });

          if (fused.decision === "auto_accept") {
            pushLayerVerdict(finding, {
              layer: "multi_modal",
              verdict: "pass",
              confidence: fused.confidence,
              reason: `auto_accept: ${fused.reasoning}`,
              startedAt: mmStartedAt,
            });
            finding.confidence = Math.max(finding.confidence ?? 0, fused.confidence);
            finding.triageStatus = "accepted";
            finding.triageNote = `multi_modal_accept: ${fused.reasoning}`;
          } else if (fused.decision === "auto_reject") {
            pushLayerVerdict(finding, {
              layer: "multi_modal",
              verdict: "reject",
              confidence: fused.confidence,
              reason: `auto_reject: ${fused.reasoning}`,
              startedAt: mmStartedAt,
              changedSeverity: { from: finding.severity, to: "info" },
            });
            finding.severity = "info";
            finding.triageStatus = "suppressed";
            finding.triageNote = `multi_modal_reject: ${fused.reasoning}`;
            db.updateFindingStatus?.(finding.id, "false-positive");
            finding.status = "false-positive";
            db.saveFinding?.(scanId, finding);
            emit({
              type: "stage:end",
              stage: "attack",
              message: `Multi-modal rejected ${finding.id}: ${fused.reasoning}`,
            });
            continue;
          } else if (fused.decision === "verify_priority") {
            pushLayerVerdict(finding, {
              layer: "multi_modal",
              verdict: "pass",
              confidence: mm.confidence,
              reason: `verify_priority: ${mm.reasoning}`,
              startedAt: mmStartedAt,
            });
            finding.confidence = Math.max(finding.confidence ?? 0, mm.confidence);
            finding.triageNote = `multi_modal_agree: ${mm.reasoning}`;
          } else {
            pushLayerVerdict(finding, {
              layer: "multi_modal",
              verdict: "pass",
              confidence: mm.confidence,
              reason: `verify (${fused.decision}): ${fused.reasoning}`,
              startedAt: mmStartedAt,
            });
          }
        } catch (err) {
          pushLayerVerdict(finding, {
            layer: "multi_modal",
            verdict: "error",
            reason: `multi-modal threw: ${(err as Error).message}`,
            startedAt: mmStartedAt,
          });
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "multi_modal_error",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              error: (err as Error).message,
            },
            timestamp: Date.now(),
          });
        }
      } else {
        pushLayerVerdict(finding, {
          layer: "multi_modal",
          verdict: "skip",
          reason: features.multiModalAgreement
            ? "no repoPath available (black-box mode)"
            : "PWNKIT_FEATURE_MULTIMODAL=0",
          startedAt: Date.now(),
        });
      }

      // ── Per-class verification oracle ──
      // "No exploit, no report" — attempt a deterministic exploit check for
      // each category we have an oracle for. If the oracle verifies, boost
      // confidence and mark the finding accepted. If it fails and we have an
      // oracle for the category, downgrade severity to low and annotate.
      // Categories without oracles fall through to the LLM-verify stage.
      const oracleStartedAt = Date.now();
      try {
        const oracle = await verifyOracleByCategory(finding, config.target);
        db.logEvent?.({
          scanId,
          stage: "verify",
          eventType: "oracle_result",
          agentRole: "triage",
          payload: {
            findingId: finding.id,
            category: finding.category,
            verified: oracle.verified,
            confidence: oracle.confidence,
            evidence: oracle.evidence,
            reason: oracle.reason,
          },
          timestamp: Date.now(),
        });

        if (oracle.verified) {
          pushLayerVerdict(finding, {
            layer: "oracle",
            verdict: "pass",
            confidence: oracle.confidence,
            reason: `verified: ${oracle.evidence}`,
            startedAt: oracleStartedAt,
          });
          finding.confidence = 1.0;
          finding.triageStatus = "accepted";
          finding.triageNote = `oracle_verified: ${oracle.evidence}`;
        } else if (
          oracle.reason &&
          !oracle.reason.startsWith("no oracle for category")
        ) {
          // An oracle exists for this category but the exploit didn't
          // reproduce. Downgrade severity and annotate so downstream agents
          // don't over-promote the finding.
          const fromSev = finding.severity;
          finding.severity = "low";
          finding.triageNote = `oracle_failed: ${oracle.reason}`;
          pushLayerVerdict(finding, {
            layer: "oracle",
            verdict: "downgrade",
            confidence: oracle.confidence,
            reason: `failed to reproduce: ${oracle.reason}`,
            startedAt: oracleStartedAt,
            changedSeverity: { from: fromSev, to: "low" },
          });
        } else {
          pushLayerVerdict(finding, {
            layer: "oracle",
            verdict: "skip",
            reason: `no oracle for category=${finding.category}`,
            startedAt: oracleStartedAt,
          });
        }
      } catch (err) {
        pushLayerVerdict(finding, {
          layer: "oracle",
          verdict: "error",
          reason: `oracle threw: ${(err as Error).message}`,
          startedAt: oracleStartedAt,
        });
        // Never let oracle errors kill the scan — log and move on.
        db.logEvent?.({
          scanId,
          stage: "verify",
          eventType: "oracle_error",
          agentRole: "triage",
          payload: {
            findingId: finding.id,
            error: (err as Error).message,
          },
          timestamp: Date.now(),
        });
      }

      // ── PoV generation gate ──
      // Empirical ground truth from arXiv:2509.07225: if the agent cannot
      // build a working PoC in N turns, the finding is likely a false
      // positive. Run AFTER the oracle (so we skip oracle-verified findings)
      // and BEFORE the blind verify agent. Only runs when the feature flag
      // is enabled and we have a native runtime.
      if (
        features.povGate
        && nativeApiRuntime
        && finding.triageStatus !== "accepted"
      ) {
        const povStart = Date.now();
        try {
          const pov = await generatePov(finding, config.target, nativeApiRuntime, 5);
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "pov_gate_result",
            agentRole: "triage",
            payload: {
              findingId: finding.id,
              category: finding.category,
              hasPov: pov.hasPov,
              artifactType: pov.artifactType,
              confidence: pov.confidence,
              turnsUsed: pov.turnsUsed,
              reason: pov.reason,
              durationMs: Date.now() - povStart,
            },
            timestamp: Date.now(),
          });
          if (pov.hasPov) {
            pushLayerVerdict(finding, {
              layer: "pov_gate",
              verdict: "pass",
              confidence: pov.confidence,
              reason: `pov_verified(${pov.artifactType}): ${pov.reason}`,
              startedAt: povStart,
            });
            // Boost confidence and attach the working PoC as evidence.
            finding.confidence = Math.max(finding.confidence ?? 0, pov.confidence);
            finding.triageStatus = "accepted";
            finding.triageNote =
              (finding.triageNote ? `${finding.triageNote}; ` : "") +
              `pov_verified(${pov.artifactType}): ${pov.reason}`;
            const existing = finding.evidence.analysis ?? "";
            finding.evidence.analysis =
              `${existing}${existing ? "\n\n" : ""}` +
              `## PoV Artifact (${pov.artifactType})\n${pov.povArtifact ?? ""}\n\n` +
              `## Execution Evidence\n${pov.executionEvidence}`;
          } else if (pov.turnsUsed >= 5 || pov.reason.startsWith("max turns")) {
            const fromSev = finding.severity;
            // Hard gate: no working PoC in budget → downgrade to info.
            finding.severity = "info";
            finding.triageNote =
              (finding.triageNote ? `${finding.triageNote}; ` : "") + "no_pov";
            pushLayerVerdict(finding, {
              layer: "pov_gate",
              verdict: "downgrade",
              confidence: pov.confidence,
              reason: `no_pov in ${pov.turnsUsed} turns: ${pov.reason}`,
              startedAt: povStart,
              changedSeverity: { from: fromSev, to: "info" },
            });
          } else {
            // Agent gave up / runtime error / judge failed — annotate but don't
            // downgrade (the verify agent gets a second shot).
            finding.triageNote =
              (finding.triageNote ? `${finding.triageNote}; ` : "") +
              `pov_failed: ${pov.reason}`;
            pushLayerVerdict(finding, {
              layer: "pov_gate",
              verdict: "pass",
              confidence: pov.confidence,
              reason: `inconclusive: ${pov.reason}`,
              startedAt: povStart,
            });
          }
        } catch (err) {
          pushLayerVerdict(finding, {
            layer: "pov_gate",
            verdict: "error",
            reason: `pov gate threw: ${(err as Error).message}`,
            startedAt: povStart,
          });
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "pov_gate_error",
            agentRole: "triage",
            payload: { findingId: finding.id, error: (err as Error).message },
            timestamp: Date.now(),
          });
        }
      } else {
        pushLayerVerdict(finding, {
          layer: "pov_gate",
          verdict: "skip",
          reason: !features.povGate
            ? "PWNKIT_FEATURE_POV_GATE=0"
            : !nativeApiRuntime
              ? "no native runtime available"
              : "already accepted by upstream layer",
          startedAt: Date.now(),
        });
      }

      db.saveFinding?.(scanId, finding);
      verifyCandidates.push(finding);
    }

    // ── Stage 3: Verification Agent ──
    if (verifyCandidates.length > 0) {
      emit({
        type: "stage:start",
        stage: "verify",
        message: `Verifying ${verifyCandidates.length} findings (${allFindings.length - verifyCandidates.length} rejected by triage)...`,
      });
      db.transitionCaseWorkItem?.(scanId, "blind_verify", "in_progress", {
        owner: "verify-agent",
        summary: `Verification agent is reproducing ${verifyCandidates.length} finding${verifyCandidates.length > 1 ? "s" : ""}.`,
      });
      db.logEvent({
        scanId,
        stage: "verify",
        eventType: "stage_start",
        agentRole: "verify",
        payload: {
          findingCount: verifyCandidates.length,
          triageRejected: allFindings.length - verifyCandidates.length,
        },
        timestamp: Date.now(),
      });

      // ── Self-consistency voting (feature-gated) ──
      // Before the agentic verify agent touches anything, optionally run the
      // structured verify pipeline N=3 times per candidate and take a
      // majority vote. Findings rejected by consensus are dropped from the
      // verify queue and marked as false positives — this is the cheapest
      // remaining FP-reduction knob in the pipeline (~15% in research).
      let consensusFiltered = verifyCandidates;
      if (features.selfConsistencyVerify && nativeApiRuntime) {
        const survivors: Finding[] = [];
        for (const finding of verifyCandidates) {
          try {
            const consensus = await runSelfConsistencyVerify(
              finding,
              config.target,
              nativeApiRuntime,
              { numRuns: 3, temperature: 0.7, earlyStopThreshold: 0.8 },
            );
            db.logEvent?.({
              scanId,
              stage: "verify",
              eventType: "consensus_verify",
              agentRole: "verify",
              payload: {
                findingId: finding.id,
                verdict: consensus.verdict,
                confidence: consensus.confidence,
                agreement: consensus.agreement,
                runCount: consensus.runs.length,
                runVerdicts: consensus.runs.map((r) => r.verdict),
              },
              timestamp: Date.now(),
            });
            emit({
              type: "stage:end",
              stage: "verify",
              message: `Consensus ${consensus.verdict} for ${finding.id} (${Math.round(consensus.confidence * 100)}% agreement across ${consensus.runs.length} runs)`,
            });
            if (consensus.verdict === "rejected") {
              finding.triageStatus = "suppressed";
              finding.triageNote = `rejected by self-consistency vote (${Math.round(consensus.confidence * 100)}% agreement, ${consensus.runs.length} runs)`;
              db.updateFindingStatus?.(finding.id, "false-positive");
              finding.status = "false-positive";
              db.saveFinding?.(scanId, finding);
              continue;
            }
            survivors.push(finding);
          } catch (err) {
            // If consensus verification itself errors, fall through to the
            // agentic verify agent rather than silently dropping the finding.
            db.logEvent?.({
              scanId,
              stage: "verify",
              eventType: "consensus_verify_error",
              agentRole: "verify",
              payload: {
                findingId: finding.id,
                error: err instanceof Error ? err.message : String(err),
              },
              timestamp: Date.now(),
            });
            survivors.push(finding);
          }
        }
        consensusFiltered = survivors;
      }

      if (consensusFiltered.length === 0) {
        emit({
          type: "stage:end",
          stage: "verify",
          message: "All candidates rejected by consensus — skipping agentic verify.",
        });
      } else if (useNative) {
        await runNativeVerify(nativeApiRuntime, db, config, scanId, consensusFiltered, emit);
      } else {
        await runLegacyVerify(legacyRuntime, db, config, scanId, consensusFiltered, emit, dbPath);
      }

      // Merge verification results — DB is source of truth
      const dbFindings = db.getFindings(scanId);
      allFindings = dbFindings.map(dbFindingToFinding);

      // Attach remediation guidance to confirmed/verified findings
      for (const finding of allFindings) {
        if (finding.status !== "false-positive") {
          finding.remediation = generateRemediation(finding);
        }
      }

      db.logEvent({
        scanId,
        stage: "verify",
        eventType: "stage_complete",
        agentRole: "verify",
        payload: {
          verified: allFindings.filter((f) => f.status === "verified").length,
          falsePositive: allFindings.filter((f) => f.status === "false-positive").length,
        },
        timestamp: Date.now(),
      });
      const verifiedCount = allFindings.filter((f) => f.status === "verified").length;
      const falsePositiveCount = allFindings.filter((f) => f.status === "false-positive").length;
      db.transitionCaseWorkItem?.(scanId, "blind_verify", "done", {
        owner: "verify-agent",
        summary: `Verification finished with ${verifiedCount} verified and ${falsePositiveCount} false-positive findings.`,
      });
      db.transitionCaseWorkItem?.(scanId, "consensus", "done", {
        owner: "consensus-agent",
        summary: "Verification evidence has been consolidated into the next decision state.",
      });
      db.transitionCaseWorkItem?.(scanId, "human_review", "todo", {
        owner: "operator",
        summary: "Autonomous verification completed. Operator review is now required.",
      });
      emit({
        type: "stage:end",
        stage: "verify",
        message: `Verification complete: ${allFindings.filter((f) => f.status !== "false-positive").length} confirmed`,
      });
    }

    // ── Remediation: ensure all non-false-positive findings have guidance ──
    for (const finding of allFindings) {
      if (!finding.remediation && finding.status !== "false-positive") {
        finding.remediation = generateRemediation(finding);
      }
    }

    // ── Stage 4: Report ──
    emit({ type: "stage:start", stage: "report", message: "Generating report..." });

    const confirmed = allFindings.filter(
      (f) => f.status !== "false-positive" && f.status !== "discovered",
    ).length;
    const summary = {
      totalAttacks: attackState.turnCount,
      totalFindings: allFindings.length,
      critical: allFindings.filter((f) => f.severity === "critical").length,
      high: allFindings.filter((f) => f.severity === "high").length,
      medium: allFindings.filter((f) => f.severity === "medium").length,
      low: allFindings.filter((f) => f.severity === "low").length,
      info: allFindings.filter((f) => f.severity === "info").length,
    };

    db.completeScan(scanId, summary);

    const report: ScanReport = {
      target: config.target,
      scanDepth: config.depth,
      startedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      durationMs: 0,
      summary,
      findings: allFindings.filter((f) => f.status !== "false-positive"),
      warnings: [],
      benchmarkMeta: {
        attackTurns: attackState.turnCount,
        estimatedCostUsd: attackState.estimatedCostUsd,
        model: config.model,
      },
    };

    // Attach conversation trace (discovery + attack) when available.
    // Only native-mode runs produce messages; legacy CLI runs don't.
    const traceMessages = [
      ...(discoveryState.messages ?? []),
      ...(attackState.messages ?? []),
    ];
    if (traceMessages.length > 0) {
      report.trace = traceMessages;
    }

    // Compute actual duration from DB
    const dbScan = db.getScan(scanId);
    if (dbScan) {
      report.startedAt = dbScan.startedAt;
      report.completedAt = dbScan.completedAt ?? report.completedAt;
      report.durationMs = dbScan.durationMs ?? 0;
    }

    db.logEvent({
      scanId,
      stage: "report",
      eventType: "scan_complete",
      payload: { ...summary, durationMs: report.durationMs },
      timestamp: Date.now(),
    });

    emit({
      type: "stage:end",
      stage: "report",
      message: `Report: ${summary.totalFindings} findings (${confirmed} confirmed)`,
    });

    // Stream final report to the opt-in webhook sink (no-op when unset).
    await postFinalReport(report);

    // If either stage's agent loop bailed because the planner LLM
    // returned an error (e.g. transient Azure OpenAI 5xx), the loop
    // already drained and produced an empty/partial report — but the
    // exit_reason MUST surface as "failed" to the cloud, not
    // "completed". Without this, the cloud persists status='complete'
    // and shows the raw "Error: ..." string as the scan summary,
    // mislabeling a legitimate failure as a clean pass. See
    // pwnkit-cloud scan 3abdf5b7-873d-449b-ab3f-e9a38f05a778 for the
    // reproducer that motivated this branch.
    const planError = attackState?.errorExit ?? discoveryState?.errorExit;
    if (planError) {
      emitScanCompleted("failed", report.findings.length, {
        turnsUsed:
          (discoveryState?.turnCount ?? 0) + (attackState?.turnCount ?? 0),
        summary: planError.error,
      });
    } else {
      emitScanCompleted("completed", report.findings.length, {
        turnsUsed:
          (discoveryState?.turnCount ?? 0) + (attackState?.turnCount ?? 0),
        // `attackState.summary` is the loop's free-text narrative
        // ("Audited lodash, no exploitable sinks found"). `report.summary`
        // is severity counts ({critical, high, medium, low, info}), not
        // narrative — it goes to `findings` field instead.
        summary: attackState?.summary ?? discoveryState?.summary,
      });
    }
    return report;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const blockedSummary = msg.slice(0, 500);
    db.transitionCaseWorkItem?.(scanId, "surface_map", "blocked", { summary: blockedSummary });
    db.transitionCaseWorkItem?.(scanId, "hypothesis", "blocked", { summary: blockedSummary });
    db.transitionCaseWorkItem?.(scanId, "poc_build", "blocked", { summary: blockedSummary });
    db.transitionCaseWorkItem?.(scanId, "blind_verify", "blocked", { summary: blockedSummary });
    db.transitionCaseWorkItem?.(scanId, "consensus", "blocked", { summary: blockedSummary });
    db.failScan(scanId, msg);
    db.logEvent({
      scanId,
      stage: "report",
      eventType: "scan_error",
      payload: { error: msg },
      timestamp: Date.now(),
    });
    emitScanCompleted("failed", allFindings.length);
    throw err;
  } finally {
    // Safety net: if none of the normal exit paths fired (e.g. a synchronous
    // exception bypassed the catch above, or a future refactor adds a new
    // return site), ensure the cloud relay still sees a terminal event.
    if (!emittedScanCompleted) {
      emitScanCompleted("failed", allFindings.length);
    }
    db.close();
  }
}

// ── Shared state type for agent outputs ──

interface AgentOutput {
  findings: Finding[];
  targetInfo: Partial<import("@pwnkit/shared").TargetInfo>;
  summary: string;
  turnCount: number;
  estimatedCostUsd: number;
  /** True when this stage terminated because the cost ceiling was hit. */
  costCeilingExceeded?: boolean;
  /**
   * Set when the agent loop bailed because the planner LLM returned an
   * error (or empty response). Propagated up from `NativeAgentState.errorExit`
   * so the top-level scan can flip `exit_reason` from "completed" to "failed"
   * — the legacy `summary` field still carries the raw "Error: ..." marker
   * for back-compat with older readers.
   */
  errorExit?: { error: string; turn: number };
  /** Full conversation trace (messages) from the agent loop. */
  messages?: NativeMessage[];
}

// ── Native (Claude API) stage runners ──

async function runNativeDiscovery(
  runtime: NativeRuntime,
  db: any,
  config: ScanConfig,
  scanId: string,
  emit: ScanListener,
  apiSpecPromptText?: string,
  getPendingUserMessages?: () => string[],
): Promise<AgentOutput> {
  const isWeb = config.mode === "web";
  const basePrompt = isWeb
    ? webPentestDiscoveryPrompt(config.target, config.auth)
    : discoveryPrompt(config.target, config.auth);
  const systemPrompt = apiSpecPromptText
    ? basePrompt + "\n\n" + apiSpecPromptText
    : basePrompt;
  const tools = isWeb
    ? getToolsForRole("discovery", { webMode: true })
    : getToolsForRole("discovery");

  const state = await runNativeAgentLoop({
    config: {
      role: "discovery",
      systemPrompt,
      tools,
      maxTurns: isWeb ? 12 : 8,
      target: config.target,
      scanId,
      sessionId: db.getSession(scanId, "discovery")?.id,
      authConfig: config.auth,
      scope: config.scopeFile ? loadScope(config.scopeFile) : undefined,
      costCeilingUsd: config.costCeilingUsd,
      costModel: config.model,
    },
    runtime,
    db,
    getPendingUserMessages,
    onEvent: (eventType, payload) => {
      if (eventType === "user:injected") {
        emit({ type: "user:injected", stage: "discovery", message: String(payload.text ?? ""), data: payload });
      }
    },
    onTurn: (turn, toolCalls) => {
      // One sub-action per tool call with a real preview of what the tool
      // was invoked with — e.g. `turn 3: bash: curl -sI https://t/admin`
      // instead of a useless `turn 3: bash`. Uses `stage:start` (not
      // `stage:end`) because the stage is still running; `stage:end` would
      // prematurely mark Discover as ✓ done every turn, which was the exact
      // bug we carried pre-0.7.7.
      if (toolCalls.length === 0) {
        emit({ type: "stage:start", stage: "discovery", message: `turn ${turn}: thinking` });
      } else {
        for (const call of toolCalls) {
          emit({
            type: "stage:start",
            stage: "discovery",
            message: `turn ${turn}: ${toolCallPreview(call)}`,
          });
        }
      }
    },
  });
  return {
    findings: state.findings,
    targetInfo: state.targetInfo,
    summary: state.summary,
    turnCount: state.turnCount,
    estimatedCostUsd: state.estimatedCostUsd,
    errorExit: state.errorExit,
    messages: state.messages,
  };
}

async function runNativeAttack(
  runtime: NativeRuntime,
  db: any,
  config: ScanConfig,
  scanId: string,
  targetInfo: Partial<import("@pwnkit/shared").TargetInfo>,
  categories: string[],
  maxTurns: number,
  emit: ScanListener,
  challengeHint?: string,
  apiSpecPromptText?: string,
  getPendingUserMessages?: () => string[],
): Promise<AgentOutput> {
  const isWeb = config.mode === "web";

  // Detect playwright availability for browser tool
  let hasBrowser = false;
  // @ts-ignore — playwright is an optional dependency
  try { await import("playwright"); hasBrowser = true; } catch { /* playwright not installed */ }

  // Shell-first for web targets: minimal tool set (bash + save_finding + done)
  // White-box mode: add read_file + run_command when source code path is provided
  const hasSource = !!config.repoPath;
  let basePrompt = isWeb
    ? shellPentestPrompt(config.target, config.repoPath, { hasBrowser, auth: config.auth })
    : attackPrompt(config.target, targetInfo, categories, config.auth);
  // Inject API spec knowledge if available
  if (apiSpecPromptText) basePrompt += "\n\n" + apiSpecPromptText;

  // Pre-recon CVE check (white-box mode only). Walk the source tree,
  // run `npm audit` / `pip-audit` against any detected manifests, and
  // surface high/critical advisories as priority leads in the system
  // prompt. Defends against expensive thrash on CVE-tagged challenges
  // like XBEN-030 / XBEN-034 where the agent had source access but no
  // concrete leads and burned $6+ producing 0 findings.
  // Gated behind PWNKIT_FEATURE_PRE_RECON_CVE (default ON in white-box).
  let preReconBlock = "";
  if (hasSource && config.repoPath && features.preReconCve) {
    try {
      const { runPreReconCveCheck, formatPreReconForPrompt } = await import(
        "./pre-recon-cve.js"
      );
      const report = runPreReconCveCheck(config.repoPath);
      const formatted = formatPreReconForPrompt(report);
      if (formatted) {
        preReconBlock = "\n\n" + formatted;
        emit({
          type: "stage:end",
          stage: "discovery",
          message: `Pre-recon CVE check: ${report.advisories.length} high/critical advisor${report.advisories.length === 1 ? "y" : "ies"} across ${report.manifestsScanned.length} manifest${report.manifestsScanned.length === 1 ? "" : "s"} (${report.durationMs}ms)`,
        });
      }
    } catch (err) {
      // Pre-recon must never break the scan
      console.error(
        `[pre-recon-cve] failed: ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  // Phase-4 WordPress pre-recon. Runs three cheap probes against the
  // target; if WP is detected, invokes runWpFingerprint directly (not
  // via the agent loop) and folds the structured CVE leads into the
  // system prompt alongside the source-tree CVE block above. Gated by
  // the `wpFingerprint` feature flag so it stays off in runs where
  // network egress is not wanted. See GitHub issue #83.
  if (isWeb && features.wpFingerprint) {
    try {
      const { runPreReconWordPress, formatPreReconWordPressForPrompt } =
        await import("./pre-recon-cve.js");
      const wpReport = await runPreReconWordPress({
        target: config.target,
      });
      if (wpReport.isWordPress && wpReport.fingerprint) {
        const formatted = formatPreReconWordPressForPrompt(wpReport);
        if (formatted) {
          preReconBlock += "\n\n" + formatted;
          const pluginCount = wpReport.fingerprint.plugins.length;
          const cveCount = wpReport.fingerprint.findings.reduce(
            (sum, f) => sum + f.cves.length,
            0,
          );
          emit({
            type: "stage:end",
            stage: "discovery",
            message: `Pre-recon WordPress: ${pluginCount} plugin${pluginCount === 1 ? "" : "s"} enumerated, ${cveCount} CVE hit${cveCount === 1 ? "" : "s"} (${wpReport.durationMs}ms)`,
          });
        }
      }
    } catch (err) {
      console.error(
        `[pre-recon-wp] failed: ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  // Append challenge hint if provided (standard practice for XBOW benchmarks)
  const systemPrompt =
    (challengeHint ? basePrompt + "\n" + challengeHint : basePrompt) + preReconBlock;

  const shellToolNames = hasSource
    ? [
        "bash",
        ...(hasBrowser ? ["browser"] : []),
        "payload_lookup",
        ...(features.wpFingerprint ? ["wp_fingerprint"] : []),
        ...(features.mongoObjectIdForge ? ["mongo_objectid"] : []),
        "read_file",
        "run_command",
        "spawn_agent",
        "save_finding",
        "done",
      ]
    : [
        "bash",
        ...(hasBrowser ? ["browser"] : []),
        "payload_lookup",
        ...(features.wpFingerprint ? ["wp_fingerprint"] : []),
        ...(features.mongoObjectIdForge ? ["mongo_objectid"] : []),
        "spawn_agent",
        "save_finding",
        "done",
      ];
  const shellTools: import("./agent/types.js").ToolDefinition[] = shellToolNames
    .map((n) => TOOL_DEFINITIONS[n])
    .filter((t): t is import("./agent/types.js").ToolDefinition => t !== undefined);

  const tools = isWeb ? shellTools : getToolsForRole("attack", { hasBrowser });

  const effectiveMaxTurns = isWeb ? Math.max(maxTurns, 15) : maxTurns;

  const cloudSinkCfg = getCloudSinkConfig();
  const onTurnHandler = (turn: number, toolCalls: import("./agent/types.js").ToolCall[]) => {
    // One sub-action per tool call with a full preview (tool + first-order
    // argument) so the verbose TUI can show what the attack agent is
    // actually running on each turn — e.g. `turn 7: bash: nmap -sV t.com`
    // instead of `turn 7: bash`. Compact view still clips to last 3.
    if (toolCalls.length === 0) {
      emit({ type: "stage:start", stage: "attack", message: `turn ${turn}: thinking` });
    } else {
      for (const call of toolCalls) {
        emit({
          type: "stage:start",
          stage: "attack",
          message: `turn ${turn}: ${toolCallPreview(call)}`,
        });
      }
    }

    for (const call of toolCalls) {
      if (call.name === "save_finding") {
        emit({
          type: "finding",
          message: `[${call.arguments.severity}] ${call.arguments.title}`,
          data: call.arguments,
        });
        // Fire-and-forget: stream finding to opt-in webhook sink.
        // Failures are logged in postFinding and never abort the scan.
        void postFinding(call.arguments, cloudSinkCfg);
      }
    }
  };

  // First attempt: give the full budget. The loop's early-stop logic will
  // bail at 50% if no save_finding has been called (retryCount=0 enables this).
  const state = await runNativeAgentLoop({
    config: {
      role: "attack",
      systemPrompt,
      tools,
      maxTurns: effectiveMaxTurns,
      target: config.target,
      scanId,
      scopePath: config.repoPath,
      sessionId: db.getSession(scanId, "attack")?.id,
      retryCount: 0,
      authConfig: config.auth,
      scope: config.scopeFile ? loadScope(config.scopeFile) : undefined,
      costCeilingUsd: config.costCeilingUsd,
      costModel: config.model,
    },
    runtime,
    db,
    getPendingUserMessages,
    onEvent: (eventType, payload) => {
      if (eventType === "user:injected") {
        emit({ type: "user:injected", stage: "attack", message: String(payload.text ?? ""), data: payload });
      }
    },
    onTurn: onTurnHandler,
  });

  // ── Early-stop retry: if no findings by halfway, retry with a different strategy ──
  if (features.earlyStopRetry && state.earlyStopNoProgress) {
    const remainingBudget = effectiveMaxTurns - state.turnCount;

    emit({
      type: "stage:start",
      stage: "attack",
      message: `No findings after ${state.turnCount} turns — retrying with different strategy (${remainingBudget} turns remaining)...`,
    });

    db.logEvent?.({
      scanId,
      stage: "attack",
      eventType: "early_stop_retry",
      agentRole: "attack",
      payload: {
        firstAttemptTurns: state.turnCount,
        remainingBudget,
        attemptSummary: state.attemptSummary,
      },
      timestamp: Date.now(),
    });

    // Build structured progress handoff: prefer LLM-generated summary from
    // the agent loop (richer context, captures reasoning), fall back to regex
    // extraction if the LLM summary wasn't generated.
    let progressSection = "";
    if (features.progressHandoff) {
      if (state.progressSummary) {
        progressSection = `## Previous Attempt — Structured Progress\n\n${state.progressSummary}`;
      } else {
        progressSection = formatProgressHandoff(extractProgressFromAttempt(state.messages));
      }
    }

    const retrySystemPrompt = systemPrompt + `\n\n## RETRY — Previous Attempt Failed\n\nA previous attack attempt used ${state.turnCount} turns and found NOTHING.\n${state.attemptSummary}\n${progressSection}\nYou MUST try a COMPLETELY DIFFERENT approach:\n- Different entry points and endpoints\n- Different vulnerability classes (if SQLi failed, try SSTI/command injection/SSRF/path traversal)\n- Different tools and techniques (if curl failed, try Python scripts; if GET failed, try POST)\n- Different encoding and bypass techniques\n- Look for indirect/second-order vulnerabilities\n\nDo NOT repeat the same strategies. Be creative and aggressive.`;

    const retryState = await runNativeAgentLoop({
      config: {
        role: "attack",
        systemPrompt: retrySystemPrompt,
        tools,
        maxTurns: remainingBudget,
        target: config.target,
        scanId,
        scopePath: config.repoPath,
        retryCount: 1,
        authConfig: config.auth,
      scope: config.scopeFile ? loadScope(config.scopeFile) : undefined,
        costCeilingUsd: config.costCeilingUsd,
        costModel: config.model,
      },
      runtime,
      db,
      getPendingUserMessages,
      onEvent: (eventType, payload) => {
        if (eventType === "user:injected") {
          emit({ type: "user:injected", stage: "attack", message: String(payload.text ?? ""), data: payload });
        }
      },
      onTurn: onTurnHandler,
    });

    // Merge results from both attempts
    const combinedFindings = [...state.findings, ...retryState.findings];
    const totalTurns = state.turnCount + retryState.turnCount;
    const combinedSummary = retryState.findings.length > 0
      ? retryState.summary
      : `First attempt (${state.turnCount} turns): no findings. Retry (${retryState.turnCount} turns): ${retryState.summary}`;

    return {
      findings: combinedFindings,
      targetInfo: { ...state.targetInfo, ...retryState.targetInfo },
      summary: combinedSummary,
      turnCount: totalTurns,
      estimatedCostUsd: state.estimatedCostUsd + retryState.estimatedCostUsd,
      costCeilingExceeded: state.costCeilingExceeded || retryState.costCeilingExceeded,
      // If either attempt bailed on a planner error, surface the latest
      // one (retry takes precedence — it ran most recently).
      errorExit: retryState.errorExit ?? state.errorExit,
      messages: [...state.messages, ...retryState.messages],
    };
  }

  // First attempt completed normally (found something, or exhausted turns).
  // No retry needed.
  return {
    findings: state.findings,
    targetInfo: state.targetInfo,
    summary: state.summary,
    turnCount: state.turnCount,
    estimatedCostUsd: state.estimatedCostUsd,
    costCeilingExceeded: state.costCeilingExceeded,
    errorExit: state.errorExit,
    messages: state.messages,
  };
}

// ── Progress Handoff: extract structured findings from a failed attempt's conversation ──

interface AttemptProgress {
  endpoints: string[];
  credentials: string[];
  technologies: string[];
  attacksTried: string[];
}

/**
 * Regex-extract structured progress from the first attempt's messages.
 * No LLM call — pure pattern matching on tool results.
 */
function extractProgressFromAttempt(messages: NativeMessage[]): AttemptProgress {
  const endpoints = new Set<string>();
  const credentials = new Set<string>();
  const technologies = new Set<string>();
  const attacksTried = new Set<string>();

  // Patterns
  const urlPattern = /https?:\/\/[^\s"'<>)\]}{,]+/g;
  const credPatterns = [
    /(?:login|username|user|email)[\s:="']+([^\s"'<>,;}{)(\]]{2,60})/gi,
    /(?:password|passwd|pass|pwd)[\s:="']+([^\s"'<>,;}{)(\]]{2,60})/gi,
    /(?:token|cookie|session[_-]?id|api[_-]?key|bearer|jwt|authorization)[\s:="']+([^\s"'<>,;}{)(\]]{2,80})/gi,
  ];
  const techPatterns = [
    /(?:server|x-powered-by|x-framework):\s*([^\r\n]+)/gi,
    /(?:express|flask|django|rails|spring|laravel|next\.?js|fastapi|gin|fiber|sinatra|koa)/gi,
    /(?:mysql|postgres(?:ql)?|sqlite|mongodb|redis|mariadb)/gi,
    /(?:php|python|ruby|node(?:\.?js)?|java|golang|go|rust|\.net)/gi,
  ];
  const curlPattern = /curl\s+[^\n]{10,}/g;

  for (const msg of messages) {
    for (const block of msg.content) {
      let text = "";
      if (block.type === "tool_result") {
        text = block.content;
      } else if (block.type === "text") {
        text = block.text;
      } else if (block.type === "tool_use") {
        // Extract curl commands from shell_exec / run_command arguments
        const input = block.input as Record<string, unknown>;
        const cmd = (input.command ?? input.cmd ?? "") as string;
        if (cmd) text = cmd;
        // Also capture the URL from http_request tool
        const url = (input.url ?? "") as string;
        if (url) endpoints.add(url);
      }

      if (!text) continue;

      // Extract URLs/endpoints
      for (const match of text.matchAll(urlPattern)) {
        const u = match[0].replace(/[.,;:!?)}\]]+$/, ""); // strip trailing punctuation
        if (u.length < 200) endpoints.add(u);
      }

      // Extract credentials
      for (const pattern of credPatterns) {
        for (const match of text.matchAll(pattern)) {
          const full = match[0].trim();
          if (full.length < 200) credentials.add(full);
        }
      }

      // Extract technologies
      for (const pattern of techPatterns) {
        for (const match of text.matchAll(pattern)) {
          const tech = (match[1] ?? match[0]).trim();
          if (tech.length < 100) technologies.add(tech);
        }
      }

      // Extract curl commands (as attacks tried)
      for (const match of text.matchAll(curlPattern)) {
        const cmd = match[0].trim();
        if (cmd.length < 300) attacksTried.add(cmd);
      }
    }
  }

  return {
    endpoints: [...endpoints].slice(0, 30),
    credentials: [...credentials].slice(0, 20),
    technologies: [...technologies].slice(0, 15),
    attacksTried: [...attacksTried].slice(0, 25),
  };
}

/** Format extracted progress into a section for the retry system prompt. */
function formatProgressHandoff(progress: AttemptProgress): string {
  const sections: string[] = ["## Previous Attempt Summary", ""];

  if (progress.endpoints.length > 0) {
    sections.push("### URLs/Endpoints Discovered");
    for (const ep of progress.endpoints) sections.push(`- ${ep}`);
    sections.push("");
  }

  if (progress.credentials.length > 0) {
    sections.push("### Credentials / Tokens Found");
    for (const c of progress.credentials) sections.push(`- ${c}`);
    sections.push("");
  }

  if (progress.technologies.length > 0) {
    sections.push("### Technologies Identified");
    for (const t of progress.technologies) sections.push(`- ${t}`);
    sections.push("");
  }

  if (progress.attacksTried.length > 0) {
    sections.push("### Attacks Already Tried (do NOT repeat these)");
    for (const a of progress.attacksTried) sections.push(`- \`${a}\``);
    sections.push("");
  }

  // Only return if we actually extracted something useful
  const hasContent = progress.endpoints.length > 0
    || progress.credentials.length > 0
    || progress.technologies.length > 0
    || progress.attacksTried.length > 0;

  return hasContent ? sections.join("\n") : "";
}

/** Format targetInfo from the discovery stage into a human-readable summary for the web attack prompt. */
function formatWebDiscoveryInfo(targetInfo: Partial<import("@pwnkit/shared").TargetInfo>): string {
  const parts: string[] = [];
  if (targetInfo.type) parts.push(`Type: ${targetInfo.type}`);
  if (targetInfo.model) parts.push(`Server/Framework: ${targetInfo.model}`);
  if (targetInfo.endpoints?.length) {
    parts.push(`Discovered endpoints:\n${targetInfo.endpoints.map((e) => `  - ${e}`).join("\n")}`);
  }
  if (targetInfo.detectedFeatures?.length) {
    parts.push(`Features: ${targetInfo.detectedFeatures.join(", ")}`);
  }
  if (targetInfo.systemPrompt) {
    parts.push(`Additional info: ${targetInfo.systemPrompt.slice(0, 1000)}`);
  }
  return parts.length > 0 ? parts.join("\n") : "No prior discovery information available. Start by crawling the target.";
}

async function runNativeVerify(
  runtime: NativeRuntime,
  db: any,
  config: ScanConfig,
  scanId: string,
  findings: Finding[],
  emit: ScanListener,
): Promise<void> {
  await runNativeAgentLoop({
    config: {
      role: "verify",
      systemPrompt: verifyPrompt(config.target, findings, config.auth),
      tools: getToolsForRole("verify", { hasScope: !!config.repoPath }),
      maxTurns: Math.min(findings.length * 3, 15),
      target: config.target,
      scanId,
      sessionId: db.getSession(scanId, "verify")?.id,
      authConfig: config.auth,
      scope: config.scopeFile ? loadScope(config.scopeFile) : undefined,
      costCeilingUsd: config.costCeilingUsd,
      costModel: config.model,
    },
    runtime,
    db,
    onTurn: (turn, toolCalls) => {
      // One sub-action per tool call with a full preview, matching the
      // discovery and attack handlers. Without this the verify stage is
      // completely silent in the TUI, even under verbose mode.
      if (toolCalls.length === 0) {
        emit({ type: "stage:start", stage: "verify", message: `turn ${turn}: thinking` });
      } else {
        for (const call of toolCalls) {
          emit({
            type: "stage:start",
            stage: "verify",
            message: `turn ${turn}: ${toolCallPreview(call)}`,
          });
        }
      }
    },
  });
}

// ── Legacy (text-based) stage runners ──

async function runLegacyDiscovery(
  runtime: import("./runtime/types.js").Runtime,
  db: any,
  config: ScanConfig,
  scanId: string,
  emit: ScanListener,
  dbPath?: string,
  apiSpecPromptText?: string,
): Promise<AgentOutput> {
  const isWeb = config.mode === "web";
  const basePrompt = isWeb
    ? webPentestDiscoveryPrompt(config.target, config.auth)
    : discoveryPrompt(config.target, config.auth);
  const systemPrompt = apiSpecPromptText
    ? basePrompt + "\n\n" + apiSpecPromptText
    : basePrompt;
  const tools = isWeb
    ? getToolsForRole("discovery", { webMode: true })
    : getToolsForRole("discovery");

  const state = await runAgentLoop({
    config: {
      role: "discovery",
      systemPrompt,
      tools,
      maxTurns: isWeb ? 12 : 8,
      target: config.target,
      scanId,
      sessionId: db?.getSession(scanId, "discovery")?.id,
      attachTargetToolsMcp: true,
      dbPath,
      authConfig: config.auth,
      scope: config.scopeFile ? loadScope(config.scopeFile) : undefined,
    },
    runtime,
    db,
    onTurn: (turn, msg) => {
      // Sub-action while the stage is still running — must be `stage:start`,
      // not `stage:end`, or the UI marks Discover as ✓ done every turn.
      const preview = msg.content.replace(/\s+/g, " ").trim().slice(0, 100);
      emit({
        type: "stage:start",
        stage: "discovery",
        message: `turn ${turn}: ${preview}`,
      });
    },
  });
  return {
    findings: state.findings,
    targetInfo: state.targetInfo,
    summary: state.summary,
    turnCount: state.turnCount,
    estimatedCostUsd: 0, // Legacy runtime does not track token usage
  };
}

async function runLegacyAttack(
  runtime: import("./runtime/types.js").Runtime,
  db: any,
  config: ScanConfig,
  scanId: string,
  targetInfo: Partial<import("@pwnkit/shared").TargetInfo>,
  categories: string[],
  maxTurns: number,
  emit: ScanListener,
  dbPath?: string,
  apiSpecPromptText?: string,
): Promise<AgentOutput> {
  const isWeb = config.mode === "web";

  // Detect playwright availability for browser tool (mirrors native path)
  let hasBrowser = false;
  // @ts-ignore — playwright is an optional dependency
  try { await import("playwright"); hasBrowser = true; } catch { /* playwright not installed */ }

  let baseAttackPrompt = isWeb
    ? webPentestAttackPrompt(config.target, formatWebDiscoveryInfo(targetInfo), config.auth)
    : attackPrompt(config.target, targetInfo, categories, config.auth);
  if (apiSpecPromptText) baseAttackPrompt += "\n\n" + apiSpecPromptText;
  const systemPrompt = baseAttackPrompt;
  const tools = isWeb
    ? getToolsForRole("attack", { webMode: true, hasBrowser })
    : getToolsForRole("attack", { hasBrowser });

  const state = await runAgentLoop({
    config: {
      role: "attack",
      systemPrompt,
      tools,
      maxTurns: isWeb ? Math.max(maxTurns, 25) : maxTurns,
      target: config.target,
      scanId,
      sessionId: db?.getSession(scanId, "attack")?.id,
      attachTargetToolsMcp: true,
      dbPath,
      authConfig: config.auth,
      scope: config.scopeFile ? loadScope(config.scopeFile) : undefined,
    },
    runtime,
    db,
    onTurn: (turn, msg) => {
      const calls = msg.toolCalls ?? [];
      // One sub-action per tool call with a full preview (tool + first-
      // order argument), same as the native-API path. Previously this
      // handler only emitted finding events; the verbose TUI showed an
      // empty actions list between finding discoveries.
      if (calls.length === 0) {
        emit({ type: "stage:start", stage: "attack", message: `turn ${turn}: thinking` });
      } else {
        for (const call of calls) {
          emit({
            type: "stage:start",
            stage: "attack",
            message: `turn ${turn}: ${toolCallPreview(call)}`,
          });
        }
      }

      const cloudSinkCfg = getCloudSinkConfig();
      for (const call of calls) {
        if (call.name === "save_finding") {
          emit({
            type: "finding",
            message: `[${call.arguments.severity}] ${call.arguments.title}`,
            data: call.arguments,
          });
          void postFinding(call.arguments, cloudSinkCfg);
        }
      }
    },
  });
  return {
    findings: state.findings,
    targetInfo: state.targetInfo,
    summary: state.summary,
    turnCount: state.turnCount,
    estimatedCostUsd: 0, // Legacy runtime does not track token usage
  };
}

async function runLegacyVerify(
  runtime: import("./runtime/types.js").Runtime,
  db: any,
  config: ScanConfig,
  scanId: string,
  findings: Finding[],
  _emit: ScanListener,
  dbPath?: string,
): Promise<void> {
  await runAgentLoop({
    config: {
      role: "verify",
      systemPrompt: verifyPrompt(config.target, findings, config.auth),
      tools: getToolsForRole("verify", { hasScope: !!config.repoPath }),
      maxTurns: Math.min(findings.length * 3, 15),
      target: config.target,
      scanId,
      sessionId: db?.getSession(scanId, "verify")?.id,
      attachTargetToolsMcp: true,
      dbPath,
      authConfig: config.auth,
      scope: config.scopeFile ? loadScope(config.scopeFile) : undefined,
    },
    runtime,
    db,
  });
}

// ── Helper: convert DB finding row to Finding type ──

function dbFindingToFinding(dbf: {
  id: string;
  templateId: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  status: string;
  confidence: number | null;
  cvssVector: string | null;
  cvssScore: number | null;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis: string | null;
  pocSteps?: string | null;
  layerVerdicts?: string | null;
  timestamp: number;
}): Finding {
  let layerVerdicts: LayerVerdict[] | undefined;
  if (dbf.layerVerdicts) {
    try {
      const parsed = JSON.parse(dbf.layerVerdicts) as unknown;
      if (Array.isArray(parsed)) layerVerdicts = parsed as LayerVerdict[];
    } catch {
      // Corrupt or legacy row — drop the field rather than crashing the
      // hydration. The triage stage will repopulate on the next scan.
    }
  }
  let pocSteps: PocStep[] | undefined;
  if (dbf.pocSteps) {
    try {
      const parsed = JSON.parse(dbf.pocSteps) as unknown;
      // Validate each element via the same predicate the agent tool path uses,
      // so a half-corrupt array degrades to "drop bad steps" rather than
      // letting malformed rows escape into Finding.pocSteps.
      const valid = parsePocStepsArg(parsed);
      if (valid && valid.length > 0) {
        pocSteps = valid;
      }
    } catch {
      // Corrupt or legacy row — drop the field rather than crashing
      // hydration. The agent loop is free to repopulate on a future scan.
    }
  }
  return {
    id: dbf.id,
    templateId: dbf.templateId,
    title: dbf.title,
    description: dbf.description,
    severity: dbf.severity as Finding["severity"],
    category: dbf.category as Finding["category"],
    status: dbf.status as Finding["status"],
    confidence: dbf.confidence ?? undefined,
    cvssVector: dbf.cvssVector ?? undefined,
    cvssScore: dbf.cvssScore ?? undefined,
    evidence: {
      request: dbf.evidenceRequest,
      response: dbf.evidenceResponse,
      analysis: dbf.evidenceAnalysis ?? undefined,
    },
    ...(pocSteps ? { pocSteps } : {}),
    ...(layerVerdicts ? { layerVerdicts } : {}),
    ...(pocSteps ? { pocSteps } : {}),
    timestamp: dbf.timestamp,
  };
}
