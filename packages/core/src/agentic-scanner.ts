import type { ScanConfig, ScanReport, Finding } from "@pwnkit/shared";
import { loadTemplates } from "@pwnkit/templates";
import { createRuntime } from "./runtime/index.js";
import { LlmApiRuntime } from "./runtime/llm-api.js";
import { detectAvailableRuntimes } from "./runtime/registry.js";
// DB lazy-loaded to avoid native module issues
import { runAgentLoop } from "./agent/loop.js";
import { runNativeAgentLoop } from "./agent/native-loop.js";
import { getToolsForRole, TOOL_DEFINITIONS } from "./agent/tools.js";
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
} from "./triage/index.js";
import { runSelfConsistencyVerify } from "./triage/verify-pipeline.js";
import { generatePov } from "./triage/pov-gate.js";

export interface AgenticScanOptions {
  config: ScanConfig;
  dbPath?: string;
  onEvent?: ScanListener;
  /** Optional hint/description for benchmark challenges */
  challengeHint?: string;
  /** Resume from a previous scan (uses persisted sessions) */
  resumeScanId?: string;
}

/**
 * Auto-detect whether an HTTP target is a web app vs an AI/API endpoint.
 * If the target serves HTML and the user requested "deep" mode,
 * automatically switch to "web" mode for better coverage.
 */
async function normalizeScanConfig(config: ScanConfig): Promise<ScanConfig> {
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
  const { dbPath, onEvent, resumeScanId } = opts;
  const emit = onEvent ?? (() => {});
  const config = await normalizeScanConfig(opts.config);

  const db = await (async () => { try { const { pwnkitDB } = await import("@pwnkit/db"); return new pwnkitDB(dbPath); } catch { return null as any; } })() as any;

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
  const nativeApiAvailable = await nativeApiRuntime.isAvailable();

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
      ? await runNativeDiscovery(nativeApiRuntime, db, config, scanId, emit, apiSpecPromptText)
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
        ? await runNativeAttack(nativeApiRuntime, db, config, scanId, discoveryState.targetInfo, categories, maxAttackTurns, emit, opts.challengeHint, apiSpecPromptText)
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
      const hiw = isHoldingItWrong(finding);
      const featureVector = extractFeatures(finding);
      const evidenceCompleteness =
        evidenceCompletenessIdx >= 0 ? featureVector[evidenceCompletenessIdx] ?? 0 : 0;

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

      if (hiw.isHoldingItWrong) {
        // Downgrade severity to info and mark rejected. Skip further verify.
        finding.severity = "info";
        finding.triageStatus = "suppressed";
        finding.triageNote = `rejected: holding-it-wrong — ${hiw.reason}`;
        db.updateFindingStatus?.(finding.id, "false-positive");
        finding.status = "false-positive";
        emit({
          type: "stage:end",
          stage: "attack",
          message: `Triage rejected ${finding.id}: ${hiw.reason}`,
        });
        continue;
      }

      if (evidenceCompleteness <= 0.5) {
        finding.triageStatus = "suppressed";
        finding.triageNote = `rejected: evidence_completeness=${evidenceCompleteness.toFixed(2)} <= 0.5`;
        db.updateFindingStatus?.(finding.id, "false-positive");
        finding.status = "false-positive";
        emit({
          type: "stage:end",
          stage: "attack",
          message: `Triage rejected ${finding.id}: insufficient evidence (completeness=${evidenceCompleteness.toFixed(2)})`,
        });
        continue;
      }

      // ── Reachability gate ("Endor Labs moat") ──
      // Opt-in via PWNKIT_FEATURE_REACHABILITY_GATE. Only runs in white-box
      // mode when we have source code. For each finding, check whether the
      // vulnerable sink is actually reachable from an application entry
      // point (HTTP handler, CLI main, route file). Dead code and test-only
      // paths are suppressed before we spend any LLM tokens on verify.
      if (features.reachabilityGate && config.repoPath) {
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
            finding.triageStatus = "suppressed";
            finding.triageNote = `unreachable: ${reach.reason}`;
            db.updateFindingStatus?.(finding.id, "false-positive");
            finding.status = "false-positive";
            emit({
              type: "stage:end",
              stage: "attack",
              message: `Reachability gate rejected ${finding.id}: ${reach.reason}`,
            });
            continue;
          }
        } catch (err) {
          // Reachability check errors must not drop findings silently —
          // let the rest of the pipeline continue.
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
      }

      // ── Multi-modal agreement (foxguard cross-validation) ──
      // Opt-in via PWNKIT_FEATURE_MULTIMODAL. Only runs when we have source
      // code (white-box mode). Cross-checks every finding against the
      // foxguard Rust pattern scanner — if both agents agree, the finding is
      // almost certainly real; if foxguard disagrees and the evidence is
      // thin, we auto-reject. This is the "opensoar-hq trinity" validation.
      if (features.multiModalAgreement && config.repoPath) {
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
            finding.confidence = Math.max(finding.confidence ?? 0, fused.confidence);
            finding.triageStatus = "accepted";
            finding.triageNote = `multi_modal_accept: ${fused.reasoning}`;
          } else if (fused.decision === "auto_reject") {
            finding.severity = "info";
            finding.triageStatus = "suppressed";
            finding.triageNote = `multi_modal_reject: ${fused.reasoning}`;
            db.updateFindingStatus?.(finding.id, "false-positive");
            finding.status = "false-positive";
            emit({
              type: "stage:end",
              stage: "attack",
              message: `Multi-modal rejected ${finding.id}: ${fused.reasoning}`,
            });
            continue;
          } else if (fused.decision === "verify_priority") {
            finding.confidence = Math.max(finding.confidence ?? 0, mm.confidence);
            finding.triageNote = `multi_modal_agree: ${mm.reasoning}`;
          }
        } catch (err) {
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
      }

      // ── Per-class verification oracle ──
      // "No exploit, no report" — attempt a deterministic exploit check for
      // each category we have an oracle for. If the oracle verifies, boost
      // confidence and mark the finding accepted. If it fails and we have an
      // oracle for the category, downgrade severity to low and annotate.
      // Categories without oracles fall through to the LLM-verify stage.
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
          finding.severity = "low";
          finding.triageNote = `oracle_failed: ${oracle.reason}`;
        }
      } catch (err) {
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
        try {
          const povStart = Date.now();
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
            // Hard gate: no working PoC in budget → downgrade to info.
            finding.severity = "info";
            finding.triageNote =
              (finding.triageNote ? `${finding.triageNote}; ` : "") + "no_pov";
          } else {
            // Agent gave up / runtime error / judge failed — annotate but don't
            // downgrade (the verify agent gets a second shot).
            finding.triageNote =
              (finding.triageNote ? `${finding.triageNote}; ` : "") +
              `pov_failed: ${pov.reason}`;
          }
        } catch (err) {
          db.logEvent?.({
            scanId,
            stage: "verify",
            eventType: "pov_gate_error",
            agentRole: "triage",
            payload: { findingId: finding.id, error: (err as Error).message },
            timestamp: Date.now(),
          });
        }
      }

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
    throw err;
  } finally {
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
}

// ── Native (Claude API) stage runners ──

async function runNativeDiscovery(
  runtime: NativeRuntime,
  db: any,
  config: ScanConfig,
  scanId: string,
  emit: ScanListener,
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
    },
    runtime,
    db,
    onTurn: (turn) => {
      emit({ type: "stage:end", stage: "discovery", message: `Discovery turn ${turn}` });
    },
  });
  return {
    findings: state.findings,
    targetInfo: state.targetInfo,
    summary: state.summary,
    turnCount: state.turnCount,
    estimatedCostUsd: state.estimatedCostUsd,
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
  // Append challenge hint if provided (standard practice for XBOW benchmarks)
  const systemPrompt = challengeHint ? basePrompt + "\n" + challengeHint : basePrompt;

  const shellToolNames = hasSource
    ? ["bash", ...(hasBrowser ? ["browser"] : []), "read_file", "run_command", "spawn_agent", "save_finding", "done"]
    : ["bash", ...(hasBrowser ? ["browser"] : []), "spawn_agent", "save_finding", "done"];
  const shellTools: import("./agent/types.js").ToolDefinition[] = shellToolNames
    .map((n) => TOOL_DEFINITIONS[n])
    .filter((t): t is import("./agent/types.js").ToolDefinition => t !== undefined);

  const tools = isWeb ? shellTools : getToolsForRole("attack", { hasBrowser });

  const effectiveMaxTurns = isWeb ? Math.max(maxTurns, 15) : maxTurns;

  const onTurnHandler = (_turn: number, toolCalls: import("./agent/types.js").ToolCall[]) => {
    for (const call of toolCalls) {
      if (call.name === "save_finding") {
        emit({
          type: "finding",
          message: `[${call.arguments.severity}] ${call.arguments.title}`,
          data: call.arguments,
        });
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
    },
    runtime,
    db,
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

    // Build structured progress handoff from the first attempt's conversation
    const progressSection = features.progressHandoff
      ? formatProgressHandoff(extractProgressFromAttempt(state.messages))
      : "";

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
      },
      runtime,
      db,
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
    },
    runtime,
    db,
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
    },
    runtime,
    db,
    onTurn: (turn, msg) => {
      emit({
        type: "stage:end",
        stage: "discovery",
        message: `Discovery turn ${turn}: ${msg.content.slice(0, 100)}...`,
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
    },
    runtime,
    db,
    onTurn: (turn, msg) => {
      const calls = msg.toolCalls ?? [];
      for (const call of calls) {
        if (call.name === "save_finding") {
          emit({
            type: "finding",
            message: `[${call.arguments.severity}] ${call.arguments.title}`,
            data: call.arguments,
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
  timestamp: number;
}): Finding {
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
    timestamp: dbf.timestamp,
  };
}
