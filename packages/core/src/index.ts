export { scan } from "./scanner.js";
export type { ScanEvent, ScanListener, ScanEventType } from "./scanner.js";
export { agenticScan } from "./agentic-scanner.js";
export type { AgenticScanOptions } from "./agentic-scanner.js";
export { createScanContext, addFinding, addAttackResult, finalize } from "./context.js";
export { sendPrompt, extractResponseText, isMcpTarget } from "./http.js";
export { createRuntime, ProcessRuntime, LlmApiRuntime, OpenRouterRuntime, DEFAULT_ENSEMBLE_MODELS, RUNTIME_REGISTRY, pickRuntimeForStage, detectAvailableRuntimes, getRuntimeInfo } from "./runtime/index.js";
export type { Runtime, RuntimeConfig, RuntimeContext, RuntimeResult, RuntimeType, NativeRuntime, NativeMessage, NativeContentBlock, NativeToolDef, NativeRuntimeResult, OpenRouterConfig } from "./runtime/index.js";
export { buildDeepScanPrompt, buildMcpAuditPrompt, buildSourceAnalysisPrompt } from "./prompts.js";
export { resolveMcpEndpoint, listMcpTools, callMcpTool, discoverMcpTarget, runMcpSecurityChecks } from "./mcp.js";

// Analysis prompts
export { auditAgentPrompt, reviewAgentPrompt } from "./analysis-prompts.js";

// Agent runner
export { runAnalysisAgent } from "./agent-runner.js";
export type { AnalysisAgentOptions } from "./agent-runner.js";

// Package audit
export { packageAudit } from "./audit.js";
export type { PackageAuditOptions } from "./audit.js";

// Source code review
export { sourceReview } from "./review.js";
export type { SourceReviewOptions } from "./review.js";

// Unified pipeline: prepare + static analysis
export { prepare, detectTargetType } from "./prepare.js";
export type { TargetType, PrepareResult, PrepareOptions } from "./prepare.js";
export { runStaticAnalysis } from "./static-analysis.js";
export type { StaticAnalysisResult } from "./static-analysis.js";

// Unified pipeline
export { runPipeline } from "./unified-pipeline.js";
export type { PipelineOptions, PipelineReport } from "./unified-pipeline.js";

// Agent system
export { runAgentLoop, runNativeAgentLoop, ToolExecutor, getToolsForRole, TOOL_DEFINITIONS, features, estimateCost } from "./agent/index.js";
export { runEGATS, runEGATSWithDefaults, scoreEvidence, summariseTree } from "./agent/egats.js";
export type { AttackNode, AttackTreeResult, EGATSConfig, Evidence as EGATSEvidence, NodeStatus as EGATSNodeStatus } from "./agent/egats.js";
export { discoveryPrompt, attackPrompt, verifyPrompt, reportPrompt, sourceVerifyPrompt, researchPrompt, blindVerifyPrompt } from "./agent/prompts.js";
export type {
  AgentRole,
  AgentConfig,
  AgentState,
  AgentMessage,
  ToolDefinition,
  ToolCall,
  ToolResult,
  ToolContext,
  AgentLoopOptions,
  NativeAgentConfig,
  NativeAgentLoopOptions,
  NativeAgentState,
} from "./agent/index.js";

// Strategy racing (best-of-N)
export { raceStrategies, raceWithDefaults, DEFAULT_STRATEGIES } from "./racing.js";
export type { AttackStrategy, RaceConfig, RaceResult, StrategyResult } from "./racing.js";

export type { DBScan, DBFinding, DBTarget, DBAttackResult } from "./db/schema.js";

// API spec parser
export { parseApiSpec } from "./api-spec.js";
export type { ApiSpecSummary, ApiSpecEndpoint, ApiSpecParameter, ApiSpecAuthScheme } from "./api-spec.js";

// Structured verification pipeline
export {
  runStructuredVerify,
  runSelfConsistencyVerify,
  tallyConsensus,
} from "./triage/verify-pipeline.js";
export type {
  VerifyResult,
  StepResult,
  VerifyVerdict,
  VerifyStepName,
  ConsensusResult,
  SelfConsistencyOptions,
  VerifyMemoryOptions,
} from "./triage/verify-pipeline.js";

// Triage memories (Semgrep-style persistent FP learning)
export { MemoryStore, scoreMemory, inferPackage } from "./triage/memories.js";
export type {
  TriageMemory,
  MemoryScope,
  MemoryStoreOptions,
  MemoryDbHandle,
} from "./triage/memories.js";

// PoV (Proof-of-Vulnerability) gate
export { generatePov, judgePovEvidence } from "./triage/pov-gate.js";
export type { PovResult, PovArtifactType, GeneratePovOptions } from "./triage/pov-gate.js";

// Handcrafted feature extractor (45-element vector for triage classifiers)
export { extractFeatures, FEATURE_NAMES } from "./triage/feature-extractor.js";

// Remediation guidance
export { generateRemediation, generateRemediationWithLLM } from "./remediation.js";
export type { Remediation, RemediationCodeExample } from "./remediation.js";

// Adversarial eval runner (fast AI safety scorecard)
export { runEval, getEvalCategories } from "./eval-runner.js";
export type { EvalScorecard, EvalCategoryResult, EvalCategory, EvalCategoryVerdict, EvalVerdict, EvalRunnerOptions } from "./eval-runner.js";

// Scan TUI state reducers (pure, consumed by the CLI's renderScan.ts).
export {
  appendStageAction,
  formatStageDetail,
  normalizeStageAction,
  normalizeStageEndDetail,
  selectVisibleActions,
  truncateStageAction,
  STAGE_ACTION_HISTORY_CAP,
  VERBOSE_ACTIONS_RENDER_CAP,
  COMPACT_ACTIONS_RENDER_CAP,
  COMPACT_ACTION_CHARS,
  VERBOSE_ACTION_CHARS,
  COMPACT_DETAIL_CHARS,
} from "./scan-ui-state.js";
export type { VisibleActions } from "./scan-ui-state.js";

// Tool call preview formatter (pure, used by scan TUI sub-action emission
// in the agentic scanner and reusable by logs / cloud-sink / dashboard).
export { toolCallPreview, summariseTurnToolCalls } from "./agent/tool-preview.js";

// Kernel crash ingest (crash report → Finding pipeline)
export { parseCrashReport, crashToFinding, ingestArtifactsFromDirectory, ingestArtifactsFromFile, ingestFile, ingestDirectory, crashTypeToCategory, crashSeverity } from "./ingest/index.js";

// Kernel crash verification oracle
export { verifyKernelCrash, compileAndRunReproducer, matchCrashSignature, validateCrashReportConsistency } from "./triage/kernel-oracle.js";
export type { KernelOracleResult, ReproducerResult, CrashSignatureMatch, ConsistencyResult } from "./triage/kernel-oracle.js";

// Cloud event-bus sink (PWNKIT_CLOUD_EVENTS=1 → emit `PWNKIT_EVENT_<TYPE>`
// lines on stdout for the pwnkit-cloud worker-controller to relay).
// The CLI entry must call `maybeSubscribeCloudEventSink()` so the sink
// subscribes once; without that call the sink module is dead code and
// the cloud's live-trace UI stays dark for every scan.
export {
  eventBus,
  cloudEventSink,
  maybeSubscribeCloudEventSink,
  isCloudEventSinkActive,
} from "./events/bus.js";

// Live-agent state reducer (CLI TUI panel). Pure transform of
// eventBus payloads into a "what the agent is doing right now"
// snapshot, with replace-in-place semantics so the terminal stays
// readable on long scans.
export {
  hasLiveAgentState,
  reduceLiveAgentState,
} from "./agent/live-agent-state.js";
export type { LiveAgentState } from "./agent/live-agent-state.js";

// Verification spec evaluator (pwnkit#193 / pwnkit-cloud#111). Re-checks a
// finding's `verificationSpec` predicates against a repo on disk so cloud's
// canary watcher (and any OSS caller) can deterministically decide whether
// a finding is still real after upstream changes.
export {
  evaluateVerificationSpec,
  runCliPathTraversalReplayFixture,
} from "./verification/index.js";
export type {
  CliPathTraversalFixtureOptions,
  DeterministicReplayResult,
  PredicateResult,
  ReplayAssertion,
  ReplayCommand,
  ReplayStatus,
  VerificationResult,
} from "./verification/index.js";

// Disclosure bundle assembly (finding → GHSA-ready advisory markdown)
export { suggestCwesForCategory, formatCweSection, suggestCvss, renderAdvisoryMarkdown, EmptyPocError, redactSensitiveHeaders, renderExploitScreenshot, isFreezeAvailable, composeExploitSession, composeStepSession, verifyAgainstRef, extractFileRefs, formatPatchStatusSection, detectVersionRange, formatVersionRangeLine, extractSiblingFix, executePocSteps, setRuntimeDeps, MAX_CAPTURE_BYTES, DEFAULT_STEP_TIMEOUT_MS, decideFilingState, assembleBundleIndex, formatDroppedReason, droppedFilename, dropSlug } from "./disclose/index.js";
export type { CweEntry, CvssSuggestion, AdvisoryContext, AdvisoryScreenshot, RenderedAdvisory, ScreenshotResult, ScreenshotOptions, PatchStatus, FileRef, ReverifyResult, ReverifyOptions, VersionRangeResult, VersionRangeOptions, SiblingFixCandidate, SiblingFixOptions, PocExecutionTarget, PocExecutionReport, PocStepResult, PocStepVerdict, PocOverallVerdict, FilingState, BundleEntry, AssembleIndexOptions } from "./disclose/index.js";
