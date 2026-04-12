// ── Scan Configuration ──

export type ScanDepth = "quick" | "default" | "deep";
export type OutputFormat = "terminal" | "json" | "markdown" | "html" | "sarif" | "pdf";
export type RuntimeMode = "api" | "claude" | "codex" | "gemini" | "auto";
export type ScanMode = "probe" | "deep" | "mcp" | "web";
export type PackageEcosystem = "npm" | "pypi" | "cargo" | "oci";

// ── Authentication ──

export type AuthType = "bearer" | "cookie" | "basic" | "header";

export interface AuthConfigBearer {
  type: "bearer";
  token: string;
}

export interface AuthConfigCookie {
  type: "cookie";
  value: string;
}

export interface AuthConfigBasic {
  type: "basic";
  username: string;
  password: string;
}

export interface AuthConfigHeader {
  type: "header";
  name: string;
  value: string;
}

export type AuthConfig = AuthConfigBearer | AuthConfigCookie | AuthConfigBasic | AuthConfigHeader;

export interface ScanConfig {
  target: string;
  depth: ScanDepth;
  format: OutputFormat;
  runtime?: RuntimeMode;
  mode?: ScanMode;
  repoPath?: string;
  apiKey?: string;
  model?: string;
  templateFilter?: string[];
  maxConcurrency?: number;
  timeout?: number;
  verbose?: boolean;
  auth?: AuthConfig;
  /** Path to an OpenAPI 3.x / Swagger 2.0 spec file for pre-loaded endpoint knowledge */
  apiSpecPath?: string;
  /** Enable best-of-N strategy racing: run multiple attack strategies in parallel, take the first that succeeds */
  race?: boolean;
  /** Enable EGATS (Evidence-Gated Attack Tree Search): beam-search over hypothesis tree */
  egats?: boolean;
  /**
   * Hard per-scan cost ceiling in USD. When set, the cumulative estimated
   * cost is checked after every tool call and the scan aborts cleanly
   * (exit code 4, partial findings preserved) once exceeded. Default
   * undefined → no ceiling, behavior unchanged.
   */
  costCeilingUsd?: number;
}

// ── Attack Templates ──

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AttackCategory =
  | "prompt-injection"
  | "jailbreak"
  | "system-prompt-extraction"
  | "data-exfiltration"
  | "tool-misuse"
  | "output-manipulation"
  | "encoding-bypass"
  | "multi-turn"
  // Source-code audit categories (pwnkit audit)
  | "prototype-pollution"
  | "path-traversal"
  | "command-injection"
  | "code-injection"
  | "regex-dos"
  | "unsafe-deserialization"
  | "information-disclosure"
  | "ssrf"
  | "sql-injection"
  | "xss"
  | "cors"
  | "security-misconfiguration"
  // Memory corruption / binary categories (kernel crash validation)
  | "heap-overflow"
  | "use-after-free"
  | "stack-buffer-overflow"
  | "null-pointer-deref"
  | "integer-overflow"
  | "race-condition"
  | "type-confusion"
  | "double-free";

export interface AttackTemplate {
  id: string;
  name: string;
  category: AttackCategory;
  description: string;
  severity: Severity;
  owaspLlmTop10?: string;
  depth: ScanDepth[];
  payloads: AttackPayload[];
  detection: DetectionRules;
  metadata?: Record<string, unknown>;
}

export interface AttackPayload {
  id: string;
  prompt: string;
  systemContext?: string;
  multiTurn?: string[];
  description?: string;
}

export interface DetectionRules {
  vulnerablePatterns: string[];
  safePatterns?: string[];
  customCheck?: string;
}

// ── Scan Context (shared agent memory) ──

export interface ScanContext {
  config: ScanConfig;
  scanId?: string;
  target: TargetInfo;
  findings: Finding[];
  attacks: AttackResult[];
  warnings: ScanWarning[];
  startedAt: number;
  completedAt?: number;
}

export interface TargetInfo {
  url: string;
  type: "api" | "chatbot" | "agent" | "mcp" | "web-app" | "unknown";
  endpoints?: string[];
  systemPrompt?: string;
  model?: string;
  detectedFeatures?: string[];
}

// ── Findings ──

export type FindingStatus = "discovered" | "verified" | "confirmed" | "scored" | "reported" | "false-positive";
export type FindingTriageStatus = "new" | "accepted" | "suppressed";
export type FindingWorkflowStatus =
  | "backlog"
  | "todo"
  | "agent_review"
  | "in_progress"
  | "human_review"
  | "blocked"
  | "done"
  | "cancelled";

export type CaseTargetType = "ai-app" | "package" | "repository" | "web-app" | "unknown";
export type WorkItemKind =
  | "surface_map"
  | "hypothesis"
  | "poc_build"
  | "blind_verify"
  | "consensus"
  | "human_review";
export type WorkItemStatus = "backlog" | "todo" | "in_progress" | "blocked" | "done" | "cancelled";
export type ArtifactKind = "request" | "response" | "analysis" | "verdicts" | "sessions" | "events";
export type WorkerStatus = "idle" | "claiming" | "running" | "sleeping" | "stopped" | "error";

export interface FindingRemediation {
  summary: string;
  steps: string[];
  codeExample?: { before: string; after: string; language: string };
  references: string[];
}

/**
 * Per-layer triage telemetry. Each entry records what happened when one
 * triage layer (holding-it-wrong, evidence_gate, oracle, …) evaluated a
 * finding: did it pass, reject, downgrade, or skip; what was its confidence;
 * what reason did it give; how long did it take; what did it cost.
 *
 * The array is append-only and ordered by execution. A downstream router
 * model trains on it: given the layerVerdicts a finding accumulates, can a
 * cheaper subset of layers reach the same final verdict?
 *
 * See pwnkit#112 for the design and pwnkit#113 for the dynamic-routing
 * model that consumes this telemetry.
 */
export type TriageLayerName =
  | "holding_it_wrong"
  | "evidence_gate"
  | "reachability"
  | "multi_modal"
  | "oracle"
  | "pov_gate"
  | "structured_verify"
  | "consensus"
  | "memories"
  | "debate"
  | "kernel_oracle";

export type LayerVerdictKind =
  | "pass"      // layer ran and approved the finding
  | "reject"    // layer ran and rejected (suppressed) the finding
  | "downgrade" // layer ran and downgraded severity but kept the finding
  | "skip"      // layer was disabled or didn't run for this finding
  | "error";    // layer threw, finding kept (conservative default)

export interface LayerVerdict {
  layer: TriageLayerName;
  verdict: LayerVerdictKind;
  /** 0.0–1.0 confidence in the verdict, where applicable. */
  confidence?: number;
  /** Short human-readable reason. Stable across runs for the same input. */
  reason: string;
  /** Wall-clock duration of this layer, in milliseconds. */
  durationMs: number;
  /** USD cost of this layer (LLM tokens etc). 0 for regex/grep layers. */
  costUsd: number;
  /** Severity transition if the layer changed it. */
  changedSeverity?: { from: Severity; to: Severity };
}

export interface Finding {
  id: string;
  templateId: string;
  title: string;
  description: string;
  severity: Severity;
  category: AttackCategory;
  status: FindingStatus;
  evidence: Evidence;
  fingerprint?: string;
  triageStatus?: FindingTriageStatus;
  triageNote?: string;
  /**
   * Append-only list of triage layer verdicts, ordered by execution.
   * Empty until the triage stage runs. See {@link LayerVerdict} for details.
   */
  layerVerdicts?: LayerVerdict[];
  workflowStatus?: FindingWorkflowStatus;
  workflowAssignee?: string | null;
  confidence?: number; // 0.0–1.0 agent-assessed confidence
  cvssVector?: string; // CVSS vector string
  cvssScore?: number; // CVSS numeric score (0–10)
  remediation?: FindingRemediation;
  timestamp: number;
}

// ── Agent Verdicts (multi-agent consensus) ──

export type VerdictType = "TRUE_POSITIVE" | "FALSE_POSITIVE" | "UNSURE";

export interface AgentVerdict {
  id: string;
  findingId: string;
  agentRole: string;
  model: string;
  verdict: VerdictType;
  confidence: number; // 0.0–1.0
  reasoning: string;
  timestamp: number;
}

// ── Case / Work Graph ──

export interface CaseRecord {
  id: string;
  target: string;
  targetType: CaseTargetType;
  latestScanId?: string | null;
  status: "open" | "in_progress" | "human_review" | "done" | "cancelled";
  createdAt: string;
  updatedAt: string;
}

export interface WorkItemRecord {
  id: string;
  caseId: string;
  findingFingerprint?: string | null;
  kind: WorkItemKind;
  title: string;
  owner?: string | null;
  status: WorkItemStatus;
  summary?: string | null;
  dependsOn?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ArtifactRecord {
  id: string;
  caseId: string;
  findingFingerprint?: string | null;
  workItemId?: string | null;
  kind: ArtifactKind;
  label: string;
  content?: string | null;
  metadata?: Record<string, unknown> | null;
  createdAt: string;
  updatedAt: string;
}

export interface WorkerRecord {
  id: string;
  role: "orchestrator";
  status: WorkerStatus;
  label: string;
  currentCaseId?: string | null;
  currentWorkItemId?: string | null;
  currentScanId?: string | null;
  pid?: number | null;
  host?: string | null;
  lastError?: string | null;
  heartbeatAt: string;
  startedAt: string;
  updatedAt: string;
}

// ── Pipeline Events (audit trail) ──

export interface PipelineEvent {
  id: string;
  scanId: string;
  stage: string; // PipelineStage or agent role
  eventType: string;
  findingId?: string;
  agentRole?: string;
  payload: Record<string, unknown>;
  timestamp: number;
}

// ── Agent Sessions (resumable state) ──

export interface AgentSessionState {
  id: string;
  scanId: string;
  agentRole: string;
  turnCount: number;
  messages: unknown[]; // serialized conversation
  toolContext: Record<string, unknown>;
  status: "running" | "paused" | "completed" | "failed";
  createdAt: string;
  updatedAt: string;
}

export interface Evidence {
  request: string;
  response: string;
  analysis?: string;
}

// ── Kernel Crash Reports ──

export type CrashType =
  | "kasan-oob"          // KASAN: out-of-bounds
  | "kasan-uaf"          // KASAN: use-after-free
  | "kasan-null"         // KASAN: null-ptr-deref
  | "kasan-wild"         // KASAN: wild-memory-access
  | "ubsan"              // UBSAN: undefined behavior
  | "kernel-bug"         // BUG()/BUG_ON()
  | "kernel-oops"        // Kernel oops
  | "kernel-panic"       // Kernel panic
  | "general-protection" // general protection fault
  | "rcu-stall"          // RCU stall
  | "lockdep"            // Lock dependency violation
  | "unknown";

export interface CrashReport {
  rawText: string;
  crashType: CrashType;
  faultingFunction: string;
  callStack: string[];
  subsystem: string;
  accessType?: "read" | "write";
  accessSize?: number;
  accessAddress?: string;
  allocSite?: string;
  freeSite?: string;
  reproducer?: string;
  reproducerLanguage?: "c" | "syz" | "bash";
  kernelVersion?: string;
  commitHash?: string;
  configFragment?: string;
}

export interface IngestConfig {
  inputPath: string;
  format?: "auto" | "kasan" | "ubsan" | "oops" | "syzkaller" | "generic";
  outputFormat: OutputFormat;
  verbose?: boolean;
}

// ── Attack Results ──

export type AttackOutcome = "vulnerable" | "safe" | "error" | "inconclusive";

export interface AttackResult {
  templateId: string;
  payloadId: string;
  outcome: AttackOutcome;
  request: string;
  response: string;
  latencyMs: number;
  timestamp: number;
  error?: string;
}

// ── Pipeline Stages ──

export type PipelineStage = "discovery" | "source-analysis" | "attack" | "verify" | "report";

export interface StageResult<T = unknown> {
  stage: PipelineStage;
  success: boolean;
  data: T;
  durationMs: number;
  error?: string;
}

// ── Report ──

export interface ScanWarning {
  stage: PipelineStage;
  message: string;
}

/**
 * Reason a scan terminated. Undefined / "completed" means the scan finished
 * normally. "cost_ceiling_exceeded" means the per-scan cost ceiling
 * (`PWNKIT_COST_CEILING_USD` / `--cost-ceiling`) was hit and the scan
 * aborted with partial findings preserved.
 */
export type ScanExitReason = "completed" | "cost_ceiling_exceeded";

export interface ScanReport {
  target: string;
  scanDepth: ScanDepth;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  summary: ReportSummary;
  findings: Finding[];
  warnings: ScanWarning[];
  benchmarkMeta?: {
    attackTurns?: number;
    estimatedCostUsd?: number;
    model?: string;
  };
  /**
   * Reason the scan terminated. Undefined for normal completion. Set to
   * "cost_ceiling_exceeded" when the scan was aborted by the cost ceiling.
   */
  exitReason?: ScanExitReason;
  /** True when the scan was aborted by the per-scan cost ceiling. */
  costCeilingExceeded?: boolean;
  /**
   * Full conversation trace from the agent loop (discovery + attack messages).
   * Populated only when the caller opts in (e.g. benchmark runs). Not included
   * in normal scan output to avoid bloating JSON reports.
   */
  trace?: unknown[];
}

export interface ReportSummary {
  totalAttacks: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// ── Package Audit (pwnkit audit) ──

export interface AuditConfig {
  package: string;
  version?: string;
  ecosystem?: PackageEcosystem;
  depth: ScanDepth;
  format: OutputFormat;
  runtime?: RuntimeMode;
  timeout?: number;
  verbose?: boolean;
  dbPath?: string;
  apiKey?: string;
  model?: string;
  /** Hard cost ceiling in USD; aborts the audit when exceeded. Default: no ceiling. */
  costCeilingUsd?: number;
}

export interface SemgrepFinding {
  ruleId: string;
  message: string;
  severity: string;
  path: string;
  startLine: number;
  endLine: number;
  snippet: string;
  metadata?: Record<string, unknown>;
}

export interface NpmAuditFinding {
  name: string;
  severity: Severity;
  title: string;
  range?: string;
  source?: number | string;
  url?: string;
  via: string[];
  fixAvailable: boolean | string;
}

/**
 * Token usage from an LLM-driven scan / audit / review. Optional because
 * non-LLM runtimes (semgrep-only, deterministic-only) won't populate it.
 */
export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
}

export interface AuditReport {
  package: string;
  version: string;
  ecosystem?: PackageEcosystem;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  semgrepFindings: number;
  npmAuditFindings: NpmAuditFinding[];
  summary: ReportSummary;
  findings: Finding[];
  /** LLM token usage (input + output). Undefined when no LLM agent ran. */
  usage?: TokenUsage;
  /** Estimated USD cost from token usage at the configured model rates. */
  estimatedCostUsd?: number;
}

// ── Source Code Review (pwnkit review) ──

export interface ReviewConfig {
  repo: string;
  depth: ScanDepth;
  format: OutputFormat;
  runtime?: RuntimeMode;
  timeout?: number;
  verbose?: boolean;
  dbPath?: string;
  apiKey?: string;
  model?: string;
  /** Hard cost ceiling in USD; aborts the review when exceeded. Default: no ceiling. */
  costCeilingUsd?: number;
}

export interface ReviewReport {
  repo: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  semgrepFindings: number;
  summary: ReportSummary;
  findings: Finding[];
  /** LLM token usage (input + output). Undefined when no LLM agent ran. */
  usage?: TokenUsage;
  /** Estimated USD cost from token usage at the configured model rates. */
  estimatedCostUsd?: number;
}
