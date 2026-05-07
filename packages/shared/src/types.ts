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
  /**
   * Path to a JSON scope file (pwnkit#215). Format: `{ "in_scope": [...],
   * "out_of_scope": [...] }` with rules of the form `host`, `*.domain`,
   * or `cidr/prefix`. When set, every URL the agent touches is checked
   * against this policy and out-of-scope URLs return as
   * `ToolResult.error`. The CLI pre-validates `--target` is in scope
   * before the agent boots; out-of-scope target = hard exit.
   */
  scopeFile?: string;
  /**
   * Per-host token-bucket rate-limit specification (#214). Accepts a
   * plain rps (`"5"` / `"10:25"` for rps:burst) or a comma-separated
   * mixture of per-host overrides plus a default
   * (`"api.example.com=5,*.example.com=3:6,2"`). When unset, scan
   * applies a conservative 5 rps default; set to disable
   * (semantically: `"0"` is rejected as invalid — a missing flag is
   * the way to disable, when we add an opt-out).
   */
  rateLimit?: string;
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
  /**
   * Ordered proof-of-concept step graph (pwnkit#170). Optional and additive —
   * findings produced before this field existed leave it undefined, and every
   * renderer/exporter/sink must continue to work in that case. When populated,
   * downstream consumers (screenshot renderer, behavioural re-verify, advisory
   * markdown) prefer this structured form over the prose `evidence.*` strings.
   */
  pocSteps?: PocStep[];
  /**
   * Machine-executable verification contract (pwnkit#193 / pwnkit-cloud#111).
   * Optional and additive. When populated, cloud's canary watcher (and any
   * OSS caller) can re-evaluate whether the finding is still real against
   * a fresh checkout of the target repo. See {@link VerificationSpec}.
   */
  verificationSpec?: VerificationSpec;
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

// ── PoC Step Graph (pwnkit#170) ──────────────────────────────────────────────
//
// Today, `Finding.evidence` is three free-text strings. Everything downstream
// that wants to *act* on the PoC — multi-frame screenshot rendering, behavioural
// re-verification (pwnkit#171), advisory rendering, machine-checkable
// verification specs — has to re-parse that prose.
//
// `pocSteps` formalises the proof-of-concept as an ordered list of named
// steps. Each step has a `kind` (setup / auth / prerequisite / exploit /
// verify), a one-line `summary` that captions the step in screenshots and
// advisories, an `action` (shell / http / docker / note), and an optional
// `expect` predicate that downstream executors check to decide pass/fail.
//
// The field is OPTIONAL and ADDITIVE. Existing findings produced before this
// type existed have `pocSteps === undefined` and continue to round-trip
// unchanged through every renderer, exporter, the DB, and the cloud sink.

/** Stage of a PoC step in the discover → exploit → verify lifecycle. */
export type PocStepKind = "setup" | "auth" | "prerequisite" | "exploit" | "verify";

/**
 * Action of a PoC step. Discriminated union keyed on `type`. Exactly one
 * variant is set; downstream executors switch on `type` to dispatch.
 *
 * - `shell` — a command to run in a shell. `cwd` is optional and defaults to
 *   the executor's working directory.
 * - `http` — a single HTTP request. `headers`/`body` optional.
 * - `docker` — a docker run with image + args, used when the PoC needs a
 *   side-container (e.g. attacker-controlled HTTP listener).
 * - `note` — operator-narrated, non-executable step. Renders into screenshots
 *   and advisories but is skipped by the behavioural re-verify executor.
 */
export type PocStepAction =
  | { type: "shell"; cmd: string; cwd?: string }
  | {
      type: "http";
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: string;
    }
  | { type: "docker"; image: string; args: string[] }
  | { type: "note"; text: string };

/**
 * Predicate the behavioural re-verify executor checks after running an action.
 * If `expect` is undefined the step is treated as informational and any
 * non-throwing execution counts as pass.
 *
 * - `exit-zero` — process exited 0 (only meaningful for shell/docker).
 * - `http-status` — HTTP status equals the given code or is a member of the
 *   given set.
 * - `body-contains` — response body contains the given substring (HTTP) or
 *   stdout contains it (shell/docker).
 * - `body-matches` — response body matches the given regex pattern.
 * - `file-exists` — the named path exists after the step ran.
 */
export type PocStepExpect =
  | { type: "exit-zero" }
  | { type: "http-status"; status: number | number[] }
  | { type: "body-contains"; text: string }
  | { type: "body-matches"; pattern: string }
  | { type: "file-exists"; path: string };

export interface PocStep {
  /** Stable identifier — used by the screenshot renderer to name its output. */
  id: string;
  /** Lifecycle stage of this step. */
  kind: PocStepKind;
  /** One-line description shown as caption in screenshots and the advisory. */
  summary: string;
  /** How to execute this step. Exactly one variant set. */
  action: PocStepAction;
  /**
   * Optional predicate the re-verify executor checks. When present, the step
   * counts as pass only if the predicate is satisfied; otherwise the step is
   * informational.
   */
  expect?: PocStepExpect;
}

// ── Verification Spec (pwnkit#193 / pwnkit-cloud#111) ───────────────────────
//
// A `VerificationSpec` is a *machine-executable* contract attached to a
// finding. It answers a single question: "is this finding still real?".
//
// The engine emits the spec when it produces a finding. Cloud (and OSS
// callers) can later evaluate it against a fresh checkout of the target
// repo to decide if the underlying vulnerability has been patched, partially
// fixed, or is still exploitable — without re-running the full LLM agent.
//
// The spec is split into two layers:
//
// 1. `code[]` — pure code-level predicates. Cheap, deterministic, no target
//    provisioning required. All predicates must pass for the finding to
//    still count as vulnerable. If any fails, surface as `partial-fix`.
//
// 2. `behavior` — optional behavioural predicate. Requires a provisioned
//    target. If present and its exploit predicate fails, the finding is
//    `fixed` regardless of what `code[]` says.
//
// The field is OPTIONAL and ADDITIVE on `Finding`. Existing findings produced
// before this type existed leave it undefined and continue to round-trip
// unchanged through every renderer, exporter, the DB, and the cloud sink.

/**
 * Code-level predicate. Each variant is a discriminated union keyed on
 * `kind`. All paths are repo-relative (resolved against the repoRoot the
 * verifier is given). Patterns are JS regex source strings (so they can
 * be persisted as JSON and re-hydrated cleanly).
 *
 * - `file-contains` — file exists AND its contents match `pattern` (with
 *   optional regex `flags`). The vulnerable shape should still be present.
 * - `file-missing-pattern` — file exists AND its contents do NOT match
 *   `pattern`. Used to assert that a fix-marker (e.g. an `assertAdmin`
 *   call) is still absent.
 * - `file-exists` — file simply exists. Cheapest predicate; useful when
 *   the vulnerable file has a stable name but the shape is hard to pin
 *   with a single regex.
 * - `ast-shape` — tree-sitter query against the file's parsed AST.
 *   Stronger than regex but costs a tree-sitter dependency. Marked as
 *   not-yet-implemented in the OSS verifier; treated as "skipped" when
 *   evaluated, which is conservative (an unimplemented predicate cannot
 *   prove the finding is fixed).
 */
export type VerificationCodePredicate =
  | { kind: "file-contains"; file: string; pattern: string; flags?: string }
  | { kind: "file-missing-pattern"; file: string; pattern: string; flags?: string }
  | { kind: "file-exists"; file: string }
  | { kind: "ast-shape"; file: string; query: string };

/**
 * Behavioural predicate — a single HTTP step the verifier should replay
 * against a provisioned target. `expect` is one of:
 *
 * - `"success"` — any 2xx is fine.
 * - `"forbidden"` — the request is expected to be rejected (4xx, typically
 *   401/403). When the finding is "still vulnerable" the actual response
 *   is a `success`, so a `forbidden` here is the *fix marker*: if the
 *   target is forbidden, the exploit no longer works.
 * - `{ status: number }` — exact status code match.
 *
 * The runtime executor that consumes this is OUT OF SCOPE for the OSS
 * verifier in pwnkit#193 — code predicates only. The shape is recorded
 * here so cloud's canary watcher can dispatch it later.
 */
export interface VerificationBehaviorStep {
  method: string;
  path: string;
  body?: unknown;
  expect: "success" | "forbidden" | { status: number };
}

export interface VerificationBehavior {
  steps: VerificationBehaviorStep[];
}

export interface VerificationSpec {
  /**
   * Code-level predicates that must all be true for the finding to remain
   * vulnerable. Empty array is permitted (means "no code-level signal";
   * verifier returns inconclusive when there is also no `behavior`).
   */
  code: VerificationCodePredicate[];
  /** Optional behavioural predicate. Requires target provisioning. */
  behavior?: VerificationBehavior;
}

// ── Kernel Crash Reports ──

export type CrashType =
  | "kasan-oob"          // KASAN: heap out-of-bounds
  | "kasan-stack-oob"    // KASAN: stack-out-of-bounds
  | "kasan-uaf"          // KASAN: use-after-free
  | "kasan-double-free"  // KASAN: double-free
  | "kasan-invalid-free" // KASAN: invalid-free (freeing non-allocated memory)
  | "kasan-null"         // KASAN: null-ptr-deref
  | "kasan-wild"         // KASAN: wild-memory-access
  | "ubsan"              // UBSAN: undefined behavior (unrecognized subtype)
  | "ubsan-shift"        // UBSAN: shift-out-of-range
  | "ubsan-overflow"     // UBSAN: signed/unsigned integer overflow
  | "ubsan-bounds"       // UBSAN: array-index-out-of-bounds
  | "ubsan-alignment"    // UBSAN: misaligned access
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
