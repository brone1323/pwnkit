/**
 * Feature flags for A/B testing agent improvements.
 * Set via environment variables: PWNKIT_FEATURE_<NAME>=0 to disable.
 * All features are ON by default.
 */
export const features = {
  /** Early-stop at 50% budget if no findings, retry with different strategy */
  earlyStopRetry: env("PWNKIT_FEATURE_EARLY_STOP", true),
  /** Detect A-A-A and A-B-A-B loop patterns, inject warning */
  loopDetection: env("PWNKIT_FEATURE_LOOP_DETECTION", true),
  /** Compress middle messages when context exceeds 30k tokens */
  contextCompaction: env("PWNKIT_FEATURE_CONTEXT_COMPACTION", true),
  /** Exploit script templates in shell prompt (blind SQLi, SSTI, auth chain) */
  scriptTemplates: env("PWNKIT_FEATURE_SCRIPT_TEMPLATES", true),
  /** Dynamic vulnerability playbooks injected after recon phase */
  dynamicPlaybooks: env("PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS", false),
  /** Agent writes plan/creds to disk, injected at reflection checkpoints */
  externalMemory: env("PWNKIT_FEATURE_EXTERNAL_MEMORY", false),
  /** Inject prior attempt findings when retrying */
  progressHandoff: env("PWNKIT_FEATURE_PROGRESS_HANDOFF", false),
  /** Allow the agent to search the web for CVE details, docs, and technique references */
  webSearch: env("PWNKIT_FEATURE_WEB_SEARCH", false),
  /** Run bash commands inside a Kali Docker container with full pentesting toolset */
  dockerExecutor: env("PWNKIT_FEATURE_DOCKER_EXECUTOR", false),
  /** Interactive PTY sessions for exploits requiring interactivity (reverse shells, DB clients, SSH) */
  ptySession: env("PWNKIT_FEATURE_PTY_SESSION", false),
  /** EGATS (Evidence-Gated Attack Tree Search) — beam-search exploration of attack hypotheses */
  egatsTreeSearch: env("PWNKIT_FEATURE_EGATS", false),
  /** Self-consistency voting: run the structured verify pipeline N times and take the majority vote */
  selfConsistencyVerify: env("PWNKIT_FEATURE_CONSENSUS_VERIFY", false),
  /** Adversarial debate: prosecutor vs defender agents debate each finding, skeptical judge decides */
  adversarialDebate: env("PWNKIT_FEATURE_DEBATE", false),
  /** Multi-modal agreement: cross-validate findings against foxguard (Rust pattern scanner) */
  multiModalAgreement: env("PWNKIT_FEATURE_MULTIMODAL", false),
  /** Reachability gate: suppress findings whose sink is not reachable from an application entry point */
  reachabilityGate: env("PWNKIT_FEATURE_REACHABILITY_GATE", false),
  /** PoV gate: require a working, executable PoC per finding or downgrade to info */
  povGate: env("PWNKIT_FEATURE_POV_GATE", false),
  /** Semgrep-style per-target persistent FP memories injected into the verify pipeline */
  triageMemories: env("PWNKIT_FEATURE_TRIAGE_MEMORIES", false),
};

function env(key: string, defaultValue: boolean): boolean {
  const val = process.env[key];
  if (val === undefined) return defaultValue;
  return val !== "0" && val !== "false";
}
