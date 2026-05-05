/**
 * pwnkit#194 — `pwnkit verify` command.
 *
 * Wraps `executePocSteps` (the deterministic-replay runtime introduced in
 * pwnkit#171, see `packages/core/src/disclose/poc-runtime.ts`) behind a
 * single CLI surface so cloud's worker-controller (pwnkit-cloud#193) can
 * shell out to the OSS engine instead of re-implementing replay logic
 * in-process.
 *
 * Contract:
 *   - Read a {@link Finding} from `--finding <path>`.
 *   - Optionally read a {@link PocExecutionTarget} from `--target <path>`.
 *   - Run the finding's `pocSteps` (if any) via `executePocSteps`.
 *   - Emit a JSON {@link VerificationResult} to stdout (or to `--output`).
 *   - Exit 0 (reproduced) / 1 (not_reproduced) / 2 (inconclusive) / 3 (error).
 *
 * Bundle support (`--finding-id <id> --bundle <zip>`) is reserved for a
 * follow-up; the proposed flag is parsed and rejected explicitly so the
 * cloud side can detect engine capability without a silent miss.
 */

import type { Command } from "commander";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  executePocSteps,
  runCliPathTraversalReplayFixture,
  type PocExecutionReport,
  type PocExecutionTarget,
  type PocStepResult,
} from "@pwnkit/core";
import type { Finding, PocStep } from "@pwnkit/shared";
import { VERSION } from "@pwnkit/shared";

// ── Public output schema ────────────────────────────────────────────────────

export type VerificationStatus =
  | "reproduced"
  | "not_reproduced"
  | "inconclusive"
  | "error";

export interface VerificationCommand {
  argv: string[];
  exit_code: number | null;
  stdout_excerpt: string;
  stderr_excerpt: string;
}

export interface VerificationAssertion {
  kind: string;
  passed: boolean;
  detail: string;
}

export interface VerificationResult {
  status: VerificationStatus;
  mode: "deterministic_replay";
  finding_id: string;
  engine_version: string;
  started_at: string;
  completed_at: string;
  commands: VerificationCommand[];
  assertions: VerificationAssertion[];
  artifacts: Record<string, string>;
  summary: string;
  error_reason: string | null;
}

// ── Tunables ────────────────────────────────────────────────────────────────

/** stdout/stderr excerpt cap in the emitted JSON. The runtime caps captures at
 *  1 MiB; the verifier's JSON is meant to be log-sized, so re-cap at 4 KiB
 *  per stream. Cloud-side ingestion can always re-fetch the full bundle. */
export const EXCERPT_BYTES = 4 * 1024;

// ── Pure helpers (exported for unit tests) ──────────────────────────────────

/** Truncate to N bytes with a trailing marker if cut. */
export function excerpt(text: string | undefined, max = EXCERPT_BYTES): string {
  if (!text) return "";
  if (text.length <= max) return text;
  return text.slice(0, max) + "…[truncated]";
}

/** Map `PocOverallVerdict` → public `VerificationStatus`. */
export function statusFromVerdict(
  verdict: PocExecutionReport["overallVerdict"],
): VerificationStatus {
  switch (verdict) {
    case "exploit_still_works":
      return "reproduced";
    case "exploit_broken":
      return "not_reproduced";
    case "could_not_run":
      return "inconclusive";
    default: {
      const _exhaustive: never = verdict;
      void _exhaustive;
      return "inconclusive";
    }
  }
}

/** Map `VerificationStatus` → process exit code per pwnkit#194. */
export function exitCodeForStatus(status: VerificationStatus): number {
  switch (status) {
    case "reproduced":
      return 0;
    case "not_reproduced":
      return 1;
    case "inconclusive":
      return 2;
    case "error":
      return 3;
    default: {
      const _exhaustive: never = status;
      void _exhaustive;
      return 3;
    }
  }
}

/**
 * Render a one-line, deterministic argv slug for a step. The runtime doesn't
 * surface argv directly (shell steps are spawned through `/bin/sh -c`, http
 * steps don't have argv at all), so we synthesise something stable per
 * action kind that's good enough for log triage and downstream search.
 */
function argvForStep(step: PocStep): string[] {
  switch (step.action.type) {
    case "shell":
      return ["/bin/sh", "-c", step.action.cmd];
    case "docker":
      return ["docker", "run", "--rm", ...step.action.args, step.action.image];
    case "http":
      return [step.action.method, step.action.url];
    case "note":
      return ["note", step.id];
    default: {
      const _exhaustive: never = step.action;
      void _exhaustive;
      return ["unknown"];
    }
  }
}

/** Default summary string for the four terminal states. */
function defaultSummary(
  status: VerificationStatus,
  ran: number,
  total: number,
): string {
  switch (status) {
    case "reproduced":
      return `Replay reproduced the finding (${ran}/${total} steps executed).`;
    case "not_reproduced":
      return `Replay completed but the exploit no longer reproduces (${ran}/${total} steps executed).`;
    case "inconclusive":
      return total === 0
        ? "No PoC steps to execute"
        : `Replay was inconclusive (${ran}/${total} steps executed).`;
    case "error":
      return "Verifier failed before reaching a verdict.";
  }
}

/**
 * Build a {@link VerificationResult} from the runtime's report plus the
 * original finding (needed because `PocStepResult` doesn't carry the action
 * or the `expect` predicate — both are on the source `PocStep`).
 */
export function buildVerificationResult(args: {
  finding: Finding;
  report: PocExecutionReport;
  startedAt: string;
  completedAt: string;
}): VerificationResult {
  const { finding, report, startedAt, completedAt } = args;
  const stepsById = new Map<string, PocStep>(
    (finding.pocSteps ?? []).map((s) => [s.id, s]),
  );
  const status = statusFromVerdict(report.overallVerdict);

  const commands: VerificationCommand[] = report.steps
    .filter((r) => r.kind !== "skipped")
    .map((r) => {
      const step = stepsById.get(r.stepId);
      const argv = step ? argvForStep(step) : ["unknown", r.stepId];
      // For http steps the runtime returns observedStatus instead of an exit
      // code; we surface that as the exit_code field so cloud can read a
      // single uniform "did it succeed numerically" signal across step kinds.
      const exit_code =
        typeof r.observedExit === "number"
          ? r.observedExit
          : typeof r.observedStatus === "number"
            ? r.observedStatus
            : null;
      const stdout = r.observedStdout ?? r.observedResponseBody ?? "";
      const stderr = r.observedStderr ?? r.error ?? "";
      return {
        argv,
        exit_code,
        stdout_excerpt: excerpt(stdout),
        stderr_excerpt: excerpt(stderr),
      };
    });

  const assertions: VerificationAssertion[] = [];
  for (const r of report.steps) {
    const step = stepsById.get(r.stepId);
    const expect = step?.expect;
    if (!expect) continue;
    assertions.push({
      kind: expect.type,
      passed: r.kind === "passed",
      detail: assertionDetail(r, expect),
    });
  }

  const ran = report.steps.filter((r) => r.kind !== "skipped").length;
  const total = (finding.pocSteps ?? []).length;

  return {
    status,
    mode: "deterministic_replay",
    finding_id: finding.id,
    engine_version: VERSION,
    started_at: startedAt,
    completed_at: completedAt,
    commands,
    assertions,
    artifacts: {},
    summary: defaultSummary(status, ran, total),
    error_reason: null,
  };
}

function assertionDetail(
  result: PocStepResult,
  expect: NonNullable<PocStep["expect"]>,
): string {
  if (result.kind === "passed") {
    return `${expect.type} passed`;
  }
  if (result.error) return result.error;
  return `${expect.type} did not pass (kind=${result.kind})`;
}

/**
 * Build the `inconclusive` result returned when the finding has no PoC
 * steps to execute. Per #194 spec: status='inconclusive', exit 2.
 */
export function buildNoStepsResult(args: {
  finding: Finding;
  startedAt: string;
  completedAt: string;
}): VerificationResult {
  return {
    status: "inconclusive",
    mode: "deterministic_replay",
    finding_id: args.finding.id,
    engine_version: VERSION,
    started_at: args.startedAt,
    completed_at: args.completedAt,
    commands: [],
    assertions: [],
    artifacts: {},
    summary: "No PoC steps to execute",
    error_reason: null,
  };
}

/** Build the `error` result returned when the verifier itself crashes. */
export function buildErrorResult(args: {
  finding: Finding | null;
  startedAt: string;
  completedAt: string;
  error: unknown;
}): VerificationResult {
  const reason =
    args.error instanceof Error ? args.error.message : String(args.error);
  return {
    status: "error",
    mode: "deterministic_replay",
    finding_id: args.finding?.id ?? "",
    engine_version: VERSION,
    started_at: args.startedAt,
    completed_at: args.completedAt,
    commands: [],
    assertions: [],
    artifacts: {},
    summary: "Verifier failed before reaching a verdict.",
    error_reason: reason,
  };
}

// ── Input parsing ───────────────────────────────────────────────────────────

interface VerifyOpts {
  finding?: string;
  findingId?: string;
  bundle?: string;
  target?: string;
  fixture?: string;
  fixtureMode?: string;
  retainArtifacts?: boolean;
  artifactDir?: string;
  format?: string;
  output?: string;
}

function readJson<T>(path: string, kind: string): T {
  const abs = resolve(path);
  let raw: string;
  try {
    raw = readFileSync(abs, "utf8");
  } catch (err) {
    throw new Error(
      `failed to read ${kind} from ${abs}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  try {
    return JSON.parse(raw) as T;
  } catch (err) {
    throw new Error(
      `failed to parse ${kind} as JSON (${abs}): ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

// ── Main entry point ────────────────────────────────────────────────────────

export interface VerifyOutcome {
  result: VerificationResult;
  exitCode: number;
}

/**
 * Allocate an isolated workspace for shell/docker PoC steps when the caller
 * didn't pass a `--target` (and therefore didn't specify a `cwd`). Without
 * this, Node's `spawn()` falls through to `process.cwd()` — meaning a PoC
 * would execute in the operator's current working directory, which is
 * exactly the kind of "PoC steps touching real user paths" the #194 spec
 * is designed to prevent. We create the dir under `os.tmpdir()` with a
 * recognisable prefix, return both the dir and a cleanup callback to the
 * caller, and the caller is responsible for invoking cleanup once
 * execution completes (or errors out).
 */
function allocateIsolatedWorkspace(): { cwd: string; cleanup: () => void } {
  const cwd = mkdtempSync(join(tmpdir(), "pwnkit-verify-"));
  return {
    cwd,
    cleanup: () => {
      try {
        rmSync(cwd, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup. Leaving a stale tmp dir behind is preferable
        // to throwing in a finally block and masking the real outcome.
      }
    },
  };
}

/**
 * Run the verifier and return the outcome without writing files or exiting.
 * Exposed separately from the commander action so tests can drive it
 * directly without spawning a subprocess.
 *
 * Working-directory contract: if `--target` is supplied and provides a
 * `cwd`, that wins. Otherwise, we always allocate an isolated tmpdir under
 * `os.tmpdir()` and pass that as `target.cwd`, then clean it up when
 * execution completes. PoC shell/docker steps therefore never inherit the
 * caller's `process.cwd()`.
 */
export async function runVerify(opts: {
  findingPath?: string;
  targetPath?: string;
  fixture?: string;
  fixtureMode?: string;
  retainArtifacts?: boolean;
  artifactDir?: string;
}): Promise<VerifyOutcome> {
  const startedAt = new Date().toISOString();
  let finding: Finding | null = null;
  let cleanup: (() => void) | undefined;
  try {
    if (opts.fixture) {
      if (opts.fixture !== "cli-path-traversal") {
        throw new Error(
          `unsupported fixture '${opts.fixture}', supported fixtures: cli-path-traversal`,
        );
      }
      if (
        opts.fixtureMode &&
        opts.fixtureMode !== "vulnerable" &&
        opts.fixtureMode !== "patched"
      ) {
        throw new Error(
          `unsupported --fixture-mode '${opts.fixtureMode}', expected 'vulnerable' or 'patched'`,
        );
      }
      const result = await runCliPathTraversalReplayFixture({
        fixtureMode:
          opts.fixtureMode === "patched" ? "patched" : "vulnerable",
        retainArtifacts: opts.retainArtifacts,
        artifactDir: opts.artifactDir,
        engineVersion: VERSION,
      });
      return { result, exitCode: exitCodeForStatus(result.status) };
    }

    if (!opts.findingPath) {
      throw new Error("missing required flag: --finding <path>");
    }

    finding = readJson<Finding>(opts.findingPath, "finding");
    if (!finding || typeof finding !== "object" || !finding.id) {
      throw new Error(
        "finding JSON is missing required fields (expected at least an `id`)",
      );
    }

    const baseTarget: PocExecutionTarget = opts.targetPath
      ? readJson<PocExecutionTarget>(opts.targetPath, "target")
      : {};

    // Always provide a cwd to the runtime. If the caller's target didn't set
    // one, allocate an isolated tmpdir so PoC steps cannot reach into the
    // operator's process.cwd() (#194 isolation requirement).
    let target: PocExecutionTarget = baseTarget;
    if (!baseTarget.cwd) {
      const isolated = allocateIsolatedWorkspace();
      cleanup = isolated.cleanup;
      target = { ...baseTarget, cwd: isolated.cwd };
    }

    if (!finding.pocSteps || finding.pocSteps.length === 0) {
      const completedAt = new Date().toISOString();
      const result = buildNoStepsResult({ finding, startedAt, completedAt });
      return { result, exitCode: exitCodeForStatus(result.status) };
    }

    const report = await executePocSteps(finding, target);
    const completedAt = new Date().toISOString();
    const result = buildVerificationResult({
      finding,
      report,
      startedAt,
      completedAt,
    });
    return { result, exitCode: exitCodeForStatus(result.status) };
  } catch (err) {
    const completedAt = new Date().toISOString();
    const result = buildErrorResult({
      finding,
      startedAt,
      completedAt,
      error: err,
    });
    return { result, exitCode: exitCodeForStatus(result.status) };
  } finally {
    if (cleanup) cleanup();
  }
}

async function verifyAction(opts: VerifyOpts): Promise<void> {
  // Validate flag combinations early so users get a clear error rather than
  // a confusing "no finding loaded" downstream.
  if (opts.findingId || opts.bundle) {
    if (opts.findingId && !opts.bundle) {
      throw new Error("--finding-id requires --bundle <path>");
    }
    if (opts.bundle && !opts.findingId) {
      throw new Error("--bundle requires --finding-id <id>");
    }
    throw new Error(
      "--finding-id / --bundle is reserved for a follow-up. Use --finding <path> for now.",
    );
  }
  if (opts.fixture && opts.finding) {
    throw new Error("--fixture and --finding are mutually exclusive");
  }
  if ((opts.retainArtifacts || opts.artifactDir) && !opts.fixture) {
    throw new Error("--retain-artifacts / --artifact-dir are only supported with --fixture");
  }
  if (!opts.finding && !opts.fixture) {
    throw new Error("missing required flag: --finding <path>");
  }
  if (opts.format && opts.format !== "json") {
    throw new Error(`unsupported --format '${opts.format}', only 'json' is supported`);
  }

  const outcome = await runVerify({
    findingPath: opts.finding,
    targetPath: opts.target,
    fixture: opts.fixture,
    fixtureMode: opts.fixtureMode,
    retainArtifacts: opts.retainArtifacts,
    artifactDir: opts.artifactDir,
  });

  const json = JSON.stringify(outcome.result, null, 2);
  if (opts.output) {
    writeFileSync(resolve(opts.output), json + "\n", "utf8");
  } else {
    process.stdout.write(json + "\n");
  }
  // Avoid `process.exit()` immediately after a stdout write — Node's docs warn
  // that exit() can truncate pending async writes. Setting `process.exitCode`
  // and returning lets the event loop drain the JSON cleanly before we exit.
  process.exitCode = outcome.exitCode;
}

export function registerVerifyCommand(program: Command): void {
  program
    .command("verify")
    .description(
      "Deterministically replay a finding's PoC steps and emit a verification_result JSON.",
    )
    .option("--finding <path>", "Path to a finding.json (required for now).")
    .option(
      "--finding-id <id>",
      "[reserved] Finding id; pair with --bundle for cloud-bundle mode (not yet implemented).",
    )
    .option(
      "--bundle <path>",
      "[reserved] Artifact bundle zip; pair with --finding-id (not yet implemented).",
    )
    .option(
      "--target <path>",
      "Path to a target.json (PocExecutionTarget: baseUrl, env, cwd, timeoutMs, personas).",
    )
    .option(
      "--fixture <name>",
      "Run a built-in deterministic replay fixture. Supported: cli-path-traversal.",
    )
    .option(
      "--fixture-mode <mode>",
      "Fixture behavior for --fixture: vulnerable or patched.",
      "vulnerable",
    )
    .option(
      "--retain-artifacts",
      "Keep the fixture sandbox, harness script, and stdout/stderr logs.",
      false,
    )
    .option(
      "--artifact-dir <path>",
      "Use this directory as the fixture sandbox root.",
    )
    .option("--format <fmt>", "Output format. Only 'json' is supported.", "json")
    .option(
      "--output <path>",
      "Write the verification_result JSON to this path instead of stdout.",
    )
    .action(async (opts: VerifyOpts) => {
      try {
        await verifyAction(opts);
      } catch (err) {
        // Verifier-infrastructure failure (bad flags, unreadable file, etc.)
        // — distinct from a non-reproduction. Per #194 spec: exit 3.
        const reason = err instanceof Error ? err.message : String(err);
        const now = new Date().toISOString();
        const result: VerificationResult = {
          status: "error",
          mode: "deterministic_replay",
          finding_id: "",
          engine_version: VERSION,
          started_at: now,
          completed_at: now,
          commands: [],
          assertions: [],
          artifacts: {},
          summary: "Verifier failed before reaching a verdict.",
          error_reason: reason,
        };
        const json = JSON.stringify(result, null, 2);
        if (opts.output) {
          try {
            writeFileSync(resolve(opts.output), json + "\n", "utf8");
          } catch {
            process.stderr.write(json + "\n");
          }
        } else {
          process.stdout.write(json + "\n");
        }
        // Same reason as the success path: prefer `process.exitCode` so the
        // pending stderr/stdout JSON write actually flushes before exit.
        process.exitCode = 3;
      }
    });
}
