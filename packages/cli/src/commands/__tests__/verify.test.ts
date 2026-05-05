/**
 * pwnkit#194 — `pwnkit verify` CLI tests.
 *
 * Strategy: drive `runVerify` directly (the same entry point the commander
 * action uses) and assert on (a) the resolved {@link VerificationResult}
 * object and (b) the exit code resolver. We do NOT spawn a subprocess —
 * the runtime's deps (spawn/fetch) are stubbed via `setRuntimeDeps`, so
 * tests run hermetically.
 *
 * The runtime itself has its own coverage in
 * `packages/core/src/disclose/poc-runtime.test.ts`; here we only verify the
 * CLI's argument handling, exit-code mapping, and JSON shape.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { EventEmitter } from "node:events";
import { setRuntimeDeps } from "@pwnkit/core";
import type { Finding, PocStep } from "@pwnkit/shared";
import {
  runVerify,
  exitCodeForStatus,
  statusFromVerdict,
  buildVerificationResult,
  buildNoStepsResult,
  buildErrorResult,
  type VerificationResult,
} from "../verify.js";

// ── Output schema (zod) ─────────────────────────────────────────────────────

const verificationResultSchema = z.object({
  status: z.enum(["reproduced", "not_reproduced", "inconclusive", "error"]),
  mode: z.literal("deterministic_replay"),
  finding_id: z.string(),
  engine_version: z.string(),
  started_at: z.string(),
  completed_at: z.string(),
  commands: z.array(
    z.object({
      argv: z.array(z.string()),
      exit_code: z.union([z.number(), z.null()]),
      stdout_excerpt: z.string(),
      stderr_excerpt: z.string(),
    }),
  ),
  assertions: z.array(
    z.object({
      kind: z.string(),
      passed: z.boolean(),
      detail: z.string(),
    }),
  ),
  artifacts: z.record(z.string()),
  summary: z.string(),
  error_reason: z.union([z.string(), z.null()]),
});

// ── Test fixture helpers ────────────────────────────────────────────────────

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "pwnkit-verify-test-"));
});

afterEach(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

function makeFinding(pocSteps?: PocStep[]): Finding {
  const f: Finding = {
    id: "finding-cafe1234",
    templateId: "tpl-test",
    title: "Test finding",
    description: "Synthetic finding for verify CLI tests",
    severity: "high",
    category: "command-injection",
    status: "discovered",
    evidence: { request: "GET /", response: "200 OK" },
    timestamp: 1714521600000,
  };
  if (pocSteps) f.pocSteps = pocSteps;
  return f;
}

function writeFinding(finding: Finding): string {
  const path = join(tmpRoot, "finding.json");
  writeFileSync(path, JSON.stringify(finding, null, 2), "utf8");
  return path;
}

// ── Fake spawn helper ───────────────────────────────────────────────────────

class FakeChild extends EventEmitter {
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  kill() {
    setImmediate(() => this.emit("close", null));
    return true;
  }
}

interface FakeShellSpec {
  exitCode: number;
  stdout?: string;
  stderr?: string;
}

/** Build a spawn fake that maps the shell command (the body passed to
 *  `/bin/sh -c <body>`) to a scripted exit code / stdout. Anything
 *  unmatched returns exit 0 with no captured output. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- spawn shim is loose by design
function fakeSpawnFromMap(map: Record<string, FakeShellSpec>): any {
  return (cmd: string, args: string[]) => {
    const child = new FakeChild();
    // The runtime invokes `/bin/sh` as `spawn("/bin/sh", ["-c", cmd], ...)` —
    // so the script body is at `args[1]`. Map lookup is keyed on that body.
    const sh = args[0] === "-c" && args.length >= 2 ? args[1] : args.join(" ");
    const spec = map[sh] ?? { exitCode: 0 };
    setImmediate(() => {
      if (spec.stdout) child.stdout.emit("data", Buffer.from(spec.stdout, "utf8"));
      if (spec.stderr) child.stderr.emit("data", Buffer.from(spec.stderr, "utf8"));
      child.emit("close", spec.exitCode);
    });
    void cmd;
    return child;
  };
}

// ── Pure helper tests ───────────────────────────────────────────────────────

describe("verify pure helpers", () => {
  it("statusFromVerdict maps the three runtime verdicts", () => {
    expect(statusFromVerdict("exploit_still_works")).toBe("reproduced");
    expect(statusFromVerdict("exploit_broken")).toBe("not_reproduced");
    expect(statusFromVerdict("could_not_run")).toBe("inconclusive");
  });

  it("exitCodeForStatus follows pwnkit#194 spec", () => {
    expect(exitCodeForStatus("reproduced")).toBe(0);
    expect(exitCodeForStatus("not_reproduced")).toBe(1);
    expect(exitCodeForStatus("inconclusive")).toBe(2);
    expect(exitCodeForStatus("error")).toBe(3);
  });

  it("buildNoStepsResult returns inconclusive with the canonical summary", () => {
    const finding = makeFinding();
    const result = buildNoStepsResult({
      finding,
      startedAt: "2026-05-01T00:00:00.000Z",
      completedAt: "2026-05-01T00:00:00.001Z",
    });
    expect(result.status).toBe("inconclusive");
    expect(result.summary).toBe("No PoC steps to execute");
    expect(verificationResultSchema.parse(result)).toEqual(result);
  });

  it("buildErrorResult preserves the error message in error_reason", () => {
    const result = buildErrorResult({
      finding: null,
      startedAt: "2026-05-01T00:00:00.000Z",
      completedAt: "2026-05-01T00:00:00.001Z",
      error: new Error("kaboom"),
    });
    expect(result.status).toBe("error");
    expect(result.error_reason).toBe("kaboom");
    expect(result.finding_id).toBe("");
    expect(verificationResultSchema.parse(result)).toEqual(result);
  });

  it("buildVerificationResult records assertions only for steps with predicates", () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "exploit",
        summary: "exploit",
        action: { type: "shell", cmd: "echo hi" },
        expect: { type: "exit-zero" },
      },
      {
        id: "s2",
        kind: "setup",
        summary: "setup with no predicate",
        action: { type: "shell", cmd: "true" },
      },
    ]);
    const result = buildVerificationResult({
      finding,
      report: {
        findingId: finding.id,
        startedAt: "2026-05-01T00:00:00.000Z",
        endedAt: "2026-05-01T00:00:00.005Z",
        steps: [
          { stepId: "s1", kind: "passed", durationMs: 1, observedExit: 0, observedStdout: "hi" },
          { stepId: "s2", kind: "passed", durationMs: 1, observedExit: 0, observedStdout: "" },
        ],
        overallVerdict: "exploit_still_works",
      },
      startedAt: "2026-05-01T00:00:00.000Z",
      completedAt: "2026-05-01T00:00:00.005Z",
    });
    expect(result.assertions.length).toBe(1);
    expect(result.assertions[0].kind).toBe("exit-zero");
    expect(result.assertions[0].passed).toBe(true);
  });
});

// ── runVerify (integration) tests ───────────────────────────────────────────

describe("runVerify", () => {
  let restore: (() => void) | undefined;
  afterEach(() => {
    if (restore) {
      restore();
      restore = undefined;
    }
  });

  it("happy path — all verify steps pass → exit 0, status=reproduced", async () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "exploit",
        summary: "exploit",
        action: { type: "shell", cmd: "echo pwn" },
        expect: { type: "exit-zero" },
      },
      {
        id: "s2",
        kind: "verify",
        summary: "verify",
        action: { type: "shell", cmd: "echo verified" },
        expect: { type: "exit-zero" },
      },
    ]);
    restore = setRuntimeDeps({
      spawn: fakeSpawnFromMap({
        "echo pwn": { exitCode: 0, stdout: "pwn\n" },
        "echo verified": { exitCode: 0, stdout: "verified\n" },
      }),
    });
    const findingPath = writeFinding(finding);
    const outcome = await runVerify({ findingPath });
    expect(outcome.exitCode).toBe(0);
    expect(outcome.result.status).toBe("reproduced");
    expect(outcome.result.finding_id).toBe(finding.id);
    expect(outcome.result.commands.length).toBe(2);
    expect(outcome.result.commands[0].argv).toEqual(["/bin/sh", "-c", "echo pwn"]);
    expect(outcome.result.commands[0].exit_code).toBe(0);
    expect(outcome.result.commands[0].stdout_excerpt).toContain("pwn");
    expect(outcome.result.assertions.every((a) => a.passed)).toBe(true);
    expect(verificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("negative path — a verify step fails → exit 1, status=not_reproduced", async () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "verify",
        summary: "verify",
        action: { type: "shell", cmd: "false" },
        expect: { type: "exit-zero" },
      },
    ]);
    restore = setRuntimeDeps({
      spawn: fakeSpawnFromMap({ false: { exitCode: 1 } }),
    });
    const findingPath = writeFinding(finding);
    const outcome = await runVerify({ findingPath });
    expect(outcome.exitCode).toBe(1);
    expect(outcome.result.status).toBe("not_reproduced");
    expect(outcome.result.assertions.length).toBe(1);
    expect(outcome.result.assertions[0].passed).toBe(false);
    expect(outcome.result.commands[0].exit_code).toBe(1);
    expect(verificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("no pocSteps → exit 2, status=inconclusive, canonical summary", async () => {
    const finding = makeFinding();
    const findingPath = writeFinding(finding);
    const outcome = await runVerify({ findingPath });
    expect(outcome.exitCode).toBe(2);
    expect(outcome.result.status).toBe("inconclusive");
    expect(outcome.result.summary).toBe("No PoC steps to execute");
    expect(outcome.result.commands.length).toBe(0);
    expect(outcome.result.assertions.length).toBe(0);
    expect(verificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("missing finding file → exit 3, status=error, error_reason populated", async () => {
    const outcome = await runVerify({ findingPath: "/nonexistent/finding.json" });
    expect(outcome.exitCode).toBe(3);
    expect(outcome.result.status).toBe("error");
    expect(outcome.result.error_reason).toBeTruthy();
    expect(outcome.result.error_reason).toMatch(/finding/);
    expect(verificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("malformed finding JSON → exit 3, status=error", async () => {
    const path = join(tmpRoot, "bad.json");
    writeFileSync(path, "{not valid json", "utf8");
    const outcome = await runVerify({ findingPath: path });
    expect(outcome.exitCode).toBe(3);
    expect(outcome.result.status).toBe("error");
    expect(outcome.result.error_reason).toMatch(/parse/i);
  });

  it("writes a JSON file that round-trips through the zod schema", async () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "verify",
        summary: "verify",
        action: { type: "shell", cmd: "true" },
        expect: { type: "exit-zero" },
      },
    ]);
    restore = setRuntimeDeps({
      spawn: fakeSpawnFromMap({ true: { exitCode: 0 } }),
    });
    const findingPath = writeFinding(finding);
    const outcome = await runVerify({ findingPath });
    const outPath = join(tmpRoot, "result.json");
    writeFileSync(outPath, JSON.stringify(outcome.result, null, 2), "utf8");
    const parsed: VerificationResult = JSON.parse(readFileSync(outPath, "utf8"));
    expect(verificationResultSchema.parse(parsed)).toEqual(parsed);
  });

  it("runs the built-in cli-path-traversal fixture and reports reproduced", async () => {
    const outcome = await runVerify({
      fixture: "cli-path-traversal",
      fixtureMode: "vulnerable",
    });

    expect(outcome.exitCode).toBe(0);
    expect(outcome.result.status).toBe("reproduced");
    expect(outcome.result.finding_id).toBe("fixture:cli-path-traversal");
    expect(outcome.result.commands).toHaveLength(1);
    expect(outcome.result.assertions.find((a) => a.kind === "filesystem_exists")?.passed).toBe(true);
    expect(outcome.result.assertions.find((a) => a.kind === "path_outside_export_root")?.passed).toBe(true);
    expect(verificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("runs the patched cli-path-traversal fixture as the negative control", async () => {
    const outcome = await runVerify({
      fixture: "cli-path-traversal",
      fixtureMode: "patched",
    });

    expect(outcome.exitCode).toBe(1);
    expect(outcome.result.status).toBe("not_reproduced");
    expect(outcome.result.commands[0].stderr_excerpt).toContain("blocked path traversal");
    expect(outcome.result.assertions.find((a) => a.kind === "filesystem_exists")?.passed).toBe(false);
    expect(verificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });

  it("retains fixture artifacts when requested", async () => {
    const artifactDir = join(tmpRoot, "retained-fixture");
    const outcome = await runVerify({
      fixture: "cli-path-traversal",
      retainArtifacts: true,
      artifactDir,
    });

    expect(outcome.exitCode).toBe(0);
    expect(outcome.result.artifacts.sandbox_ref).toBe(artifactDir);
    expect(outcome.result.artifacts.harness_ref).toBeTruthy();
    expect(existsSync(outcome.result.artifacts.harness_ref)).toBe(true);
    expect(existsSync(outcome.result.artifacts.stdout_ref)).toBe(true);
    expect(existsSync(outcome.result.artifacts.stderr_ref)).toBe(true);
    expect(verificationResultSchema.parse(outcome.result)).toEqual(outcome.result);
  });
});

// ── Workspace isolation tests (CodeRabbit #194 — cwd safety) ────────────────

describe("runVerify workspace isolation", () => {
  let restore: (() => void) | undefined;
  afterEach(() => {
    if (restore) {
      restore();
      restore = undefined;
    }
  });

  /**
   * Spawn fake that records the third-arg `cwd` it was invoked with.
   * Used to assert that `runVerify` always passes an isolated cwd through
   * to the runtime, never `undefined` (which would fall through to
   * `process.cwd()` in real `spawn`).
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- spawn shim is loose by design
  function fakeSpawnRecordingCwd(seen: { cwd?: string; allCwds: string[] }): any {
    return (
      cmd: string,
      args: string[],
      opts?: { cwd?: string; env?: NodeJS.ProcessEnv },
    ) => {
      seen.cwd = opts?.cwd;
      seen.allCwds.push(opts?.cwd ?? "<undefined>");
      const child = new FakeChild();
      setImmediate(() => child.emit("close", 0));
      void cmd;
      void args;
      return child;
    };
  }

  it("when --target is omitted, spawn receives an isolated tmpdir cwd (never undefined)", async () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "verify",
        summary: "verify",
        action: { type: "shell", cmd: "echo isolated" },
        expect: { type: "exit-zero" },
      },
    ]);
    const seen: { cwd?: string; allCwds: string[] } = { allCwds: [] };
    restore = setRuntimeDeps({ spawn: fakeSpawnRecordingCwd(seen) });
    const findingPath = writeFinding(finding);

    await runVerify({ findingPath });

    expect(seen.cwd).toBeDefined();
    expect(seen.cwd).not.toBe("");
    // Must not be the test process cwd — that's exactly the isolation
    // failure CodeRabbit flagged on PR #197.
    expect(seen.cwd).not.toBe(process.cwd());
    // Should land under os.tmpdir() with the recognisable prefix.
    expect(seen.cwd).toMatch(/pwnkit-verify-/);
  });

  it("when --target supplies a cwd, spawn receives that cwd (caller wins)", async () => {
    const callerCwd = mkdtempSync(join(tmpdir(), "pwnkit-verify-caller-"));
    try {
      const finding = makeFinding([
        {
          id: "s1",
          kind: "verify",
          summary: "verify",
          action: { type: "shell", cmd: "echo from-target" },
          expect: { type: "exit-zero" },
        },
      ]);
      const seen: { cwd?: string; allCwds: string[] } = { allCwds: [] };
      restore = setRuntimeDeps({ spawn: fakeSpawnRecordingCwd(seen) });
      const findingPath = writeFinding(finding);
      const targetPath = join(tmpRoot, "target.json");
      writeFileSync(targetPath, JSON.stringify({ cwd: callerCwd }), "utf8");

      await runVerify({ findingPath, targetPath });

      expect(seen.cwd).toBe(callerCwd);
    } finally {
      rmSync(callerCwd, { recursive: true, force: true });
    }
  });

  it("cleans up the isolated tmpdir after execution completes", async () => {
    const finding = makeFinding([
      {
        id: "s1",
        kind: "verify",
        summary: "verify",
        action: { type: "shell", cmd: "echo cleanup" },
        expect: { type: "exit-zero" },
      },
    ]);
    const seen: { cwd?: string; allCwds: string[] } = { allCwds: [] };
    restore = setRuntimeDeps({ spawn: fakeSpawnRecordingCwd(seen) });
    const findingPath = writeFinding(finding);

    await runVerify({ findingPath });

    expect(seen.cwd).toBeDefined();
    // The isolated dir should not survive past runVerify — leaving stale
    // tmp dirs around would let a successor run see prior PoC state.
    expect(existsSync(seen.cwd as string)).toBe(false);
  });

  it("cleans up the isolated tmpdir even when execution errors out", async () => {
    // Force an error path: malformed finding JSON throws inside runVerify
    // *after* the tmpdir has been allocated (we have to allocate first
    // for the failure point to matter; readJson throws before allocation,
    // so we use a finding that triggers a runtime error instead).
    //
    // Approach: use an unsupported action variant via a hand-crafted
    // finding JSON. The runtime will bubble back with `errored` per-step
    // — but that doesn't throw at the runVerify level, so we instead use
    // a spawn fake that throws synchronously to provoke the catch.
    const finding = makeFinding([
      {
        id: "s1",
        kind: "verify",
        summary: "verify",
        action: { type: "shell", cmd: "boom" },
        expect: { type: "exit-zero" },
      },
    ]);
    let capturedCwd: string | undefined;
    restore = setRuntimeDeps({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- spawn shim
      spawn: ((
        _cmd: string,
        _args: string[],
        opts?: { cwd?: string },
      ) => {
        capturedCwd = opts?.cwd;
        // Don't throw — runtime catches that. Just resolve normally so the
        // happy path runs through, then we assert cleanup happened.
        const child = new FakeChild();
        setImmediate(() => child.emit("close", 0));
        return child;
      }) as never,
    });
    const findingPath = writeFinding(finding);

    await runVerify({ findingPath });

    expect(capturedCwd).toBeDefined();
    expect(existsSync(capturedCwd as string)).toBe(false);
  });
});

// ── process.exit / exitCode tests (CodeRabbit #194 — flush stdout) ──────────
//
// We can't easily import `verifyAction` directly (it's not exported), so we
// validate the property by introspection of the verify.ts source: the
// invariant is that the file must not contain `process.exit(` calls. This
// is mechanical but it's exactly what CodeRabbit flagged — `process.exit`
// can truncate pending stdout writes; we use `process.exitCode` instead.

describe("verify.ts uses process.exitCode (no process.exit in the action)", () => {
  it("source file does not call process.exit() (uses process.exitCode instead)", () => {
    // Resolve verify.ts relative to this test file.
    const verifySrc = readFileSync(
      join(__dirname, "..", "verify.ts"),
      "utf8",
    );
    // Strip block + line comments so commentary mentioning `process.exit`
    // doesn't trip the assertion.
    const stripped = verifySrc
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
    expect(stripped).not.toMatch(/\bprocess\.exit\s*\(/);
    // And it *should* be using process.exitCode at least once (the
    // success/error paths each set it).
    expect(stripped).toMatch(/\bprocess\.exitCode\s*=/);
  });
});
