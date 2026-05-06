import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import type { Finding, PocStep } from "@pwnkit/shared";

export interface PocExecutionTarget {
  baseUrl?: string;
  personas?: Record<string, { cookies?: string; headers?: Record<string, string> }>;
  env?: Record<string, string>;
  cwd?: string;
  timeoutMs?: number;
  totalTimeoutMs?: number;
}

export type PocPredicateState = "passed" | "failed" | "skipped" | "not-applicable";

export interface PocStepResult {
  stepId: string;
  kind: "setup" | "auth" | "prerequisite" | "exploit" | "verify";
  executed: boolean;
  stdout?: string;
  stderr?: string;
  httpStatus?: number;
  httpBody?: string;
  exitCode?: number;
  durationMs: number;
  predicate: PocPredicateState;
  predicateReason?: string;
  raw?: Record<string, unknown>;
  redacted?: Record<string, unknown>;
}

export interface PocExecutionResult {
  findingId: string;
  executedAt: string;
  target: PocExecutionTarget;
  steps: PocStepResult[];
  stillExploitable: boolean;
  summary: string;
}

interface ActionResult {
  executed: boolean;
  stdout?: string;
  stderr?: string;
  httpStatus?: number;
  httpBody?: string;
  exitCode?: number;
  raw?: Record<string, unknown>;
}

function redactSecrets(text: string, target: PocExecutionTarget): string {
  if (!text) return text;
  let out = text;
  const candidates = new Set<string>();
  for (const [k, v] of Object.entries(target.env ?? {})) {
    if (v && /(token|secret|pass|key|cookie|auth)/i.test(k)) candidates.add(v);
  }
  for (const persona of Object.values(target.personas ?? {})) {
    if (persona.cookies) candidates.add(persona.cookies);
    for (const [k, v] of Object.entries(persona.headers ?? {})) {
      if (v && /(token|secret|pass|key|cookie|auth)/i.test(k)) candidates.add(v);
    }
  }
  for (const secret of candidates) {
    if (!secret) continue;
    out = out.split(secret).join("[REDACTED]");
  }
  return out;
}

function absoluteUrl(url: string, baseUrl?: string): string {
  if (/^https?:\/\//i.test(url)) return url;
  if (!baseUrl) return url;
  return new URL(url, baseUrl).toString();
}

async function runShell(cmd: string, target: PocExecutionTarget, timeoutMs: number): Promise<ActionResult> {
  return await new Promise<ActionResult>((resolvePromise) => {
    const child = spawn("sh", ["-lc", cmd], {
      cwd: target.cwd,
      env: { ...process.env, ...(target.env ?? {}) },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let finished = false;

    const timer = setTimeout(() => {
      if (finished) return;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 500).unref();
      finished = true;
      resolvePromise({
        executed: true,
        stdout,
        stderr: `${stderr}\n[timeout after ${timeoutMs}ms]`.trim(),
        exitCode: 124,
        raw: { type: "shell", timedOut: true, cmd, stdout, stderr },
      });
    }, timeoutMs);

    child.stdout.on("data", (d) => {
      stdout += String(d);
    });
    child.stderr.on("data", (d) => {
      stderr += String(d);
    });
    child.on("close", (code) => {
      if (finished) return;
      clearTimeout(timer);
      finished = true;
      resolvePromise({
        executed: true,
        stdout,
        stderr,
        exitCode: code ?? 1,
        raw: { type: "shell", cmd, stdout, stderr },
      });
    });
  });
}

async function runHttp(step: PocStep, target: PocExecutionTarget, timeoutMs: number): Promise<ActionResult> {
  if (step.action.type !== "http") return { executed: false };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const url = absoluteUrl(step.action.url, target.baseUrl);
    const response = await fetch(url, {
      method: step.action.method,
      headers: step.action.headers,
      body: step.action.body,
      signal: controller.signal,
    });
    const body = await response.text();
    return {
      executed: true,
      httpStatus: response.status,
      httpBody: body,
      raw: {
        type: "http",
        request: { method: step.action.method, url, headers: step.action.headers, body: step.action.body },
        response: { status: response.status, headers: Object.fromEntries(response.headers.entries()) },
        body,
      },
    };
  } catch (error) {
    return {
      executed: true,
      stderr: error instanceof Error ? error.message : String(error),
      exitCode: 1,
      raw: { type: "http", error: error instanceof Error ? error.message : String(error) },
    };
  } finally {
    clearTimeout(timer);
  }
}

async function runDocker(step: PocStep, target: PocExecutionTarget, timeoutMs: number): Promise<ActionResult> {
  if (step.action.type !== "docker") return { executed: false };
  const cmd = `docker run ${step.action.image} ${step.action.args.join(" ")}`.trim();
  return await runShell(cmd, target, timeoutMs);
}

function evaluatePredicate(step: PocStep, result: ActionResult): { predicate: PocPredicateState; reason: string } {
  const expect = step.expect ?? (step.kind === "exploit"
    ? (step.action.type === "http" ? { type: "http-status", status: 200 } : { type: "exit-zero" })
    : undefined);

  if (!expect) return { predicate: "not-applicable", reason: "no expect predicate" };

  if (expect.type === "exit-zero") {
    const ok = (result.exitCode ?? 1) === 0;
    return { predicate: ok ? "passed" : "failed", reason: ok ? "exit code 0" : `exit code ${result.exitCode ?? "unknown"}` };
  }

  if (expect.type === "http-status") {
    const expected = Array.isArray(expect.status) ? expect.status : [expect.status];
    const ok = result.httpStatus !== undefined && expected.includes(result.httpStatus);
    return { predicate: ok ? "passed" : "failed", reason: ok ? `status ${result.httpStatus}` : `expected ${expected.join("/")}, got ${result.httpStatus ?? "none"}` };
  }

  if (expect.type === "body-contains") {
    const body = result.httpBody ?? result.stdout ?? "";
    const ok = body.includes(expect.text);
    return { predicate: ok ? "passed" : "failed", reason: ok ? "body contains expected text" : "missing expected text" };
  }

  if (expect.type === "body-matches") {
    const body = result.httpBody ?? result.stdout ?? "";
    const re = new RegExp(expect.pattern);
    const ok = re.test(body);
    return { predicate: ok ? "passed" : "failed", reason: ok ? "body matches regex" : "regex did not match" };
  }

  if (expect.type === "file-exists") {
    const ok = existsSync(resolve(expect.path));
    return { predicate: ok ? "passed" : "failed", reason: ok ? "file exists" : "file missing" };
  }

  return { predicate: "not-applicable", reason: "unsupported predicate" };
}

export async function executePocSteps(finding: Finding, target: PocExecutionTarget): Promise<PocExecutionResult> {
  const stepTimeout = Math.max(1000, target.timeoutMs ?? 30_000);
  const totalTimeout = Math.max(stepTimeout, target.totalTimeoutMs ?? 10 * 60_000);
  const started = Date.now();
  const steps = finding.pocSteps ?? [];
  const results: PocStepResult[] = [];

  for (const step of steps) {
    if (Date.now() - started > totalTimeout) {
      results.push({
        stepId: step.id,
        kind: step.kind,
        executed: false,
        durationMs: 0,
        predicate: "skipped",
        predicateReason: `total timeout (${totalTimeout}ms) exceeded`,
      });
      continue;
    }

    const t0 = Date.now();
    let actionResult: ActionResult;
    if (step.action.type === "note") {
      actionResult = { executed: true, stdout: step.action.text, exitCode: 0, raw: { type: "note" } };
    } else if (step.action.type === "shell") {
      actionResult = await runShell(step.action.cmd, target, stepTimeout);
    } else if (step.action.type === "http") {
      actionResult = await runHttp(step, target, stepTimeout);
    } else {
      actionResult = await runDocker(step, target, stepTimeout);
    }

    const decision = evaluatePredicate(step, actionResult);
    const rawText = JSON.stringify(actionResult.raw ?? {});
    const redactedText = redactSecrets(rawText, target);

    results.push({
      stepId: step.id,
      kind: step.kind,
      executed: actionResult.executed,
      stdout: actionResult.stdout,
      stderr: actionResult.stderr,
      httpStatus: actionResult.httpStatus,
      httpBody: actionResult.httpBody,
      exitCode: actionResult.exitCode,
      durationMs: Date.now() - t0,
      predicate: decision.predicate,
      predicateReason: decision.reason,
      raw: actionResult.raw,
      redacted: JSON.parse(redactedText || "{}"),
    });
  }

  const exploitSteps = results.filter((r) => r.kind === "exploit");
  const stillExploitable = exploitSteps.length > 0
    ? exploitSteps.every((s) => s.predicate === "passed")
    : results.every((s) => s.predicate !== "failed");

  const passed = results.filter((s) => s.predicate === "passed").length;
  const failed = results.filter((s) => s.predicate === "failed").length;
  const skipped = results.filter((s) => s.predicate === "skipped").length;
  const summary = `Executed ${results.length} step(s): ${passed} passed, ${failed} failed, ${skipped} skipped. Exploit verdict: ${stillExploitable ? "still exploitable" : "not reproducible"}.`;

  return {
    findingId: finding.id,
    executedAt: new Date().toISOString(),
    target,
    steps: results,
    stillExploitable,
    summary,
  };
}
