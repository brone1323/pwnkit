import { createServer } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { executePocSteps } from "./poc-runtime.js";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-poc-runtime-1",
    templateId: "manual",
    title: "PoC runtime test",
    description: "test",
    severity: "high",
    category: "tool-misuse",
    status: "verified",
    evidence: { request: "", response: "", analysis: "" },
    timestamp: Date.now(),
    ...overrides,
  };
}

const closers: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (closers.length > 0) {
    const close = closers.pop();
    if (close) await close();
  }
});

async function startServer(handler: (url: string, method: string) => { status: number; body: string }): Promise<string> {
  const server = createServer((req, res) => {
    const out = handler(req.url ?? "/", req.method ?? "GET");
    res.statusCode = out.status;
    res.end(out.body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("failed to bind test server");
  closers.push(async () => await new Promise<void>((resolve) => server.close(() => resolve())));
  return `http://127.0.0.1:${addr.port}`;
}

describe("executePocSteps", () => {
  it("handles shell success and failure predicates", async () => {
    const finding = baseFinding({
      pocSteps: [
        {
          id: "ok",
          kind: "setup",
          summary: "ok",
          action: { type: "shell", cmd: "exit 0" },
          expect: { type: "exit-zero" },
        },
        {
          id: "fail",
          kind: "verify",
          summary: "fail",
          action: { type: "shell", cmd: "exit 7" },
          expect: { type: "exit-zero" },
        },
      ],
    });
    const out = await executePocSteps(finding, { timeoutMs: 5000 });
    expect(out.steps[0]?.predicate).toBe("passed");
    expect(out.steps[1]?.predicate).toBe("failed");
  });

  it("handles shell timeout", async () => {
    const finding = baseFinding({
      pocSteps: [{ id: "timeout", kind: "exploit", summary: "sleep", action: { type: "shell", cmd: "sleep 2" }, expect: { type: "exit-zero" } }],
    });
    const out = await executePocSteps(finding, { timeoutMs: 100 });
    expect(out.steps[0]?.exitCode).toBe(124);
    expect(out.steps[0]?.predicate).toBe("failed");
  });

  it("supports http status and body predicates", async () => {
    const baseUrl = await startServer((url) => {
      if (url === "/ok") return { status: 200, body: "hello-world" };
      return { status: 404, body: "missing" };
    });
    const finding = baseFinding({
      pocSteps: [
        { id: "s1", kind: "exploit", summary: "status", action: { type: "http", method: "GET", url: "/ok" }, expect: { type: "http-status", status: [200, 201] } },
        { id: "s2", kind: "verify", summary: "contains", action: { type: "http", method: "GET", url: "/ok" }, expect: { type: "body-contains", text: "world" } },
        { id: "s3", kind: "verify", summary: "regex", action: { type: "http", method: "GET", url: "/ok" }, expect: { type: "body-matches", pattern: "hello-.*" } },
      ],
    });
    const out = await executePocSteps(finding, { baseUrl, timeoutMs: 5000 });
    expect(out.steps.every((s) => s.predicate === "passed")).toBe(true);
    expect(out.stillExploitable).toBe(true);
  });

  it("redacts sensitive values in redacted output", async () => {
    const finding = baseFinding({
      pocSteps: [
        {
          id: "s1",
          kind: "setup",
          summary: "echo secret",
          action: { type: "shell", cmd: "printf '%s' \"$API_TOKEN\"" },
          expect: { type: "exit-zero" },
        },
      ],
    });
    const out = await executePocSteps(finding, { env: { API_TOKEN: "super-secret-token" }, timeoutMs: 5000 });
    const redacted = JSON.stringify(out.steps[0]?.redacted ?? {});
    expect(redacted).toContain("[REDACTED]");
    expect(redacted).not.toContain("super-secret-token");
  });

  it("runs end-to-end setup auth exploit verify pipeline", async () => {
    const baseUrl = await startServer((url, method) => {
      if (method === "POST" && url === "/exploit") return { status: 200, body: "pwned" };
      if (method === "GET" && url === "/verify") return { status: 200, body: "marker:pwned" };
      return { status: 200, body: "ok" };
    });
    const finding = baseFinding({
      pocSteps: [
        { id: "setup", kind: "setup", summary: "prep", action: { type: "shell", cmd: "true" }, expect: { type: "exit-zero" } },
        { id: "auth", kind: "auth", summary: "auth", action: { type: "note", text: "attacker account" } },
        { id: "exploit", kind: "exploit", summary: "exploit", action: { type: "http", method: "POST", url: "/exploit" }, expect: { type: "body-contains", text: "pwned" } },
        { id: "verify", kind: "verify", summary: "verify", action: { type: "http", method: "GET", url: "/verify" }, expect: { type: "body-contains", text: "marker" } },
      ],
    });
    const out = await executePocSteps(finding, { baseUrl, timeoutMs: 5000 });
    expect(out.steps).toHaveLength(4);
    expect(out.stillExploitable).toBe(true);
    expect(out.summary).toContain("Executed 4 step(s)");
  });
});
