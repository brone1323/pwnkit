import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { Finding } from "@pwnkit/shared";
import { extractSiblingFix } from "./sibling-fix.js";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-sibling-0001",
    templateId: "auth-gap-template",
    title: "Auth gap in adapter install",
    description:
      "Vulnerable route at server/src/routes/adapters.ts:420 gates on assertBoard instead of assertInstanceAdmin. " +
      "Correct pattern is present in sibling handler at server/src/routes/plugins.ts:10.",
    severity: "high",
    category: "tool-misuse",
    status: "verified",
    evidence: {
      request: "",
      response: "",
      analysis: "",
    },
    timestamp: 1712345678,
    ...overrides,
  };
}

function withRepo(files: Record<string, string>, run: (repoPath: string) => void): void {
  const repoPath = mkdtempSync(join(tmpdir(), "pwnkit-sibling-"));
  try {
    for (const [path, content] of Object.entries(files)) {
      const abs = join(repoPath, path);
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, content, "utf8");
    }
    run(repoPath);
  } finally {
    rmSync(repoPath, { recursive: true, force: true });
  }
}

describe("extractSiblingFix", () => {
  it("returns snippet when finding says a sibling route is the correct pattern", () => {
    withRepo(
      {
        "server/src/routes/plugins.ts": [
          "line 1",
          "line 2",
          "line 3",
          "line 4",
          "line 5",
          "line 6",
          "line 7",
          "line 8",
          "const gate = assertInstanceAdmin(ctx);",
          "router.post('/plugins/:pluginId/install', handler);",
          "line 11",
          "line 12",
        ].join("\n"),
      },
      (repoPath) => {
        const out = extractSiblingFix(baseFinding(), { repoPath, linesOfContext: 2 });
        expect(out).not.toBeNull();
        expect(out?.fileRef.file).toBe("server/src/routes/plugins.ts");
        expect(out?.fileRef.line).toBe(10);
        expect(out?.snippet).toContain("router.post('/plugins/:pluginId/install', handler);");
        expect(out?.language).toBe("ts");
      },
    );
  });

  it("returns null when no sibling wording is present", () => {
    withRepo(
      {
        "server/src/routes/plugins.ts": "router.post('/plugins/:pluginId/install', handler);",
      },
      (repoPath) => {
        const out = extractSiblingFix(
          baseFinding({
            description: "Vulnerable path at server/src/routes/plugins.ts:1 allows non-admin install.",
          }),
          { repoPath },
        );
        expect(out).toBeNull();
      },
    );
  });

  it("picks the highest-confidence candidate when multiple refs exist", () => {
    withRepo(
      {
        "server/src/routes/a.ts": "line 1\nline 2\nline 3",
        "server/src/routes/b.ts": "line 1\nline 2\nline 3",
      },
      (repoPath) => {
        const out = extractSiblingFix(
          baseFinding({
            description:
              "Vulnerable at server/src/routes/a.ts:2. " +
              "The correct pattern at sibling server/src/routes/b.ts:2 uses the right gate.",
          }),
          { repoPath },
        );
        expect(out).not.toBeNull();
        expect(out?.fileRef.file).toBe("server/src/routes/b.ts");
      },
    );
  });

  it("returns null when repo path does not exist", () => {
    const out = extractSiblingFix(baseFinding(), { repoPath: join(tmpdir(), "missing-repo-path") });
    expect(out).toBeNull();
  });

  it("returns null when cited line is beyond EOF", () => {
    withRepo(
      {
        "server/src/routes/plugins.ts": "line 1\nline 2\nline 3",
      },
      (repoPath) => {
        const out = extractSiblingFix(
          baseFinding({
            description: "Correct pattern in sibling file at server/src/routes/plugins.ts:99.",
          }),
          { repoPath },
        );
        expect(out).toBeNull();
      },
    );
  });
});
