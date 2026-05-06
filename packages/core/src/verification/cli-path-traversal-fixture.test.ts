import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runCliPathTraversalReplayFixture } from "./cli-path-traversal-fixture.js";

describe("runCliPathTraversalReplayFixture", () => {
  it("reproduces the vulnerable Paperclip-style export traversal", async () => {
    const result = await runCliPathTraversalReplayFixture({
      fixtureMode: "vulnerable",
      engineVersion: "test",
    });

    expect(result.status).toBe("reproduced");
    expect(result.mode).toBe("deterministic_replay");
    expect(result.finding_id).toBe("fixture:cli-path-traversal");
    expect(result.commands).toHaveLength(1);
    expect(result.commands[0].argv).toContain("--output");
    expect(result.commands[0].exit_code).toBe(0);
    expect(result.commands[0].stdout_excerpt).toContain("escaped-marker");
    expect(result.assertions.find((a) => a.kind === "filesystem_exists")?.passed).toBe(true);
    expect(result.assertions.find((a) => a.kind === "path_outside_export_root")?.passed).toBe(true);
    expect(result.assertions.find((a) => a.kind === "path_inside_sandbox")?.passed).toBe(true);
    expect(result.artifacts).toEqual({});
    const escapedDetail = result.assertions.find((a) => a.kind === "filesystem_exists")?.detail ?? "";
    const escapedPath = escapedDetail.replace(/^escaped marker exists at /, "");
    const sandbox = dirname(escapedPath);
    expect(existsSync(sandbox)).toBe(false);
  });

  it("returns not_reproduced when the fixture CLI rejects traversal", async () => {
    const result = await runCliPathTraversalReplayFixture({
      fixtureMode: "patched",
      engineVersion: "test",
    });

    expect(result.status).toBe("not_reproduced");
    expect(result.commands[0].exit_code).toBe(1);
    expect(result.commands[0].stderr_excerpt).toContain("blocked path traversal");
    expect(result.assertions.find((a) => a.kind === "filesystem_exists")?.passed).toBe(false);
    expect(result.assertions.find((a) => a.kind === "path_outside_export_root")?.passed).toBe(false);
  });

  it("retains the sandbox and artifact refs when requested", async () => {
    const sandbox = mkdtempSync(join(tmpdir(), "pwnkit-fixture-retain-"));
    try {
      const result = await runCliPathTraversalReplayFixture({
        artifactDir: sandbox,
        retainArtifacts: true,
        engineVersion: "test",
      });

      expect(result.status).toBe("reproduced");
      expect(result.artifacts.sandbox_ref).toBe(sandbox);
      expect(result.artifacts.harness_ref).toBeTruthy();
      expect(result.artifacts.stdout_ref).toBeTruthy();
      expect(result.artifacts.stderr_ref).toBeTruthy();
      expect(existsSync(result.artifacts.sandbox_ref)).toBe(true);
      expect(existsSync(result.artifacts.harness_ref)).toBe(true);
      expect(existsSync(result.artifacts.stdout_ref)).toBe(true);
      expect(existsSync(result.artifacts.stderr_ref)).toBe(true);
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });

  it("returns artifact refs on setup errors when artifact retention is requested", async () => {
    const sandbox = mkdtempSync(join(tmpdir(), "pwnkit-fixture-error-"));
    try {
      writeFileSync(join(sandbox, "export"), "not a directory", "utf8");

      const result = await runCliPathTraversalReplayFixture({
        artifactDir: sandbox,
        retainArtifacts: true,
        engineVersion: "test",
      });

      expect(result.status).toBe("error");
      expect(result.commands).toEqual([]);
      expect(result.artifacts.sandbox_ref).toBe(sandbox);
      expect(result.artifacts.export_ref).toBe(join(sandbox, "export"));
      expect(result.artifacts.harness_ref).toBe(join(sandbox, "harness", "paperclip-export-fixture.mjs"));
      expect(result.artifacts.stdout_ref).toBe(join(sandbox, "stdout.log"));
      expect(result.artifacts.stderr_ref).toBe(join(sandbox, "stderr.log"));
    } finally {
      rmSync(sandbox, { recursive: true, force: true });
    }
  });
});
