/**
 * pwnkit#193 — `restorePersistedFinding` round-trip for `verificationSpec`.
 *
 * CodeRabbit flagged that `Finding.verificationSpec` is part of the shared
 * model but the unified-pipeline reload path was dropping it on restore.
 * Cloud's canary watcher then had nothing to re-evaluate against on the
 * next upstream HEAD refresh, breaking the whole point of the spec.
 *
 * These tests exercise the restore helper directly so the wire round-trip
 * is captured in a unit test rather than only via an end-to-end resume.
 */
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { pwnkitDB } from "@pwnkit/db";
import type { Finding, ScanConfig, VerificationSpec } from "@pwnkit/shared";
import { restorePersistedFinding } from "./unified-pipeline.js";

const tempDirs: string[] = [];

function makeDb(): { db: pwnkitDB; scanId: string } {
  const dir = mkdtempSync(join(tmpdir(), "pwnkit-restore-vspec-"));
  tempDirs.push(dir);
  const db = new pwnkitDB(join(dir, "pwnkit.db"));
  const scanConfig: ScanConfig = {
    target: "http://example.test",
    depth: "default",
    format: "json",
    runtime: "api",
    mode: "deep",
  };
  const scanId = db.createScan(scanConfig);
  return { db, scanId };
}

function makeSpec(): VerificationSpec {
  return {
    code: [
      {
        kind: "file-contains",
        file: "app/users.ts",
        pattern: "db\\.query.*req\\.body",
      },
      { kind: "file-exists", file: "lib/db.ts" },
    ],
    behavior: {
      steps: [{ method: "GET", path: "/users", expect: "success" }],
    },
  };
}

function makeFinding(spec?: VerificationSpec): Finding {
  return {
    id: randomUUID(),
    templateId: "manual",
    title: "SQLi on /users",
    description: "user input concatenated into SQL",
    severity: "high",
    category: "sql-injection",
    status: "discovered",
    evidence: {
      request: "POST /users",
      response: "[{...}]",
      analysis: "db.query interpolates req.body",
    },
    verificationSpec: spec,
    timestamp: 1_700_000_000_000,
  };
}

describe("restorePersistedFinding (pwnkit#193 — verificationSpec round-trip)", () => {
  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("threads verificationSpec through saveFinding → getFindings → restore", () => {
    const { db, scanId } = makeDb();
    try {
      const spec = makeSpec();
      const original = makeFinding(spec);
      db.saveFinding(scanId, original);

      const rows = db.getFindings(scanId);
      expect(rows).toHaveLength(1);

      const restored = restorePersistedFinding(rows[0]);
      expect(restored.verificationSpec).toEqual(spec);
      // Other fields still survive — the new column doesn't disrupt the
      // existing rehydration.
      expect(restored.id).toBe(original.id);
      expect(restored.title).toBe(original.title);
      expect(restored.evidence.analysis).toBe("db.query interpolates req.body");
    } finally {
      db.close();
    }
  });

  it("restores verificationSpec=undefined when the column is NULL (legacy row)", () => {
    const { db, scanId } = makeDb();
    try {
      const original = makeFinding(undefined);
      db.saveFinding(scanId, original);
      const rows = db.getFindings(scanId);
      const restored = restorePersistedFinding(rows[0]);
      expect(restored.verificationSpec).toBeUndefined();
    } finally {
      db.close();
    }
  });

  it("drops a malformed JSON column without breaking the restore", () => {
    // Simulate a row where the verificationSpec column got corrupted
    // (older write path, manual edit, etc.). The finding must still
    // restore — just without a usable spec.
    const restored = restorePersistedFinding({
      id: "f-1",
      templateId: "manual",
      title: "still useful",
      description: "x",
      severity: "low",
      category: "sql-injection",
      status: "discovered",
      evidenceRequest: "x",
      evidenceResponse: "y",
      verificationSpec: "{not json [",
      timestamp: 0,
    });
    expect(restored.verificationSpec).toBeUndefined();
    expect(restored.title).toBe("still useful");
  });

  it("drops a JSON object that lacks the `code` array (defensive)", () => {
    const restored = restorePersistedFinding({
      id: "f-2",
      templateId: "manual",
      title: "weird",
      description: "x",
      severity: "low",
      category: "sql-injection",
      status: "discovered",
      evidenceRequest: "x",
      evidenceResponse: "y",
      // Looks like JSON but isn't a VerificationSpec.
      verificationSpec: JSON.stringify({ foo: "bar" }),
      timestamp: 0,
    });
    expect(restored.verificationSpec).toBeUndefined();
  });

  it("accepts an already-parsed object (test/sink-shim path)", () => {
    const spec = makeSpec();
    const restored = restorePersistedFinding({
      id: "f-3",
      templateId: "manual",
      title: "preparsed",
      description: "x",
      severity: "low",
      category: "sql-injection",
      status: "discovered",
      evidenceRequest: "x",
      evidenceResponse: "y",
      verificationSpec: spec,
      timestamp: 0,
    });
    expect(restored.verificationSpec).toEqual(spec);
  });
});
