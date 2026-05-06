import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { pwnkitDB } from "@pwnkit/db";
import type { Finding, ScanConfig } from "@pwnkit/shared";

const tempDirs: string[] = [];

function makeDb(): { db: pwnkitDB; scanId: string } {
  const dir = mkdtempSync(join(tmpdir(), "pwnkit-triage-persist-"));
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

function makeFinding(): Finding {
  return {
    id: randomUUID(),
    templateId: "manual",
    title: "Reflected XSS",
    description: "raw finding",
    severity: "high",
    category: "xss",
    status: "discovered",
    evidence: {
      request: "POST /page",
      response: "<script>alert(1)</script>",
      analysis: "initial evidence",
    },
    timestamp: Date.now(),
  };
}

describe("triage persistence", () => {
  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("persists triage fields when a finding is re-saved after triage", () => {
    const { db, scanId } = makeDb();
    try {
      const finding = makeFinding();
      db.saveFinding(scanId, finding);

      finding.severity = "info";
      finding.status = "false-positive";
      finding.triageStatus = "suppressed";
      finding.triageNote = "rejected: holding-it-wrong";
      finding.evidence.analysis = "updated after triage";

      db.saveFinding(scanId, finding);

      const persisted = db.getFinding(finding.id);
      expect(persisted?.severity).toBe("info");
      expect(persisted?.status).toBe("false-positive");
      expect(persisted?.triageStatus).toBe("suppressed");
      expect(persisted?.triageNote).toBe("rejected: holding-it-wrong");
      expect(persisted?.evidenceAnalysis).toBe("updated after triage");
      expect(persisted?.triagedAt).toBeTruthy();
    } finally {
      db.close();
    }
  });

  it("round-trips pocSteps through DB persistence", () => {
    const { db, scanId } = makeDb();
    try {
      const finding = makeFinding();
      finding.pocSteps = [
        {
          id: "setup-1",
          kind: "setup",
          summary: "Boot target service",
          action: { type: "shell", cmd: "docker run demo" },
          expect: { type: "exit-zero" },
        },
        {
          id: "verify-1",
          kind: "verify",
          summary: "Confirm marker in response",
          action: { type: "http", method: "GET", url: "http://localhost/health" },
          expect: { type: "body-contains", text: "ok" },
        },
      ];

      db.saveFinding(scanId, finding);
      const persisted = db.getFinding(finding.id) as { pocSteps?: string | null } | undefined;
      expect(persisted?.pocSteps).toBeTruthy();

      const parsed = JSON.parse(persisted!.pocSteps!) as Finding["pocSteps"];
      expect(parsed).toEqual(finding.pocSteps);
    } finally {
      db.close();
    }
  });

  it("backfills legacy evidence fields from pocSteps when request/response are empty", () => {
    const { db, scanId } = makeDb();
    try {
      const finding = makeFinding();
      finding.evidence = { request: "", response: "", analysis: undefined };
      finding.pocSteps = [
        {
          id: "exploit-1",
          kind: "exploit",
          summary: "Call vulnerable endpoint",
          action: { type: "http", method: "POST", url: "http://localhost/install" },
          expect: { type: "http-status", status: 200 },
        },
      ];

      db.saveFinding(scanId, finding);
      const persisted = db.getFinding(finding.id) as {
        evidenceRequest?: string;
        evidenceResponse?: string;
        evidenceAnalysis?: string | null;
      } | undefined;

      expect(persisted?.evidenceRequest).toContain("POST http://localhost/install");
      expect(persisted?.evidenceAnalysis).toContain("expect http-status");
      expect(persisted?.evidenceResponse ?? "").toBe("");
    } finally {
      db.close();
    }
  });

  it("persists PoC execution artifacts alongside a finding", () => {
    const { db, scanId } = makeDb();
    try {
      const finding = makeFinding();
      db.saveFinding(scanId, finding);

      const execution = {
        findingId: finding.id,
        executedAt: new Date().toISOString(),
        stillExploitable: true,
        summary: "Executed 2 step(s): 2 passed, 0 failed, 0 skipped.",
        steps: [
          { stepId: "exploit-1", predicate: "passed" },
          { stepId: "verify-1", predicate: "passed" },
        ],
      };
      db.saveFindingPocExecution(finding.id, execution);

      const persisted = db.getFinding(finding.id) as { pocExecution?: string | null } | undefined;
      expect(persisted?.pocExecution).toBeTruthy();
      expect(JSON.parse(persisted!.pocExecution!)).toEqual(execution);
    } finally {
      db.close();
    }
  });
});
