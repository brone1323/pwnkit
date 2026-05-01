/**
 * pwnkit#193 / pwnkit-cloud#111 — VerificationSpec evaluator tests.
 *
 * Coverage:
 *   1. file-contains predicate: passes when pattern matches, fails when it
 *      doesn't, and gracefully handles missing files.
 *   2. file-missing-pattern predicate: passes when the pattern is absent,
 *      fails when it's present, conservatively fails on missing files.
 *   3. file-exists predicate: passes when the file exists, fails when not.
 *   4. ast-shape predicate: surfaced as not-yet-implemented (failed) until
 *      tree-sitter is wired in as a runtime dep.
 *   5. Aggregate: passed === true only when every predicate held.
 *   6. failedPredicates list captures each predicate that flipped (with
 *      reasons), so callers can render "these predicates flipped → finding
 *      is partial-fix".
 *   7. Behaviour predicates short-circuit with "behavior eval not yet
 *      supported" — code result is reported but caller knows it's
 *      incomplete.
 *   8. Path safety: absolute paths and `..` escapes are rejected.
 *   9. Bad regex patterns flip the predicate to failed without throwing.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { VerificationSpec } from "@pwnkit/shared";
import { evaluateVerificationSpec } from "./spec.js";

let repoRoot: string;

beforeAll(() => {
  repoRoot = mkdtempSync(join(tmpdir(), "pwnkit-verify-"));
  mkdirSync(join(repoRoot, "app"), { recursive: true });
  mkdirSync(join(repoRoot, "lib"), { recursive: true });
  writeFileSync(
    join(repoRoot, "app", "users.ts"),
    [
      "import { db } from '../lib/db';",
      "export async function listUsers(req, res) {",
      "  // Vulnerable: SQL string built from req.body without parameterisation",
      "  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.body.name}'`);",
      "  res.json(rows);",
      "}",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(repoRoot, "lib", "db.ts"),
    [
      "export const db = {",
      "  async query(sql: string) { /* ... */ return []; },",
      "};",
      "",
    ].join("\n"),
  );
  // app/users-fixed.ts is the patched sibling — it uses parameterised query
  // and lacks the vulnerable shape.
  writeFileSync(
    join(repoRoot, "app", "users-fixed.ts"),
    [
      "import { db } from '../lib/db';",
      "export async function listUsers(req, res) {",
      "  const rows = await db.query('SELECT * FROM users WHERE name = ?', [req.body.name]);",
      "  res.json(rows);",
      "}",
      "",
    ].join("\n"),
  );
});

afterAll(() => {
  rmSync(repoRoot, { recursive: true, force: true });
});

describe("evaluateVerificationSpec — file-contains", () => {
  it("passes when the pattern matches", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          pattern: "db\\.query.*\\$\\{req\\.body",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(true);
    expect(result.failedPredicates).toEqual([]);
  });

  it("fails when the pattern does not match", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users-fixed.ts",
          pattern: "db\\.query.*\\$\\{req\\.body",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates).toHaveLength(1);
    expect(result.failedPredicates[0].reason).toMatch(/pattern not found/);
  });

  it("fails gracefully when the file is missing", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/does-not-exist.ts",
          pattern: "anything",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates).toHaveLength(1);
    expect(result.failedPredicates[0].reason).toMatch(/file not found/);
  });

  it("respects regex flags", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          // Case-insensitive match against a SQL keyword
          pattern: "select \\* from users",
          flags: "i",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(true);
  });

  it("flips to failed without throwing on a bad regex", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          pattern: "[unclosed",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(/invalid regex/);
  });
});

describe("evaluateVerificationSpec — file-missing-pattern", () => {
  it("passes when the pattern is absent (fix marker still missing)", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-missing-pattern",
          file: "app/users.ts",
          // The fixed sibling uses parameterised "?" placeholders. The
          // vulnerable file does not — predicate should pass.
          pattern: "WHERE name = \\?",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(true);
  });

  it("fails when the pattern is present (fix marker introduced)", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-missing-pattern",
          file: "app/users-fixed.ts",
          pattern: "WHERE name = \\?",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(/pattern unexpectedly present/);
  });

  it("fails conservatively when the file is missing", async () => {
    // A missing file cannot be asserted to "lack a pattern" in any
    // meaningful sense — treat as failed so the result surfaces as
    // partial-fix rather than silently passing.
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-missing-pattern",
          file: "app/never-existed.ts",
          pattern: "anything",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(/file not found/);
  });
});

describe("evaluateVerificationSpec — file-exists", () => {
  it("passes when the file exists", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "lib/db.ts" }],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(true);
  });

  it("fails when the file is missing", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "lib/missing.ts" }],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(/file not found/);
  });
});

describe("evaluateVerificationSpec — ast-shape", () => {
  it("is reported as not-yet-implemented (conservative failed)", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "ast-shape",
          file: "app/users.ts",
          query: "(call_expression function: (member_expression))",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates).toHaveLength(1);
    expect(result.failedPredicates[0].reason).toMatch(/ast-shape.*not yet implemented/);
  });
});

describe("evaluateVerificationSpec — aggregate semantics", () => {
  it("passed=true only when every predicate held", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          pattern: "db\\.query",
        },
        { kind: "file-exists", file: "lib/db.ts" },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(true);
    expect(result.failedPredicates).toEqual([]);
  });

  it("failedPredicates lists every predicate that flipped", async () => {
    const spec: VerificationSpec = {
      code: [
        // pass
        { kind: "file-exists", file: "lib/db.ts" },
        // fail — file gone
        { kind: "file-exists", file: "lib/gone.ts" },
        // fail — pattern missing
        {
          kind: "file-contains",
          file: "app/users-fixed.ts",
          pattern: "\\$\\{req\\.body",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates).toHaveLength(2);
    const reasons = result.failedPredicates.map((p) => p.reason);
    expect(reasons.some((r) => r.includes("file not found"))).toBe(true);
    expect(reasons.some((r) => r.includes("pattern not found"))).toBe(true);
  });

  it("empty code[] with no behavior surfaces a 'no predicates' reason", async () => {
    const spec: VerificationSpec = { code: [] };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.reason).toBe("no predicates");
    expect(result.failedPredicates).toEqual([]);
  });
});

describe("evaluateVerificationSpec — behavior predicate", () => {
  it("returns 'behavior eval not yet supported' when behavior is set", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          pattern: "db\\.query",
        },
      ],
      behavior: {
        steps: [
          { method: "GET", path: "/users", expect: "success" },
        ],
      },
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    // Code-level still passes…
    expect(result.passed).toBe(true);
    // …but the caller is told that behavioural verification didn't run.
    expect(result.reason).toBe("behavior eval not yet supported");
  });
});

describe("evaluateVerificationSpec — path safety", () => {
  it("rejects absolute paths", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "/etc/passwd" }],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(
      /path escapes repo root or is invalid/,
    );
  });

  it("rejects ../ escapes", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "../../../etc/passwd" }],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(
      /path escapes repo root or is invalid/,
    );
  });

  it("rejects empty paths", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "" }],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
  });
});
