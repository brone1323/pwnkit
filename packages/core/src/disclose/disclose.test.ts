import { describe, it, expect } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { suggestCwesForCategory, suggestCvss, renderAdvisoryMarkdown } from "./index.js";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-abcdef123",
    templateId: "ssrf-template",
    title: "SSRF via /api/foo",
    description: "Attacker-controlled URL reaches server-side fetch without a hostname allowlist.",
    severity: "medium",
    category: "ssrf",
    status: "verified",
    evidence: {
      request: "GET /api/foo?url=http://169.254.169.254/ HTTP/1.1",
      response: '{"status":"reachable","httpStatus":200}',
      analysis: "Full SSRF with response reflection.",
    },
    timestamp: 1712345678,
    ...overrides,
  };
}

describe("suggestCwesForCategory", () => {
  it("returns a primary entry for every covered category", () => {
    const cats: Finding["category"][] = [
      "ssrf", "path-traversal", "command-injection", "xss", "prompt-injection", "prototype-pollution", "heap-overflow",
    ];
    for (const c of cats) {
      const entries = suggestCwesForCategory(c);
      expect(entries.length).toBeGreaterThan(0);
      expect(entries[0].role).toBe("primary");
      expect(entries[0].id).toMatch(/^CWE-\d+$/);
    }
  });

  it("maps ssrf to CWE-918 as primary", () => {
    const entries = suggestCwesForCategory("ssrf");
    expect(entries[0].id).toBe("CWE-918");
  });

  it("maps path-traversal to CWE-22 primary + CWE-73 secondary", () => {
    const entries = suggestCwesForCategory("path-traversal");
    expect(entries[0].id).toBe("CWE-22");
    expect(entries.some((e) => e.id === "CWE-73" && e.role === "secondary")).toBe(true);
  });
});

describe("suggestCvss", () => {
  it("passes through finding.cvssVector + cvssScore when present", () => {
    const finding = baseFinding({ cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvssScore: 9.8 });
    const suggestion = suggestCvss(finding);
    expect(suggestion.source).toBe("finding");
    expect(suggestion.score).toBe(9.8);
  });

  it("synthesises a heuristic vector when the finding has none", () => {
    const finding = baseFinding();
    const suggestion = suggestCvss(finding);
    expect(suggestion.source).toBe("heuristic");
    expect(suggestion.vector).toMatch(/^CVSS:3\.1\/AV:N\/AC:L\/PR:[NLH]\/UI:N\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/);
    expect(suggestion.score).toBeGreaterThan(0);
    expect(suggestion.score).toBeLessThanOrEqual(10);
  });

  it("produces a higher score for command-injection than for cors at the same severity", () => {
    const cmd = suggestCvss(baseFinding({ category: "command-injection", severity: "high" }));
    const cors = suggestCvss(baseFinding({ category: "cors", severity: "high" }));
    expect(cmd.score).toBeGreaterThan(cors.score);
  });
});

describe("renderAdvisoryMarkdown", () => {
  it("includes Title / Severity / CWE / Affected versions / Summary / PoC / Suggested fix / Patch status / Credits", () => {
    const finding = baseFinding();
    const { markdown } = renderAdvisoryMarkdown(finding);
    for (const header of ["# Title", "# Severity", "# CWE", "# Affected versions", "## Summary", "## PoC", "## Suggested fix", "## Patch status", "## Credits"]) {
      expect(markdown).toContain(header);
    }
  });

  it("embeds the evidence request and response in fenced blocks", () => {
    const finding = baseFinding();
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("GET /api/foo?url=http://169.254.169.254/");
    expect(markdown).toContain('"status":"reachable"');
  });

  it("embeds the primary CWE ID in the CWE section", () => {
    const finding = baseFinding({ category: "path-traversal" });
    const { markdown, primaryCwe } = renderAdvisoryMarkdown(finding);
    expect(primaryCwe).toBe("CWE-22");
    expect(markdown).toContain("CWE-22");
  });

  it("renders remediation.summary + steps + codeExample when provided", () => {
    const finding = baseFinding({
      remediation: {
        summary: "Allowlist hostnames.",
        steps: [
          "Resolve hostname before fetching.",
          "Reject private IPs after DNS.",
        ],
        codeExample: {
          language: "typescript",
          before: "await fetch(url);",
          after: "await fetch(url, { dispatcher: ssrfSafeAgent });",
        },
        references: [],
      },
    });
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("Allowlist hostnames.");
    expect(markdown).toContain("1. Resolve hostname before fetching.");
    expect(markdown).toContain("ssrfSafeAgent");
  });

  it("emits a stable filename slug prefixed by severity rank + severity label (no doubling)", () => {
    const finding = baseFinding({ severity: "high", title: "Auth gap: non-admin can mint tokens" });
    const { filename } = renderAdvisoryMarkdown(finding);
    expect(filename).toMatch(/^2-high-auth-gap/);
    expect(filename).not.toMatch(/high-high/);
  });

  it("sorts criticals before highs in a lexicographic sort of filenames", () => {
    const critical = renderAdvisoryMarkdown(baseFinding({ severity: "critical", title: "C" }));
    const high = renderAdvisoryMarkdown(baseFinding({ severity: "high", title: "H" }));
    const sorted = [high.filename, critical.filename].sort();
    expect(sorted[0]).toBe(critical.filename);
  });
});
