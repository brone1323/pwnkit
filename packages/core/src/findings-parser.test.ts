import { describe, it, expect } from "vitest";
import { parseFindingsFromCliOutput } from "./findings-parser.js";

describe("parseFindingsFromCliOutput", () => {
  it("derives pocSteps for structured finding blocks", () => {
    const raw = [
      "---FINDING---",
      "title: SSRF test",
      "severity: high",
      "category: ssrf",
      "description: reaches metadata endpoint",
      "file: GET /api/proxy?url=http://169.254.169.254/",
      "---END---",
    ].join("\n");
    const findings = parseFindingsFromCliOutput(raw, { templatePrefix: "test" });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.pocSteps?.length).toBeGreaterThan(0);
    expect(findings[0]?.pocSteps?.some((s) => s.kind === "exploit")).toBe(true);
  });

  it("prefers explicit pocSteps in JSON output when present", () => {
    const raw = JSON.stringify({
      findings: [
        {
          title: "Auth gap",
          severity: "high",
          category: "tool-misuse",
          description: "desc",
          file: "POST /plugins/install",
          poc: "200 OK",
          pocSteps: [
            {
              id: "x",
              kind: "exploit",
              summary: "hit endpoint",
              action: { type: "http", method: "POST", url: "/plugins/install" },
            },
          ],
        },
      ],
    });
    const findings = parseFindingsFromCliOutput(raw, { templatePrefix: "test" });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.pocSteps?.[0]?.id).toBe("x");
  });
});
