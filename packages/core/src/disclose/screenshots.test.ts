import { describe, it, expect } from "vitest";
import { mkdtempSync, existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "@pwnkit/shared";
import { composeExploitSession, renderExploitScreenshot, isFreezeAvailable } from "./screenshots.js";
import { renderAdvisoryMarkdown } from "./template.js";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-abcdef123456",
    templateId: "ssrf-template",
    title: "SSRF via /api/foo",
    description: "Attacker-controlled URL reaches fetch without allowlist.",
    severity: "medium",
    category: "ssrf",
    status: "verified",
    evidence: {
      request: "GET /api/foo?url=http://169.254.169.254/ HTTP/1.1\nHost: target:3108",
      response: '{"status":"reachable","httpStatus":200,"durationMs":12}',
      analysis: "Full SSRF with response reflection.",
    },
    timestamp: 1712345678,
    ...overrides,
  };
}

describe("composeExploitSession", () => {
  it("includes the finding title, category, and severity as header comments", () => {
    const text = composeExploitSession(baseFinding());
    expect(text).toContain("# PoC for: SSRF via /api/foo");
    expect(text).toContain("Category: ssrf");
    expect(text).toContain("severity: medium");
  });

  it("prefixes the first request line with $ and indents the rest", () => {
    const text = composeExploitSession(baseFinding());
    const lines = text.split("\n");
    const reqIdx = lines.findIndex((l) => l.startsWith("$ GET /api/foo"));
    expect(reqIdx).toBeGreaterThan(-1);
    expect(lines[reqIdx + 1]).toMatch(/^  Host: target:3108$/);
  });

  it("appends the response body unprefixed", () => {
    const text = composeExploitSession(baseFinding());
    expect(text).toContain('{"status":"reachable"');
  });

  it("comments the agent analysis block", () => {
    const text = composeExploitSession(baseFinding());
    expect(text).toContain("# Agent analysis:");
    expect(text).toContain("# Full SSRF with response reflection.");
  });
});

describe("isFreezeAvailable", () => {
  it("returns boolean for a missing binary without throwing", () => {
    const result = isFreezeAvailable("this-binary-definitely-does-not-exist-pwnkit-test");
    expect(typeof result).toBe("boolean");
    expect(result).toBe(false);
  });
});

describe("renderExploitScreenshot", () => {
  it("returns null when available=false and still writes no files", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "pwnkit-shot-"));
    const result = renderExploitScreenshot(baseFinding(), { outputDir, available: false });
    expect(result).toBeNull();
  });

  it("writes a session file and a stub output file when a fake binary is provided", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "pwnkit-shot-"));
    // Stub freeze: just `touch` the file at the -o position.
    const stubBinary = join(outputDir, "fake-freeze");
    writeFileSync(stubBinary, `#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    touch "$2"
    shift 2
    continue
  fi
  shift
done
`);
    chmodSync(stubBinary, 0o755);

    const result = renderExploitScreenshot(baseFinding(), {
      outputDir,
      binary: stubBinary,
      available: true,
    });
    expect(result).not.toBeNull();
    expect(existsSync(result!.path)).toBe(true);
    const sessionFile = result!.path.replace(/\.png$/, ".session.txt");
    expect(existsSync(sessionFile)).toBe(true);
    const sessionText = readFileSync(sessionFile, "utf8");
    expect(sessionText).toContain("SSRF via /api/foo");
  });

  it("returns null when the rendering binary exits nonzero", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "pwnkit-shot-"));
    const stubBinary = join(outputDir, "broken-freeze");
    writeFileSync(stubBinary, "#!/usr/bin/env bash\nexit 1\n");
    chmodSync(stubBinary, 0o755);
    const result = renderExploitScreenshot(baseFinding(), {
      outputDir,
      binary: stubBinary,
      available: true,
    });
    expect(result).toBeNull();
  });

  it("produces a relativePath when markdownDir is passed", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "pwnkit-shot-"));
    const markdownDir = outputDir;
    const imagesDir = join(outputDir, "images");
    const stubBinary = join(outputDir, "fake-freeze-rel");
    writeFileSync(stubBinary, `#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    mkdir -p "$(dirname "$2")"
    touch "$2"
    shift 2
    continue
  fi
  shift
done
`);
    chmodSync(stubBinary, 0o755);
    const result = renderExploitScreenshot(baseFinding(), {
      outputDir: imagesDir,
      markdownDir,
      binary: stubBinary,
      available: true,
    });
    expect(result).not.toBeNull();
    expect(result!.relativePath.startsWith("./images/")).toBe(true);
  });
});

describe("template integration", () => {
  it("embeds screenshot img tags into the PoC section when passed", () => {
    const { markdown } = renderAdvisoryMarkdown(baseFinding(), {
      screenshots: [
        { alt: "exploit-demo", relativePath: "./images/shot.png", caption: "Exploit in action", width: 1200 },
      ],
    });
    expect(markdown).toContain('<img width="1200" alt="exploit-demo" src="./images/shot.png" />');
    expect(markdown).toContain("> Exploit in action");
  });

  it("suppresses the 'to fill in' PoC placeholder once a screenshot is attached even without evidence", () => {
    const noEvidenceFinding = {
      ...baseFinding(),
      evidence: { request: "", response: "", analysis: undefined },
    };
    const { markdown } = renderAdvisoryMarkdown(noEvidenceFinding, {
      screenshots: [{ alt: "shot", relativePath: "./images/shot.png" }],
    });
    expect(markdown).not.toContain("To fill in: concrete reproduction steps");
  });
});
