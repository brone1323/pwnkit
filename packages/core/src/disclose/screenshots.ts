import { execFileSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "@pwnkit/shared";

export interface ScreenshotResult {
  alt: string;
  path: string;
  relativePath: string;
  caption: string;
  sessionText: string;
}

export interface ScreenshotOptions {
  outputDir: string;
  /** Emit image paths relative to this directory (so the markdown sibling file can reference them). */
  markdownDir?: string;
  binary?: string;
  theme?: string;
  width?: number;
  fontSize?: number;
  background?: string;
  /** Override freeze detection (for tests). */
  available?: boolean;
}

const DEFAULT_OPTS: Required<Pick<ScreenshotOptions, "binary" | "theme" | "width" | "fontSize" | "background">> = {
  binary: "freeze",
  theme: "dracula",
  width: 1200,
  fontSize: 14,
  background: "#0f1117",
};

function slugify(input: string, max = 40): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, max);
}

export function isFreezeAvailable(binary = DEFAULT_OPTS.binary): boolean {
  try {
    execFileSync(process.platform === "win32" ? "where" : "which", [binary], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Compose a shell-session text file from the finding's evidence. This is what
 * gets rendered into the terminal-style PNG. Keeps the request and response in
 * the same pane so the exploit and its observable effect appear together.
 */
export function composeExploitSession(finding: Finding): string {
  const lines: string[] = [];
  lines.push(`$ # PoC for: ${finding.title}`);
  lines.push(`$ # Category: ${finding.category} | severity: ${finding.severity}`);
  lines.push("");

  const request = finding.evidence?.request?.trim();
  const response = finding.evidence?.response?.trim();

  if (request) {
    const requestLines = request.split("\n");
    lines.push(`$ ${requestLines[0]}`);
    for (const line of requestLines.slice(1)) {
      lines.push(`  ${line}`);
    }
    lines.push("");
  }

  if (response) {
    lines.push(response);
  }

  const analysis = finding.evidence?.analysis?.trim();
  if (analysis) {
    lines.push("");
    lines.push("# Agent analysis:");
    for (const line of analysis.split("\n")) {
      lines.push(`# ${line}`);
    }
  }

  return lines.join("\n");
}

/**
 * Render a single screenshot from the finding's evidence. Returns null when
 * freeze is unavailable or rendering fails — callers should treat that as a
 * graceful skip, not an error.
 */
export function renderExploitScreenshot(
  finding: Finding,
  options: ScreenshotOptions,
): ScreenshotResult | null {
  const opts = { ...DEFAULT_OPTS, ...options };
  const available = options.available ?? isFreezeAvailable(opts.binary);
  if (!available) return null;

  mkdirSync(opts.outputDir, { recursive: true });

  const slug = slugify(`${finding.severity}-${finding.id.slice(0, 8)}-${finding.title}`);
  const sessionText = composeExploitSession(finding);
  const sessionFile = join(opts.outputDir, `${slug}.session.txt`);
  const pngPath = join(opts.outputDir, `${slug}.png`);
  writeFileSync(sessionFile, sessionText, "utf8");

  try {
    execFileSync(
      opts.binary,
      [
        sessionFile,
        "--language", "bash",
        "--theme", opts.theme,
        "--window",
        "--padding", "20,30",
        "--margin", "10",
        "--background", opts.background,
        "--font.size", String(opts.fontSize),
        "--width", String(opts.width),
        "-o", pngPath,
      ],
      { stdio: "ignore" },
    );
  } catch {
    return null;
  }

  const relativePath = options.markdownDir
    ? pngPath.startsWith(options.markdownDir)
      ? "." + pngPath.slice(options.markdownDir.length)
      : pngPath
    : pngPath;

  return {
    alt: `exploit-${slug}`,
    path: pngPath,
    relativePath,
    caption: finding.title,
    sessionText,
  };
}
