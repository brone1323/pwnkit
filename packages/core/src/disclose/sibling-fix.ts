import { existsSync, readFileSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import type { Finding } from "@pwnkit/shared";
import { extractFileRefs, type FileRef } from "./canary.js";

export interface SiblingFixCandidate {
  fileRef: FileRef;
  snippet: string;
  language: string;
  confidence: number;
  rationale: string;
}

interface SiblingScore {
  confidence: number;
  rationale: string;
}

const POSITIVE_SIGNALS: Array<{ re: RegExp; weight: number; reason: string }> = [
  { re: /correct pattern/i, weight: 0.45, reason: "mentions correct pattern" },
  { re: /\bsibling\b/i, weight: 0.3, reason: "mentions sibling code" },
  { re: /uses the correct/i, weight: 0.3, reason: "calls this ref the correct variant" },
  { re: /the right gate is/i, weight: 0.35, reason: "references the right gate" },
  { re: /correctly[- ]gated/i, weight: 0.3, reason: "marks this path as correctly gated" },
  { re: /assertinstanceadmin/i, weight: 0.2, reason: "mentions expected admin gate" },
];

const NEGATIVE_SIGNALS: Array<{ re: RegExp; weight: number; reason: string }> = [
  { re: /vulnerable at/i, weight: -0.45, reason: "explicitly marks this as vulnerable" },
  { re: /instead of/i, weight: -0.35, reason: "describes this as the weaker variant" },
  { re: /where the/i, weight: -0.15, reason: "context suggests this is the vulnerable site" },
  { re: /gates on .* instead/i, weight: -0.4, reason: "describes incorrect gate" },
];

function languageForPath(filePath: string): string {
  const ext = extname(filePath).toLowerCase();
  switch (ext) {
    case ".ts":
      return "ts";
    case ".tsx":
      return "tsx";
    case ".js":
      return "js";
    case ".jsx":
      return "jsx";
    case ".mjs":
      return "js";
    case ".cjs":
      return "js";
    case ".py":
      return "py";
    case ".rb":
      return "rb";
    case ".go":
      return "go";
    case ".rs":
      return "rs";
    case ".java":
      return "java";
    case ".kt":
      return "kt";
    case ".php":
      return "php";
    case ".swift":
      return "swift";
    case ".sh":
      return "sh";
    case ".sql":
      return "sql";
    default:
      return "";
  }
}

function scoreContext(context: string): SiblingScore {
  let confidence = 0;
  const reasons: string[] = [];
  for (const signal of POSITIVE_SIGNALS) {
    if (signal.re.test(context)) {
      confidence += signal.weight;
      reasons.push(signal.reason);
    }
  }
  for (const signal of NEGATIVE_SIGNALS) {
    if (signal.re.test(context)) {
      confidence += signal.weight;
      reasons.push(signal.reason);
    }
  }
  if (confidence < 0) confidence = 0;
  if (confidence > 1) confidence = 1;
  return {
    confidence,
    rationale: reasons.length > 0 ? reasons.join("; ") : "no sibling-specific wording",
  };
}

function buildEvidenceText(finding: Finding): string {
  return [
    finding.description,
    finding.evidence?.analysis,
    finding.evidence?.request,
    finding.evidence?.response,
  ]
    .filter((s): s is string => typeof s === "string" && s.length > 0)
    .join("\n\n");
}

function nearestBoundaryLeft(text: string, from: number): number {
  const dot = text.lastIndexOf(".", from);
  const nl = text.lastIndexOf("\n", from);
  const semi = text.lastIndexOf(";", from);
  return Math.max(dot, nl, semi);
}

function nearestBoundaryRight(text: string, from: number): number {
  const dot = text.indexOf(".", from);
  const nl = text.indexOf("\n", from);
  const semi = text.indexOf(";", from);
  const options = [dot, nl, semi].filter((n) => n >= 0);
  if (options.length === 0) return -1;
  return Math.min(...options);
}

function contextualSlice(text: string, start: number, end: number): string {
  const sentLeft = nearestBoundaryLeft(text, start);
  const sentRight = nearestBoundaryRight(text, end);
  const left = sentLeft >= 0 ? sentLeft + 1 : Math.max(0, start - 120);
  const right = sentRight >= 0 ? sentRight + 1 : Math.min(text.length, end + 120);
  return text.slice(left, right);
}

function scoreRefsFromText(haystack: string): Map<string, SiblingScore> {
  const scored = new Map<string, SiblingScore>();
  const regex = /(?<![\w/\-:])([a-zA-Z0-9_./\-]+\.(?:ts|tsx|js|jsx|mjs|cjs|py|rb|go|rs|c|h|cc|cpp|java|kt|swift|php|sh|sql))(?::(\d+)(?:-\d+)?)?/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(haystack)) !== null) {
    const file = match[1];
    const line = match[2] ? Number(match[2]) : undefined;
    if (file.startsWith("http:") || file.startsWith("https:")) continue;
    const context = contextualSlice(haystack, match.index, regex.lastIndex);
    const score = scoreContext(context);
    const key = `${file}:${line ?? ""}`;
    const existing = scored.get(key);
    if (!existing || score.confidence > existing.confidence) {
      scored.set(key, score);
    }
  }
  return scored;
}

export function extractSiblingFix(
  finding: Finding,
  options: { repoPath: string; linesOfContext?: number },
): SiblingFixCandidate | null {
  if (!options?.repoPath) return null;
  const repoPath = resolve(options.repoPath);
  if (!existsSync(repoPath)) return null;

  const refs = extractFileRefs(finding);
  if (refs.length === 0) return null;

  const scores = scoreRefsFromText(buildEvidenceText(finding));
  const ranked: Array<{ ref: FileRef; score: SiblingScore }> = [];
  for (const ref of refs) {
    const key = `${ref.file}:${ref.line ?? ""}`;
    const score = scores.get(key);
    if (!score || score.confidence <= 0) continue;
    ranked.push({ ref, score });
  }
  if (ranked.length === 0) return null;
  ranked.sort((a, b) => b.score.confidence - a.score.confidence);

  for (const winner of ranked) {
    const absPath = join(repoPath, winner.ref.file);
    if (!existsSync(absPath)) continue;
    if (winner.ref.line === undefined || winner.ref.line < 1) continue;

    const lines = readFileSync(absPath, "utf8").split("\n");
    if (winner.ref.line > lines.length) continue;

    const context = options.linesOfContext ?? 8;
    const start = Math.max(1, winner.ref.line - context);
    const end = Math.min(lines.length, winner.ref.line + context);
    const snippet = lines.slice(start - 1, end).join("\n").trimEnd();
    if (!snippet) continue;

    return {
      fileRef: winner.ref,
      snippet,
      language: languageForPath(winner.ref.file),
      confidence: winner.score.confidence,
      rationale: winner.score.rationale,
    };
  }

  return null;
}
