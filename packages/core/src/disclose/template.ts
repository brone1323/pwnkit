import type { Finding } from "@pwnkit/shared";
import { suggestCwesForCategory, formatCweSection } from "./cwe.js";
import { suggestCvss } from "./cvss.js";
import { formatPatchStatusSection, type ReverifyResult } from "./canary.js";
import { formatVersionRangeLine, type VersionRangeResult } from "./version-range.js";
import type { SiblingFixCandidate } from "./sibling-fix.js";
import type { PocExecutionResult } from "./poc-runtime.js";

export interface AdvisoryScreenshot {
  alt: string;
  /** Markdown-ready href (usually a path relative to the advisory file). */
  relativePath: string;
  caption?: string;
  width?: number;
}

export interface AdvisoryContext {
  target?: string;
  targetRef?: string;
  commitHash?: string;
  pwnkitVersion?: string;
  scanId?: string;
  screenshots?: AdvisoryScreenshot[];
  patchStatus?: ReverifyResult;
  versionRange?: VersionRangeResult;
  siblingFix?: SiblingFixCandidate;
  pocExecution?: PocExecutionResult;
}

export interface RenderedAdvisory {
  filename: string;
  markdown: string;
  cvssVector: string;
  cvssScore: number;
  primaryCwe: string;
  severity: string;
}

function severityHeading(severity: string): string {
  const upper = severity.toUpperCase();
  return upper === "CRITICAL" || upper === "HIGH" || upper === "MEDIUM" || upper === "LOW" ? upper : severity;
}

function slugifyTitle(title: string, max = 80): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, max);
}

function indentEvidenceBlock(raw: string, lang = ""): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  return "```" + lang + "\n" + trimmed + "\n```";
}

function renderPocSteps(finding: Finding): string[] {
  if (!finding.pocSteps || finding.pocSteps.length === 0) return [];
  const lines: string[] = ["**Step graph:**", ""];
  for (const [index, step] of finding.pocSteps.entries()) {
    lines.push(`${index + 1}. **${step.kind}** — ${step.summary} _(id: \`${step.id}\`)_`);
    if (step.action.type === "shell") {
      lines.push("", indentEvidenceBlock(step.action.cmd, "bash"));
    } else if (step.action.type === "http") {
      const method = step.action.method.toUpperCase();
      lines.push("", indentEvidenceBlock(`${method} ${step.action.url}${step.action.body ? `\n\n${step.action.body}` : ""}`, "http"));
    } else if (step.action.type === "docker") {
      lines.push("", indentEvidenceBlock(`docker run ${step.action.image} ${step.action.args.join(" ")}`.trim(), "bash"));
    } else {
      lines.push("", step.action.text);
    }
    if (step.expect) {
      lines.push("", `Expected result: \`${step.expect.type}\``);
    }
    lines.push("");
  }
  return lines;
}

export function renderAdvisoryMarkdown(finding: Finding, ctx: AdvisoryContext = {}): RenderedAdvisory {
  const cwes = suggestCwesForCategory(finding.category);
  const cvss = suggestCvss(finding);
  const severity = severityHeading(finding.severity);

  // Prefix by severity rank so lexicographic sort = criticals-first.
  // Explicit numeric map because "critical" < "high" alphabetically.
  const rank: Record<string, string> = { critical: "1", high: "2", medium: "3", low: "4", info: "5" };
  const filenameSlug = slugifyTitle(finding.title);
  const filename = `${rank[finding.severity] ?? "9"}-${finding.severity}-${filenameSlug}.md`;

  let affectedLine: string;
  if (ctx.versionRange) {
    affectedLine = formatVersionRangeLine(ctx.versionRange);
  } else if (ctx.target) {
    affectedLine = `\`${ctx.target}\`${ctx.targetRef ? ` at \`${ctx.targetRef}\`` : ""}${ctx.commitHash ? ` (commit \`${ctx.commitHash.slice(0, 12)}\`)` : ""}`;
  } else {
    affectedLine = "_Pass `--repo <path>` to `pwnkit-cli disclose` to auto-detect the affected version range from git tags._";
  }

  const cvssSource = cvss.source === "finding"
    ? "populated on the finding by pwnkit"
    : "heuristic from category + severity — override in the GHSA editor if the operator disagrees";

  const remediation = finding.remediation;
  const suggestedFixParts: string[] = [];
  if (remediation?.summary) suggestedFixParts.push(remediation.summary);
  if (remediation?.steps?.length) {
    suggestedFixParts.push(remediation.steps.map((step, i) => `${i + 1}. ${step}`).join("\n"));
  }
  if (remediation?.codeExample?.after) {
    const lang = remediation.codeExample.language || "";
    suggestedFixParts.push(
      remediation.codeExample.before
        ? `**Before:**\n\n\`\`\`${lang}\n${remediation.codeExample.before}\n\`\`\`\n\n**After:**\n\n\`\`\`${lang}\n${remediation.codeExample.after}\n\`\`\``
        : `\`\`\`${lang}\n${remediation.codeExample.after}\n\`\`\``,
    );
  } else if (ctx.siblingFix) {
    const ref = `${ctx.siblingFix.fileRef.file}${ctx.siblingFix.fileRef.line ? `:${ctx.siblingFix.fileRef.line}` : ""}`;
    suggestedFixParts.push(
      `**Correct pattern already present in the repo at \`${ref}\`** *(extracted by pwnkit):*\n\n\`\`\`${ctx.siblingFix.language}\n${ctx.siblingFix.snippet}\n\`\`\``,
    );
  }
  const suggestedFix = suggestedFixParts.length > 0
    ? suggestedFixParts.join("\n\n")
    : "_To fill in: copy-paste the correct pattern from a sibling handler in the same repo._";

  const evidenceAnalysis = finding.evidence?.analysis?.trim() ?? "";

  const out: string[] = [];
  out.push("# Title", "");
  out.push(finding.title, "");

  out.push("# Severity", "");
  out.push(`**${severity}** — ${cvss.vector} (~${cvss.score.toFixed(1)})`, "");
  out.push(`_CVSS source: ${cvssSource}._`, "");

  out.push(formatCweSection(cwes), "");

  out.push("# Affected versions", "");
  out.push(affectedLine, "");

  if (ctx.pwnkitVersion || ctx.scanId) {
    const bits: string[] = [];
    if (ctx.pwnkitVersion) bits.push(`pwnkit \`${ctx.pwnkitVersion}\``);
    if (ctx.scanId) bits.push(`scan \`${ctx.scanId.slice(0, 8)}\``);
    out.push(`> Code-verified by ${bits.join(", ")}.`, "");
  }

  out.push("## Summary", "");
  out.push(finding.description.trim(), "");

  if (evidenceAnalysis && evidenceAnalysis !== finding.description.trim()) {
    out.push("## Analysis", "");
    out.push(evidenceAnalysis, "");
  }

  out.push("## PoC", "");
  const pocStepsBlock = renderPocSteps(finding);
  if (pocStepsBlock.length > 0) {
    out.push(...pocStepsBlock);
  }
  if (ctx.screenshots && ctx.screenshots.length > 0) {
    for (const shot of ctx.screenshots) {
      const width = shot.width ? ` width="${shot.width}"` : "";
      out.push(`<img${width} alt="${shot.alt}" src="${shot.relativePath}" />`, "");
      if (shot.caption) {
        out.push(`> ${shot.caption}`, "");
      }
    }
  }
  if (finding.evidence?.request?.trim()) {
    out.push("**Request:**", "");
    out.push(indentEvidenceBlock(finding.evidence.request, "http"), "");
  }
  if (finding.evidence?.response?.trim()) {
    out.push("**Response:**", "");
    out.push(indentEvidenceBlock(finding.evidence.response, "http"), "");
  }
  if (pocStepsBlock.length === 0 && !finding.evidence?.request?.trim() && !finding.evidence?.response?.trim() && (!ctx.screenshots || ctx.screenshots.length === 0)) {
    out.push("_To fill in: concrete reproduction steps. `pwnkit-cli disclose` will auto-populate this once PoC execution lands (issue #168)._", "");
  }

  out.push("## Suggested fix", "");
  out.push(suggestedFix, "");

  out.push("## Patch status", "");
  if (ctx.patchStatus) {
    out.push(formatPatchStatusSection(ctx.patchStatus), "");
  } else {
    out.push("_Pass `--repo <path>` to `pwnkit-cli disclose` to auto-verify this against the target's current HEAD or a specific tag._", "");
  }
  if (ctx.pocExecution) {
    const verdict = ctx.pocExecution.stillExploitable ? "**Behavioral check: exploit still reproducible.**" : "**Behavioral check: exploit no longer reproducible.**";
    out.push(verdict, "");
    out.push(`> ${ctx.pocExecution.summary}`, "");
  }

  out.push("## Credits", "");
  out.push(
    "Discovered by **pwnkit**, an AI-assisted security scanner ([github.com/PwnKit-Labs/pwnkit](https://github.com/PwnKit-Labs/pwnkit)).",
    "",
    "Reporter: _(your github handle)_",
    "",
  );

  return {
    filename,
    markdown: out.join("\n").replace(/\n{3,}/g, "\n\n"),
    cvssVector: cvss.vector,
    cvssScore: cvss.score,
    primaryCwe: cwes[0]?.id ?? "",
    severity: finding.severity,
  };
}
