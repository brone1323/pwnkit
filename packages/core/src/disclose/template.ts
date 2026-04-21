import type { Finding } from "@pwnkit/shared";
import { suggestCwesForCategory, formatCweSection } from "./cwe.js";
import { suggestCvss } from "./cvss.js";

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

export function renderAdvisoryMarkdown(finding: Finding, ctx: AdvisoryContext = {}): RenderedAdvisory {
  const cwes = suggestCwesForCategory(finding.category);
  const cvss = suggestCvss(finding);
  const severity = severityHeading(finding.severity);

  const filenameSlug = slugifyTitle(finding.title);
  const filename = `${String(finding.severity).padStart(1, "0")}-${finding.severity}-${filenameSlug}.md`;

  const affectedLine = ctx.target
    ? `\`${ctx.target}\`${ctx.targetRef ? ` at \`${ctx.targetRef}\`` : ""}${ctx.commitHash ? ` (commit \`${ctx.commitHash.slice(0, 12)}\`)` : ""}`
    : "_To fill in: the versions/refs this is present on._";

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
  if (!finding.evidence?.request?.trim() && !finding.evidence?.response?.trim() && (!ctx.screenshots || ctx.screenshots.length === 0)) {
    out.push("_To fill in: concrete reproduction steps. `pwnkit-cli disclose` will auto-populate this once PoC execution lands (issue #168)._", "");
  }

  out.push("## Suggested fix", "");
  out.push(suggestedFix, "");

  out.push("## Patch status", "");
  out.push("_To fill in after canary re-verification. `pwnkit-cli disclose` will auto-populate this once the canary-reverify capability lands (issue #168)._", "");

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
