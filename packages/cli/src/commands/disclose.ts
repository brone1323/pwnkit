import type { Command } from "commander";
import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { homedir } from "node:os";
import chalk from "chalk";
import type { Finding, AttackCategory, Severity, Evidence, FindingStatus } from "@pwnkit/shared";
import {
  renderAdvisoryMarkdown,
  renderExploitScreenshot,
  isFreezeAvailable,
  verifyAgainstRef,
  detectVersionRange,
  extractSiblingFix,
  type AdvisoryContext,
  type AdvisoryScreenshot,
  type ReverifyResult,
  type VersionRangeResult,
  type PatchStatus,
} from "@pwnkit/core";

interface DiscloseOptions {
  dbPath?: string;
  scan?: string;
  outputDir?: string;
  severityFloor?: string;
  dryRun?: boolean;
  noScreenshots?: boolean;
  repo?: string;
  ref?: string;
  dropFixed?: boolean;
}

const STATUS_COLOUR: Record<PatchStatus, (s: string) => string> = {
  "still-vulnerable": (s) => chalk.green(s),
  "partial-fix": (s) => chalk.yellow(s),
  "fixed": (s) => chalk.gray(s),
  "file-removed": (s) => chalk.gray(s),
  "unknown": (s) => chalk.dim(s),
};

interface FindingRow {
  id: string;
  scanId: string;
  title: string;
  severity: string;
  category: string;
  status: string;
  fingerprint?: string | null;
  triageStatus?: string | null;
  triageNote?: string | null;
  timestamp: number;
  templateId: string;
  description: string;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
  cvssVector?: string | null;
  cvssScore?: number | null;
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function rowToFinding(row: FindingRow): Finding {
  const evidence: Evidence = {
    request: row.evidenceRequest,
    response: row.evidenceResponse,
    analysis: row.evidenceAnalysis ?? undefined,
  };
  const finding: Finding = {
    id: row.id,
    templateId: row.templateId,
    title: row.title,
    description: row.description,
    severity: row.severity as Severity,
    category: row.category as AttackCategory,
    status: row.status as FindingStatus,
    evidence,
    fingerprint: row.fingerprint ?? undefined,
    timestamp: row.timestamp,
  };
  if (row.cvssVector) finding.cvssVector = row.cvssVector;
  if (row.cvssScore !== null && row.cvssScore !== undefined) finding.cvssScore = row.cvssScore;
  return finding;
}

function resolveOutputDir(opts: DiscloseOptions, scanId: string): string {
  if (opts.outputDir) return resolve(opts.outputDir);
  return join(homedir(), "pwnkit", "disclosures", `scan-${scanId.slice(0, 8)}`);
}

async function disclose(findingId: string | undefined, opts: DiscloseOptions): Promise<void> {
  const { pwnkitDB } = await import("@pwnkit/db");
  const db = new pwnkitDB(opts.dbPath);
  try {
    const rows = db.listFindings({ scanId: opts.scan, limit: 5000 }) as FindingRow[];
    if (rows.length === 0) {
      console.log(chalk.gray("No findings in the database matching your filters."));
      return;
    }

    let selected: FindingRow[];
    if (findingId) {
      const exact = rows.find((r) => r.id === findingId);
      const prefix = rows.filter((r) => r.id.startsWith(findingId));
      if (exact) selected = [exact];
      else if (prefix.length === 1) selected = prefix;
      else if (prefix.length > 1) throw new Error(`Finding prefix '${findingId}' is ambiguous across ${prefix.length} rows.`);
      else throw new Error(`Finding '${findingId}' not found.`);
    } else {
      const floor = SEVERITY_RANK[opts.severityFloor ?? "medium"] ?? 2;
      selected = rows.filter((r) => (SEVERITY_RANK[r.severity] ?? 0) >= floor && r.triageStatus !== "suppressed");
      if (selected.length === 0) {
        console.log(chalk.gray(`No findings at or above severity '${opts.severityFloor ?? "medium"}' after triage filtering.`));
        return;
      }
    }

    const scanIds = Array.from(new Set(selected.map((r) => r.scanId)));
    const scanId = scanIds[0];
    if (scanIds.length > 1 && !opts.outputDir && !opts.scan) {
      throw new Error(
        `Selected ${selected.length} findings span ${scanIds.length} scans. Pass --scan <id> to narrow, or --output-dir <path> to override the default scan-scoped output directory.`,
      );
    }
    const outputDir = resolveOutputDir(opts, scanId);
    const imagesDir = join(outputDir, "images");
    if (!opts.dryRun) mkdirSync(outputDir, { recursive: true });

    const freezeOn = !opts.noScreenshots && !opts.dryRun && isFreezeAvailable();
    const reverifyOn = !!opts.repo;
    const droppedDir = join(outputDir, "_dropped");
    console.log(chalk.red.bold("\n  ◆ pwnkit") + chalk.gray(` disclose — ${selected.length} finding${selected.length === 1 ? "" : "s"}`));
    console.log(chalk.gray(`  output: ${outputDir}${opts.dryRun ? " (dry-run — nothing written)" : ""}`));
    console.log(chalk.gray(`  screenshots: ${freezeOn ? "on (freeze)" : opts.noScreenshots ? "disabled" : opts.dryRun ? "skipped (dry-run)" : "disabled (freeze not on PATH)"}`));
    if (reverifyOn) {
      console.log(chalk.gray(`  reverify:    ${opts.repo}${opts.ref ? ` @ ${opts.ref}` : " @ HEAD"}${opts.dropFixed ? " (fixed → _dropped/)" : ""}`));
    } else {
      console.log(chalk.gray(`  reverify:    disabled (pass --repo to enable)`));
    }
    console.log("");

    type ResultState = "wrote" | "skipped-exists" | "dropped";
    const results: Array<{ finding: FindingRow; filename: string; primaryCwe: string; cvssScore: number; screenshot: boolean; patchStatus?: PatchStatus; state: ResultState }> = [];
    for (const row of selected) {
      const finding = rowToFinding(row);
      let patchStatus: ReverifyResult | undefined;
      let versionRange: VersionRangeResult | undefined;
      if (reverifyOn) {
        try {
          patchStatus = verifyAgainstRef(finding, { repoPath: opts.repo!, ref: opts.ref, checkout: !!opts.ref });
        } catch (err) {
          console.log(chalk.red(`  reverify failed on ${row.id.slice(0, 8)}: ${err instanceof Error ? err.message : String(err)}`));
        }
        try {
          versionRange = detectVersionRange(finding, { repoPath: opts.repo! });
        } catch (err) {
          console.log(chalk.red(`  version-range failed on ${row.id.slice(0, 8)}: ${err instanceof Error ? err.message : String(err)}`));
        }
        // Sibling-code correct-pattern extractor (#172). If the finding has no
        // pre-populated code example, scan its prose for "correct pattern at
        // file.ts:N" cues and read the matching snippet from the local repo —
        // the advisory template renders this verbatim under "Suggested fix".
        if (!finding.remediation?.codeExample?.after) {
          try {
            const sibling = extractSiblingFix(finding, { repoPath: opts.repo! });
            if (sibling) {
              const existing = finding.remediation;
              finding.remediation = {
                summary: existing?.summary ?? "",
                steps: existing?.steps ?? [],
                references: existing?.references ?? [],
                codeExample: {
                  before: "",
                  after: sibling.snippet,
                  language: sibling.language,
                },
              };
            }
          } catch (err) {
            console.log(chalk.red(`  sibling-fix failed on ${row.id.slice(0, 8)}: ${err instanceof Error ? err.message : String(err)}`));
          }
        }
      }

      // If --drop-fixed, route "fixed" / "file-removed" findings into _dropped/
      // with a reason file instead of into the main advisory bundle.
      if (patchStatus && opts.dropFixed && (patchStatus.status === "fixed" || patchStatus.status === "file-removed")) {
        if (!opts.dryRun) {
          mkdirSync(droppedDir, { recursive: true });
          const reasonPath = join(droppedDir, `${finding.id.slice(0, 8)}-${finding.severity}-${patchStatus.status}.md`);
          const body = [
            `# Dropped: ${finding.title}`,
            "",
            `- **Status:** ${patchStatus.status}`,
            `- **Ref:** \`${patchStatus.ref}\``,
            `- **Scan:** \`${scanId}\``,
            `- **Finding id:** \`${finding.id}\``,
            "",
            "## Notes",
            "",
            ...patchStatus.notes.map((n) => `- ${n}`),
            "",
            "## Refs checked",
            "",
            ...patchStatus.refsChecked.map((r) => `- \`${r.file}${r.line ? `:${r.line}` : ""}\``),
            "",
          ].join("\n");
          writeFileSync(reasonPath, body, "utf8");
        }
        console.log(
          `  ${chalk.gray("drop")}  ${chalk.dim((row.title + " …").slice(0, 64).padEnd(64))}  ${chalk.gray(`patch=${patchStatus.status}`)}`
        );
        results.push({ finding: row, filename: "_dropped", primaryCwe: "", cvssScore: 0, screenshot: false, patchStatus: patchStatus.status, state: "dropped" });
        continue;
      }

      const screenshots: AdvisoryScreenshot[] = [];
      let wroteShot = false;
      if (freezeOn) {
        const shot = renderExploitScreenshot(finding, { outputDir: imagesDir, markdownDir: outputDir });
        if (shot) {
          screenshots.push({ alt: shot.alt, relativePath: shot.relativePath, caption: shot.caption, width: 1200 });
          wroteShot = true;
        }
      }
      const ctx: AdvisoryContext = { scanId, screenshots, patchStatus, versionRange };
      const rendered = renderAdvisoryMarkdown(finding, ctx);
      const path = join(outputDir, rendered.filename);
      let state: ResultState = "wrote";
      if (!opts.dryRun) {
        if (existsSync(path)) {
          state = "skipped-exists";
        } else {
          writeFileSync(path, rendered.markdown, "utf8");
        }
      }
      results.push({ finding: row, filename: rendered.filename, primaryCwe: rendered.primaryCwe, cvssScore: rendered.cvssScore, screenshot: wroteShot, patchStatus: patchStatus?.status, state });
      const shotMark = wroteShot ? chalk.cyan(" +png") : chalk.gray("     ");
      const patchMark = patchStatus ? " " + STATUS_COLOUR[patchStatus.status](`[${patchStatus.status}]`) : "";
      const verb = state === "skipped-exists"
        ? chalk.yellow("skip ")
        : chalk.green("wrote");
      console.log(
        `  ${verb}  ${chalk.white(rendered.filename.padEnd(70))}  ${chalk.cyan(rendered.primaryCwe.padEnd(10))}  ${chalk.dim(`cvss=${rendered.cvssScore.toFixed(1)}`)}${shotMark}${patchMark}`
      );
    }

    if (results.length > 0 && !opts.dryRun) {
      const indexPath = join(outputDir, "INDEX.md");
      const drafts = results.filter((r) => r.state === "wrote" || r.state === "skipped-exists");
      const dropped = results.filter((r) => r.state === "dropped");
      const stateBadge = (s: ResultState) => s === "wrote" ? "new" : s === "skipped-exists" ? "existing" : "dropped";
      const scanLabel = scanIds.length === 1 ? `\`${scanId}\`` : `\`${scanIds.join("`, `")}\` (${scanIds.length} scans)`;
      const indexContent = [
        "# Disclosure batch",
        "",
        `- Scan: ${scanLabel}`,
        `- Drafts: ${drafts.length} (${results.filter((r) => r.state === "wrote").length} new, ${results.filter((r) => r.state === "skipped-exists").length} existing)`,
        dropped.length > 0 ? `- Dropped: ${dropped.length} (see \`_dropped/\`)` : undefined,
        `- Generated: ${new Date().toISOString()}`,
        "",
        "## Filing order",
        "",
        "| State | File | Primary CWE | CVSS | Patch status |",
        "|---|---|---|---|---|",
        ...drafts.map((r) => `| ${stateBadge(r.state)} | \`${r.filename}\` | ${r.primaryCwe} | ${r.cvssScore.toFixed(1)} | ${r.patchStatus ?? "—"} |`),
        ...(dropped.length > 0 ? [
          "",
          "## Dropped",
          "",
          "| File | Reason |",
          "|---|---|",
          ...dropped.map((r) => `| \`_dropped/${r.finding.id.slice(0, 8)}-${r.finding.severity}-${r.patchStatus}.md\` | ${r.patchStatus} |`),
        ] : []),
        "",
        "## Before filing each advisory",
        "",
        "1. Re-read the draft — the PoC and Patch Status sections are auto-populated from the scan but you should sanity-check against the current upstream HEAD.",
        "2. Verify the CVSS vector suggested by pwnkit is still appropriate for your deployment model.",
        "3. Attach or replace screenshots in the PoC section as needed.",
        "4. File at https://github.com/<owner>/<repo>/security/advisories/new",
        "",
      ].filter((line) => line !== undefined).join("\n");
      writeFileSync(indexPath, indexContent, "utf8");
      console.log("\n  " + chalk.gray(`wrote ${indexPath}`));
    }
  } finally {
    db.close();
  }
}

export function registerDiscloseCommand(program: Command): void {
  program
    .command("disclose")
    .description("Assemble GHSA-ready advisory drafts from persisted findings")
    .argument("[findingId]", "Finding ID (or prefix). Omit to batch every finding at or above --severity-floor.")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--scan <scanId>", "Restrict to findings from this scan")
    .option("--output-dir <path>", "Directory to write advisories into (default ~/pwnkit/disclosures/scan-<id>)")
    .option("--severity-floor <severity>", "In batch mode, only draft findings at or above this severity", "medium")
    .option("--no-screenshots", "Skip terminal-screenshot rendering even when freeze is available")
    .option("--repo <path>", "Local git checkout of the target repo to re-verify findings against")
    .option("--ref <tag>", "Git ref (tag/sha/branch) to check out before verifying — defaults to the repo's current HEAD")
    .option("--drop-fixed", "Move findings whose status is 'fixed' or 'file-removed' into _dropped/ with a reason file instead of drafting an advisory for them", false)
    .option("--dry-run", "Show what would be written without writing files", false)
    .action(async (findingId: string | undefined, opts: DiscloseOptions) => {
      await disclose(findingId, opts);
    });
}
