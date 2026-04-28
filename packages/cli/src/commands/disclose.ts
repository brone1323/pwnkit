import type { Command } from "commander";
import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { homedir } from "node:os";
import chalk from "chalk";
import type { Finding, AttackCategory, Severity, Evidence, FindingStatus, PocStep } from "@pwnkit/shared";
import {
  renderAdvisoryMarkdown,
  renderExploitScreenshot,
  isFreezeAvailable,
  verifyAgainstRef,
  detectVersionRange,
  extractSiblingFix,
  executePocSteps,
  type AdvisoryContext,
  type AdvisoryScreenshot,
  type ReverifyResult,
  type VersionRangeResult,
  type PatchStatus,
  type PocExecutionReport,
  type PocExecutionTarget,
  type PocStepResult,
  decideFilingState,
  assembleBundleIndex,
  formatDroppedReason,
  droppedFilename,
  type BundleEntry,
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
  reverify?: boolean;
  targetUrl?: string;
  targetEnv?: string[];
  targetTimeoutMs?: string;
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
  pocSteps?: string | null;
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
  if (row.pocSteps) {
    try {
      const parsed = JSON.parse(row.pocSteps) as PocStep[];
      if (Array.isArray(parsed) && parsed.length > 0) finding.pocSteps = parsed;
    } catch {
      // Malformed pocSteps blob — drop silently and fall back to evidence prose.
    }
  }
  return finding;
}

/**
 * Parse `--target-env KEY=VAL --target-env OTHER=VAL` repeated flags into a
 * `Record<string, string>` shaped for `PocExecutionTarget.env`.
 */
function parseTargetEnv(pairs: string[] | undefined): Record<string, string> | undefined {
  if (!pairs || pairs.length === 0) return undefined;
  const out: Record<string, string> = {};
  for (const raw of pairs) {
    const eq = raw.indexOf("=");
    if (eq <= 0) {
      throw new Error(`--target-env expects KEY=VALUE, got: ${raw}`);
    }
    const k = raw.slice(0, eq);
    const v = raw.slice(eq + 1);
    out[k] = v;
  }
  return out;
}

const VERDICT_COLOUR: Record<NonNullable<PocExecutionReport["overallVerdict"]>, (s: string) => string> = {
  exploit_still_works: (s) => chalk.green(s),
  exploit_broken: (s) => chalk.yellow(s),
  could_not_run: (s) => chalk.red(s),
};

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
    const behaviouralOn = !!opts.reverify && !!opts.targetUrl;
    if (opts.reverify && !opts.targetUrl) {
      throw new Error("--reverify requires --target-url <url> to dispatch http actions against.");
    }
    const targetEnv = parseTargetEnv(opts.targetEnv);
    const targetTimeoutMs = opts.targetTimeoutMs ? Number(opts.targetTimeoutMs) : undefined;
    if (targetTimeoutMs !== undefined && (!Number.isFinite(targetTimeoutMs) || targetTimeoutMs <= 0)) {
      throw new Error(`--target-timeout-ms must be a positive integer, got: ${opts.targetTimeoutMs}`);
    }
    const droppedDir = join(outputDir, "_dropped");
    console.log(chalk.red.bold("\n  ◆ pwnkit") + chalk.gray(` disclose — ${selected.length} finding${selected.length === 1 ? "" : "s"}`));
    console.log(chalk.gray(`  output: ${outputDir}${opts.dryRun ? " (dry-run — nothing written)" : ""}`));
    console.log(chalk.gray(`  screenshots: ${freezeOn ? "on (freeze)" : opts.noScreenshots ? "disabled" : opts.dryRun ? "skipped (dry-run)" : "disabled (freeze not on PATH)"}`));
    if (reverifyOn) {
      console.log(chalk.gray(`  reverify:    ${opts.repo}${opts.ref ? ` @ ${opts.ref}` : " @ HEAD"}${opts.dropFixed ? " (fixed → _dropped/)" : ""}`));
    } else {
      console.log(chalk.gray(`  reverify:    disabled (pass --repo to enable)`));
    }
    if (behaviouralOn) {
      console.log(chalk.gray(`  behavioural: ${opts.targetUrl}${targetTimeoutMs ? ` (timeout=${targetTimeoutMs}ms)` : ""}`));
    } else {
      console.log(chalk.gray(`  behavioural: disabled (pass --reverify --target-url to enable)`));
    }
    console.log("");

    type ResultState = "wrote" | "skipped-exists" | "dropped";
    interface FindingResult extends BundleEntry {
      severity: string;
      title: string;
      shotCount: number;
      state: ResultState;
    }
    const results: FindingResult[] = [];
    for (const row of selected) {
      const finding = rowToFinding(row);
      let patchStatus: ReverifyResult | undefined;
      let versionRange: VersionRangeResult | undefined;
      let behaviouralReport: PocExecutionReport | undefined;
      if (behaviouralOn && finding.pocSteps && finding.pocSteps.length > 0) {
        const target: PocExecutionTarget = {
          baseUrl: opts.targetUrl,
          env: targetEnv,
          timeoutMs: targetTimeoutMs,
        };
        try {
          behaviouralReport = await executePocSteps(finding, target);
        } catch (err) {
          console.log(chalk.red(`  behavioural reverify failed on ${row.id.slice(0, 8)}: ${err instanceof Error ? err.message : String(err)}`));
        }
        if (behaviouralReport && !opts.dryRun) {
          const execPath = join(outputDir, `${finding.id.slice(0, 8)}.execution.json`);
          writeFileSync(execPath, JSON.stringify(behaviouralReport, null, 2), "utf8");
        }
      }
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

      // ── Filing-state gate (#168) ──
      // Combine code-level patch status (canary) and behavioural verdict
      // (#171) into a single keep / drop / needs-review verdict the operator
      // sees in the INDEX. Logic lives in @pwnkit/core/disclose/bundle so the
      // tests can exercise it without going through the CLI.
      const { filingState, dropReason } = decideFilingState({
        patchStatus,
        behaviouralReport,
        dropFixed: !!opts.dropFixed,
      });

      // Route dropped findings into _dropped/ with a reason file. This catches
      // both code-level drops (canary-fixed) and behavioural drops (exploit
      // no longer fires) — the reason file makes the audit trail explicit.
      if (filingState === "drop") {
        const droppedEntry: BundleEntry = {
          finding,
          filename: "",
          primaryCwe: "",
          cvssScore: 0,
          patchStatus: patchStatus?.status,
          behaviouralVerdict: behaviouralReport?.overallVerdict,
          filingState,
          dropReason,
        };
        if (!opts.dryRun) {
          mkdirSync(droppedDir, { recursive: true });
          const reasonPath = join(droppedDir, droppedFilename(droppedEntry));
          const body = formatDroppedReason({
            finding,
            scanId,
            patchStatus,
            behaviouralReport,
            reason: dropReason ?? "dropped",
          });
          writeFileSync(reasonPath, body, "utf8");
        }
        console.log(
          `  ${chalk.gray("drop")}  ${chalk.dim((row.title + " …").slice(0, 64).padEnd(64))}  ${chalk.gray(dropReason ?? "dropped")}`
        );
        results.push({
          ...droppedEntry,
          severity: row.severity,
          title: row.title,
          shotCount: 0,
          state: "dropped",
        });
        continue;
      }

      // ── Multi-frame screenshot rendering (#168 / #170) ──
      // When the finding has a step graph, render one PNG per step and embed
      // each as its own <img>. Falls back to the single-frame composite when
      // the graph is absent so existing scans without pocSteps still get a
      // screenshot the way #169 shipped them.
      const screenshots: AdvisoryScreenshot[] = [];
      let shotCount = 0;
      if (freezeOn) {
        if (finding.pocSteps && finding.pocSteps.length > 0) {
          const stepResults: Record<string, PocStepResult> = {};
          if (behaviouralReport) {
            for (const sr of behaviouralReport.steps) stepResults[sr.stepId] = sr;
          }
          const frames = renderExploitScreenshot(finding, {
            outputDir: imagesDir,
            markdownDir: outputDir,
            pocSteps: finding.pocSteps,
            stepResults,
          });
          for (const f of frames) {
            screenshots.push({ alt: f.alt, relativePath: f.relativePath, caption: f.caption, width: 1200 });
            shotCount++;
          }
        } else {
          const shot = renderExploitScreenshot(finding, { outputDir: imagesDir, markdownDir: outputDir });
          if (shot) {
            screenshots.push({ alt: shot.alt, relativePath: shot.relativePath, caption: shot.caption, width: 1200 });
            shotCount = 1;
          }
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
      results.push({
        finding,
        filename: rendered.filename,
        primaryCwe: rendered.primaryCwe,
        cvssScore: rendered.cvssScore,
        severity: row.severity,
        title: row.title,
        shotCount,
        patchStatus: patchStatus?.status,
        behaviouralVerdict: behaviouralReport?.overallVerdict,
        filingState,
        state,
      });
      const shotMark = shotCount > 0 ? chalk.cyan(` +${shotCount}png`) : chalk.gray("       ");
      const patchMark = patchStatus ? " " + STATUS_COLOUR[patchStatus.status](`[${patchStatus.status}]`) : "";
      const behaviouralMark = behaviouralReport
        ? " " + VERDICT_COLOUR[behaviouralReport.overallVerdict](`[${behaviouralReport.overallVerdict}]`)
        : "";
      const reviewMark = filingState === "needs-review" ? " " + chalk.magenta("[needs-review]") : "";
      const verb = state === "skipped-exists"
        ? chalk.yellow("skip ")
        : chalk.green("wrote");
      console.log(
        `  ${verb}  ${chalk.white(rendered.filename.padEnd(70))}  ${chalk.cyan(rendered.primaryCwe.padEnd(10))}  ${chalk.dim(`cvss=${rendered.cvssScore.toFixed(1)}`)}${shotMark}${patchMark}${behaviouralMark}${reviewMark}`
      );
    }

    if (!opts.dryRun) {
      const indexPath = join(outputDir, "INDEX.md");
      // Bundle index assembly is pure and lives in @pwnkit/core/disclose so
      // the table layout can be tested without touching the CLI / db / fs.
      const indexContent = assembleBundleIndex(results, { scanIds });
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
    .option("--reverify", "Behaviourally re-verify each finding's PoC step graph against a live target. Requires --target-url.", false)
    .option("--target-url <url>", "Base URL the behavioural re-verify runtime dispatches http actions against (e.g. http://localhost:3108)")
    .option("--target-env <kv...>", "Repeated KEY=VALUE pairs added to the shell-action environment for behavioural re-verify")
    .option("--target-timeout-ms <ms>", "Per-step timeout for behavioural re-verify, in milliseconds (default 30000)")
    .option("--dry-run", "Show what would be written without writing files", false)
    .action(async (findingId: string | undefined, opts: DiscloseOptions) => {
      await disclose(findingId, opts);
    });
}
