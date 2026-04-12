import type { Command } from "commander";
import chalk from "chalk";
import { statSync } from "node:fs";
import { resolve } from "node:path";
import type { Finding, ScanReport, Severity } from "@pwnkit/shared";
import type { KernelOracleResult } from "@pwnkit/core";
import { formatSarif } from "../formatters/sarif.js";

const VALID_FORMATS = ["auto", "kasan", "ubsan", "oops", "syzkaller", "generic"] as const;
const VALID_OUTPUT_FORMATS = ["terminal", "json", "sarif"] as const;

type IngestFormat = (typeof VALID_FORMATS)[number];
type IngestOutputFormat = (typeof VALID_OUTPUT_FORMATS)[number];

interface IngestOpts {
  format: string;
  output: string;
  verify?: boolean;
  verbose?: boolean;
}

interface VerifiedCrashResult {
  sourcePath: string;
  reproducerPath?: string;
  finding: Finding;
  verification: KernelOracleResult;
}

export function registerIngestCommand(program: Command): void {
  program
    .command("ingest")
    .description("Import kernel crash reports (KASAN, UBSAN, oops, syzkaller) into pwnkit findings")
    .argument("<path>", "Path to a crash report file or directory of reports")
    .option("--format <format>", "Input format: auto | kasan | ubsan | oops | syzkaller | generic", "auto")
    .option("-o, --output <format>", "Output format: terminal | json | sarif", "terminal")
    .option("--verify", "Run kernel oracle verification for each report/reproducer")
    .option("-v, --verbose", "Verbose output")
    .action(async (inputPath: string, opts: IngestOpts) => {
      try {
        const format = opts.format as IngestFormat;
        const outputFormat = opts.output as IngestOutputFormat;

        if (!VALID_FORMATS.includes(format)) {
          throw new Error(
            `Invalid input format '${format}'. Valid: ${VALID_FORMATS.join(", ")}`,
          );
        }
        if (!VALID_OUTPUT_FORMATS.includes(outputFormat)) {
          throw new Error(
            `Invalid output format '${outputFormat}'. Valid: ${VALID_OUTPUT_FORMATS.join(", ")}`,
          );
        }
        // sarif+verify is supported: verification results are embedded as SARIF result properties

        const resolved = resolve(inputPath);
        const stat = statSync(resolved);

        const {
          ingestFile,
          ingestDirectory,
          ingestArtifactsFromFile,
          ingestArtifactsFromDirectory,
          verifyKernelCrash,
        } = await import("@pwnkit/core");

        let findings: Finding[];
        let verifiedResults: VerifiedCrashResult[] | undefined;

        if (opts.verify) {
          const artifacts = stat.isDirectory()
            ? (console.log(chalk.blue(`Scanning and verifying directory: ${resolved}`)), ingestArtifactsFromDirectory(resolved))
            : (console.log(chalk.blue(`Parsing and verifying crash report: ${resolved}`)), ingestArtifactsFromFile(resolved));

          verifiedResults = await Promise.all(
            artifacts.map(async (artifact) => ({
              sourcePath: artifact.sourcePath,
              reproducerPath: artifact.reproducerPath,
              finding: artifact.finding,
              verification: await verifyKernelCrash(artifact.finding, {
                raw: artifact.report.rawText,
                crashType: artifact.report.crashType,
                faultingFunction: artifact.report.faultingFunction,
                stackFrames: artifact.report.callStack,
                reproducer: artifact.report.reproducer,
                accessType: artifact.report.accessType,
                accessSize: artifact.report.accessSize,
                subsystem: artifact.report.subsystem,
              }),
            })),
          );
          findings = verifiedResults.map((result) => result.finding);
        } else {
          if (stat.isDirectory()) {
            console.log(chalk.blue(`Scanning directory: ${resolved}`));
            findings = ingestDirectory(resolved);
          } else {
            console.log(chalk.blue(`Parsing crash report: ${resolved}`));
            findings = ingestFile(resolved);
          }
        }

        if (findings.length === 0) {
          console.log(chalk.yellow("No crash reports found."));
          return;
        }

        console.log(
          chalk.green(
            `\nIngested ${findings.length} finding${findings.length > 1 ? "s" : ""}:\n`,
          ),
        );

        if (outputFormat === "json") {
          console.log(JSON.stringify(verifiedResults ?? findings, null, 2));
          return;
        }

        if (outputFormat === "sarif") {
          const now = new Date().toISOString();
          const bySev = (sev: Severity) => findings.filter((f) => f.severity === sev).length;
          const syntheticReport: ScanReport = {
            target: resolved,
            scanDepth: "default",
            startedAt: now,
            completedAt: now,
            durationMs: 0,
            summary: {
              totalAttacks: 0,
              totalFindings: findings.length,
              critical: bySev("critical"),
              high: bySev("high"),
              medium: bySev("medium"),
              low: bySev("low"),
              info: bySev("info"),
            },
            findings,
            warnings: [],
          };

          let sarifOutput = formatSarif(syntheticReport);

          // If --verify was used, embed verification results as properties on each SARIF result
          if (verifiedResults) {
            const verifiedById = new Map(
              verifiedResults.map((r) => [r.finding.id, r]),
            );
            const sarif = JSON.parse(sarifOutput);
            const results = sarif.runs?.[0]?.results as Array<{ ruleId: string; properties?: Record<string, unknown> }> | undefined;
            if (results) {
              // Results are in the same order as findings
              for (let i = 0; i < results.length; i++) {
                const f = findings[i];
                if (!f) continue;
                const v = verifiedById.get(f.id);
                if (v) {
                  results[i].properties = {
                    ...results[i].properties,
                    verification: {
                      verified: v.verification.verified,
                      reproduced: v.verification.reproduced,
                      confidence: v.verification.confidence,
                      reason: v.verification.reason,
                    },
                  };
                }
              }
            }
            sarifOutput = JSON.stringify(sarif, null, 2);
          }

          console.log(sarifOutput);
          return;
        }

        // Terminal output
        const severityColor: Record<string, (s: string) => string> = {
          critical: chalk.bgRed.white.bold,
          high: chalk.red.bold,
          medium: chalk.yellow,
          low: chalk.blue,
          info: chalk.gray,
        };

        const verifiedById = new Map<string, VerifiedCrashResult>(
          (verifiedResults ?? []).map((result) => [result.finding.id, result]),
        );

        for (const f of findings) {
          const color = severityColor[f.severity] ?? chalk.white;
          console.log(
            `  ${color(f.severity.toUpperCase().padEnd(8))} ${chalk.white(f.title)}`,
          );
          console.log(
            `           ${chalk.gray(`category=${f.category}  confidence=${(f.confidence ?? 0).toFixed(1)}  id=${f.id.slice(0, 8)}`)}`,
          );
          const verified = verifiedById.get(f.id);
          if (verified) {
            const verdict = verified.verification.verified
              ? chalk.green("VERIFIED")
              : verified.verification.reproduced
                ? chalk.yellow("MISMATCH")
                : chalk.gray("UNVERIFIED");
            console.log(
              `           ${verdict} ${chalk.gray(`runner=${verified.verification.reproduced ? "kernel-vm" : "static"} oracle_confidence=${verified.verification.confidence.toFixed(2)}`)}`,
            );
            if (verified.verification.reason) {
              console.log(
                chalk.gray(`           reason=${verified.verification.reason}`),
              );
            }
          }
          if (opts.verbose && f.evidence.analysis) {
            console.log(
              chalk.gray(`           ${f.evidence.analysis.slice(0, 200)}`),
            );
          }
          console.log();
        }

        // Summary
        const bySeverity = findings.reduce(
          (acc, f) => {
            acc[f.severity] = (acc[f.severity] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>,
        );

        console.log(chalk.white.bold("Summary:"));
        for (const sev of ["critical", "high", "medium", "low", "info"] as const) {
          if (bySeverity[sev]) {
            const color = severityColor[sev] ?? chalk.white;
            console.log(`  ${color(`${sev}: ${bySeverity[sev]}`)}`);
          }
        }
        if (verifiedResults) {
          const verifiedCount = verifiedResults.filter((r) => r.verification.verified).length;
          const reproducedCount = verifiedResults.filter((r) => r.verification.reproduced).length;
          console.log(chalk.white.bold("Verification:"));
          console.log(`  ${chalk.green(`verified: ${verifiedCount}`)}`);
          console.log(`  ${chalk.yellow(`reproduced-but-mismatch: ${reproducedCount - verifiedCount}`)}`);
          console.log(`  ${chalk.gray(`static-only/unverified: ${verifiedResults.length - reproducedCount}`)}`);
        }
      } catch (err) {
        console.error(
          chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`),
        );
        process.exitCode = 1;
      }
    });
}
