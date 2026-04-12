import type { Command } from "commander";
import chalk from "chalk";
import { statSync } from "node:fs";
import { resolve } from "node:path";
import type { Finding } from "@pwnkit/shared";

const VALID_FORMATS = ["auto", "kasan", "ubsan", "oops", "syzkaller", "generic"] as const;
const VALID_OUTPUT_FORMATS = ["terminal", "json", "sarif"] as const;

type IngestFormat = (typeof VALID_FORMATS)[number];
type IngestOutputFormat = (typeof VALID_OUTPUT_FORMATS)[number];

interface IngestOpts {
  format: string;
  output: string;
  verbose?: boolean;
}

export function registerIngestCommand(program: Command): void {
  program
    .command("ingest")
    .description("Import kernel crash reports (KASAN, UBSAN, oops, syzkaller) into pwnkit findings")
    .argument("<path>", "Path to a crash report file or directory of reports")
    .option("--format <format>", "Input format: auto | kasan | ubsan | oops | syzkaller | generic", "auto")
    .option("-o, --output <format>", "Output format: terminal | json | sarif", "terminal")
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

        const resolved = resolve(inputPath);
        const stat = statSync(resolved);

        const { ingestFile, ingestDirectory } = await import("@pwnkit/core");

        let findings: Finding[];

        if (stat.isDirectory()) {
          console.log(chalk.blue(`Scanning directory: ${resolved}`));
          findings = ingestDirectory(resolved);
        } else {
          console.log(chalk.blue(`Parsing crash report: ${resolved}`));
          findings = ingestFile(resolved);
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
          console.log(JSON.stringify(findings, null, 2));
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

        for (const f of findings) {
          const color = severityColor[f.severity] ?? chalk.white;
          console.log(
            `  ${color(f.severity.toUpperCase().padEnd(8))} ${chalk.white(f.title)}`,
          );
          console.log(
            `           ${chalk.gray(`category=${f.category}  confidence=${(f.confidence ?? 0).toFixed(1)}  id=${f.id.slice(0, 8)}`)}`,
          );
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
      } catch (err) {
        console.error(
          chalk.red(`Error: ${err instanceof Error ? err.message : String(err)}`),
        );
        process.exitCode = 1;
      }
    });
}
