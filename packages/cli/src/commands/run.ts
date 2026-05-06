import { writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import chalk from "chalk";
import { VERSION } from "@pwnkit/shared";
import type { ScanDepth, OutputFormat, RuntimeMode, ScanMode, AuthConfig, ScanReport } from "@pwnkit/shared";
import { formatAuditReport, formatReviewReport, formatReport, generatePdfReport } from "../formatters/index.js";
import { buildShareUrl, checkRuntimeAvailability, getRuntimeAvailability } from "../utils.js";

type CoreModule = typeof import("@pwnkit/core");

let coreModulePromise: Promise<CoreModule> | null = null;

async function loadCoreModule(): Promise<CoreModule> {
  if (!coreModulePromise) {
    // Under Bun in a dev workspace checkout we can import the TypeScript
    // source directly, skipping the compile step. In the packaged tarball
    // that path doesn't exist, so fall back to the bundled module. The
    // presence-check keeps both Bun-dev and Bun-prod users happy.
    const srcUrl = new URL("../../../core/src/index.ts", import.meta.url);
    const srcExists = process.versions.bun && existsSync(fileURLToPath(srcUrl));
    coreModulePromise = srcExists
      ? import(srcUrl.href) as Promise<CoreModule>
      : import("@pwnkit/core");
  }
  return coreModulePromise;
}

export interface RunOptions {
  target: string;
  targetType?: "npm-package" | "pypi-package" | "cargo-package" | "oci-image" | "source-code" | "url" | "web-app";
  resumeScanId?: string;
  diffBase?: string;
  changedOnly?: boolean;
  depth: ScanDepth;
  format: OutputFormat;
  runtime: RuntimeMode;
  mode?: ScanMode;
  timeout: number;
  verbose: boolean;
  dbPath?: string;
  apiKey?: string;
  model?: string;
  packageVersion?: string;
  reportPath?: string;
  repoPath?: string;
  auth?: AuthConfig;
  apiSpecPath?: string;
  exportTarget?: string;
  race?: boolean;
  egats?: boolean;
  /** Hard per-scan USD cost ceiling. Aborts cleanly with partial findings if exceeded. */
  costCeilingUsd?: number;
  /** Open the operator TUI after the run completes. */
  tui?: boolean;
  /** Path to a JSON scope file (pwnkit#215). Threaded into ScanConfig.scopeFile. */
  scopeFile?: string;
  sessionUiFactory?: (options: {
    target: string;
    depth: string;
    mode: "scan" | "audit" | "review";
  }) => Promise<{
    onEvent: (event: any) => void;
    setReport: (report: any) => void;
    waitForExit: () => Promise<void>;
    getPendingUserMessages?: () => string[];
  }>;
}

interface ResultLinePayload {
  ok: boolean;
  exitCode: number;
  exit_reason: string;
  target: string;
  targetType?: string;
  runtime: RuntimeMode;
  format: OutputFormat;
  cost_usd?: number;
  token_input?: number;
  token_output?: number;
  finding_count?: number;
  estimatedCostUsd?: number;
  usage?: { inputTokens: number; outputTokens: number };
  summary?: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  error?: string;
}

function toScanReport(report: any): ScanReport {
  if (report.targetType === "npm-package" || report.targetType === "pypi-package" || report.targetType === "cargo-package" || report.targetType === "oci-image") {
    return {
      target: `${report.package}@${report.version}`,
      scanDepth: "deep",
      startedAt: report.startedAt,
      completedAt: report.completedAt,
      durationMs: report.durationMs,
      summary: report.summary,
      findings: report.findings,
      warnings: [],
    };
  }

  if (report.targetType === "source-code") {
    return {
      target: report.repo,
      scanDepth: "deep",
      startedAt: report.startedAt,
      completedAt: report.completedAt,
      durationMs: report.durationMs,
      summary: report.summary,
      findings: report.findings,
      warnings: [],
    };
  }

  return report as ScanReport;
}

function getEstimatedCost(report: any): number | undefined {
  if (typeof report?.estimatedCostUsd === "number") return report.estimatedCostUsd;
  if (typeof report?.benchmarkMeta?.estimatedCostUsd === "number") return report.benchmarkMeta.estimatedCostUsd;
  return undefined;
}

function getUsage(report: any): { inputTokens: number; outputTokens: number } | undefined {
  return report?.usage;
}

function getTargetType(report: any, opts: RunOptions): string | undefined {
  return report?.targetType ?? opts.targetType;
}

function emitResultLine(payload: ResultLinePayload): void {
  if (process.env.PWNKIT_EMIT_RESULT_LINE !== "1" && !process.env.PWNKIT_CLOUD_SINK) return;
  console.log(`PWNKIT_RESULT=${JSON.stringify(payload)}`);
}

function getCloudFinalSinkConfig(): { sinkUrl: string; scanId: string; token?: string } | null {
  if (process.env.PWNKIT_FEATURE_CLOUD_SINK === "0") return null;
  const sinkUrl = process.env.PWNKIT_CLOUD_SINK?.trim();
  const scanId = process.env.PWNKIT_CLOUD_SCAN_ID?.trim();
  if (!sinkUrl || !scanId) return null;
  const token = process.env.PWNKIT_CLOUD_TOKEN?.trim() || undefined;
  return { sinkUrl, scanId, token };
}

async function postFinalResultToCloud(report: unknown): Promise<void> {
  const config = getCloudFinalSinkConfig();
  if (!config) return;
  const url = `${config.sinkUrl.replace(/\/+$/, "")}/scans/${encodeURIComponent(config.scanId)}/findings`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Pwnkit-Scan-Id": config.scanId,
  };
  if (config.token) headers.Authorization = `Bearer ${config.token}`;

  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({ report, final: true }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      process.stderr.write(
        `[pwnkit cloud-sink] report POST ${url} returned ${res.status}: ${text.slice(0, 200)}\n`,
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[pwnkit cloud-sink] report POST ${url} failed: ${msg}\n`);
  }
}

export async function runUnified(opts: RunOptions): Promise<void> {
  const { target, depth, format, runtime, timeout } = opts;
  const core = await loadCoreModule();

  const validRuntimes = ["api", "claude", "codex", "gemini", "auto"];
  if (!validRuntimes.includes(runtime)) {
    console.error(chalk.red(`Unknown runtime '${runtime}'. Valid: ${validRuntimes.join(", ")}`));
    process.exit(2);
  }

  // Check non-auto runtime availability
  if (runtime !== "api" && runtime !== "auto") {
    const rt = core.createRuntime({ type: runtime, timeout });
    const available = await rt.isAvailable();
    if (!available) {
      console.error(chalk.red(`Runtime '${runtime}' not available. Is ${runtime} installed?`));
      process.exit(2);
    }
  }

  if (format === "terminal") await checkRuntimeAvailability(runtime);

  // Ink TUI for terminal, silent for json/md
  let inkUI: { onEvent: (event: any) => void; setReport: (report: any) => void; waitForExit: () => Promise<void>; getPendingUserMessages?: () => string[] } | null = null;
  let eventHandler: (event: any) => void = () => {};
  let getPendingUserMessages: (() => string[]) | undefined;

  if (format === "terminal" && process.stdout.isTTY && process.stdin.isTTY) {
    const mode = opts.targetType === "npm-package" || opts.targetType === "pypi-package" || opts.targetType === "cargo-package" || opts.targetType === "oci-image" ? "audit"
      : opts.targetType === "source-code" ? "review"
      : "scan";
    if (opts.sessionUiFactory) {
      inkUI = await opts.sessionUiFactory({ target, depth, mode });
    } else {
      const { isBunRuntime } = await import("../tui/runtime.js");
      if (isBunRuntime()) {
        const { createOpenTuiSession } = await import("../tui/run.js");
        const availability = await getRuntimeAvailability();
        inkUI = await createOpenTuiSession({
          target,
          depth,
          mode,
          runtime,
          apiProviderLabel: availability.apiRuntime.providerLabel,
          apiConfigured: availability.apiRuntime.configured,
          apiConnected: availability.hasApiKey && availability.apiRuntime.valid,
          localRuntimes: availability.availableRuntimes,
          model: opts.model,
        });
      } else {
        const { renderScanUI } = await import("../ui/renderScan.js");
        inkUI = renderScanUI({ version: VERSION, target, depth, mode });
      }
    }
    eventHandler = inkUI.onEvent;
    getPendingUserMessages = inkUI.getPendingUserMessages;
  }

  try {
    const report = opts.targetType === "url" || opts.targetType === "web-app"
      ? await core.agenticScan({
          config: {
            target,
            depth,
            format,
            runtime,
            mode: opts.mode ?? "deep",
            timeout,
            verbose: opts.verbose,
            apiKey: opts.apiKey,
            model: opts.model,
            repoPath: opts.repoPath,
            auth: opts.auth,
            apiSpecPath: opts.apiSpecPath,
            race: opts.race,
            egats: opts.egats,
            costCeilingUsd: opts.costCeilingUsd,
            scopeFile: opts.scopeFile,
          },
          dbPath: opts.dbPath,
          onEvent: eventHandler,
          getPendingUserMessages,
          resumeScanId: opts.resumeScanId,
        })
      : await core.runPipeline({
          target,
          targetType: opts.targetType,
          resumeScanId: opts.resumeScanId,
          diffBase: opts.diffBase,
          changedOnly: opts.changedOnly,
          depth,
          format,
          runtime,
          onEvent: eventHandler,
          dbPath: opts.dbPath,
          apiKey: opts.apiKey,
          model: opts.model,
          timeout,
          packageVersion: opts.packageVersion,
        } as any);

    const reportAny = report as any;

    if (opts.targetType !== "url" && opts.targetType !== "web-app") {
      await postFinalResultToCloud(reportAny);
    }

    if (inkUI) {
      inkUI.setReport(report as any);
      await inkUI.waitForExit();
    } else {
      if (format === "html" || format === "pdf") {
        const extension = format === "pdf" ? "pdf" : "html";
        const filePath = opts.reportPath
          ? resolve(opts.reportPath)
          : join(tmpdir(), `pwnkit-report-${Date.now()}.${extension}`);
        if (format === "pdf") {
          await generatePdfReport(toScanReport(reportAny), filePath);
        } else {
          const output = reportAny.targetType === "npm-package" || reportAny.targetType === "pypi-package" || reportAny.targetType === "cargo-package" || reportAny.targetType === "oci-image"
            ? formatAuditReport(reportAny, format)
            : reportAny.targetType === "source-code"
              ? formatReviewReport(reportAny, format)
              : formatReport(reportAny, format);
          await writeFile(filePath, output, "utf-8");
        }
        console.log(chalk.green(`Report saved to: ${filePath}`));
        const openCmd = process.platform === "darwin" ? "open" : "xdg-open";
        execFile(openCmd, [filePath], () => {});
      } else {
        const output = reportAny.targetType === "npm-package" || reportAny.targetType === "pypi-package" || reportAny.targetType === "cargo-package" || reportAny.targetType === "oci-image"
          ? formatAuditReport(reportAny, format)
          : reportAny.targetType === "source-code"
            ? formatReviewReport(reportAny, format)
            : formatReport(reportAny, format);
        console.log(output);
      }
    }

    if (opts.tui && process.stdout.isTTY && process.stdin.isTTY) {
      const { showOperatorTui } = await import("../ui/Tui.js");
      await showOperatorTui({
        dbPath: opts.dbPath,
      });
    }

    let exitCode = 0;
    const estimatedCostUsd = getEstimatedCost(reportAny);
    const usage = getUsage(reportAny);

    // ── Export findings to issue tracker if requested ──
    if (opts.exportTarget) {
      const match = opts.exportTarget.match(/^github:(.+\/.+)$/);
      if (!match) {
        console.error(
          chalk.red(`Invalid --export format: '${opts.exportTarget}'. Expected: github:owner/repo`),
        );
        process.exit(2);
      }
      const repo = match[1];
      const reportAny = report as any;
      const findings = reportAny.findings ?? [];
      if (findings.length === 0) {
        console.log(chalk.yellow("No findings to export."));
      } else {
        const { exportToGitHubIssues } = await import("../exporters/github-issues.js");
        console.log(chalk.blue(`Exporting ${findings.length} finding(s) to GitHub Issues on ${repo}...`));
        const result = await exportToGitHubIssues(findings, repo);
        console.log(
          chalk.green(`Export complete: ${result.created} created, ${result.skipped} skipped (duplicates).`),
        );
      }
    }

    const ceilingRaw = process.env.PWNKIT_COST_CEILING_USD?.trim();
    if (ceilingRaw) {
      const ceiling = Number(ceilingRaw);
      if (Number.isFinite(ceiling) && estimatedCostUsd !== undefined && estimatedCostUsd > ceiling) {
        console.error(chalk.red(`Cost ceiling exceeded: $${estimatedCostUsd.toFixed(4)} > $${ceiling.toFixed(4)}`));
        exitCode = 4;
      }
    }

    // Cost ceiling abort from the live scan path: exit code 4 so operators
    // (CI, schedulers, cloud watchers) can distinguish a clean budget abort
    // from a normal completion or failure.
    if ((report as ScanReport).costCeilingExceeded && exitCode === 0) {
      console.error(
        chalk.yellow(
          `Scan aborted: cost ceiling exceeded. ${report.summary.totalFindings} partial finding(s) preserved.`,
        ),
      );
      exitCode = 4;
    }

    if (exitCode === 0 && (report.summary.critical > 0 || report.summary.high > 0)) {
      exitCode = 1;
    }

    emitResultLine({
      ok: exitCode === 0,
      exitCode,
      exit_reason:
        exitCode === 4
          ? "cost_ceiling_exceeded"
          : exitCode === 1
            ? "findings"
            : "completed",
      target,
      targetType: getTargetType(reportAny, opts),
      runtime,
      format,
      cost_usd: estimatedCostUsd,
      token_input: usage?.inputTokens,
      token_output: usage?.outputTokens,
      finding_count: report.summary.totalFindings,
      estimatedCostUsd,
      usage,
      summary: report.summary,
    });

    if (exitCode !== 0) process.exit(exitCode);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (inkUI) {
      eventHandler({
        type: "error",
        stage: "report",
        message,
      });
      await inkUI.waitForExit();
      return;
    }
    console.error(chalk.red(message));
    emitResultLine({
      ok: false,
      exitCode: 2,
      exit_reason: "error",
      target,
      targetType: opts.targetType,
      runtime,
      format,
      error: message,
    });
    process.exit(2);
  }
}
