#!/usr/bin/env node

/**
 * pwnkit npm audit benchmark — issue #21
 *
 * Ground-truth test suite for npm package security scanning.
 * 81 cases: 27 known-malicious, 27 known-CVE, 27 known-safe.
 *
 * Each case below is verified against npm advisories, GitHub Security
 * Advisories, NVD, Socket.dev, ReversingLabs, or Phylum reports.
 *
 * Usage:
 *   tsx src/npm-bench.ts
 *   tsx src/npm-bench.ts --json
 *   tsx src/npm-bench.ts --depth deep
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { packageAudit } from "@pwnkit/core";
import type { ScanDepth, RuntimeMode } from "@pwnkit/shared";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── CLI Args ──

const args = process.argv.slice(2);
const depth = args.includes("--depth") ? args[args.indexOf("--depth") + 1] : "quick";
const jsonOutput = args.includes("--json");
const runtimeArg = args.includes("--runtime") ? args[args.indexOf("--runtime") + 1] : "api";

// ── Ground Truth ──

type Verdict = "malicious" | "vulnerable" | "safe";

interface TestCase {
  /** npm package specifier (name or name@version) */
  pkg: string;
  verdict: Verdict;
  /** Short description of why this is in the ground truth set */
  reason: string;
}

const TEST_CASES: TestCase[] = [
  // ── Known malicious (should be flagged) ──
  // Original 10 (do not remove — preserve baseline comparability)
  { pkg: "event-stream",   verdict: "malicious", reason: "supply-chain attack — flatmap-stream dependency" },
  { pkg: "ua-parser-js",   verdict: "malicious", reason: "compromised version shipped crypto-miner" },
  { pkg: "colors",         verdict: "malicious", reason: "maintainer sabotaged with infinite loop (v1.4.1+)" },
  { pkg: "faker",          verdict: "malicious", reason: "maintainer sabotaged, replaced with ENDGAME" },
  { pkg: "node-ipc",       verdict: "malicious", reason: "protestware / peacenotwar geo-targeted wiper" },
  { pkg: "coa",            verdict: "malicious", reason: "hijacked — malicious preinstall script" },
  { pkg: "rc",             verdict: "malicious", reason: "hijacked — malicious preinstall script" },
  { pkg: "eslint-scope",   verdict: "malicious", reason: "credential-theft via npm token exfiltration" },
  { pkg: "crossenv",       verdict: "malicious", reason: "typosquat of cross-env — data exfiltration" },
  { pkg: "loadsh",         verdict: "malicious", reason: "typosquat of lodash" },
  // Expansion (verified against npm advisories / GHSA / Socket / ReversingLabs / Phylum)
  { pkg: "flatmap-stream",        verdict: "malicious", reason: "the actual malicious payload behind event-stream (GHSA-mh6f-8j2x-4483)" },
  { pkg: "electron-native-notify",verdict: "malicious", reason: "Komodo wallet credential stealer (GHSA-mc3j-455x-fjhj)" },
  { pkg: "bb-builder",            verdict: "malicious", reason: "credential exfiltration typosquat (GHSA-7h2p-3mh4-fj7g)" },
  { pkg: "bigchaindb-driver",     verdict: "malicious", reason: "compromised release contained malicious post-install (Snyk SNYK-JS-BIGCHAINDB)" },
  { pkg: "fallguys",              verdict: "malicious", reason: "discord token + credit-card stealer (GHSA-mh3m-62v7-68xc)" },
  { pkg: "discord-selfbot-v14",   verdict: "malicious", reason: "discord token grabber, removed by npm (Socket.dev report)" },
  { pkg: "twilio-npm",            verdict: "malicious", reason: "typosquat of twilio with reverse shell (GHSA-c2gm-cwxv-q4wx)" },
  { pkg: "ffmepg",                verdict: "malicious", reason: "typosquat of ffmpeg, payload exfiltrates env vars (GHSA-rjmj-fvf6-q9xc)" },
  { pkg: "discord.dll",           verdict: "malicious", reason: "discord token + browser data stealer (GHSA-39q7-7r5w-3pmm)" },
  { pkg: "nodejs_net_server",     verdict: "malicious", reason: "stealer + remote shell, flagged by ReversingLabs 2023" },
  { pkg: "noblox.js-proxy",       verdict: "malicious", reason: "typosquat of noblox.js — data exfiltration (GHSA-7w4q-46j2-w278)" },
  { pkg: "okhsa",                 verdict: "malicious", reason: "executes calc.exe payload (GHSA-q9w9-6hcc-xqqw)" },
  { pkg: "node-fabric",           verdict: "malicious", reason: "Phylum-reported infostealer / typosquat of fabric" },
  { pkg: "ngfm",                  verdict: "malicious", reason: "preinstall data exfil, npm-flagged 2023" },
  { pkg: "circle.js",             verdict: "malicious", reason: "Socket.dev-reported infostealer 2024" },
  { pkg: "rocketrefer",           verdict: "malicious", reason: "Phylum-reported credential stealer 2024" },
  { pkg: "lodahs",                verdict: "malicious", reason: "typosquat of lodash, miner payload (GHSA-cph5-m8f7-6c5x)" },

  // ── Known CVE packages (should report vulnerabilities) ──
  // Original 10
  { pkg: "lodash@4.17.20",     verdict: "vulnerable", reason: "prototype pollution CVE-2021-23337" },
  { pkg: "minimist@1.2.5",     verdict: "vulnerable", reason: "prototype pollution CVE-2021-44906" },
  { pkg: "node-forge@0.9.0",   verdict: "vulnerable", reason: "multiple CVEs in older forge" },
  { pkg: "express@4.17.1",     verdict: "vulnerable", reason: "path traversal in serve-static dep" },
  { pkg: "axios@0.21.0",       verdict: "vulnerable", reason: "SSRF CVE-2021-3749" },
  { pkg: "tar@4.4.12",         verdict: "vulnerable", reason: "arbitrary file overwrite CVE-2021-32803" },
  { pkg: "glob-parent@5.1.0",  verdict: "vulnerable", reason: "ReDoS CVE-2021-35065" },
  { pkg: "json5@2.2.1",        verdict: "vulnerable", reason: "prototype pollution CVE-2022-46175" },
  { pkg: "qs@6.5.2",           verdict: "vulnerable", reason: "prototype pollution CVE-2022-24999" },
  { pkg: "semver@7.3.7",       verdict: "vulnerable", reason: "ReDoS CVE-2022-25883" },
  // Expansion (verified against NVD / GHSA)
  { pkg: "lodash@4.17.10",     verdict: "vulnerable", reason: "prototype pollution CVE-2019-10744" },
  { pkg: "lodash@4.17.4",      verdict: "vulnerable", reason: "prototype pollution CVE-2018-3721" },
  { pkg: "minimist@0.0.8",     verdict: "vulnerable", reason: "prototype pollution CVE-2020-7598" },
  { pkg: "node-fetch@2.6.6",   verdict: "vulnerable", reason: "exposure of sensitive info CVE-2022-0235" },
  { pkg: "axios@0.19.0",       verdict: "vulnerable", reason: "denial of service CVE-2020-28168 / regression CVE-2019-10742" },
  { pkg: "tar@6.1.8",          verdict: "vulnerable", reason: "arbitrary file creation/overwrite CVE-2021-37701" },
  { pkg: "glob-parent@5.1.1",  verdict: "vulnerable", reason: "ReDoS CVE-2020-28469" },
  { pkg: "nth-check@1.0.2",    verdict: "vulnerable", reason: "ReDoS CVE-2021-3803" },
  { pkg: "json5@1.0.1",        verdict: "vulnerable", reason: "prototype pollution CVE-2022-46175" },
  { pkg: "ansi-regex@3.0.0",   verdict: "vulnerable", reason: "ReDoS CVE-2021-3807" },
  { pkg: "shell-quote@1.7.2",  verdict: "vulnerable", reason: "command injection CVE-2021-42740" },
  { pkg: "y18n@4.0.0",         verdict: "vulnerable", reason: "prototype pollution CVE-2020-7774" },
  { pkg: "ws@7.4.5",           verdict: "vulnerable", reason: "ReDoS CVE-2021-32640" },
  { pkg: "marked@2.0.0",       verdict: "vulnerable", reason: "ReDoS CVE-2022-21680 / CVE-2022-21681" },
  { pkg: "follow-redirects@1.14.7", verdict: "vulnerable", reason: "exposure of sensitive info CVE-2022-0155" },
  { pkg: "http-cache-semantics@4.1.0", verdict: "vulnerable", reason: "ReDoS CVE-2022-25881" },
  { pkg: "decode-uri-component@0.2.0", verdict: "vulnerable", reason: "DoS CVE-2022-38900" },

  // ── Safe packages (should produce 0 findings) ──
  // Original 10
  { pkg: "express@latest",     verdict: "safe", reason: "widely-used, patched" },
  { pkg: "react@latest",       verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "typescript@latest",  verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "zod@latest",         verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "drizzle-orm@latest", verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "vitest@latest",      verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "esbuild@latest",     verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "chalk@latest",       verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "commander@latest",   verdict: "safe", reason: "well-maintained, no known issues" },
  { pkg: "dotenv@latest",      verdict: "safe", reason: "well-maintained, no known issues" },
  // Expansion — top-50 npm packages by downloads, current versions
  { pkg: "react-dom@latest",   verdict: "safe", reason: "top-10 npm download, well-maintained" },
  { pkg: "vue@latest",         verdict: "safe", reason: "top framework, well-maintained" },
  { pkg: "next@latest",        verdict: "safe", reason: "top framework, well-maintained" },
  { pkg: "vite@latest",        verdict: "safe", reason: "top dev tool, well-maintained" },
  { pkg: "webpack@latest",     verdict: "safe", reason: "top bundler, well-maintained" },
  { pkg: "eslint@latest",      verdict: "safe", reason: "top linter, well-maintained" },
  { pkg: "prettier@latest",    verdict: "safe", reason: "top formatter, well-maintained" },
  { pkg: "tslib@latest",       verdict: "safe", reason: "TypeScript runtime helpers, top-10 dl" },
  { pkg: "@types/node@latest", verdict: "safe", reason: "TypeScript type definitions, top dl" },
  { pkg: "rollup@latest",      verdict: "safe", reason: "top bundler, well-maintained" },
  { pkg: "rxjs@latest",        verdict: "safe", reason: "top reactive lib, well-maintained" },
  { pkg: "fastify@latest",     verdict: "safe", reason: "top server framework, well-maintained" },
  { pkg: "pino@latest",        verdict: "safe", reason: "top logger, well-maintained" },
  { pkg: "uuid@latest",        verdict: "safe", reason: "top utility, well-maintained" },
  { pkg: "cross-env@latest",   verdict: "safe", reason: "top utility, well-maintained" },
  { pkg: "rimraf@latest",      verdict: "safe", reason: "top utility, well-maintained" },
  { pkg: "globby@latest",      verdict: "safe", reason: "top utility, well-maintained" },
];

// ── Types ──

interface CaseResult {
  pkg: string;
  verdict: Verdict;
  reason: string;
  findingsCount: number;
  hasFindings: boolean;
  correct: boolean;
  durationMs: number;
  error?: string;
  infrastructureError: boolean;
}

interface NpmBenchReport {
  timestamp: string;
  depth: string;
  runtime: string;
  totalCases: number;
  scoredCases: number;
  infrastructureFailures: number;
  validScore: boolean;
  /** True positive + true negative rate */
  accuracy: number | null;
  /** TP / (TP + FN) — how many bad packages we caught */
  detectionRate: number | null;
  /** FP / (FP + TN) — how often we cry wolf on safe packages */
  falsePositiveRate: number | null;
  /** Harmonic mean of precision and recall */
  f1: number | null;
  totalDurationMs: number;
  results: CaseResult[];
  verdictBreakdown: Record<Verdict, { total: number; correct: number; rate: number }>;
  note?: string;
}

// ── Runner ──

async function auditPackage(pkg: string): Promise<{ findings: any[]; raw: string }> {
  // Parse package specifier into name and optional version
  let packageName: string;
  let version: string | undefined;

  if (pkg.startsWith("@")) {
    // Scoped package: @scope/name or @scope/name@version
    const idx = pkg.indexOf("@", 1);
    if (idx !== -1) {
      packageName = pkg.slice(0, idx);
      version = pkg.slice(idx + 1);
    } else {
      packageName = pkg;
    }
  } else {
    const idx = pkg.indexOf("@");
    if (idx !== -1) {
      packageName = pkg.slice(0, idx);
      version = pkg.slice(idx + 1);
    } else {
      packageName = pkg;
    }
  }

  const report = await packageAudit({
    config: {
      package: packageName,
      version,
      depth: depth as ScanDepth,
      format: "json",
      runtime: runtimeArg as RuntimeMode,
    },
  });

  return { findings: report.findings ?? [], raw: JSON.stringify(report) };
}

function shouldHaveFindings(verdict: Verdict): boolean {
  return verdict === "malicious" || verdict === "vulnerable";
}

function isInfrastructureError(error: string | undefined): boolean {
  if (!error) return false;
  const lower = error.toLowerCase();
  return [
    "enoent",
    "spawn ",
    "eacces",
    "timed out",
    "timeout",
    "rate limit",
    "api key",
    "authentication",
    "unauthorized",
    "forbidden",
    "deployment unavailable",
    "model may be rate-limited",
    "failed to install",
  ].some((token) => lower.includes(token));
}

async function runNpmBench(): Promise<NpmBenchReport> {
  const results: CaseResult[] = [];
  const start = Date.now();

  for (const tc of TEST_CASES) {
    const caseStart = Date.now();
    try {
      const { findings } = await auditPackage(tc.pkg);
      const hasFindings = findings.length > 0;
      const expectFindings = shouldHaveFindings(tc.verdict);
      const correct = hasFindings === expectFindings;

      results.push({
        pkg: tc.pkg,
        verdict: tc.verdict,
        reason: tc.reason,
        findingsCount: findings.length,
        hasFindings,
        correct,
        durationMs: Date.now() - caseStart,
        infrastructureError: false,
      });
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      results.push({
        pkg: tc.pkg,
        verdict: tc.verdict,
        reason: tc.reason,
        findingsCount: 0,
        hasFindings: false,
        correct: false,
        durationMs: Date.now() - caseStart,
        error,
        infrastructureError: isInfrastructureError(error),
      });
    }

    // Terminal progress
    const last = results[results.length - 1];
    const icon = last.error
      ? "\x1b[33m?\x1b[0m"
      : last.correct
        ? "\x1b[32m✓\x1b[0m"
        : "\x1b[31m✗\x1b[0m";

    if (!jsonOutput) {
      console.log(
        `  ${icon} [${last.verdict.padEnd(10)}] ${last.pkg.padEnd(30)} ${last.findingsCount} findings  ${last.durationMs}ms${last.error ? "  ERR" : ""}`,
      );
    }
  }

  const infrastructureFailures = results.filter((r) => r.infrastructureError).length;
  const scoredCases = results.length - infrastructureFailures;
  const validScore = infrastructureFailures === 0;

  // ── Metrics ──

  // Confusion matrix (positive = "should have findings")
  let tp = 0; // bad pkg flagged
  let fn = 0; // bad pkg missed
  let fp = 0; // safe pkg wrongly flagged
  let tn = 0; // safe pkg correctly clean

  for (const r of results) {
    const expectPositive = shouldHaveFindings(r.verdict);
    if (expectPositive && r.hasFindings) tp++;
    else if (expectPositive && !r.hasFindings) fn++;
    else if (!expectPositive && r.hasFindings) fp++;
    else tn++;
  }

  const accuracy = validScore ? (tp + tn) / results.length : null;
  const detectionRate = validScore ? (tp + fn > 0 ? tp / (tp + fn) : 0) : null;
  const falsePositiveRate = validScore ? (fp + tn > 0 ? fp / (fp + tn) : 0) : null;
  const precision = validScore ? (tp + fp > 0 ? tp / (tp + fp) : 0) : 0;
  const recall = detectionRate;
  const f1 = validScore && recall !== null && precision + recall > 0
    ? (2 * precision * recall) / (precision + recall)
    : validScore
      ? 0
      : null;

  // Per-verdict breakdown
  const verdictBreakdown = {} as Record<Verdict, { total: number; correct: number; rate: number }>;
  for (const v of ["malicious", "vulnerable", "safe"] as Verdict[]) {
    const subset = results.filter((r) => r.verdict === v);
    const correct = subset.filter((r) => r.correct).length;
    verdictBreakdown[v] = {
      total: subset.length,
      correct,
      rate: subset.length > 0 ? correct / subset.length : 0,
    };
  }

  return {
    timestamp: new Date().toISOString(),
    depth,
    runtime: runtimeArg,
    totalCases: results.length,
    scoredCases,
    infrastructureFailures,
    validScore,
    accuracy,
    detectionRate,
    falsePositiveRate,
    f1,
    totalDurationMs: Date.now() - start,
    results,
    verdictBreakdown,
    note: validScore
      ? undefined
      : `Infrastructure failures affected ${infrastructureFailures}/${results.length} cases. Metrics are invalid; inspect case-level errors instead of using this run as a score.`,
  };
}

// ── Main ──

async function main() {
  if (!jsonOutput) {
    console.log("\n\x1b[31m\x1b[1m  pwnkit npm audit benchmark\x1b[0m");
    console.log(`  depth: ${depth}  cases: ${TEST_CASES.length}\n`);
  }

  const report = await runNpmBench();

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("\n  ──────────────────────────────────────");
    console.log(`  Runtime:           \x1b[1m${report.runtime}\x1b[0m`);
    console.log(`  Infrastructure:    \x1b[1m${report.infrastructureFailures}/${report.totalCases}\x1b[0m errored cases`);
    if (report.validScore && report.accuracy !== null && report.detectionRate !== null && report.falsePositiveRate !== null && report.f1 !== null) {
      console.log(`  Accuracy:          \x1b[1m${(report.accuracy * 100).toFixed(1)}%\x1b[0m  (${Math.round(report.accuracy * report.totalCases)}/${report.totalCases})`);
      console.log(`  Detection rate:    \x1b[1m${(report.detectionRate * 100).toFixed(1)}%\x1b[0m  (recall)`);
      console.log(`  False positive:    \x1b[1m${(report.falsePositiveRate * 100).toFixed(1)}%\x1b[0m`);
      console.log(`  F1 score:          \x1b[1m${report.f1.toFixed(3)}\x1b[0m`);
    } else {
      console.log("  Score:             \x1b[33mINVALID\x1b[0m  infrastructure errors make this run unusable for comparison");
      if (report.note) {
        console.log(`  Note:              ${report.note}`);
      }
    }
    console.log(`  Total time:        ${(report.totalDurationMs / 1000).toFixed(1)}s`);

    console.log("\n  By verdict:");
    for (const [verdict, data] of Object.entries(report.verdictBreakdown)) {
      const bar =
        "\x1b[32m" +
        "█".repeat(Math.round(data.rate * 10)) +
        "\x1b[0m" +
        "░".repeat(10 - Math.round(data.rate * 10));
      console.log(`    ${verdict.padEnd(14)} ${bar} ${data.correct}/${data.total}`);
    }
    console.log("");
  }

  // Save results
  const resultsDir = join(__dirname, "..", "results");
  mkdirSync(resultsDir, { recursive: true });
  writeFileSync(
    join(resultsDir, "npm-bench-latest.json"),
    JSON.stringify(report, null, 2),
  );

  if (!jsonOutput) {
    console.log(`  Results saved to results/npm-bench-latest.json\n`);
  }

  if (!report.validScore) {
    process.exitCode = 2;
  }
}

main().catch((err) => {
  console.error("npm-bench failed:", err);
  process.exit(1);
});
