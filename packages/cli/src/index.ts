#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import { VERSION } from "@pwnkit/shared";
import { maybeSubscribeCloudEventSink } from "@pwnkit/core";

// Subscribe the cloud-event sink before any subcommand runs. Idempotent
// + env-gated (PWNKIT_CLOUD_EVENTS=1): the sink writes one
// `PWNKIT_EVENT_<TYPE>` line per emitted event to stdout, which the
// pwnkit-cloud worker-controller's stdout streamer parses and POSTs to
// the orchestrator's /scans/:id/events endpoint. Without this call,
// the sink module is dead code and the cloud's live-trace UI stays
// dark for every scan.
maybeSubscribeCloudEventSink();
import {
  registerScanCommand,
  registerResumeCommand,
  registerReplayCommand,
  registerHistoryCommand,
  registerFindingsCommand,
  registerReviewCommand,
  registerAuditCommand,
  registerDoctorCommand,
  registerDashboardCommand,
  registerTuiCommand,
  registerOrchestrateCommand,
  registerDbCommand,
  registerMcpServerCommand,
  registerTriageCommand,
  registerEvalCommand,
  registerIngestCommand,
  registerDiscloseCommand,
  registerVerifyCommand,
} from "./commands/index.js";
import { detectAndRoute } from "./routing.js";
import { preloadBanner } from "./ui/banner.js";

// Start loading cfonts in the background so it's ready when the banner prints
void preloadBanner();

const program = new Command();

program
  .name("pwnkit-cli")
  .description("Fully autonomous agentic pentesting framework")
  .version(VERSION);

registerScanCommand(program);
registerResumeCommand(program);
registerReplayCommand(program);
registerHistoryCommand(program);
registerFindingsCommand(program);
registerReviewCommand(program);
registerAuditCommand(program);
registerDoctorCommand(program);
registerDashboardCommand(program);
registerTuiCommand(program);
registerOrchestrateCommand(program);
registerDbCommand(program);
registerMcpServerCommand(program);
registerTriageCommand(program);
registerEvalCommand(program);
registerIngestCommand(program);
registerDiscloseCommand(program);
registerVerifyCommand(program);

// ── Interactive menu ──
//
// Under Bun, launches the OpenTUI home (`@opentui/react`-based mission
// control). Under Node, the interactive menu was Ink-based and was
// removed in v0.9.0 — print install instructions for the standalone
// binary and exit so the user gets the full TUI experience.
async function showInteractiveMenu(): Promise<void> {
  const { isBunRuntime } = await import("./tui/runtime.js");
  if (isBunRuntime()) {
    const { showOpenTuiHome } = await import("./tui/run.js");
    await showOpenTuiHome();
    return;
  }

  console.log("");
  console.log(`  ${chalk.bold("pwnkit")} ${chalk.dim(`v${VERSION}`)}`);
  console.log("");
  console.log(`  ${chalk.dim("From v0.9.0 onwards, pwnkit ships as a self-contained binary.")}`);
  console.log(`  ${chalk.dim("The full TUI (mission control + live scan view) needs Bun's runtime.")}`);
  console.log("");
  console.log(`  ${chalk.bold("Install")} (single curl, no Node / Bun required):`);
  console.log(`    curl -fsSL https://raw.githubusercontent.com/PwnKit-Labs/pwnkit/main/install.sh | bash`);
  console.log("");
  console.log(`  ${chalk.dim("Or via Bun:")}`);
  console.log(`    bun add -g pwnkit-cli`);
  console.log("");
  console.log(`  ${chalk.dim("Subcommands still work under Node — try:")}`);
  console.log(`    npx pwnkit-cli scan --target https://example.com`);
  console.log(`    npx pwnkit-cli --help`);
  console.log("");
}

// ── Entry point ──
const userArgs = process.argv.slice(2);
const knownCommands = ["scan", "resume", "replay", "history", "findings", "review", "audit", "doctor", "dashboard", "tui", "watch", "orchestrate", "db", "mcp-server", "eval", "ingest", "disclose", "verify", "help"];

if (userArgs.length === 0) {
  showInteractiveMenu().catch((err) => {
    console.error(chalk.red(err instanceof Error ? err.message : String(err)));
    process.exit(2);
  });
} else if (userArgs.length >= 1 && !knownCommands.includes(userArgs[0]) && !userArgs[0].startsWith("-")) {
  const route = detectAndRoute(userArgs[0]);
  if (route) {
    const extraArgs = userArgs.slice(1);
    process.argv = [process.argv[0], process.argv[1], ...route, ...extraArgs];
    program.parse();
  } else {
    program.parse();
  }
} else {
  program.parse();
}
