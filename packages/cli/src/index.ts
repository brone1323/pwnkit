#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import { VERSION } from "@pwnkit/shared";
import type { HomeSelection } from "./tui/run.js";
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

// ── Interactive menu (Ink) ──
async function showInteractiveMenu(): Promise<void> {
  const { isBunRuntime, showOpenTuiHome } = await import("./tui/run.js");
  if (isBunRuntime()) {
    await showOpenTuiHome();
    return;
  }

  const selection = await (await import("./ui/Menu.js")).showInkMenu() as HomeSelection | null;
  if (!selection) return;
  const { action, target } = selection;

  if (action === "history") {
    process.argv = [process.argv[0], process.argv[1], "history"];
    await program.parseAsync();
    return;
  }

  if (action === "findings") {
    process.argv = [process.argv[0], process.argv[1], "findings"];
    await program.parseAsync();
    return;
  }

  if (action === "doctor") {
    process.argv = [process.argv[0], process.argv[1], "doctor"];
    await program.parseAsync();
    return;
  }

  if (action === "replay") {
    process.argv = [process.argv[0], process.argv[1], "replay"];
    await program.parseAsync();
    return;
  }

  if (action === "tui") {
    process.argv = [process.argv[0], process.argv[1], "tui"];
    await program.parseAsync();
    return;
  }

  if (!target) return;

  if (action === "scan") {
    process.argv = [
      process.argv[0],
      process.argv[1],
      "scan",
      "--target",
      target,
      "--depth",
      selection.depth ?? "default",
      "--runtime",
      selection.runtime ?? "auto",
    ];
    if (selection.mode && selection.mode !== "auto") {
      process.argv.push("--mode", selection.mode);
    }
  } else if (action === "audit") {
    process.argv = [
      process.argv[0],
      process.argv[1],
      "audit",
      target,
      "--depth",
      selection.depth ?? "default",
      "--runtime",
      selection.runtime ?? "auto",
      "--ecosystem",
      selection.ecosystem ?? "npm",
    ];
  } else if (action === "review") {
    process.argv = [
      process.argv[0],
      process.argv[1],
      "review",
      target,
      "--depth",
      selection.depth ?? "default",
      "--runtime",
      selection.runtime ?? "auto",
    ];
  }

  await program.parseAsync();
}

// ── Entry point ──
const userArgs = process.argv.slice(2);
const knownCommands = ["scan", "resume", "replay", "history", "findings", "review", "audit", "doctor", "dashboard", "tui", "watch", "orchestrate", "db", "mcp-server", "eval", "ingest", "help"];

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
