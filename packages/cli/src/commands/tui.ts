import type { Command } from "commander";

type TuiOptions = {
  dbPath?: string;
  refreshMs?: string;
};

export function registerTuiCommand(program: Command): void {
  program
    .command("tui")
    .alias("watch")
    .description("Open a local terminal operator UI for runs, findings, queue state, workers, and evidence")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--refresh-ms <n>", "Refresh interval in milliseconds", "4000")
    .action(async (opts: TuiOptions) => {
      const refreshMs = Number.parseInt(opts.refreshMs ?? "4000", 10);
      const { isBunRuntime } = await import("../tui/runtime.js");
      if (isBunRuntime()) {
        const { showOpenTuiOps } = await import("../tui/run.js");
        await showOpenTuiOps({ dbPath: opts.dbPath, refreshMs });
        return;
      }

      const { showOperatorTui } = await import("../ui/Tui.js");
      await showOperatorTui({ dbPath: opts.dbPath, refreshMs });
    });
}
