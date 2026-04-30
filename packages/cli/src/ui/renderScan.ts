import React, { useState, useEffect } from "react";
import { render, useInput } from "ink";
import {
  appendStageAction,
  eventBus,
  normalizeStageAction,
  normalizeStageEndDetail,
  reduceLiveAgentState,
} from "@pwnkit/core";
import type { LiveAgentState } from "@pwnkit/core";
import { printBanner } from "./banner.js";
import { ScanUI } from "./ScanUI.js";
import { buildShareUrl } from "../utils.js";
import type { ScanEvent, ScanSummary, StageState, StageStatusKind } from "./ScanUI.js";

export type { ScanEvent, ScanSummary };
export type CommandMode = "audit" | "review" | "scan";

interface RenderScanOptions {
  version: string;
  target: string;
  depth: string;
  mode: CommandMode;
}

interface RenderScanResult {
  onEvent: (event: { type: string; stage?: string; message: string; data?: unknown }) => void;
  waitForExit: () => Promise<void>;
  setReport: (report: Record<string, unknown>) => void;
}

// 4 stages — clean pipeline view for the user
function getStages(): StageState[] {
  return [
    { id: "discover", label: "Discover",  status: "pending", actions: [], findings: [] },
    { id: "attack",   label: "Attack",    status: "pending", actions: [], findings: [] },
    { id: "verify",   label: "Verify",    status: "pending", actions: [], findings: [] },
    { id: "report",   label: "Report",    status: "pending", actions: [], findings: [] },
  ];
}

export function renderScanUI(opts: RenderScanOptions): RenderScanResult {
  let stages = getStages();
  let summary: ScanSummary | null = null;
  let thinking: string | null = null;
  let verbose = false;
  let rerender: (() => void) | null = null;
  let resolveExit: (() => void) | null = null;
  /**
   * Live snapshot of the agent's most-recent activity, fed by the
   * eventBus subscriber below. Replaces in place — no scrollback —
   * so the panel stays terminal-friendly even on long scans where
   * the eventBus fires hundreds of times.
   */
  let liveAgent: LiveAgentState = {};


  // Static banner — printed once before Ink takes over
  const modeLabel = opts.mode === "audit" ? `auditing npm package \x1b[1m${opts.target}\x1b[0m`
    : opts.mode === "review" ? `reviewing source code \x1b[1m${opts.target}\x1b[0m`
    : `scanning target \x1b[1m${opts.target}\x1b[0m`;
  printBanner(modeLabel);

  function App() {
    const [tick, setTick] = useState(0);
    useEffect(() => {
      rerender = () => setTick((t) => t + 1);
      return () => { rerender = null; };
    }, []);
    useInput((input, key) => {
      // Verbose toggle is live at any point during the scan (not just after
      // summary). Both `v` and Ctrl+O (muscle memory from codex / claude CLI)
      // flip the detail level. The stored event log stays uncapped, so the
      // toggle can reveal history the compact view had been hiding.
      if ((key.ctrl && input === "o") || input === "v" || input === "V") {
        verbose = !verbose;
        rerender?.();
        return;
      }
      if (!summary) return;
      if (key.return || key.escape || input.toLowerCase() === "q") {
        resolveExit?.();
      }
    });
    return React.createElement(ScanUI, {
      stages,
      summary,
      thinking,
      target: opts.target,
      depth: opts.depth,
      mode: opts.mode,
      verbose,
      liveAgent,
      exitHint: summary ? "Press Enter, Esc, or q to close." : null,
    });
  }

  const instance = render(React.createElement(App));

  // Subscribe to the agent's eventBus so the live panel can render
  // turn / tool / reasoning / cost in real time. The pure reducer
  // lives in @pwnkit/core (`reduceLiveAgentState`) so the
  // replace-in-place invariants are unit-tested without booting the
  // TUI. Unsubscribed in `waitForExit` so embedded SDK consumers
  // don't leak listeners.
  const unsubscribeLiveAgent = eventBus.subscribe({
    emit(type, payload) {
      const next = reduceLiveAgentState(liveAgent, type, payload);
      if (next !== liveAgent) {
        liveAgent = next;
        rerender?.();
      }
    },
  });

  function updateStage(id: string, updater: (s: StageState) => StageState) {
    stages = stages.map((s) => (s.id === id ? updater(s) : s));
    rerender?.();
  }

  // Map core scanner stage names to TUI stage IDs
  function mapStageId(coreStage: string | undefined): string | undefined {
    switch (coreStage) {
      case "discovery":
      case "discover":
      case "source-analysis":
      case "prepare":
      case "analyze":
        return "discover";
      case "attack":
      case "research":
      case "agent":
        return "attack";
      case "verify":
        return "verify";
      case "report":
        return "report";
      default:
        return undefined;
    }
  }

  function onEvent(event: { type: string; stage?: string; message: string; data?: unknown }): void {
    const msg = event.message ?? "";
    const stageId = mapStageId(event.stage);

    if (event.type === "stage:start") {
      if (!stageId) return;
      const current = stages.find((s) => s.id === stageId);

      if (current?.status === "running") {
        // Already running — this is a sub-action (tool call, turn update).
        // The reducer in @pwnkit/core handles prefix normalization and the
        // history cap so compact/verbose display logic in ScanUI.tsx has a
        // clean source of truth to slice from.
        const action = normalizeStageAction(msg);
        if (!action) return;
        updateStage(stageId, (s) => ({
          ...s,
          actions: appendStageAction(s.actions, action),
        }));
      } else {
        // New stage start — show a clean label
        let detail = msg;
        const lower = msg.toLowerCase();
        if (lower.includes("claude")) detail = "using Claude";
        else if (lower.includes("codex")) detail = "using Codex";
        else if (lower.includes("gemini")) detail = "using Gemini";
        else if (lower.includes("api") || lower.includes("agentic")) detail = "using API";
        else if (detail.length > 50) detail = detail.slice(0, 50) + "...";
        updateStage(stageId, (s) => ({ ...s, status: "running", detail }));
      }
      return;
    }

    if (event.type === "stage:end") {
      if (!stageId) return;
      // Store the FULL cleaned detail; ScanUI clips at render time based on
      // the verbose toggle. Previously this site clipped to 55 chars at store
      // time, which meant the verbose toggle could reveal every per-turn
      // sub-action but never the final "First attempt (10 turns): no findings.
      // Retry (10 turns): ..." terminal summary — the piece of text the user
      // most wants to read when a scan completes with 0 findings.
      const detail = normalizeStageEndDetail(msg) || "done";
      updateStage(stageId, (s) => ({
        ...s,
        status: "done",
        detail,
        duration: (event.data as any)?.durationMs ?? s.duration,
      }));
      return;
    }

    if (event.type === "finding") {
      const running = stages.find((s) => s.status === "running") ?? stages.find((s) => s.id === "attack");
      if (running) {
        const severity = (event.data as any)?.severity ?? "info";
        // Clean up title — remove [severity] prefix if present, truncate
        let title = msg.replace(/^\[[\w]+\]\s*/g, "").trim();
        if (title.length > 60) title = title.slice(0, 60) + "...";
        if (!title || title === "Untitled finding") title = "Finding from AI analysis";
        updateStage(running.id, (s) => ({
          ...s,
          findings: [...s.findings, { severity, title }],
        }));
      }
      return;
    }

    if (event.type === "verify:result") {
      const data = event.data as any;
      const confirmed = data?.confirmed;
      const title = data?.title ?? event.message;
      const reason = data?.reason;
      const label = confirmed ? `\u2713 ${title}` : `\u2717 ${title}${reason ? ` \u2014 ${reason}` : ""}`;
      updateStage("verify", (s) => ({
        ...s,
        actions: [...s.actions, label],
      }));
      return;
    }

    if (event.type === "error") {
      const running = stages.find((s) => s.status === "running");
      if (running) {
        updateStage(running.id, (s) => ({ ...s, status: "error", error: msg }));
      }
      return;
    }

    // Thinking tokens
    if ((event.type as string) === "thinking") {
      thinking = msg;
      rerender?.();
    }
  }

  function setReport(report: Record<string, unknown>): void {
    stages = stages.map((s) =>
      s.status === "pending" ? { ...s, status: "done" as StageStatusKind, detail: "—" } :
      s.status === "running" ? { ...s, status: "done" as StageStatusKind } : s
    );

    const rep = report as any;
    summary = {
      critical: rep.summary?.critical ?? 0,
      high: rep.summary?.high ?? 0,
      medium: rep.summary?.medium ?? 0,
      low: rep.summary?.low ?? 0,
      info: rep.summary?.info ?? 0,
      duration: rep.durationMs,
      shareUrl: buildShareUrl(rep),
    };
    rerender?.();
  }

  async function waitForExit(): Promise<void> {
    await new Promise<void>((resolve) => {
      resolveExit = () => {
        resolveExit = null;
        unsubscribeLiveAgent();
        instance.unmount();
        resolve();
      };

      if (!process.stdin.isTTY) {
        setTimeout(() => resolveExit?.(), 1500);
      }
    });
    await instance.waitUntilExit();
  }

  return { onEvent, waitForExit, setReport };
}
