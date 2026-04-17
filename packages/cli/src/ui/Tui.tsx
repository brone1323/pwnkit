import React, { useEffect, useMemo, useState } from "react";
import { Box, Text, useApp, useInput, render, type Key } from "ink";
import type { FindingTriageStatus } from "@pwnkit/shared";
import { printBanner } from "./banner.js";
import {
  BORDER,
  ERROR,
  INFO,
  MUTED,
  PRIMARY,
  RAIL,
  SECONDARY,
  SUCCESS,
  TEXT,
  WARNING,
  severityTone,
} from "./theme.js";

type TuiOptions = {
  dbPath?: string;
  refreshMs?: number;
};

type ScanRow = {
  id: string;
  target: string;
  depth: string;
  runtime: string;
  mode: string;
  status: string;
  startedAt: string;
  completedAt?: string | null;
  durationMs?: number | null;
  summary?: string | null;
};

type FindingRow = {
  id: string;
  scanId: string;
  templateId: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  status: string;
  fingerprint?: string | null;
  triageStatus?: string | null;
  triageNote?: string | null;
  timestamp: number;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
};

type EventRow = {
  id: string;
  scanId: string;
  scanTarget?: string;
  stage: string;
  eventType: string;
  findingId?: string | null;
  agentRole?: string | null;
  payload: string;
  timestamp: number;
};

type WorkerRow = {
  id: string;
  status: string;
  label: string;
  currentCaseId?: string | null;
  currentWorkItemId?: string | null;
  currentScanId?: string | null;
  pid?: number | null;
  host?: string | null;
  lastError?: string | null;
  heartbeatAt: string;
  startedAt: string;
  updatedAt: string;
};

type WorkItemRow = {
  id: string;
  caseId: string;
  kind: string;
  title: string;
  status: string;
  dependsOn?: string | null;
  summary?: string | null;
  findingFingerprint?: string | null;
};

type QueueSummary = {
  runnable: number;
  active: number;
  blockedByDependency: number;
  manualReview: number;
  staleWorkers: number;
  recoveredClaims: number;
};

type ActiveWorkerSummary = {
  id: string;
  label: string;
  status: string;
  currentTitle: string;
  heartbeatLabel: string;
  lastError?: string | null;
};

type IncidentSummary = {
  scanId: string;
  scanTarget: string;
  stage: string;
  actor?: string | null;
  headline: string;
  timestamp: number;
};

type Pane = "scans" | "findings" | "details";
type InputMode = "normal" | "filter" | "note";
type PendingTriageAction = "accepted" | "suppressed" | null;

function parseSummary(summary?: string | null): Record<string, number> {
  if (!summary) return {};
  try {
    return JSON.parse(summary) as Record<string, number>;
  } catch {
    return {};
  }
}

function formatDuration(ms?: number | null): string {
  if (!ms || ms <= 0) return "-";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatStarted(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  })}`;
}

function severityColor(severity: string): string {
  return severityTone(severity);
}

function statusColor(status: string): string {
  if (status === "completed" || status === "reported") return SUCCESS;
  if (status === "failed" || status === "false-positive") return ERROR;
  if (status === "running" || status === "verified") return WARNING;
  return MUTED;
}

function triageColor(status?: string | null): string {
  switch ((status ?? "new") as FindingTriageStatus | "new") {
    case "accepted":
      return SUCCESS;
    case "suppressed":
      return MUTED;
    default:
      return INFO;
  }
}

function truncate(value: string | undefined | null, max = 120): string {
  if (!value) return "";
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= max) return compact;
  return `${compact.slice(0, max - 1)}…`;
}

function parsePayload(raw: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

function formatHeartbeatAge(iso: string): string {
  const at = Date.parse(iso);
  if (!Number.isFinite(at)) return iso;
  const elapsedMs = Math.max(0, Date.now() - at);
  if (elapsedMs < 60_000) return `${Math.round(elapsedMs / 1000)}s ago`;
  if (elapsedMs < 3_600_000) return `${Math.round(elapsedMs / 60_000)}m ago`;
  return `${Math.round(elapsedMs / 3_600_000)}h ago`;
}

function isFreshWorker(worker: WorkerRow): boolean {
  return Date.now() - Date.parse(worker.heartbeatAt) < 20_000;
}

function summarizeQueue(workItems: WorkItemRow[], workers: WorkerRow[]): QueueSummary {
  const executableKinds = new Set(["surface_map", "hypothesis", "poc_build", "blind_verify", "consensus"]);
  const executableScope = workItems.filter((item) => Boolean(item.findingFingerprint));
  const workItemsById = new Map(executableScope.map((item) => [item.id, item] as const));
  const workItemsByCaseId = new Map<string, WorkItemRow[]>();

  for (const item of executableScope) {
    const list = workItemsByCaseId.get(item.caseId) ?? [];
    list.push(item);
    workItemsByCaseId.set(item.caseId, list);
  }

  let runnable = 0;
  let active = 0;
  let blockedByDependency = 0;
  let manualReview = 0;
  let recoveredClaims = 0;

  for (const item of executableScope) {
    if (item.status === "in_progress") active += 1;
    if (item.kind === "human_review" && item.status === "todo") manualReview += 1;
    if ((item.summary ?? "").includes("Recovered after stale worker")) recoveredClaims += 1;

    if (!executableKinds.has(item.kind)) continue;
    const dependency = item.dependsOn ? workItemsById.get(item.dependsOn) : null;
    const siblings = workItemsByCaseId.get(item.caseId) ?? [];
    const hasActiveSibling = siblings.some((candidate) => candidate.id !== item.id && candidate.status === "in_progress");
    const dependencyDone = !item.dependsOn || dependency?.status === "done";

    if (item.status === "todo" && dependencyDone && !hasActiveSibling) {
      runnable += 1;
    } else if ((item.status === "todo" || item.status === "backlog") && !dependencyDone) {
      blockedByDependency += 1;
    }
  }

  const staleWorkers = workers.filter(
    (worker) => worker.status === "error" && typeof worker.lastError === "string" && worker.lastError.includes("Heartbeat expired"),
  ).length;

  return {
    runnable,
    active,
    blockedByDependency,
    manualReview,
    staleWorkers,
    recoveredClaims,
  };
}

function summarizeActiveWorkers(workers: WorkerRow[], workItems: WorkItemRow[]): ActiveWorkerSummary[] {
  const workItemsById = new Map(workItems.map((item) => [item.id, item] as const));
  return workers
    .filter((worker) => isFreshWorker(worker) && worker.status !== "stopped")
    .map((worker) => {
      const currentWorkItem = worker.currentWorkItemId ? workItemsById.get(worker.currentWorkItemId) : null;
      return {
        id: worker.id,
        label: worker.label,
        status: worker.status,
        currentTitle: currentWorkItem?.title ?? worker.currentWorkItemId ?? "Idle",
        heartbeatLabel: formatHeartbeatAge(worker.heartbeatAt),
        lastError: worker.lastError ?? null,
      };
    });
}

function summarizeIncidents(events: EventRow[]): IncidentSummary[] {
  const byScan = new Map<string, IncidentSummary>();
  for (const event of events) {
    const payload = parsePayload(event.payload);
    const summaryText =
      typeof payload.summary === "string" && payload.summary.trim()
        ? payload.summary.trim()
        : event.payload;
    const isExecutionStall =
      ["stage_complete", "agent_complete", "runtime_incompatible"].includes(event.eventType)
      && /max turns|did not emit required tool_call/i.test(summaryText);
    if (!["agent_error", "scan_error", "worker_failed"].includes(event.eventType) && !isExecutionStall) continue;
    if (byScan.has(event.scanId)) continue;

    const headline =
      typeof payload.error === "string" && payload.error.trim()
        ? payload.error.trim()
        : typeof payload.summary === "string" && payload.summary.trim()
          ? payload.summary.trim()
          : truncate(event.payload, 120);

    byScan.set(event.scanId, {
      scanId: event.scanId,
      scanTarget: event.scanTarget ?? event.scanId,
      stage: event.stage,
      actor: event.agentRole ?? null,
      headline,
      timestamp: event.timestamp,
    });
  }

  return [...byScan.values()].slice(0, 4);
}

function originTags(finding: FindingRow): string[] {
  const tags: string[] = [];
  const templateId = finding.templateId ?? "";
  const triageNote = (finding.triageNote ?? "").toLowerCase();

  if (templateId === "known-package-advisories") {
    tags.push("deterministic advisory");
  } else if (templateId === "malicious-known-compromise") {
    tags.push("historical compromise");
  } else if (templateId === "malicious-typosquat") {
    tags.push("typosquat oracle");
  } else if (templateId === "malicious-install-hook") {
    tags.push("install-hook oracle");
  } else if (templateId.startsWith("manual-")) {
    tags.push("manual package finding");
  } else if (templateId.startsWith("custom-")) {
    tags.push("custom finding");
  } else if (templateId === "audit-agent") {
    tags.push("agent finding");
  }

  if (triageNote.includes("suppressed documented extension") || triageNote.includes("suppress")) {
    tags.push("suppressor");
  }
  if (triageNote.includes("downgraded")) {
    tags.push("downgraded");
  }
  if (finding.triageStatus === "accepted") {
    tags.push("accepted");
  } else if (finding.triageStatus === "suppressed") {
    tags.push("suppressed");
  } else {
    tags.push("new");
  }

  return [...new Set(tags)];
}

function badgeColor(tag: string): string {
  if (tag === "accepted") return SUCCESS;
  if (tag === "suppressed") return MUTED;
  if (tag === "downgraded") return WARNING;
  if (tag === "deterministic advisory") return INFO;
  if (tag === "historical compromise") return ERROR;
  if (tag === "typosquat oracle" || tag === "install-hook oracle") return PRIMARY;
  if (tag === "suppressor") return SECONDARY;
  return MUTED;
}

async function loadState(dbPath?: string): Promise<{
  scans: ScanRow[];
  findings: FindingRow[];
  events: EventRow[];
  workItems: WorkItemRow[];
  workers: WorkerRow[];
}> {
  const { pwnkitDB } = await import("@pwnkit/db");
  const db = new pwnkitDB(dbPath);
  try {
    return {
      scans: db.listScans(50) as ScanRow[],
      findings: db.listFindings({ limit: 500 }) as FindingRow[],
      events: db.listRecentEvents(100) as EventRow[],
      workItems: (db.listWorkItems?.({ limit: 500 }) ?? []) as WorkItemRow[],
      workers: (db.listWorkers?.(50) ?? []) as WorkerRow[],
    };
  } finally {
    db.close();
  }
}

async function applyFindingTriage(
  dbPath: string | undefined,
  findingId: string,
  triageStatus: FindingTriageStatus,
  triageNote?: string,
): Promise<void> {
  const { pwnkitDB } = await import("@pwnkit/db");
  const db = new pwnkitDB(dbPath);
  try {
    db.updateFindingTriage(findingId, triageStatus, triageNote);
  } finally {
    db.close();
  }
}

function PaneTitle({
  label,
  active,
  meta,
}: {
  label: string;
  active: boolean;
  meta?: string;
}) {
  return (
    <Box justifyContent="space-between">
      <Text color={active ? PRIMARY : TEXT} bold>
        {label}
      </Text>
      {meta ? <Text color={MUTED}>{meta}</Text> : null}
    </Box>
  );
}

function PanelFrame({
  label,
  active,
  meta,
  tone,
  width,
  flexGrow,
  children,
}: {
  label: string;
  active?: boolean;
  meta?: string;
  tone?: string;
  width?: number;
  flexGrow?: number;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <Box width={width} flexGrow={flexGrow}>
      <Text color={tone ?? (active ? PRIMARY : BORDER)}>{RAIL}</Text>
      <Box flexDirection="column" marginLeft={1} flexGrow={1}>
        <PaneTitle label={label} active={Boolean(active)} meta={meta} />
        <Box flexDirection="column" marginTop={1}>
          {children}
        </Box>
      </Box>
    </Box>
  );
}

function nextPane(current: Pane): Pane {
  if (current === "scans") return "findings";
  if (current === "findings") return "details";
  return "scans";
}

function previousPane(current: Pane): Pane {
  if (current === "details") return "findings";
  if (current === "findings") return "scans";
  return "details";
}

function Stat({
  label,
  value,
  color = TEXT,
}: {
  label: string;
  value: string;
  color?: string;
}) {
  return (
    <Box marginRight={2}>
      <Text color={MUTED}>{label} </Text>
      <Text color={color} bold>{value}</Text>
    </Box>
  );
}

function OperatorTui({ dbPath, refreshMs = 4000 }: TuiOptions): React.ReactElement {
  const { exit } = useApp();
  const [pane, setPane] = useState<Pane>("scans");
  const [mode, setMode] = useState<InputMode>("normal");
  const [filter, setFilter] = useState("");
  const [familyFocus, setFamilyFocus] = useState(false);
  const [pendingTriageNote, setPendingTriageNote] = useState("");
  const [scanIndex, setScanIndex] = useState(0);
  const [findingIndex, setFindingIndex] = useState(0);
  const [detailOffset, setDetailOffset] = useState(0);
  const [pendingTriage, setPendingTriage] = useState<PendingTriageAction>(null);
  const [flashMessage, setFlashMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [state, setState] = useState<{
    scans: ScanRow[];
    findings: FindingRow[];
    events: EventRow[];
    workItems: WorkItemRow[];
    workers: WorkerRow[];
  }>({ scans: [], findings: [], events: [], workItems: [], workers: [] });

  useEffect(() => {
    let alive = true;

    const refresh = async () => {
      try {
        const next = await loadState(dbPath);
        if (!alive) return;
        setState(next);
        setError(null);
      } catch (err) {
        if (!alive) return;
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (alive) setLoading(false);
      }
    };

    void refresh();
    const timer = setInterval(() => void refresh(), refreshMs);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [dbPath, refreshMs]);

  const scans = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return state.scans;
    return state.scans.filter((scan: ScanRow) =>
      [
        scan.target,
        scan.depth,
        scan.runtime,
        scan.mode,
        scan.status,
        scan.id,
      ]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }, [filter, state.scans]);
  const selectedScan = scans[scanIndex] ?? null;
  const selectedScanFindings = useMemo(() => {
    if (!selectedScan) return [] as FindingRow[];
    return state.findings.filter((finding: FindingRow) => finding.scanId === selectedScan.id);
  }, [selectedScan, state.findings]);
  const selectedScanCandidate = selectedScanFindings[findingIndex] ?? null;
  const activeFingerprint =
    familyFocus && selectedScanCandidate?.fingerprint
      ? selectedScanCandidate.fingerprint
      : null;
  const findingsForScan = useMemo(() => {
    if (!selectedScan) return [] as FindingRow[];
    const source = activeFingerprint
      ? state.findings.filter((finding: FindingRow) => (finding.fingerprint ?? finding.id) === activeFingerprint)
      : selectedScanFindings;
    const q = filter.trim().toLowerCase();
    if (!q) return source;
    return source.filter((finding: FindingRow) =>
      [
        finding.title,
        finding.category,
        finding.severity,
        finding.status,
        finding.triageStatus ?? "",
        finding.triageNote ?? "",
      ]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }, [activeFingerprint, filter, selectedScan, selectedScanFindings, state.findings]);
  const selectedFinding = findingsForScan[findingIndex] ?? null;
  const eventsForSelection = useMemo(() => {
    if (!selectedScan) return [] as EventRow[];
    const source = state.events.filter((event: EventRow) => event.scanId === selectedScan.id);
    if (!selectedFinding) return source.slice(0, 8);
    return source
      .filter((event: EventRow) => !event.findingId || event.findingId === selectedFinding.id)
      .slice(0, 8);
  }, [selectedScan, selectedFinding, state.events]);
  const queueSummary = useMemo(
    () => summarizeQueue(state.workItems, state.workers),
    [state.workItems, state.workers],
  );
  const activeWorkers = useMemo(
    () => summarizeActiveWorkers(state.workers, state.workItems),
    [state.workItems, state.workers],
  );
  const recentIncidents = useMemo(
    () => summarizeIncidents(state.events),
    [state.events],
  );

  const detailLines = useMemo(() => {
    const lines: Array<{ color: string; text: string; bold?: boolean }> = [];

    if (selectedFinding) {
      lines.push({
        color: "#FFFFFF",
        text: selectedFinding.title,
        bold: true,
      });
      lines.push({
        color: severityColor(selectedFinding.severity),
        text: `${selectedFinding.severity.toUpperCase()} · ${selectedFinding.category}`,
      });
      lines.push({
        color: "#6B7280",
        text: `provenance: ${originTags(selectedFinding).join(" · ")}`,
      });
      lines.push({
        color: "#6B7280",
        text: `template: ${selectedFinding.templateId}`,
      });
      if (selectedFinding.triageStatus || selectedFinding.triageNote) {
        lines.push({
          color: "#6B7280",
          text: `triage: ${selectedFinding.triageStatus ?? "new"}${selectedFinding.triageNote ? ` · ${selectedFinding.triageNote}` : ""}`,
        });
      }
      lines.push({ color: "#9CA3AF", text: selectedFinding.description });
      if (selectedFinding.evidenceRequest) {
        lines.push({ color: "#6B7280", text: "Request" });
        lines.push({ color: "#D1D5DB", text: selectedFinding.evidenceRequest });
      }
      if (selectedFinding.evidenceResponse) {
        lines.push({ color: "#6B7280", text: "Response" });
        lines.push({ color: "#D1D5DB", text: selectedFinding.evidenceResponse });
      }
      if (selectedFinding.evidenceAnalysis) {
        lines.push({ color: "#6B7280", text: "Analysis" });
        lines.push({ color: "#D1D5DB", text: selectedFinding.evidenceAnalysis });
      }
    } else if (selectedScan) {
      lines.push({
        color: "#FFFFFF",
        text: selectedScan.target,
        bold: true,
      });
      lines.push({
        color: "#9CA3AF",
        text: `${selectedScan.mode}/${selectedScan.depth} · ${selectedScan.runtime} · ${selectedScan.status}`,
      });
      lines.push({
        color: "#9CA3AF",
        text: `Started ${formatStarted(selectedScan.startedAt)}`,
      });
      if (selectedScan.completedAt) {
        lines.push({
          color: "#9CA3AF",
          text: `Completed ${formatStarted(selectedScan.completedAt)}`,
        });
      }
    }

    lines.push({ color: "#6B7280", text: "" });
    lines.push({ color: "#6B7280", text: "Recent events" });
    if (eventsForSelection.length === 0) {
      lines.push({ color: "#9CA3AF", text: "No recent events." });
    } else {
      for (const event of eventsForSelection) {
        lines.push({
          color: "#FFFFFF",
          text: `${event.stage} · ${event.eventType}`,
        });
        lines.push({
          color: "#6B7280",
          text: event.payload,
        });
      }
    }

    return lines.flatMap((line) => {
      const source = line.text.length === 0 ? [""] : line.text.split(/\n/);
      return source.map((text) => ({ ...line, text }));
    });
  }, [eventsForSelection, selectedFinding, selectedScan]);

  const detailPageSize = 18;
  const maxDetailOffset = Math.max(0, detailLines.length - detailPageSize);
  const visibleDetailLines = detailLines.slice(detailOffset, detailOffset + detailPageSize);

  useEffect(() => {
    if (scanIndex >= scans.length) {
      setScanIndex(Math.max(0, scans.length - 1));
    }
  }, [scanIndex, scans.length]);

  useEffect(() => {
    if (findingIndex >= findingsForScan.length) {
      setFindingIndex(Math.max(0, findingsForScan.length - 1));
    }
  }, [findingIndex, findingsForScan.length]);

  useEffect(() => {
    setDetailOffset(0);
  }, [selectedScan?.id, selectedFinding?.id]);

  useEffect(() => {
    setPendingTriageNote("");
  }, [selectedFinding?.id]);

  useInput((input: string, key: Key) => {
    if (mode === "filter") {
      if (key.escape) {
        setMode("normal");
        setFilter("");
        return;
      }
      if (key.return) {
        setMode("normal");
        return;
      }
      if (key.backspace || key.delete) {
        setFilter((current: string) => current.slice(0, -1));
        return;
      }
      if (input && !key.ctrl && !key.meta) {
        setFilter((current: string) => current + input);
      }
      return;
    }

    if (mode === "note") {
      if (key.escape) {
        setMode("normal");
        return;
      }
      if (key.return) {
        setMode("normal");
        return;
      }
      if (key.backspace || key.delete) {
        setPendingTriageNote((current: string) => current.slice(0, -1));
        return;
      }
      if (
        !pendingTriage
        && selectedFinding
        && (input === "A" || input === "S")
      ) {
        setPendingTriage(input === "A" ? "accepted" : "suppressed");
        setMode("normal");
        return;
      }
      if (input && !key.ctrl && !key.meta) {
        setPendingTriageNote((current: string) => current + input);
      }
      return;
    }

    if (pendingTriage) {
      if (key.escape || input === "n") {
        setPendingTriage(null);
        return;
      }
      if ((key.return || input === "y") && selectedFinding) {
        setLoading(true);
        const triageNote = pendingTriageNote.trim() || undefined;
        void applyFindingTriage(dbPath, selectedFinding.id, pendingTriage, triageNote)
          .then(async () => {
            const next = await loadState(dbPath);
            setState(next);
            setError(null);
            const id = selectedFinding.id.slice(0, 8);
            setFlashMessage(
              triageNote
                ? `Marked ${id} as ${pendingTriage} with note.`
                : `Marked ${id} as ${pendingTriage}.`,
            );
            setTimeout(() => setFlashMessage(null), 2500);
          })
          .catch((err) => setError(err instanceof Error ? err.message : String(err)))
          .finally(() => {
            setLoading(false);
            setPendingTriage(null);
            setPendingTriageNote("");
          });
        return;
      }
      return;
    }

    if (key.escape || input === "q" || (key.ctrl && input === "c")) {
      exit();
      return;
    }

    if (input === "/") {
      setMode("filter");
      setFilter("");
      return;
    }

    if (input === "\t" || key.rightArrow) {
      setPane((current: Pane) => nextPane(current));
      return;
    }

    if (key.leftArrow) {
      setPane((current: Pane) => previousPane(current));
      return;
    }

    if (key.upArrow) {
      if (pane === "scans") {
        setScanIndex((current: number) => Math.max(0, current - 1));
        setFindingIndex(0);
      } else if (pane === "findings") {
        setFindingIndex((current: number) => Math.max(0, current - 1));
      } else {
        setDetailOffset((current: number) => Math.max(0, current - 1));
      }
      return;
    }

    if (key.downArrow) {
      if (pane === "scans") {
        setScanIndex((current: number) => Math.min(scans.length - 1, current + 1));
        setFindingIndex(0);
      } else if (pane === "findings") {
        setFindingIndex((current: number) =>
          Math.min(findingsForScan.length - 1, current + 1),
        );
      } else {
        setDetailOffset((current: number) => Math.min(maxDetailOffset, current + 1));
      }
      return;
    }

    if (pane === "details") {
      if (input === "j") {
        setDetailOffset((current: number) => Math.min(maxDetailOffset, current + 1));
        return;
      }
      if (input === "k") {
        setDetailOffset((current: number) => Math.max(0, current - 1));
        return;
      }
      if (input === "d" || key.pageDown) {
        setDetailOffset((current: number) => Math.min(maxDetailOffset, current + detailPageSize));
        return;
      }
      if (input === "u" || key.pageUp) {
        setDetailOffset((current: number) => Math.max(0, current - detailPageSize));
        return;
      }
      if (input === "g") {
        setDetailOffset(0);
        return;
      }
      if (input === "G") {
        setDetailOffset(maxDetailOffset);
        return;
      }
    }

      if (input === "r") {
      setLoading(true);
      void loadState(dbPath)
        .then((next) => {
          setState(next);
          setError(null);
        })
        .catch((err) => setError(err instanceof Error ? err.message : String(err)))
        .finally(() => setLoading(false));
    }

    if ((pane === "findings" || pane === "details") && selectedFinding) {
      if (input === "f") {
        setFamilyFocus((current: boolean) => !current);
        setFindingIndex(0);
        return;
      }
      if (input === "n") {
        setPendingTriageNote(selectedFinding.triageNote ?? "");
        setMode("note");
        return;
      }
      if (input === "a") {
        setPendingTriage("accepted");
        return;
      }
      if (input === "s") {
        setPendingTriage("suppressed");
        return;
      }
      if (input === "A") {
        setPendingTriage("accepted");
        return;
      }
      if (input === "S") {
        setPendingTriage("suppressed");
        return;
      }
    }
  });

  return (
    <Box flexDirection="column" paddingLeft={2} paddingRight={2}>
      <PanelFrame label="Mission control" meta="operator shell" tone={PRIMARY}>
        <Box flexDirection="row" flexWrap="wrap">
          <Stat label="runs" value={String(scans.length)} />
          <Stat label="findings" value={String(state.findings.length)} />
          <Stat
            label="critical"
            value={String(state.findings.filter((finding: FindingRow) => finding.severity === "critical").length)}
            color={ERROR}
          />
          <Stat
            label="high"
            value={String(state.findings.filter((finding: FindingRow) => finding.severity === "high").length)}
            color={WARNING}
          />
          <Stat label="pane" value={pane} color={SECONDARY} />
          <Stat label="refresh" value={`${refreshMs}ms`} color={MUTED} />
          <Stat label="family" value={familyFocus ? "on" : "off"} color={familyFocus ? PRIMARY : MUTED} />
          <Stat label="runnable" value={String(queueSummary.runnable)} color={SUCCESS} />
          <Stat label="workers" value={String(activeWorkers.length)} color={activeWorkers.length > 0 ? INFO : MUTED} />
          <Stat label="incidents" value={String(recentIncidents.length)} color={recentIncidents.length > 0 ? ERROR : MUTED} />
        </Box>
      </PanelFrame>
      <Box marginTop={1} marginLeft={2} gap={2}>
        <Text color={MUTED}>tab / arrows switch</Text>
        <Text color={MUTED}>/ filter</Text>
        <Text color={MUTED}>f family</Text>
        <Text color={MUTED}>n note</Text>
        <Text color={MUTED}>a s triage</Text>
        <Text color={MUTED}>r refresh</Text>
        <Text color={MUTED}>q quit</Text>
      </Box>
      {mode === "filter" ? (
        <PanelFrame label="Filter" meta="query" tone={SECONDARY}>
          <Box>
            <Text color={TEXT}>{filter}</Text>
            <Text color={INFO}>█</Text>
          </Box>
        </PanelFrame>
      ) : mode === "note" ? (
        <PanelFrame label="Triage note" meta="enter or esc to finish" tone={PRIMARY}>
          <Box>
            <Text color={TEXT}>{pendingTriageNote}</Text>
            <Text color={INFO}>█</Text>
          </Box>
          <Text color={MUTED}>A accept with note · S suppress with note</Text>
        </PanelFrame>
      ) : pendingTriage ? (
        <PanelFrame label="Confirmation" meta="pending action" tone={WARNING}>
          <Text color={WARNING}>
            Mark {selectedFinding?.id.slice(0, 8) ?? "finding"} as {pendingTriage}
            {pendingTriageNote.trim() ? " with note" : ""}? enter or y confirm, esc or n cancel
          </Text>
        </PanelFrame>
      ) : flashMessage ? (
        <PanelFrame label="Update" meta="applied" tone={SUCCESS}>
          <Text color={SUCCESS}>{flashMessage}</Text>
        </PanelFrame>
      ) : filter ? (
        <PanelFrame label="Filter" meta="active" tone={SECONDARY}>
          <Text color={MUTED}>{filter}</Text>
        </PanelFrame>
      ) : pendingTriageNote ? (
        <PanelFrame label="Note" meta="ready" tone={PRIMARY}>
          <Text color={MUTED}>{truncate(pendingTriageNote, 80)}</Text>
        </PanelFrame>
      ) : null}
      {loading ? <Text color={MUTED}>  Loading local pwnkit state…</Text> : null}
      {error ? <Text color={ERROR}>  {error}</Text> : null}
      {!loading && !error && scans.length === 0 ? (
        <Text color={MUTED}>  No local scans found. Run a scan, audit, or review first.</Text>
      ) : null}

      {!loading && !error && scans.length > 0 ? (
        <Box flexDirection="row" gap={3} marginTop={1} marginBottom={1}>
          <PanelFrame
            label="Queue"
            meta="scheduler"
            tone={queueSummary.runnable > 0 ? SUCCESS : BORDER}
            width={36}
          >
            <Text color={TEXT}>runnable <Text color={SUCCESS}>{String(queueSummary.runnable)}</Text></Text>
            <Text color={TEXT}>active claims <Text color={WARNING}>{String(queueSummary.active)}</Text></Text>
            <Text color={TEXT}>blocked deps <Text color={MUTED}>{String(queueSummary.blockedByDependency)}</Text></Text>
            <Text color={TEXT}>manual review <Text color={PRIMARY}>{String(queueSummary.manualReview)}</Text></Text>
            <Text color={TEXT}>stale workers <Text color={queueSummary.staleWorkers > 0 ? ERROR : MUTED}>{String(queueSummary.staleWorkers)}</Text></Text>
            <Text color={TEXT}>recovered <Text color={INFO}>{String(queueSummary.recoveredClaims)}</Text></Text>
          </PanelFrame>

          <PanelFrame
            label="Workers"
            meta={`${activeWorkers.length} active`}
            tone={activeWorkers.length > 0 ? INFO : BORDER}
            width={52}
          >
            {activeWorkers.length === 0 ? (
              <Text color={MUTED}>No active orchestration daemons.</Text>
            ) : (
              activeWorkers.slice(0, 3).map((worker: ActiveWorkerSummary) => (
                <Box key={worker.id} flexDirection="column" marginBottom={1}>
                  <Text color={TEXT}>
                    {worker.label} · <Text color={statusColor(worker.status)}>{worker.status}</Text>
                  </Text>
                  <Text color={MUTED}>{truncate(worker.currentTitle, 46)}</Text>
                  <Text color={MUTED}>heartbeat {worker.heartbeatLabel}</Text>
                  {worker.lastError ? <Text color={ERROR}>{truncate(worker.lastError, 52)}</Text> : null}
                </Box>
              ))
            )}
          </PanelFrame>

          <PanelFrame
            label="Incidents"
            meta={recentIncidents.length > 0 ? "attention" : "clear"}
            tone={recentIncidents.length > 0 ? ERROR : BORDER}
            flexGrow={1}
          >
            {recentIncidents.length === 0 ? (
              <Text color={SUCCESS}>No recent runtime incidents.</Text>
            ) : (
              recentIncidents.slice(0, 3).map((incident: IncidentSummary) => (
                <Box key={`${incident.scanId}:${incident.timestamp}`} flexDirection="column" marginBottom={1}>
                  <Text color={TEXT}>{truncate(incident.scanTarget, 54)}</Text>
                  <Text color={ERROR}>{truncate(incident.headline, 72)}</Text>
                  <Text color={MUTED}>
                    {incident.stage}
                    {incident.actor ? ` · ${incident.actor}` : ""}
                    {` · ${formatStarted(new Date(incident.timestamp).toISOString())}`}
                  </Text>
                </Box>
              ))
            )}
          </PanelFrame>
        </Box>
      ) : null}

      {!loading && !error && scans.length > 0 ? (
        <Box flexDirection="row" gap={3}>
          <PanelFrame
            label="Runs"
            active={pane === "scans"}
            meta={`${scans.length} total`}
            tone={pane === "scans" ? PRIMARY : BORDER}
            width={40}
          >
            {scans.slice(0, 14).map((scan: ScanRow, index: number) => {
              const selected = index === scanIndex;
              const summary = parseSummary(scan.summary);
              return (
                <Box key={scan.id} marginBottom={1}>
                  <Text color={selected ? PRIMARY : BORDER}>{selected ? RAIL : "│"}</Text>
                  <Box flexDirection="column" marginLeft={1}>
                    <Text color={selected ? TEXT : "#CFCFCF"} bold={selected}>
                      {truncate(scan.target, 28)}
                    </Text>
                    <Text color={MUTED}>
                      {scan.mode}/{scan.depth} · {scan.runtime} · <Text color={statusColor(scan.status)}>{scan.status}</Text>
                    </Text>
                    <Text color={MUTED}>
                      {summary.totalFindings ?? 0} findings · {formatDuration(scan.durationMs)}
                    </Text>
                  </Box>
                </Box>
              );
            })}
          </PanelFrame>

          <PanelFrame
            label="Findings"
            active={pane === "findings"}
            meta={
              selectedScan
                ? familyFocus
                  ? `${findingsForScan.length} in family`
                  : `${findingsForScan.length} in run`
                : ""
            }
            tone={pane === "findings" ? PRIMARY : BORDER}
            width={48}
          >
            {findingsForScan.length === 0 ? (
              <Text color={MUTED}>No findings for this run.</Text>
            ) : (
              findingsForScan.slice(0, 14).map((finding: FindingRow, index: number) => {
                const selected = index === findingIndex;
                return (
                  <Box key={finding.id} marginBottom={1}>
                    <Text color={selected ? PRIMARY : BORDER}>{selected ? RAIL : "│"}</Text>
                    <Box flexDirection="column" marginLeft={1}>
                      <Text color={severityColor(finding.severity)} bold={selected}>
                        [{finding.severity}] {truncate(finding.title, 34)}
                      </Text>
                      <Text color={MUTED}>
                        {finding.category} · <Text color={triageColor(finding.triageStatus)}>{finding.triageStatus ?? "new"}</Text>
                      </Text>
                      <Box flexDirection="row" flexWrap="wrap">
                        {originTags(finding).slice(0, 3).map((tag) => (
                          <Box key={tag} marginRight={1}>
                            <Text color={badgeColor(tag)}>{tag}</Text>
                          </Box>
                        ))}
                      </Box>
                      {finding.triageNote ? (
                        <Text color={MUTED}>{truncate(finding.triageNote, 40)}</Text>
                      ) : null}
                    </Box>
                  </Box>
                );
              })
            )}
          </PanelFrame>

          <PanelFrame
            label="Details"
            active={pane === "details"}
            meta={`${detailOffset + 1}-${Math.min(detailOffset + detailPageSize, detailLines.length)}/${detailLines.length || 0}`}
            tone={pane === "details" ? PRIMARY : BORDER}
            flexGrow={1}
          >
            {visibleDetailLines.map((line: { color: string; text: string; bold?: boolean }, index: number) => (
              <Text
                key={`${detailOffset}-${index}-${line.text.slice(0, 16)}`}
                color={line.color}
                bold={line.bold}
                wrap="truncate-end"
              >
                {truncate(line.text, 300)}
              </Text>
            ))}
          </PanelFrame>
        </Box>
      ) : null}
      {!loading && !error && scans.length > 0 ? (
        <Box marginTop={1} marginLeft={2}>
          <Text color={MUTED}>
            {pane === "scans"
              ? `runs ${scanIndex + 1}/${Math.max(scans.length, 1)} · ${selectedScan?.id.slice(0, 8) ?? "none"}`
              : pane === "findings"
                ? `findings ${findingIndex + 1}/${Math.max(findingsForScan.length, 1)} · ${selectedFinding?.id.slice(0, 8) ?? "none"}`
                : `details ${detailOffset + 1}-${Math.min(detailOffset + detailPageSize, detailLines.length)}/${detailLines.length || 0}`}
            {selectedScan ? ` · ${selectedScan.mode}/${selectedScan.depth} · ${selectedScan.runtime}` : ""}
            {selectedFinding ? ` · ${selectedFinding.severity}/${selectedFinding.category}` : ""}
            {activeFingerprint ? ` · fp:${activeFingerprint.slice(0, 8)}` : ""}
            {filter ? ` · filter:${filter}` : ""}
            {` · queue:${queueSummary.runnable}/${queueSummary.active}/${queueSummary.manualReview}`}
            {activeWorkers.length > 0 ? ` · workers:${activeWorkers.length}` : ""}
            {recentIncidents.length > 0 ? ` · incidents:${recentIncidents.length}` : ""}
          </Text>
        </Box>
      ) : null}
    </Box>
  );
}

export async function showOperatorTui(options: TuiOptions): Promise<void> {
  printBanner();
  await new Promise<void>((resolve) => {
    const instance = render(<OperatorTui {...options} />);
    const done = () => {
      instance.unmount();
      resolve();
    };
    instance.waitUntilExit().then(done).catch(done);
  });
}
