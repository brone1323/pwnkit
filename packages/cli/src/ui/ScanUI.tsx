import React from "react";
import { Box, Text } from "ink";
import Spinner from "ink-spinner";
import {
  formatStageDetail,
  selectVisibleActions,
  truncateStageAction,
} from "@pwnkit/core";
import {
  ACCENT,
  BORDER,
  BULLET,
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

// ── Types ──

export type StageStatusKind = "pending" | "running" | "done" | "error";

export interface StageFinding {
  severity: string;
  title: string;
}

export interface StageState {
  id: string;
  label: string;
  status: StageStatusKind;
  detail?: string;
  duration?: number;
  actions: string[];
  findings: StageFinding[];
  error?: string;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
  duration?: number;
  shareUrl?: string;
}

export interface ScanEvent {
  type: string;
  stage?: string;
  message: string;
  data?: unknown;
}

export interface ScanUIProps {
  stages: StageState[];
  summary: ScanSummary | null;
  thinking: string | null;
  target: string;
  depth: string;
  mode: string;
  exitHint?: string | null;
  /**
   * When false (the default), each stage shows only the last 3 actions and
   * each action is truncated to ~60 chars, to keep the banner terminal-friendly.
   * When true, more history is shown with a wider per-row budget so the user
   * can see what every turn is doing. Toggled at runtime via `v` or Ctrl+O in
   * the scan TUI. The actual caps live in @pwnkit/core's scan-ui-state module.
   */
  verbose?: boolean;
}

function formatDuration(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

function toneForStage(status: StageStatusKind): string {
  if (status === "running") return PRIMARY;
  if (status === "done") return SUCCESS;
  if (status === "error") return ERROR;
  return BORDER;
}

function RailBlock({
  tone,
  title,
  meta,
  children,
}: {
  tone: string;
  title: string;
  meta?: string;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <Box>
      <Text color={tone}>{RAIL}</Text>
      <Box flexDirection="column" marginLeft={1}>
        <Box justifyContent="space-between">
          <Text color={TEXT} bold>{title}</Text>
          {meta ? <Text color={MUTED}>{meta}</Text> : null}
        </Box>
        {children}
      </Box>
    </Box>
  );
}

function InlineBadge({ label, value, color }: { label: string; value: string; color?: string }): React.ReactElement {
  return (
    <Text color={color ?? MUTED}>
      {label} <Text color={TEXT} bold>{value}</Text>
    </Text>
  );
}

function SessionHeader({ target, mode, depth, summary }: { target: string; mode: string; depth: string; summary: ScanSummary | null }): React.ReactElement {
  return (
    <RailBlock
      tone={PRIMARY}
      title="Live session"
      meta={summary ? "final report ready" : "streaming"}
    >
      <Text color={TEXT} bold>{target}</Text>
      <Box gap={2}>
        <InlineBadge label="mode" value={mode} color={PRIMARY} />
        <InlineBadge label="depth" value={depth} color={SECONDARY} />
        <InlineBadge label="view" value={summary ? "report" : "pipeline"} color={MUTED} />
      </Box>
    </RailBlock>
  );
}

// ── Stage Row ──

function StageRow({ stage, verbose }: { stage: StageState; verbose: boolean }) {
  const icon =
    stage.status === "done" ? (
      <Text color={SUCCESS}>{"✓"}</Text>
    ) : stage.status === "running" ? (
      <Text color={PRIMARY}><Spinner type="dots" /></Text>
    ) : stage.status === "error" ? (
      <Text color={ERROR}>{"✗"}</Text>
    ) : (
      <Text color={BORDER}>{"◌"}</Text>
    );

  // Compute verify confirmed count
  let verifyCount = "";
  if (stage.id === "verify" && stage.status === "done" && stage.actions.length > 0) {
    const confirmed = stage.actions.filter((a) => a.startsWith("\u2713")).length;
    const total = stage.actions.filter((a) => a.startsWith("\u2713") || a.startsWith("\u2717")).length;
    if (total > 0) {
      verifyCount = `${confirmed}/${total} confirmed`;
    }
  }

  return (
    <RailBlock
      tone={toneForStage(stage.status)}
      title={`${stage.label}${stage.duration !== undefined ? ` · ${formatDuration(stage.duration)}` : ""}`}
      meta={verifyCount || undefined}
    >
      <Box gap={1}>
        {icon}
        {stage.detail ? (
          <Text color={stage.status === "done" ? MUTED : TEXT} dimColor={stage.status === "done"}>
            {formatStageDetail(stage.detail, verbose)}
          </Text>
        ) : (
          <Text color={MUTED}>{stage.status === "pending" ? "waiting" : stage.status}</Text>
        )}
      </Box>

      {stage.actions.length > 0 && (() => {
        const { shown, hiddenCount } = selectVisibleActions(stage.actions, verbose);
        return (
          <Box flexDirection="column" marginTop={1}>
            {hiddenCount > 0 && (
              <Text color={MUTED}>
                {`… ${hiddenCount} earlier ${hiddenCount === 1 ? "action" : "actions"} hidden`}
              </Text>
            )}
            {shown.map((rawAction, i) => {
              const action = truncateStageAction(rawAction, verbose);
              if (stage.id === "verify") {
                const isConfirmed = action.startsWith("\u2713");
                const isRejected = action.startsWith("\u2717");
                const color = isConfirmed ? SUCCESS : isRejected ? ERROR : SECONDARY;
                return (
                  <Text key={i} color={color} dimColor={isRejected} strikethrough={isRejected}>
                    {BULLET} {action}
                  </Text>
                );
              }
              return (
                <Text key={i} color={stage.status === "done" ? MUTED : SECONDARY} dimColor={stage.status === "done"}>
                  {BULLET} {action}
                </Text>
              );
            })}
          </Box>
        );
      })()}

      {stage.findings.length > 0 && (
        <Box flexDirection="column" marginTop={1}>
          {stage.findings.map((f, i) => (
            <Text key={i} color={severityTone(f.severity)}>
              {BULLET} <Text bold>{f.severity.toUpperCase()}</Text> {f.title}
            </Text>
          ))}
        </Box>
      )}
    </RailBlock>
  );
}

// ── Summary ──

function SummaryBar({ summary }: { summary: ScanSummary }) {
  return (
    <RailBlock tone={summary.critical > 0 || summary.high > 0 ? ERROR : PRIMARY} title="Report" meta={summary.duration !== undefined ? formatDuration(summary.duration) : undefined}>
      <Box gap={2}>
        <Text color={summary.critical > 0 ? ERROR : MUTED} bold={summary.critical > 0}>
          {summary.critical} critical
        </Text>
        <Text color={summary.high > 0 ? ERROR : MUTED} bold={summary.high > 0}>
          {summary.high} high
        </Text>
        <Text color={summary.medium > 0 ? WARNING : MUTED} bold={summary.medium > 0}>
          {summary.medium} medium
        </Text>
        <Text color={MUTED}>{summary.low} low</Text>
        <Text color={MUTED}>{summary.info ?? 0} info</Text>
      </Box>
      {summary.shareUrl && (
        <Box marginTop={1}>
          <Text color={MUTED}>share </Text>
          <Text color={SECONDARY}>{summary.shareUrl}</Text>
        </Box>
      )}
    </RailBlock>
  );
}

// ── Outcome ──

/**
 * Per-stage terminal explanation rendered under the summary bar once the
 * scan finishes. This is where users finally get to read the full
 * "First attempt (10 turns): no findings. Retry (10 turns): Agent reached
 * max turns (10) without completing." sentence that the compact stage-row
 * detail clips at 55 chars. Without this block a 0-findings scan felt
 * like the agent "just stopped" — the narrative that explains *why* the
 * agent stopped is now always visible at the end.
 */
function OutcomeBlock({ stages }: { stages: StageState[] }) {
  const withDetail = stages.filter(
    (s) => s.status === "done" && s.detail && s.detail !== "done",
  );
  if (withDetail.length === 0) return null;
  return (
    <RailBlock tone={BORDER} title="Outcome" meta={`${withDetail.length} stage notes`}>
      <Box flexDirection="column">
        {withDetail.map((s) => (
          <Box key={s.id} flexDirection="column" marginBottom={1}>
            <Text color={TEXT} bold>{s.label}</Text>
            <Text color={MUTED} wrap="wrap">{s.detail}</Text>
          </Box>
        ))}
      </Box>
    </RailBlock>
  );
}

// ── Main ──

export function ScanUI({ stages, summary, thinking, target, depth, mode, exitHint, verbose = false }: ScanUIProps) {
  return (
    <Box flexDirection="column" paddingLeft={2} paddingRight={2}>
      <SessionHeader target={target} mode={mode} depth={depth} summary={summary} />
      <Box marginTop={1} marginLeft={2} gap={2}>
        <Text color={MUTED}>{verbose ? "verbose on" : "v / ctrl+o verbose"}</Text>
        <Text color={MUTED}>{summary ? "enter / esc / q close" : "watching agent activity"}</Text>
      </Box>
      <Box marginTop={1} flexDirection="column">
      {stages.map((stage) => (
        <StageRow key={stage.id} stage={stage} verbose={verbose} />
      ))}
      </Box>
      {thinking && (
        <RailBlock tone={ACCENT} title="Latest thought" meta={verbose ? "expanded" : "tail"}>
          <Text color={MUTED} wrap={verbose ? "wrap" : "truncate"}>
            {verbose ? thinking : thinking.slice(-80)}
          </Text>
        </RailBlock>
      )}
      {summary && <SummaryBar summary={summary} />}
      {summary && <OutcomeBlock stages={stages} />}
      <Box marginTop={1} marginLeft={2} gap={2}>
        <Text color={MUTED}>
          {verbose ? "verbose on" : "compact mode"}
        </Text>
        {summary && exitHint && (
          <Text color={MUTED}>{exitHint}</Text>
        )}
      </Box>
    </Box>
  );
}
