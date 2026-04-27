/**
 * Pluggable event bus for scanner / agent-loop telemetry.
 *
 * The legacy `ScanListener` API (see `../scanner.ts`) only carried coarse
 * stage:start / stage:end / finding events. The cloud worker-controller and
 * future tracing sinks need richer signal — per-turn agent state, tool calls,
 * planner invocations, finding ingests — so this module introduces a
 * fan-out `EventBus` that the rest of the core can `emit()` typed events
 * into, and that any number of `EventSink` consumers can subscribe to.
 *
 * Design goals:
 *
 *   1. Pluggable. Any module that can take an `EventSink` (cloud relay,
 *      in-memory spy for tests, OpenTelemetry exporter, etc.) can subscribe
 *      at process start without the scanner knowing about it.
 *   2. Backwards-compatible. The existing `ScanListener` public API is
 *      preserved via `scanListenerSink()` — an adapter that maps the new
 *      richer event vocabulary back onto the three legacy `ScanEvent`
 *      shapes so external consumers keep receiving familiar signals.
 *   3. Fail-soft. One buggy sink must never be able to abort a scan;
 *      exceptions thrown by a sink are caught and logged to stderr.
 *   4. Opt-in cloud relay. The `CloudEventSink` is OFF by default so
 *      local CLI runs are not spammed with `PWNKIT_EVENT_*` lines;
 *      enable via `PWNKIT_CLOUD_EVENTS=1` (checked at subscribe time).
 *
 * Cloud wire format (matches the cloud worker-controller's
 * `parseEventLines` in `pwnkit-cloud/services/worker-controller/src/poller.ts`):
 *
 *     PWNKIT_EVENT_<TYPE_UPPER> {"…json payload…"}
 *
 * e.g. `PWNKIT_EVENT_STEP_STARTED {"step":"recon","n":1}`.
 */
import type { ScanEvent, ScanListener } from "../scanner.js";

// ── Event taxonomy ──────────────────────────────────────────────────────────
//
// The discriminated union below is the single source of truth for what
// events the core emits. New event types MUST be added here (and in the
// `EventType` alias) before they can be emitted — TypeScript will then
// enforce payload shapes at every call site.
//
// Canonical event types the cloud already understands (schema comment in
// `pwnkit-cloud/services/dashboard/src/db/schema.ts:680`):
//
//   step_started, step_completed, finding_ingested, cost_update,
//   scan_completed
//
// M5 (agent-trace) additions — cloud will learn to render these:
//
//   agent_turn_started, agent_turn_completed,
//   tool_call_started, tool_call_completed,
//   llm_planner_invoked, reasoning_summary

export interface StepStartedPayload {
  step: string;
  n?: number;
}

export interface StepCompletedPayload {
  step: string;
  duration_ms?: number;
  n?: number;
  [k: string]: unknown;
}

export interface FindingIngestedPayload {
  finding_id?: string;
  severity?: string;
  title?: string;
  category?: string;
  [k: string]: unknown;
}

export interface CostUpdatePayload {
  cost_usd?: number;
  input_tokens?: number;
  output_tokens?: number;
  turn?: number;
  [k: string]: unknown;
}

export interface ScanCompletedPayload {
  exit_reason?: string;
  findings?: number;
  duration_ms?: number;
  /**
   * How many agent turns the scan consumed before terminating. Sourced
   * from the loop state's `turnCount`. Cloud dashboard renders this in
   * the per-scan card meta line so a no-findings scan still tells the
   * operator how much work was done.
   */
  turns_used?: number;
  /**
   * Total tool calls across all turns. Tracked by counting
   * `tool_call_completed` bus events between `scan_started` and this
   * one, so we never under-count even on partial / errored exits.
   */
  tool_calls_total?: number;
  /**
   * Short narrative the agent produced in its final `done` tool call,
   * e.g. "Audited lodash, no exploitable sinks found in template.js".
   * Empty when the scan didn't reach a `done` call (cost-exceeded,
   * max-turns, etc.). Cloud uses this verbatim as the human-readable
   * summary on the scan card and detail header.
   */
  summary?: string;
  [k: string]: unknown;
}

export interface AgentTurnStartedPayload {
  turn: number;
  max_turns: number;
  role?: string;
}

export interface AgentTurnCompletedPayload {
  turn: number;
  duration_ms: number;
  reason: "continue" | "finished" | "max_turns" | "error" | "cost_ceiling" | "early_stop";
  role?: string;
}

export interface ToolCallStartedPayload {
  tool: string;
  turn: number;
  args_preview: string;
}

export interface ToolCallCompletedPayload {
  tool: string;
  turn: number;
  duration_ms: number;
  status: "ok" | "error";
  error?: string;
}

export interface LlmPlannerInvokedPayload {
  turn: number;
  model?: string;
  tokens_est?: number;
  role?: string;
}

export interface ReasoningSummaryPayload {
  turn: number;
  summary: string;
}

/** Discriminated union of all events flowing through the bus. */
export type PwnkitEvent =
  | { type: "step_started"; payload: StepStartedPayload }
  | { type: "step_completed"; payload: StepCompletedPayload }
  | { type: "finding_ingested"; payload: FindingIngestedPayload }
  | { type: "cost_update"; payload: CostUpdatePayload }
  | { type: "scan_completed"; payload: ScanCompletedPayload }
  | { type: "agent_turn_started"; payload: AgentTurnStartedPayload }
  | { type: "agent_turn_completed"; payload: AgentTurnCompletedPayload }
  | { type: "tool_call_started"; payload: ToolCallStartedPayload }
  | { type: "tool_call_completed"; payload: ToolCallCompletedPayload }
  | { type: "llm_planner_invoked"; payload: LlmPlannerInvokedPayload }
  | { type: "reasoning_summary"; payload: ReasoningSummaryPayload };

/** Narrow the event type string to the known vocabulary. */
export type EventType = PwnkitEvent["type"];

/** Payload for a given event type. */
export type EventPayloadFor<T extends EventType> = Extract<
  PwnkitEvent,
  { type: T }
>["payload"];

// ── Sink interface ──────────────────────────────────────────────────────────

export interface EventSink {
  /**
   * Called once per emitted event. Exceptions are caught by the bus; a sink
   * SHOULD still try to avoid throwing — the diagnostic write happens on
   * stderr which may itself be captured.
   */
  emit(type: EventType, payload: Record<string, unknown>): void;
}

// ── EventBus ────────────────────────────────────────────────────────────────

class EventBus {
  private sinks: EventSink[] = [];

  /** Subscribe a sink. Returns an unsubscribe function. */
  subscribe(sink: EventSink): () => void {
    this.sinks.push(sink);
    return () => {
      const idx = this.sinks.indexOf(sink);
      if (idx >= 0) this.sinks.splice(idx, 1);
    };
  }

  /** Remove every subscriber — primarily useful in tests. */
  clear(): void {
    this.sinks = [];
  }

  /** Returns a read-only snapshot of the current sinks (for tests). */
  get size(): number {
    return this.sinks.length;
  }

  /**
   * Fan out a single event to every subscribed sink. Exceptions thrown by
   * any sink are swallowed — one misbehaving consumer must never abort a
   * scan. Diagnostic is written to stderr so the failure is visible.
   */
  emit<T extends EventType>(type: T, payload: EventPayloadFor<T>): void {
    // Snapshot so unsubscribes mid-iteration don't skip sinks.
    const snapshot = this.sinks.slice();
    for (const sink of snapshot) {
      try {
        sink.emit(type, payload as Record<string, unknown>);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        try {
          process.stderr.write(`[pwnkit event-bus] sink threw on ${type}: ${msg}\n`);
        } catch {
          /* stderr gone — nothing more we can do */
        }
      }
    }
  }
}

/** Singleton bus. Modules `import { eventBus } from "../events/bus.js"`. */
export const eventBus = new EventBus();

// ── ScanListenerSink: legacy adapter ────────────────────────────────────────

/**
 * Translate the new richer event vocabulary back onto the legacy
 * `ScanListener` / `ScanEvent` shape so external consumers keep seeing the
 * familiar `stage:start` / `stage:end` / `finding` / `usage` events.
 *
 * Events that have no legacy equivalent (agent_turn_*, tool_call_*,
 * llm_planner_invoked, reasoning_summary) are intentionally dropped by this
 * adapter — callers who want those should subscribe a richer sink directly.
 */
export function scanListenerSink(listener: ScanListener): EventSink {
  return {
    emit(type, payload) {
      const scanEvent = mapToScanEvent(type, payload);
      if (scanEvent !== null) listener(scanEvent);
    },
  };
}

function mapToScanEvent(
  type: EventType,
  payload: Record<string, unknown>,
): ScanEvent | null {
  switch (type) {
    case "step_started": {
      const step = String(payload.step ?? "");
      return {
        type: "stage:start",
        stage: step,
        message: typeof payload.message === "string"
          ? payload.message
          : `Stage ${step} started`,
        data: payload,
      };
    }
    case "step_completed": {
      const step = String(payload.step ?? "");
      return {
        type: "stage:end",
        stage: step,
        message: typeof payload.message === "string"
          ? payload.message
          : `Stage ${step} completed`,
        data: payload,
      };
    }
    case "finding_ingested": {
      const severity = typeof payload.severity === "string"
        ? payload.severity.toUpperCase()
        : "INFO";
      const title = typeof payload.title === "string" ? payload.title : "Finding";
      return {
        type: "finding",
        message: `[${severity}] ${title}`,
        data: payload,
      };
    }
    case "cost_update":
      return {
        type: "usage",
        message: "usage",
        data: payload,
      };
    case "scan_completed":
      // The OSS ScanListener has no "done" event — swallow.
      return null;
    default:
      return null;
  }
}

// ── CloudEventSink ──────────────────────────────────────────────────────────

/**
 * Emits one line per event to stdout in the format the cloud
 * worker-controller expects:
 *
 *     PWNKIT_EVENT_<TYPE_UPPER> {"…json payload…"}
 *
 * Default OFF. Opt-in by setting `PWNKIT_CLOUD_EVENTS=1` (or, equivalently,
 * by calling `subscribeCloudEventSink()` explicitly from the CLI entry
 * point when worker mode is selected). Local interactive runs keep a clean
 * stdout.
 */
export const cloudEventSink: EventSink = {
  emit(type, payload) {
    const prefix = `PWNKIT_EVENT_${type.toUpperCase()}`;
    let line: string;
    try {
      line = `${prefix} ${JSON.stringify(payload)}`;
    } catch {
      // Unserializable payload — degrade gracefully rather than throwing.
      line = `${prefix} {"_unserializable":true}`;
    }
    // Use process.stdout.write directly so we bypass any console.log
    // formatting / buffering surprises. One PWNKIT_EVENT_ line per call.
    process.stdout.write(line + "\n");
  },
};

/**
 * Idempotent helper for the CLI entry point: subscribe the cloud sink iff
 * the opt-in env var is truthy AND we haven't already subscribed. Safe to
 * call multiple times.
 */
let cloudSinkSubscribed = false;
export function maybeSubscribeCloudEventSink(): void {
  if (cloudSinkSubscribed) return;
  const flag = process.env.PWNKIT_CLOUD_EVENTS;
  if (flag && flag !== "0" && flag.toLowerCase() !== "false") {
    eventBus.subscribe(cloudEventSink);
    cloudSinkSubscribed = true;
  }
}

/** Test-only: reset the idempotency flag. */
export function _resetCloudSinkSubscriptionForTests(): void {
  cloudSinkSubscribed = false;
}
