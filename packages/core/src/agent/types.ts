import type { Finding, AttackResult, TargetInfo, AuthConfig } from "@pwnkit/shared";
import type { ScopePolicy } from "../scope/scope.js";
import type { RateLimiter } from "../scope/rate-limit.js";

// ── Agent Roles ──

export type AgentRole = "discovery" | "attack" | "verify" | "report" | "audit" | "review";

// ── Tool Definitions ──

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, ToolParam>;
  required?: string[];
}

export interface ToolParam {
  type: "string" | "number" | "boolean" | "object";
  description: string;
  enum?: string[];
}

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

export interface ToolResult {
  success: boolean;
  output: unknown;
  error?: string;
}

// ── Agent Messages (multi-turn) ──

export type MessageRole = "system" | "user" | "assistant" | "tool";

export interface AgentMessage {
  role: MessageRole;
  content: string;
  toolCalls?: ToolCall[];
  toolResults?: Array<{ name: string; result: ToolResult }>;
}

// ── Agent Configuration ──

export interface AgentConfig {
  role: AgentRole;
  systemPrompt: string;
  tools: ToolDefinition[];
  maxTurns: number;
  target: string;
  scanId: string;
  scopePath?: string;
  sessionId?: string;
  attachTargetToolsMcp?: boolean;
  dbPath?: string;
  authConfig?: AuthConfig;
  /**
   * Programmatic engagement scope (pwnkit#215). When set, every URL the
   * agent touches — http_request, submit_form, browser navigate, crawl,
   * shellExec URL extraction, wp_fingerprint, web_search inputs — is
   * checked against this policy and out-of-scope URLs return as
   * `ToolResult.error`. Same-origin checks remain enforced ON TOP of
   * this; scope is additive, never substitutive.
   */
  scope?: ScopePolicy;
  /**
   * Per-host rate limiter for outbound HTTP. When set, every fetch
   * chokepoint (`http_request`, `crawl`, `submit_form`, `web_search`,
   * `wp_fingerprint`) acquires a token before the network call and
   * pipes the response back via `noteResponse` so 429 honours.
   * See `scope/rate-limit.ts` (#214).
   */
  rateLimiter?: RateLimiter;
  /**
   * Generic-scanner-traffic suppression opt-out (pwnkit#217). When
   * scope is loaded the agent refuses to spawn `sqlmap`, `nikto`,
   * `gobuster`, `dirb`, `wfuzz`, `ffuf`, and the noisy `nmap -sV` /
   * `nmap -A` modes — those binaries fingerprint themselves on the
   * wire and most coordinated-disclosure programs forbid them. Setting
   * this to `true` disables that gate (use only when the engagement
   * explicitly permits generic-scanner traffic).
   */
  allowScanners?: boolean;
}

// ── Agent State ──

export interface AgentState {
  messages: AgentMessage[];
  turnCount: number;
  findings: Finding[];
  attackResults: AttackResult[];
  targetInfo: Partial<TargetInfo>;
  done: boolean;
  summary: string;
}

// ── Tool Execution Context ──

export interface ToolContext {
  target: string;
  scanId: string;
  findings: Finding[];
  attackResults: AttackResult[];
  targetInfo: Partial<TargetInfo>;
  scopePath?: string;
  persistFindings?: boolean;
  authConfig?: AuthConfig;
  /**
   * See `AgentConfig.scope`. When present, every URL-touching tool
   * runs `policy.match()` before egress and refuses out-of-scope URLs
   * with `ToolResult.error`.
   */
  scope?: ScopePolicy;
  /** Per-host rate limiter; see AgentConfig.rateLimiter. */
  rateLimiter?: RateLimiter;
  /**
   * See `AgentConfig.allowScanners`. Opt-out for the scanner-binary
   * suppression gate (pwnkit#217). Only consulted when `scope` is set.
   */
  allowScanners?: boolean;
}
