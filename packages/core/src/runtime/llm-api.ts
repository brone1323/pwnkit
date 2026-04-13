import type {
  Runtime,
  NativeRuntime,
  RuntimeConfig,
  RuntimeContext,
  RuntimeResult,
  NativeMessage,
  NativeToolDef,
  NativeRuntimeResult,
  NativeContentBlock,
} from "./types.js";

import { existsSync, readFileSync } from "node:fs";

/** Safely parse JSON tool arguments; returns empty object on malformed input. */
function safeParseJson(raw: string | null | undefined): Record<string, unknown> {
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return { _raw: raw };
  }
}

/**
 * Cache for the resolved Azure region, keyed by base URL. The region is
 * probed once per process (per endpoint) and reused thereafter — see
 * {@link probeAzureRegion}.
 */
const azureRegionCache = new Map<string, string>();

/**
 * Probe the Azure OpenAI endpoint once for its deployment region.
 *
 * Azure surfaces the physical region of a resource in the `x-ms-region`
 * response header (e.g. "eastus2"). The URL itself never reveals this —
 * two `*.openai.azure.com` endpoints can live in completely different
 * geographies — so this probe is the only reliable way to tell an
 * operator which data-residency jurisdiction their traffic lands in.
 *
 * The probe issues a single cheap request to `${baseUrl}/models`, reads
 * the header, and caches the result per base URL for the rest of the
 * process. It never throws: on any failure (network error, HTTP error,
 * missing header) the function resolves to "unknown" so startup logging
 * stays a no-op in adverse conditions.
 *
 * Test hook: `PWNKIT_REGION_OVERRIDE` short-circuits the probe entirely.
 * Set it to force a specific region string without hitting the network —
 * this keeps unit tests and air-gapped CI runs deterministic.
 */
export async function probeAzureRegion(
  baseUrl: string,
  apiKey: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  // PWNKIT_REGION_OVERRIDE: lets tests (and operators running offline)
  // force a specific region string without touching the network.
  const override = process.env.PWNKIT_REGION_OVERRIDE;
  if (override && override.trim().length > 0) {
    return override.trim();
  }

  const cached = azureRegionCache.get(baseUrl);
  if (cached) return cached;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const res = await fetchImpl(`${baseUrl.replace(/\/+$/, "")}/models`, {
      method: "GET",
      headers: { "api-key": apiKey },
      signal: controller.signal,
    }).finally(() => clearTimeout(timer));

    // Azure returns x-ms-region even on 401/403 — the header is set by the
    // front door before authentication, so a missing key still reveals the
    // resource geography. We accept any response that has the header.
    const region = res.headers.get("x-ms-region");
    const resolved = region && region.trim().length > 0
      ? prettyRegion(region.trim())
      : "unknown";
    azureRegionCache.set(baseUrl, resolved);
    return resolved;
  } catch {
    azureRegionCache.set(baseUrl, "unknown");
    return "unknown";
  }
}

/** Convert Azure's lowercase region codes into a human-readable label. */
function prettyRegion(code: string): string {
  const map: Record<string, string> = {
    eastus: "East US",
    eastus2: "East US 2",
    westus: "West US",
    westus2: "West US 2",
    westus3: "West US 3",
    centralus: "Central US",
    northcentralus: "North Central US",
    southcentralus: "South Central US",
    westcentralus: "West Central US",
    canadaeast: "Canada East",
    canadacentral: "Canada Central",
    brazilsouth: "Brazil South",
    northeurope: "North Europe",
    westeurope: "West Europe",
    uksouth: "UK South",
    ukwest: "UK West",
    francecentral: "France Central",
    germanywestcentral: "Germany West Central",
    switzerlandnorth: "Switzerland North",
    norwayeast: "Norway East",
    swedencentral: "Sweden Central",
    polandcentral: "Poland Central",
    italynorth: "Italy North",
    eastasia: "East Asia",
    southeastasia: "Southeast Asia",
    japaneast: "Japan East",
    japanwest: "Japan West",
    koreacentral: "Korea Central",
    australiaeast: "Australia East",
    centralindia: "Central India",
    southindia: "South India",
    uaenorth: "UAE North",
    southafricanorth: "South Africa North",
  };
  return map[code.toLowerCase()] ?? code;
}

/** Reset the region cache. Test-only — do not call from production code. */
export function __resetAzureRegionCacheForTests(): void {
  azureRegionCache.clear();
}

/** Tracks which endpoints we've already printed a startup banner for. */
const loggedProviderStartup = new Set<string>();

function shouldLogProviderStartup(): boolean {
  return process.env.PWNKIT_SUPPRESS_PROVIDER_STARTUP_LOG !== "1";
}

/**
 * Emit a single-line startup banner summarising the resolved provider
 * config. For Azure, also probes and logs the physical region. Runs at
 * most once per (provider, baseUrl) tuple per process.
 *
 * Non-Azure providers are a no-op beyond the provider label — the region
 * only matters when the endpoint sits behind Azure's front door. This is
 * called lazily from the first request on an `LlmApiRuntime` instance to
 * avoid forcing a network probe at module import time.
 */
export async function logProviderStartup(
  provider: ApiProvider,
  providerLabel: string,
  baseUrl: string,
  model: string,
  wireApi: WireApi,
  apiKey: string,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const key = `${provider}:${baseUrl}`;
  if (loggedProviderStartup.has(key)) return;
  loggedProviderStartup.add(key);
  if (!shouldLogProviderStartup()) return;

  if (provider !== "azure") {
    // Non-Azure: brief banner, no region probe.
    console.error(
      `[pwnkit] ${providerLabel} provider initialized\n` +
      `  endpoint: ${baseUrl}\n` +
      `  model: ${model}`,
    );
    return;
  }

  const region = await probeAzureRegion(baseUrl, apiKey, fetchImpl);
  const regionLine = region === "unknown"
    ? "  region: unknown (x-ms-region header absent or probe failed)"
    : `  region: ${region} (probed via x-ms-region header)`;

  console.error(
    `[pwnkit] Azure OpenAI provider initialized\n` +
    `  endpoint: ${baseUrl}\n` +
    `  model: ${model}\n` +
    `${regionLine}\n` +
    `  wire api: ${wireApi}`,
  );
}

/** Reset the startup-banner guard. Test-only. */
export function __resetProviderStartupLogForTests(): void {
  loggedProviderStartup.clear();
}

const DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6";
const DEFAULT_OPENROUTER_MODEL = "anthropic/claude-sonnet-4.6";
const FREE_OPENROUTER_MODEL = "nvidia/nemotron-3-super-120b-a12b:free";
const DEFAULT_OPENAI_MODEL = "gpt-4o";

type ApiProvider = "openrouter" | "anthropic" | "openai" | "azure";
type WireApi = "chat_completions" | "responses";

export interface ApiRuntimeDiagnostics {
  valid: boolean;
  provider: ApiProvider;
  providerLabel: string;
  reason?: "missing_key" | "invalid_config";
  fatalError?: string;
}

function parseCodexAzureConfig(): {
  baseUrl?: string;
  model?: string;
  wireApi?: WireApi;
  reasoningEffort?: string;
} {
  const configPath = `${process.env.HOME ?? ""}/.codex/config.toml`;
  if (!existsSync(configPath)) return {};

  try {
    const content = readFileSync(configPath, "utf8");
    const azureSectionMatch = content.match(/\[model_providers\.azure\]([\s\S]*?)(?:\n\[|$)/);
    const activeProviderMatch = content.match(/^\s*model_provider\s*=\s*"([^"]+)"/m);
    const baseUrlMatch = azureSectionMatch?.[1]?.match(/base_url\s*=\s*"([^"]+)"/);
    const wireApiMatch = azureSectionMatch?.[1]?.match(/wire_api\s*=\s*"([^"]+)"/);
    const azureModelMatch = azureSectionMatch?.[1]?.match(/model\s*=\s*"([^"]+)"/);
    const topLevelModelMatch = content.match(/^\s*model\s*=\s*"([^"]+)"/m);
    const reasoningMatch = content.match(/model_reasoning_effort\s*=\s*"([^"]+)"/);

    return {
      baseUrl: baseUrlMatch?.[1],
      model: azureModelMatch?.[1] ?? (activeProviderMatch?.[1] === "azure" ? topLevelModelMatch?.[1] : undefined),
      wireApi: wireApiMatch?.[1] === "responses" ? "responses" : "chat_completions",
      reasoningEffort: reasoningMatch?.[1],
    };
  } catch {
    return {};
  }
}

/**
 * Detect which API provider to use based on available keys.
 * Priority: OPENROUTER_API_KEY -> ANTHROPIC_API_KEY -> AZURE_OPENAI_API_KEY -> OPENAI_API_KEY
 */
function detectProvider(configApiKey?: string): {
  provider: ApiProvider;
  apiKey: string;
  baseUrl: string;
  defaultModel: string;
  wireApi: WireApi;
  reasoningEffort?: string;
} {
  // If an explicit API key is passed via config, try to guess the provider from the key prefix
  if (configApiKey) {
    if (configApiKey.startsWith("sk-or-")) {
      return {
        provider: "openrouter",
        apiKey: configApiKey,
        baseUrl: "https://openrouter.ai/api/v1",
        defaultModel: DEFAULT_OPENROUTER_MODEL,
        wireApi: "chat_completions",
      };
    }
    if (configApiKey.startsWith("sk-ant-")) {
      return {
        provider: "anthropic",
        apiKey: configApiKey,
        baseUrl: "https://api.anthropic.com",
        defaultModel: DEFAULT_ANTHROPIC_MODEL,
        wireApi: "chat_completions",
      };
    }
    // Assume OpenAI-compatible for other keys
    return {
      provider: "openai",
      apiKey: configApiKey,
      baseUrl: "https://api.openai.com/v1",
      defaultModel: DEFAULT_OPENAI_MODEL,
      wireApi: "chat_completions",
    };
  }

  // Check env vars in priority order
  const openrouterKey = process.env.OPENROUTER_API_KEY;
  if (openrouterKey) {
    return {
      provider: "openrouter",
      apiKey: openrouterKey,
      baseUrl: "https://openrouter.ai/api/v1",
      defaultModel: DEFAULT_OPENROUTER_MODEL,
      wireApi: "chat_completions",
    };
  }

  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  if (anthropicKey) {
    return {
      provider: "anthropic",
      apiKey: anthropicKey,
      baseUrl: process.env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com",
      defaultModel: DEFAULT_ANTHROPIC_MODEL,
      wireApi: "chat_completions",
    };
  }

  const azureKey = process.env.AZURE_OPENAI_API_KEY;
  if (azureKey) {
    const azureConfig = parseCodexAzureConfig();
    return {
      provider: "azure",
      apiKey: azureKey,
      baseUrl: process.env.AZURE_OPENAI_BASE_URL ?? process.env.OPENAI_BASE_URL ?? azureConfig.baseUrl ?? "https://api.openai.com/v1",
      defaultModel: process.env.AZURE_OPENAI_MODEL ?? azureConfig.model ?? DEFAULT_OPENAI_MODEL,
      wireApi: (process.env.AZURE_OPENAI_WIRE_API as WireApi) ?? azureConfig.wireApi ?? "chat_completions",
      reasoningEffort: azureConfig.reasoningEffort,
    };
  }

  const openaiKey = process.env.OPENAI_API_KEY;
  if (openaiKey) {
    return {
      provider: "openai",
      apiKey: openaiKey,
      baseUrl: "https://api.openai.com/v1",
      defaultModel: DEFAULT_OPENAI_MODEL,
      wireApi: "chat_completions",
    };
  }

  // No key found — default to Anthropic (will fail at runtime with helpful message)
  return {
    provider: "anthropic",
    apiKey: "",
    baseUrl: process.env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com",
    defaultModel: DEFAULT_ANTHROPIC_MODEL,
    wireApi: "chat_completions",
  };
}

/**
 * Runtime that calls LLM APIs directly.
 *
 * Supports multiple providers with automatic detection:
 * - OpenRouter (OPENROUTER_API_KEY) — access many models through one API
 * - Anthropic (ANTHROPIC_API_KEY) — direct Claude API access
 * - OpenAI (OPENAI_API_KEY) — direct OpenAI API access
 *
 * Priority: OPENROUTER_API_KEY -> ANTHROPIC_API_KEY -> AZURE_OPENAI_API_KEY -> OPENAI_API_KEY
 *
 * Model can be overridden with PWNKIT_MODEL env var or --model flag.
 *
 * Supports two modes:
 * - Legacy: single-prompt execute() for backward compat with existing agent loop
 * - Native: structured multi-turn messages with tool_use for the new agent loop
 */
export class LlmApiRuntime implements Runtime, NativeRuntime {
  readonly type = "api" as const;
  private config: RuntimeConfig;
  private provider: ApiProvider;
  private apiKey: string;
  private baseUrl: string;
  private model: string;
  private wireApi: WireApi;
  private reasoningEffort?: string;
  private azureConfig: ReturnType<typeof parseCodexAzureConfig>;

  constructor(config: RuntimeConfig) {
    this.config = config;
    this.azureConfig = parseCodexAzureConfig();
    const detected = detectProvider(config.apiKey);
    this.provider = detected.provider;
    this.apiKey = detected.apiKey;
    this.baseUrl = detected.baseUrl;
    this.wireApi = detected.wireApi;
    this.reasoningEffort = process.env.PWNKIT_REASONING_EFFORT ?? detected.reasoningEffort;
    const requestedModel = config.model ?? process.env.PWNKIT_MODEL;
    // "free" is a special alias for the free OpenRouter model
    if (requestedModel === "free" && this.provider === "openrouter") {
      this.model = FREE_OPENROUTER_MODEL;
    } else {
      this.model = requestedModel ?? detected.defaultModel;
    }

    // Fire-and-forget startup banner. For Azure, this probes `/models`
    // once for the x-ms-region header so operators can see where their
    // traffic physically lands (data-residency transparency). The probe
    // is cached and tolerant of failures — never blocks the main path.
    // Skip entirely when no key is configured (the diagnostics path will
    // surface the missing-key error to the user instead).
    if (this.apiKey && !process.env.PWNKIT_SKIP_PROVIDER_BANNER) {
      void logProviderStartup(
        this.provider,
        this.providerLabel,
        this.baseUrl,
        this.model,
        this.wireApi,
        this.apiKey,
      ).catch(() => {
        // Swallow — startup logging must never abort runtime init.
      });
    }
  }

  /** Whether this provider uses OpenAI-compatible chat/completions format. */
  private get isOpenAICompat(): boolean {
    return this.provider === "openrouter" || this.provider === "openai" || this.provider === "azure";
  }

  /** Build the appropriate headers for the configured provider. */
  private buildHeaders(): Record<string, string> {
    if (this.isOpenAICompat) {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (this.provider === "azure") {
        // Azure OpenAI uses api-key header, not Bearer token
        headers["api-key"] = this.apiKey;
      } else {
        headers["Authorization"] = `Bearer ${this.apiKey}`;
      }
      if (this.provider === "openrouter") {
        headers["HTTP-Referer"] = "https://pwnkit.com";
        headers["X-Title"] = "pwnkit Security Scanner";
      }
      return headers;
    }
    // Anthropic
    return {
      "Content-Type": "application/json",
      "x-api-key": this.apiKey,
      "anthropic-version": "2023-06-01",
    };
  }

  /** Build the API endpoint URL. */
  private buildUrl(): string {
    if (this.isOpenAICompat) {
      return `${this.baseUrl}/${this.wireApi === "responses" ? "responses" : "chat/completions"}`;
    }
    return `${this.baseUrl}/v1/messages`;
  }

  /** Friendly provider name for error messages. */
  private get providerLabel(): string {
    switch (this.provider) {
      case "openrouter": return "OpenRouter";
      case "anthropic": return "Anthropic";
      case "openai": return "OpenAI";
      case "azure": return "Azure OpenAI";
    }
  }

  private noKeyError(): string {
    return (
      "No API key found. Set one of:\n" +
      "  export OPENROUTER_API_KEY=sk-or-...   (OpenRouter — many models, one key)\n" +
      "  export ANTHROPIC_API_KEY=sk-ant-...    (Anthropic — direct Claude access)\n" +
      "  export AZURE_OPENAI_API_KEY=...        (Azure OpenAI — reuse your Codex Azure provider)\n" +
      "  export OPENAI_API_KEY=sk-...           (OpenAI — direct GPT access)"
    );
  }

  getConfigurationDiagnostics(): ApiRuntimeDiagnostics {
    if (!this.apiKey) {
      return {
        valid: false,
        provider: this.provider,
        providerLabel: this.providerLabel,
        reason: "missing_key",
        fatalError: this.noKeyError(),
      };
    }

    if (this.provider !== "azure") {
      return {
        valid: true,
        provider: this.provider,
        providerLabel: this.providerLabel,
      };
    }

    const hasConfiguredBaseUrl = !!(
      process.env.AZURE_OPENAI_BASE_URL ||
      process.env.OPENAI_BASE_URL ||
      this.azureConfig.baseUrl
    );
    const hasConfiguredModel = !!(
      this.config.model ||
      process.env.PWNKIT_MODEL ||
      process.env.AZURE_OPENAI_MODEL ||
      this.azureConfig.model
    );

    const missing: string[] = [];
    if (!hasConfiguredBaseUrl) {
      missing.push("AZURE_OPENAI_BASE_URL (or [model_providers.azure].base_url in ~/.codex/config.toml)");
    }
    if (!hasConfiguredModel) {
      missing.push("AZURE_OPENAI_MODEL or an Azure-backed `model = \"...\"` in ~/.codex/config.toml");
    }

    if (missing.length > 0) {
      return {
        valid: false,
        provider: this.provider,
        providerLabel: this.providerLabel,
        reason: "invalid_config",
        fatalError:
          "Azure OpenAI runtime is selected, but the configuration is incomplete.\n" +
          `Missing: ${missing.join("; ")}\n` +
          "pwnkit will not guess Azure defaults because that can silently route to the wrong endpoint or deployment.",
      };
    }

    return {
      valid: true,
      provider: this.provider,
      providerLabel: this.providerLabel,
    };
  }

  // ── Legacy Runtime interface (single-prompt) ──

  async execute(
    prompt: string,
    context?: RuntimeContext,
  ): Promise<RuntimeResult> {
    const start = Date.now();

    if (!this.apiKey) {
      return {
        output: "",
        exitCode: 1,
        timedOut: false,
        durationMs: Date.now() - start,
        error: this.noKeyError(),
      };
    }

    const systemPrompt = context?.systemPrompt ?? "";

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.config.timeout || 120_000,
    );

    try {
      let res: Response;

      if (this.isOpenAICompat && this.wireApi === "chat_completions") {
        // OpenRouter / OpenAI / Azure chat completions format
        const messages: Array<Record<string, string>> = [];
        if (systemPrompt) {
          messages.push({ role: "system", content: systemPrompt });
        }
        messages.push({ role: "user", content: prompt });

        res = await fetch(this.buildUrl(), {
          method: "POST",
          headers: this.buildHeaders(),
          body: JSON.stringify({
            model: this.model,
            max_tokens: 8192,
            messages,
          }),
          signal: controller.signal,
        });
      } else if (this.isOpenAICompat && this.wireApi === "responses") {
        // Azure Responses API format
        const input: Array<Record<string, unknown>> = [];
        if (systemPrompt) {
          input.push({
            role: "system",
            content: [{ type: "input_text", text: systemPrompt }],
          });
        }
        input.push({
          role: "user",
          content: [{ type: "input_text", text: prompt }],
        });

        res = await fetch(this.buildUrl(), {
          method: "POST",
          headers: this.buildHeaders(),
          body: JSON.stringify({
            model: this.model,
            input,
            max_output_tokens: 8192,
          }),
          signal: controller.signal,
        });
      } else {
        // Anthropic Messages API format
        res = await fetch(this.buildUrl(), {
          method: "POST",
          headers: this.buildHeaders(),
          body: JSON.stringify({
            model: this.model,
            max_tokens: 8192,
            ...(systemPrompt ? { system: systemPrompt } : {}),
            messages: [{ role: "user", content: prompt }],
          }),
          signal: controller.signal,
        });
      }

      clearTimeout(timer);

      const body = await res.text();

      if (!res.ok) {
        return {
          output: "",
          exitCode: 1,
          timedOut: false,
          durationMs: Date.now() - start,
          error: `${this.providerLabel} API error ${res.status}: ${body.slice(0, 500)}`,
        };
      }

      const json = JSON.parse(body);

      // Extract text from response (different formats)
      let text: string;
      if (this.isOpenAICompat && this.wireApi === "chat_completions") {
        const msg = json.choices?.[0]?.message;
        // Some models (reasoning models) return content: null with reasoning field
        text = msg?.content ?? msg?.reasoning ?? "";
      } else if (this.isOpenAICompat && this.wireApi === "responses") {
        text =
          typeof json.output_text === "string" && json.output_text.trim()
            ? json.output_text
            : Array.isArray(json.output)
              ? json.output
                  .flatMap((item: Record<string, unknown>) => Array.isArray(item.content) ? item.content : [])
                  .filter((block: Record<string, unknown>) => block.type === "output_text")
                  .map((block: Record<string, unknown>) => String(block.text ?? ""))
                  .join("\n")
              : "";
      } else {
        text =
          json.content
            ?.filter((b: { type: string }) => b.type === "text")
            .map((b: { text: string }) => b.text)
            .join("\n") ?? "";
      }

      return {
        output: text,
        exitCode: 0,
        timedOut: false,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      clearTimeout(timer);
      const msg = err instanceof Error ? err.message : String(err);
      const timedOut = msg.includes("abort") || msg.includes("timeout");
      return {
        output: "",
        exitCode: 1,
        timedOut,
        durationMs: Date.now() - start,
        error: timedOut
          ? `${this.providerLabel} API request timed out`
          : `${this.providerLabel} API error: ${msg}`,
      };
    }
  }

  // ── Native Runtime interface (structured messages + tool_use) ──

  async executeNative(
    system: string,
    messages: NativeMessage[],
    tools: NativeToolDef[],
  ): Promise<NativeRuntimeResult> {
    const start = Date.now();

    if (!this.apiKey) {
      return {
        content: [{ type: "text", text: "" }],
        stopReason: "error",
        durationMs: Date.now() - start,
        error: this.noKeyError(),
      };
    }

    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.config.timeout || 120_000,
    );

    try {
      let res: Response;

      if (this.isOpenAICompat && this.wireApi === "chat_completions") {
        // Convert to OpenAI chat completions format
        const chatMessages: Array<Record<string, unknown>> = [];
        chatMessages.push({ role: "system", content: system });

        for (const m of messages) {
          for (const block of m.content) {
            if (block.type === "text") {
              chatMessages.push({ role: m.role, content: block.text });
            } else if (block.type === "tool_use") {
              chatMessages.push({
                role: "assistant",
                content: null,
                tool_calls: [{
                  id: block.id,
                  type: "function",
                  function: { name: block.name, arguments: JSON.stringify(block.input) },
                }],
              });
            } else if (block.type === "tool_result") {
              chatMessages.push({
                role: "tool",
                tool_call_id: block.tool_use_id,
                content: block.content,
              });
            }
          }
        }

        const body: Record<string, unknown> = {
          model: this.model,
          max_tokens: 8192,
          messages: chatMessages,
        };

        if (tools.length > 0) {
          body.tools = tools.map((t) => ({
            type: "function",
            function: {
              name: t.name,
              description: t.description,
              parameters: t.input_schema,
            },
          }));
        }

        res = await fetch(this.buildUrl(), {
          method: "POST",
          headers: this.buildHeaders(),
          body: JSON.stringify(body),
          signal: controller.signal,
        });
      } else if (this.isOpenAICompat && this.wireApi === "responses") {
        // Responses API uses a flat list of items, not role-based messages.
        // function_call and function_call_output are top-level items, not nested
        // inside content arrays. See: developers.openai.com/docs/api-reference/responses
        const input: Array<Record<string, unknown>> = [
          {
            role: "system",
            content: [{ type: "input_text", text: system }],
          },
        ];

        for (const m of messages) {
          // Collect text blocks into a role-based message. The OpenAI Responses
          // API distinguishes text content by producer: user/system/developer
          // roles use `input_text`, but the assistant role must use
          // `output_text` (or `refusal`). Sending `input_text` on an assistant
          // message yields a 400 on Azure with:
          //   "Invalid value: 'input_text'. Supported values are:
          //    'output_text' and 'refusal'."
          // The agent loop replays the assistant's prior text replies on every
          // turn, so this bug used to kill every multi-turn scan on Azure
          // starting at turn 2 — the error was misdiagnosed as a "max turns
          // without completion" because each retry failed with the same 400.
          const assistantText = m.role === "assistant";
          const textType = assistantText ? "output_text" : "input_text";
          const textBlocks: Array<Record<string, unknown>> = [];
          for (const block of m.content) {
            if (block.type === "text") {
              textBlocks.push({ type: textType, text: block.text });
            } else if (block.type === "tool_use") {
              // Flush any pending text blocks first
              if (textBlocks.length > 0) {
                input.push({ role: m.role, content: [...textBlocks] });
                textBlocks.length = 0;
              }
              // Assistant tool_use → top-level function_call item
              input.push({
                type: "function_call",
                call_id: block.id,
                name: block.name,
                arguments: JSON.stringify(block.input),
              });
            } else if (block.type === "tool_result") {
              // Flush any pending text blocks first
              if (textBlocks.length > 0) {
                input.push({ role: m.role, content: [...textBlocks] });
                textBlocks.length = 0;
              }
              // Tool result → top-level function_call_output item
              input.push({
                type: "function_call_output",
                call_id: block.tool_use_id,
                output: block.content,
              });
            }
          }
          // Flush remaining text blocks
          if (textBlocks.length > 0) {
            input.push({ role: m.role, content: textBlocks });
          }
        }

        const body: Record<string, unknown> = {
          model: this.model,
          input,
          max_output_tokens: 8192,
          ...(this.reasoningEffort ? { reasoning: { effort: this.reasoningEffort } } : {}),
        };

        if (tools.length > 0) {
          body.tools = tools.map((t) => ({
            type: "function",
            name: t.name,
            description: t.description,
            parameters: t.input_schema,
          }));
        }

        res = await fetch(this.buildUrl(), {
          method: "POST",
          headers: this.buildHeaders(),
          body: JSON.stringify(body),
          signal: controller.signal,
        });
      } else {
        // Anthropic Messages API format
        const apiMessages = messages.map((m) => ({
          role: m.role,
          content: m.content.map((block) => {
            if (block.type === "text") return { type: "text", text: block.text };
            if (block.type === "tool_use") {
              return { type: "tool_use", id: block.id, name: block.name, input: block.input };
            }
            if (block.type === "tool_result") {
              return {
                type: "tool_result",
                tool_use_id: block.tool_use_id,
                content: block.content,
                ...(block.is_error ? { is_error: true } : {}),
              };
            }
            return block;
          }),
        }));

        const body: Record<string, unknown> = {
          model: this.model,
          max_tokens: 8192,
          system,
          messages: apiMessages,
        };

        if (tools.length > 0) {
          body.tools = tools;
        }

        res = await fetch(this.buildUrl(), {
          method: "POST",
          headers: this.buildHeaders(),
          body: JSON.stringify(body),
          signal: controller.signal,
        });
      }

      clearTimeout(timer);

      const responseText = await res.text();

      if (!res.ok) {
        return {
          content: [{ type: "text", text: "" }],
          stopReason: "error",
          durationMs: Date.now() - start,
          error: `${this.providerLabel} API error ${res.status}: ${responseText.slice(0, 500)}`,
        };
      }

      const json = JSON.parse(responseText);

      // Parse response into unified content blocks
      let content: NativeContentBlock[];
      let stopReason: "end_turn" | "tool_use" | "max_tokens" | "error";
      let usage: { inputTokens: number; outputTokens: number } | undefined;

      if (this.isOpenAICompat && this.wireApi === "chat_completions") {
        const choice = json.choices?.[0];
        const msg = choice?.message;
        content = [];

        // Handle reasoning models that return content: null with reasoning field
        const textContent = msg?.content ?? msg?.reasoning;
        if (textContent) {
          content.push({ type: "text", text: textContent });
        }
        if (msg?.tool_calls) {
          for (const tc of msg.tool_calls) {
            content.push({
              type: "tool_use",
              id: tc.id,
              name: tc.function.name,
              input: safeParseJson(tc.function.arguments),
            });
          }
        }

        const finishReason = choice?.finish_reason;
        stopReason =
          finishReason === "tool_calls" || finishReason === "function_call"
            ? "tool_use"
            : finishReason === "length"
              ? "max_tokens"
              : "end_turn";

        if (json.usage) {
          usage = {
            inputTokens: json.usage.prompt_tokens ?? 0,
            outputTokens: json.usage.completion_tokens ?? 0,
          };
        }
      } else if (this.isOpenAICompat && this.wireApi === "responses") {
        content = [];
        for (const item of json.output ?? []) {
          if (item.type === "function_call") {
            content.push({
              type: "tool_use",
              id: item.call_id as string,
              name: item.name as string,
              input: safeParseJson(item.arguments as string),
            });
            continue;
          }

          for (const block of item.content ?? []) {
            if (block.type === "output_text") {
              content.push({ type: "text", text: block.text as string });
            }
          }
        }

        stopReason = content.some((block) => block.type === "tool_use") ? "tool_use" : "end_turn";

        if (json.usage) {
          usage = {
            inputTokens: json.usage.input_tokens ?? 0,
            outputTokens: json.usage.output_tokens ?? 0,
          };
        }
      } else {
        // Anthropic format
        content = (json.content ?? []).map(
          (block: Record<string, unknown>) => {
            if (block.type === "text") {
              return { type: "text", text: block.text as string };
            }
            if (block.type === "tool_use") {
              return {
                type: "tool_use",
                id: block.id as string,
                name: block.name as string,
                input: block.input as Record<string, unknown>,
              };
            }
            return { type: "text", text: JSON.stringify(block) };
          },
        );

        stopReason = json.stop_reason === "tool_use" ? "tool_use" as const
          : json.stop_reason === "max_tokens" ? "max_tokens" as const
          : "end_turn" as const;

        if (json.usage) {
          usage = {
            inputTokens: json.usage.input_tokens ?? 0,
            outputTokens: json.usage.output_tokens ?? 0,
          };
        }
      }

      return {
        content,
        stopReason,
        usage,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      clearTimeout(timer);
      const msg = err instanceof Error ? err.message : String(err);
      const timedOut = msg.includes("abort") || msg.includes("timeout");
      return {
        content: [{ type: "text", text: "" }],
        stopReason: "error",
        durationMs: Date.now() - start,
        error: timedOut
          ? `${this.providerLabel} API request timed out`
          : `${this.providerLabel} API error: ${msg}`,
      };
    }
  }

  async isAvailable(): Promise<boolean> {
    return !!this.apiKey;
  }
}
