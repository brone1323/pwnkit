/** Approximate cost per 1M tokens by provider/model */
const PRICING: Record<string, { input: number; output: number }> = {
  // OpenAI
  "gpt-5.4": { input: 2.50, output: 10.00 },
  "gpt-4o": { input: 2.50, output: 10.00 },
  "gpt-4o-mini": { input: 0.15, output: 0.60 },
  "gpt-4.1": { input: 2.00, output: 8.00 },
  "gpt-4.1-mini": { input: 0.40, output: 1.60 },
  "gpt-4.1-nano": { input: 0.10, output: 0.40 },
  "o3": { input: 2.00, output: 8.00 },
  "o3-mini": { input: 1.10, output: 4.40 },
  "o4-mini": { input: 1.10, output: 4.40 },
  // Anthropic
  "claude-opus-4-6": { input: 15.00, output: 75.00 },
  "claude-sonnet-4-6": { input: 3.00, output: 15.00 },
  "claude-haiku-4-5": { input: 0.80, output: 4.00 },
  // Google
  "gemini-2.5-pro": { input: 1.25, output: 10.00 },
  "gemini-2.5-flash": { input: 0.15, output: 0.60 },
  "gemini-2.0-flash": { input: 0.10, output: 0.40 },
  // DeepSeek
  "deepseek-chat": { input: 0.27, output: 1.10 },
  "deepseek-reasoner": { input: 0.55, output: 2.19 },
  // Meta (hosted)
  "llama-4-maverick": { input: 0.50, output: 0.77 },
  "llama-4-scout": { input: 0.20, output: 0.35 },
  // Mistral
  "mistral-large": { input: 2.00, output: 6.00 },
  "mistral-small": { input: 0.10, output: 0.30 },
  default: { input: 3.00, output: 15.00 },
};

/** Known vendor prefixes to strip (e.g. "openai/gpt-4o" -> "gpt-4o") */
function normalizeModel(model: string): string {
  const prefixes = ["openai/", "anthropic/", "google/", "deepseek/", "meta/", "mistral/"];
  for (const p of prefixes) {
    if (model.startsWith(p)) return model.slice(p.length);
  }
  return model;
}

export function estimateCost(
  usage: { inputTokens: number; outputTokens: number },
  model?: string,
): number {
  const key = model ? normalizeModel(model) : "";
  const rates = PRICING[key] ?? (() => {
    if (model) console.warn(`[pwnkit] Unknown model for cost estimation: ${model}`);
    return PRICING.default;
  })();
  return (
    (usage.inputTokens / 1_000_000) * rates.input +
    (usage.outputTokens / 1_000_000) * rates.output
  );
}
