---
title: API Keys
description: Supported LLM providers, environment variables, and priority order.
---

pwnkit's `api` runtime (the default) makes direct HTTP calls to an LLM provider. You need to set an API key as an environment variable.

## Supported providers

| Provider | Environment Variable | Notes |
|----------|---------------------|-------|
| **OpenRouter** | `OPENROUTER_API_KEY` | Recommended. One key, access to many models (Claude, GPT-4, Llama, Mistral, and more). Includes free-tier models. Get a key at [openrouter.ai](https://openrouter.ai). |
| **Anthropic** | `ANTHROPIC_API_KEY` | Direct access to Claude models. Get a key at [console.anthropic.com](https://console.anthropic.com). |
| **Azure OpenAI** | `AZURE_OPENAI_API_KEY` | Azure-hosted OpenAI models. See [Azure configuration](#azure-openai-configuration) below for additional settings. |
| **OpenAI** | `OPENAI_API_KEY` | Direct access to GPT models. Get a key at [platform.openai.com](https://platform.openai.com). |

## Priority order

When multiple API keys are set, pwnkit uses this priority:

1. `OPENROUTER_API_KEY` (highest priority)
2. `ANTHROPIC_API_KEY`
3. `AZURE_OPENAI_API_KEY`
4. `OPENAI_API_KEY` (lowest priority)

Only one key is needed. If you set multiple, the highest-priority one is used.

## Setting your key

### macOS / Linux

```bash
# Add to your shell profile (~/.zshrc, ~/.bashrc, etc.)
export OPENROUTER_API_KEY="sk-or-v1-..."
```

Then reload your shell or run `source ~/.zshrc`.

### GitHub Actions

Add the key as a repository secret, then reference it in your workflow:

```yaml
- uses: PwnKit-Labs/pwnkit@main
  with:
    mode: review
    path: .
  env:
    OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
```

### Why OpenRouter is recommended

OpenRouter acts as a unified gateway to many LLM providers. Benefits:

- **One key, many models** — access Claude, GPT-4, Llama, Mistral, and others
- **Free-tier models available** — useful for testing and CI
- **Automatic fallback** — if one provider is down, OpenRouter can route to another
- **Usage dashboard** — track costs across all models in one place

## Azure OpenAI configuration

Azure OpenAI is stricter than the other providers. The API key alone is not enough. pwnkit needs:

- an Azure base URL
- an Azure deployment/model name

You can provide those explicitly via env vars, or let pwnkit reuse them from `~/.codex/config.toml` when Codex is already configured against Azure.

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_OPENAI_API_KEY` | Yes | Your Azure OpenAI API key |
| `AZURE_OPENAI_BASE_URL` | Yes, unless pwnkit can read it from Codex config | Base URL for your Azure deployment. For the Responses API this should include `/openai/v1`. |
| `AZURE_OPENAI_MODEL` | Yes, unless pwnkit can read it from Codex config | Azure deployment/model name (not just a generic model family string) |
| `AZURE_OPENAI_WIRE_API` | No | Wire API format: `chat_completions` (default) or `responses` |

```bash
export AZURE_OPENAI_API_KEY="your-azure-key"
export AZURE_OPENAI_BASE_URL="https://your-resource.openai.azure.com/openai/v1"
export AZURE_OPENAI_MODEL="gpt-4o"
export AZURE_OPENAI_WIRE_API="responses"
```

If you rely on Codex config instead of env vars, make sure `~/.codex/config.toml` points at Azure and contains a usable Azure base URL plus model/deployment. If the selected Azure runtime is incomplete, pwnkit stops immediately with a configuration error instead of silently falling through to a broken scan.

## Alternative: CLI runtimes

If you prefer not to use API keys at all, you can use the CLI runtimes instead. These use your existing subscription to Claude, Codex, or Gemini:

```bash
# Use Claude Code CLI (requires Claude subscription)
pwnkit scan --target https://api.example.com/chat --runtime claude

# Use Codex CLI
pwnkit review ./my-repo --runtime codex

# Use Gemini CLI
pwnkit review ./my-repo --runtime gemini
```

No API key environment variable is needed for CLI runtimes — authentication is handled by the respective CLI tool.
