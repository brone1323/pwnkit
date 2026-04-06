---
title: Getting Started
description: Install pwnkit, set up your API key, and run your first scan.
---

pwnkit is a general-purpose autonomous pentesting framework. It scans AI/LLM apps, web applications, REST/OpenAPI APIs, npm packages, and source code using an agentic pipeline that discovers, attacks, verifies, and reports — with blind verification to kill false positives. It ships as an npm package. You can run it directly with `npx` or install it globally.

## Installation

```bash
# Run directly (no install)
npx pwnkit-cli scan --target https://your-app.com/api/chat

# Or install globally
npm i -g pwnkit-cli
```

**Requirements:** Node.js 20+ and pnpm 8+ (for development).

## Set up an API key

pwnkit needs an LLM provider to power its agentic pipeline. Set one of these environment variables:

```bash
# Recommended — one key, many models
export OPENROUTER_API_KEY="sk-or-..."

# Or use a direct provider
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
```

pwnkit checks for keys in this order: **OpenRouter > Anthropic > Azure OpenAI > OpenAI**. For Azure, you can also set `AZURE_OPENAI_BASE_URL`, `AZURE_OPENAI_MODEL`, and `AZURE_OPENAI_WIRE_API` for full control. If no API keys are set, the `api` runtime will not work, but you can still use `--runtime claude`, `--runtime codex`, or `--runtime gemini` if those CLIs are installed and authenticated.

See [API Keys](/api-keys/) for full details on supported providers.

## Your first scan

### Scan an LLM API

```bash
npx pwnkit-cli scan --target https://your-app.com/api/chat
```

This discovers the attack surface, launches targeted attacks (prompt injection, jailbreaks, data exfiltration), verifies every finding, and generates a report — typically in under 5 minutes.

### Scan a web application

```bash
npx pwnkit-cli scan --target https://your-app.com --mode web
```

Runs autonomous pentesting against a web application using a shell-first approach. The agent gets `bash` as its primary tool and uses curl, python3, bash pipelines, and standard pentesting utilities to probe for CORS misconfigurations, exposed files, SSRF, XSS, SQL injection, SSTI, and other traditional web vulnerabilities. See [Architecture](/architecture/) for why shell-first beats structured tools.

### Audit an npm package

```bash
npx pwnkit-cli audit lodash
```

Installs the package in a sandbox, runs static analysis (semgrep), and performs an AI-powered code review.

### Review a codebase

```bash
# Local directory
npx pwnkit-cli review ./my-app

# GitHub URL (clones automatically)
npx pwnkit-cli review https://github.com/user/repo
```

### Auto-detect

You can skip the subcommand entirely. pwnkit figures out what to do:

```bash
pwnkit-cli express              # audits npm package
pwnkit-cli ./my-repo            # reviews source code
pwnkit-cli https://github.com/user/repo  # clones and reviews
pwnkit-cli https://example.com/api/chat  # scans LLM API
pwnkit-cli https://example.com --mode web  # pentests web app
```

## Scan depth

Control how thorough the scan is:

| Depth     | Test Cases | Time     |
|-----------|-----------|----------|
| `quick`   | ~15       | ~1 min   |
| `default` | ~50       | ~3 min   |
| `deep`    | ~150      | ~10 min  |

```bash
# Quick scan for CI
npx pwnkit-cli scan --target https://api.example.com/chat --depth quick

# Deep audit before launch
npx pwnkit-cli scan --target https://api.example.com/chat --depth deep
```

## Common scenarios

### Scan a REST API with an OpenAPI spec

Point pwnkit at an OpenAPI 3.x or Swagger 2.0 document and it will pre-load every endpoint, parameter schema, and auth requirement before attacking — no crawl phase needed.

```bash
npx pwnkit-cli scan \
  --target https://api.example.com \
  --api-spec ./openapi.yaml \
  --mode web
```

### Authenticated scanning (login-protected app)

Use `--auth` to pass credentials. Four types are supported: `bearer`, `cookie`, `basic`, and `header`.

```bash
# Bearer token (OAuth / JWT)
npx pwnkit-cli scan --target https://app.example.com \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Session cookie
npx pwnkit-cli scan --target https://app.example.com \
  --auth '{"type":"cookie","value":"session=abc123"}'

# Custom header (API key)
npx pwnkit-cli scan --target https://api.example.com \
  --auth '{"type":"header","name":"X-API-Key","value":"sk_live_..."}'

# Or load from a file to avoid leaking to shell history
npx pwnkit-cli scan --target https://app.example.com --auth ./auth.json
```

### Multi-model ensemble via OpenRouter

Set `OPENROUTER_API_KEY` and pass `--model` to mix models across runs. OpenRouter gives you access to Claude, GPT-4, Gemini, Llama, DeepSeek, and more with one key.

```bash
export OPENROUTER_API_KEY="sk-or-..."

# Use Claude Sonnet for hard targets
npx pwnkit-cli scan --target https://example.com --mode web \
  --model anthropic/claude-sonnet-4-5

# Cheap and fast for CI
npx pwnkit-cli scan --target https://example.com --mode web \
  --model deepseek/deepseek-chat --depth quick
```

### Best-of-N strategy racing

Spawn 5 attack agents in parallel and let the fastest one win. Great for hard targets where a linear attack plan gets stuck.

```bash
npx pwnkit-cli scan --target https://example.com --mode web --race
```

### Kali Docker executor

Enable `PWNKIT_FEATURE_DOCKER_EXECUTOR=1` to run every bash command inside a Kali Linux container with the full pentesting toolset (nmap, sqlmap, nikto, gobuster, ffuf, hydra, etc.) already installed. No host pollution, reproducible tool versions.

```bash
export PWNKIT_FEATURE_DOCKER_EXECUTOR=1
npx pwnkit-cli scan --target https://example.com --mode web --verbose
```

### Export findings to GitHub Issues

Push every confirmed finding to a GitHub repo as a labelled issue with evidence and reproduction steps. Requires a `GITHUB_TOKEN` with `repo` scope.

```bash
export GITHUB_TOKEN="ghp_..."
npx pwnkit-cli scan --target https://example.com --mode web \
  --export github:myorg/myrepo
```

### Generate an HTML or Markdown report

```bash
# HTML (auto-opens in browser)
npx pwnkit-cli scan --target https://example.com --mode web \
  --depth deep \
  --format html

# Markdown (printed to stdout; pipe to a file)
npx pwnkit-cli scan --target https://example.com --mode web \
  --depth deep \
  --format md > example-pentest.md
```

## Next steps

- [Commands](/commands/) — full reference for every CLI command
- [Configuration](/configuration/) — runtime modes, feature flags, and options
- [Recipes](/recipes/) — real-world scan recipes for common scenarios
- [Architecture](/architecture/) — how the 4-stage pipeline works
