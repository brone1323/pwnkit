---
title: Configuration
description: Runtime modes, scan modes, depth settings, and environment options.
---

pwnkit is designed for zero-config usage, but every default can be overridden via CLI flags or environment variables.

## Runtime modes

pwnkit is an agentic harness — bring your own AI. The `--runtime` flag controls which LLM backend powers the agents.

| Runtime | Flag | Description |
|---------|------|-------------|
| `api` | `--runtime api` | Uses your API key (OpenRouter, Anthropic, OpenAI). Best for CI and quick scans. **Default.** |
| `claude` | `--runtime claude` | Spawns the Claude Code CLI with your existing subscription. Best for deep analysis. |
| `codex` | `--runtime codex` | Spawns the Codex CLI. Best for source-level analysis. |
| `gemini` | `--runtime gemini` | Spawns the Gemini CLI. Best for large-context source analysis. |
| `auto` | `--runtime auto` | Auto-detects installed CLIs and picks the best one per pipeline stage. |

### API runtime

The default `api` runtime makes direct HTTP calls to an LLM provider. It requires one of these environment variables:

```bash
export OPENROUTER_API_KEY="sk-or-..."   # Recommended
export ANTHROPIC_API_KEY="sk-ant-..."
export AZURE_OPENAI_API_KEY="..."
export OPENAI_API_KEY="sk-..."
```

See [API Keys](/api-keys/) for the full priority order and provider details.

### CLI runtimes (claude, codex, gemini)

These runtimes spawn the respective CLI tool as a subprocess. You must have the CLI installed and authenticated:

```bash
# Claude Code CLI
npm i -g @anthropic-ai/claude-code

# Codex CLI
npm i -g @openai/codex

# Gemini CLI
npm i -g @google/gemini-cli
```

Then use them:

```bash
npx pwnkit-cli scan --target https://api.example.com/chat --runtime claude
npx pwnkit-cli review ./my-repo --runtime codex --depth deep
```

## Scan modes

The `--mode` flag controls what kind of target is being scanned.

| Mode | Description |
|------|-------------|
| `llm` | Probe AI/LLM apps with prompt injection, jailbreaks, exfiltration, and tool poisoning attacks. **Default for `scan`.** |
| `web` | Shell-first autonomous pentesting for web applications. The agent uses `bash` (curl, python3, bash) as its primary tool to probe for CORS, headers, exposed files, SSRF, XSS, SQLi, SSTI, and more. |
| `mcp` | Scan MCP (Model Context Protocol) servers for tool poisoning and schema abuse. *(Coming soon)* |

```bash
# LLM API scan (default)
npx pwnkit-cli scan --target https://api.example.com/chat

# Web app scan
npx pwnkit-cli scan --target https://example.com --mode web
```

## Depth settings

The `--depth` flag controls how thorough the scan is.

| Depth | Test Cases | Typical Time | Best For |
|-------|-----------|-------------|----------|
| `quick` | ~15 | ~1 min | CI pipelines, smoke tests |
| `default` | ~50 | ~3 min | Day-to-day scanning |
| `deep` | ~150 | ~10 min | Pre-launch audits, thorough review |

```bash
npx pwnkit-cli scan --target https://api.example.com/chat --depth quick
npx pwnkit-cli audit express --depth deep
npx pwnkit-cli review ./my-repo --depth deep --runtime claude
```

## Output formats

pwnkit supports multiple output formats:

| Format | Description |
|--------|-------------|
| `json` | Machine-readable JSON output for pipelines |
| `sarif` | SARIF format for the GitHub Security tab |
| `markdown` | Human-readable Markdown report |

In CI (GitHub Action), set `format: sarif` to populate the Security tab:

```yaml
- uses: peaktwilight/pwnkit@main
  with:
    mode: review
    path: .
    format: sarif
```

## Diff-aware review

For PR workflows, review only changed files against a base branch:

```bash
npx pwnkit-cli review ./my-repo --diff-base origin/main --changed-only
```

This is particularly useful in CI to avoid scanning the entire codebase on every PR.

## Verbose output

Use `--verbose` to see the animated attack replay and detailed agent reasoning:

```bash
npx pwnkit-cli scan --target https://api.example.com/chat --verbose
```

## Feature flags

pwnkit ships a set of agent-improvement features behind environment-variable flags so you can A/B test them and opt in/out per run. Every flag is read at process start; set `<FLAG>=0` or `<FLAG>=false` to disable, anything else to enable.

| Flag | Default | What it enables |
|------|---------|-----------------|
| `PWNKIT_FEATURE_EARLY_STOP` | **on** | Early-stop at 50% budget if no findings, then retry with a different strategy. |
| `PWNKIT_FEATURE_LOOP_DETECTION` | **on** | Detects A-A-A and A-B-A-B action loops, injects a warning to break the cycle. |
| `PWNKIT_FEATURE_CONTEXT_COMPACTION` | **on** | Compresses middle-of-conversation messages when the context exceeds 30k tokens. |
| `PWNKIT_FEATURE_SCRIPT_TEMPLATES` | **on** | Adds exploit-script templates (blind SQLi, SSTI, auth chain) to the shell prompt. |
| `PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS` | off | Injects technology-specific vulnerability playbooks after the recon phase. |
| `PWNKIT_FEATURE_EXTERNAL_MEMORY` | off | Agent writes plan/creds to disk, re-injected at reflection checkpoints. |
| `PWNKIT_FEATURE_PROGRESS_HANDOFF` | off | Injects prior-attempt findings when retrying, so retries don't restart from zero. |
| `PWNKIT_FEATURE_WEB_SEARCH` | off | Lets the agent search the web for CVE details, vendor docs, and technique references. |
| `PWNKIT_FEATURE_DOCKER_EXECUTOR` | off | Runs every bash command inside a Kali Linux container with the full pentesting toolchain. |
| `PWNKIT_FEATURE_PTY_SESSION` | off | Interactive PTY sessions for exploits requiring interactivity (reverse shells, DB clients, SSH). |
| `PWNKIT_FEATURE_EGATS` | off | Evidence-Gated Attack Tree Search — beam search over a hypothesis tree. Also toggled by `--egats`. |
| `PWNKIT_FEATURE_CONSENSUS_VERIFY` | off | Self-consistency voting: runs the verify pipeline N times and takes the majority vote. |
| `PWNKIT_FEATURE_DEBATE` | off | Adversarial debate: prosecutor vs. defender agents argue each finding, a skeptical judge decides. |
| `PWNKIT_FEATURE_MULTIMODAL` | off | Cross-validates findings against foxguard (Rust pattern scanner). |
| `PWNKIT_FEATURE_REACHABILITY_GATE` | off | Suppresses findings whose sink is not reachable from an application entry point. |
| `PWNKIT_FEATURE_POV_GATE` | off | Requires a working executable PoC per finding, otherwise downgrades to `info`. |
| `PWNKIT_FEATURE_TRIAGE_MEMORIES` | off | Injects Semgrep-style per-target persistent FP memories into the verify pipeline. Pairs with `pwnkit-cli triage`. |

### Example: maximum-accuracy pentest

Turn on every false-positive reduction feature for a client-ready scan:

```bash
export PWNKIT_FEATURE_CONSENSUS_VERIFY=1
export PWNKIT_FEATURE_REACHABILITY_GATE=1
export PWNKIT_FEATURE_POV_GATE=1
export PWNKIT_FEATURE_TRIAGE_MEMORIES=1
export PWNKIT_FEATURE_MULTIMODAL=1

npx pwnkit-cli scan --target https://example.com --mode web --depth deep
```

### Example: Kali toolchain + web search

```bash
export PWNKIT_FEATURE_DOCKER_EXECUTOR=1
export PWNKIT_FEATURE_WEB_SEARCH=1

npx pwnkit-cli scan --target https://example.com --mode web
```
