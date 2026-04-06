---
title: Features
description: Comprehensive feature list for pwnkit, organized by category.
---

pwnkit is a fully autonomous agentic pentesting framework. This page is a
complete, category-organized inventory of what ships in the current release.
For deep dives, follow the linked pages.

## Target coverage

| Target | Command | What pwnkit finds |
|--------|---------|-------------------|
| Web apps | `scan --target <url> --mode web` | SQLi, IDOR, SSTI, XSS, auth bypass, SSRF, LFI, RCE, file upload, deserialization, request smuggling |
| AI / LLM apps | `scan --target <url>` | Prompt injection, jailbreaks, system-prompt extraction, PII leakage, MCP tool abuse |
| npm packages | `audit <pkg>` | Malicious code, known CVEs, supply-chain attacks |
| Source code | `review <path>` | SAST-style vulnerabilities via static analysis + AI review |
| White-box | `scan --target <url> --repo <path>` | Source-aware scanning — reads code before attacking |
| MCP servers | `scan --target mcp://…` | Tool poisoning and schema abuse |

## CLI flags (scan)

| Flag | Description |
|------|-------------|
| `--target <url>` | Target URL or `mcp://` endpoint (required) |
| `--mode <m>` | `probe`, `deep`, `mcp`, or `web` |
| `--depth <d>` | `quick`, `default`, or `deep` |
| `--runtime <rt>` | `api`, `claude`, `codex`, `gemini`, or `auto` |
| `--format <f>` | `terminal`, `json`, `md`, `html`, `sarif` |
| `--repo <path>` | Source code path for white-box scanning |
| `--auth <json\|file>` | Authenticated scanning. JSON string or file path; supports `bearer`, `cookie`, `basic`, `header` |
| `--api-spec <path>` | Pre-load endpoints from OpenAPI 3.x / Swagger 2.0 (JSON or YAML) |
| `--export <target>` | Export findings to an issue tracker, e.g. `github:owner/repo` |
| `--race` | Best-of-N strategy racing — run multiple attack strategies in parallel |
| `--egats` | Enable Evidence-Gated Attack Tree Search (beam search over hypotheses) |
| `--verbose` | Animated attack replay |
| `--replay` | Re-render the last scan's results from the local DB |

### Authenticated scanning

```bash
npx pwnkit-cli scan --target https://app.example.com \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Or point at a JSON file
npx pwnkit-cli scan --target https://app.example.com --auth ./auth.json
```

Supported auth types: `bearer`, `cookie`, `basic`, `header`.

### API spec import

```bash
npx pwnkit-cli scan --target https://api.example.com \
  --api-spec ./openapi.yaml
```

Pre-loads endpoint/parameter knowledge so the agent starts from a rich
surface map instead of discovering everything from scratch.

### Export to GitHub Issues

```bash
npx pwnkit-cli scan --target https://example.com \
  --export github:my-org/my-repo
```

### Best-of-N strategy racing

```bash
npx pwnkit-cli scan --target https://example.com --race
```

Runs multiple attack strategies in parallel and keeps whichever one produces
a verified finding first.

### EGATS

```bash
npx pwnkit-cli scan --target https://example.com --egats
```

Evidence-Gated Attack Tree Search: the agent maintains an explicit hypothesis
tree and only expands branches backed by observed evidence.

## Runtimes

| Runtime | Description |
|---------|-------------|
| `api` | Direct HTTP to an LLM provider. Default. |
| `claude` | Spawns the Claude Code CLI. |
| `codex` | Spawns the OpenAI Codex CLI. |
| `gemini` | Spawns the Gemini CLI. |
| `auto` | Auto-detect the best runtime per pipeline stage. |

Supported providers: **OpenRouter** (multi-model ensemble), **Anthropic**,
**Azure OpenAI**, and **OpenAI**. See [API Keys](/api-keys/) for priority
order.

## Executors and tools

| Feature | Flag / env var | Description |
|---------|----------------|-------------|
| Shell executor | default | Host `bash` with `curl`, `python3`, and standard tooling |
| Kali Docker executor | `PWNKIT_FEATURE_DOCKER_EXECUTOR=1` | Runs bash inside a Kali container with the full pentesting toolset |
| PTY sessions | `PWNKIT_FEATURE_PTY_SESSION=1` | Long-lived interactive sessions (reverse shells, DB clients, SSH) |
| Playwright browser | auto in `web` mode | Real-browser verification for XSS, cracked XBEN-011 & XBEN-018 |
| Web search | `PWNKIT_FEATURE_WEB_SEARCH=1` | Lets the agent look up CVE details and technique references |

## Output formats

| Format | Description |
|--------|-------------|
| `terminal` | Colored terminal report (default) |
| `json` | Machine-readable JSON |
| `md` / `markdown` | Human-readable Markdown |
| `html` | HTML report |
| `sarif` | SARIF 2.1 — drops into GitHub's Security tab |
| PDF | Branded pentest-style PDF report |

## False-positive reduction moat

pwnkit ships a full triage pipeline with ten+ independent techniques. See
[Finding Triage](/triage/) for the full reference.

- Holding-it-wrong filter
- 45-feature extractor
- Per-class oracles (SQLi, XSS, SSRF, RCE, path traversal, IDOR)
- Reachability gate
- Multi-modal agreement (foxguard × pwnkit)
- PoV generation gate
- Structured 4-step verify pipeline
- Self-consistency voting
- Assistant memories (Semgrep-style)
- EGATS (Evidence-Gated Attack Tree Search)

## Agent loop enhancements

| Feature | Flag / env var | Description |
|---------|----------------|-------------|
| Early-stop + retry | `PWNKIT_FEATURE_EARLY_STOP` (on) | Stops at 50% budget with no findings and retries with a different strategy |
| Loop detection | `PWNKIT_FEATURE_LOOP_DETECTION` (on) | Detects A-A-A / A-B-A-B patterns and injects a warning |
| Context compaction | `PWNKIT_FEATURE_CONTEXT_COMPACTION` (on) | LLM-based compression of middle messages at 30k tokens |
| Exploit templates | `PWNKIT_FEATURE_SCRIPT_TEMPLATES` (on) | Blind-SQLi / SSTI / auth-chain exploit scripts in the prompt |
| Dynamic playbooks | `PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS` | Vuln-class playbooks injected after recon |
| External working memory | `PWNKIT_FEATURE_EXTERNAL_MEMORY` | Agent writes plan/creds to disk; re-injected at reflection checkpoints |
| Progress handoff | `PWNKIT_FEATURE_PROGRESS_HANDOFF` | Prior attempt findings injected when retrying |
| Adversarial debate | `PWNKIT_FEATURE_DEBATE` | Prosecutor vs defender debate with a skeptical judge |

## Benchmarks

- **XBOW:** **86.5% (90/104)** — single model, 3 tools, full 104-challenge
  coverage. Beats MAPTA (76.9%), deadend-cli (77.6%), Cyber-AutoAgent
  (84.6%), XBOW's own agent (85%), and BoxPwnr's best single-model score
  (81.7%).
- **AI/LLM regression suite:** 10/10 on the self-authored suite covering
  prompt injection, jailbreaks, system-prompt extraction, PII leakage,
  encoding bypass, multi-turn escalation, MCP SSRF.
- **AutoPenBench, HarmBench, npm audit** harnesses shipped; see
  [Benchmark](/benchmark/).

## Unified SOC story

pwnkit is one leg of an open-source three-part security stack:

- **[pwnkit](https://github.com/peaktwilight/pwnkit)** — AI agent pentester (detect)
- **[foxguard](https://github.com/peaktwilight/foxguard)** — Rust security scanner (prevent)
- **[opensoar](https://github.com/opensoar-hq/opensoar-core)** — Python-native SOAR platform (respond)

With `PWNKIT_FEATURE_MULTIMODAL=1`, pwnkit automatically cross-validates
every finding against foxguard's pattern scanner — the same neural +
symbolic agreement pattern Endor Labs uses to reach ~95% FP elimination,
except fully open source.
