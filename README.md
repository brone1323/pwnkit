<p align="center">
 <img src="assets/pwnkit-icon.gif" alt="pwnkit" width="80" />
</p>

<h1 align="center">pwnkit</h1>

<p align="center">
 <strong>Let autonomous AI agents hack you before attackers do.</strong><br/>
 <em>Fully autonomous agentic pentesting framework.</em>
</p>

<!-- Row 1 — the proof: what the agent actually does on public benchmarks.
     Bold crimson e63946 across all three so they read as one wall of impact. -->
<p align="center">
 <a href="https://docs.pwnkit.com/benchmark"><img src="https://img.shields.io/badge/XBOW%20retained%20artifacts-95.2%25%20(99%2F104)-e63946?style=flat-square&labelColor=2b2d42" alt="XBOW retained artifact-backed aggregate" /></a>
 <a href="https://docs.pwnkit.com/benchmark"><img src="https://img.shields.io/badge/XBOW%20historical%20published-91.3%25%20(95%2F104)-e63946?style=flat-square&labelColor=2b2d42" alt="XBOW historical mixed local+CI tally" /></a>
 <a href="https://docs.pwnkit.com/benchmark"><img src="https://img.shields.io/badge/Cybench-80%25%20(8%2F10)-e63946?style=flat-square&labelColor=2b2d42" alt="Cybench score" /></a>
</p>

<!-- Row 2 — identity, install, license, build. Coordinated muted palette
     so Row 2 visually recedes behind Row 1's red proof. Charcoal label
     across the row, varied accent colors per badge. -->
<p align="center">
 <a href="https://www.npmjs.com/package/pwnkit-cli"><img src="https://img.shields.io/npm/v/pwnkit-cli?color=e63946&style=flat-square&labelColor=2b2d42" alt="npm version" /></a>
 <a href="https://github.com/PwnKit-Labs/pwnkit/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-1d3557?style=flat-square&labelColor=2b2d42" alt="license" /></a>
 <img src="https://img.shields.io/badge/runtime-npx%20%C2%B7%20bunx%20%C2%B7%20docker-2a9d8f?style=flat-square&labelColor=2b2d42" alt="runs with npx, bunx, docker" />
 <img src="https://img.shields.io/badge/native%20deps-zero-457b9d?style=flat-square&labelColor=2b2d42" alt="zero native modules" />
 <a href="https://github.com/PwnKit-Labs/pwnkit/actions"><img src="https://img.shields.io/github/actions/workflow/status/PwnKit-Labs/pwnkit/ci.yml?style=flat-square&labelColor=2b2d42&label=build" alt="build" /></a>
</p>

<p align="center">
 <img src="assets/demo.gif" alt="pwnkit Demo" width="700" />
</p>

<p align="center">
 <a href="https://docs.pwnkit.com">Docs</a> &middot;
 <a href="https://pwnkit.com">Website</a> &middot;
 <a href="https://pwnkit.com/blog">Blog</a> &middot;
 <a href="https://docs.pwnkit.com/benchmark">Benchmark</a> &middot;
 <a href="https://docs.pwnkit.com/triage">Triage</a>
</p>

---

> Fully autonomous agentic pentesting for web apps, AI/LLM apps, package ecosystems, and source code.

This README is the fast path. The detailed command reference, configuration, architecture notes, recipes, and benchmark breakdowns live in the docs site.

## Quick Start

### Docker

```bash
docker run --rm -e OPENROUTER_API_KEY=$KEY \
  ghcr.io/peaktwilight/pwnkit:latest scan --target https://example.com
```

If you use Azure OpenAI instead, also pass `AZURE_OPENAI_BASE_URL` and `AZURE_OPENAI_MODEL`. For the Responses API, the Azure base URL should include `/openai/v1`.

The image ships with Node 20, Playwright/Chromium, and the standard pentest toolbox (sqlmap, nmap, nikto, gobuster, ffuf, hydra, john, …) preinstalled.

### npx / bunx

```bash
# Scan an AI / LLM endpoint
npx pwnkit-cli scan --target https://example.com/api/chat

# Pentest a web app
npx pwnkit-cli scan --target https://example.com --mode web

# White-box scan with source code access
npx pwnkit-cli scan --target https://example.com --repo ./source

# Audit a package
npx pwnkit-cli audit lodash

# Review source code
npx pwnkit-cli review ./my-app

# Auto-detect — just give it a target
npx pwnkit-cli https://example.com
```

Prefer [Bun](https://bun.sh)? Swap `npx` for `bunx` — same commands, same flags, zero-install, noticeably faster cold start. pwnkit-cli is pure-JS with a WASM SQLite core, so there are no native bindings to rebuild on either runtime.

Global install:

```bash
npm i -g pwnkit-cli
# or
bun add -g pwnkit-cli
```

## What It Does

- `scan` targets AI / LLM apps, web apps, REST / OpenAPI APIs, and MCP servers.
- `audit` installs and inspects packages across `npm`, `pypi`, `cargo`, and `oci` with ecosystem-specific prep, static analysis, and AI review.
- `review` performs deep source-code security review on a local repo or Git URL.
- `triage-data` turns benchmark runs and verified findings into labeled JSONL for triage-model training.
- `cloud-sink` can stream findings and final reports to an orchestrator with `PWNKIT_CLOUD_SINK` + `PWNKIT_CLOUD_SCAN_ID`.
- `dashboard`, `history`, `findings`, and `triage` provide local persistence and review workflows.

## Why It’s Different

- Shell-first web pentesting. The agent uses `bash`, writes scripts, and chains tools like a human pentester instead of being trapped in a small HTTP-tool DSL.
- Blind verification. Findings are independently re-exploited before they are reported.
- Docs-backed benchmark transparency. The current benchmark details live in the docs and raw artifacts under [`packages/benchmark/results`](https://github.com/PwnKit-Labs/pwnkit/tree/main/packages/benchmark/results).

## Docs

- [Getting Started](https://docs.pwnkit.com/getting-started)
- [Adversarial evals](https://docs.pwnkit.com/adversarial-evals)
- [Commands](https://docs.pwnkit.com/commands)
- [Configuration](https://docs.pwnkit.com/configuration)
- [Recipes](https://docs.pwnkit.com/recipes)
- [Architecture](https://docs.pwnkit.com/architecture)
- [Triage Pipeline](https://docs.pwnkit.com/triage)
- [Benchmark](https://docs.pwnkit.com/benchmark)

## Snapshot

- XBOW retained artifact-backed aggregate: 99/104 = 95.2%
- XBOW retained artifact-backed black-box: 74/104 = 71.2%
- XBOW historical mixed local+CI publication: 95/104 aggregate and 90/104 black-box
- Cybench: 8/10 = 80%
- AI / LLM regression set: 10/10

The benchmark docs page is the canonical benchmark surface. It distinguishes the current retained artifact-backed tally from the older mixed local+CI publication line and lists the remaining challenge-set mismatches explicitly.

## GitHub Action

```yaml
- uses: PwnKit-Labs/pwnkit@main
  with:
    mode: review
    path: .
    format: sarif
  env:
    OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
```

## Development

```bash
git clone https://github.com/PwnKit-Labs/pwnkit.git
cd pwnkit
pnpm install
pnpm lint
pnpm test
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Part of PwnKit Labs

**Open-source adversarial security for the agentic AI era.** pwnkit is one piece of the open-source PwnKit Labs stack:
- **[pwnkit](https://github.com/PwnKit-Labs/pwnkit)** — AI agent pentester (detect)
- **[foxguard](https://github.com/PwnKit-Labs/foxguard)** — Rust security scanner (prevent)
- **[opensoar](https://github.com/opensoar-hq/opensoar-core)** — Python-native SOAR platform (respond)

## License

[Apache 2.0](LICENSE)
