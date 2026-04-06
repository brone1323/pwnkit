---
title: Commands
description: Complete reference for all pwnkit CLI commands.
---

All commands are available via `npx pwnkit-cli <command>`. You can also skip the subcommand and let auto-detect figure it out (see [Getting Started](/getting-started/)).

## scan

Probe AI/LLM apps, web apps, APIs, or MCP servers for vulnerabilities.

```bash
# Scan an LLM API
npx pwnkit-cli scan --target https://api.example.com/chat

# Scan a traditional web app
npx pwnkit-cli scan --target https://example.com --mode web

# Deep scan with Claude Code CLI
npx pwnkit-cli scan --target https://api.example.com/chat --depth deep --runtime claude

# Authenticated scan using a bearer token
npx pwnkit-cli scan --target https://api.example.com \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Scan an API with an OpenAPI spec pre-loaded
npx pwnkit-cli scan --target https://api.example.com --api-spec ./openapi.yaml

# Run 5 attack strategies in parallel — first to succeed wins
npx pwnkit-cli scan --target https://example.com --mode web --race

# Evidence-Gated Attack Tree Search (EGATS)
npx pwnkit-cli scan --target https://example.com --mode web --egats

# Export findings to GitHub Issues
npx pwnkit-cli scan --target https://example.com --mode web \
  --export github:myorg/myrepo

# Generate a PDF report
npx pwnkit-cli scan --target https://example.com --mode web \
  --format pdf --output report.pdf
```

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target <url>` | The URL or `mcp://` endpoint to scan | (required) |
| `--mode <mode>` | Scan mode: `probe`, `deep`, `mcp`, `web` | auto |
| `--depth <depth>` | Scan depth: `quick`, `default`, `deep` | `default` |
| `--runtime <rt>` | Runtime: `auto`, `api`, `claude`, `codex`, `gemini` | `auto` |
| `--format <fmt>` | Output format: `terminal`, `json`, `md`, `html`, `sarif`, `pdf` | `terminal` |
| `--output <path>` | Write report to a file (required for `pdf`) | (stdout) |
| `--timeout <ms>` | Request timeout in milliseconds | `30000` |
| `--api-key <key>` | API key for the LLM provider | (from env) |
| `--model <model>` | Specific LLM model to use | provider default |
| `--repo <path>` | Local source code path for white-box scanning | (none) |
| `--auth <json>` | Authenticated scanning credentials (see below) | (none) |
| `--api-spec <path>` | Path to an OpenAPI 3.x / Swagger 2.0 spec (JSON or YAML) | (none) |
| `--export <target>` | Export findings to an issue tracker, e.g. `github:owner/repo` | (none) |
| `--race` | Best-of-N: run 5 attack strategies in parallel, first-to-succeed wins | `false` |
| `--egats` | Evidence-Gated Attack Tree Search (beam search over hypothesis tree) | `false` |
| `--db-path <path>` | Path to SQLite database | `~/.pwnkit/pwnkit.db` |
| `--verbose` | Show animated attack replay and detailed agent reasoning | `false` |
| `--replay` | Replay the last scan's results without re-running | `false` |

### `--auth` credential formats

The `--auth` flag accepts either an inline JSON string or a path to a JSON file. Four credential types are supported:

```bash
# Bearer token
--auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Session cookie
--auth '{"type":"cookie","value":"session=abc123; csrf=def456"}'

# HTTP Basic auth
--auth '{"type":"basic","username":"admin","password":"hunter2"}'

# Custom header (e.g. API key)
--auth '{"type":"header","name":"X-API-Key","value":"sk_live_..."}'

# Or load from a file
--auth ./auth.json
```

### `--api-spec` — OpenAPI / Swagger import

Point `--api-spec` at an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML). pwnkit will parse the spec, extract all endpoints with their parameter schemas and auth requirements, and seed the recon phase with that knowledge so the agent starts pentesting with full endpoint awareness instead of having to crawl.

```bash
npx pwnkit-cli scan --target https://api.example.com --api-spec ./openapi.yaml
```

### `--race` — best-of-N strategy racing

With `--race`, pwnkit spawns 5 attack strategies in parallel against the same target. The first agent to confirm a finding wins; the others are terminated. Ideal for hard targets where a single linear attack plan gets stuck.

### `--egats` — Evidence-Gated Attack Tree Search

EGATS performs a beam search over a tree of attack hypotheses, pruning branches that fail evidence checks. Slower than `--race` but much more thorough.

### `--export github:owner/repo`

Pushes every confirmed finding to a GitHub repo as an issue, with severity labels, evidence blocks, and reproduction steps. Requires `GITHUB_TOKEN` in the environment with `repo` scope.

## audit

Install and security-audit any npm package with static analysis and AI review. Supports every scan flag (auth, api-spec, export, race, egats, pdf).

```bash
npx pwnkit-cli audit express@4.18.2
npx pwnkit-cli audit react --depth deep --runtime claude
npx pwnkit-cli audit left-pad --format pdf --output left-pad-audit.pdf
```

The package is installed in a sandbox, scanned with semgrep, and then reviewed by an AI agent that traces data flow and looks for supply-chain vulnerabilities.

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `<package>` | npm package name (with optional `@version`) | (required) |
| `--version <v>` | Specific version to audit | `latest` |
| `--depth <d>` | Audit depth: `quick`, `default`, `deep` | `default` |
| `--runtime <rt>` | Runtime: `auto`, `api`, `claude`, `codex`, `gemini` | `auto` |
| `--format <fmt>` | Output format: `terminal`, `json`, `md`, `html`, `sarif`, `pdf` | `terminal` |
| `--output <path>` | Write report to a file | (stdout) |
| `--timeout <ms>` | AI agent timeout in milliseconds | `600000` |
| `--auth <json>` | Auth credentials when the package talks to an authenticated API | (none) |
| `--api-spec <path>` | OpenAPI spec for APIs the package integrates with | (none) |
| `--export <target>` | Export findings to an issue tracker | (none) |
| `--race` | Best-of-N strategy racing | `false` |
| `--egats` | Evidence-Gated Attack Tree Search | `false` |
| `--verbose` | Detailed agent output | `false` |

## review

Deep source code security review of a local repo or GitHub URL.

```bash
# Review a local directory
npx pwnkit-cli review ./my-ai-app

# Review a GitHub repo (cloned automatically)
npx pwnkit-cli review https://github.com/user/repo

# Diff-aware review against a base branch
npx pwnkit-cli review ./my-repo --diff-base origin/main --changed-only
```

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `<path-or-url>` | Local path or GitHub URL | (required) |
| `--depth` | Scan depth | `default` |
| `--runtime` | Runtime to use | `auto` |
| `--diff-base <ref>` | Base branch for diff-aware review | (none) |
| `--changed-only` | Only review changed files | `false` |

## triage

Triage findings and manage learned false-positive memories. Every time you mark a finding as a false positive, pwnkit stores a pattern that future verify passes will consult — think Semgrep's `nosemgrep` but learned automatically.

```bash
# Create a memory from an existing finding
pwnkit-cli triage memory add --finding NF-001 --reason "test fixture, not reachable in prod"

# List all memories
pwnkit-cli triage memory list
pwnkit-cli triage memory list --scope target --category xss

# Delete a memory
pwnkit-cli triage memory remove <memory-id>

# Mark a finding as FP and auto-create a memory
pwnkit-cli triage mark-fp NF-042 --reason "known sandbox echo endpoint"
```

**`triage memory add`**

| Flag | Description | Default |
|------|-------------|---------|
| `--finding <id>` | Finding ID (full or prefix) to derive the memory from | (required) |
| `--reason <text>` | Why this finding is a false positive | (required) |
| `--scope <scope>` | Memory scope: `global`, `target`, `package` | `target` |
| `--scope-value <v>` | Scope identifier (target URL or package name) | (inferred) |
| `--db-path <path>` | Path to SQLite database | default |

**`triage memory list`**

| Flag | Description |
|------|-------------|
| `--scope <scope>` | Filter by scope: `global`, `target`, `package` |
| `--category <cat>` | Filter by vulnerability category |
| `--db-path <path>` | Path to SQLite database |

**`triage memory remove <id>`** — deletes a memory by its ID.

**`triage mark-fp <finding-id>`** — flips a finding's triage status to `suppressed` and auto-creates a memory.

| Flag | Description | Default |
|------|-------------|---------|
| `--reason <text>` | Why this finding is a false positive | (required) |
| `--scope <scope>` | Memory scope | `target` |
| `--scope-value <v>` | Scope identifier | (inferred) |

Enable memory injection into the verify pipeline with `PWNKIT_FEATURE_TRIAGE_MEMORIES=1` (see [Configuration](/configuration/#feature-flags)).

## resume

Resume a persisted review or audit scan by its scan ID.

```bash
npx pwnkit-cli resume <scan-id>
```

Useful when a long-running deep scan was interrupted or when you want to continue where a previous run left off.

## dashboard

Open the local verification workbench for board-based triage, evidence review, and scan provenance.

```bash
npx pwnkit-cli dashboard
npx pwnkit-cli dashboard --port 48123
```

The dashboard provides a Kanban-style board for triaging findings, reviewing evidence, and tracking active scans. It runs entirely locally.

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--port <port>` | Port to serve the dashboard on | `48120` |

## history

Browse past scans with status, depth, findings count, and duration.

```bash
npx pwnkit-cli history
npx pwnkit-cli history --limit 20
```

| Flag | Description | Default |
|------|-------------|---------|
| `--limit <n>` | Number of scans to show | `10` |

## findings

Query, filter, and inspect verified findings across all scans. Findings are persisted in a local SQLite database.

```bash
# List all findings
npx pwnkit-cli findings list

# Filter by severity
npx pwnkit-cli findings list --severity critical

# Filter by category and status
npx pwnkit-cli findings list --category prompt-injection --status confirmed

# Inspect a specific finding with full evidence
npx pwnkit-cli findings show NF-001

# Triage findings
npx pwnkit-cli findings accept <finding-id> --note "confirmed and tracked"
npx pwnkit-cli findings suppress <finding-id> --note "known test fixture"
npx pwnkit-cli findings reopen <finding-id>
```

**Finding lifecycle:** `discovered` -> `verified` -> `confirmed` -> `scored` -> `reported` (or `false-positive` if verification fails).

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `list` | List findings with optional filters |
| `show <id>` | Show a finding with full evidence |
| `accept <id>` | Accept a finding as confirmed |
| `suppress <id>` | Suppress a finding (known FP or accepted risk) |
| `reopen <id>` | Reopen a previously suppressed finding |

## XBOW benchmark runner

The XBOW benchmark runner lives in `packages/benchmark` and is invoked with `pnpm --filter @pwnkit/benchmark xbow`. It runs pwnkit against the 104 XBOW validation challenges and reports pass/fail with evidence.

```bash
# Run the whole benchmark
pnpm --filter @pwnkit/benchmark xbow

# Run a specific subset of challenges
pnpm --filter @pwnkit/benchmark xbow --only XBEN-010,XBEN-051,XBEN-066

# Skip the first 20 challenges (useful for resuming)
pnpm --filter @pwnkit/benchmark xbow --start 20

# Include full finding objects in results JSON (for offline analysis)
pnpm --filter @pwnkit/benchmark xbow --save-findings
```

| Flag | Description | Default |
|------|-------------|---------|
| `--only <ids>` | Comma-separated challenge IDs to run | (all 104) |
| `--start <n>` | Skip the first `n` challenges | `0` |
| `--save-findings` | Include full finding objects in the results JSON | `false` |
