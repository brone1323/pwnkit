---
title: Commands
description: Complete reference for all pwnkit CLI commands.
---

All commands are available via `pwnkit <command>`. You can also skip the subcommand and let auto-detect figure it out (see [Getting Started](/getting-started/)).

## scan

Probe AI/LLM apps, web apps, APIs, or MCP servers for vulnerabilities.

```bash
# Scan an LLM API
pwnkit scan --target https://api.example.com/chat

# Scan a traditional web app
pwnkit scan --target https://example.com --mode web

# Deep scan with Claude Code CLI
pwnkit scan --target https://api.example.com/chat --depth deep --runtime claude

# Authenticated scan using a bearer token
pwnkit scan --target https://api.example.com \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# Scan an API with an OpenAPI spec pre-loaded
pwnkit scan --target https://api.example.com --api-spec ./openapi.yaml

# Run 5 attack strategies in parallel — first to succeed wins
pwnkit scan --target https://example.com --mode web --race

# Evidence-Gated Attack Tree Search (EGATS)
pwnkit scan --target https://example.com --mode web --egats

# Abort cleanly if the scan exceeds a USD ceiling
pwnkit scan --target https://example.com --mode web --cost-ceiling 5

# Export findings to GitHub Issues
pwnkit scan --target https://example.com --mode web \
  --export github:myorg/myrepo

# Generate an HTML report (auto-opens in browser)
pwnkit scan --target https://example.com --mode web \
  --format html
```

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target <url>` | The URL or `mcp://` endpoint to scan | (required) |
| `--mode <mode>` | Scan mode: `probe`, `deep`, `mcp`, `web` | auto |
| `--depth <depth>` | Scan depth: `quick`, `default`, `deep` | `default` |
| `--runtime <rt>` | Runtime: `auto`, `api`, `claude`, `codex`, `gemini` | `auto` |
| `--format <fmt>` | Output format: `terminal`, `json`, `md`, `html`, `sarif`, `pdf` | `terminal` |
| `--timeout <ms>` | Request timeout in milliseconds | `30000` |
| `--api-key <key>` | API key for the LLM provider | (from env) |
| `--model <model>` | Specific LLM model to use | provider default |
| `--repo <path>` | Local source code path for white-box scanning | (none) |
| `--auth <json>` | Authenticated scanning credentials (see below) | (none) |
| `--api-spec <path>` | Path to an OpenAPI 3.x / Swagger 2.0 spec (JSON or YAML) | (none) |
| `--export <target>` | Export findings to an issue tracker, e.g. `github:owner/repo` | (none) |
| `--race` | Best-of-N: run 5 attack strategies in parallel, first-to-succeed wins | `false` |
| `--egats` | Evidence-Gated Attack Tree Search (beam search over hypothesis tree) | `false` |
| `--cost-ceiling <usd>` | Hard USD ceiling; aborts cleanly with partial findings preserved if exceeded | (none) |
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
pwnkit scan --target https://api.example.com --api-spec ./openapi.yaml
```

### `--race` — best-of-N strategy racing

With `--race`, pwnkit spawns 5 attack strategies in parallel against the same target. The first agent to confirm a finding wins; the others are terminated. Ideal for hard targets where a single linear attack plan gets stuck.

### `--egats` — Evidence-Gated Attack Tree Search

EGATS performs a beam search over a tree of attack hypotheses, pruning branches that fail evidence checks. Slower than `--race` but much more thorough.

### `--cost-ceiling` — hard spend guardrail

Set a hard per-scan USD ceiling:

```bash
pwnkit scan --target https://example.com --mode web --cost-ceiling 5
```

If cumulative estimated spend exceeds the ceiling, pwnkit:

- preserves findings collected so far
- exits with status code `4`
- emits `exit_reason: "cost_ceiling_exceeded"` in the machine-readable result line

The CLI flag overrides `PWNKIT_COST_CEILING_USD`.

### `--export github:owner/repo`

Pushes every confirmed finding to a GitHub repo as an issue, with severity labels, evidence blocks, and reproduction steps. Requires `GITHUB_TOKEN` in the environment with `repo` scope.

## audit

Install and security-audit a package with static analysis and AI review.

```bash
pwnkit audit express --version 4.18.2
pwnkit audit requests --ecosystem pypi
pwnkit audit serde --ecosystem cargo
pwnkit audit alpine:3.20 --ecosystem oci
pwnkit audit react --depth deep --runtime claude
pwnkit audit left-pad --format html
```

The package is installed in a sandbox, scanned with semgrep, and then reviewed by an AI agent that traces data flow and looks for supply-chain vulnerabilities.

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `<package>` | Package name | (required) |
| `--ecosystem <e>` | Package ecosystem: `npm`, `pypi`, `cargo`, `oci` | `npm` |
| `--version <v>` | Specific version to audit | `latest` |
| `--depth <d>` | Audit depth: `quick`, `default`, `deep` | `default` |
| `--runtime <rt>` | Runtime: `auto`, `api`, `claude`, `codex`, `gemini` | `auto` |
| `--format <fmt>` | Output format: `terminal`, `json`, `md`, `html`, `sarif`, `pdf` | `terminal` |
| `--timeout <ms>` | AI agent timeout in milliseconds | `600000` |
| `--api-key <key>` | API key for the LLM provider | (from env) |
| `--model <model>` | Specific LLM model to use | provider default |
| `--cost-ceiling <usd>` | Hard USD ceiling; aborts cleanly with partial findings preserved if exceeded | (none) |
| `--db-path <path>` | Path to SQLite database | `~/.pwnkit/pwnkit.db` |
| `--verbose` | Detailed agent output | `false` |

## review

Deep source code security review of a local repo or GitHub URL.

```bash
# Review a local directory
pwnkit review ./my-ai-app

# Review a GitHub repo (cloned automatically)
pwnkit review https://github.com/user/repo

# Diff-aware review against a base branch
pwnkit review ./my-repo --diff-base origin/main --changed-only
```

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `<repo>` | Local path or git URL | (required) |
| `--depth <d>` | Review depth: `quick`, `default`, `deep` | `default` |
| `--format <fmt>` | Output format: `terminal`, `json`, `md`, `html`, `sarif`, `pdf` | `terminal` |
| `--runtime <rt>` | Runtime: `auto`, `api`, `claude`, `codex`, `gemini` | `auto` |
| `--diff-base <ref>` | Git base ref for diff-aware review | (none) |
| `--changed-only` | Restrict semgrep + prioritization to changed files | `false` |
| `--timeout <ms>` | AI agent timeout in milliseconds | `600000` |
| `--api-key <key>` | API key for LLM provider | (from env) |
| `--model <model>` | Specific LLM model to use | provider default |
| `--cost-ceiling <usd>` | Hard USD ceiling; aborts cleanly with partial findings preserved if exceeded | (none) |
| `--db-path <path>` | Path to SQLite database | `~/.pwnkit/pwnkit.db` |
| `--verbose` | Detailed agent output | `false` |

## ingest

Import kernel crash reports and optionally verify them against attached reproducers.

```bash
# Parse one crash report into findings
pwnkit ingest ./crashes/report.log

# Parse a directory of syzbot-style reports and reproducers
pwnkit ingest ./crashes --output json

# Validate reports against attached reproducers
pwnkit ingest ./crashes --verify --output json
```

For directory ingest, reproducers are attached by matching filename prefix:

- `crash001.log` + `crash001.c`
- `bug-42.report` + `bug-42.syz`

When `--verify` is enabled, the command returns a richer result object per crash:

- `sourcePath`
- `reproducerPath`
- `finding`
- `verification`

Without a configured kernel VM, verification falls back to static consistency and reproducer analysis only.

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `<path>` | Crash report file or directory of reports | (required) |
| `--format <fmt>` | Input hint: `auto`, `kasan`, `ubsan`, `oops`, `syzkaller`, `generic` | `auto` |
| `--output <fmt>` | Output format: `terminal`, `json`, `sarif` | `terminal` |
| `--verify` | Run the kernel oracle for each parsed report | `false` |
| `--verbose` | Include extra crash-analysis detail in terminal output | `false` |

### Real kernel VM verification

Set `PWNKIT_KERNEL_QEMU=1` to enable VM-backed execution. The runner expects a bootable guest image with:

- a boot path that mounts the `pwnkitshare` 9p share and executes `/mnt/pwnkit/runner.sh`
- a working C toolchain (`gcc`)
- a linker toolchain (`ld`, provided by `binutils`)
- permission to read kernel logs via `dmesg`

Required environment variables:

```bash
export PWNKIT_KERNEL_QEMU=1
export PWNKIT_KERNEL_QEMU_KERNEL=/path/to/bzImage
export PWNKIT_KERNEL_QEMU_DISK=/path/to/rootfs.img
```

Useful optional variables:

```bash
export PWNKIT_KERNEL_QEMU_APPEND='console=ttyS0 root=/dev/vda rw nokaslr panic=-1 init=/sbin/pwnkit-init'
export PWNKIT_KERNEL_QEMU_BOOT_TIMEOUT_SEC=120
export PWNKIT_KERNEL_QEMU_TIMEOUT_SEC=60
export PWNKIT_KERNEL_QEMU_ACCEL=kvm
export PWNKIT_KERNEL_QEMU_SHARE_TAG=pwnkitshare
export PWNKIT_KERNEL_QEMU_ARTIFACT_DIR=/tmp/pwnkit-kvm-runs
```

If the VM is not configured, pwnkit does **not** claim a reproduced crash; it reports static-only verification with capped confidence.

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
pwnkit resume <scan-id>
```

Useful when a long-running deep scan was interrupted or when you want to continue where a previous run left off.

## dashboard

Open the local verification workbench for board-based triage, evidence review, and scan provenance.

```bash
pwnkit dashboard
pwnkit dashboard --port 48123
```

The dashboard provides a Kanban-style board for triaging findings, reviewing evidence, and tracking active scans. It runs entirely locally.

**Key flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--port <port>` | Port to bind | `48123` |
| `--host <host>` | Host to bind | `127.0.0.1` |
| `--no-open` | Do not auto-open a browser | (opens by default) |
| `--db-path <path>` | Path to SQLite database | `~/.pwnkit/pwnkit.db` |

## history

Browse past scans with status, depth, findings count, and duration.

```bash
pwnkit history
pwnkit history --limit 20
```

| Flag | Description | Default |
|------|-------------|---------|
| `--limit <n>` | Number of scans to show | `10` |

## findings

Query, filter, and inspect verified findings across all scans. Findings are persisted in a local SQLite database.

```bash
# List all findings
pwnkit findings list

# Filter by severity
pwnkit findings list --severity critical

# Filter by category and status
pwnkit findings list --category prompt-injection --status confirmed

# Inspect a specific finding with full evidence
pwnkit findings show NF-001

# Triage findings
pwnkit findings accept <finding-id> --note "confirmed and tracked"
pwnkit findings suppress <finding-id> --note "known test fixture"
pwnkit findings reopen <finding-id>
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
