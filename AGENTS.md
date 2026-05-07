# Agent guidance for the pwnkit repo

This file is project-level instructions for AI coding agents (Claude Code, Cursor, etc.) working in this repository. Read it before starting any non-trivial task.

## How to operate in this repo

- Use **pnpm**, not npm or yarn. Workspace root has `pnpm-workspace.yaml`.
- Run filtered commands: `pnpm --filter @pwnkit/core build`, `pnpm --filter @pwnkit/cli build`, etc. Don't `pnpm -r build` for one package.
- Tests: `pnpm --filter @pwnkit/core test` (vitest). 800+ tests; new code must add tests.
- Type-check: each package has `tsc --noEmit` via its `build` script. Build before declaring done.
- Lint clean. The project has `pnpm lint` at root.

## Parallel work — use worktrees, not branches

When multiple agents work on the repo simultaneously (e.g. one fixes `disclose`, another updates docs, another runs benchmarks), branches collide and one agent's commit nukes another's working tree.

**Rule:** when launching subagents that will modify files, pass `isolation: "worktree"` to the Agent tool. Each agent gets a separate clone of the repo on its own branch. Cleanup is automatic if the agent makes no changes; otherwise the agent reports a path + branch you can rebase or PR.

This applies to:
- Multiple parallel doc updates
- Code-modifying agents running alongside CI-driven workflows
- Any "let's do X and Y in parallel" where both touch repo files

Single read-only agents (research, scoring, enumeration) don't need worktrees — they don't write files in the repo.

## Benchmark workflow

- XBOW canonical: `pnpm --filter @pwnkit/benchmark consolidate-xbow --limit-runs 200 --output /tmp/xbow-canonical-200.json`. Reports BB / WB / aggregate counts. **The retained-artifact tally rotates** as new CI runs occupy the 200-run lookback window — do NOT publish docs to numbers in active flux. Wait for stability after the latest dispatch wave finishes.
- Benchmark workflow files live in `.github/workflows/`: `xbow-bench.yml`, `cybench.yml`, `npm-bench.yml`, `autopenbench.yml`, `harmbench.yml`. Each has `workflow_dispatch` inputs.
- Dispatch via `gh workflow run`. Default features=`default`; the moat ablation already showed moat regresses some slices, so don't enable it without a reason.
- The patched benchmark fork `0ca/xbow-validation-benchmarks-patched` fixes all 104 Docker builds — use it.
- Cost ceilings matter: default `repeat_cost_ceiling_usd=5.00` caps retries early. For wb-only conversions use `$50`+, for hard-tail unsolved use `$100-$300`.

## HackerOne API

Auth scheme as of May 2026:

```bash
# Identifier = the friendly NAME you typed when generating the token (e.g. "mybot")
# Value = the 44-char base64 secret shown once at creation
curl -u "$H1_API_IDENTIFIER:$H1_API_TOKEN" \
     -H "Accept: application/json" \
     -A "your-tool/0.1" \
     "https://api.hackerone.com/v1/hackers/payments/balance"
# → 200 OK with valid creds
```

Gotchas the H1 docs don't make obvious:
- The Identifier is set at token creation. It's NOT auto-generated. It's the name field you type. **It's also not your H1 handle.**
- Identifier is visible at `https://hackerone.com/settings/api_token` (list view, NOT `/edit` regenerate view).
- Identifier rules: must begin with letter or number; only letters, numbers, hyphens, underscores. (So the token value itself, which contains `+/=`, can't be the identifier.)
- H1 returns `WWW-Authenticate: Basic realm="HackerOne API"` on 401 — Basic is the only scheme; Bearer / X-Token / etc. always 401.
- Hackers can have only ONE active token at a time. Regenerating revokes the previous one.
- Pagination uses bracketed query params: `page[size]=100&page[number]=2` — URL-encode brackets as `%5B`/`%5D` or pass `-g` to curl.
- Rate limit: 600 reads/min, 25 writes per 20s. Pace with `sleep 0.2` between calls in batch scripts.
- Hacker API endpoints: `/v1/hackers/programs`, `/v1/hackers/programs/{handle}/structured_scopes`, `/v1/hackers/payments/balance`. There is no `/v1/hackers/me`.

Credential storage: `~/.pwnkit/h1.env` (chmod 600) holds `H1_API_IDENTIFIER` and `H1_API_TOKEN`. Never commit. Use the `h1env` zsh helper to load on demand.

## HackerOne CoC for AI tools — bright lines

H1's Community Member Code of Conduct (April 2026) treats AI-driven low-quality submissions harshly: **Final Warning on FIRST offense → 12-month ban second offense → permanent ban third.** No "Educational" lane like for other violations.

Specific tripwires:
- Hallucinated function/file/endpoint references in reports (curl shut down their bounty over this)
- Submissions without working PoC
- Fabricated patch suggestions
- Volume-firsting (large numbers of low-signal reports)
- Out-of-scope scanning
- Excessive traffic / rate-limit violation

Pre-submission practice (XBOW playbook): every report goes through human review BEFORE submission. XBOW's actual numbers were 1,060 submissions → 130 resolved + 245 informative/N-A + 208 duplicates. Even with their human gate, 46% noise. Don't auto-submit anything.

## /disclose pipeline — H1-readiness state

After PR #206 (`feat/disclose-h1-readiness`), `/disclose` enforces:
- Filters out `Finding.status: discovered | false-positive` before drafting
- Drops `could_not_run` PoC verdicts by default (use `--keep-unrun` to override)
- Refuses to render advisories with empty PoCs (no more TODO placeholder string)
- Redacts auth headers, cookies, AWS keys, JWTs from advisory + screenshots
- "Code-verified by pwnkit" footer only renders when reverify+canary BOTH pass
- Per-host RPS cap on PoC reverify runtime (`--reverify-rps`, default 2)
- Scope allowlist on PoC runtime (`--scope-allowlist`, blocks http and bash URLs out of scope)

Still-missing for full H1 quality bar (post-PR-206):
- Mandatory `## Impact` narrative section in template
- Content-level hallucination canary (verify quoted snippets match cited file:line)
- Mitigation-aware reverify (detect WAF/CSP/CDN responses)
- Reproducibility manifest (env fingerprint per finding)
- Two-step file gate (`disclose review <id>` interactive Y/n per advisory)

## Scope ingestion (planned, not yet built)

Subagent B's design from 2026-05-06 session:

- New CLI: `pwnkit scope load <h1-program-handle>` — fetches scope JSON via H1 API, persists to `~/.pwnkit/scopes/<handle>.json`
- `pwnkit scan --scope <path>` — constrains agent to in-scope assets only
- Scope rule shapes: exact host, `*.domain.com` wildcard (sub-domains only, NOT bare apex), CIDR (IPv4 only)
- Enforced at: `validateTargetUrl` (existing chokepoint) + `shellExec` URL extraction (regex `https?://[^\s'"]+`) + 5 other fetch sites
- Out-of-scope = hard error returned as `ToolResult.error`, not soft warning
- Effort estimate: ~14h. Critical path before any H1 submission.

The bash subprocess egress is an acknowledged gap (subprocesses bypass node's fetch). Real fix is egress-proxy on runner; mitigation in the meantime is the URL-extraction pre-flight.

## Generic-scanner-traffic suppression (pwnkit#217)

When `--scope` is loaded, the engagement is presumed to be a coordinated-disclosure run, and most venue policies forbid the named generic scanners because they fingerprint themselves on the wire (`User-Agent: sqlmap/1.7`, `User-Agent: gobuster/3.6`, etc.). `bash` (`shellExec`) refuses to spawn:

- `sqlmap` (and `python -m sqlmap`)
- `nikto`
- `gobuster`
- `dirb`
- `wfuzz` (and `python -m wfuzz`)
- `ffuf`
- `nmap -sV` and `nmap -A` (service / OS fingerprinting)

Plain `nmap -p ... host` is allowed — port scanning is policy-orthogonal. Detection runs against every pipeline / `&&` / `||` / `;` segment and recognises bare, absolute, relative, env-prefixed, and quoted invocations (`"sqlmap"`, `/usr/bin/sqlmap`, `./sqlmap`, `HTTP_PROXY=… sqlmap`, `echo … | sqlmap`).

`--allow-scanners` overrides the gate for engagements that explicitly permit those tools. The flag has no effect unless `--scope` is also set (no scope = no gate).

The shell-first agent does NOT need these binaries to find vulnerabilities — `http_request` and `crawl` give it the fine-grained probe surface most venue policies welcome.

## Repo conventions

- `packages/core` — agent loop, tools, runtime, scanner, disclose, db
- `packages/cli` — CLI commands (scan, audit, disclose, etc.)
- `packages/shared` — types only
- `packages/db` — drizzle schema, WASM SQLite shim (NEVER reintroduce native bindings; see `project_db_wasm.md` memory)
- `packages/benchmark` — benchmark runners and result consolidation
- `docs/` — Astro docs site, deploys to docs.pwnkit.com
- `docs/paper/` — research paper draft

## Common gotchas

- Don't use `git rebase -i` or `git add -i` (interactive flags not supported).
- Don't push --force to main (warn user if requested).
- Don't add destructive commands without confirmation (rm -rf, db DROP, force-push).
- When updating benchmark numbers across docs, update ALL of: README.md, docs/src/content/docs/benchmark.md, features.md, index.mdx, roadmap.md, research/* files, paper/pwnkit.md, packages/benchmark/results/benchmark-ledger.json. Use grep `grep -rn "OLD_NUMBER" docs/src/content/docs/` to verify nothing's left stale.
- The historical-line section of `benchmark-ledger.json` is intentionally frozen — don't touch its `asOf` or counts.
