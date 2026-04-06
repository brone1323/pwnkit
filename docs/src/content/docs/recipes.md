---
title: Recipes
description: Real-world pwnkit recipes for common scanning scenarios.
---

Copy-paste recipes for the most common pwnkit scenarios. Every recipe assumes you have an `OPENROUTER_API_KEY` (or equivalent) exported. See [Getting Started](/getting-started/) if you don't.

## Scan my REST API (OpenAPI)

Point pwnkit at your OpenAPI 3.x / Swagger 2.0 document and it will seed the recon phase with every endpoint, parameter, and auth requirement — skipping the crawl entirely.

```bash
npx pwnkit-cli scan \
  --target https://api.example.com \
  --api-spec ./openapi.yaml \
  --mode web \
  --depth deep
```

If your API requires authentication, add `--auth` (see [Scan authenticated APIs](#scan-authenticated-apis-bearer-token) below).

## Scan a WordPress site for CVEs

Enable the Kali Docker executor so the agent has `wpscan`, `nmap`, and friends available, and turn on web search so it can look up plugin CVEs as it goes.

```bash
export PWNKIT_FEATURE_DOCKER_EXECUTOR=1
export PWNKIT_FEATURE_WEB_SEARCH=1
export PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS=1

npx pwnkit-cli scan \
  --target https://blog.example.com \
  --mode web \
  --depth deep \
  --verbose
```

## Audit an npm package for security issues

```bash
# Default audit
npx pwnkit-cli audit express@4.18.2

# Deep audit with the Claude Code CLI runtime
npx pwnkit-cli audit left-pad --depth deep --runtime claude

# Audit a package that talks to an authenticated API
npx pwnkit-cli audit my-sdk \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}' \
  --api-spec ./partner-api.yaml
```

The package is installed in a sandbox, scanned with semgrep, then reviewed by an AI agent that traces data flow and hunts for supply-chain issues.

## Run a full pentest with maximum accuracy

Turn on every false-positive reduction feature and let EGATS do a thorough tree search. Slower, but produces client-ready findings.

```bash
export PWNKIT_FEATURE_CONSENSUS_VERIFY=1
export PWNKIT_FEATURE_REACHABILITY_GATE=1
export PWNKIT_FEATURE_POV_GATE=1
export PWNKIT_FEATURE_TRIAGE_MEMORIES=1
export PWNKIT_FEATURE_MULTIMODAL=1
export PWNKIT_FEATURE_DOCKER_EXECUTOR=1

npx pwnkit-cli scan \
  --target https://example.com \
  --mode web \
  --depth deep \
  --egats \
  --runtime claude
```

See [Configuration — Feature flags](/configuration/#feature-flags) for what each flag does.

## Best-of-N racing for hard targets

When a single linear attack plan keeps getting stuck, spawn 5 parallel strategies and let the fastest one win.

```bash
npx pwnkit-cli scan \
  --target https://hard-target.example.com \
  --mode web \
  --race \
  --depth deep
```

## Export findings to GitHub Issues

Push every confirmed finding to a GitHub repo as a labelled issue with evidence and reproduction steps.

```bash
export GITHUB_TOKEN="ghp_..."

npx pwnkit-cli scan \
  --target https://example.com \
  --mode web \
  --export github:myorg/security-findings
```

Each finding becomes an issue labelled by severity (`sev:critical`, `sev:high`, …) and category (`cat:xss`, `cat:ssrf`, …) so you can triage from the GitHub UI.

## Generate a client-ready PDF report

```bash
npx pwnkit-cli scan \
  --target https://example.com \
  --mode web \
  --depth deep \
  --format pdf \
  --output example-pentest.pdf
```

The PDF includes an executive summary, a severity breakdown, per-finding evidence blocks with request/response pairs, and reproduction steps. Works for `audit` and `review` too.

## Scan authenticated APIs (bearer token)

```bash
# Inline
npx pwnkit-cli scan \
  --target https://api.example.com \
  --api-spec ./openapi.yaml \
  --auth '{"type":"bearer","token":"eyJhbGciOi..."}'

# From a file (avoids leaking the token to shell history)
cat > auth.json <<'EOF'
{"type":"bearer","token":"eyJhbGciOi..."}
EOF

npx pwnkit-cli scan \
  --target https://api.example.com \
  --api-spec ./openapi.yaml \
  --auth ./auth.json
```

Other auth types:

```bash
# Session cookie
--auth '{"type":"cookie","value":"session=abc123; csrf=def456"}'

# HTTP Basic
--auth '{"type":"basic","username":"admin","password":"hunter2"}'

# Custom header (API key)
--auth '{"type":"header","name":"X-API-Key","value":"sk_live_..."}'
```

## Track learned false positives across runs

After a scan, mark noisy findings as false positives and pwnkit will remember the pattern for next time.

```bash
# Mark a single finding as FP (auto-creates a memory)
pwnkit-cli triage mark-fp NF-042 --reason "test fixture echo endpoint, not reachable in prod"

# Add a memory from an existing finding without suppressing it
pwnkit-cli triage memory add --finding NF-017 --reason "intentional CORS config for public API"

# List what pwnkit has learned
pwnkit-cli triage memory list

# Remove a memory that's no longer accurate
pwnkit-cli triage memory remove <memory-id>
```

Enable memory injection into the verify pipeline with `PWNKIT_FEATURE_TRIAGE_MEMORIES=1`.
