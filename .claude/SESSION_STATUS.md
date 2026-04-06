# pwnkit Session Status

> **Do not commit.** This is a scratch pad for tracking the current session.
> Updated: April 6, 2026

## Score improvement

| Benchmark | Before | After | Delta |
|-----------|--------|-------|-------|
| XBOW unique flags | 35 | 90 | +55 |
| XBOW % (of 104) | 33.7% | 86.5% | +52.8pp |
| Core tests | 62 | 118 | +56 |

## Shipped this session

### Features (code that ships)
1. LLM context compaction (multi-recompaction)
2. Web search tool with anti-cheat blocklist
3. Progress handoff between retries
4. Per-scan cost tracking (USD estimates)
5. XSS playbook (5 steps, 21 detection patterns, browser verification)
6. OpenRouter multi-model runtime (6 default models)
7. Kali Docker executor
8. PDF pentest reports (pdfkit-based)
9. Authenticated scanning (`--auth` bearer/cookie/basic/header)
10. OpenAPI/Swagger import (`--api-spec`)
11. Remediation guidance (18+ categories, static KB + LLM-enhanced)
12. GitHub Issues export (`--export github:owner/repo`)
13. 45-feature handcrafted triage extractor
14. Structured 4-step verify pipeline (reachability → payload → impact → exploit)
15. PTY session management (`pty_session` tool)
16. Best-of-N strategy racing (5 strategies: aggressive/methodical/creative/tool-heavy/minimal)
17. Blind exploitation playbook
18. CVE lookup playbook (WordPress/Drupal/Joomla)
19. Deserialization playbook (PHP/Python/YAML/Java/.NET/Ruby)
20. HTTP request smuggling playbook
21. Creative IDOR playbook
22. Holding-it-wrong filter (rejects works-as-designed findings)
23. EGATS evidence-gated attack tree search
24. Per-class verification oracles (SQLi/XSS/SSRF/RCE/traversal/IDOR)
25. Self-consistency voting (N=3 majority vote)
26. `--only` flag for targeted CI runs
27. `--save-findings` + result merging
28. Triage data collector

### Infrastructure
- CI: 330min step timeout, sqlmap/nmap/nikto installed, 3 retries
- Scripts: Azure CLI setup (removed per request)
- Docs: Research page on finding triage ML
- README: Stripped indie tools, added SOC portfolio footer

### Fixes
- Fix CI hang after benchmark completion (process.exit)
- Fix Azure OpenAI detection (hasApiKey check)
- Fix OpenRouter priority over Azure (removed from CI env)
- Fix npm CVE hunt CLI path

## Still building (background agents)

| Agent | Feature | Expected impact |
|-------|---------|-----------------|
| Reachability gate | Static call graph before LLM | 80% SCA noise cut (Endor moat) |
| Assistant memories | Per-target persistent FP context | 2.8x multiplier (Semgrep) |
| Multi-modal | pwnkit × foxguard agreement | Portfolio killer feature |
| PoV generation gate | "No working PoC → FP" | Empirical ground truth |
| Adversarial debate | Prosecutor vs defender | Uncorrelated error modes |

## FP Reduction Stack

Target: 50% → <5% FP rate (Endor Labs parity)

| Step | Technique | Status |
|------|-----------|--------|
| 1 | Decomposed verify pipeline (7 subtasks) | SHIPPED |
| 2 | Evidence gating (MAPTA) | SHIPPED (via EGATS) |
| 3 | Holding-it-wrong filter | SHIPPED |
| 4 | Feature extractor (45 features) | SHIPPED |
| 5 | Per-class oracles | SHIPPED |
| 6 | Self-consistency voting | SHIPPED |
| 7 | Reachability gate | BUILDING |
| 8 | Multi-modal agreement | BUILDING |
| 9 | PoV generation gate | BUILDING |
| 10 | Adversarial debate | BUILDING |
| 11 | Assistant memories | BUILDING |

## Issues

**Closed today:** #22, #23, #25, #26, #27, #28, #29, #30, #31, #32, #33, #34, #35, #36, #37, #38, #43, #44

**Still open:**
- #39 — ML finding triage (infrastructure mostly shipped, needs training)
- #40 — XBOW 85%+ (achieved: 86.5%, can close)
- #41 — LLM context compaction A/B test
- #42 — Multi-model ensemble (OpenRouter shipped, needs benchmark)
- #45 — ML research landscape (research done)

**Need to create (gh auth blocked):**
- "Scanner tuning: holding-it-wrong filter" — body ready at /tmp/issue-scanner-tuning.md
- "FP reduction moat" — 8 techniques from research synthesis

## Blocking

1. **gh auth** — broken, blocks: issue creation, CI trigger, CI status check
   - Fix: `gh auth logout -h github.com && gh auth login -h github.com --web`
   - Or use PAT: `gh auth login --with-token`

## Next actions (after gh auth fix)

1. Create the 2 pending issues
2. Retrigger npm CVE hunt — measure FP rate with new triage system
3. Retrigger XBOW 14 unsolved with all new playbooks
4. Update benchmark docs with whatever results come back
