---
title: FP Reduction Moat
description: The full stack of false-positive reduction techniques shipped in pwnkit's triage pipeline, with published numbers per technique and the 50% to under-5% progression.
---

pwnkit's triage pipeline is designed so every finding passes through a stack of independent filters, each trained or tuned against a different failure mode. The stack mirrors the disclosed architectures of Endor Labs and Semgrep Assistant — except every layer is open-source. This page documents what we shipped, why each layer exists, and the FP reduction we expect from it based on published numbers.

> **Where to read next:** the [Finding Triage ML](/research/finding-triage-ml/) page is the design doc with the feature-list, datasets, and planned Layer-2 CodeBERT fine-tune. The [Architecture](/architecture/) page shows how the triage stage slots into the overall pipeline.

## Research synthesis

Every disclosed production triage system converges on the same shape: **rules + reachability + neural + memory**. The numbers:

| System | Disclosed FP reduction | What they do |
|--------|------------------------|--------------|
| Endor Labs AI SAST | ~95% FP elimination | Rules + reachability dataflow via proprietary "Code API" + LLM reasoning. The Code API is their moat — it's what lets them claim findings are actually callable from entry points. |
| Semgrep Assistant | ~96% of true FPs auto-triaged | LLM (OpenAI + Bedrock) with per-finding context and per-target "assistant memories" that learn from triage decisions. |
| Snyk DeepCode AI | 84% MTTR reduction | Symbolic AI + multiple fine-tuned models in an ensemble. |
| GitHub Security Lab taskflow-agent | ~30 real vulns surfaced (open-source reference) | GPT-4.1 with 7+ YAML subtasks per alert — the reference architecture for structured decomposition. |
| VulnBERT (Guanni Qu, Pebblebed) | 92.2% recall / 1.2% FPR on kernel commits | Hybrid: CodeBERT + 51 handcrafted features fused via cross-attention. Ablation: features alone 76.8%/15.9%, CodeBERT alone 84.3%/4.2%, hybrid 92.2%/1.2%. |

### Research papers we implemented directly

| Paper | Reference | Layer |
|-------|-----------|-------|
| FalseCrashReducer | [arXiv:2510.02185](https://arxiv.org/abs/2510.02185) | Crash validation agent that must reproduce the crash -> basis for "must produce a working PoC" gating. |
| All You Need Is A Fuzzing Brain | [arXiv:2509.07225](https://arxiv.org/abs/2509.07225) | Empirical evidence that agents failing to build an executable PoC in N turns almost always are on a false positive. Direct basis for `triage/pov-gate.ts`. |
| MAPTA | [arXiv:2508.20816](https://arxiv.org/abs/2508.20816) | Evidence-gated branching: don't expand an exploitation path without concrete prior-step evidence. Basis for EGATS (`agent/egats.ts`) and the "no speculation" posture of every verify layer. |
| Anthropic Debate | [arXiv:2402.06782](https://arxiv.org/abs/2402.06782) | Adversarial verification — two agents argue, a weaker judge decides. Reserved for the planned debate layer. |
| IBM D2A | [arXiv:2102.07995](https://arxiv.org/abs/2102.07995) | TP/FP labels for static analysis findings derived from differential analysis across commit boundaries. Training corpus target for the Layer-2 CodeBERT fine-tune. |
| VulnBERT | [Pebblebed blog](https://pebblebed.com/blog/kernel-bugs) | Hybrid handcrafted + neural + cross-attention. Basis for the Layer 1 feature extractor and planned Layer 3 fusion head. |

## The stack (50% -> under 5%)

Each layer rejects or downgrades a fraction of the false positives that survived the previous layer. The numbers below are published figures for the reference technique — not a promise for any particular pwnkit scan — but they show the shape of the stack.

| # | Layer | Module | Expected FP reduction (reference) | Acts on |
|---|-------|--------|-----------------------------------|---------|
| 0 | Raw agent findings | `agentic-scanner.ts` | baseline (~50% FP on noisy targets) | — |
| 1 | Holding-it-wrong filter | `triage/holding-it-wrong.ts` | Removes library-API-as-vuln category entirely | Sink name |
| 2 | Feature extractor (45 features) | `triage/feature-extractor.ts` | 15.9% FPR alone (VulnBERT ablation) | Finding fields |
| 3 | Reachability gate | `triage/reachability.ts` | Large (Endor Labs' ~95% headline depends on this) | Source tree |
| 4 | Per-class oracles | `triage/oracles.ts` | Exploitable-only acceptance | Live target |
| 5 | Multi-modal (foxguard) | `triage/multi-modal.ts` | Mirrors Endor Labs' rules+neural agreement (~95% class) | Source tree |
| 6 | Structured 4-step verify | `triage/verify-pipeline.ts` | GitHub Security Lab reference (~30 real vulns surfaced from noise) | Finding + target |
| 7 | Consensus (self-consistency) | `verify-pipeline.ts` `runSelfConsistencyVerify` | Self-consistency voting converts single-run variance into stable majority | Finding + target |
| 8 | PoV gate | `triage/pov-gate.ts` | "Fuzzing Brain" empirical: no PoC = almost always FP | Live target |
| 9 | Triage memories | `triage/memories.ts` | Semgrep Assistant ~96% auto-triage (with user feedback) | Historical triage |
| 10 | Adversarial debate (planned) | — | Anthropic debate reference | Finding + target |

**End-to-end target:** drive the ~50% raw FP rate toward **under 5%** — matching Endor Labs' 95% and Semgrep Assistant's 96% disclosed numbers — while retaining >=95% recall.

### Why the stack ordering matters

Layers 1-3 are free (no LLM cost). Anything rejected here saves LLM spend on the later layers.

- **Layer 1 (holding-it-wrong)** is pure blocklist — microsecond cost, ~100% precision when it fires.
- **Layer 2 (features)** is regex and string ops — sub-millisecond, provides a fast prior for later layers.
- **Layer 3 (reachability)** is grep over the source tree — milliseconds, kills findings in dead code.

Layers 4-5 require either a live target (oracles) or a local tool (foxguard) but no LLM spend.

- **Layer 4 (oracles)** attempts the exploit deterministically. Verified = accept with zero LLM cost.
- **Layer 5 (multi-modal)** is a second, fully independent scanner. Agreement doubles the confidence; disagreement flags review.

Layers 6-10 spend LLM tokens, but only on findings that survived the free layers.

- **Layer 6 (structured verify)** is a 4-step decomposition with category-specific addendums — the GitHub Security Lab reference architecture.
- **Layer 7 (consensus)** converts single-shot variance into a stable majority vote, with early termination once a verdict can't be overturned.
- **Layer 8 (PoV gate)** enforces "no executable exploit = no finding" — the hardest filter in the stack.
- **Layer 9 (memories)** recycles prior human triage decisions so known FP patterns auto-reject without any verify cost.
- **Layer 10 (debate)** is the final tie-breaker, reserved for cases the rest of the stack couldn't resolve.

## Our implementation notes

### Every layer ships as a feature flag

See `packages/core/src/agent/features.ts`. Flags:

- `PWNKIT_FEATURE_REACHABILITY_GATE`
- `PWNKIT_FEATURE_MULTIMODAL`
- `PWNKIT_FEATURE_POV_GATE`
- `PWNKIT_FEATURE_CONSENSUS_VERIFY`
- `PWNKIT_FEATURE_TRIAGE_MEMORIES`
- `PWNKIT_FEATURE_DEBATE` (planned)

This lets us A/B test each layer independently in CI against the XBOW benchmark and measure its marginal FP reduction.

### Conservative by default

Every layer errs toward **keeping** findings when it's not confident. Reachability returns `reachable: true` with low confidence when its grep-based first pass can't reach a verdict. Memories only auto-reject on strong matches above a tunable score threshold. Consensus defaults ties to `rejected` but the caller can opt out. The stack is designed so each layer adds precision without costing recall on the next.

### foxguard × pwnkit is unique

No other open-source pentest agent runs a second, fully independent scanner for cross-validation. This is the pwnkit / foxguard / opensoar trinity — pwnkit detects, foxguard cross-checks, opensoar responds. It's the open-source analogue of Endor Labs' rules + neural agreement architecture.

### Zero proprietary dependencies

- Reachability gate is grep/pattern-based — no LSP server, no compiled call graph, no Code API license.
- Feature extractor is regex — no embedding model, no GPU.
- Oracles use `fetch` and `createServer` — no external exploit framework.
- Multi-modal runs foxguard via `execFile` — no vendor API.
- Memories use the existing SQLite store — no vector DB.

Everything here can run on a developer laptop, in CI, or in an air-gapped environment.

## Related

- [Finding Triage ML](/research/finding-triage-ml/) — the design doc, feature list, datasets, and planned Layer 2/3 neural components.
- [Agent Techniques](/research/agent-techniques/) — attack-phase techniques (early-stop, playbooks, EGATS, racing, handoff).
- [Architecture](/architecture/) — how the triage stage fits into the overall plan-discover-attack-verify-report pipeline.
- [Competitive Landscape](/research/competitive-landscape/) — how pwnkit's stack compares to BoxPwnr, Shannon, KinoSec, and the academic agents.
