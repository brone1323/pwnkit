---
title: Research
description: Why pwnkit uses a shell-first approach, what data backs our decisions, and experiments from building the pentesting agent.
---

This page is the single source of truth for "why we made these decisions and what data backs them up." All experiments run against the [XBOW benchmark](https://github.com/xbow-engineering/validation-benchmarks) (104 Docker CTF challenges). For benchmark scores and flag tables, see [Benchmark](/benchmark/).

## Topics

### [Adversarial Evals](/adversarial-evals/)

Why attack-driven evaluation is a better fit than generic judge-model evals
for high-stakes AI systems, and how pwnkit can expose that category
without weakening the pentest wedge.

### [Triage Dataset](/research/triage-dataset/)

How benchmark runs and verified findings are converted into labeled JSONL
for triage-model training.

### [Feature Extractor](/research/feature-extractor/)

The 45 handcrafted features exposed by `extractFeatures()` and how they fit
into the hybrid triage direction.

### [Agent Techniques](/research/agent-techniques/)

What shipped in the agent loop: planning, reflection checkpoints, context compaction, dynamic playbooks, progress handoff, and EGATS.

### [FP Reduction Moat](/research/fp-reduction-moat/)

The full false-positive reduction stack, why the layers are ordered the way they are, and how the dataset / feature foundation supports the shipped runtime layers.

### [2026-04-11 Triage Ablation Results](/research/2026-04-11-ablation/)

The archival experiment log for the 21-profile triage ablation, with batch-1 and batch-2 numbers, methodology notes, and links to raw run artifacts.

### [Finding Triage ML](/research/finding-triage-ml/)

Implementation notes for reachability, consensus verify, PoV generation, memories, adversarial debate, and multi-modal agreement with foxguard.

### [Shell-First Rationale](/research/shell-first/)

Why bash beats structured tools for pentesting. Includes A/B test data on prompt length, reasoning effort, sub-agent spawning, tool routing, and multi-checkpoint budgets.

### [Model Comparison](/research/model-comparison/)

Head-to-head testing of gpt-5.4, Kimi K2.5, Qwen3 Coder, DeepSeek, GLM, and free OpenRouter models. Cost, speed, and flag extraction across multiple XBOW challenges.

### [XBOW Analysis](/research/xbow-analysis/)

Shannon gap analysis, competitor verification, what moves the score, white-box vs black-box results, critical bugs found, and future benchmark targets (AutoPenBench, HarmBench, JailbreakBench). The exact current pwnkit numbers live on the [Benchmark](/benchmark/) page because the retained artifact-backed tally and the older historical publication line are tracked separately.

### [Competitive Landscape](/research/competitive-landscape/)

Full competitor breakdown (Shannon 96%, KinoSec 92%, Cyber-AutoAgent 84%, deadend-cli 78%, MAPTA 77%), 10 ranked improvement techniques with expected impact, key research papers, and what we've shipped vs what's next.

## The big picture

pwnkit is not a template runner or static analyzer. It's an autonomous agent that thinks like a pentester. Pentesters use terminals, not GUIs with dropdowns.

The scanner should feel like giving a skilled pentester SSH access. One command. Full autonomy. Real findings with proof.

**The conclusion:** the framework should get out of the model's way. 3 tools, a 25-line prompt, and let the model's training do the work. The ceiling is the model, not the framework.
