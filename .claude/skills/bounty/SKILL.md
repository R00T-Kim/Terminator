---
name: bounty
description: Start Bug Bounty target analysis pipeline. Auto-matches "bounty", "target analysis", "find vulns", "bug hunting", "Immunefi", "Bugcrowd", "H1"
argument-hint: [target-url-or-name] [scope]
context: fork
effort: high
model: opus
---

# Bug Bounty Pipeline (v4 — Explore Lane)

## CRITICAL RULES (NEVER VIOLATE)
1. **No PoC = No Submission** — reports without exploitation path are 100% Informative
2. **Quality > Quantity** — 3 deep-dives > 16 skims. Tool-First (Slither/CodeQL before code)
3. **Orchestrator MUST NOT analyze directly** — delegate to agents. Reading code directly = context waste
4. **Agent model parameter MANDATORY** — unspecified model inherits opus = 3-5x token waste

## Pre-checks (auto-executed)

Program rules check:
!`if [ -d "targets/$1" ]; then cat "targets/$1/program_rules_summary.md" 2>/dev/null | head -20 || echo "rules not generated"; fi`

Existing findings check:
!`python3 /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/tools/knowledge_indexer.py search "$ARGUMENTS" 2>/dev/null | head -10 || echo "search unavailable"`

## Pipeline Rules

**MUST use Agent Teams.** Orchestrator directly reading and analyzing code is FORBIDDEN.
Subagent spawn uses `Task` or `Agent` tool depending on Claude build, but `subagent_type` is always canonical hyphen-case (`target-evaluator`, `triager-sim`).

### Phase 0: Target Intelligence
1. `TeamCreate("mission-<target>")`
2. `target-evaluator` (model=sonnet) → GO/NO-GO verdict
   - **Hard NO-GO (v6)**: 3+ audits, 2+ reputable audits, 100+ reports, 3yr+, source inaccessible
   - NO-GO → stop immediately, evaluate another target
3. **Run `oos-check` skill** — full program OOS scan
4. Use target-evaluator's `suggested_searches` for knowledge-fts → inject `[KNOWLEDGE CONTEXT]` into HANDOFF

### Phase 0.2: Program Rules Generation (MANDATORY)
```bash
python3 tools/bb_preflight.py init targets/<target>/
# Fill program_rules_summary.md (auth format, Known Issues, exclusion list)
python3 tools/bb_preflight.py rules-check targets/<target>/
# FAIL = Phase 1 blocked
```

### Phase 0.5: Automated Tool Scan
- scout runs Slither/Semgrep/CodeQL auto-scan (DeFi targets)
- **analyst MUST NOT read code without tool results first**

### Phase 1: Discovery (v12 — Explore Lane)
- scout (model=sonnet) + analyst (model=sonnet) parallel spawn
- **threat-modeler (model=sonnet, v12 NEW)** → trust boundaries, role matrix, state machines, invariants
- **patch-hunter (model=sonnet, v12 NEW)** → variant candidates from security commits
- inject-rules output in prompt lines 3-5 (lines 1-2 = Critical Facts)
- On each finding: `oos-check` pattern match (OOS BLOCK → auto-exclude)

### Phase 1.5: Deep Exploration (v12 NEW)
- **workflow-auditor (model=sonnet)** → workflow state transitions, anomaly flags
- web-tester (model=sonnet) → request-level + workflow pack testing
- Reads: workflow_map.md, invariants.md, trust_boundary_map.md

### Phase 1→2 Gate: Coverage + Workflow Check (v12)
- **Run `coverage-gate` skill** (risk-weighted in v12: HIGH endpoints count 2x):
```bash
python3 tools/bb_preflight.py coverage-check targets/<target>/ --json
# ≥80% risk-weighted → Phase 2 / <80% → additional round
```
- **Workflow check (v12 NEW)**:
```bash
python3 tools/bb_preflight.py workflow-check targets/<target>/
# PASS → Phase 2 / FAIL → workflow-auditor supplement
```
- **Fresh-surface check (v12 NEW, for CONDITIONAL GO targets)**:
```bash
python3 tools/bb_preflight.py fresh-surface-check targets/<target>/
```

### Phase 2: PoC Validation
- exploiter (model=opus) → only PoC Quality Tier 1-2 pass
- **`poc-tier` skill for Tier verification** — Tier 3-4 = DROPPED
- **`threat-model-check` skill for prerequisite validation** — BLOCK = do not send to exploiter
- exploiter MUST update endpoint_map.md
- **Evidence tier check (v12 NEW)**:
```bash
python3 tools/bb_preflight.py evidence-tier-check targets/<target>/submission/<name>/
# E1/E2 → Gate 2 / E3/E4 → explore_candidates.md
```
- **Duplicate graph check (v12 NEW)** at Gate 2:
```bash
python3 tools/bb_preflight.py duplicate-graph-check targets/<target>/ --finding "<desc>"
```

### Phase 3-5: Report → Review → Finalize
- reporter → critic + architect → triager-sim → reporter (final)
- **`slop-check` skill for AI slop score** (≤2 PASS, 3-5 STRENGTHEN, >5 KILL)
- triager-sim outputs `triager_sim_result.json` → reporter auto-feedback loop (max 3 rounds)
- No submission without triager-sim SUBMIT
- **`checkpoint-validate` skill for idle agent detection** (as needed)

### Phase 6: Cleanup
- TeamDelete

## Time-Box Enforcement
- Phase 0: 45min MAX | Phase 0.5: 30min MAX | Phase 1: 2hr MAX
- Phase 2: 3hr MAX | Phase 3-5: 2hr MAX | Total: 8hr (12hr DeFi)
- No HIGH+ signal at 2hr mark → ABANDON (after checklist pass)

> **REMINDER**: No PoC = No Submission. Quality over Quantity. Orchestrator delegates, never analyzes directly. Evidence Tier E1/E2 required for submission. Triage feedback checked before every Gate.
