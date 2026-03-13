> **ARCHIVED** — This is the v11 pipeline preserved for historical reference. See `bb_pipeline_v12.md` for the current pipeline.

# Bug Bounty Pipeline v11 — Kill Gate Detail

Referenced from CLAUDE.md. This file contains the full phase-by-phase procedure.

## Phase 0: Target Intelligence

0. `TeamCreate("mission-<target>")`
1. `target-evaluator` → program analysis, competition, tech stack match → `target_assessment.md`
   - **GO** (8-10): full pipeline
   - **CONDITIONAL GO** (5-7): limited scope + token budget
   - **NO-GO** (0-4): stop immediately
   - Kill Signal = instant NO-GO (deprecated, OOS, ghost program)
   - **OOS Exclusion Pre-Check (MANDATORY)**:
     - Check program "Out of Scope" items exhaustively
     - Cross-check `immunefi.com/common-vulnerabilities-to-exclude/`
     - Especially: "Incorrect data supplied by third party oracles" (oracle staleness = OOS)
     - Check Known Issues / audit tracking docs
     - If candidate vuln type matches OOS → instant NO-GO

## Phase 0.2: Program Rules Generation (MANDATORY)

Orchestrator runs directly (not agent):
```bash
python3 tools/bb_preflight.py init targets/<target>/
# Fill program_rules_summary.md: auth header format, required headers, Known Issues, exclusion list
# Verify actual auth from API traffic (Frida/mitmproxy/curl)
python3 tools/bb_preflight.py rules-check targets/<target>/
```
- PASS → proceed | FAIL → repeat until filled. **No agent spawn until PASS.**
- Why: NAMUHX reporter used wrong auth format (`Bearer` vs `IdToken:`)

## Phase 0.5: Automated Tool Scan

scout runs Slither/Semgrep (DeFi targets):
- `slither .` → `slither_results.json`
- `myth analyze` → `mythril_results.json`
- `semgrep --config auto` → `semgrep_results.json`
- Results go to analyst — analyst starts from tool results, not code reading

**Code Path Activation Check (DeFi MANDATORY)**:
```bash
cast call <vault_addr> "decimalsOffset()(uint8)" --rpc-url $RPC_URL
cast call <pool_addr> "fee()(uint256)" --rpc-url $RPC_URL
```
- All disabled(0) → "latent bug" → severity downgrade (Kiln lesson: 5 vaults all offset=0 → CLOSED $0)

## Phase 1: Discovery

Parallel spawn:
- `scout` → Duplicate Pre-Screen + nmap/ffuf + Program Context + Tool Scan + `endpoint_map.md`
- `analyst` → reads program_rules_summary.md + exclusion filter → tool results first → source analysis → `vulnerability_candidates.md`
- **Inject program rules**: `python3 tools/bb_preflight.py inject-rules targets/<target>/` output in prompt top 3 lines
- **Inject exclusion filter**: `python3 tools/bb_preflight.py exclusion-filter targets/<target>/`

### Phase 1.5: Parallel Hunting (Shannon Pattern — 10K+ LOC only)

Optional. N parallel hunters by vuln-category:
```
analyst (mode=injection|ssrf|auth|crypto|bizlogic|fileupload)
```
Merge results → vulnerability_candidates.md sorted by confidence. Token 4-6x increase — skip for <5K LOC.

### Phase 1→2 Gate: Coverage Check (Web/API MANDATORY)

```bash
python3 tools/bb_preflight.py coverage-check targets/<target>/
# PASS (≥80%) → Phase 2 | FAIL → additional analyst rounds for UNTESTED endpoints
```

## Kill Gate 1: Finding Viability (MANDATORY before PoC)

`triager-sim` (model=**sonnet**, mode=finding-viability) per candidate:
- Input: 1-paragraph finding summary + prerequisites (no report, no PoC)
- Pre-check: `python3 tools/bb_preflight.py kill-gate-1 targets/<target>/ --finding "<finding>"`

**5-Question Destruction Test:**
1. FEATURE CHECK: documented/intended behavior? → YES = KILL
2. SCOPE CHECK: Out-of-Scope per program brief? → YES = KILL
3. DUPLICATE CHECK: same root cause as previous/known CVE? → YES = KILL
4. PREREQUISITE CHECK: attacker prerequisite ≥ impact? → YES = KILL
5. LIVE PROOF CHECK: provable with live evidence? → NO = KILL

Verdict: GO (5/5 pass) | CONDITIONAL GO (1 uncertain) | KILL (1+ definitive fail)
**IRON RULE: No exploiter spawn without Gate 1 pass.**

## Phase 2: PoC Validation

`exploiter` → PoC development + runtime verification:
- Use auth from program_rules_summary.md (inject-rules in prompt)
- Skip Duplicate Risk HIGH findings
- Integration Test: `npm install <pkg>` → real API → listener capture
- PoC Quality Tier: Tier 1-2 → Phase 3 / Tier 3-4 → delete
- Post-PoC Self-Validation 5 questions
- Update endpoint_map.md (VULN/SAFE/TESTED)
- **Driver/Library Verification (MANDATORY)**: verify target's actual driver before PoC run
- **Target-OS Evidence**: Windows claim needs Windows evidence (not bash)
- PASS → Gate 2 | FAIL → delete candidate

## Kill Gate 2: Pre-Report Destruction (MANDATORY before report)

`triager-sim` (model=**opus**, mode=poc-destruction):
- Input: PoC script + evidence output only (no report)
- Pre-check: `python3 tools/bb_preflight.py kill-gate-2 targets/<target>/submission/<name>/`

**3-Section Destruction Test:**

SECTION A — Evidence Quality (any NO without fix path = KILL):
1. LIVE vs MOCK: PoC runs against REAL target?
2. PROVEN vs INFERRED: every claimed impact directly demonstrated?
3. ENVIRONMENT MATCH: test env = claimed attack target?

SECTION B — Triager Objections:
4. Top 3 objections a triager would raise
5. Hard counter in evidence for each? YES=quote line, NO=gap(STRENGTHEN)

SECTION C — Severity Reality:
6. PREREQUISITE vs IMPACT: meaningful beyond prerequisite?
7. RAW CVSS: based purely on PoC evidence

Verdict: GO | STRENGTHEN (max 2x, 3rd = auto KILL) | KILL
**IRON RULE: No reporter spawn without Gate 2 GO.**

## Phase 3: Report Writing

`reporter` → draft + CVSS + **bugcrowd_form.md (MANDATORY)**:
- Observational language ("identified in reviewed code")
- Conditional CVSS table
- Executive Conclusion 3 sentences at top
- **bugcrowd_form.md**: Title, Target, VRT, Severity, CVSS, URL/Asset, Attachments, Checklist
- **VRT from `bugcrowd.com/vulnerability-rating-taxonomy`** (WebFetch) — match root cause, not impact
- **Conservative CVSS**: no unproven metrics (A:H without benchmark → A:L)
- **"What This Report Does NOT Claim" section (MANDATORY)**
- **File Path Verification**: all `file:line` refs verified via glob/find

## Phase 4: Review Cycle

1. `critic` → fact-check only (CWE, dates, function names, line numbers, file paths)
   - Documented Feature Check + Driver/Library Match Check
   - Phase 4 fundamental KILL = Gate 2 failure → Gate 2 prompt retrospective
2. `architect` → consistency (report-PoC-evidence alignment)
3. Optional: user external review

## Phase 4.5: Triager Simulation

`triager-sim` (mode=report-review):
- SUBMIT → Phase 5 | STRENGTHEN → reporter fix → re-run | KILL → delete finding
- AI Slop Score check (≤2 PASS, 3-5 STRENGTHEN, >5 KILL)
- Evidence-Target Alignment Check
- File Path Verification
- Gate Feedback Loop: KILL here = Gate 2 bug → update Gate 2 prompt

## Phase 5: Finalization

`reporter` → unify language, reframing, ZIP packaging
- Cluster submission (same codebase = same day)
- **VRT + Bugcrowd Form final verification checklist**

## Phase 6: Cleanup

TeamDelete

## BB Core Rules

- No PoC = No submit (IRON RULE)
- Phase 0 mandatory — NO-GO = stop
- No submit without triager-sim SUBMIT
- Tier 1-2 only — Tier 3-4 = auto delete
- Duplicate Pre-Screen mandatory
- PoC before report (never report-only)
- Same root cause = bundle
- Check CVSS version (3.1 vs 4.0)
- No V8 prototype pollution solo claims
- No LLM echo claims
- 3-layer remediation preferred
- Anti-AI slop: target-specific details, no template language
- VRT = Priority determinant (not CVSS alone)
- bugcrowd_form.md mandatory
- Bounty table verification mandatory
- Kill Gate without pass = no report (v11 IRON RULE)
- Gate 2 STRENGTHEN max 2x
- Phase 4.5 KILL = Gate bug → feedback loop

## Quality-First Rules

### No Direct Orchestrator Analysis
Orchestrator reads agent artifacts only, never source code directly.

### Quality over Quantity
3 contracts at Level 2-4 > 16 contracts at Level 0-1

### Tool-First Gate (DeFi/Smart Contract)
1. Slither → 2. Mythril → 3. Foundry fork → 4. Semgrep/CodeQL → 5. Manual review of HIGH+ only

### ABANDON Checklist (all must be checked before ABANDON)
- [ ] Slither/Mythril complete? (Smart Contract)
- [ ] CodeQL/Semgrep complete? (All targets)
- [ ] Foundry fork on-chain verification? (DeFi)
- [ ] Gemini triage complete? (5K+ LOC)
- [ ] Minimum Level 2 depth reached?
- [ ] analyst delegated ≥1 hour?
- [ ] Manual review ≤3 contracts?

### Analysis Depth Levels
```
Level 0: grep pattern matching (insufficient alone)
Level 1: Gemini triage + Semgrep auto-scan
Level 2: CodeQL taint tracking + 3-pass source→sink (standard)
Level 3: Protocol/business logic + Gemini deep modes
Level 4: Smart contract — Slither + Mythril + Foundry fork (Web3)
```
Level 0-1 only → cannot declare "0 findings". DeFi → Level 4 mandatory.

### Hard NO-GO Rules (override impossible)
```
3+ audits = AUTO NO-GO
2+ reputable audits (Nethermind, OZ, ToB, Zellic, Spearbit) = AUTO NO-GO
100+ resolved reports = AUTO NO-GO
Operating 3+ years = AUTO NO-GO
Last commit >6mo + 2+ audits = AUTO NO-GO
Source private/inaccessible = AUTO NO-GO
Fork → original audit + fix commits all applied = AUTO NO-GO
DeFi → cast call mandatory in Phase 0
```

### Target Selection (success pattern from 37 submissions)
Prioritize: open source, locally testable, low external dependency, business logic category, <6mo or scope expansion, multi-root-cause potential

### Time-Box
```
Phase 0: 45min | Phase 0.5: 30min | Phase 1: 2hr | Phase 2: 3hr | Phase 3-5: 2hr
Total: 8hr (general) / 12hr (DeFi)
No HIGH+ signal at 2hr → ABANDON (after checklist)
```

### Anti-AI Detection
- Specific block number or tx hash in report
- Vary report structure each time
- Observational language ("reviewed implementation")
- Zero template phrases
- AI Slop Score ≤2/10
- At least 1 unique analysis element

### Platform Priority
Bugcrowd (PRIMARY, 40% success) > HackenProof (Web3) > PSIRT Direct > Immunefi (<6mo+≤1audit) > Intigriti/YesWeHack > H1 (paused)

### Immediate Submission Rule
Report complete + triager-sim SUBMIT → submit within 24hr. reporter auto-generates submission/ folder + ZIP in Phase 5.
