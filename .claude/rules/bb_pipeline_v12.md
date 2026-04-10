# Bug Bounty Pipeline v12 — Explore Lane + Kill Gate

Referenced from CLAUDE.md. This file contains the full phase-by-phase procedure. Supersedes v11.

## Architecture: Explore Lane + Prove Lane

v12 splits the pipeline into two lanes:
- **Explore Lane** (Phases 0–1.5): Discover, model, understand. Kill bad targets and OOS early, but keep borderline findings alive in explore_candidates.md.
- **Prove Lane** (Phases 2–6): Validate, gate, submit. Only E1/E2 evidence proceeds to submission. Kill Gate rigor preserved from v11.

```
EXPLORE LANE                                              PROVE LANE
┌─────────────────────────────────────────┐   ┌──────────────────────────────────────┐
│ Phase 0:   target-evaluator (+ novelty) │   │ ★ Gate 1: triager-sim (finding)      │
│ Phase 0.2: bb_preflight rules           │   │ Phase 2:  exploiter (E1-E4 tiers)    │
│ Phase 0.5: automated tool scan          │   │ ★ Gate 2: triager-sim (PoC)          │
│ Phase 1:   scout + analyst + threat-    │   │ Phase 3:  reporter                   │
│            modeler + patch-hunter       │   │ Phase 4:  critic + architect          │
│ Phase 1.5: workflow-auditor + web-tester│   │ Phase 4.5:triager-sim (report)       │
│ ★ Gate 1→2: coverage + workflow check   │   │ Phase 5:  reporter (finalize)        │
└─────────────────────────────────────────┘   │ Phase 6:  TeamDelete                 │
                                               └──────────────────────────────────────┘
```

---

## EXPLORE LANE

### Phase 0: Target Intelligence

1. `TeamCreate("mission-<target>")`
2. `target-evaluator` (model=sonnet) → program analysis, competition, tech stack match, **Research Novelty Score (v12)** → `target_assessment.md`
   - **GO** (48-60): full pipeline
   - **CONDITIONAL GO** (30-47): limited scope + token budget
   - **NO-GO** (<30 or Hard NO-GO): stop immediately
   - Kill Signal = instant NO-GO (deprecated, OOS, ghost program)
   - **Fresh-Surface Exception (v12)**: Mature target with new modules/bridges/migrations in last 6 months → CONDITIONAL GO for new surface only
   - **OOS Exclusion Pre-Check (MANDATORY)**:
     - Check program "Out of Scope" items exhaustively
     - Cross-check `immunefi.com/common-vulnerabilities-to-exclude/`
     - Especially: "Incorrect data supplied by third party oracles" (oracle staleness = OOS)
     - Check Known Issues / audit tracking docs
     - If candidate vuln type matches OOS → instant NO-GO

### Phase 0.2: Program Rules Generation (MANDATORY)

Orchestrator runs directly (not agent):
```bash
python3 tools/bb_preflight.py init targets/<target>/
# Fill program_rules_summary.md: auth header format, required headers, Known Issues, exclusion list
# Verify actual auth from API traffic (Frida/mitmproxy/curl)
python3 tools/bb_preflight.py rules-check targets/<target>/
```
- PASS → proceed | FAIL → repeat until filled. **No agent spawn until PASS.**

### Phase 0.5: Automated Tool Scan

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
- All disabled(0) → "latent bug" → severity downgrade

#### Discovery vs Exploitation Cost Principle (Anthropic Firefox)

발견 비용은 익스플로잇의 1/10 수준 (Firefox: 발견 $수백 vs 익스플로잇 $4,000).
Phase 1은 **넓고 빠르게**, Phase 2는 **좁고 깊게** 운영:

- Phase 1: analyst confidence **5/10 이상**이면 모두 후보 유지 (7+ 우선 전달, 5-6도 리스트 유지)
- Phase 1.5: 후보가 5개 미만이면 추가 analyst 라운드 (dynamic budget +2)
- Phase 2: confidence 7+ 먼저 exploiter 투입, 그 다음 5-6 순서
- **Quantity in Discovery, Quality in Exploitation** — 발견은 FP 허용, 증명은 FP 불허

#### Graphify Pre-Analysis (10K+ LOC targets — OPTIONAL)

대형 코드베이스에서 Phase 1 전에 구조 이해 가속:
```bash
graphify <target_source_dir> --no-viz   # AST + 클러스터링 → graph.json + GRAPH_REPORT.md
graphify query "authentication flow"     # 구조 쿼리 (71.5x 토큰 효율)
```
- **God Nodes**: GRAPH_REPORT.md의 최다 연결 노드 → analyst manual review 우선 대상
- **Surprising Connections**: 예상 밖 관계 → 숨겨진 공격 경로 후보
- Orchestrator가 결과를 analyst/scout 핸드오프에 포함

### Phase 1: Discovery (EXPANDED in v12)

Parallel spawn — up to 4 agents:
- `scout` (model=sonnet) → `endpoint_map.md` (risk-weighted) + `workflow_map.md` (v12) + `program_context.md`
- `analyst` (model=sonnet) → reads program_rules_summary.md + tool results → `vulnerability_candidates.md` (dynamic review budget v12)
- `threat-modeler` (model=sonnet, **v12 NEW**) → `trust_boundary_map.md`, `role_matrix.md`, `state_machines.md`, `invariants.md`
- `patch-hunter` (model=sonnet, **v12 NEW**) → `patch_analysis.md` (variant candidates from security commits)

- **Inject program rules**: `python3 tools/bb_preflight.py inject-rules targets/<target>/` output in prompt top 3 lines
- **Inject exclusion filter**: `python3 tools/bb_preflight.py exclusion-filter targets/<target>/`

### Phase 1.5: Deep Exploration (v12 NEW)

After Phase 1 artifacts are produced:
- `workflow-auditor` (model=sonnet, **v12 NEW**) → reads state_machines.md + endpoint_map.md → `workflow_map.md` (refined with anomaly flags)
- `web-tester` (model=sonnet) → request-level testing + **workflow pack testing (v12)** using workflow_map.md and invariants.md
- `analyst` parallel hunting (optional, 10K+ LOC only) — now with dynamic budget and explore lane artifacts

### Phase 1→2 Gate: Coverage + Workflow Check (EXPANDED in v12)

```bash
# Coverage check (risk-weighted in v12: HIGH endpoints count 2x)
python3 tools/bb_preflight.py coverage-check targets/<target>/
# PASS (≥80% risk-weighted) → proceed | FAIL → additional rounds

# Workflow check (v12 NEW)
python3 tools/bb_preflight.py workflow-check targets/<target>/
# PASS (workflow_map.md exists with mapped workflows) → proceed | FAIL → scout/workflow-auditor supplement

# Fresh-surface check (v12 NEW — for mature targets with CONDITIONAL GO)
python3 tools/bb_preflight.py fresh-surface-check targets/<target>/
# FOUND → confirm new surface is in scope | NONE → maintain original NO-GO
```

---

## PROVE LANE

### Kill Gate 1: Finding Viability (MANDATORY before PoC)

`triager-sim` (model=**sonnet**, mode=finding-viability) per candidate:
- Input: 1-paragraph finding summary + prerequisites (no report, no PoC)
- **Pre-check (v12)**: scan `knowledge/triage_objections/` for same program feedback → calibrate
- Pre-check: `python3 tools/bb_preflight.py kill-gate-1 targets/<target>/ --finding "<finding>"`

**5-Question Destruction Test:**
1. FEATURE CHECK: documented/intended behavior? → YES = KILL
2. SCOPE CHECK: Out-of-Scope per program brief? → YES = KILL
3. DUPLICATE CHECK: same root cause as previous/known CVE? → YES = KILL
4. PREREQUISITE CHECK: attacker prerequisite ≥ impact? → YES = KILL
5. LIVE PROOF CHECK: provable with live evidence? → NO = KILL

Verdict: GO (5/5 pass) | CONDITIONAL GO (1 uncertain) | KILL (1+ definitive fail)
**IRON RULE: No exploiter spawn without Gate 1 pass.**

### Phase 2: PoC Validation (EXPANDED in v12)

`exploiter` (model=opus) → PoC development + runtime verification:
- Use auth from program_rules_summary.md (inject-rules in prompt)
- Skip Duplicate Risk HIGH findings
- **Evidence Tier classification (v12)**: E1/E2/E3/E4
  - E1/E2 → proceed to Gate 2
  - E3/E4 → log to `explore_candidates.md` → Orchestrator may re-explore
- **Evidence tier check (v12)**:
  ```bash
  python3 tools/bb_preflight.py evidence-tier-check targets/<target>/submission/<name>/
  # E1/E2 (exit 0) → Gate 2 | E3/E4 (exit 1) → explore_candidates.md
  ```
- PoC Quality: Tier 1-2 only for submission
- Post-PoC Self-Validation 8 questions (v12: includes evidence tier Q8)
- Update endpoint_map.md (VULN/SAFE/TESTED)
- PASS → Gate 2 | FAIL → explore_candidates.md or delete

#### Best@N for Exploiter (BB-specific)
When exploiter fails on a CONDITIONAL GO finding (SCONE-bench Best@N 방법론):
1. First attempt: standard exploiter with analyst's approach
2. If fail → re-spawn exploiter with different approach hint (e.g., different auth bypass, injection vector, exploit primitive)
3. Max 2 re-attempts per finding (total 3 tries). 3rd fail → archive to explore_candidates.md as "explored, not proven"
4. Each re-attempt MUST use a **different strategy** — same payload retry is forbidden

### Kill Gate 2: Pre-Report Destruction (MANDATORY before report)

`triager-sim` (model=**opus**, mode=poc-destruction):
- Input: PoC script + evidence output only (no report)
- **Pre-check (v12)**: scan `knowledge/triage_objections/` for same program → calibrate
- Pre-check: `python3 tools/bb_preflight.py kill-gate-2 targets/<target>/submission/<name>/`
- **Duplicate graph check (v12)**:
  ```bash
  python3 tools/bb_preflight.py duplicate-graph-check targets/<target>/ --finding "<desc>"
  # PASS → proceed | WARN → review duplicate candidates before submitting
  ```

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

### Phase 3: Report Writing

`reporter` → draft + CVSS + **bugcrowd_form.md (MANDATORY)**:
- Observational language ("identified in reviewed code")
- Conditional CVSS table
- Executive Conclusion 3 sentences at top
- **bugcrowd_form.md**: Title, Target, VRT, Severity, CVSS, URL/Asset, Attachments, Checklist
- **VRT from `bugcrowd.com/vulnerability-rating-taxonomy`** (WebFetch) — match root cause, not impact
- **Conservative CVSS**: no unproven metrics (A:H without benchmark → A:L)
- **"What This Report Does NOT Claim" section (MANDATORY)**
- **File Path Verification**: all `file:line` refs verified via glob/find
- **Platform Style**: reporter reads `context/report-templates/platform-style/<platform>.md` BEFORE writing
- **Writing Style**: reporter follows `context/report-templates/writing-style.md` (First 3 Sentences Rule)

#### Phase 3.5: Report Quality Loop (NEW)

After reporter saves draft, automated quality gate:
1. `python3 tools/report_scorer.py <report> --poc-dir <evidence/> --json`
2. Composite >= 75 → proceed | < 75 → reporter auto-fixes top priority_fixes → re-score (max 2x)
3. `python3 tools/report_scrubber.py <report>` — remove AI signatures (Unicode watermarks, em-dash overuse)
4. Score < 75 after 2 iterations → QUALITY_GATE_FAIL → Orchestrator decides: critic escalation or KILL
**IRON RULE: No Phase 4 without quality score >= 75.**

### Phase 4: Review Cycle

1. `critic` → fact-check only (CWE, dates, function names, line numbers, file paths)
   - Documented Feature Check + Driver/Library Match Check
   - Phase 4 fundamental KILL = Gate 2 failure → Gate 2 prompt retrospective
2. `architect` → consistency (report-PoC-evidence alignment)
3. **`codex:adversarial-review` (v12.1 NEW)** → cross-model design challenge
   - `/codex:adversarial-review --wait` on submission/ directory
   - GPT-5.4 independently challenges: threat model realism, CVSS justification, evidence gaps
   - CRITICAL ISSUE → reporter fix before Phase 4.5 | PASS → proceed
   - **AI Slop cross-check**: different model's writing patterns neutralize Claude-specific slop
4. Optional: user external review

### Phase 4.5: Triager Simulation

`triager-sim` (mode=report-review):
- SUBMIT → Phase 5 | STRENGTHEN → reporter fix → re-run | KILL → delete finding
- AI Slop Score check (≤2 PASS, 3-5 STRENGTHEN, >5 KILL)
- **Codex Slop cross-check (v12.1)**: `/codex:review --wait` on final report → Claude-blind patterns detected
- Evidence-Target Alignment Check
- File Path Verification
- Gate Feedback Loop: KILL here = Gate 2 bug → update Gate 2 prompt

### Phase 5: Finalization

`reporter` → unify language, reframing, ZIP packaging
- Cluster submission (same codebase = same day)
- **VRT + Bugcrowd Form final verification checklist**
- **Pre-submit Codex review (v12.1)**: `/codex:review --wait --base main` on submission/ → final cross-model sanity check
- **Evidence Manifest (NEW)**: `python3 tools/evidence_manifest.py <target_dir>` → `evidence_manifest.json`
  - Collects all artifacts with SHA256 hashes, checkpoint state, triager-sim results, report score
  - Validates critical artifacts present (exit 1 if missing)
  - Include in submission ZIP as audit trail

#### Cluster Submission Protocol (Anthropic Firefox)
같은 타겟에 2+ finding이 Gate 2 통과 시:
1. **같은 날 제출** — 단일 리뷰 세션 가능성 높음
2. **Root cause 번들링**: 동일 root cause → 하나의 리포트로 통합 (VRT 동일)
3. **Cross-reference**: 각 리포트에 관련 finding 참조 ("See also: Report #X")
4. **제출 순서**: 가장 높은 severity 먼저 (심사관 신뢰도 확보)
5. **ZIP 단일화**: 관련 finding들은 하나의 submission/ 디렉터리에 모아 ZIP

### Phase 6: Cleanup

TeamDelete

---

## Explore Lane Recycling (v12 NEW)

When the prove lane kills a finding at Gate 1, Gate 2, or Phase 4.5:
1. Archive kill reason in `knowledge/triage_objections/` (for triager-sim replay mode)
2. Run `triager-sim` (mode=replay) to calibrate future predictions
3. If `explore_candidates.md` has remaining E3/E4 findings:
   - Orchestrator MAY re-enter explore lane for those candidates
   - Re-spawn exploiter with new context/approach (max 2 re-attempts per candidate)
4. After all recycling: finalize explore_candidates.md status (proven / archived / killed)

---

## v12 Agent Model Assignment

| Agent | Model | Phase | Role |
|-------|-------|-------|------|
| target-evaluator | sonnet | 0 | GO/NO-GO + Novelty Score |
| scout | sonnet | 1 | Surface mapping + workflow discovery |
| analyst | sonnet | 1 | Vulnerability triage (dynamic budget) |
| threat-modeler | sonnet | 1 | Trust boundary + invariant extraction |
| patch-hunter | sonnet | 1 | Variant hunting from security commits |
| workflow-auditor | sonnet | 1.5 | Workflow state transition mapping |
| web-tester | sonnet | 1.5 | Request + workflow pack testing |
| triager-sim | sonnet/opus | Gates | Gate 1=sonnet, Gate 2+=opus |
| exploiter | opus | 2 | PoC with evidence tiers |
| reporter | sonnet | 3,5 | Report + bugcrowd_form.md |
| critic | opus | 4 | Fact-check |

---

## BB Core Rules (carried from v11 + v12 additions)

- No PoC = No submit (IRON RULE)
- Phase 0 mandatory — NO-GO = stop
- No submit without triager-sim SUBMIT
- Tier 1-2 only — Tier 3-4 = auto delete (submission). E3/E4 = explore_candidates.md (v12)
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
- Kill Gate without pass = no report (IRON RULE)
- Gate 2 STRENGTHEN max 2x
- Phase 4.5 KILL = Gate bug → feedback loop
- **v12**: Evidence tier classification mandatory (E1-E4)
- **v12**: Triage feedback pre-check before Gates (knowledge/triage_objections/)
- **v12**: workflow_map.md required for Web/API targets
- **v12**: Risk-weighted coverage (HIGH endpoints count 2x)
- **v12**: Fresh-Surface Exception for mature targets with new modules

## Time-Box (unchanged from v11)

```
Phase 0: 45min | Phase 0.5: 30min | Phase 1: 2hr | Phase 1.5: 1hr (v12 NEW)
Phase 2: 3hr | Phase 3-5: 2hr
Total: 9hr (general, was 8hr) / 13hr (DeFi, was 12hr)
No HIGH+ signal at 2hr → ABANDON (after checklist pass)
```

### Token Efficiency Tracking Protocol (Anthropic SCONE-bench)

SCONE-bench: 세대당 중앙값 22% 토큰 감소. 파이프라인 효율 모니터링:

**기록 시점**: 각 target 완료 시 Orchestrator가 기록
**기록 방법**: `python3 tools/infra_client.py db cost-summary --target <target> --json`
**비교 기준**:
- 동일 유형 타겟 간 tokens/finding 비율
- 모델 업그레이드 전후 동일 태스크 토큰 비교
- Phase별 토큰 비율 (Discovery:Exploitation 이상적 1:3)
**ROI 계산**: (예상 보상금 / 추정 API 비용) > 5x → 효율적

## Hard NO-GO Rules (unchanged from v11)

```
3+ audits = AUTO NO-GO (unless Fresh-Surface Exception v12)
2+ reputable audits (Nethermind, OZ, ToB, Zellic, Spearbit) = AUTO NO-GO (unless Fresh-Surface Exception v12)
100+ resolved reports = AUTO NO-GO
Operating 3+ years = AUTO NO-GO (unless Fresh-Surface Exception v12)
Last commit >6mo + 2+ audits = AUTO NO-GO
Source private/inaccessible = AUTO NO-GO
Fork → original audit + fix commits all applied = AUTO NO-GO
DeFi → cast call mandatory in Phase 0
```

## Anti-AI Detection (unchanged from v11)

- Specific block number or tx hash in report
- Vary report structure each time
- Observational language ("reviewed implementation")
- Zero template phrases
- AI Slop Score ≤2/10
- At least 1 unique analysis element

## Platform Priority (unchanged from v11)

Bugcrowd (PRIMARY, 40% success) > HackenProof (Web3) > PSIRT Direct > Immunefi (<6mo+≤1audit) > Intigriti/YesWeHack > H1 (paused)
