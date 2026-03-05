---
name: bounty
description: Bug Bounty 타겟 분석 파이프라인 시작. "bounty", "바운티", "타겟 분석", "취약점 찾아", "버그 헌팅", "Immunefi", "Bugcrowd", "H1" 등의 키워드에 자동 매칭
argument-hint: [target-url-or-name] [scope]
---

# Bug Bounty Pipeline (v3)

## 사전 체크 (자동 실행)

Program rules 확인:
!`if [ -d "targets/$1" ]; then cat "targets/$1/program_rules_summary.md" 2>/dev/null | head -20 || echo "rules 미생성"; fi`

기존 findings 확인:
!`python3 /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/tools/knowledge_indexer.py search "$ARGUMENTS" 2>/dev/null | head -10 || echo "검색 불가"`

## 파이프라인 실행 규칙

**반드시 Agent Teams로 분석하라.** Orchestrator가 직접 코드를 읽고 분석하는 것은 금지.

### Phase 0: Target Intelligence
1. `TeamCreate("mission-<target>")`
2. `target_evaluator` (model=sonnet) → GO/NO-GO 판정
   - **Hard NO-GO (v6)**: 3+ audits, 2+ reputable audits, 100+ reports, 3년+, source inaccessible
   - NO-GO → 즉시 중단, 다른 타겟 검토
3. **`oos-check` skill 실행** — 프로그램 전체 OOS 스캔
4. target_evaluator의 `suggested_searches`로 knowledge-fts 검색 → HANDOFF에 `[KNOWLEDGE CONTEXT]` 주입

### Phase 0.2: Program Rules Generation (MANDATORY)
```bash
python3 tools/bb_preflight.py init targets/<target>/
# program_rules_summary.md 채우기 (auth 형식, Known Issues, 배제 목록)
python3 tools/bb_preflight.py rules-check targets/<target>/
# PASS 아니면 Phase 1 진행 금지
```

### Phase 0.5: Automated Tool Scan
- scout가 Slither/Semgrep/CodeQL 자동 스캔 (DeFi 시)
- **도구 결과 없이 analyst가 코드 읽기 금지**

### Phase 1: Discovery
- scout (model=sonnet) + analyst (model=sonnet) 병렬 스폰
- inject-rules 출력을 프롬프트 줄 3-5에 포함 (줄 1-2는 Critical Facts)
- analyst가 finding 생성 시 `oos-check` 패턴 매칭 (OOS BLOCK → 자동 제외)

### Phase 1→2 Gate: Coverage Check
- **`coverage-gate` skill 실행** (또는 직접):
```bash
python3 tools/bb_preflight.py coverage-check targets/<target>/ --json
# ≥80% → Phase 2 / <80% → 추가 라운드 (<10 endpoints → 100% 필수)
```

### Phase 2: PoC Validation
- exploiter (model=opus) → PoC Quality Tier 1-2만 통과
- **`poc-tier` skill로 Tier 검증** — Tier 3-4 = DROPPED
- **`threat-model-check` skill로 전제조건 검증** — BLOCK = exploiter에 전달 금지
- exploiter가 endpoint_map.md 업데이트 필수

### Phase 3-5: Report → Review → Finalize
- reporter → critic + architect → triager_sim → reporter (최종)
- **`slop-check` skill로 AI 슬롭 측정** (≤2 PASS, 3-5 STRENGTHEN, >5 KILL)
- triager_sim이 `triager_sim_result.json` 출력 → reporter 자동 피드백 루프 (최대 3회)
- triager_sim SUBMIT 없이 제출 금지
- **`checkpoint-validate` skill로 idle 에이전트 탐지** (필요 시)

### Phase 6: Cleanup
- TeamDelete

### 핵심 규칙
- PoC 없으면 절대 제출 금지 (IRON RULE)
- Quality > Quantity (3개 컨트랙트 심층 > 16개 스킴)
- Tool-First: Slither/Mythril/CodeQL → 코드
- 45분 MAX Phase 0 / 8시간 MAX 일반 / 12시간 MAX DeFi
- 2시간 HIGH+ 없으면 ABANDON (체크리스트 통과 후)
- AI 슬롭 방지: specific block/tx, Slop ≤2/10 (`slop-check` skill)
