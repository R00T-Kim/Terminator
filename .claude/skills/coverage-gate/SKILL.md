---
name: coverage-gate
description: Phase 1->2 전환 시 endpoint_map.md 커버리지 체크. 80% 미만이면 Phase 2 진행 차단. "coverage check", "커버리지", "endpoint 커버리지", "Phase 2 gate" 키워드 매칭
user-invocable: true
argument-hint: <target-dir>
allowed-tools: [Read, Bash, Grep, Glob]
---

# Endpoint Coverage Gate

Phase 1→2 전환 시 endpoint_map.md 커버리지를 체크한다.
NAMUHX에서 40% coverage로 Phase 2 진행, 실제 IDOR은 나머지 60%에서 발견된 교훈 반영.

## 입력
- `$ARGUMENTS`: 타겟 디렉토리 (예: `targets/keeper`)

## 실행 절차

### Step 1: bb_preflight.py coverage-check 실행
!`python3 /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/tools/bb_preflight.py coverage-check "$ARGUMENTS" 2>&1`

### Step 2: 결과 파싱 및 판정

| 결과 | 조건 | 행동 |
|------|------|------|
| **PASS** | coverage >= 80% | Phase 2 진행 OK |
| **FAIL** | coverage < 80% | Phase 2 진행 **차단**. UNTESTED 엔드포인트 목록 출력 |
| **ERROR** | endpoint_map.md 없음 | Scout가 생성해야 함. Phase 2 진행 차단 |

### Step 3: FAIL 시 UNTESTED 엔드포인트 출력
!`grep -i "UNTESTED" "$ARGUMENTS/endpoint_map.md" 2>/dev/null || echo "endpoint_map.md 없음"`

### Step 4: 소규모 타겟 예외
- 총 엔드포인트 < 10개 → **100% 커버리지 필수** (80% 임계값 대신)
- 이유: 소규모에서 1-2개 미테스트 = 핵심 공격면 누락 가능

### Step 5: 결과 출력
```
[COVERAGE-GATE] Target: <target>
[COVERAGE-GATE] Total endpoints: N
[COVERAGE-GATE] Tested: N (VULN=X, SAFE=Y, TESTED=Z)
[COVERAGE-GATE] Untested: N
[COVERAGE-GATE] Coverage: XX.X%
[COVERAGE-GATE] Threshold: 80% (또는 100% for <10 endpoints)
[COVERAGE-GATE] Result: PASS / FAIL
[COVERAGE-GATE] Action: <"Phase 2 진행" 또는 "추가 analyst/exploiter 라운드 필요 — UNTESTED 목록 첨부">
```

## 핵심 규칙
- **FAIL → 추가 analyst/exploiter 라운드를 UNTESTED 엔드포인트 대상으로 스폰**
- **"analysis complete" 조기 선언 방지** — coverage gate 통과 없이 Phase 2 진행 금지
- Orchestrator가 Phase 1 완료 후, Phase 2 스폰 전에 반드시 이 skill 호출
