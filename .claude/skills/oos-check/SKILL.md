---
name: oos-check
description: Bug Bounty finding이 Out-of-Scope에 해당하는지 사전 체크. Phase 0 target_evaluator 후, Phase 1 analyst finding별 교차확인 시 자동 트리거. "OOS", "out of scope", "exclusion check" 키워드 매칭
user-invocable: true
argument-hint: <target-dir> [finding-type]
allowed-tools: [Read, Grep, Glob, Bash, WebFetch]
---

# OOS (Out-of-Scope) Pre-Check

Bug Bounty finding이 프로그램의 Out-of-Scope 규칙에 해당하는지 사전 체크한다.
OOS 미스가 전체 실패의 22%를 차지 — CapyFi(oracle staleness), AXIS(D-Bus) 모두 brief에 명시돼 있었음.

## 입력
- `$ARGUMENTS`: `<target-dir>` (예: `targets/keeper`) + 선택적 `[finding-type]` (예: `oracle-staleness`)
- finding-type이 없으면 전체 프로그램 OOS 스캔

## 실행 절차

### Step 1: Program Rules 로드
```
Read targets/<target>/program_rules_summary.md
```
- "Exclusion List" 섹션에서 OOS 항목 추출
- "Known Issues" 섹션에서 이미 알려진 이슈 추출

### Step 2: 공통 배제 패턴 매칭
OOS 패턴 DB (`scripts/oos_patterns.json`) 로드 후 finding-type과 교차 매칭:

!`cat /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/.claude/skills/oos-check/scripts/oos_patterns.json 2>/dev/null || echo "패턴 DB 없음"`

### Step 3: 프로그램 페이지 OOS 확인 (Immunefi/H1)
- Immunefi: `immunefi.com/common-vulnerabilities-to-exclude/` 기본 배제 목록
- H1/Bugcrowd: 프로그램 policy 페이지에서 "Out of Scope" 항목

### Step 4: 판정
| 결과 | 조건 | 행동 |
|------|------|------|
| **PASS** | 어떤 OOS 패턴에도 매칭 안 됨 | Phase 1 진행 OK |
| **WARN** | 부분 매칭 (bypass 가능성 있음) | analyst에게 경고 + bypass 리프레이밍 필요 |
| **BLOCK** | 명확히 OOS에 해당 | 해당 finding 자동 제외. Phase 1에서 분석 금지 |

### Step 5: 결과 출력
```
[OOS-CHECK] Target: <target>
[OOS-CHECK] Finding type: <type or "전체 스캔">
[OOS-CHECK] Program exclusions matched: <count>
[OOS-CHECK] Common pattern matched: <count>
[OOS-CHECK] Result: PASS / WARN(<이유>) / BLOCK(<이유>)
```

## 과거 실패 교훈 (이것들을 잡기 위한 skill)
- **CapyFi**: oracle staleness → Immunefi 공통 배제 목록에 명시. OOS로 거절
- **AXIS**: D-Bus authorization bypass → "local access bugs OOS unless root escalation" 명시
- **Kiln DeFi**: offset=0인 vault → 코드 경로 비활성화 = latent bug = OOS
- **stake.link**: sandwich attack → "third party oracle data" OOS by default

## 핵심 규칙
- **BLOCK 판정 → 해당 finding은 vulnerability_candidates.md에서 제외**
- **WARN 판정 → bypass 리프레이밍 없이 진행 금지** (예: "oracle staleness" → "oracle manipulation via flash loan"으로 리프레이밍 가능?)
- **Phase 0에서 전체 OOS 스캔, Phase 1에서 finding별 개별 스캔**
