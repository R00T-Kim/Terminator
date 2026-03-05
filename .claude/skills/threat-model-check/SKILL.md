---
name: threat-model-check
description: Finding의 공격 전제조건이 현실적인지 검증. 비현실적 threat model 사전 차단. "threat model", "위협 모델", "공격 전제", "attack prerequisites" 키워드 매칭
user-invocable: true
argument-hint: <finding-description-or-file>
allowed-tools: [Read, Bash]
---

# Threat Model Consistency Check

Finding의 공격 전제조건이 프로그램의 threat model과 일치하는지 검증한다.
Threat model breach가 실패의 19%를 차지 (MCP, Immutable, OPPO).

## 입력
- `$ARGUMENTS`: finding 설명 텍스트 또는 보고서 파일 경로

## 실행 절차

### Step 1: Finding에서 공격 전제조건 추출
Finding 설명/보고서를 읽고 공격자가 제어해야 하는 것을 분류:

| 전제조건 카테고리 | 설명 | 현실성 |
|-------------------|------|--------|
| 네트워크 접근 | 인터넷에서 도달 가능 | HIGH (일반적) |
| 사용자 인증정보 | 유효한 계정/토큰 필요 | MEDIUM (피싱 등) |
| 코드 실행 | 타겟 시스템에서 코드 실행 | LOW (이미 침해됨) |
| 인프라 접근 | 서버/클라우드 접근 | VERY LOW |
| 물리 접근 | 디바이스 물리적 접근 | VERY LOW |
| 내부자 | 조직 내부 권한 | VERY LOW |
| 사용자 기기 접근 | 피해자 기기 접근 | LOW |
| MitM 위치 | 네트워크 중간자 위치 | LOW-MEDIUM |

### Step 2: 전제조건 수 기반 판정
```
prerequisite_count = 공격자가 제어해야 하는 카테고리 수

if prerequisite_count == 0-1:
    → PASS (현실적 공격 시나리오)
elif prerequisite_count == 2:
    → WARN ("2개 전제조건 — 공격 실현 가능성 낮을 수 있음")
elif prerequisite_count >= 3:
    → BLOCK ("3개+ 전제조건 — 비현실적 공격 시나리오")
```

### Step 3: 프로그램 Threat Model 교차검증
```
Read targets/<target>/program_rules_summary.md  # 프로그램 threat model
```

특별 규칙:
- **D-Bus/로컬 접근** → root escalation 체인 없으면 → **BLOCK**
- **Admin/governance 접근** → "admin trust assumed" 프로그램에서 → **BLOCK**
- **물리 접근 필요** → 원격 exploit 없으면 → **WARN** (낮은 severity)
- **사용자 상호작용 필요** → 1-click = OK, 복잡한 시나리오 = **WARN**

### Step 4: 결과 출력
```
[THREAT-MODEL] Finding: <summary>
[THREAT-MODEL] Prerequisites:
  - [카테고리1]: <설명> (현실성: HIGH/MEDIUM/LOW)
  - [카테고리2]: <설명> (현실성: HIGH/MEDIUM/LOW)
[THREAT-MODEL] Prerequisite count: N
[THREAT-MODEL] Program threat model match: YES/NO
[THREAT-MODEL] Result: PASS / WARN(<이유>) / BLOCK(<이유>)
```

## 과거 실패 교훈
- **MCP (Immutable)**: "공격자가 MCP 서버 코드를 수정할 수 있다" 전제 → 프로그램이 "intended behavior" 판정
- **OPPO**: "정적 분석만으로 RCE 주장" → 실행 환경 접근 없이 증명 불가 → Informative
- **AXIS D-Bus**: 로컬 접근 + D-Bus 호출 → root escalation 체인 없어서 OOS

## 핵심 규칙
- **BLOCK → 해당 finding은 exploiter에게 전달 금지**
- **WARN → exploiter에게 전제조건 명시적 전달 + 보고서에 honest prerequisite disclosure 필수**
- 전제조건이 많을수록 severity 하향 필수 (CVSS PR/UI 보정)
