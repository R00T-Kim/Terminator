---
name: slop-check
description: 보고서의 AI 슬롭 점수 측정 (0-10). triager_sim/reporter가 사용. "slop", "AI 탐지", "ai detection", "템플릿 언어" 키워드 매칭
user-invocable: true
argument-hint: <report-file-path>
allowed-tools: [Read, Bash, Grep]
---

# AI Slop Detection

보고서의 AI 슬롭 점수를 0-10 스케일로 측정한다.
AI-generated 보고서는 40%+ 제출의 문제 — 트리아저가 적극 탐지 중.

## 입력
- `$ARGUMENTS`: 보고서 파일 경로

## AI Slop 스코어 기준 (통일)
| 점수 | 판정 | 행동 |
|------|------|------|
| **0-2** | PASS | 제출 가능 |
| **3-5** | STRENGTHEN | 재작성 필요 — 슬롭 패턴 제거 후 재체크 |
| **6-10** | KILL | 제출 불가 — 전면 재작성 또는 finding 삭제 |

## 실행 절차

### Step 1: 보고서 읽기
```
Read $ARGUMENTS
```

### Step 2: 슬롭 패턴 카운트

**템플릿 언어 패턴** (+0.5점 각):
!`grep -ciE "It is important to note|comprehensive|robust|Furthermore|In conclusion|It should be noted|leveraging|utilizing|In summary|As mentioned|It is worth noting|It is crucial|seamlessly|facilitate|Subsequently|Consequently|Notably|Specifically|Importantly|holistic|paradigm|synergy|delve into|multifaceted" "$ARGUMENTS" 2>/dev/null || echo "0"`

**불확실 언어** (+0.5점 각):
!`grep -ciE "should work|probably|most likely|presumably|seems to|appears to|it is believed|potentially|theoretically|could potentially|might potentially" "$ARGUMENTS" 2>/dev/null || echo "0"`

**구체적 증거 부재** (+2점):
- 특정 block number / tx hash / timestamp 없음
- 특정 파일:라인 참조 없음
- 실제 응답 캡처 없음

### Step 3: 양성 시그널 (감점)

**타겟 특정 세부사항** (-1점 각):
- 구체적 block number 또는 tx hash 포함
- 실제 API 응답 또는 에러 메시지 인용
- 특정 코드 라인 참조 (file.ts:123)
- 커스텀 분석 요소 (독특한 공격 시나리오명, 다이어그램 등)

**구조 차별화** (-0.5점):
- 이전 제출과 다른 섹션 순서
- 관찰적 언어 사용 ("identified in reviewed code")

### Step 4: 스코어 계산
```
score = 0
score += template_language_count * 0.5
score += uncertain_language_count * 0.5
score += (2 if no_specific_evidence else 0)
score -= target_specific_details * 1.0
score -= (0.5 if structure_differentiated else 0)
score = clamp(score, 0, 10)
```

### Step 5: validation_prompts.py 교차검증 (가능 시)
!`python3 -c "
import sys; sys.path.insert(0, '/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator')
from tools.validation_prompts import check_ai_slop
with open('$ARGUMENTS') as f: text = f.read()
result = check_ai_slop(text)
print(f'validation_prompts score: {result}')
" 2>/dev/null || echo "validation_prompts.py 사용 불가 — manual scoring만 적용"`

### Step 6: 결과 출력
```
[SLOP-CHECK] File: <path>
[SLOP-CHECK] Template language instances: N
[SLOP-CHECK] Uncertain language instances: N
[SLOP-CHECK] Specific evidence present: YES/NO
[SLOP-CHECK] Target-specific details: N
[SLOP-CHECK] Score: X/10
[SLOP-CHECK] Result: PASS (<=2) / STRENGTHEN (3-5) / KILL (6+)
[SLOP-CHECK] Fix suggestions: <구체적 수정 제안>
```

## 핵심 규칙
- **triager_sim은 이 skill의 결과를 SUBMIT/STRENGTHEN/KILL 판정에 반영**
- **reporter는 STRENGTHEN 판정 시 지적된 패턴을 모두 제거 후 재체크**
- **KILL → finding 삭제 또는 전면 재작성 (단순 패턴 제거로는 부족)**
