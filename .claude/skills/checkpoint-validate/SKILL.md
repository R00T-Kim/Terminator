---
name: checkpoint-validate
description: 에이전트 checkpoint.json 검증. idle 감지, fake completion 탐지, 에러 복구 제안. "checkpoint", "idle", "에이전트 상태", "agent status" 키워드 매칭
user-invocable: true
argument-hint: <checkpoint-json-path>
allowed-tools: [Read, Bash, Glob]
---

# Checkpoint Validation

에이전트의 checkpoint.json을 검증하여 idle/fake completion/error 상태를 탐지한다.

## 입력
- `$ARGUMENTS`: checkpoint.json 파일 경로

## 실행 절차

### Step 1: checkpoint.json 읽기
```
Read $ARGUMENTS
```

### Step 2: 상태 판정

| checkpoint.status | 판정 | 행동 |
|-------------------|------|------|
| `"completed"` | expected_artifacts 전부 존재 확인 | 모두 존재 → **PASS** / 누락 → **FAKE COMPLETION** |
| `"in_progress"` | timestamp 확인 | 마지막 업데이트 > 5분 전 → **FAKE IDLE** / 최근 → **WORKING** |
| `"error"` | error 필드 분석 | **ERROR** + 복구 제안 출력 |
| 파일 없음 | 에이전트 미시작 | **NOT STARTED** — 즉시 재스폰 필요 |

### Step 3: 산출물 검증 (completed 상태일 때)
```bash
# expected_artifacts의 각 파일 존재 + 크기 확인
for f in <expected_artifacts>; do
  if [ ! -f "$f" ] || [ ! -s "$f" ]; then
    echo "FAKE: $f missing or empty"
  fi
done
```
- 0바이트 파일 = fake artifact → **FAKE COMPLETION**

### Step 4: 결과 출력
```
[CHECKPOINT] Path: <path>
[CHECKPOINT] Agent: <agent_name>
[CHECKPOINT] Status: <status>
[CHECKPOINT] Phase: <phase>/<phase_name>
[CHECKPOINT] Completed: <completed_list>
[CHECKPOINT] In Progress: <in_progress>
[CHECKPOINT] Artifacts: <produced> / <expected>
[CHECKPOINT] Result: PASS / FAKE IDLE / FAKE COMPLETION / ERROR / NOT STARTED
[CHECKPOINT] Recovery: <구체적 복구 제안>
```

### Step 5: 복구 제안
| 상태 | 복구 행동 |
|------|----------|
| FAKE IDLE | 에이전트에게 "checkpoint.json 읽고 이어서 작업" 메시지 1회 → 여전히 idle → 재스폰 |
| FAKE COMPLETION | 누락 artifact 목록 포함하여 재스폰 (checkpoint injection) |
| ERROR | 에러 원인 해결 후 재스폰 (환경 문제면 Orchestrator가 해결) |
| NOT STARTED | 즉시 새 에이전트 스폰 |

## 핵심 규칙
- **"산출물 있음 = 완료"로 판단 금지** — checkpoint.status == "completed"만 신뢰
- **같은 역할 에이전트 2개 동시 실행 금지** — 재스폰 전 기존 에이전트 종료 확인
- 재스폰 시 이전 산출물 + checkpoint를 프롬프트에 포함 (중복 작업 방지)
