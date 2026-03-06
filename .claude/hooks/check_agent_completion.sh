#!/bin/bash
# check_agent_completion.sh — SubagentStop hook
# 에이전트 종료 시 checkpoint.json으로 실제 완료 여부 자동 검증
# FAKE IDLE (compaction/에러로 중단) vs 진짜 완료 판별

set -euo pipefail

INPUT=$(cat)
CWD=$(echo "$INPUT" | jq -r '.cwd // ""')

PROJECT_DIR="/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator"
COORD_CLI="$PROJECT_DIR/tools/coordination_cli.py"
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)

if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID="$(python3 "$COORD_CLI" derive-session --cwd "${CWD:-$PROJECT_DIR}" 2>/dev/null | jq -r '.session_id' 2>/dev/null || basename "${CWD:-$PROJECT_DIR}")"
fi

# 최근 수정된 checkpoint.json 찾기 (최근 10분 이내)
WARNINGS=""
FOUND_INCOMPLETE=false

for cp in $(find "$CWD" "$PROJECT_DIR" -maxdepth 4 -name "checkpoint*.json" -mmin -10 2>/dev/null | head -5); do
    STATUS=$(jq -r '.status // "unknown"' "$cp" 2>/dev/null || continue)
    AGENT=$(jq -r '.agent // "unknown"' "$cp" 2>/dev/null || echo "unknown")
    PHASE=$(jq -r '.phase_name // .phase // "?"' "$cp" 2>/dev/null || echo "?")
    IN_PROG=$(jq -r '.in_progress // "none"' "$cp" 2>/dev/null || echo "none")
    EXPECTED=$(jq -r '.expected_artifacts // [] | join(", ")' "$cp" 2>/dev/null || echo "")
    PRODUCED=$(jq -r '.produced_artifacts // [] | join(", ")' "$cp" 2>/dev/null || echo "")
    ERROR=$(jq -r '.error // ""' "$cp" 2>/dev/null || echo "")
    DIR=$(dirname "$cp")

    case "$STATUS" in
        completed)
            # 산출물 존재 여부 검증
            MISSING=""
            for artifact in $(jq -r '.expected_artifacts // [] | .[]' "$cp" 2>/dev/null); do
                if [[ ! -f "$DIR/$artifact" ]]; then
                    MISSING="${MISSING} $artifact"
                fi
            done
            if [[ -n "$MISSING" ]]; then
                WARNINGS="${WARNINGS}
[WARN] $AGENT: status=completed but missing artifacts:$MISSING"
                FOUND_INCOMPLETE=true
            fi
            ;;
        in_progress)
            WARNINGS="${WARNINGS}
[ALERT] $AGENT: FAKE IDLE detected — status=in_progress, phase=$PHASE
  in_progress: $IN_PROG
  produced: $PRODUCED
  expected: $EXPECTED
  → 에이전트가 compaction/에러로 중단됨. 재스폰 또는 resume 필요."
            FOUND_INCOMPLETE=true
            ;;
        error)
            WARNINGS="${WARNINGS}
[ERROR] $AGENT: status=error at phase=$PHASE
  error: $ERROR
  → 환경 문제 해결 후 재스폰 필요."
            FOUND_INCOMPLETE=true
            ;;
    esac
done

if [[ "$FOUND_INCOMPLETE" == true ]]; then
    python3 "$COORD_CLI" event \
        --session "$SESSION_ID" \
        --type "subagent_completion_warning" \
        --payload-json "$(jq -n --arg warnings "$WARNINGS" '{warnings: $warnings}')" >/dev/null 2>&1 || true
fi

# 결과 출력
if [[ "$FOUND_INCOMPLETE" == true ]]; then
    jq -n --arg msg "$WARNINGS" '{additionalContext: $msg}'
else
    echo '{}'
fi

exit 0
