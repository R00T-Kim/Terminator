# Shared coordination layer

이 디렉터리는 Claude Code, Codex/OMX, Gemini가 공통으로 읽고 쓰는 경량 상태 계층이다.

## 목적
- 리더가 바뀌어도 같은 긴 문서/로그/스킬을 다시 읽지 않게 하기
- 세션 상태, digest, artifact, checkpoint를 공통 포맷으로 남기기
- Claude native hook과 Codex 작업 흐름이 같은 source-of-truth를 보게 만들기

## 구조
- `sessions/<session_id>/session_manifest.json` — 현재 세션의 기준 manifest
- `sessions/<session_id>/summaries/*.json` — 구조화된 context digest
- `sessions/<session_id>/artifact_index.json` — 공식 artifact 목록
- `sessions/<session_id>/checkpoints/*.json` — 복구용 checkpoint
- `sessions/<session_id>/skills/skill_index.json` — 검색된 skill 카탈로그
- `sessions/<session_id>/instructions/instruction_index.json` — 현재 cwd 기준 AGENTS.md / CLAUDE.md 인덱스
- `sessions/<session_id>/events/events.jsonl` — append-only 이벤트 로그
- `cache/digests/` — 내용 해시 기반 digest 캐시

## 기본 흐름
0. 1회 `./scripts/install_omx_wrapper.sh` 실행 후 repo 안에서는 plain `omx` 사용
1. `ensure-session`으로 세션 manifest 생성/갱신
2. `discover-skills`, `discover-instructions`로 현재 작업 범위의 지침 자산 인덱싱
3. `bootstrap-codex`, `sync-omx-state`로 Codex/OMX 상태를 coordination에 미러링
4. `write-handoff`, `consume-handoff`로 Claude ↔ Codex 전환을 구조화
5. `context_digest.py`로 큰 입력을 digest로 저장
6. hook/agent가 raw context 대신 latest digest + artifact index를 우선 사용

## 예시
```bash
./scripts/install_omx_wrapper.sh
omx hooks status
omx

python3 tools/coordination_cli.py ensure-session --cwd . --leader claude --tool claude_code
python3 tools/coordination_cli.py derive-session --cwd .
python3 tools/coordination_cli.py bootstrap-codex --cwd .
python3 tools/coordination_cli.py discover-skills --session <session_id>
python3 tools/coordination_cli.py discover-instructions --session <session_id>
python3 tools/coordination_cli.py session-status --session <session_id>
python3 tools/coordination_cli.py write-handoff --session <session_id> --from claude --to codex \
  --reason "need review" --decision-scope "review latest exploit" --required-output review.md
printf 'critical finding\nnext action: reuse digest\n' | \
  python3 tools/context_digest.py --session <session_id> --cwd . \
    --kind note --title "Quick note" --stdin
```

## 주의
- runtime 산출물은 `coordination/sessions/`, `coordination/cache/` 아래에 쌓이며 git ignore 대상이다.
- 문서형 파일만 source-of-truth가 아니고, 실제 hook에서 이 경로를 자동으로 갱신한다.
- wrapper는 `.omx/hooks/`와 `tools/coordination_cli.py`가 모두 보이는 repo에서만 `OMX_HOOK_PLUGINS=1`을 자동 주입한다.
