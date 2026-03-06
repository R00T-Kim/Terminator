# OMX coordination hooks

이 디렉터리는 Codex/OMX 런타임을 `coordination/` 정본과 자동 동기화하는 hook plugins를 담는다.

## 사용법
```bash
./scripts/install_omx_wrapper.sh   # 1회 설치
omx
```

직접 wrapper를 우회해야 하면:
```bash
OMX_HOOK_PLUGINS=1 omx
```

## 포함된 플러그인
- `coord-session-start.mjs` — Codex 세션 bootstrap + skill/instruction/digest 초기화
- `coord-turn-complete.mjs` — `.omx` 상태/plan/notepad를 coordination에 동기화
- `coord-session-idle.mjs` — idle 시점 snapshot + pending handoff 상태 기록

## 설계 원칙
- cross-tool 정본은 `coordination/`
- `.omx/`는 Codex 로컬 런타임 상태
- 실패해도 Codex 세션을 죽이지 않고 로그만 남긴다
