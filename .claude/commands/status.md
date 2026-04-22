현재 진행 중인 타겟/챌린지 상태를 요약합니다.

1. `knowledge/index.md` 읽기 — 전체 현황 파악
2. `targets/` 디렉토리에서 활성 타겟 목록 확인
3. 각 활성 타겟에 대해:
   - `checkpoint.json` 읽기 → 현재 phase, status
   - `vulnerability_candidates.md` 존재 여부 → finding 수
   - `submission/` 존재 여부 → 제출 준비 상태
4. 결과를 마크다운 테이블로 출력:

| Target | Phase | Status | Findings | Submissions | Blockers |
|--------|-------|--------|----------|-------------|----------|

5. 전체 통계: 활성/대기/완료/폐기 타겟 수
