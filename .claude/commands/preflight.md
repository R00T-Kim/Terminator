BB preflight 게이트를 순차 실행합니다.

$ARGUMENTS 는 타겟 디렉토리입니다 (예: targets/myapp/).

1. rules-check:
   ```
   python3 tools/bb_preflight.py rules-check $ARGUMENTS
   ```

2. coverage-check (endpoint_map.md 기반):
   ```
   python3 tools/bb_preflight.py coverage-check $ARGUMENTS
   ```

3. workflow-check:
   ```
   python3 tools/bb_preflight.py workflow-check $ARGUMENTS
   ```

4. kill-gate-1 (finding 지정 시):
   ```
   python3 tools/bb_preflight.py kill-gate-1 $ARGUMENTS --finding "$FINDING"
   ```

5. 각 게이트 결과를 PASS/FAIL 테이블로 출력
6. 전체 FAIL 항목에 대해 구체적 해결 방법 안내
