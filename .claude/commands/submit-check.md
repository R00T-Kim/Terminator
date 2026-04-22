제출 전 최종 품질 체크를 수행합니다.

$ARGUMENTS 는 submission 디렉토리 경로입니다 (예: targets/myapp/submission/vuln-01/).

1. 리포트 품질 스코어링:
   ```
   python3 tools/report_scorer.py $ARGUMENTS/*.md --poc-dir $ARGUMENTS/evidence/ --json
   ```
   - composite >= 75 필수 (미달 시 구체적 개선 포인트 제시)

2. AI slop 스크러빙:
   ```
   python3 tools/report_scrubber.py $ARGUMENTS/*.md
   ```
   - Unicode 워터마크, em-dash 과다, 템플릿 언어 제거

3. 증거 매니페스트 검증:
   ```
   python3 tools/evidence_manifest.py $ARGUMENTS/ --validate
   ```
   - 모든 아티팩트 SHA256 해시 + 누락 검사

4. triager-sim 시뮬레이션 (report-review 모드):
   - SUBMIT → 제출 준비 완료
   - STRENGTHEN → 구체적 보완 포인트 안내
   - KILL → 제출 중단 + 사유

5. 최종 결과를 PASS/FAIL + 체크리스트로 출력
