Bug Bounty 타겟 분석 파이프라인을 실행합니다.

1. `knowledge/index.md`에서 $ARGUMENTS 타겟 이전 시도 여부 확인
2. `python3 tools/bb_preflight.py init targets/$ARGUMENTS/` 실행 (없으면 생성)
3. `python3 tools/bb_preflight.py rules-check targets/$ARGUMENTS/` 실행
4. bb_pipeline_v12 절차에 따라 순차 실행:
   - Phase 0: target-evaluator → GO/NO-GO 판정
   - Phase 0.2: program_rules_summary.md 작성 + rules-check PASS
   - Phase 1: scout + analyst + threat-modeler + patch-hunter (병렬)
   - Phase 1.5: workflow-auditor + web-tester
   - Gate 1→2: coverage-check + workflow-check
   - Phase 2: exploiter (Gate 1 통과 건만)
   - Gate 2: triager-sim (opus)
   - Phase 3-5: reporter → critic → triager-sim → finalize
5. 진행 상황을 단계별로 보고

$ARGUMENTS 에 대해 파이프라인을 시작하세요.
