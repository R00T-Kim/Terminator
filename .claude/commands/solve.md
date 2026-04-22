CTF 챌린지 풀이 파이프라인을 실행합니다.

1. `knowledge/index.md`에서 $ARGUMENTS 챌린지 이전 시도 여부 확인
2. 챌린지 파일 확인: `file`, `checksec`, `strings | head -20` 실행
3. ctf_pipeline 절차에 따라 파이프라인 선택:
   - trivial (소스 제공, 1-3줄 취약점): ctf-solver 1-agent
   - pwn (취약점 명확): reverser → chain → critic → verifier → reporter
   - pwn (취약점 불명확): reverser → trigger → chain → critic → verifier → reporter
   - reversing/crypto: reverser → solver → critic → verifier → reporter
   - web: scout → analyst → exploiter → reporter
4. 각 단계의 아티팩트를 다음 에이전트에 전달
5. FLAG_FOUND 시 solve.py를 직접 실행하여 검증
6. `knowledge/challenges/` 에 결과 기록 + `knowledge/index.md` 업데이트

$ARGUMENTS 에 대해 풀이를 시작하세요.
