# Pipeline External Review (2026-02-23)

## Overview
GPT-4.5, Gemini 2.5 Pro, Claude Opus 4.6이 Terminator 파이프라인을 독립 평가.
128개 파일 전수분석 (Claude) + 아키텍처/보안/실전 격차 검토 (3모델 공통).

## 3모델 공통 지적사항

### 1. 하드코딩 시크릿 (Critical)
- docker-compose.yml에 6곳 하드코딩 자격증명
- **조치**: ${VAR:-default} 패턴으로 환경변수화 완료 (Task 1)

### 2. 문서-실행 불일치 (High)
- CLAUDE.md는 `general-purpose 사용 금지`인데 terminator.sh에서 6곳 사용
- **조치**: 커스텀 에이전트 타입으로 전부 교체 완료 (Task 2)

### 3. DAG 엔진 미연결 (High)
- dag.py 252줄 완전한 DAG 엔진이 존재하지만 실제 에이전트 스폰과 연결 안 됨
- agent_bridge.py는 DB 로깅만 수행, 에이전트 실행 안 함
- **조치**: claude_handler.py 구현으로 DAG→Claude CLI 연결 (Task 3)

### 4. E2E 벤치마크 부재 (Medium)
- benchmark.py가 메타데이터만 집계, 실제 solve.py 재실행 안 함
- 리그레션 감지 불가
- **조치**: replay_challenge() 메서드 추가 (Task 4)

### 5. Hard Pwn 0건 (Medium)
- hunter, Sand_Message, unibitmap 전부 heap에서 실패
- chain.md에 heap 전용 가이드 없음
- **조치**: Heap Exploitation Sub-Protocol 추가 (Task 5)

## Claude 전수분석 추가 발견

### 구조적 강점
- DAG 엔진 (dag.py) 설계 품질 우수 — ThreadPoolExecutor, 병렬, feedback edge
- 4개 파이프라인 정의 (ctf_pwn, ctf_rev, bounty, firmware) 완비
- Agent definitions (.claude/agents/*.md) 체계적
- Knowledge base 시스템 (20개 풀이 누적)
- Firmware pipeline 통합 (SCOUT + AIEdge)

### 개선 필요 (중기)
- agent_bridge.py PG 연결 하드코딩 (환경변수 미사용)
- 에이전트별 토큰 사용량 트래킹 미구현
- Web dashboard 인증 없음 (localhost 전용이라 낮은 우선순위)
- SARIF/PDF 리포트 생성기 에러 핸들링 부족

### 개선 필요 (장기)
- 멀티모델 라우팅 (LiteLLM) 실전 테스트 부족
- Neo4j 공격 그래프 쿼리 최적화
- CI/CD 파이프라인 (benchmark.yml) 실행 기록 없음

## 적용 현황

| Task | 설명 | 상태 | 영향도 |
|------|------|------|--------|
| 1 | docker-compose.yml 시크릿 환경변수화 | ✅ 완료 | Critical |
| 2 | terminator.sh general-purpose 수정 | ✅ 완료 | High |
| 3 | claude_handler.py 구현 | ✅ 완료 | High |
| 4 | E2E Replay Benchmark | ✅ 완료 | Medium |
| 5 | chain.md Heap Sub-Protocol | ✅ 완료 | Medium |
| 6 | 3모델 평가 결과 저장 | ✅ 완료 | Low |
| 7 | .env.example 보강 | ✅ 완료 | Low |

## 평가 점수 (3모델 평균)
- 아키텍처: 8/10 (DAG + Agent Teams 잘 설계됨)
- 보안: 5/10 → 7/10 (시크릿 하드코딩 해결 후)
- 실전 준비도: 6/10 → 8/10 (DAG 연결 + 벤치마크 후)
- 문서화: 9/10 (CLAUDE.md, agent defs 매우 상세)
