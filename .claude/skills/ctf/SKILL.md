---
name: ctf
description: CTF 챌린지 풀이 파이프라인 시작. "ctf", "챌린지 풀어", "pwn", "reversing", "crypto 문제", "워게임" 등의 키워드에 자동 매칭
argument-hint: [challenge-path] [host:port]
---

# CTF Challenge Pipeline

## 사전 체크 (자동 실행)

현재 챌린지 정보:
!`if [ -n "$1" ] && [ -e "$1" ]; then file "$1" 2>/dev/null && checksec --file="$1" 2>/dev/null | head -5; elif [ -d "$ARGUMENTS" ] 2>/dev/null; then ls -la "$ARGUMENTS" 2>/dev/null | head -10; fi`

Knowledge DB 기존 풀이 확인:
!`python3 /home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/tools/knowledge_indexer.py search "$ARGUMENTS" 2>/dev/null | head -10 || echo "검색 불가"`

## 파이프라인 실행 규칙

**반드시 Agent Teams로 풀이하라.** 직접 풀지 말 것.

### Step 0: 사전 분석 (Orchestrator 직접)
1. `knowledge/index.md` 읽어서 이미 풀었거나 시도한 문제 확인
2. 바이너리 실행 가능 여부 확인: `echo "test" | ./<binary> 2>&1`
3. 실행 불가 → 라이브러리 먼저 설치 (`sudo apt install libc6:i386` 등)
4. `file`, `checksec`, `strings | head -20` 기본 분석

### Step 1: 난이도 판정 → 파이프라인 선택
```
if 난이도 == "trivial" (소스 있음, 로직버그, one-liner exploit):
    ctf-solver 1-agent (model=sonnet) → reporter
elif 문제_유형 == "pwn" and 취약점_명확:
    reverser → chain → critic → verifier → reporter  (5-agent)
elif 문제_유형 == "pwn" and 취약점_불명확:
    reverser → trigger → chain → critic → verifier → reporter  (6-agent)
elif 문제_유형 == "reversing" or "crypto":
    reverser → solver → critic → verifier → reporter  (4-agent)
elif 문제_유형 == "web":
    scout → analyst → exploiter → reporter  (4-agent)
```

### Step 2: TeamCreate + 순차 파이프라인
```
TeamCreate("ctf-<challenge_name>")
```
각 에이전트는 `subagent_type="<역할명>"`, `mode="bypassPermissions"`, model 필수 지정.

### Step 3: 결과 수집
- FLAG_FOUND → Orchestrator가 solve.py 직접 실행 검증
- `knowledge/index.md` 업데이트
- TeamDelete 정리

### 핵심 규칙
- 로컬 flag 파일 = FAKE. remote(host, port)만 진짜 플래그
- 3회 실패 → Dual-Approach, 5회 실패 → writeup 검색
- 에이전트별 model 필수: reverser=sonnet, chain=opus, critic=opus, verifier=sonnet, reporter=sonnet
