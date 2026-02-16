# Efficient CTF Solving: Token & Session Minimization

## Origin
Too Many Questions 챌린지에서 14번의 solver iteration, 3-4 세션, 추정 400K-800K 토큰을 소모한 경험에서 도출.
핵심 원인: 휴리스틱 접근을 먼저 시도하고, 형식적 방법(z3)을 마지막에 적용함.

---

## 원칙 1: 문제 유형 먼저 분류하라

코딩 전에 반드시 문제를 분류:

| 유형 | 특징 | 도구 | 예시 |
|------|------|------|------|
| **Exact Constraint** | 정해진 답, 검증 가능 (MD5 등) | z3, SMT, SAT | ECB codebook, 수학 퍼즐, 암호 |
| **Search/Explore** | 입력 공간 탐색 | fuzzing, brute force | pwn crash 탐색, web param 탐색 |
| **Pattern Match** | 알려진 취약점 패턴 | exploit-db, writeup 검색 | 포맷 스트링, UAF, SQLi |
| **Reverse Compute** | 알고리즘 역연산 | Python, sympy | 커스텀 인코딩, 해시 역추적 |

**핵심**: Exact Constraint 문제에 휴리스틱을 쓰면 토큰만 날린다. 바로 z3로 가라.

## 원칙 2: 프로토콜/알고리즘을 완전히 모델링하라

### Bad (Too Many Questions v1-v13에서 한 것)
```
관찰: "block2 X일 때 target T가 'yes' 응답"
제약: V[T] < N[X]  (단순 부등식만)
결과: under-constrained → 틀린 답
```

### Good (v14에서 한 것)
```
모델: 이진 탐색의 전체 상태 전이
제약:
  1. 초기 상태: lo=0, hi=255
  2. 프로브 범위: N은 [lo, hi] 내에 있어야 함
  3. 상태 전이: y< → hi=N-1, n< → lo=N, ...
  4. 수렴: 마지막에 lo==hi==V[T]
  5. 전사: Distinct(N[0]..N[255])
결과: 충분히 constrained → 정답
```

**교훈**: 부분 관찰이 아니라 **전체 프로토콜의 상태 전이**를 모델링해야 한다.
프로토콜을 "시뮬레이션"하는 제약이 단순 입출력 비교보다 훨씬 강력하다.

## 원칙 3: 3회 실패 시 멈추고 재고하라 (Stop-and-Rethink Rule)

```
시도 1 실패 → 변형 시도
시도 2 실패 → 다른 변형
시도 3 실패 → ⛔ STOP
```

3회 실패 후 반드시 자문:
1. **도구가 맞는가?** 휴리스틱 vs 형식적 방법 vs brute force
2. **제약이 충분한가?** 빠진 제약이 있는지 (상태 전이, bijection, 범위 등)
3. **관점을 바꿔야 하는가?** 공격 벡터, 데이터 해석 방법
4. **이미 풀린 유사 문제가 있는가?** knowledge/ 검색, 웹 검색

이 규칙을 안 지키면: v4→v5→v6→...→v13 (10번 연속 실패) = 토큰 낭비

## 원칙 4: 분석 시간 >> 코딩 시간

| 나쁜 패턴 | 좋은 패턴 |
|-----------|----------|
| 바로 코딩 시작 | 프로토콜을 완전히 이해한 후 코딩 |
| "될 것 같은데" 코딩 | "이 접근이 수학적으로 맞는지" 먼저 확인 |
| 결과 보고 고치기 (iterate) | 한 번에 맞는 모델 구축 |

**경험칙**: 분석 50% + 코딩 30% + 디버깅 20% = 최적 비율
Too Many Questions 실패 패턴: 분석 10% + 코딩 60% + 디버깅 30%

## 원칙 5: z3 사용 시 체크리스트

z3로 풀 때 반드시 포함할 제약 유형:

- [ ] **범위 제약**: 각 변수의 유효 범위 (0-255, 0-N 등)
- [ ] **유일성/전사**: Distinct() — bijection이 있으면 반드시
- [ ] **상태 전이**: 프로토콜이 상태를 가지면 모든 step의 lo/hi/state 모델링
- [ ] **프로브/입력 범위**: 각 step에서 입력이 유효 범위 내에 있는지
- [ ] **수렴/종료**: 알고리즘이 특정 값으로 수렴하는 조건
- [ ] **관찰 일치**: pcap/로그에서 관찰된 실제 입출력

하나라도 빠지면 under-constrained → 틀린 답이 나올 수 있다.

## 원칙 6: Reverser가 솔버 전략을 추천하라

Reverser(분석 단계)에서 이미 최적 솔버 전략을 식별할 수 있다:

| 분석 결과 | 추천 전략 |
|-----------|----------|
| 결정론적 암호 (ECB, 고정 키) | codebook 분석 + z3 |
| 상태 기반 프로토콜 | 전체 상태 전이 시뮬레이션 |
| 수학적 관계 (mod, XOR, 행렬) | z3 / sympy 직행 |
| 메모리 취약점 (BOF, UAF) | pwntools + ROP chain |
| 알려진 CVE 패턴 | exploit-db 검색 + 기존 PoC 수정 |

이 추천을 reversal_map.md에 포함하면, chain agent가 삽질 없이 바로 최적 접근을 택할 수 있다.

---

## 적용 예시: Too Many Questions를 효율적으로 풀었다면

### 이상적 흐름 (1 세션, ~100K 토큰)
```
1. Reverser: 바이너리 분석
   → "AES-ECB 결정론적, 이진 탐색 프로토콜, 32개 워커"
   → 추천: "z3로 전체 이진 탐색 시뮬레이션 모델링"

2. Chain: reversal_map.md 읽고 바로 z3 접근
   → pcap 파싱 + block1 그룹핑 + 전체 상태 전이 모델링
   → 1~2회 시도로 정답

3. Verifier: MD5 확인 → 통과
4. Reporter: 라이트업 작성
```

### 실제 흐름 (3-4 세션, ~500K 토큰)
```
1. Reverser: 바이너리 분석 (좋았음)
2. Chain: 통계적 접근 시도 (v1-v5) → 실패
3. Chain: 반복 정제 (v6-v9) → 실패
4. Chain: 단순 z3 (v10-v13) → under-constrained
5. Chain: 전체 시뮬레이션 z3 (v14) → 성공
```

**차이: 4x 토큰, 3x 세션.** Reverser가 전략 추천 + Chain이 형식적 방법 우선 → 1회에 끝남.

---

## 원칙 7: 문제 유형에 맞는 파이프라인을 선택하라 (ultrushawasm에서 도출)

```
reversing → reverser + solver (3-agent, trigger/chain 불필요)
pwn       → reverser + trigger + chain + verifier (5-agent, 현재)
web       → scanner + analyst + exploiter (4-agent)
crypto    → reverser + solver(z3/sympy) (3-agent)
```

**핵심**: 6-agent 풀 파이프라인을 모든 문제에 적용하면 에이전트가 할 일 없이 같은 분석을 반복함.

## 원칙 8: 큰 파일은 요약 문서로 전달하라

- 68K줄 WAT 파일을 5개 에이전트가 각각 읽음 = 300K+ 토큰 낭비
- reverser가 reversal_map.md에 핵심만 정리 → 후속 에이전트는 요약만 읽음
- **규칙**: 10K줄 이상 파일은 직접 전달 금지, 요약 문서 의무화

## 원칙 9: 힌트와 모순되는 접근은 즉시 배제하라

- "Bruteforce no need" → SSH 40회 시도 = 힌트 직접 무시
- CTF 힌트는 출제자의 의도적 가이드. 가설 필터로 활용할 것

## 원칙 10: 5회 시도 실패 → 외부 지식 검색

- CTFtime, GitHub, 블로그에서 유사 문제 writeup 검색
- 혼자 분석으로 안 될 때 커뮤니티 지식 활용이 가장 효율적
- **상세**: [techniques/wasm_challenge_lessons.md](wasm_challenge_lessons.md)

## 원칙 11: 에이전트 수 최소화 (ultrushawasm에서 도출)

- 확실한 작업이 있을 때만 에이전트 스폰
- "혹시 모르니까" 스폰 금지
- 분석 에이전트 1개 + 실행 에이전트 1개가 기본

## 원칙 12: Exploit은 단계별로 작성하고 테스트하라 (unibitmap에서 도출)

### 나쁜 패턴 (unibitmap chain agent)
```
1400줄 solve.py를 한 번에 작성
→ 한 번도 테스트하지 않고 idle
→ 다음 세션에서 디버깅부터 시작 (토큰 낭비)
```

### 좋은 패턴
```
Phase 1: leak 코드 작성 (100줄) → 로컬 테스트 → leak 확인
Phase 2: overflow 코드 작성 (50줄) → 로컬 테스트 → 제어 확인
Phase 3: ROP chain 조립 (100줄) → 로컬 테스트 → shell/flag 확인
Phase 4: 합치기 → 원격 테스트
```

**핵심**: 각 단계를 200줄 이내로 작성하고 **반드시 로컬 테스트 후 다음 단계로 진행**.
1400줄을 한 번에 쓰면 어디서 틀렸는지 디버깅이 불가능.

## 원칙 13: Chain agent에 "테스트 먼저" 규칙 강제

chain.md 프롬프트에 다음을 추가해야 함:
```
1. Phase별로 코드를 작성하라 (각 200줄 이내)
2. 각 Phase 작성 후 반드시 process('./binary')로 로컬 테스트
3. 테스트 결과(성공/실패)를 보고한 후 다음 Phase 진행
4. 전체 1000줄 이상 작성 없이 제출 금지
```

## 원칙 14: 취약점이 명확하면 Trigger 단계 생략

- OOB read 같은 정적 분석으로 확인 가능한 취약점 → trigger 불필요
- fuzzing은 취약점이 불확실할 때만 (복잡한 파서, 알 수 없는 상태 전이)
- **간략 파이프라인**: reverser → chain(+검증) → verifier → reporter (4-agent)

## 원칙 15: 상수 추출은 반드시 GDB 메모리 덤프로 검증 (conquergent에서 도출)

### 문제
- r2 정적 디스어셈블리에서 `0xcafebaba`로 읽은 상수가 실제로는 `0xcafebabe`
- 1바이트 차이로 solver 출력 전체가 틀림
- 특히 retf 모드 스위칭, overlapping 명령어, 복잡한 인코딩이 있는 바이너리에서 발생

### 교훈
```
r2 정적 분석 → 상수 추출 → "cafebaba"  (틀림)
GDB 메모리 덤프 → 상수 확인 → "cafebabe"  (맞음)
```

**규칙**: 바이너리에 하드코딩된 상수가 5개 이상이면, GDB로 메모리 덤프하여 r2 결과와 교차 검증.

### 순환 검증의 함정
Python forward reimplementation으로 "검증"하는 것은 순환 논리:
- 잘못된 상수 → 잘못된 forward → 잘못된 inverse → **forward와 inverse가 서로 일치** → "검증 통과" (거짓)
- **실제 바이너리에 파이프해서 "Correct" 메시지를 확인해야 진짜 검증**

## 원칙 16: 문제 난이도를 먼저 분류하라 (Toddler's Bottle에서 도출)

소스코드/바이너리를 30초 훑어본 후 난이도 분류:

| 난이도 | 기준 | 풀이 방법 | 예시 |
|--------|------|-----------|------|
| **Trivial** | 취약점 1-3줄, exploit one-liner | Orchestrator 직접 풀이 | cmd1, random, blackjack, mistake |
| **Easy** | 취약점 명확, exploit 50줄 이내 | 2-3 agent (reverser→chain→verifier) | passcode, horcruxes |
| **Medium** | 분석+exploit 필요, 100줄+ | 4-5 agent 풀 파이프라인 | unibitmap, sand_message |
| **Hard** | Custom VM, 난독화, 다단계 | 5 agent + GDB Oracle 등 기법 | damnida, conquergent |

**핵심**: Trivial 문제에 5-agent 파이프라인 = 토큰 20x 낭비.
pwnable.kr Toddler's Bottle 20문제 중 ~12개가 Trivial (직접 풀이 2-5분).

### Trivial 판별 체크리스트
- [ ] 소스코드가 50줄 이내?
- [ ] 취약점이 변수/조건 1개에 집중?
- [ ] 풀이가 인자/입력 1줄로 완성?
→ 3개 모두 Yes → **직접 풀이** (Agent Teams 불필요)

## 원칙 17: 에러 시 멈추지 말고 즉시 대안을 시도하라 (Toddler's Bottle에서 도출)

```
접근 A 실패 → 3초 내 접근 B 시도
접근 B 실패 → 3초 내 접근 C 시도
접근 C 실패 → STOP & 문제 구조 재분석
```

**특히 SSH/네트워크 상호작용에서**:
- pexpect 타임아웃 → nc 파이프로 전환
- nc 파이프 한계 → SSH 터널 + pwntools로 전환
- PTY 에러 → subprocess.communicate로 전환

**절대 하지 말 것**: 같은 에러에 같은 방법으로 3회 이상 재시도

상세 패턴: [techniques/ssh_interaction_patterns.md](ssh_interaction_patterns.md)

## 원칙 18: 정수 입력 취약점 체크리스트 (blackjack에서 도출)

`scanf("%d")`, `atoi()`, `strtol()` 등 정수 입력 함수 발견 시:

- [ ] **음수 입력** 허용? → 산술 역전 (cash -= negative_bet → cash 증가)
- [ ] **0 입력** 허용? → 나눗셈 0, 조건 우회
- [ ] **INT_MAX/INT_MIN** → 오버플로우
- [ ] **두 번째 입력에 검증 누락?** → 첫 입력 거부 후 재입력에 검증 없음

**blackjack 패턴**: bet > cash → "다시 입력" → 두 번째 scanf에 검증 없음 + 음수 허용

## 원칙 19: Orchestrator가 바이너리 실행 가능성을 사전 확인 (conquergent에서 도출)

에이전트 스폰 전에 Orchestrator가 직접:
1. `echo "test" | ./binary` 실행하여 실행 가능 여부 확인
2. 실행 불가 → 라이브러리 설치 (libc6:i386 등) 먼저 수행
3. 에이전트가 바이너리 검증 없이 Python-only 순환 검증으로 빠지는 것을 원천 차단

## 원칙 17: 유용한 MCP/도구 조합 (2026-02 기준)

| 도구 | 용도 | ROI | 현재 상태 |
|------|------|-----|-----------|
| **GhidraMCP** | 디컴파일, 심볼 분석, stripped binary | 매우 높음 | 설치 완료 (GUI 필요) |
| **mcp-gdb** | 디버깅, breakpoint, 메모리 검사 | 높음 | 설치 완료 |
| **pentest-mcp** | nmap, gobuster, nikto, john, hashcat | 중간 (web/bounty용) | 설치 완료 |
| **frida-mcp** | 동적 계측, 함수 후킹 | 높음 (reversing) | 설치 완료 |
| **one_gadget CLI** | libc one-gadget 자동 검색 | 높음 (pwn) | `gem install one_gadget` 필요 |
| **seccomp-tools** | seccomp 필터 분석 | 중간 (pwn) | `gem install seccomp-tools` 필요 |
| **patchelf** | ELF 런타임 링커/libc 교체 | 높음 (pwn 로컬 재현) | `apt install patchelf` 필요 |

### 아직 없지만 만들면 좋을 MCP
1. **CTF Writeup 검색 MCP**: CTFtime/GitHub에서 유사 문제 검색 (가장 높은 ROI)
2. **Pwntools Interactive MCP**: remote/process 연결, 자동 leak/exploit 테스트
3. **Binary Info MCP**: checksec + ROPgadget + one_gadget + seccomp-tools 통합
