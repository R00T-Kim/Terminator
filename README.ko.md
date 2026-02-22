# Terminator

**Claude Code Agent Teams 기반 자율 보안 연구 에이전트**

CTF 자동 풀이 및 버그바운티 평가 시스템

[English Documentation](README.md)

---

## 개요

Terminator는 CTF 챌린지를 자율적으로 풀고 인가된 버그바운티 평가를 수행하는 멀티에이전트 보안 시스템입니다. **Claude Code Agent Teams** 기반으로 구축되어, 17개의 전문화된 에이전트를 구조화된 파이프라인을 통해 조율합니다.

이 시스템은 단순히 취약점을 찾는 것이 아니라 **검증**합니다. 모든 CTF 익스플로잇은 원격 실행 전에 로컬에서 3회 테스트됩니다. 모든 버그바운티 발견사항은 작동하는 PoC가 있어야만 보고서가 생성됩니다.

### 핵심 원칙

- **에이전트 팀, 단독 작업 없음** — 오케스트레이터는 전문화된 에이전트에게 위임, 직접 풀이하지 않음
- **산출물 전달 파이프라인** — 각 에이전트는 이전 에이전트의 출력을 읽고 구조화된 산출물을 생성
- **검증 우선** — 원격 서버 확인 없이 플래그를 주장하지 않음; 작동하는 PoC 없이 보고서를 제출하지 않음
- **경험 축적** — 모든 풀이(및 실패)는 향후 참조를 위해 지식 베이스에 기록됨

---

## 아키텍처

```
                          ┌─────────────────────────┐
                          │   Claude Code Session    │
                          │   (Orchestrator / Lead)  │
                          └────────────┬────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                                      │
          ┌────────▼─────────┐                  ┌─────────▼────────┐
          │   CTF Pipeline   │                  │  Bug Bounty      │
          │   (Sequential)   │                  │  Pipeline (v3)   │
          └────────┬─────────┘                  └─────────┬────────┘
                   │                                      │
      ┌────────────┼────────────┐            ┌────────────┼────────────┐
      │            │            │            │            │            │
  ┌───▼───┐  ┌────▼────┐  ┌───▼───┐    ┌───▼───┐  ┌────▼────┐  ┌───▼───┐
  │Reverser│→ │Trigger/ │→ │Critic │    │Scout  │→ │Exploiter│→ │Triager│
  │       │  │Chain/   │  │       │    │+Analyst│  │        │  │  Sim  │
  └───────┘  │Solver   │  └───┬───┘    └───────┘  └────────┘  └───────┘
             └─────────┘      │
                         ┌────▼────┐
                         │Verifier │→ FLAG_FOUND
                         └─────────┘
```

---

## 파이프라인

### CTF 파이프라인

| 조건 | 파이프라인 | 에이전트 수 |
|:-----|:-----------|:-----------:|
| **Trivial** — 소스 제공, 1-3줄 버그, one-liner exploit | 직접 풀이 (팀 없음) | 0 |
| **Reversing / Crypto** — 알고리즘 복원, 수학적 역연산 | reverser → solver → critic → verifier → reporter | 5 |
| **Pwn (명확한 취약점)** — 오버플로우, 포맷 스트링 등 | reverser → chain → critic → verifier → reporter | 5 |
| **Pwn (불명확한 취약점)** — 크래시 발견 필요 | reverser → trigger → chain → critic → verifier → reporter | 6 |
| **Web** — 인젝션, SSRF, 인증 우회 | scanner → analyst → exploiter → reporter | 4 |
| **Firmware** — ARM 바이너리 diff, 에뮬레이션 PoC | fw_profiler → fw_inventory → fw_surface → fw_validator → reporter | 5 |

### 버그바운티 파이프라인 (v3 — 7단계)

```
Phase 0   @target_evaluator     GO/NO-GO 타겟 ROI 평가
          ─── GO gate ──────────────────────────────────────────
Phase 1   @scout + @analyst     병렬 정찰 + 중복 사전검증 + CVE 매칭
Phase 1.5 @analyst (N 병렬)    OWASP 카테고리별 병렬 헌팅 (대형 코드베이스 전용)
Phase 2   @exploiter            PoC 개발 + 품질 등급 분류 (1-4)
Phase 3   @reporter             보고서 초안 + CVSS 계산
Phase 4   @critic + @architect  2라운드 리뷰 (팩트 + 프레이밍)
Phase 4.5 @triager_sim          적대적 트리아저 시뮬레이션 (SUBMIT / STRENGTHEN / KILL)
Phase 5   @reporter             최종본 + ZIP 패키징
Phase 6   TeamDelete            정리
```

> **철칙**: Exploit 없으면, Report 없음. 작동하는 PoC가 없는 발견사항은 자동으로 폐기됩니다.

---

## 에이전트

17개의 전문화된 에이전트, 각각 명확한 역할, 구조화된 프롬프트, 산출물 계약:

### CTF 에이전트

| 에이전트 | 역할 | 모델 | 입력 | 출력 |
|:---------|:-----|:----:|:-----|:-----|
| **reverser** | 바이너리 구조 분석, 보호 기법 탐지, 공격 표면 매핑 | Sonnet | 바이너리 + 소스(있다면) | reversal_map.md |
| **trigger** | 크래시 발견, 입력 최소화, 프리미티브 식별 | Sonnet | reversal_map.md | trigger_report.md + trigger_poc.py |
| **solver** | reversing/crypto 챌린지용 역연산 | Opus | reversal_map.md | solve.py |
| **chain** | 다단계 익스플로잇 조립: leak → overwrite → shell | Opus | reversal_map.md + trigger_report.md | solve.py + chain_report.md |
| **critic** | 주소, 오프셋, 상수, 로직 교차 검증 | Opus | 모든 이전 산출물 | critic_review.md (APPROVED/REJECTED) |
| **verifier** | 로컬 3회 재현 → 원격 익스플로잇 실행 | Sonnet | solve.py | FLAG_FOUND: <flag> |
| **reporter** | 실패한 시도 및 핵심 기법 포함 챌린지 라이트업 | Sonnet | 모든 산출물 + 플래그 | knowledge/challenges/<name>.md |

### 버그바운티 에이전트

| 에이전트 | 역할 | 모델 | 출력 |
|:---------|:-----|:----:|:-----|
| **target_evaluator** | 프로그램 분석, 경쟁 밀도, 기술스택 매칭, ROI 점수화 | Sonnet | target_assessment.md (GO/NO-GO) |
| **scout** | 정찰 + HackerOne Hacktivity 중복 사전검증 | Sonnet | recon_report.json + program_context.md |
| **analyst** | CVE 매칭, 변종 분석, source→sink 추적, 신뢰도 점수화 | Sonnet | vulnerability_candidates.md |
| **exploiter** | PoC 개발, 통합 테스트, 품질 등급 분류 | Opus | PoC 스크립트 + 증거 |
| **triager_sim** | 적대적 트리아저 시뮬레이션 — 회의적 리뷰어 관점에서 보고서 공격 | Opus | SUBMIT / STRENGTHEN / KILL 판정 |

### 펌웨어 에이전트

| 에이전트 | 역할 | 모델 | 출력 |
|:---------|:-----|:----:|:-----|
| **fw_profiler** | 펌웨어 이미지 프로파일링, 아키텍처 탐지 | Sonnet | firmware_profile.md |
| **fw_inventory** | 바이너리 인벤토리, 버전 추출, CVE 매칭 | Sonnet | firmware_inventory.md |
| **fw_surface** | 공격 표면 매핑, 바이너리 diff 분석 | Sonnet | attack_surface.md |
| **fw_validator** | QEMU 에뮬레이션, 동적 PoC 검증 | Sonnet | validation_results.md |

---

## 도구 체인

### 리버스 엔지니어링 및 바이너리 분석

- **디스어셈블리**: radare2, objdump, strings, readelf, nm, file
- **디컴파일**: Ghidra (MCP), jadx (Android)
- **디버깅**: gdb + pwndbg + GEF (93 commands), strace
- **심볼릭 실행**: angr, unicorn, z3-solver, keystone-engine
- **바이너리 파싱**: LIEF, pyelftools, capstone, seccomp-tools

### 익스플로잇 개발

- **프레임워크**: pwntools (process/remote, ROP, shellcraft, ELF 파싱)
- **가젯**: ROPgadget, ropper, one_gadget
- **암호**: pycryptodome, sympy, z3-solver
- **패칭**: patchelf, LIEF

### 웹 보안

- **인젝션**: sqlmap, commix (command injection), dalfox (XSS)
- **SSRF**: SSRFmap (18+ 모듈)
- **업로드**: fuxploider (파일 업로드 익스플로잇)
- **정찰**: ffuf, subfinder, katana, httpx, gau, waybackurls, arjun, dirsearch
- **스캔**: nuclei (12K+ 탐지 템플릿), trufflehog (800+ 시크릿 타입)
- **프록시**: mitmproxy, interactsh-client

### 코드 분석

- **시맨틱**: CodeQL (taint tracking, variant analysis)
- **정적**: Semgrep (skill plugin), custom rule authoring
- **스마트 컨트랙트**: Slither (100+ Solidity detectors), Mythril (EVM symbolic), Foundry (forge/cast/anvil)

### MCP 서버

| 서버 | 기능 |
|:-----|:-----|
| **mcp-gdb** | 브레이크포인트, 메모리 검사, 스텝 실행 GDB 디버깅 |
| **radare2-mcp** | 디스어셈블리, 디컴파일, 함수 목록, xrefs |
| **ghidra-mcp** | 헤드리스 디컴파일, 구조체/열거형 분석 |
| **frida-mcp** | 동적 계측, 후킹, 프로세스 스포닝 |
| **pentest-mcp** | nmap 스캔, nikto, gobuster, john/hashcat |
| **playwright** | 웹 익스플로잇용 브라우저 자동화 |
| **context7** | 최신 라이브러리 문서 조회 |
| **nuclei-mcp** | 12K+ 취약점 탐지 템플릿 스캔 |
| **codeql-mcp** | 시맨틱 taint tracking, 변종 분석 |
| **semgrep-mcp** | 패턴 기반 정적 분석 |

### 참조 데이터베이스

- **ExploitDB**: 47K+ exploits (searchsploit CLI)
- **PoC-in-GitHub**: 8K+ CVE proof-of-concepts
- **PayloadsAllTheThings**: 70+ vulnerability categories
- **trickest-cve**: 154K+ CVE PoCs
- **SecLists**: Fuzzing wordlists, passwords, discovery
- **libc-database**: ret2libc용 libc 오프셋 조회

---

## 연구 기반

에이전트 정의는 10+ 외부 LLM 보안 프레임워크의 패턴을 통합:

| 패턴 | 출처 | 적용 대상 |
|:-----|:-----|:----------|
| **Variant Analysis** | Google Big Sleep | analyst, scout |
| **LLM-first PoV** | RoboDuck (AIxCC 3위) | chain |
| **Symbolic + Neural Hybrid** | ATLANTIS (AIxCC 1위) | reverser |
| **No Exploit, No Report** | Shannon, XBOW | exploiter, reporter |
| **Confidence Questionnaire** | Shannon | analyst |
| **Iterative Context Gathering** | Vulnhuntr | analyst |
| **Coverage Gap Analysis** | RoboDuck | trigger |
| **Dual-Approach Parallel** | RoboDuck | chain, solver |
| **OWASP Parallel Hunters** | Shannon | orchestrator |
| **Guardrails** | CAI (300+ LLM) | orchestrator |

---

## 빠른 시작

### 사전 요구사항

```bash
# Claude Code CLI (필수)
npm install -g @anthropic-ai/claude-code

# Python 3.10+ 및 의존성
pip install pwntools z3-solver pycryptodome requests paramiko

# 보안 도구 (권장)
sudo apt install radare2 gdb python3-pwndbg binutils strace ltrace
```

### 설치

```bash
git clone https://github.com/yourusername/Terminator.git
cd Terminator
chmod +x terminator.sh

# 선택사항: 선호하는 모델 설정
export TERMINATOR_MODEL=opus  # 또는 sonnet (기본값), haiku
```

### 사용 예시

#### 대화형 모드 (권장)

```bash
cd Terminator
claude

# CTF — 챌린지 설명만 하면 됨:
# "pwnable.kr fd 챌린지 풀어줘. SSH: fd@pwnable.kr -p2222 (pw: guest)"
# "tests/wargames/Level10_1.zip 풀어줘. remote: host1.dreamhack.games:12345"

# 버그바운티 — 타겟 이름만:
# "HackerOne의 <program> 버그바운티 시작해줘"

# 오케스트레이터가 자동으로 파이프라인 선택,
# 에이전트 팀 스폰, 단계별 진행합니다.
```

#### 자율 모드 (무인)

```bash
# CTF 챌린지 (zip 또는 디렉토리)
./terminator.sh ctf /path/to/challenge[.zip]

# 버그바운티 타겟
./terminator.sh bounty https://target.com "*.target.com"

# 펌웨어 분석 (SCOUT 설정 필요)
export TERMINATOR_ACK_AUTHORIZATION=1
export TERMINATOR_FIRMWARE_PROFILE=analysis  # 또는 exploit
./terminator.sh firmware /path/to/firmware.bin

# 진행 상황 모니터
./terminator.sh status
./terminator.sh logs
```

---

## 프로젝트 구조

```
Terminator/
├── .claude/agents/          # 17개 에이전트 정의 (~4,300줄)
│   ├── reverser.md          #   바이너리 분석 → reversal_map.md
│   ├── chain.md             #   익스플로잇 체인 (+ heap sub-protocol)
│   ├── critic.md            #   교차 검증
│   ├── fw_*.md              #   펌웨어 분석 (4개 에이전트)
│   └── ...                  #   + 10개 전문가 에이전트
├── knowledge/               # 축적된 경험 (20개 라이트업, 17개 기법)
│   ├── index.md             #   마스터 인덱스
│   ├── challenges/          #   챌린지별 라이트업
│   └── techniques/          #   재사용 가능한 공격 기법
├── research/                # LLM 보안 프레임워크 분석 (14개 문서)
├── tools/                   # 파이프라인 도구
│   ├── dag_orchestrator/    #   DAG 스케줄링 + Claude CLI 핸들러
│   ├── mitre_mapper.py      #   CVE→CWE→CAPEC→ATT&CK
│   ├── recon_pipeline.py    #   6-phase 정찰 오케스트레이터
│   ├── sarif_generator.py   #   SARIF 2.1.0 출력
│   └── mcp-servers/         #   nuclei, codeql, semgrep MCP
├── web/                     # FastAPI + D3 대시보드 (독립 + Docker)
├── targets/                 # 버그바운티 작업공간 (28+ 미션)
├── tests/                   # CTF 파일 + E2E 리플레이 벤치마크
├── CLAUDE.md                # 오케스트레이터 지침
├── terminator.sh            # 자율 모드 런처
├── docker-compose.yml       # 전체 스택 인프라 (시크릿 환경변수화)
└── .env.example             # 환경변수 설정 템플릿
```

---

## 출력물

### CTF 챌린지

각 풀이된 챌린지는 다음을 생성:

| 산출물 | 설명 |
|:-------|:-----|
| `solve.py` | 작동하는 익스플로잇 스크립트 (로컬 3회 테스트, 원격 검증) |
| `knowledge/challenges/<name>.md` | 분석, 실패한 시도, 핵심 기법 포함 상세 라이트업 |
| `FLAG_FOUND: <flag>` | 원격 서버에서 획득한 검증된 플래그 |

### 버그바운티 타겟

각 평가된 타겟은 다음을 생성:

| 산출물 | 설명 |
|:-------|:-----|
| `targets/<name>/h1_reports/` | HackerOne 형식 취약점 보고서 |
| `targets/<name>/evidence/` | PoC 스크립트, 스크린샷, 네트워크 캡처 |
| `targets/<name>/submission/*.zip` | 패키징된 제출 산출물 |

---

## 설계 결정

### 왜 순차 파이프라인인가? (병렬이 아닌)

보안 분석은 **컨텍스트 축적**이 필요합니다. reverser의 공격 지도는 익스플로잇 전략을 근본적으로 형성합니다. 모든 에이전트를 병렬로 실행하면 단절되고 종종 모순되는 결과가 생성됩니다. 구조화된 핸드오프가 있는 순차 파이프라인은 각 에이전트가 검증된 이전 작업을 기반으로 구축하도록 보장합니다.

### 왜 Critic 에이전트인가?

익스플로잇 개발은 오류가 발생하기 쉽습니다 — 잘못된 오프셋, 잘못된 상수, 결함 있는 로직. critic은 익스플로잇이 verifier에 도달하기 전에 도구(r2, gdb)를 사용하여 모든 주소와 계산을 독립적으로 검증합니다. 이는 실패한 원격 시도로 시간을 낭비하는 오류를 포착합니다.

### 왜 적대적 트리아저 시뮬레이션인가?

버그바운티 보고서는 시간 압박 하에 회의적인 트리아저에 의해 평가됩니다. triager_sim 에이전트는 리뷰어의 관점에서 보고서를 공격합니다 — 누락된 PoC, 중복 겹침, 약한 프레이밍, AI 생성 보일러플레이트를 확인 — 제출 전에. 이는 거절률을 줄입니다.

### 왜 에이전트별 모델인가?

모든 에이전트가 가장 강력한 모델이 필요한 것은 아닙니다. Reverser와 verifier는 Sonnet으로 잘 작동합니다(패턴 매칭, 실행). Solver와 critic은 Opus가 필요합니다(복잡한 추론, 수학적 증명). 에이전트별 명시적 모델 할당은 품질을 희생하지 않고 토큰을 절약합니다.

---

## 학습된 기법

지식 베이스에는 챌린지에서 축적된 재사용 가능한 패턴이 포함되어 있습니다:

| 기법 | 설명 |
|:-----|:-----|
| **GDB Oracle Reverse** | 메모리를 패치하고 실행을 추적하여 커스텀 VM의 비선형 함수 역산 |
| **z3 Protocol Simulation** | 정확한 솔루션을 위해 전체 네트워크 프로토콜을 SMT 제약으로 모델링 |
| **SSH Interaction Patterns** | paramiko exec → nc pipe → SSH tunnel + pwntools (신뢰성 계층) |
| **Incremental Exploit Dev** | 단계별: leak → test → overflow → test → ROP → test → combine |
| **Dual-Approach Parallel** | 3회 실패 후, 다른 전략으로 2개의 solver를 동시 스폰 |
| **Constant Verification** | 항상 GDB 메모리 덤프를 통해 상수 검증 (정적 분석만으로는 off-by-one 오류 발생) |
| **Trivial Detection** | 소스 < 50줄 + 1-3줄 버그 + one-liner exploit = 에이전트 팀 건너뛰기 |

---

## 최근 개선사항 (2026-02)

- **시크릿 환경변수화** — docker-compose.yml 자격증명이 `${VAR:-default}` 패턴 사용
- **커스텀 에이전트 타입** — terminator.sh 자율 모드가 적절한 에이전트 정의 사용
- **결정적 파이프라인** — DAG 엔진이 `claude_handler.py`를 통해 Claude CLI에 연결
- **E2E 리플레이 벤치마크** — solve.py 자동 재실행으로 리그레션 감지
- **Heap 익스플로잇 프로토콜** — chain.md에 allocator fingerprinting, glibc 버전별 기법 추가
- **3모델 외부 평가** — GPT/Gemini/Claude 독립 파이프라인 검토 반영

---

## 보안 및 윤리

> **인가된 사용만**

이 시스템은 다음 용도로만 설계되었습니다:

- **CTF / Wargame 챌린지** — 보안 학습을 위해 설계된 연습 환경
- **버그바운티 프로그램** — 명시적 인가가 있는 타겟만 (예: HackerOne 프로그램)
- **보안 연구** — 적절한 범위가 있는 제어된 실험 환경

**엄격한 규칙:**
- 안전한 페이로드만 (`id`, `whoami`, `cat /etc/passwd` — 파괴적 명령 금지)
- 인가되지 않은 시스템에 대한 공격 금지
- 프롬프트 인젝션 가드레일이 악의적으로 분석된 코드로부터 에이전트 보호
- 모든 발견사항은 책임 있는 공개 관행 준수

---

## 라이선스

MIT License

---

## 감사의 말

- Anthropic **Claude Code Team** — 에이전트 조율 기능
- **oh-my-claudecode** 프레임워크 — 멀티에이전트 패턴
- CTF 커뮤니티 — 챌린지 데이터셋 및 라이트업
- 버그바운티 연구자 — 공개 모범 사례
- 보안 도구 유지관리자 (pwntools, radare2, ghidra, frida 등)

---

**주의**: 이것은 연구 도구입니다. 소유하지 않은 시스템을 테스트하기 전에 항상 적절한 인가를 받으십시오. 컴퓨터 시스템에 대한 무단 접근은 불법입니다.
