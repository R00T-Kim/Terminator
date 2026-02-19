<div align="center">

<br>

<img src="https://img.shields.io/badge/TERMINATOR-Autonomous_Security_Agent-cc0000?style=for-the-badge&labelColor=1a1a1a" alt="Terminator">

<br><br>

**CTF 문제를 자율적으로 풀고, 버그 바운티 취약점을 찾아내는 멀티 에이전트 AI 시스템.**

[Claude Code Agent Teams](https://docs.anthropic.com/en/docs/claude-code) 기반 — 17개의 전문 에이전트가 구조화된 핸드오프를 통해 순차 파이프라인으로 협업합니다.

<br>

[![Claude Code](https://img.shields.io/badge/Claude_Code-Agent_Teams-7C3AED?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA4LTggNHoiLz48L3N2Zz4=)](https://docs.anthropic.com/en/docs/claude-code)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Solidity](https://img.shields.io/badge/Solidity-Foundry-363636?style=flat-square&logo=solidity&logoColor=white)](https://book.getfoundry.sh/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

<br>

| CTF 풀이 | 버그 바운티 타겟 | AI 에이전트 | MCP 서버 | 보안 도구 |
|:--------:|:---------------:|:----------:|:--------:|:--------:|
| **20** | **28+** | **17** | **10** | **30+** |

<br>

[English](README.md) | **한국어**

</div>

---

## 무엇을 하는가

Terminator는 취약점을 찾기만 하는 것이 아니라 — **검증**합니다.

- 모든 CTF 익스플로잇은 원격 실행 전 **로컬에서 3회 테스트**
- 모든 버그 바운티 발견 사항에는 **동작하는 PoC가 필수**
- 모든 보고서는 제출 전 **적대적 트리아지 시뮬레이션** 통과 필수

```
사용자: "pwnable.kr fd 풀어줘. SSH: fd@pwnable.kr -p2222 (pw: guest)"

Terminator:
  → @reverser 스폰  → 바이너리 분석, 공격 지도 생성
  → @chain 스폰     → 공격 지도 기반 익스플로잇 작성
  → @critic 스폰    → gdb/r2로 오프셋 교차 검증
  → @verifier 스폰  → 로컬 3회 실행 후 원격 실행
  → FLAG_FOUND: mama, are you prout of me?
```

---

## 아키텍처

```
                        ┌─────────────────────────┐
                        │     Claude Code CLI      │
                        │   오케스트레이터 (리더)    │
                        └────────────┬────────────┘
                                     │
                  ┌──────────────────┼──────────────────┐
                  │                                      │
        ┌────────▼─────────┐                  ┌─────────▼────────┐
        │  CTF 파이프라인   │                  │ 버그 바운티 v3    │
        │    (순차 실행)    │                  │   (7 단계)       │
        └────────┬─────────┘                  └─────────┬────────┘
                 │                                      │
    ┌────────────┼────────────┐          ┌──────────────┼──────────────┐
    │            │            │          │              │              │
┌───▼───┐  ┌────▼────┐  ┌───▼───┐  ┌───▼────┐  ┌─────▼─────┐  ┌────▼────┐
│Reverser│→ │ Chain/  │→ │Critic │  │ Scout  │→ │ Exploiter │→ │ Triager │
│       │  │ Solver  │  │       │  │+Analyst│  │           │  │   Sim   │
└───────┘  └─────────┘  └───┬───┘  └────────┘  └───────────┘  └─────────┘
                        ┌────▼────┐
                        │Verifier │→ FLAG_FOUND
                        └─────────┘

          ┌──────────────────────────────────────────────┐
          │              인프라 계층                       │
          ├──────────┬───────────┬──────────┬────────────┤
          │ 10 MCP   │ 대시보드  │ 30+      │ 지식       │
          │ 서버     │ (Web UI)  │ 도구     │ 베이스     │
          └──────────┴───────────┴──────────┴────────────┘
```

### 구조화된 핸드오프

에이전트 간 구조화된 산출물 전달을 통해 단계 간 컨텍스트 유실이 없습니다:

```
[HANDOFF from @reverser to @chain]
- Artifact: reversal_map.md
- Confidence: PASS
- Key Result: read_input()에서 BOF 발견, 64바이트 오버플로우, 카나리 비활성화
- Next Action: system("/bin/sh") 타겟 leak + ROP 체인 구축
```

---

## 파이프라인

### CTF — 적응형 파이프라인 선택

| 조건 | 파이프라인 | 에이전트 수 |
|:-----|:----------|:----------:|
| **Trivial** — 소스 제공, 1-3줄 버그 | 직접 풀이 | 0 |
| **리버싱 / 크립토** — 수학적 역연산 필요 | `reverser → solver → critic → verifier → reporter` | 5 |
| **Pwn (명확한 취약점)** — 명백한 오버플로우/포맷스트링 | `reverser → chain → critic → verifier → reporter` | 5 |
| **Pwn (불명확한 취약점)** — 크래시 탐색 필요 | `reverser → trigger → chain → critic → verifier → reporter` | 6 |
| **Web** — 인젝션, SSRF, 인증 우회 | `scanner → analyst → exploiter → reporter` | 4 |
| **펌웨어** — ARM 바이너리 diff, 에뮬레이션 PoC | `fw_profiler → fw_inventory → fw_surface → fw_validator → reporter` | 5 |

### 버그 바운티 — v3 파이프라인 (7단계)

```
Phase 0   @target_evaluator     GO / NO-GO 판정 (ROI, 경쟁도, 기술 스택)
          ─── GO 게이트 ────────────────────────────────────────────────
Phase 0.5 @scout                자동 도구 스캔 (Slither, Semgrep, Mythril)
Phase 1   @scout + @analyst     병렬 정찰 + 중복 사전 검사 + CVE 매칭
Phase 1.5 @analyst (N개 병렬)   OWASP 카테고리별 헌팅 (대형 코드베이스 전용)
Phase 2   @exploiter            PoC 개발 + Quality Tier 게이트 (Tier 1-2만 통과)
Phase 3   @reporter             보고서 초안 + CVSS
Phase 4   @critic + @architect  2라운드 리뷰: 팩트체크 → 프레이밍
Phase 4.5 @triager_sim          적대적 트리아지 (SUBMIT / STRENGTHEN / KILL)
Phase 5   @reporter             최종 보고서 + ZIP 패키징
Phase 6   TeamDelete            정리
```

> **철칙**: 익스플로잇 없이 보고서 없다. 동작하는 PoC가 없는 발견 사항은 자동 삭제됩니다.

---

## 에이전트

### CTF 에이전트

| 에이전트 | 역할 | 모델 | 산출물 |
|:---------|:-----|:----:|:-------|
| **reverser** | 바이너리 분석, 보호기법 탐지, 공격 표면 매핑 | Sonnet | `reversal_map.md` |
| **trigger** | 크래시 탐색, 입력 최소화, 프리미티브 식별 | Sonnet | `trigger_report.md` |
| **solver** | 리버싱/크립토 챌린지의 역연산 | Opus | `solve.py` |
| **chain** | 멀티 스테이지 익스플로잇: leak → overwrite → shell | Opus | `solve.py` |
| **critic** | 오프셋, 상수, 로직의 교차 검증 | Opus | `critic_review.md` |
| **verifier** | 로컬 3회 재현 → 원격 실행 | Sonnet | `FLAG_FOUND` |
| **reporter** | 실패한 시도와 기법을 포함한 라이트업 작성 | Sonnet | `knowledge/challenges/<name>.md` |

### 버그 바운티 에이전트

| 에이전트 | 역할 | 모델 | 산출물 |
|:---------|:-----|:----:|:-------|
| **target_evaluator** | 프로그램 ROI 평가, GO/NO-GO 게이트 | Sonnet | `target_assessment.md` |
| **scout** | 정찰 + 중복 사전 검사 + 자동 도구 스캔 | Sonnet | `recon_report.json` |
| **analyst** | CVE 매칭, source→sink 추적, 신뢰도 평가 | Sonnet | `vulnerability_candidates.md` |
| **exploiter** | PoC 개발, Quality Tier 분류 | Opus | PoC 스크립트 + 증거 |
| **triager_sim** | 적대적 트리아지 — 제출 전 보고서 공격 | Opus | SUBMIT / STRENGTHEN / KILL |

### 펌웨어 에이전트

| 에이전트 | 역할 | 모델 | 산출물 |
|:---------|:-----|:----:|:-------|
| **fw_profiler** | 펌웨어 이미지 프로파일링, 아키텍처 탐지 | Sonnet | `firmware_profile.md` |
| **fw_inventory** | 바이너리 인벤토리, 버전 추출, CVE 매칭 | Sonnet | `firmware_inventory.md` |
| **fw_surface** | 공격 표면 매핑, 바이너리 diff 분석 | Sonnet | `attack_surface.md` |
| **fw_validator** | QEMU 에뮬레이션, 동적 PoC 검증 | Sonnet | `validation_results.md` |

---

## 대시보드

모든 작업을 모니터링하는 실시간 웹 UI — 외부 의존성 없이 **독립 모드**로 실행됩니다.

```
┌──────────────────────────────────────────────────────────────────┐
│  TERMINATOR                                        ● WebSocket  │
├──────────┬──────────────┬──────────────┬──────────┬─────────────┤
│ CTF      │ 버그 바운티   │ 인프라       │ 발견사항 │ 공격        │
│ 세션     │ 미션         │ 스트럭처     │          │ 그래프      │
├──────────┴──────────────┴──────────────┴──────────┴─────────────┤
│                                                                  │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │ 20      │  │ 28+     │  │ 114+    │  │ 16      │           │
│  │ FLAGS   │  │ TARGETS │  │ FINDINGS│  │ TOOLS   │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
│                                                                  │
│  심각도 분포              도구 상태          실시간 로그          │
│  ████ CRITICAL  12         ● Radare2    up     [session.log     │
│  ██████ HIGH    18         ● GDB        up      tail -f ...]    │
│  ████████ MED   34         ● Nuclei     up                      │
│  ██ LOW         8          ● Slither    up                      │
│  █ INFO         42         ● CodeQL     up                      │
│                            ● Foundry    up                      │
│  D3 Force-Directed 공격 그래프                                   │
│  ┌──────────────────────────────────────────────────┐           │
│  │  (타겟) ──→ (발견사항) ──→ (기법)                  │           │
│  │     ↓             ↓              ↓               │           │
│  │  (서비스)    (익스플로잇)     (보고서)              │           │
│  └──────────────────────────────────────────────────┘           │
└──────────────────────────────────────────────────────────────────┘
```

### 5개 탭

| 탭 | 데이터 소스 | 기능 |
|:---|:-----------|:-----|
| **CTF 세션** | `reports/` 디렉토리 | 세션 목록, 플래그, 라이트업, WebSocket 실시간 로그 |
| **버그 바운티 미션** | `targets/` 디렉토리 | 파이프라인 단계 추적, GO/NO-GO 상태, 미션별 발견사항 |
| **인프라** | System + Docker | 16+ 도구 상태 확인, Docker 서비스 상태, RAG 통계 |
| **발견사항** | 파일시스템 + DB | CVSS 자동 추출이 포함된 집계된 발견사항, 심각도 분포 |
| **공격 그래프** | Neo4j 또는 파일시스템 | D3 force-directed 그래프 — 타겟, 발견사항, 기법, 서비스 |

### 두 가지 운영 모드

| 모드 | 요구사항 | 기능 |
|:-----|:---------|:-----|
| **독립 모드** (기본) | Python + FastAPI만 | 파일시스템 기반 발견사항 집계, 도구 상태, 마크다운 기반 공격 그래프, 팀 설정 기반 에이전트 히스토리 |
| **풀 스택** (선택) | Docker Compose | 독립 모드의 모든 기능 + pgvector RAG, Neo4j 그래프 DB, Ollama 임베딩, LiteLLM 멀티모델 프록시 |

```bash
# 독립 모드 — Docker 불필요
cd web && uvicorn app:app --host 0.0.0.0 --port 3000

# 풀 스택 — 6개 Docker 서비스
docker compose up -d
```

---

## 도구 체인

### MCP 서버 — AI 네이티브 도구 통합

10개의 MCP 서버가 에이전트에게 보안 도구에 대한 직접적인 프로그래밍 접근을 제공합니다:

| 서버 | 기능 |
|:-----|:-----|
| **mcp-gdb** | 브레이크포인트, 메모리 검사, 스테핑, 백트레이스 |
| **radare2-mcp** | 디스어셈블리, 디컴파일, xref, 함수 분석 |
| **ghidra-mcp** | 헤드리스 디컴파일, 구조체, 열거형 |
| **frida-mcp** | 동적 계측, 후킹, 프로세스 스폰 |
| **pentest-mcp** | nmap, gobuster, nikto, john, hashcat |
| **nuclei-mcp** | 12K+ 취약점 탐지 템플릿 |
| **codeql-mcp** | 시맨틱 taint tracking, 변종 분석 |
| **semgrep-mcp** | 패턴 기반 정적 분석 |
| **playwright** | 웹 익스플로잇을 위한 브라우저 자동화 |
| **context7** | 최신 라이브러리 문서 조회 |

### 보안 도구

<details>
<summary><b>리버스 엔지니어링 & 익스플로잇 개발</b></summary>

| 카테고리 | 도구 |
|:---------|:-----|
| 디스어셈블리 | radare2, objdump, strings, readelf, nm |
| 디컴파일 | Ghidra (MCP), jadx |
| 디버깅 | gdb + pwndbg + GEF (93개 명령어), strace |
| 심볼릭 실행 | angr, unicorn, z3-solver, keystone |
| 익스플로잇 | pwntools, ROPgadget, ropper, one_gadget |
| 암호학 | pycryptodome, sympy, z3-solver |

</details>

<details>
<summary><b>웹 보안</b></summary>

| 카테고리 | 도구 |
|:---------|:-----|
| 인젝션 | sqlmap, commix, dalfox (XSS) |
| SSRF | SSRFmap (18+ 모듈) |
| 정찰 | ffuf, subfinder, katana, httpx, gau, waybackurls, arjun |
| 스캐닝 | nuclei (12K+ 템플릿), trufflehog (800+ 시크릿 타입) |
| 업로드 | fuxploider |

</details>

<details>
<summary><b>코드 분석 & 스마트 컨트랙트</b></summary>

| 카테고리 | 도구 |
|:---------|:-----|
| 시맨틱 | CodeQL (taint tracking, 변종 분석) |
| 정적 분석 | Semgrep (커스텀 룰 작성) |
| 스마트 컨트랙트 | Slither (100+ 탐지기), Mythril (EVM 심볼릭), Foundry 1.5.1 |
| AI | Gemini CLI (gemini-3-pro-preview) |

</details>

<details>
<summary><b>펌웨어 분석</b></summary>

| 카테고리 | 도구 |
|:---------|:-----|
| 에뮬레이션 | QEMU ARM user-mode, rootfs 마운팅 |
| Diffing | 펌웨어 버전간 바이너리 diff |
| 프로파일링 | 아키텍처 탐지, 라이브러리 인벤토리 |
| 검증 | 에뮬레이션 환경에서의 동적 PoC |

</details>

<details>
<summary><b>참조 데이터베이스</b></summary>

| 데이터베이스 | 커버리지 |
|:-------------|:---------|
| ExploitDB | 47K+ 익스플로잇 |
| PoC-in-GitHub | 8K+ CVE PoC |
| PayloadsAllTheThings | 70+ 취약점 카테고리 |
| trickest-cve | 154K+ CVE PoC |
| SecLists | 워드리스트, 패스워드, 디스커버리 |

</details>

<details>
<summary><b>스킬 플러그인 (Trail of Bits, Sentry, Anthropic)</b></summary>

| 플러그인 | 스킬 | 용도 |
|:---------|:-----|:-----|
| static-analysis | semgrep, codeql, sarif-parsing | 자동 정적 분석 |
| variant-analysis | variant-analysis | CVE 변종 패턴 탐색 |
| testing-handbook | aflpp, libfuzzer, harness-writing + 12개 | 퍼징 (Trail of Bits) |
| insecure-defaults | insecure-defaults | 하드코딩 시크릿, 취약한 인증 |
| sharp-edges | sharp-edges | 위험한 API 탐지 |
| audit-context | audit-context-building | 감사 전 아키텍처 매핑 |
| dwarf-expert | dwarf-expert | DWARF 디버그 포맷 |
| yara-authoring | yara-rule-authoring | YARA 룰 작성 |
| differential-review | differential-review | Git diff 보안 리뷰 |
| sentry-skills | find-bugs, security-review, code-review | 버그 탐지 |

</details>

---

## 인프라

### 독립 모드 (기본)

Docker 불필요. 대시보드가 파일시스템에서 직접 읽습니다:

| 소스 | 읽는 내용 |
|:-----|:----------|
| `targets/` | 28+ 미션 디렉토리 (평가, 발견사항, 보고서) |
| `reports/` | CTF 세션 로그, 플래그, 라이트업 |
| `~/.claude/teams/` | 에이전트 팀 설정 (실행 히스토리) |
| System `$PATH` | `shutil.which()`로 자동 탐지되는 16개 보안 도구 |

마크다운 보고서에서 자동 CVSS 추출을 포함한 **114+ 발견사항**을 집계합니다. 취약점 후보, 정찰 데이터, 보고서 파일로부터 D3 호환 공격 그래프를 구축합니다 — Neo4j 불필요.

### 풀 스택 모드 (선택)

```bash
docker compose up -d
```

| 서비스 | 포트 | 용도 |
|:-------|:----:|:-----|
| **pgvector** | 5433 | RAG 벡터 데이터베이스 |
| **ollama** | 11434 | 로컬 임베딩 모델 |
| **rag-api** | 8100 | ExploitDB/PoC 지식 검색 |
| **neo4j** | 7474 | 공격 표면 그래프 데이터베이스 |
| **litellm** | 4000 | 멀티모델 프록시 (Claude/Gemini/DeepSeek) |
| **web-ui** | 3000 | 풀 DB 기반 기능을 갖춘 대시보드 |

### 파이프라인 도구

| 도구 | 용도 |
|:-----|:-----|
| **MITRE Mapper** | CVE → CWE → CAPEC → ATT&CK 매핑 (27개 CWE) |
| **Attack Graph** | Neo4j 또는 파일시스템 기반 공격 표면 시각화 |
| **DAG Orchestrator** | 파이프라인 스케줄링 (CTF pwn/rev, bounty, firmware) |
| **Recon Pipeline** | 6단계 자동 정찰 |
| **SARIF Generator** | GitHub Code Scanning 호환 출력 |
| **PDF Generator** | 보고서 PDF 생성 |

---

## 실적

### CTF 챌린지 — 20문제 풀이

| 카테고리 | 수 | 사용 기법 |
|:---------|:--:|:---------|
| Pwn (heap, stack, ROP) | 10 | pwntools, ROP 체인, GOT overwrite, 셸코드 |
| 리버싱 (VM, 난독화) | 6 | GDB Oracle, DFA 추출, z3, 커스텀 VM 분석 |
| 크립토 | 2 | AES-ECB, z3 제약 풀이 |
| 기타 (로직, 필터 우회) | 2 | 연산자 우선순위, 이진 탐색 |

### 버그 바운티 — 28+ 타겟 평가

| 항목 | 수 |
|:-----|---:|
| 평가한 프로그램 | 28+ |
| 플랫폼 | Immunefi, HackerOne, Bugcrowd |
| 카테고리 | 스마트 컨트랙트 (DeFi), 웹 앱, VPN, IoT/펌웨어, AI/SDK |
| 분석한 스마트 컨트랙트 | 50+ |
| 조사한 취약점 리드 | 100+ |
| 동작하는 PoC를 갖춘 발견사항 | 15+ |

> 구체적인 타겟과 발견사항은 공개 완료 시까지 비공개로 유지됩니다.

---

## 연구 기반

에이전트 정의에는 10개 이상의 LLM 보안 프레임워크 패턴이 반영되어 있습니다:

| 패턴 | 출처 |
|:-----|:-----|
| 변종 분석 — CVE 패치 diff를 시드로 활용 | Google Big Sleep (Project Zero + DeepMind) |
| LLM 우선 PoV 생성 | RoboDuck (AIxCC 3위) |
| 심볼릭 + 뉴럴 하이브리드 | ATLANTIS (AIxCC 1위) |
| 익스플로잇 없이 보고서 없다 | Shannon, XBOW |
| 반복적 컨텍스트 수집 — 3-pass 역추적 | Vulnhuntr |
| 이중 접근 병렬 — 3회 실패 후 2가지 전략 | RoboDuck |
| OWASP 병렬 헌터 | Shannon |
| PoC Quality Tier 게이트 (1-4) | XBOW |
| 적대적 트리아지 시뮬레이션 | 자체 개발 |
| 프롬프트 인젝션 가드레일 | CAI (300+ LLM 에이전트) |

---

## 빠른 시작

### 사전 요구사항

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) + Anthropic API 키
- Python 3.10+ (pwntools, z3-solver, angr)
- gdb (pwndbg 또는 GEF), radare2
- Docker (선택, 풀 인프라 스택용)

### 대화형 모드

```bash
cd Terminator && claude

# CTF:
# "pwnable.kr fd 풀어줘. SSH: fd@pwnable.kr -p2222 (pw: guest)"

# 버그 바운티:
# "이뮤니파이에서 하이~크리티컬 취약점 찾을때까지 ㄱㄱ"
```

### 자율 모드

```bash
./terminator.sh ctf /path/to/challenge.zip     # CTF
./terminator.sh bounty https://target.com       # 버그 바운티
./terminator.sh status                          # 모니터링
```

### 대시보드

```bash
# 독립 모드 (Docker 불필요)
cd web && pip install -r requirements.txt && uvicorn app:app --port 3000

# 풀 스택
docker compose up -d
# http://localhost:3000 접속
```

---

## 프로젝트 구조

```
Terminator/
├── .claude/agents/          # 17개 에이전트 정의 (~4,300줄)
│   ├── reverser.md          #   바이너리 분석
│   ├── chain.md             #   익스플로잇 체인 구축
│   ├── critic.md            #   교차 검증
│   ├── fw_*.md              #   펌웨어 분석 (4개 에이전트)
│   └── ...                  #   + 10개 전문가
├── knowledge/               # 누적 경험 (20개 라이트업, 16개 기법)
│   ├── index.md             #   마스터 인덱스
│   ├── challenges/          #   챌린지별 라이트업
│   └── techniques/          #   재사용 가능한 공격 패턴
├── research/                # LLM 보안 프레임워크 분석 (14개 문서)
├── tools/                   # 파이프라인 도구
│   ├── mitre_mapper.py      #   CVE→CWE→CAPEC→ATT&CK
│   ├── recon_pipeline.py    #   6단계 정찰 오케스트레이터
│   ├── attack_graph/        #   Neo4j + 파일시스템 공격 표면 그래프
│   ├── dag_orchestrator/    #   DAG 파이프라인 스케줄링
│   ├── sarif_generator.py   #   SARIF 2.1.0 출력
│   └── mcp-servers/         #   nuclei, codeql, semgrep MCP
├── web/                     # FastAPI + D3 대시보드 (독립 + Docker)
│   ├── app.py               #   REST API + WebSocket 백엔드 (1,255줄)
│   └── static/index.html    #   싱글페이지 대시보드 (5개 탭, 1,231줄)
├── targets/                 # 버그 바운티 워크스페이스 (28+ 미션)
├── tests/                   # CTF 파일 + 벤치마크
├── CLAUDE.md                # 오케스트레이터 지시사항
├── terminator.sh            # 자율 모드 런처
├── docker-compose.yml       # 풀 스택 인프라
└── README.md
```

---

## 보안 & 윤리

이 시스템은 **인가된** 보안 작업만을 위해 설계되었습니다:

- **CTF / 워게임** — 학습을 위해 설계된 연습 환경
- **버그 바운티 프로그램** — 명시적 인가가 있는 타겟만
- **보안 연구** — 적절한 범위가 설정된 통제 환경

모든 발견사항은 책임 있는 공개 절차를 따릅니다. 프롬프트 인젝션 가드레일이 분석 대상의 악성 코드로부터 에이전트를 보호합니다.

---

<div align="center">

MIT License

</div>
