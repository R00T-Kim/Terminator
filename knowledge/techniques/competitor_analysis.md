# Competitor Analysis: AI Security Agent Systems (2026-02)

**Source**: https://github.com/ottosulin/awesome-ai-security

## 1. CAI (aliasrobotics/cai) — Bug Bounty Automation Framework
- **아키텍처**: Agent-centric, modular, agent handoff mechanism
- **모델**: 300+ via LiteLLM (Claude, GPT-4o, O3, DeepSeek, Ollama)
- **로깅**: Phoenix tracing (전체 실행 투명성)
- **성과**: 3,600x over human pentesters (CTF), CVSS 4.3-7.5 실제 취약점, Dragos OT CTF Top-10
- **특징**: HITL(Human-in-the-Loop), guardrails, 연속 에이전트 상호작용
- **Terminator 대비**:
  - 우리보다 모델 유연성 높음 (LiteLLM)
  - CTF 벤치마크 결과 공개 (우리도 해야 함)
  - Guardrails 체계화됨

## 2. RedAmon (samugit83/redamon) — Zero Intervention Red Team
- **아키텍처**: 6-phase recon pipeline → AI Agent Orchestrator (LangGraph ReAct) → Neo4j Graph
- **핵심 혁신**: **Neo4j Attack Surface Graph** (17 node types, 20+ relationships)
- **Recon Pipeline**:
  1. Domain Discovery (crt.sh, HackerTarget, Knockpy, WHOIS, DNS)
  2. Port Scanning (Naabu + Shodan passive)
  3. HTTP Probing (httpx + Wappalyzer 6K+ signatures)
  4. Resource Enumeration (Katana + GAU + Kiterunner 병렬)
  5. Vulnerability Scanning (Nuclei 8K+ templates + DAST fuzzing)
  6. MITRE Enrichment (CVE → CWE → CAPEC auto-mapping)
- **MCP Tool Servers**: Naabu(8000), Curl(8001), Nuclei(8002), Metasploit(8003)
- **Phase 전환**: Informational → Exploitation → Post-Exploitation (승인 게이트)
- **기술스택**: Next.js, FastAPI, Neo4j, PostgreSQL, Redis, Docker(Kali), Claude(기본)
- **Terminator 대비**:
  - Neo4j 그래프 > 우리의 flat markdown (가장 큰 차이)
  - Metasploit MCP 통합 (우리에겐 없음)
  - 6-phase 정찰 > 우리의 scout 단일 에이전트
  - GVM/OpenVAS 170K+ NVTs (우리에겐 없음)
  - Web UI (우리는 CLI only)

## 3. Strix (usestrix/strix) — Autonomous Web Vuln Discovery
- **아키텍처**: "Graph of agents" (비선형 에이전트 협업)
- **에이전트 도구**: HTTP Proxy(Caido), Browser(Playwright), Terminal, Python Runtime
- **모델**: GPT-5, Claude Sonnet 4.5, Gemini 3 Pro via LiteLLM
- **취약점 커버리지**: IDOR, SQLi, XSS, SSRF, XXE, race condition, JWT, proto pollution
- **실행 모드**: Interactive(TUI), Headless(-n), CI/CD(GitHub Actions)
- **테스트 방법론**: White-box, Black-box, Grey-box
- **기술스택**: LiteLLM, Caido, Nuclei, Playwright, Docker sandbox
- **Terminator 대비**:
  - Graph of agents > 우리의 linear pipeline (유연성)
  - CI/CD 통합 (우리에겐 없음)
  - Caido HTTP proxy (우리는 Burp 없음)
  - 형식화된 테스팅 모드 (우리는 비공식)

## Terminator 개선 로드맵 (차용 우선순위)

### P0: 즉시 적용 가능 (코드 변경 최소)
1. **MCP 도구 확장** — `mcp-for-security` (SQLMap, FFUF, NMAP MCP), Burp MCP Server
2. **MITRE 자동 매핑** — CVE → CWE → CAPEC (analyst 에이전트에 추가)
3. **Headless 모드 강화** — 종료 코드로 취약점 발견 여부 반환 (CI/CD 대비)

### P1: 중기 개선 (1-2주)
4. **Neo4j Attack Surface Graph** — flat markdown → queryable graph
   - 장점: 크로스 세션 지식, 복잡한 쿼리, 관계 추적
   - 구현: Docker Neo4j + Python neo4j driver
5. **LiteLLM 통합** — Claude 외 Gemini, GPT, DeepSeek fallback
   - 현재: Gemini CLI로 부분 대체 중
   - 목표: 에이전트별 최적 모델 자동 선택
6. **Recon Pipeline 정형화** — RedAmon의 6-phase를 scout 에이전트에 통합

### P2: 장기 개선 (1-2개월)
7. **Graph of Agents** — 선형 파이프라인 → DAG 기반 에이전트 협업
8. **Web UI** — 실시간 진행 모니터링, 그래프 시각화
9. **Metasploit MCP** — exploitation 자동화
10. **CI/CD GitHub Actions** — PR 자동 보안 스캐닝

### Terminator의 경쟁 우위 (유지해야 할 것)
1. **Claude Code Agent Teams 네이티브** — 다른 시스템은 자체 오케스트레이터, 우리는 Claude Code 위에 구축 → 컨텍스트 윈도우 + 도구 체인 우수
2. **CTF + Bug Bounty 듀얼 파이프라인** — 대부분 한쪽만 지원
3. **Knowledge Base 누적 시스템** — 풀이/실패 기록 → 다음 세션에 학습
4. **MCP 리버싱 도구** (r2-mcp, gdb-mcp, ghidra-mcp) — 바이너리 분석 자동화
5. **Triager Simulation** — 제출 전 적대적 검증 (다른 시스템에 없음)
6. **Critic Agent** — 교차 검증 단계 (quality gate)

## 추가 참고 도구 (awesome-ai-security)
- **garak**: LLM 보안 프로빙 (AI SDK 타겟에 유용)
- **agentic_security**: LLM 취약점 스캐너
- **promptfoo**: 프롬프트/에이전트/RAG 테스팅 + 레드팀
- **mcp-context-protector**: MCP 보안 래퍼 (우리 시스템 방어)
- **MCP-Scan**: MCP 서버 보안 스캐닝
- **claude-code-safety-net**: Claude Code 파괴적 명령 방지
- **Damn Vulnerable MCP Server**: MCP 해킹 연습
- **HexStrikeAI**: MCP 에이전트 150+ 사이버보안 도구
- **mcp-security-hub**: Nmap+Ghidra+Nuclei+SQLMap MCP 허브
