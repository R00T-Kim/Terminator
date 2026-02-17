<div align="center">

<br>

<img src="https://img.shields.io/badge/TERMINATOR-Autonomous_Security_Agent-cc0000?style=for-the-badge&labelColor=1a1a1a" alt="Terminator">

<br><br>

**Multi-agent AI system that autonomously solves CTF challenges and hunts bug bounties.**

Built on [Claude Code Agent Teams](https://docs.anthropic.com/en/docs/claude-code) — 13 specialized agents orchestrated through sequential pipelines.

<br>

[![Claude Code](https://img.shields.io/badge/Claude_Code-Agent_Teams-7C3AED?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA4LTggNHoiLz48L3N2Zz4=)](https://docs.anthropic.com/en/docs/claude-code)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Solidity](https://img.shields.io/badge/Solidity-Foundry-363636?style=flat-square&logo=solidity&logoColor=white)](https://book.getfoundry.sh/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

<br>

| CTF Solved | Bug Bounty Programs | AI Agents | MCP Servers | Docker Services |
|:----------:|:-------------------:|:---------:|:-----------:|:---------------:|
| **20** | **12+** | **13** | **10** | **6** |

<br>

</div>

---

## What It Does

Terminator doesn't just find vulnerabilities — it **verifies** them.

- Every CTF exploit is tested **3x locally** before remote execution
- Every bug bounty finding requires a **working PoC** before report generation
- Every report passes **adversarial triage simulation** before submission

```
You: "pwnable.kr fd 풀어줘. SSH: fd@pwnable.kr -p2222 (pw: guest)"

Terminator:
  → spawns @reverser  → analyzes binary, produces attack map
  → spawns @chain     → builds exploit from attack map
  → spawns @critic    → cross-verifies offsets with gdb/r2
  → spawns @verifier  → runs exploit 3x locally, then remote
  → FLAG_FOUND: mama, are you prout of me?
```

---

## Architecture

```
                        ┌─────────────────────────┐
                        │     Claude Code CLI      │
                        │   Orchestrator (Lead)    │
                        └────────────┬────────────┘
                                     │
                  ┌──────────────────┼──────────────────┐
                  │                                      │
        ┌────────▼─────────┐                  ┌─────────▼────────┐
        │   CTF Pipeline   │                  │  Bug Bounty v3   │
        │   (Sequential)   │                  │   (7 Phases)     │
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

          ┌─────────────────────────────────────────────┐
          │            Infrastructure Layer              │
          ├─────────┬──────────┬──────────┬─────────────┤
          │ 10 MCP  │ Docker   │ Web      │ Knowledge   │
          │ Servers │ Stack    │ Dashboard│ Base        │
          └─────────┴──────────┴──────────┴─────────────┘
```

### Structured Handoffs

Agents communicate through structured artifact passing — no context is lost between stages:

```
[HANDOFF from @reverser to @chain]
- Artifact: reversal_map.md
- Confidence: PASS
- Key Result: BOF in read_input(), 64-byte overflow, canary disabled
- Next Action: Build leak + ROP chain targeting system("/bin/sh")
```

---

## Pipelines

### CTF — Adaptive Pipeline Selection

| Condition | Pipeline | Agents |
|:----------|:---------|:------:|
| **Trivial** — source provided, 1-3 line bug | Direct solve | 0 |
| **Reversing / Crypto** — math inverse needed | `reverser → solver → critic → verifier → reporter` | 5 |
| **Pwn (clear vuln)** — obvious overflow/fmt | `reverser → chain → critic → verifier → reporter` | 5 |
| **Pwn (unclear vuln)** — crash discovery needed | `reverser → trigger → chain → critic → verifier → reporter` | 6 |
| **Web** — injection, SSRF, auth bypass | `scanner → analyst → exploiter → reporter` | 4 |

### Bug Bounty — v3 Pipeline (7 Phases)

```
Phase 0   @target_evaluator     GO / NO-GO assessment (ROI, competition, tech stack)
          ─── GO gate ────────────────────────────────────────────────
Phase 1   @scout + @analyst     Parallel recon + duplicate pre-screen + CVE matching
Phase 1.5 @analyst (N parallel) OWASP-category hunting (large codebases only)
Phase 2   @exploiter            PoC development + Quality Tier gate (Tier 1-2 only)
Phase 3   @reporter             Report draft + CVSS
Phase 4   @critic + @architect  2-round review: facts → framing
Phase 4.5 @triager_sim          Adversarial triage (SUBMIT / STRENGTHEN / KILL)
Phase 5   @reporter             Final report + ZIP packaging
Phase 6   TeamDelete            Cleanup
```

> **Iron Rule**: No Exploit, No Report. Findings without a working PoC are automatically discarded.

---

## Agents

### CTF Agents

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **reverser** | Binary analysis, protection detection, attack surface mapping | Sonnet | `reversal_map.md` |
| **trigger** | Crash discovery, input minimization, primitive identification | Sonnet | `trigger_report.md` |
| **solver** | Reverse computation for reversing/crypto | Opus | `solve.py` |
| **chain** | Multi-stage exploit: leak → overwrite → shell | Opus | `solve.py` |
| **critic** | Cross-verification of offsets, constants, logic | Opus | `critic_review.md` |
| **verifier** | Local 3x reproduction → remote execution | Sonnet | `FLAG_FOUND` |
| **reporter** | Writeup with failed attempts and techniques | Sonnet | `knowledge/challenges/<name>.md` |

### Bug Bounty Agents

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **target_evaluator** | Program ROI scoring, GO/NO-GO gate | Sonnet | `target_assessment.md` |
| **scout** | Recon + duplicate pre-screen | Sonnet | `recon_report.json` |
| **analyst** | CVE matching, source→sink tracing, confidence scoring | Sonnet | `vulnerability_candidates.md` |
| **exploiter** | PoC development, quality tier classification | Opus | PoC scripts + evidence |
| **triager_sim** | Adversarial triage — attacks report before submission | Opus | SUBMIT / STRENGTHEN / KILL |

---

## Toolchain

### MCP Servers — AI-Native Tool Integration

10 MCP servers give agents direct programmatic access to security tools:

| Server | Capability |
|:-------|:-----------|
| **mcp-gdb** | Breakpoints, memory inspection, stepping, backtrace |
| **radare2-mcp** | Disassembly, decompilation, xrefs, function analysis |
| **ghidra-mcp** | Headless decompilation, structures, enums |
| **frida-mcp** | Dynamic instrumentation, hooking, process spawning |
| **pentest-mcp** | nmap, gobuster, nikto, john, hashcat |
| **nuclei-mcp** | 12K+ vulnerability detection templates |
| **codeql-mcp** | Semantic taint tracking, variant analysis |
| **semgrep-mcp** | Pattern-based static analysis |
| **playwright** | Browser automation for web exploitation |
| **context7** | Up-to-date library documentation lookup |

### Security Tools

<details>
<summary><b>Reverse Engineering & Exploit Dev</b></summary>

| Category | Tools |
|:---------|:------|
| Disassembly | radare2, objdump, strings, readelf, nm |
| Decompilation | Ghidra (MCP), jadx |
| Debugging | gdb + pwndbg + GEF (93 commands), strace |
| Symbolic | angr, unicorn, z3-solver, keystone |
| Exploit | pwntools, ROPgadget, ropper, one_gadget |
| Crypto | pycryptodome, sympy, z3-solver |

</details>

<details>
<summary><b>Web Security</b></summary>

| Category | Tools |
|:---------|:------|
| Injection | sqlmap, commix, dalfox (XSS) |
| SSRF | SSRFmap (18+ modules) |
| Recon | ffuf, subfinder, katana, httpx, gau, waybackurls, arjun |
| Scanning | nuclei (12K+ templates), trufflehog (800+ secret types) |
| Upload | fuxploider |

</details>

<details>
<summary><b>Code Analysis & Smart Contracts</b></summary>

| Category | Tools |
|:---------|:------|
| Semantic | CodeQL (taint tracking, variant analysis) |
| Static | Semgrep (custom rule authoring) |
| Smart Contract | Slither (100+ detectors), Mythril (EVM symbolic), Foundry 1.5.1 |
| AI | Gemini CLI (gemini-3-pro-preview) |

</details>

<details>
<summary><b>Reference Databases</b></summary>

| Database | Coverage |
|:---------|:---------|
| ExploitDB | 47K+ exploits |
| PoC-in-GitHub | 8K+ CVE PoCs |
| PayloadsAllTheThings | 70+ vuln categories |
| trickest-cve | 154K+ CVE PoCs |
| SecLists | Wordlists, passwords, discovery |

</details>

<details>
<summary><b>Skill Plugins (Trail of Bits, Sentry, Anthropic)</b></summary>

| Plugin | Skills | Purpose |
|:-------|:-------|:--------|
| static-analysis | semgrep, codeql, sarif-parsing | Automated static analysis |
| variant-analysis | variant-analysis | CVE variant pattern search |
| testing-handbook | aflpp, libfuzzer, harness-writing + 12 more | Fuzzing (Trail of Bits) |
| insecure-defaults | insecure-defaults | Hardcoded secrets, weak auth |
| sharp-edges | sharp-edges | Dangerous API detection |
| audit-context | audit-context-building | Pre-audit architecture mapping |
| dwarf-expert | dwarf-expert | DWARF debug format |
| yara-authoring | yara-rule-authoring | YARA rule creation |
| differential-review | differential-review | Git diff security review |
| sentry-skills | find-bugs, security-review, code-review | Bug detection |

</details>

---

## Infrastructure

### Docker Stack (6 Services)

```bash
docker compose up -d
```

| Service | Port | Purpose |
|:--------|:----:|:--------|
| **pgvector** | 5433 | RAG vector database |
| **ollama** | 11434 | Local embedding models |
| **rag-api** | 8100 | ExploitDB/PoC knowledge search |
| **neo4j** | 7474 | Attack surface graph database |
| **litellm** | 4000 | Multi-model proxy (Claude/Gemini/DeepSeek) |
| **web-ui** | 3000 | Real-time dashboard with D3 attack graphs |

### Pipeline Tooling

| Tool | Purpose |
|:-----|:--------|
| **MITRE Mapper** | CVE → CWE → CAPEC → ATT&CK mapping (27 CWEs) |
| **Attack Graph** | Neo4j-backed attack surface visualization |
| **DAG Orchestrator** | Pipeline scheduling (CTF pwn/rev, bounty, firmware) |
| **Recon Pipeline** | 6-phase automated reconnaissance |
| **SARIF Generator** | GitHub Code Scanning compatible output |
| **PDF Generator** | Report PDF generation |

---

## Track Record

### CTF Challenges — 20 Solved

| Challenge | Type | Technique |
|:----------|:-----|:----------|
| dhcc | Reversing (flex/bison) | DFA table extraction + BFS |
| Too Many Questions | Crypto (AES-ECB) | z3 constraint solving |
| Damnida | Reversing (Custom VM) | GDB Oracle — memory patch + trace |
| Conquergent | Reversing (retf VM) | 3-stage cipher, x86 mode switching |
| pwnable.kr (16) | Pwn / Misc | fd, collision, passcode, asm, leg, input, ... |

### Bug Bounty — 12+ Programs Assessed

| Metric | Count |
|:-------|:-----:|
| Programs assessed | 12+ |
| Platforms | Immunefi, HackerOne |
| Categories | Smart Contract (DeFi), Web App, VPN, IoT, AI/SDK |
| Smart contracts analyzed | 50+ |
| Vulnerability leads investigated | 100+ |

> Specific targets and findings are kept private until disclosure is complete.

---

## Research Foundations

Agent definitions incorporate patterns from 10+ LLM security frameworks:

| Pattern | Origin |
|:--------|:-------|
| Variant Analysis — CVE patch diffs as seeds | Google Big Sleep (Project Zero + DeepMind) |
| LLM-first PoV Generation | RoboDuck (AIxCC 3rd place) |
| Symbolic + Neural Hybrid | ATLANTIS (AIxCC 1st place) |
| No Exploit, No Report | Shannon, XBOW |
| Iterative Context Gathering — 3-pass backtracing | Vulnhuntr |
| Dual-Approach Parallel — 2 strategies after 3 failures | RoboDuck |
| OWASP Parallel Hunters | Shannon |
| PoC Quality Tier Gate (1-4) | XBOW |
| Adversarial Triage Simulation | Internal |
| Prompt Injection Guardrails | CAI (300+ LLM agents) |

---

## Quick Start

### Prerequisites

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) with Anthropic API key
- Python 3.10+ with pwntools, z3-solver, angr
- gdb with pwndbg or GEF, radare2
- Docker (optional, for full infrastructure)

### Interactive Mode

```bash
cd Terminator && claude

# CTF:
# "Solve pwnable.kr fd. SSH: fd@pwnable.kr -p2222 (pw: guest)"

# Bug Bounty:
# "이뮤니파이에서 하이~크리티컬 취약점 찾을때까지 ㄱㄱ"
```

### Autonomous Mode

```bash
./terminator.sh ctf /path/to/challenge.zip     # CTF
./terminator.sh bounty https://target.com       # Bug bounty
./terminator.sh status                          # Monitor
```

---

## Project Structure

```
Terminator/
├── .claude/agents/          # 13 agent definitions (~2,900 lines)
├── knowledge/               # Accumulated experience (20 writeups, 15 techniques)
│   ├── index.md             #   Master index
│   ├── challenges/          #   Per-challenge writeups
│   └── techniques/          #   Reusable attack patterns
├── research/                # LLM security framework analysis (14 docs)
├── tools/                   # Pipeline tooling
│   ├── mitre_mapper.py      #   CVE→CWE→CAPEC→ATT&CK
│   ├── recon_pipeline.py    #   6-phase recon orchestrator
│   ├── attack_graph/        #   Neo4j attack surface graphs
│   ├── dag_orchestrator/    #   DAG pipeline scheduling
│   ├── sarif_generator.py   #   SARIF 2.1.0 output
│   └── mcp-servers/         #   nuclei, codeql, semgrep MCP
├── web/                     # FastAPI + WebSocket dashboard
├── targets/                 # Bug bounty workspaces
├── tests/                   # CTF files + benchmarks
├── CLAUDE.md                # Orchestrator instructions
├── terminator.sh            # Autonomous mode launcher
├── docker-compose.yml       # Infrastructure stack
└── README.md
```

---

## Security & Ethics

This system is designed exclusively for **authorized** security work:

- **CTF / Wargames** — Practice environments designed for learning
- **Bug bounty programs** — Only targets with explicit authorization
- **Security research** — Controlled environments with proper scope

All findings follow responsible disclosure. Prompt injection guardrails protect agents from malicious code in analysis targets.

---

<div align="center">

MIT License

</div>
