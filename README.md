<div align="center">

# Terminator

### Autonomous Security Agent powered by Claude Code Agent Teams

**CTF Auto-Solver & Bug Bounty Assessment System**

[![Claude Code](https://img.shields.io/badge/Claude_Code-Agent_Teams-blueviolet?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQyIDAtOC0zLjU4LTgtOHMzLjU4LTggOC04IDggMy41OCA4IDgtMy41OCA4LTggNHoiLz48L3N2Zz4=)](https://docs.anthropic.com/en/docs/claude-code)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

[**한국어 문서**](README.ko.md)

---

*13 specialized AI agents orchestrated through sequential pipelines — from binary analysis to verified exploit delivery.*

</div>

---

## Overview

Terminator is a multi-agent security system that autonomously solves CTF challenges and conducts authorized bug bounty assessments. Built on **Claude Code Agent Teams**, it orchestrates 13 specialized agents through structured pipelines — each agent produces artifacts that feed into the next stage.

The system doesn't just find vulnerabilities — it **verifies** them. Every CTF exploit is tested 3x locally before remote execution. Every bug bounty finding requires a working PoC before report generation.

### Key Principles

- **Agent Teams, not solo work** — The orchestrator delegates to specialized agents, never solves directly
- **Artifact-passing pipelines** — Each agent reads the previous agent's output and produces structured artifacts
- **Verification-first** — No flag is claimed without remote server confirmation; no report is filed without a working PoC
- **Experience accumulation** — Every solve (and every failure) is recorded in a knowledge base for future reference

---

## Architecture

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

### How It Works

1. **Orchestrator** receives a challenge or target, selects the appropriate pipeline
2. **Agents spawn sequentially**, each reading the previous agent's artifacts
3. **Structured handoffs** ensure no context is lost between stages:
   ```
   [HANDOFF from @reverser to @chain]
   - Artifact: reversal_map.md
   - Confidence: PASS
   - Key Result: BOF in read_input(), 64-byte overflow, canary disabled
   - Next Action: Build leak + ROP chain targeting system("/bin/sh")
   ```
4. **Critic** cross-verifies all artifacts before the exploit reaches verification
5. **Verifier** runs the exploit 3x locally, then once against the remote server

---

## Pipelines

The system selects the optimal pipeline based on challenge characteristics:

### CTF Pipelines

| Condition | Pipeline | Agents |
|:----------|:---------|:------:|
| **Trivial** — source provided, 1-3 line bug, one-liner exploit | Direct solve (no team) | 0 |
| **Reversing / Crypto** — algorithm recovery, mathematical inverse | `reverser` → `solver` → `critic` → `verifier` → `reporter` | 5 |
| **Pwn (clear vuln)** — obvious overflow, format string, etc. | `reverser` → `chain` → `critic` → `verifier` → `reporter` | 5 |
| **Pwn (unclear vuln)** — needs crash discovery & triage | `reverser` → `trigger` → `chain` → `critic` → `verifier` → `reporter` | 6 |
| **Web** — injection, SSRF, auth bypass | `scanner` → `analyst` → `exploiter` → `reporter` | 4 |

### Bug Bounty Pipeline (v3 — 7 Phases)

```
Phase 0   @target_evaluator     GO/NO-GO target ROI assessment
          ─── GO gate ──────────────────────────────────────────
Phase 1   @scout + @analyst     Parallel recon + duplicate pre-screen + CVE matching
Phase 1.5 @analyst (N parallel) OWASP-category parallel hunting (large codebases only)
Phase 2   @exploiter            PoC development + Quality Tier classification (1-4)
Phase 3   @reporter             Report draft + CVSS computation
Phase 4   @critic + @architect  2-round review (facts + framing)
Phase 4.5 @triager_sim          Adversarial triage simulation (SUBMIT / STRENGTHEN / KILL)
Phase 5   @reporter             Finalization + ZIP packaging
Phase 6   TeamDelete            Cleanup
```

> **Iron Rule**: No Exploit, No Report. Findings without a working PoC are automatically discarded.

---

## Agents

13 specialized agents, each with a dedicated role, structured prompts, and clear artifact contracts:

### CTF Agents

| Agent | Role | Model | Input | Output |
|:------|:-----|:-----:|:------|:-------|
| **reverser** | Binary structure analysis, protection detection, attack surface mapping | Sonnet | Binary + source (if any) | `reversal_map.md` |
| **trigger** | Crash discovery, input minimization, primitive identification | Sonnet | `reversal_map.md` | `trigger_report.md` + `trigger_poc.py` |
| **solver** | Reverse computation for reversing/crypto challenges | Opus | `reversal_map.md` | `solve.py` |
| **chain** | Multi-stage exploit assembly: leak → overwrite → shell | Opus | `reversal_map.md` + `trigger_report.md` | `solve.py` + `chain_report.md` |
| **critic** | Cross-verification of addresses, offsets, constants, logic | Opus | All prior artifacts | `critic_review.md` (APPROVED/REJECTED) |
| **verifier** | Local 3x reproduction → remote exploit execution | Sonnet | `solve.py` | `FLAG_FOUND: <flag>` |
| **reporter** | Challenge writeup with failed attempts and key techniques | Sonnet | All artifacts + flag | `knowledge/challenges/<name>.md` |

### Bug Bounty Agents

| Agent | Role | Model | Output |
|:------|:-----|:-----:|:-------|
| **target_evaluator** | Program analysis, competition density, tech stack matching, ROI scoring | Sonnet | `target_assessment.md` (GO/NO-GO) |
| **scout** | Reconnaissance + HackerOne Hacktivity duplicate pre-screen | Sonnet | `recon_report.json` + `program_context.md` |
| **analyst** | CVE matching, variant analysis, source→sink tracing, confidence scoring | Sonnet | `vulnerability_candidates.md` |
| **exploiter** | PoC development, integration testing, quality tier classification | Opus | PoC scripts + evidence |
| **triager_sim** | Adversarial triage simulation — attacks the report from a skeptical reviewer's perspective | Opus | SUBMIT / STRENGTHEN / KILL verdict |

> **Legacy**: `ctf-solver.md` — single-agent CTF solver (superseded by the pipeline approach)

---

## Toolchain

### Reverse Engineering & Binary Analysis

| Category | Tools |
|:---------|:------|
| **Disassembly** | radare2, objdump, strings, readelf, nm, file |
| **Decompilation** | Ghidra (via MCP), jadx (Android) |
| **Debugging** | gdb + pwndbg + GEF (93 commands), strace |
| **Symbolic Execution** | angr, unicorn, z3-solver, keystone-engine |
| **Binary Parsing** | LIEF, pyelftools, capstone, seccomp-tools |

### Exploit Development

| Category | Tools |
|:---------|:------|
| **Framework** | pwntools (process/remote, ROP, shellcraft, ELF parsing) |
| **Gadgets** | ROPgadget, ropper, one_gadget |
| **Crypto** | pycryptodome, sympy, z3-solver |
| **Patching** | patchelf, LIEF |

### Web Security

| Category | Tools |
|:---------|:------|
| **Injection** | sqlmap, commix (command injection), dalfox (XSS) |
| **SSRF** | SSRFmap (18+ modules) |
| **Upload** | fuxploider (file upload exploitation) |
| **Recon** | ffuf, subfinder, katana, httpx, gau, waybackurls, arjun, dirsearch |
| **Scanning** | nuclei (12K+ detection templates), trufflehog (800+ secret types) |
| **Proxy** | mitmproxy, interactsh-client |

### Code Analysis

| Category | Tools |
|:---------|:------|
| **Semantic** | CodeQL (taint tracking, variant analysis) |
| **Static** | Semgrep (via skill plugin), custom rule authoring |
| **Smart Contract** | Slither (100+ Solidity detectors), Mythril (EVM symbolic), Foundry (forge/cast/anvil) |

### MCP Servers (AI-Native Tool Integration)

| Server | Capability |
|:-------|:-----------|
| **mcp-gdb** | GDB debugging with breakpoints, memory inspection, stepping |
| **radare2-mcp** | Disassembly, decompilation, function listing, xrefs |
| **ghidra-mcp** | Headless decompilation, structure/enum analysis |
| **frida-mcp** | Dynamic instrumentation, hooking, process spawning |
| **pentest-mcp** | nmap scanning, nikto, gobuster, john/hashcat |
| **playwright** | Browser automation for web exploitation |
| **context7** | Up-to-date library documentation lookup |

### Reference Databases

| Database | Coverage |
|:---------|:---------|
| **ExploitDB** | 47K+ exploits (searchsploit CLI) |
| **PoC-in-GitHub** | 8K+ CVE proof-of-concepts |
| **PayloadsAllTheThings** | 70+ vulnerability categories |
| **trickest-cve** | 154K+ CVE PoCs |
| **SecLists** | Fuzzing wordlists, passwords, discovery |
| **libc-database** | libc offset lookup for ret2libc |

### Skill Plugins

| Plugin | Skills | Purpose |
|:-------|:-------|:--------|
| **static-analysis** | semgrep, codeql, sarif-parsing | Automated static analysis |
| **variant-analysis** | variant-analysis | CVE variant pattern search |
| **insecure-defaults** | insecure-defaults | Hardcoded secrets, weak auth |
| **sharp-edges** | sharp-edges | Dangerous API/config detection |
| **audit-context-building** | audit-context-building | Pre-audit architecture mapping |
| **testing-handbook-skills** | aflpp, libfuzzer, harness-writing, address-sanitizer, + 11 more | Fuzzing & testing (Trail of Bits) |
| **dwarf-expert** | dwarf-expert | DWARF debug format analysis |
| **yara-authoring** | yara-rule-authoring | YARA detection rule creation |
| **differential-review** | differential-review | Git diff security review |

---

## Research Foundations

The agent definitions incorporate patterns from 10+ external LLM security frameworks:

| Pattern | Origin | Applied To |
|:--------|:-------|:-----------|
| **Variant Analysis** — CVE patch diffs as search seeds | Google Big Sleep (Project Zero + DeepMind) | analyst, scout |
| **LLM-first PoV Generation** — LLM directly generates exploit inputs | RoboDuck (AIxCC 3rd place) | chain |
| **Symbolic + Neural Hybrid** — z3/angr verification when LLM confidence is low | ATLANTIS (AIxCC 1st place) | reverser |
| **No Exploit, No Report** — discard findings without working PoC | Shannon, XBOW | exploiter, reporter |
| **Confidence Questionnaire** — 10-point checklist replacing logprobs | Shannon (adapted) | analyst |
| **Iterative Context Gathering** — source→sink 3-pass backtracing | Vulnhuntr | analyst |
| **Coverage Gap Analysis** — identify unreached code paths via breakpoint analysis | RoboDuck | trigger |
| **Dual-Approach Parallel** — spawn 2 solvers with different strategies after 3 failures | RoboDuck | chain, solver |
| **OWASP Parallel Hunters** — N agents hunting by vulnerability category | Shannon | orchestrator |
| **Guardrails** — defense against prompt injection in analyzed code | CAI (300+ LLM) | orchestrator |
| **PoC Quality Tier Gate** — Tier 1-4 classification, only 1-2 advance | XBOW | exploiter |
| **Adversarial Triage Simulation** — pre-submission skeptical review | Internal | triager_sim |
| **Duplicate Pre-Screen** — Hacktivity/CVE check before deep analysis | Internal | scout |

---

## Quick Start

### Prerequisites

- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) installed and configured
- Python 3.10+ with pwntools, z3-solver, angr
- gdb with pwndbg or GEF
- radare2

### Interactive Mode (Recommended)

```bash
cd Terminator
claude

# CTF — just describe the challenge:
# "Solve pwnable.kr fd challenge. SSH: fd@pwnable.kr -p2222 (pw: guest)"
# "tests/wargames/Level10_1.zip 풀어줘. remote: host1.dreamhack.games:12345"

# Bug Bounty — name the target:
# "HackerOne의 <program> 버그바운티 시작해줘"

# The orchestrator automatically selects the pipeline,
# spawns agent teams, and works through the stages.
```

### Autonomous Mode (Unattended)

```bash
# CTF challenge (zip or directory)
./terminator.sh ctf /path/to/challenge[.zip]

# Bug bounty target
./terminator.sh bounty https://target.com "*.target.com"

# Monitor progress
./terminator.sh status
./terminator.sh logs
```

Results are saved to `reports/<timestamp>/`.

---

## Project Structure

```
Terminator/
├── .claude/
│   └── agents/                 # 13 agent definitions (~2,900 lines total)
│       ├── reverser.md         #   Binary analysis → reversal_map.md
│       ├── trigger.md          #   Crash discovery → trigger_report.md
│       ├── chain.md            #   Exploit chain → solve.py (pwn)
│       ├── solver.md           #   Reverse computation → solve.py (reversing/crypto)
│       ├── critic.md           #   Cross-verification → critic_review.md
│       ├── verifier.md         #   Local/remote verification → FLAG_FOUND
│       ├── reporter.md         #   Writeup & report generation
│       ├── scout.md            #   Bug bounty recon + duplicate pre-screen
│       ├── analyst.md          #   CVE matching, variant analysis, confidence scoring
│       ├── exploiter.md        #   PoC development (Tier 1-4 quality gate)
│       ├── target_evaluator.md #   GO/NO-GO target ROI assessment
│       ├── triager_sim.md      #   Adversarial triage simulation
│       └── ctf-solver.md       #   Legacy single-agent solver
│
├── knowledge/                  # Accumulated experience base
│   ├── index.md                #   Master index (solved/failed/pending)
│   ├── challenges/             #   Per-challenge writeups & analysis
│   └── techniques/             #   Reusable attack techniques (9 docs)
│       ├── gdb_oracle_reverse.md
│       ├── ssh_interaction_patterns.md
│       ├── efficient_solving.md
│       ├── bug_bounty_report_quality.md
│       └── ...
│
├── research/                   # External framework analysis (14 docs)
│   ├── llm_bug_bounty_sota_2024_2026.md
│   ├── multi_agent_orchestration_patterns_2024_2026.md
│   └── ...
│
├── targets/                    # Bug bounty target workspaces
├── tests/wargames/             # CTF challenge files
├── tools/                      # Helper scripts (Gemini integration, etc.)
│
├── CLAUDE.md                   # Orchestrator instructions (auto-loaded per session)
├── terminator.sh               # CLI launcher for autonomous mode
└── README.md
```

---

## Outputs

### CTF Challenges

Each solved challenge produces:

| Artifact | Description |
|:---------|:-----------|
| `solve.py` | Working exploit script (tested locally 3x, verified remotely) |
| `knowledge/challenges/<name>.md` | Detailed writeup with analysis, failed attempts, and key techniques |
| `FLAG_FOUND: <flag>` | Verified flag obtained from the remote server |

### Bug Bounty Targets

Each assessed target produces:

| Artifact | Description |
|:---------|:-----------|
| `targets/<name>/h1_reports/` | HackerOne-format vulnerability reports |
| `targets/<name>/evidence/` | PoC scripts, screenshots, network captures |
| `targets/<name>/submission/*.zip` | Packaged submission artifacts |

---

## Design Decisions

### Why Sequential Pipelines (not Parallel)?

Security analysis requires **context accumulation**. The reverser's attack map fundamentally shapes the exploit strategy. Running all agents in parallel would produce disconnected, often contradictory results. Sequential pipelines with structured handoffs ensure each agent builds on verified prior work.

### Why a Critic Agent?

Exploit development is error-prone — wrong offsets, incorrect constants, flawed logic. The critic independently verifies every address and calculation using tools (r2, gdb) before the exploit reaches the verifier. This catches errors that would otherwise waste time on failed remote attempts.

### Why Adversarial Triage Simulation?

Bug bounty reports are evaluated by skeptical triagers under time pressure. The triager_sim agent attacks the report from a reviewer's perspective — checking for missing PoCs, duplicate overlap, weak framing, and AI-generated boilerplate — before submission. This reduces rejection rates.

### Why Model-per-Agent?

Not every agent needs the most capable model. Reversers and verifiers work well with Sonnet (pattern matching, execution). Solvers and critics need Opus (complex reasoning, mathematical proofs). Explicit model assignment per agent saves tokens without sacrificing quality.

---

## Learned Techniques

The knowledge base contains reusable patterns accumulated across challenges:

| Technique | Description |
|:----------|:-----------|
| **GDB Oracle Reverse** | Reverse non-linear functions in custom VMs by patching memory and tracing execution |
| **z3 Protocol Simulation** | Model entire network protocols as SMT constraints for exact solution |
| **SSH Interaction Patterns** | paramiko exec → nc pipe → SSH tunnel + pwntools (reliability hierarchy) |
| **Incremental Exploit Dev** | Phase-by-phase: leak → test → overflow → test → ROP → test → combine |
| **Dual-Approach Parallel** | After 3 failures, spawn 2 solvers with different strategies simultaneously |
| **Constant Verification** | Always verify constants via GDB memory dump (static analysis alone causes off-by-one errors) |
| **Trivial Detection** | Source < 50 lines + 1-3 line bug + one-liner exploit = skip agent teams |

---

## Security & Ethics

> **AUTHORIZED USE ONLY**

This system is designed exclusively for:

- **CTF / Wargame challenges** — Practice environments designed for security learning
- **Bug bounty programs** — Only targets with explicit authorization (e.g., HackerOne programs)
- **Security research** — Controlled lab environments with proper scope

**Strict Rules:**
- Safe payloads only (`id`, `whoami`, `cat /etc/passwd` — never destructive commands)
- No attacks on unauthorized systems
- Prompt injection guardrails protect agents from malicious analyzed code
- All findings follow responsible disclosure practices

---

## License

MIT License
