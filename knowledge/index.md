# Challenge Index

> Template for tracking CTF challenges and Bug Bounty findings. Update dates and stats as you solve challenges.

## Solved CTF Challenges

| Challenge | Type | Flag | File |
|-----------|------|------|------|
| Example Challenge 1 | Reversing | `[FLAG]` | [example1.md](challenges/example1.md) |
| Example Challenge 2 | Pwn | `[FLAG]` | [example2.md](challenges/example2.md) |

## In Progress

| Challenge | Type | Status | Blocker | File |
|-----------|------|--------|---------|------|
| Example WIP | Pwn | Analysis complete | Exploit development | [example_wip.md](challenges/example_wip.md) |

## Failed / Paused

| Challenge | Type | Attempts | Reason | File |
|-----------|------|----------|--------|------|
| Example Failed | WASM Reversing | 15+ | Flag output path not found | [example_failed.md](challenges/example_failed.md) |

## Not Attempted

Track challenges you haven't started yet.

## Techniques Learned

| Technique | File |
|-----------|------|
| DFA table extraction + BFS | [techniques/efficient_solving.md](techniques/efficient_solving.md) |
| GDB Oracle - Custom VM reverse engineering | [techniques/gdb_oracle_reverse.md](techniques/gdb_oracle_reverse.md) |
| SSH-based CTF interaction patterns | [techniques/ssh_interaction_patterns.md](techniques/ssh_interaction_patterns.md) |
| Bug Bounty report quality guidelines | [techniques/bug_bounty_report_quality.md](techniques/bug_bounty_report_quality.md) |
| Installed tools reference | [techniques/installed_tools_reference.md](techniques/installed_tools_reference.md) |
| Offensive MCP servers research | [techniques/offensive_mcp_servers.md](techniques/offensive_mcp_servers.md) |

## Bug Bounty Programs

Track your bug bounty findings here. **All actual findings are kept in private files outside this repository.**

| Program | Platform | Focus | Status | Notes |
|---------|----------|-------|--------|-------|
| Example VDP | HackerOne | Web Application | Active | Example entry |
| Example BBP | HackerOne | API Security | Completed | Example entry |

### Finding Template

When you discover a vulnerability:
- Create detailed notes in `challenges/<target>_<finding>.md`
- Record analysis process, PoC development, review feedback
- Track: CWE, CVSS, PoC quality tier, duplicate risk, triager feedback
- Keep actual reports, target details, and submission materials **private**

### Key Learnings from Bug Bounty Research

- Integration test is critical evidence (not just unit PoC)
- CVSS version varies by program (check policy: 3.1 vs 4.0)
- Modern V8 prototype pollution is dead (use specific attack scenarios instead)
- External review cycles prevent submission failures
- Observational language increases report acceptance
- PoC quality tiers: only Tier 1-2 should be submitted
- Duplicate pre-screening is mandatory
- Target intelligence (GO/NO-GO) prevents wasted effort

See [techniques/bug_bounty_report_quality.md](techniques/bug_bounty_report_quality.md) for complete guidelines.

## Reports Archive

Automated pipeline logs and session reports are kept locally and excluded from git.
