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
| Web3: Immunefi top payouts & strategy | [techniques/web3_immunefi_top_payouts.md](techniques/web3_immunefi_top_payouts.md) |
| Web3: DeFi attack taxonomy (60+ vectors) | [techniques/web3_defi_attack_taxonomy.md](techniques/web3_defi_attack_taxonomy.md) |
| Web3: Smart contract audit methodology | [techniques/web3_audit_methodology.md](techniques/web3_audit_methodology.md) |
| Web3: Foundry fork PoC methodology | [techniques/web3_foundry_fork_poc.md](techniques/web3_foundry_fork_poc.md) |

## Bug Bounty Programs

Track your bug bounty findings here. **All actual findings are kept in private files outside this repository.**

| Program | Platform | Focus | Status | Notes |
|---------|----------|-------|--------|-------|
| USX Protocol | Immunefi | Smart Contract (Scroll L2) | B Submitted, A Ready | Report B submitted 2/16, Report A pending cooldown. Deep analysis: 13 leads, 1 High borderline (Finding C). Details: [immunefi_usx.md](challenges/immunefi_usx.md) |
| Symbiotic Protocol | Immunefi | Smart Contract ($500K max) | ABANDONED | 0 Critical findings. Well-audited by 4 firms, restrictive permissions model. Details: [bugbounty/symbiotic_analysis.md](bugbounty/symbiotic_analysis.md) |
| Superform | Immunefi | Smart Contract ($250K max) | ABANDONED | 1 Medium finding (previewDepositTo misuse), not Critical-worthy. Details: [bugbounty/superform_analysis.md](bugbounty/superform_analysis.md) |
| stake.link | Immunefi | Smart Contract ($100K max) | 1 MEDIUM READY (제출 대기) | CCIP zero slippage sandwich on Curve Gauge distribution. Foundry fork PoC confirmed profit-positive (Direction A). 유동성 제약: wstPOL 98.7% locked, 541 free float, flash loan 불가 → Medium ceiling. "Growing risk" 프레이밍. 제출물: `targets/stakelink/submission/` (4 files). Details: [targets/stakelink/submission/immunefi_report.md](../targets/stakelink/submission/immunefi_report.md) |
| YieldNest | Immunefi | Smart Contract ($200K max) | ABANDONED | 3 findings all mitigated on-chain. Donation attack bootstrap complete (3842 ynETH TVL), dead shares exist. Zokyo audit pre-launch. Details: [targets/yieldnest/vulnerability_analysis.md](../targets/yieldnest/vulnerability_analysis.md) |
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
