# Research Index

**Status**: Complete. Findings integrated into agent definitions.
**Total**: 10 documents, 6,000+ lines

## Quick Navigation

| Need | Read |
|------|------|
| 5-min overview | `FINDINGS.md` |
| Implementation patterns | `quick_reference.md` |
| Bug bounty SOTA | `llm_bug_bounty_sota_2024_2026.md` |
| Triage insights | `bug_bounty_triage_insights_2024_2026.md` |
| Multi-agent patterns | `multi_agent_orchestration_patterns_2024_2026.md` |
| PentestGPT deep dive | `llm_pentesting_patterns.md` |
| Integration details | `integration_guide.md` |

## Document Map

### Foundation Research
| File | Size | Topic |
|------|------|-------|
| FINDINGS.md | 472 lines | PentestGPT/try-harder executive summary |
| quick_reference.md | 404 lines | Top patterns + code templates |
| llm_pentesting_patterns.md | 709 lines | PentestGPT architecture (USENIX 2024) |
| integration_guide.md | 676 lines | Implementation walkthrough |

### Extended Research (Pipeline v3)
| File | Size | Topic |
|------|------|-------|
| llm_bug_bounty_sota_2024_2026.md | 1099 lines | XBOW, Shannon, Vulnhuntr, Big Sleep |
| bug_bounty_triage_insights_2024_2026.md | 1446 lines | H1 triage patterns, AI slop, rejection reasons |
| multi_agent_orchestration_patterns_2024_2026.md | 1115 lines | AIxCC winners, A2A, structured handoffs |

### Target Research
| File | Topic |
|------|-------|
| doordash_technical_profile.md | DoorDash tech stack |
| doordash_quick_reference.md | DoorDash quick ref |
| vpn_client_attack_techniques.md | VPN attack surface |
| ORCHESTRATION_QUICK_REF.md | Multi-agent quick ref |
| RESEARCH_STAGE4_SUMMARY.md | Stage 4 summary |

## Integration Status

All research findings have been integrated into:
- `.claude/agents/*.md` (agent-level prompt improvements)
- `CLAUDE.md` (orchestrator-level workflow rules)
- `knowledge/techniques/` (reusable technique documents)

No separate Python implementation was needed; patterns were applied directly as Claude Code Agent Teams prompts and orchestration rules.

---

*Last Updated: 2026-02-15*
