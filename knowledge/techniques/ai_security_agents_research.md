# AI Security Agent Research (2025-2026)

## Anthropic Red Team: AI Agents for Smart Contract Exploitation
**Source**: https://red.anthropic.com/2025/smart-contracts/
**Date**: 2025

### Architecture
- **Docker container** + forked blockchain (anvil fork at specific block height → localhost:8545)
- **MCP tools**: Bash execution (Foundry, Python 3.11) + File operations
- **Toolchain**: Foundry (forge, cast, anvil), `uniswap-smart-path` (multi-hop swap routing)

### Pipeline
1. **Contract Injection**: Source code, token balances, DEX metadata → agent prompt
2. **Iterative Development**: Agent modifies exploit scripts, tests against forked nodes
3. **Validation**: "Agent's final native token balance increased by ≥0.1" = success

### Key Metrics
- **Cost per scan**: $1.22 average
- **Cost per vuln found**: $1,738
- **Average exploit revenue**: $1,847
- **Net profit per vuln**: $109 (marginal but positive)
- **Token cost trend**: -22% per generation, -65.8% Opus 4→4.5

### Model Performance (SCONE-bench, 405 contracts)
- Claude Opus 4.5 → best extraction value ($3.5M on identical vulns)
- GPT-5 → $1.12M on same vulns
- Sonnet 4.5, DeepSeek V3, Llama 3, o3 also tested
- **Key**: 55.88% of 2025 blockchain exploits reproducible by current AI agents

### Zero-Day Discovery
- Scanned 2,849 recently deployed BSC contracts
- Found 2 novel zero-days worth $3,694
- Criteria: verified source, ≥$1,000 liquidity

### Lessons for Terminator
1. **Simple scaffolding + powerful model** beats complex pipeline (SWE-agent finding)
2. **Forked blockchain testing** = our Foundry approach, validated at scale
3. **MCP for tool access** = already our architecture
4. **Iterative development loop** = our chain agent pattern
5. **Cost is very low** ($1.22/contract) — could automate DeFi scanning
6. **Net positive ROI** possible even at scale (if targeting right contracts)

## kritt.ai
**URL**: https://kritt.ai/
**Focus**: "Bounty-Grade L1 Security Research" for L1 blockchain clients
**Technical**: Published "Building Agentic Infrastructure for Zero-Day Vulnerability Research" (HN post)
**Status**: Website JS-rendered, no details extractable. Contact: harel@kritt.ai
**Relevance**: Competitor/reference in AI-powered security agent space. Similar goals to Terminator for blockchain.

## HN Discussion Insights
- "Divide steps small enough so LLMs don't know the big picture" — bypasses safety guardrails
- Professional researchers already use AI tooling for vuln discovery
- Simple scaffolding with minimal code + powerful base model → best results
- Sonnet-class models sufficient for most scanning, Opus for complex exploitation
