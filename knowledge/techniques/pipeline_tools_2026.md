# Pipeline Tools & Ecosystem Reference (2026-02-22)

New tools, competitor systems, and integrations discovered during Feb 2026 research.

## Tool: crawl4ai (Web Crawling)
- **Stars**: 60.6K GitHub
- **Purpose**: LLM-optimized web crawler — JS rendering, Markdown output, stealth mode
- **Install**: `pipx install crawl4ai` + `crawl4ai-setup` (Playwright browsers)
- **Key Features**:
  - Playwright-based (handles SPA, lazy loading, infinite scroll)
  - Stealth mode (anti-bot evasion)
  - Session management (login, cookies)
  - Structured extraction (CSS/XPath selectors, LLM-based)
  - Markdown output (token-efficient for LLM consumption)
- **Usage in Terminator**: Scout agent — replaces curl for dynamic content
  ```python
  from crawl4ai import AsyncWebCrawler
  async with AsyncWebCrawler() as crawler:
      result = await crawler.arun(url="https://target.com")
      print(result.markdown)  # LLM-friendly output
  ```
- **Comparison**: curl = static HTML only. katana = link spider. crawl4ai = full JS render + structured extraction.

## Tool: chrome-devtools-mcp (Browser Debugging)
- **Purpose**: Chrome DevTools Protocol via MCP — 26 tools
- **Install**: `npm install -g chrome-devtools-mcp`
- **Key Tools**:
  - Network inspection (requests, responses, timing)
  - Console message capture
  - JavaScript evaluation in page context
  - Screenshots and DOM snapshots
  - Performance profiling
- **Usage in Terminator**: Exploiter agent — low-level browser debugging alongside Playwright MCP
- **Comparison**: Playwright MCP = high-level automation. chrome-devtools-mcp = low-level debugging/inspection.

## Tool: protocol-vulnerabilities-index
- **Source**: github.com/kadenzipfel/protocol-vulnerabilities-index
- **Content**: 460 vulnerability categories across 31 protocol types
- **Purpose**: Systematic checklist for DeFi protocol auditing
- **Protocol Types**: Lending, DEX, Stablecoin, Liquid Staking, Bridge, Options Vault, etc.
- **Usage in Terminator**: Analyst agent — load relevant category file for target protocol type
  ```bash
  cat knowledge/protocol-vulns-index/categories/<protocol_type>.md
  ```

## Competitor: PentAGI
- **Stars**: 2.8K GitHub (Feb 2026)
- **Architecture**: Langchain agents + Neo4j knowledge graph + Docker sandbox + Langfuse observability
- **Key Design**: LLM plans → approved by human → tools execute in Docker sandbox
- **Knowledge Persistence**: Neo4j for cross-session learning (similar to our Attack Graph)
- **Observability**: Langfuse for cost/latency/quality tracking
- **Comparison**: Our advantage = Claude Code native (no framework overhead), MCP tools, deeper agent specialization. Their advantage = UI, human-in-the-loop, Langfuse.

## Reference: zvec (pgvector alternative)
- **Source**: Alibaba (zilliztech/zvec)
- **Purpose**: In-process vector search (no separate DB server needed)
- **Relevance**: Could replace pgvector Docker service for RAG if latency matters
- **Current Decision**: Keep pgvector — Docker already running, battle-tested

## Pattern: Superpowers TDD + git worktree
- **Stars**: 57.2K GitHub
- **Key Pattern**: Each agent works on a separate git worktree → parallel development without conflicts
- **Relevance**: For Terminator's parallel bug bounty pipeline — scouts could work on separate worktrees
- **Current Decision**: Monitor — our pipeline uses sequential handoff, not parallel file editing

## Integration: claude-code-telegram
- **Purpose**: Remote monitoring of Claude Code sessions via Telegram
- **Key Feature**: Session persistence + webhook notifications
- **Relevance**: For unattended terminator.sh runs — get notified when findings discovered
- **Current Decision**: Nice-to-have, not critical path

## Reference: Jeffallan/claude-skills (66 skills)
- **Notable Skills**: Security category, Jira/Confluence integration
- **Relevance**: Inspiration for custom skills, not direct adoption

## Reference: HuggingFace Skills
- **Purpose**: ML pipeline skills (fine-tuning, embeddings, inference)
- **Relevance**: For future AI model analysis capabilities (garak integration)
