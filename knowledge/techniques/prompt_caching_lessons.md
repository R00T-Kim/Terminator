# Prompt Caching & Token Efficiency Lessons

**Created**: 2026-02-22

## Claude Code Prompt Caching Architecture

Claude Code uses automatic prompt caching to reduce costs and latency:
- System prompt and tool definitions are cached across turns
- Static content (CLAUDE.md, agent definitions) placed at cache boundaries
- Cache hit rate directly impacts cost (90% hit = 90% savings on input tokens)

### Best Practices for Agent Prompts
1. **Static content first**: Put unchanging instructions at the top of prompts
2. **Dynamic content last**: Handoff data, variable context at the bottom
3. **Avoid unnecessary prompt mutations**: Each change invalidates cache
4. **Model parameter matters**: Specify `model` explicitly to avoid parent inheritance (opus→sonnet saves 3-5x)

## Token Efficiency Rules (from 23 BB programs)

| Approach | Token Cost | Quality |
|----------|-----------|---------|
| Orchestrator reads 16 contracts directly | 500K+ tokens | LOW (Level 0-1) |
| Agent reads 3 contracts + tools | 150K tokens | HIGH (Level 2-4) |
| Gemini triage → Claude deep dive | 80K tokens | HIGH (Level 2-3) |

### Key Savings
- **Gemini CLI for 5K+ LOC**: Free triage, Claude only for HIGH signals
- **markdown.new for web pages**: 80% token savings vs raw HTML
- **Tool-first gate**: Slither/Semgrep before manual review saves 60% tokens
- **Max 3 contracts manual review**: Prevents context window exhaustion

## Prompt Caching Pitfalls
- Changing system prompt invalidates ALL cached turns
- Large tool result payloads are NOT cached (ephemeral)
- Agent spawn inherits parent model if not specified → accidental opus usage
