#!/bin/bash
# Gemini CLI wrapper for Terminator security analysis
# Usage:
#   gemini_query.sh reverse <file>              # Binary/source analysis
#   gemini_query.sh analyze <file>              # Vulnerability analysis (bug bounty)
#   gemini_query.sh review <file>               # Exploit code review
#   gemini_query.sh ask "question"              # Free-form security question
#   gemini_query.sh ask "question" <file>       # Question with file context
#   gemini_query.sh summarize <file>            # Large file summarization (token saving)
#   gemini_query.sh triage <file>               # Quick vulnerability pre-screening
#   gemini_query.sh protocol <file>             # Protocol/state machine analysis
#   gemini_query.sh bizlogic <file>             # Business logic flaw detection
#   gemini_query.sh summarize-dir <dir> <glob>  # Summarize all matching files in dir
#
# Options:
#   GEMINI_MODEL=gemini-2.5-flash (default for speed) or gemini-3-pro-preview (deep analysis)
#   GEMINI_MAX_LINES=5000 (default) - max lines to read from file

set -euo pipefail

# Load NVM for gemini CLI access
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

# Always use gemini-3-pro-preview (user preference: fixed model)
MODEL="${GEMINI_MODEL:-gemini-3-pro-preview}"
MAX_LINES="${GEMINI_MAX_LINES:-5000}"
MODE="${1:-ask}"
shift || true

# System prompts per mode
PROMPT_REVERSE="You are a binary reverse engineering expert. Analyze the provided code/disassembly and identify:
1. Key algorithms and data structures
2. Input validation logic (or lack thereof)
3. Potential vulnerability classes (buffer overflow, format string, use-after-free, integer overflow, race condition)
4. Hardcoded constants, magic values, encryption keys
5. Control flow summary (main → critical functions)
Output a structured analysis. Be precise with addresses, sizes, and offsets. No speculation without evidence."

PROMPT_ANALYZE="You are a vulnerability researcher specializing in source code auditing. Analyze the provided code for:
1. OWASP Top 10 vulnerabilities (injection, broken auth, XSS, SSRF, etc.)
2. CWE patterns (eval, exec, unsafe deserialization, prototype pollution, path traversal)
3. Dangerous API usage and insecure defaults
4. Authentication/authorization flaws
5. Data flow from user input to sensitive sinks
For each finding: specify file:line, CWE ID, severity (CRITICAL/HIGH/MEDIUM/LOW), and exploitation path.
Only report findings with clear exploitation paths. Theoretical-only findings are worthless."

PROMPT_REVIEW="You are an exploit development reviewer. Review the provided exploit code for:
1. Correctness of offsets, addresses, and gadget chains
2. Missing error handling or edge cases
3. Reliability issues (ASLR, stack alignment, race conditions)
4. Suggestions for improvement
5. Alternative approaches if current one seems fragile
Be specific and actionable."

PROMPT_ASK="You are a cybersecurity expert. Answer the following security question precisely and concisely."

PROMPT_SUMMARIZE="You are a code analysis assistant. Summarize this file for a security researcher who needs to understand it quickly.

Provide:
1. **Purpose**: What does this file/module do? (1-2 sentences)
2. **Entry Points**: Functions/endpoints that accept external input
3. **Sensitive Operations**: Crypto, auth, file I/O, network calls, eval/exec, SQL queries
4. **Data Flow**: Key input → processing → output paths
5. **Dependencies**: External libraries used and their security relevance
6. **Attack Surface**: Top 3 areas most likely to contain vulnerabilities

Keep the summary under 50 lines. Focus on security-relevant details only."

PROMPT_TRIAGE="You are a vulnerability triage specialist. Quickly scan this code and classify findings.

For each potential issue found:
- **Location**: file:line
- **Type**: CWE ID + short name
- **Confidence**: HIGH/MEDIUM/LOW (HIGH = clear sink reachable from source, LOW = needs more context)
- **Priority**: P1 (exploit likely) / P2 (needs PoC verification) / P3 (theoretical only, skip)

Rules:
- Only list P1 and P2 findings. Ignore P3.
- Do NOT report: missing headers, informational issues, best practices, theoretical timing attacks
- If zero P1/P2 findings: say 'CLEAN — no actionable findings' and stop
- Maximum 10 findings. Quality over quantity."

PROMPT_PROTOCOL="You are a protocol security analyst. Analyze this code for protocol-level and state machine vulnerabilities:

1. **State Machine Flaws**: Missing state transitions, unreachable states, state confusion attacks
2. **Message Ordering**: Can messages be replayed, reordered, or skipped?
3. **Authentication Flow**: Token lifecycle, session binding, nonce uniqueness
4. **Cryptographic Protocol**: Key exchange correctness, forward secrecy, nonce reuse
5. **Consensus/Coordination**: Race conditions in multi-party protocols, split-brain scenarios
6. **Error Recovery**: Does error handling leak state or skip validation?

Focus on exploitable logic flaws, not code quality. For each finding, describe the attack sequence step-by-step."

PROMPT_BIZLOGIC="You are a business logic security expert. Analyze this code for logic flaws that bypass intended behavior:

1. **Access Control**: Can users access resources/actions beyond their privilege level?
2. **Financial Logic**: Rounding errors, negative amounts, overflow in balance/transfer operations
3. **Rate Limiting**: Missing or bypassable rate limits on sensitive operations
4. **Workflow Bypass**: Can multi-step processes be skipped, reordered, or replayed?
5. **Input Boundaries**: Integer overflow/underflow, boundary conditions (0, -1, MAX_INT)
6. **Race Conditions**: TOCTOU in check-then-act patterns, concurrent state modification

For each finding: describe the normal flow, the attack flow, and the impact. Include concrete values/steps to trigger."

case "$MODE" in
    reverse)
        SYSTEM_PROMPT="$PROMPT_REVERSE"
        ;;
    analyze)
        SYSTEM_PROMPT="$PROMPT_ANALYZE"
        ;;
    review)
        SYSTEM_PROMPT="$PROMPT_REVIEW"
        ;;
    ask)
        SYSTEM_PROMPT="$PROMPT_ASK"
        ;;
    summarize)
        SYSTEM_PROMPT="$PROMPT_SUMMARIZE"
        ;;
    triage)
        SYSTEM_PROMPT="$PROMPT_TRIAGE"
        ;;
    protocol)
        SYSTEM_PROMPT="$PROMPT_PROTOCOL"
        ;;
    bizlogic)
        SYSTEM_PROMPT="$PROMPT_BIZLOGIC"
        ;;
    summarize-dir)
        # Special mode: summarize all matching files in a directory
        DIR="${1:-}"
        GLOB="${2:-*.ts}"
        if [ -z "$DIR" ] || [ ! -d "$DIR" ]; then
            echo "Error: valid directory required for 'summarize-dir' mode"
            exit 1
        fi
        echo "=== Summarizing $GLOB files in $DIR ==="
        find "$DIR" -name "$GLOB" -type f | sort | while read -r f; do
            LINE_COUNT=$(wc -l < "$f")
            if [ "$LINE_COUNT" -lt 20 ]; then
                continue  # Skip tiny files
            fi
            echo ""
            echo "--- $f ($LINE_COUNT lines) ---"
            FILE_CONTENT=$(head -"$MAX_LINES" "$f")
            gemini -p "$PROMPT_SUMMARIZE

Analyze this file ($f):
\`\`\`
$FILE_CONTENT
\`\`\`" -m "$MODEL" -o text 2>/dev/null
        done
        exit 0
        ;;
    *)
        echo "Usage: gemini_query.sh {reverse|analyze|review|ask|summarize|triage|protocol|bizlogic|summarize-dir} [file|question] [file|glob]"
        exit 1
        ;;
esac

# Build the query
if [ "$MODE" = "ask" ]; then
    QUESTION="${1:-}"
    FILE="${2:-}"
    if [ -z "$QUESTION" ]; then
        echo "Error: question required for 'ask' mode"
        exit 1
    fi
    if [ -n "$FILE" ] && [ -f "$FILE" ]; then
        FILE_CONTENT=$(head -"$MAX_LINES" "$FILE")
        FULL_PROMPT="$SYSTEM_PROMPT

Question: $QUESTION

File content ($FILE):
\`\`\`
$FILE_CONTENT
\`\`\`"
    else
        FULL_PROMPT="$SYSTEM_PROMPT

Question: $QUESTION"
    fi
else
    FILE="${1:-}"
    if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
        echo "Error: valid file path required for '$MODE' mode"
        exit 1
    fi
    FILE_CONTENT=$(head -"$MAX_LINES" "$FILE")
    FULL_PROMPT="$SYSTEM_PROMPT

Analyze this file ($FILE):
\`\`\`
$FILE_CONTENT
\`\`\`"
fi

# Execute Gemini CLI in headless mode
gemini -p "$FULL_PROMPT" -m "$MODEL" -o text 2>/dev/null
