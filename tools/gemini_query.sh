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
#   GEMINI_MODEL=gemini-3-pro-preview (fixed, do not change)
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

PROMPT_SOLIDITY="You are a smart contract security auditor specializing in DeFi protocols. Analyze this Solidity code for:

1. **Reentrancy**: External calls before state updates, cross-function reentrancy, read-only reentrancy
2. **Flash Loan Attacks**: Price manipulation via flash loans, oracle manipulation, sandwich attacks
3. **Slippage/MEV**: Missing slippage protection (minAmount=0), hardcoded zero parameters, sandwich-vulnerable functions
4. **Access Control**: Missing onlyOwner/onlyRole, unprotected initializers, privilege escalation
5. **Oracle Manipulation**: Spot price as oracle, TWAP bypass, stale price data
6. **Integer Issues**: Unsafe casting, precision loss in division, fee calculation rounding
7. **Token Handling**: Missing return value checks, fee-on-transfer tokens, rebasing tokens
8. **Cross-Chain**: CCIP/bridge message validation, replay attacks, finality assumptions
9. **Upgradability**: Storage collision, uninitialized proxy, selfdestruct in implementation
10. **Economic Exploits**: Donation attacks, first depositor advantage, reward distribution manipulation

For each finding:
- **Location**: contract:function:line
- **Type**: CWE ID + DeFi-specific category
- **Severity**: CRITICAL/HIGH/MEDIUM/LOW
- **Confidence**: HIGH (clear exploit path) / MEDIUM (needs verification) / LOW (theoretical)
- **Attack Steps**: Numbered step-by-step exploit flow
- **Capital Required**: Flash loan available? How much? From where?

Only report CRITICAL/HIGH/MEDIUM findings. Skip informational and gas optimizations."

PROMPT_CROSSVAL="You are a hostile bug bounty triager reviewing a vulnerability report for rejection. Your job is to find EVERY weakness in this report.

Attack these aspects:
1. **PoC Validity**: Does the PoC actually prove what it claims? Are deal()/mock() hiding infeasibility?
2. **Severity Inflation**: Is the claimed severity justified? Check CVSS vector components individually
3. **Liquidity Reality**: Can the attacker actually source the required tokens? Flash loans? DEX depth?
4. **State Dependency**: Is the attack only profitable under specific conditions? How likely are those conditions?
5. **Economic Viability**: After gas + slippage + fees, is net profit still positive?
6. **Duplicate Risk**: Does this overlap with known CVEs or common knowledge?
7. **Root Cause Accuracy**: Is the identified root cause actually the root cause, or a symptom?
8. **Fix Correctness**: Does the proposed fix actually prevent the attack? Any bypass?

Output format:
- SUBMIT: Report is solid, triager would accept
- STRENGTHEN: List specific weaknesses to fix before submission
- KILL: Report would be rejected, explain why

Be maximally adversarial. The goal is to find problems BEFORE the real triager does."

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
    solidity)
        SYSTEM_PROMPT="$PROMPT_SOLIDITY"
        ;;
    crossval)
        SYSTEM_PROMPT="$PROMPT_CROSSVAL"
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
        echo "Usage: gemini_query.sh {reverse|analyze|review|ask|summarize|triage|protocol|bizlogic|solidity|crossval|summarize-dir} [file|question] [file|glob]"
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
