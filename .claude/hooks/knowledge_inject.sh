#!/bin/bash
# knowledge_inject.sh — PreToolUse:Task hook
# Injects relevant GraphRAG knowledge into agent context before spawn

set -euo pipefail

GRAPHRAG_ROOT="$(cd "$(dirname "$0")/../../tools/graphrag-security" && pwd)"
TIMEOUT=15

# Read stdin JSON
INPUT=$(cat)

# Extract tool_name and tool_input.prompt from JSON
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')

# Only process Task tool calls
if [[ "$TOOL_NAME" != "Task" ]]; then
    echo '{}'
    exit 0
fi

# Extract subagent_type and prompt from tool_input
SUBAGENT_TYPE=$(echo "$INPUT" | jq -r '.tool_input.subagent_type // ""')
PROMPT=$(echo "$INPUT" | jq -r '.tool_input.prompt // ""')

# Combine subagent_type and prompt for matching
COMBINED="${SUBAGENT_TYPE} ${PROMPT}"

# Map agent type to GraphRAG query
QUERY=""

if echo "$COMBINED" | grep -qiE 'reverser|trigger|chain|solver|pwn|exploit|heap|rop|overflow|canary|got|plt|ret2|shellcode|gadget'; then
    QUERY="binary exploitation techniques, vulnerability primitives, heap exploitation, ROP chains, pwn CTF patterns, buffer overflow, format string, use-after-free"
elif echo "$COMBINED" | grep -qiE 'analyst|scout|recon|bounty|submission|owasp|cve|sqli|xss|ssrf|injection|web'; then
    QUERY="bug bounty findings, common rejection reasons, OOS patterns, successful submissions, CVE patterns, web vulnerability techniques, OWASP top 10"
elif echo "$COMBINED" | grep -qiE 'exploiter|poc|proof.of.concept|exploit.dev'; then
    QUERY="exploit development techniques, PoC patterns, proof of concept quality, successful exploits, exploit chain assembly"
elif echo "$COMBINED" | grep -qiE 'fw_|firmware|embedded|router|cgi|nvram|httpd|upnpd|arm|mips'; then
    QUERY="firmware analysis, CGI vulnerabilities, embedded device security, ARM binary exploitation, NVRAM injection, command injection in embedded systems"
elif echo "$COMBINED" | grep -qiE 'crypto|cipher|hash|aes|rsa|prng|random|z3|sage'; then
    QUERY="cryptographic vulnerabilities, cipher attacks, hash collisions, PRNG weaknesses, crypto CTF techniques"
elif echo "$COMBINED" | grep -qiE 'web3|defi|smart.contract|solidity|evm|slither|foundry|immunefi'; then
    QUERY="DeFi vulnerabilities, smart contract security, EVM exploitation, reentrancy, price manipulation, flash loan attacks, Immunefi submission patterns"
fi

# If no matching query found, skip
if [[ -z "$QUERY" ]]; then
    echo '{}'
    exit 0
fi

# Check if graphrag is available
if ! command -v graphrag &>/dev/null; then
    echo '{}'
    exit 0
fi

# Check if graphrag root exists
if [[ ! -d "$GRAPHRAG_ROOT" ]]; then
    echo '{}'
    exit 0
fi

# Run graphrag query with timeout
RESULT=$(timeout "$TIMEOUT" graphrag query \
    --root "$GRAPHRAG_ROOT" \
    --method local \
    --query "$QUERY" 2>/dev/null) || true

if [[ -z "$RESULT" ]]; then
    echo '{}'
    exit 0
fi

# Output JSON with systemMessage (correct field per API docs)
ESCAPED=$(echo "$RESULT" | jq -Rs '.')
printf '{"systemMessage": "[AUTO-INJECTED KNOWLEDGE - %s]\n%s"}' "$SUBAGENT_TYPE" "$(echo "$RESULT" | head -50 | jq -Rs '.[0:2000]')"
