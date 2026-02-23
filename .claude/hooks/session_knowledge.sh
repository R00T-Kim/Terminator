#!/bin/bash
# session_knowledge.sh — SessionStart hook
# Injects global GraphRAG summary at session start

set -euo pipefail

GRAPHRAG_ROOT="$(cd "$(dirname "$0")/../../tools/graphrag-security" && pwd)"
TIMEOUT=20

QUERY="Summarize the top 10 most important security techniques, common failure patterns, and key lessons learned from bug bounty and CTF experience"

# Check if graphrag is available
if ! command -v graphrag &>/dev/null; then
    echo '{}'
    exit 0
fi

# Check if graphrag root exists and has been indexed
if [[ ! -d "$GRAPHRAG_ROOT" ]] || [[ ! -d "$GRAPHRAG_ROOT/output" ]]; then
    echo '{}'
    exit 0
fi

# Check if there are any parquet outputs (index exists)
if ! ls "$GRAPHRAG_ROOT/output/"*.parquet &>/dev/null 2>&1 && \
   ! find "$GRAPHRAG_ROOT/output" -name "*.parquet" -type f 2>/dev/null | grep -q .; then
    echo '{}'
    exit 0
fi

# Run graphrag global query with timeout
RESULT=$(timeout "$TIMEOUT" graphrag query \
    --root "$GRAPHRAG_ROOT" \
    --method global \
    --query "$QUERY" 2>/dev/null) || true

if [[ -z "$RESULT" ]]; then
    echo '{}'
    exit 0
fi

# Truncate to reasonable size and output
SUMMARY=$(echo "$RESULT" | head -80)
printf '{"systemMessage": "[SESSION KNOWLEDGE SUMMARY]\n%s"}' \
    "$(echo "$SUMMARY" | jq -Rs '.[0:3000]' | tr -d '"')"
