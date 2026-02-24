#!/bin/bash
# knowledge_db_update.sh — PostToolUse hook
# Triggers fast internal DB rebuild when knowledge docs are modified.
# Only rebuilds Tier 1 (techniques + challenges), <1 second.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DB_PATH="$PROJECT_ROOT/knowledge/knowledge.db"

# Only run if DB exists (skip if never built)
if [[ ! -f "$DB_PATH" ]]; then
    echo '{}'
    exit 0
fi

# Check if the tool input references knowledge/ paths
INPUT="${CLAUDE_TOOL_INPUT:-}"
if echo "$INPUT" | grep -qE 'knowledge/(techniques|challenges)/'; then
    python3 "$PROJECT_ROOT/tools/knowledge_indexer.py" update-internal >/dev/null 2>&1 &
fi

echo '{}'
exit 0
