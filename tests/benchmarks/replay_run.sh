#!/bin/bash
# Weekly replay benchmark for CI
# Usage: ./tests/benchmarks/replay_run.sh [--type pwn] [--timeout-replay 300]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Terminator Replay Benchmark ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

python3 "$PROJECT_ROOT/tests/benchmarks/benchmark.py" --replay "$@"

EXIT=$?
if [ $EXIT -ne 0 ]; then
    echo ""
    echo "[!] REGRESSIONS DETECTED — check output above"
fi
exit $EXIT
