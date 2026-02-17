#!/bin/bash
# Weekly benchmark auto-run script for Terminator pipeline.
# Run via cron: 0 9 * * 1 /path/to/weekly_run.sh >> /var/log/terminator_benchmark.log 2>&1

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCHMARK_DIR="$PROJECT_ROOT/tests/benchmarks"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
LOG_FILE="$BENCHMARK_DIR/runs/run_${TIMESTAMP}.log"

mkdir -p "$BENCHMARK_DIR/runs"

echo "=== Terminator Benchmark Run: $TIMESTAMP ===" | tee "$LOG_FILE"
echo "Project root: $PROJECT_ROOT" | tee -a "$LOG_FILE"

cd "$PROJECT_ROOT"

# Run full benchmark suite
python3 "$BENCHMARK_DIR/benchmark.py" --all 2>&1 | tee -a "$LOG_FILE"

# Archive summary with timestamp
if [ -f "$BENCHMARK_DIR/summary.json" ]; then
    cp "$BENCHMARK_DIR/summary.json" "$BENCHMARK_DIR/runs/summary_${TIMESTAMP}.json"
    echo "Summary archived: runs/summary_${TIMESTAMP}.json" | tee -a "$LOG_FILE"
fi

echo "=== Benchmark complete: $TIMESTAMP ===" | tee -a "$LOG_FILE"
