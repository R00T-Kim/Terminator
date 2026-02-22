#!/bin/bash
# Terminator - Autonomous Security Agent Launcher
# Uses Claude Code with bypassPermissions for fully autonomous operation
#
# Usage:
#   ./terminator.sh [--json] [--timeout N] [--dry-run] ctf /path/to/challenge.zip
#   ./terminator.sh [--json] [--timeout N] [--dry-run] bounty https://target.com "*.target.com"
#   ./terminator.sh firmware /path/to/firmware.bin
#   ./terminator.sh status                         (check running sessions)
#   ./terminator.sh logs                           (tail latest session log)

set -euo pipefail

# Exit codes
EXIT_CLEAN=0
EXIT_CRITICAL=1
EXIT_HIGH=2
EXIT_MEDIUM=3
EXIT_ERROR=10

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODEL="${TERMINATOR_MODEL:-sonnet}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="$SCRIPT_DIR/reports/$TIMESTAMP"
PID_FILE="$SCRIPT_DIR/.terminator.pid"
LOG_FILE="$SCRIPT_DIR/.terminator.log"

# --- Parse global flags ---
JSON_OUTPUT=false
TIMEOUT=0
DRY_RUN=false

while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --json) JSON_OUTPUT=true; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    *) break ;;
  esac
done

MODE="${1:-help}"
TARGET="${2:-}"
SCOPE="${3:-}"

# --- Helper functions ---

extract_if_zip() {
  local target="$1"
  if [[ "$target" == *.zip ]]; then
    local basename="$(basename "$target" .zip)"
    local extract_dir="$SCRIPT_DIR/tests/wargames/extracted/$basename"
    if [ -d "$extract_dir" ]; then
      echo "[*] Already extracted: $extract_dir" >&2
    else
      echo "[*] Extracting $target → $extract_dir" >&2
      mkdir -p "$extract_dir"
      unzip -o -q "$target" -d "$extract_dir"
    fi
    echo "$extract_dir"
  elif [ -d "$target" ]; then
    echo "$(realpath "$target")"
  else
    echo "[!] Not a zip or directory: $target" >&2
    exit 1
  fi
}

generate_summary() {
  local report_dir="$1"
  local mode="$2"
  local target="$3"
  local start_ts="$4"
  local exit_code="$5"
  local status="$6"

  local end_ts
  end_ts="$(date +%s)"
  local duration=$(( end_ts - start_ts ))

  local iso_ts
  iso_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Count flags
  local flags_json="[]"
  if [ -f "$report_dir/flags.txt" ]; then
    flags_json="$(python3 -c "
import json, sys
lines = open('$report_dir/flags.txt').read().strip().splitlines()
flags = [l.strip() for l in lines if l.strip()]
print(json.dumps(flags))
" 2>/dev/null || echo '[]')"
  fi

  # Count findings by severity from session.log
  local cnt_critical=0 cnt_high=0 cnt_medium=0 cnt_low=0 cnt_info=0
  if [ -f "$report_dir/session.log" ]; then
    cnt_critical=$(grep -c '\[CRITICAL\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_high=$(grep -c '\[HIGH\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_medium=$(grep -c '\[MEDIUM\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_low=$(grep -c '\[LOW\]' "$report_dir/session.log" 2>/dev/null || true)
    cnt_info=$(grep -c '\[INFO\]' "$report_dir/session.log" 2>/dev/null || true)
  fi

  # List generated files
  local files_json
  files_json="$(python3 -c "
import json, os
files = []
report_dir = '$report_dir'
try:
    for f in os.listdir(report_dir):
        fpath = os.path.join(report_dir, f)
        if os.path.isfile(fpath):
            files.append(f)
except Exception:
    pass
print(json.dumps(sorted(files)))
" 2>/dev/null || echo '[]')"

  python3 -c "
import json
summary = {
    'timestamp': '$iso_ts',
    'mode': '$mode',
    'target': '$target',
    'duration_seconds': $duration,
    'exit_code': $exit_code,
    'flags_found': $flags_json,
    'findings': {
        'critical': $cnt_critical,
        'high': $cnt_high,
        'medium': $cnt_medium,
        'low': $cnt_low,
        'info': $cnt_info
    },
    'files_generated': $files_json,
    'status': '$status'
}
print(json.dumps(summary, indent=2))
" > "$report_dir/summary.json" 2>/dev/null || true

  # Auto-generate SARIF + PDF reports
  python3 "$SCRIPT_DIR/tools/report_generator.py" \
    --report-dir "$report_dir" --all 2>/dev/null || true
}

determine_exit_code() {
  local report_dir="$1"
  local exit_code=$EXIT_CLEAN

  if [ -f "$report_dir/session.log" ]; then
    if grep -q '\[CRITICAL\]' "$report_dir/session.log" 2>/dev/null; then
      exit_code=$EXIT_CRITICAL
    elif grep -q '\[HIGH\]' "$report_dir/session.log" 2>/dev/null; then
      exit_code=$EXIT_HIGH
    elif grep -q '\[MEDIUM\]' "$report_dir/session.log" 2>/dev/null; then
      exit_code=$EXIT_MEDIUM
    fi
  fi

  echo "$exit_code"
}

# --- Main ---

case "$MODE" in
  ctf)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./terminator.sh ctf /path/to/challenge[.zip]"
      exit $EXIT_ERROR
    fi

    CHALLENGE_DIR="$(extract_if_zip "$(realpath "$TARGET")")"
    FILES=$(ls -1 "$CHALLENGE_DIR" 2>/dev/null | head -30)
    mkdir -p "$REPORT_DIR"

    if [ "$DRY_RUN" = true ]; then
      if [ "$JSON_OUTPUT" = true ]; then
        python3 -c "
import json
plan = {
    'dry_run': True,
    'mode': 'ctf',
    'target': '$CHALLENGE_DIR',
    'model': '$MODEL',
    'report_dir': '$REPORT_DIR',
    'timeout': $TIMEOUT,
    'steps': [
        'extract_if_zip',
        'spawn_reverser_agent',
        'spawn_chain_agent',
        'spawn_verifier_agent',
        'spawn_reporter_agent',
        'generate_summary'
    ]
}
print(json.dumps(plan, indent=2))
"
      else
        echo "[DRY-RUN] CTF mode"
        echo "  Challenge: $CHALLENGE_DIR"
        echo "  Files:     $FILES"
        echo "  Model:     $MODEL"
        echo "  Report:    $REPORT_DIR"
        echo "  Timeout:   ${TIMEOUT}s (0=none)"
        echo "  Would run: claude -p <prompt> --permission-mode bypassPermissions --model $MODEL"
      fi
      exit $EXIT_CLEAN
    fi

    if [ "$JSON_OUTPUT" = false ]; then
      echo "╔══════════════════════════════════════════╗"
      echo "║        TERMINATOR - CTF Mode             ║"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Challenge: $(basename "$CHALLENGE_DIR")"
      echo "║ Files:     $FILES"
      echo "║ Model:     $MODEL"
      echo "║ Report:    $REPORT_DIR"
      echo "║ Log:       $REPORT_DIR/session.log"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Running in background...                 ║"
      echo "║ Monitor:  tail -f $REPORT_DIR/session.log"
      echo "║ Status:   ./terminator.sh status         ║"
      echo "╚══════════════════════════════════════════╝"
    fi

    START_TS="$(date +%s)"

    # Build claude command (with optional timeout wrapper)
    CLAUDE_CMD="claude -p"
    if [ "$TIMEOUT" -gt 0 ] 2>/dev/null; then
      CLAUDE_CMD="timeout $TIMEOUT claude -p"
    fi

    # Run in background with nohup
    nohup bash -c "
      START_TS=$START_TS
      $CLAUDE_CMD \"$(cat <<PROMPT
You are Terminator Team Lead. Use Claude Code Agent Teams to solve this CTF challenge.

Challenge directory: $CHALLENGE_DIR
Files found: $FILES
Report directory: $REPORT_DIR

MANDATORY: Follow CLAUDE.md pipeline rules. Use custom agent types (NOT general-purpose).

STEP 1: Create team
- TeamCreate('terminator-ctf')

STEP 2: Pre-check (do this yourself before spawning agents)
- file and strings on binaries, checksec
- Determine problem type: pwn / reversing / crypto

STEP 3: Spawn pipeline agents (Task tool, team_name='terminator-ctf', mode=bypassPermissions)

For PWN:
  @reverser (subagent_type=reverser, model=sonnet) → reversal_map.md
  @trigger (subagent_type=trigger, model=sonnet) → trigger_report.md [if crash needed]
  @chain (subagent_type=chain, model=opus) → solve.py
  @critic (subagent_type=critic, model=opus) → critic_review.md
  @verifier (subagent_type=verifier, model=sonnet) → FLAG_FOUND
  @reporter (subagent_type=reporter, model=sonnet) → writeup

For REVERSING/CRYPTO:
  @reverser (subagent_type=reverser, model=sonnet) → reversal_map.md
  @solver (subagent_type=solver, model=opus) → solve.py
  @critic (subagent_type=critic, model=opus) → critic_review.md
  @verifier (subagent_type=verifier, model=sonnet) → FLAG_FOUND
  @reporter (subagent_type=reporter, model=sonnet) → writeup

Pass each agent's output to the next via structured HANDOFF.
Save solve.py to $CHALLENGE_DIR/solve.py
Save writeup to $REPORT_DIR/writeup.md

STEP 4: Collect results
- Verify FLAG_FOUND by running solve.py yourself
- Update knowledge/index.md
- TeamDelete

Flag formats: DH{...}, FLAG{...}, flag{...}, CTF{...}, GoN{...}, CYAI{...}
PROMPT
)\" --permission-mode bypassPermissions --model \"$MODEL\" 2>&1 | tee \"$REPORT_DIR/session.log\"
      CLAUDE_EXIT=\${PIPESTATUS[0]}

      # Post-processing
      echo '' >> \"$REPORT_DIR/session.log\"
      echo '=== SESSION COMPLETE ===' >> \"$REPORT_DIR/session.log\"
      echo \"Timestamp: \$(date)\" >> \"$REPORT_DIR/session.log\"

      # Extract flags
      FLAGS=\$(grep -oE '(DH|FLAG|flag|CTF|GoN|CYAI)\{[^}]+\}' \"$REPORT_DIR/session.log\" 2>/dev/null | sort -u || true)
      if [ -n \"\$FLAGS\" ]; then
        echo \"FLAGS FOUND:\" >> \"$REPORT_DIR/session.log\"
        echo \"\$FLAGS\" >> \"$REPORT_DIR/session.log\"
        echo \"\$FLAGS\" > \"$REPORT_DIR/flags.txt\"
      else
        echo 'NO FLAGS FOUND' >> \"$REPORT_DIR/session.log\"
      fi

      # Determine exit code based on findings
      FINAL_EXIT=\$(bash $SCRIPT_DIR/terminator.sh _exit_code $REPORT_DIR 2>/dev/null || echo 0)
      echo \"\$FINAL_EXIT\" > \"$REPORT_DIR/exit_code\"

      # Determine status
      SESSION_STATUS='completed'
      if [ \"\$CLAUDE_EXIT\" -eq 124 ] 2>/dev/null; then
        SESSION_STATUS='timeout'
      elif [ \"\$CLAUDE_EXIT\" -ne 0 ] 2>/dev/null; then
        SESSION_STATUS='failed'
      fi

      # Generate summary.json
      bash $SCRIPT_DIR/terminator.sh _summary $REPORT_DIR ctf '$CHALLENGE_DIR' \$START_TS \$FINAL_EXIT \$SESSION_STATUS 2>/dev/null || true

      rm -f \"$PID_FILE\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    echo "$BGPID $REPORT_DIR $TIMESTAMP ctf" >> "$SCRIPT_DIR/.terminator.history"

    if [ "$JSON_OUTPUT" = true ]; then
      echo "$REPORT_DIR/summary.json"
    else
      echo ""
      echo "[*] PID: $BGPID"
      echo "[*] To monitor: tail -f $REPORT_DIR/session.log"
    fi
    ;;

  bounty)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./terminator.sh bounty https://target.com [scope]"
      exit $EXIT_ERROR
    fi

    SCOPE="${SCOPE:-$TARGET}"
    mkdir -p "$REPORT_DIR"

    if [ "$DRY_RUN" = true ]; then
      if [ "$JSON_OUTPUT" = true ]; then
        python3 -c "
import json
plan = {
    'dry_run': True,
    'mode': 'bounty',
    'target': '$TARGET',
    'scope': '$SCOPE',
    'model': '$MODEL',
    'report_dir': '$REPORT_DIR',
    'timeout': $TIMEOUT,
    'steps': [
        'spawn_target_evaluator',
        'spawn_scout_analyst_parallel',
        'spawn_exploiter',
        'spawn_reporter',
        'spawn_critic_architect',
        'spawn_triager_sim',
        'generate_summary'
    ]
}
print(json.dumps(plan, indent=2))
"
      else
        echo "[DRY-RUN] Bug Bounty mode"
        echo "  Target:  $TARGET"
        echo "  Scope:   $SCOPE"
        echo "  Model:   $MODEL"
        echo "  Report:  $REPORT_DIR"
        echo "  Timeout: ${TIMEOUT}s (0=none)"
        echo "  Would run: claude -p <prompt> --permission-mode bypassPermissions --model $MODEL"
      fi
      exit $EXIT_CLEAN
    fi

    if [ "$JSON_OUTPUT" = false ]; then
      echo "╔══════════════════════════════════════════╗"
      echo "║     TERMINATOR - Bug Bounty Mode         ║"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Target:  $TARGET"
      echo "║ Scope:   $SCOPE"
      echo "║ Model:   $MODEL"
      echo "║ Report:  $REPORT_DIR"
      echo "╠══════════════════════════════════════════╣"
      echo "║ Running in background...                 ║"
      echo "║ Monitor:  tail -f $REPORT_DIR/session.log"
      echo "╚══════════════════════════════════════════╝"
    fi

    START_TS="$(date +%s)"

    CLAUDE_CMD="claude -p"
    if [ "$TIMEOUT" -gt 0 ] 2>/dev/null; then
      CLAUDE_CMD="timeout $TIMEOUT claude -p"
    fi

    nohup bash -c "
      START_TS=$START_TS
      $CLAUDE_CMD \"$(cat <<PROMPT
You are Terminator Team Lead. Use Claude Code Agent Teams for this security assessment.

Target: $TARGET
Scope: $SCOPE
Report directory: $REPORT_DIR

MANDATORY: Follow CLAUDE.md pipeline rules. Use custom agent types (NOT general-purpose).

STEP 1: Create team
- TeamCreate('terminator-bounty')

STEP 2: Phase 0 — Target Intelligence
- Spawn @target_evaluator (subagent_type=target_evaluator, model=sonnet, mode=bypassPermissions)
- Wait for GO/NO-GO. If NO-GO → abort.

STEP 3: Phase 1 — Discovery (parallel)
- Spawn @scout (subagent_type=scout, model=sonnet, mode=bypassPermissions):
  nmap, ffuf, program context, duplicate pre-screen
  Save: $REPORT_DIR/recon_report.md

- Spawn @analyst (subagent_type=analyst, model=sonnet, mode=bypassPermissions):
  searchsploit, CVE matching, source analysis
  Save: $REPORT_DIR/vulnerability_candidates.md

STEP 4: Phase 2 — PoC Development
- Spawn @exploiter (subagent_type=exploiter, model=opus, mode=bypassPermissions):
  Develop safe PoC for HIGH+ candidates (benign payloads only)
  Save: $REPORT_DIR/exploit_report.md

STEP 5: Phase 3-5 — Report + Review
- Spawn @reporter (subagent_type=reporter, model=sonnet, mode=bypassPermissions):
  Draft report with CVSS. Save: $REPORT_DIR/final_report.md

- Spawn @critic (subagent_type=critic, model=opus, mode=bypassPermissions):
  Fact-check report

- Spawn @triager_sim (subagent_type=triager_sim, model=opus, mode=bypassPermissions):
  SUBMIT/STRENGTHEN/KILL decision

STEP 6: Collect results, verify tasks, TeamDelete.

SAFETY: Authorized target only. Benign payloads. No destructive actions.
PROMPT
)\" --permission-mode bypassPermissions --model \"$MODEL\" 2>&1 | tee \"$REPORT_DIR/session.log\"
      CLAUDE_EXIT=\${PIPESTATUS[0]}

      echo '=== SESSION COMPLETE ===' >> \"$REPORT_DIR/session.log\"

      # Determine exit code based on findings
      FINAL_EXIT=\$(bash $SCRIPT_DIR/terminator.sh _exit_code $REPORT_DIR 2>/dev/null || echo 0)
      echo \"\$FINAL_EXIT\" > \"$REPORT_DIR/exit_code\"

      # Determine status
      SESSION_STATUS='completed'
      if [ \"\$CLAUDE_EXIT\" -eq 124 ] 2>/dev/null; then
        SESSION_STATUS='timeout'
      elif [ \"\$CLAUDE_EXIT\" -ne 0 ] 2>/dev/null; then
        SESSION_STATUS='failed'
      fi

      # Generate summary.json
      bash $SCRIPT_DIR/terminator.sh _summary $REPORT_DIR bounty '$TARGET' \$START_TS \$FINAL_EXIT \$SESSION_STATUS 2>/dev/null || true

      rm -f \"$PID_FILE\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    echo "$BGPID $REPORT_DIR $TIMESTAMP bounty" >> "$SCRIPT_DIR/.terminator.history"

    if [ "$JSON_OUTPUT" = true ]; then
      echo "$REPORT_DIR/summary.json"
    else
      echo ""
      echo "[*] PID: $BGPID"
      echo "[*] To monitor: tail -f $REPORT_DIR/session.log"
    fi
    ;;

  firmware)
    if [ -z "$TARGET" ] || [ ! -f "$TARGET" ]; then
      echo "Usage: ./terminator.sh firmware /path/to/firmware.bin"
      exit 1
    fi

    TARGET_PATH="$(realpath "$TARGET")"
    FIRMWARE_PROFILE="${TERMINATOR_FIRMWARE_PROFILE:-analysis}"

    if [ "${TERMINATOR_ACK_AUTHORIZATION:-}" != "1" ]; then
      echo "[!] Firmware mode blocked: set TERMINATOR_ACK_AUTHORIZATION=1 to confirm explicit authorization."
      exit 1
    fi

    if [ "$FIRMWARE_PROFILE" != "analysis" ] && [ "$FIRMWARE_PROFILE" != "exploit" ]; then
      echo "[!] Invalid TERMINATOR_FIRMWARE_PROFILE='$FIRMWARE_PROFILE'. Allowed values: analysis, exploit."
      exit 1
    fi

    EXPLOIT_GATE_JSON=""
    PROMPT_EXPLOIT_GATE_BLOCK="- Analysis profile: no exploit stages."
    if [ "$FIRMWARE_PROFILE" = "exploit" ]; then
      if [ -z "${TERMINATOR_EXPLOIT_FLAG:-}" ] || [ -z "${TERMINATOR_EXPLOIT_ATTESTATION:-}" ] || [ -z "${TERMINATOR_EXPLOIT_SCOPE:-}" ]; then
        echo "[!] Firmware exploit profile blocked: set TERMINATOR_EXPLOIT_FLAG, TERMINATOR_EXPLOIT_ATTESTATION, and TERMINATOR_EXPLOIT_SCOPE."
        exit 1
      fi

      EXPLOIT_GATE_JSON=$(cat <<EOF
,
  "exploit_gate": {
    "flag": "${TERMINATOR_EXPLOIT_FLAG}",
    "attestation": "${TERMINATOR_EXPLOIT_ATTESTATION}",
    "scope": "${TERMINATOR_EXPLOIT_SCOPE}"
  }
EOF
)

      PROMPT_EXPLOIT_GATE_BLOCK=$(cat <<EOF
- Exploit profile: exploit stages are allowed within declared scope, with evidence bundles.
- Exploit authorization is lab-only and explicit for this run:
  - TERMINATOR_EXPLOIT_FLAG=${TERMINATOR_EXPLOIT_FLAG}
  - TERMINATOR_EXPLOIT_ATTESTATION=${TERMINATOR_EXPLOIT_ATTESTATION}
  - TERMINATOR_EXPLOIT_SCOPE=${TERMINATOR_EXPLOIT_SCOPE}
- Do not exceed stated scope. Treat this as authorized laboratory work only.
EOF
)
    fi

    mkdir -p "$REPORT_DIR"
    cat > "$REPORT_DIR/firmware_handoff.json" <<EOF
{
  "mode": "firmware",
  "profile": "$FIRMWARE_PROFILE",
  "status": "pending",
  "policy": {
    "max_reruns_per_stage": 2,
    "max_total_stage_attempts": 10,
    "max_wallclock_per_run": 3600
  },
  "bundles": [],
  "stop_reason": ""${EXPLOIT_GATE_JSON},
  "aiedge": {
    "run_dir": "",
    "run_id": "",
    "stages_executed": []
  }
}
EOF
    : > "$REPORT_DIR/firmware_summary.md"
    : > "$REPORT_DIR/session.log"
    AIEDGE_HANDOFF_ADAPTER="$SCRIPT_DIR/aiedge_handoff_adapter.py"

    AIEDGE_RUN_DIR=""
    AIEDGE_RUN_ID=""
    AIEDGE_HOFF_STATUS="pending"
    AIEDGE_STOP_REASON=""

    INITIAL_STAGE_SUBSET="tooling,carving,firmware_profile,inventory"
    echo "[*] Running initial AIEdge stages: $INITIAL_STAGE_SUBSET" >> "$REPORT_DIR/session.log"
    set +e
    SCOUT_DIR="${SCOUT_DIR:-$HOME/SCOUT}"
    AIEDGE_CMD_OUTPUT="$(cd "$SCOUT_DIR" && PYTHONPATH="$SCOUT_DIR/src" python3 -m aiedge analyze "$TARGET_PATH" --case-id terminator-firmware --ack-authorization --no-llm --stages "$INITIAL_STAGE_SUBSET" 2>&1)"
    AIEDGE_CMD_STATUS=$?
    set -e
    if [ -n "$AIEDGE_CMD_OUTPUT" ]; then
      printf '%s\n' "$AIEDGE_CMD_OUTPUT" >> "$REPORT_DIR/session.log"
    fi

    AIEDGE_RUN_DIR="$(AIEDGE_OUTPUT="$AIEDGE_CMD_OUTPUT" python3 - <<'PY'
import os
import re
from pathlib import Path

output = os.environ.get("AIEDGE_OUTPUT", "")
lines = [line.strip() for line in output.splitlines() if line.strip()]
candidates = []

for line in lines:
    lowered = line.lower()
    if "run_dir" in lowered:
        match = re.search(r"(/[^\s]+)", line)
        if match:
            candidates.append(match.group(1).rstrip(".,:;\"'"))
    elif line.startswith("/"):
        candidates.append(line.rstrip(".,:;\"'"))

for candidate in reversed(candidates):
    run_dir = Path(candidate)
    if run_dir.is_dir() and (run_dir / "manifest.json").is_file():
        print(str(run_dir.resolve()))
        break
PY
)"

    if [ "$AIEDGE_CMD_STATUS" -eq 0 ] && [ -n "$AIEDGE_RUN_DIR" ]; then
      AIEDGE_RUN_ID="$(python3 - <<'PY' "$AIEDGE_RUN_DIR"
import json
import sys

manifest_path = sys.argv[1] + "/manifest.json"
try:
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
except Exception:
    print("")
    raise SystemExit(0)

run_id = manifest.get("run_id", "")
if isinstance(run_id, str):
    print(run_id)
else:
    print("")
PY
)"

      if [ -z "$AIEDGE_RUN_ID" ]; then
        AIEDGE_HOFF_STATUS="failed"
        AIEDGE_STOP_REASON="Initial AIEdge firmware subset run missing run_id in manifest.json"
      fi
    else
      AIEDGE_HOFF_STATUS="failed"
      AIEDGE_STOP_REASON="Initial AIEdge firmware subset run failed (exit $AIEDGE_CMD_STATUS): ${AIEDGE_CMD_OUTPUT//$'\n'/ | }"
      if [ -z "$AIEDGE_RUN_DIR" ]; then
        AIEDGE_STOP_REASON="$AIEDGE_STOP_REASON; run_dir not found"
      fi
    fi

    python3 - <<'PY' "$REPORT_DIR/firmware_handoff.json" "$AIEDGE_HOFF_STATUS" "$AIEDGE_STOP_REASON" "$AIEDGE_RUN_DIR" "$AIEDGE_RUN_ID" "$INITIAL_STAGE_SUBSET"
import json
import sys
from pathlib import Path

handoff_path = sys.argv[1]
status = sys.argv[2]
stop_reason = sys.argv[3]
run_dir = sys.argv[4]
run_id = sys.argv[5]
initial_stages_csv = sys.argv[6]
initial_stages = [stage.strip() for stage in initial_stages_csv.split(",") if stage.strip()]

with open(handoff_path, "r", encoding="utf-8") as fh:
    handoff = json.load(fh)

handoff["status"] = status
handoff["stop_reason"] = stop_reason
handoff["aiedge"]["run_dir"] = run_dir
handoff["aiedge"]["run_id"] = run_id
handoff["aiedge"]["stages_executed"] = initial_stages if run_dir else []

candidate_artifacts = [
    "stages/tooling/stage.json",
    "stages/tooling/attempts/attempt-1/stage.json",
    "stages/carving/stage.json",
    "stages/carving/attempts/attempt-1/stage.json",
    "stages/firmware_profile/stage.json",
    "stages/firmware_profile/attempts/attempt-1/stage.json",
    "stages/firmware_profile/firmware_profile.json",
    "stages/inventory/stage.json",
    "stages/inventory/attempts/attempt-1/stage.json",
    "stages/inventory/inventory.json",
    "report/report.json",
]

if run_dir:
    resolved_run_dir = Path(run_dir)
    bundle_artifacts = [
        artifact
        for artifact in candidate_artifacts
        if (resolved_run_dir / artifact).is_file()
    ]
else:
    bundle_artifacts = []

handoff.setdefault("bundles", []).append(
    {
        "claim": "Initial AIEdge firmware subset executed to seed evidence handoff.",
        "artifacts": bundle_artifacts,
        "confidence": "low",
        "limitations": [
            "Bundle reflects only initial subset coverage before rerun expansion.",
            "Confidence placeholder requires analyst review.",
        ],
        "next_stage_request": {
            "stages": [],
            "why": "Placeholder; follow fw_profiler routing from firmware_profile.json before scheduling reruns.",
        },
    }
)

with open(handoff_path, "w", encoding="utf-8") as fh:
    json.dump(handoff, fh, indent=2)
    fh.write("\n")
PY

    echo "╔══════════════════════════════════════════╗"
    echo "║      TERMINATOR - Firmware Mode          ║"
    echo "╠══════════════════════════════════════════╣"
    echo "║ Firmware: $TARGET_PATH"
    echo "║ Profile:  $FIRMWARE_PROFILE"
    echo "║ Model:    $MODEL"
    echo "║ Report:   $REPORT_DIR"
    echo "║ Log:      $REPORT_DIR/session.log"
    echo "╠══════════════════════════════════════════╣"
    echo "║ Running in background...                 ║"
    echo "║ Monitor:  tail -f $REPORT_DIR/session.log"
    echo "║ Status:   ./terminator.sh status         ║"
    echo "╚══════════════════════════════════════════╝"

    nohup bash -c "
      claude -p \"$(cat <<PROMPT
You are Terminator Firmware Team Lead. Run a firmware analysis pipeline with stage-level control using AIEdge.

Firmware target: $TARGET_PATH
Firmware profile: $FIRMWARE_PROFILE
Report directory: $REPORT_DIR
SCOUT root: \${SCOUT_DIR:-\$HOME/SCOUT}
AIEdge adapter contract: \${SCOUT_DIR:-\$HOME/SCOUT}/docs/aiedge_adapter_contract.md
Evidence bundle contract: $SCRIPT_DIR/knowledge/contracts/firmware_evidence_bundle.md

Requirements:
1) Use subprocess CLI execution for AIEdge only (no in-process API):
   PYTHONPATH=\${SCOUT_DIR:-\$HOME/SCOUT}/src python3 -m aiedge analyze \"$TARGET_PATH\" --ack-authorization --no-llm --stages <comma-separated-stage-subset>
2) Initialize policy in $REPORT_DIR/firmware_handoff.json and enforce caps with these defaults:
   - max_reruns_per_stage: 2
   - max_total_stage_attempts: 10
   - max_wallclock_per_run: 3600 (seconds)
3) Use --stages subsets to iterate per stage group as needed; rerun targeted stages only when evidence is incomplete.
    - Every rerun must cite AIEdge append-only manifest paths: stages/<stage>/attempts/attempt-<n>/stage.json
    - To schedule stages by name on an existing run dir, use the adapter command (subprocess-only + atomic handoff update):
      python3 $AIEDGE_HANDOFF_ADAPTER stages --handoff $REPORT_DIR/firmware_handoff.json --stages tooling,carving,firmware_profile,inventory --log-file $REPORT_DIR/session.log
    - The adapter executes exactly: PYTHONPATH=\${SCOUT_DIR:-\$HOME/SCOUT}/src python3 -m aiedge stages <run_dir> --stages <subset>
    - <run_dir> must come from $REPORT_DIR/firmware_handoff.json field aiedge.run_dir.
    - Do not manually edit firmware_handoff.json for reruns; always use adapter invocations so bundles/stages_executed stay consistent.
4) Treat stages/<stage>/stage.json manifests and report.json as source-of-truth evidence.
   - Never infer stage state from logs.
5) Evidence bundle output is JSON-first and must follow this shape for each stage claim:
   {\"claim\":\"...\",\"artifacts\":[...],\"confidence\":\"high|medium|low\",\"limitations\":[...],\"next_stage_request\":{\"stages\":[...],\"why\":\"...\"}}
6) Rerun policy is finite by design (no infinite loops):
   - If any cap is hit, set stop_reason in firmware_handoff.json and stop further reruns.
7) Follow the profile gate for exploit stage behavior.
8) Redaction and compliance:
   - Do not write secrets, credentials, access tokens, private keys, or personally identifying data to session.log, firmware_summary.md, or bundle artifacts.
   - If sensitive values are unavoidable in source artifacts, redact before quoting and mark redaction clearly.
9) Profile gate:
$PROMPT_EXPLOIT_GATE_BLOCK
10) Firmware planning roles (mandatory):
    - Read and follow these role definitions before each planning decision:
      - $SCRIPT_DIR/.claude/agents/fw_profiler.md
      - $SCRIPT_DIR/.claude/agents/fw_inventory.md
      - $SCRIPT_DIR/.claude/agents/fw_surface.md
      - $SCRIPT_DIR/.claude/agents/fw_validator.md
    - Use fw_profiler routing from stages/firmware_profile/firmware_profile.json:
      - branch_plan.inventory_mode=filesystem -> prioritize inventory + surface stages over extracted filesystem.
      - branch_plan.inventory_mode=binary_only -> prioritize binary-focused surface and graph stages.
     - Schedule every additional subset using the adapter; do not hand-edit firmware_handoff.json.
11) Tribunal adjudication (mandatory, JSONL + cache-aware):
    - Materialize tribunal artifacts under $REPORT_DIR/tribunal/:
      - analyst_candidates.jsonl
      - critic_reviews.jsonl
      - judged_findings.jsonl
      - decision_trace.jsonl
    - JSONL means one JSON object per line; keep machine-readable and deterministic.
    - Prefilter candidates to top-N before critic/judge passes; default top_n=50 unless stricter policy already exists in handoff.
    - Every judged finding MUST include admissible evidence refs:
      - evidence: [{"path":"run-relative-posix","sha256":"<hex-or-empty>","locator":"json_pointer|line-range|note"}]
    - Never write absolute host paths in tribunal artifacts; all evidence paths are run-relative POSIX.
    - Use cache key inputs: (a) candidate objects, (b) aiedge.run_id + stage manifest sha256s if available, (c) top_n.
    - Use helper: python3 $SCRIPT_DIR/bridge/tribunal_cache.py key --candidates-jsonl $REPORT_DIR/tribunal/analyst_candidates.jsonl --handoff $REPORT_DIR/firmware_handoff.json --top-n <N>
    - Cache store location: $REPORT_DIR/tribunal/cache/<cache_key>.json
    - On cache hit: reuse prior judged outputs (no regeneration), rewrite judged_findings.jsonl from cache, and record cache_hit=true in decision_trace.jsonl.
    - On cache miss: generate critic/judge outputs, then store cache via python3 $SCRIPT_DIR/bridge/tribunal_cache.py put --report-dir $REPORT_DIR --key <cache_key> --judged-jsonl $REPORT_DIR/tribunal/judged_findings.jsonl --top-n <N> --run-id <run_id>
    - decision_trace.jsonl must record top_n and actual judged_count.
    - Validate artifacts before completion:
      python3 $SCRIPT_DIR/bridge/validate_tribunal_artifacts.py --report-dir $REPORT_DIR
    - Run validator immediately after tribunal artifacts are materialized:
      python3 $SCRIPT_DIR/bridge/fw_validator.py --report-dir $REPORT_DIR
    - Enforce confirmed policy fail-closed:
      python3 $SCRIPT_DIR/bridge/validate_confirmed_policy.py --report-dir $REPORT_DIR
      - If this fails and operator chooses to continue, run auto-downgrade + continue:
        python3 $SCRIPT_DIR/bridge/enforce_confirmed_policy.py --report-dir $REPORT_DIR
      - Re-run policy validator after enforcement before final output.

Deliverables (must always exist at end):
- Update $REPORT_DIR/firmware_handoff.json with minimal machine-readable fields:
  {
    \"mode\": \"firmware\",
    \"profile\": \"analysis|exploit\",
    \"status\": \"completed\" | \"failed\",
    \"policy\": {
      \"max_reruns_per_stage\": 2,
      \"max_total_stage_attempts\": 10,
      \"max_wallclock_per_run\": 3600
    },
    \"bundles\": [
      {
        \"claim\": \"...\",
        \"artifacts\": [\"stages/<stage>/stage.json\", \"stages/<stage>/attempts/attempt-<n>/stage.json\"],
        \"confidence\": \"high|medium|low\",
        \"limitations\": [\"...\"],
        \"next_stage_request\": {\"stages\": [\"...\"], \"why\": \"...\"}
      }
    ],
    \"stop_reason\": \"\",
    \"exploit_gate\": {\"flag\": \"...\", \"attestation\": \"...\", \"scope\": \"...\"},
    \"aiedge\": {
      \"run_dir\": \"<absolute run dir>\",
      \"run_id\": \"<run id if present, else empty>\",
      \"stages_executed\": [\"tooling\", \"...\"]
    }
  }
- Include exploit_gate only when profile=exploit.
- Write concise analyst-facing markdown to $REPORT_DIR/firmware_summary.md.
- Keep concise execution notes in $REPORT_DIR/session.log.
- Produce and validate tribunal outputs under $REPORT_DIR/tribunal/ as specified above.

Execution guidance:
- Start with a minimal subset that includes firmware profiling in order (for example: tooling,carving,firmware_profile,inventory), then expand via --stages based on manifest/report evidence.
- Record exactly which stages were actually executed in firmware_handoff.json.
- For each rerun decision, use one adapter invocation and ensure it appends bundle(s) with claim/artifacts/confidence/limitations/next_stage_request.
- Route rerun subsets from firmware_profile.json (linux_fs/filesystem vs binary_only) and cite the artifact path used for the decision.
- If any cap is reached, set stop_reason with cap name + current counters, set status=failed, and end reruns.
- If a run fails, still write failed status with best-known run_dir/run_id and observed stages.
PROMPT
)\" --permission-mode bypassPermissions --model \"$MODEL\" 2>&1 | tee \"$REPORT_DIR/session.log\"

      echo '=== SESSION COMPLETE ===' >> \"$REPORT_DIR/session.log\"
      rm -f \"$PID_FILE\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    echo "$BGPID $REPORT_DIR $TIMESTAMP firmware" >> "$SCRIPT_DIR/.terminator.history"
    echo ""
    echo "[*] PID: $BGPID"
    echo "[*] To monitor: tail -f $REPORT_DIR/session.log"
    ;;

  # Internal subcommands (used by nohup post-processing blocks)
  _exit_code)
    REPORT_DIR_ARG="${2:-}"
    if [ -n "$REPORT_DIR_ARG" ] && [ -f "$REPORT_DIR_ARG/session.log" ]; then
      if grep -q '\[CRITICAL\]' "$REPORT_DIR_ARG/session.log" 2>/dev/null; then
        echo $EXIT_CRITICAL
      elif grep -q '\[HIGH\]' "$REPORT_DIR_ARG/session.log" 2>/dev/null; then
        echo $EXIT_HIGH
      elif grep -q '\[MEDIUM\]' "$REPORT_DIR_ARG/session.log" 2>/dev/null; then
        echo $EXIT_MEDIUM
      else
        echo $EXIT_CLEAN
      fi
    else
      echo $EXIT_CLEAN
    fi
    ;;

  _summary)
    # Internal: _summary <report_dir> <mode> <target> <start_ts> <exit_code> <status>
    S_REPORT_DIR="${2:-}"
    S_MODE="${3:-unknown}"
    S_TARGET="${4:-}"
    S_START_TS="${5:-0}"
    S_EXIT_CODE="${6:-0}"
    S_STATUS="${7:-completed}"
    generate_summary "$S_REPORT_DIR" "$S_MODE" "$S_TARGET" "$S_START_TS" "$S_EXIT_CODE" "$S_STATUS"
    ;;

  status)
    if [ -f "$PID_FILE" ]; then
      PID=$(cat "$PID_FILE")
      if kill -0 "$PID" 2>/dev/null; then
        echo "[*] Terminator is RUNNING (PID: $PID)"
        echo "[*] Latest log:"
        LATEST=$(ls -td "$SCRIPT_DIR/reports"/20* 2>/dev/null | head -1)
        [ -n "$LATEST" ] && tail -5 "$LATEST/session.log" 2>/dev/null
      else
        echo "[*] Terminator is NOT running (stale PID file)"
        rm -f "$PID_FILE"
      fi
    else
      echo "[*] Terminator is NOT running"
    fi
    echo ""
    echo "[*] Recent sessions:"
    tail -5 "$SCRIPT_DIR/.terminator.history" 2>/dev/null || echo "  (none)"
    ;;

  logs)
    LATEST=$(ls -td "$SCRIPT_DIR/reports"/20* 2>/dev/null | head -1)
    if [ -n "$LATEST" ] && [ -f "$LATEST/session.log" ]; then
      echo "[*] Tailing: $LATEST/session.log"
      echo "[*] Ctrl+C to stop"
      tail -f "$LATEST/session.log"
    else
      echo "[!] No session logs found"
    fi
    ;;

  help|*)
    echo "Terminator - Autonomous Security Agent"
    echo ""
    echo "Usage:"
    echo "  ./terminator.sh [OPTIONS] ctf /path/to/challenge[.zip]   Solve a CTF challenge"
    echo "  ./terminator.sh [OPTIONS] bounty <url> [scope]            Bug bounty assessment"
    echo "  ./terminator.sh firmware /path/to/firmware.bin            Firmware pipeline"
    echo "  ./terminator.sh status                                     Check running session"
    echo "  ./terminator.sh logs                                       Tail latest session log"
    echo ""
    echo "Options:"
    echo "  --json         Suppress banner; print summary.json path on completion"
    echo "  --timeout N    Abort session after N seconds (0 = no limit)"
    echo "  --dry-run      Print execution plan without running claude"
    echo ""
    echo "Environment:"
    echo "  TERMINATOR_MODEL   Model to use (default: sonnet)"
    echo ""
    echo "Exit Codes:"
    echo "  0   Clean (no findings or CTF solved)"
    echo "  1   Critical severity finding"
    echo "  2   High severity finding"
    echo "  3   Medium severity finding"
    echo "  10  Script error"
    echo ""
    echo "Reports: ./reports/<timestamp>/"
    echo "  session.log            Full session transcript"
    echo "  summary.json           Machine-readable session summary"
    echo "  exit_code              Numeric exit code based on findings"
    echo "  firmware_handoff.json  Firmware machine-readable handoff"
    echo "  firmware_summary.md    Firmware analysis summary"
    echo "  writeup.md             Challenge writeup"
    echo "  flags.txt              Extracted flags (if found)"
    ;;
esac
