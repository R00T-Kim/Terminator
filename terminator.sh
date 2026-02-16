#!/bin/bash
# Terminator - Autonomous Security Agent Launcher
# Uses Claude Code with bypassPermissions for fully autonomous operation
#
# Usage:
#   ./terminator.sh ctf /path/to/challenge.zip    (zip or directory)
#   ./terminator.sh bounty https://target.com "*.target.com"
#   ./terminator.sh firmware /path/to/firmware.bin
#   ./terminator.sh status                         (check running sessions)
#   ./terminator.sh logs                           (tail latest session log)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-help}"
TARGET="${2:-}"
SCOPE="${3:-}"
MODEL="${TERMINATOR_MODEL:-sonnet}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="$SCRIPT_DIR/reports/$TIMESTAMP"
PID_FILE="$SCRIPT_DIR/.terminator.pid"
LOG_FILE="$SCRIPT_DIR/.terminator.log"

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

# --- Main ---

case "$MODE" in
  ctf)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./terminator.sh ctf /path/to/challenge[.zip]"
      exit 1
    fi

    CHALLENGE_DIR="$(extract_if_zip "$(realpath "$TARGET")")"
    FILES=$(ls -1 "$CHALLENGE_DIR" 2>/dev/null | head -30)
    mkdir -p "$REPORT_DIR"

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

    # Run in background with nohup
    nohup bash -c "
      claude -p \"$(cat <<PROMPT
You are Terminator Team Lead. Use Claude Code Agent Teams to solve this CTF challenge.

Challenge directory: $CHALLENGE_DIR
Files found: $FILES
Report directory: $REPORT_DIR

STEP 1: Create a team
- Use TeamCreate to create team 'terminator-ctf'

STEP 2: Create tasks
- TaskCreate: 'Recon and static analysis of challenge binaries'
- TaskCreate: 'Deep reverse engineering and exploit development'
- TaskCreate: 'Write solve script and extract flag'
- TaskCreate: 'Generate writeup'

STEP 3: Spawn agents (use Task tool with team_name='terminator-ctf')
- Spawn a 'recon' agent (subagent_type=general-purpose, mode=bypassPermissions):
  Analyze all files: file, strings, checksec on binaries. r2 disassembly of main functions.
  Search ExploitDB: ~/exploitdb/searchsploit <relevant terms>
  Save findings to $REPORT_DIR/recon.md

- Spawn a 'solver' agent (subagent_type=general-purpose, mode=bypassPermissions):
  Read recon findings. Identify the vulnerability/algorithm.
  Write Python solve script. Test it. Extract the flag.
  Save solve.py to $CHALLENGE_DIR/solve.py
  Output: FLAG_FOUND: <flag>

STEP 4: Collect results
- Read agent outputs
- TaskUpdate completed tasks
- Save writeup to $REPORT_DIR/writeup.md
- Output final: FLAG_FOUND: <flag>

Flag formats: DH{...}, FLAG{...}, flag{...}, CTF{...}, GoN{...}, CYAI{...}
PROMPT
)\" --permission-mode bypassPermissions --model \"$MODEL\" 2>&1 | tee \"$REPORT_DIR/session.log\"

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

      rm -f \"$PID_FILE\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    echo "$BGPID $REPORT_DIR $TIMESTAMP ctf" >> "$SCRIPT_DIR/.terminator.history"
    echo ""
    echo "[*] PID: $BGPID"
    echo "[*] To monitor: tail -f $REPORT_DIR/session.log"
    ;;

  bounty)
    if [ -z "$TARGET" ]; then
      echo "Usage: ./terminator.sh bounty https://target.com [scope]"
      exit 1
    fi

    SCOPE="${SCOPE:-$TARGET}"
    mkdir -p "$REPORT_DIR"

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

    nohup bash -c "
      claude -p \"$(cat <<PROMPT
You are Terminator Team Lead. Use Claude Code Agent Teams for this security assessment.

Target: $TARGET
Scope: $SCOPE
Report directory: $REPORT_DIR

STEP 1: Create team
- TeamCreate('terminator-bounty')

STEP 2: Create tasks for each phase
- TaskCreate: 'Reconnaissance and attack surface mapping'
- TaskCreate: 'Vulnerability analysis and CVE correlation'
- TaskCreate: 'PoC exploit development and verification'
- TaskCreate: 'Final security report compilation'

STEP 3: Spawn agents (Task tool, team_name='terminator-bounty', mode=bypassPermissions)

Agent 'scout' (subagent_type=general-purpose):
  - nmap -sV -sC -p- --min-rate 1000 $TARGET
  - Web fingerprinting, directory discovery
  - Save: $REPORT_DIR/recon_report.md

Agent 'analyst' (subagent_type=general-purpose):
  - Read scout results from $REPORT_DIR/recon_report.md
  - ~/exploitdb/searchsploit <service> <version> for each finding
  - Check ~/PoC-in-GitHub/ for CVE PoCs
  - Prioritize attack chains
  - Save: $REPORT_DIR/analysis_report.md

Agent 'exploiter' (subagent_type=general-purpose):
  - Read analysis from $REPORT_DIR/analysis_report.md
  - Develop safe PoC (benign payloads only: id, whoami)
  - Save scripts: $REPORT_DIR/evidence/
  - Save: $REPORT_DIR/exploit_report.md

Agent 'reporter' (subagent_type=general-purpose):
  - Read ALL reports in $REPORT_DIR/
  - Compile: $REPORT_DIR/final_report.md
  - Format: Executive Summary, Findings (CVSS v3.1), Remediation

STEP 4: Collect results, verify all tasks completed, shutdown team.

SAFETY: Authorized target only. Benign payloads. No destructive actions.
PROMPT
)\" --permission-mode bypassPermissions --model \"$MODEL\" 2>&1 | tee \"$REPORT_DIR/session.log\"

      echo '=== SESSION COMPLETE ===' >> \"$REPORT_DIR/session.log\"
      rm -f \"$PID_FILE\"
    " > "$LOG_FILE" 2>&1 &

    BGPID=$!
    echo "$BGPID" > "$PID_FILE"
    echo "$BGPID $REPORT_DIR $TIMESTAMP bounty" >> "$SCRIPT_DIR/.terminator.history"
    echo ""
    echo "[*] PID: $BGPID"
    echo "[*] To monitor: tail -f $REPORT_DIR/session.log"
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
    echo "  ./terminator.sh ctf /path/to/challenge[.zip]   Solve a CTF challenge"
    echo "  ./terminator.sh bounty <url> [scope]            Bug bounty assessment"
    echo "  ./terminator.sh firmware /path/to/firmware.bin  Firmware pipeline"
    echo "  ./terminator.sh status                          Check running session"
    echo "  ./terminator.sh logs                            Tail latest session log"
    echo ""
    echo "Environment:"
    echo "  TERMINATOR_MODEL   Model to use (default: sonnet)"
    echo ""
    echo "Reports: ./reports/<timestamp>/"
    echo "  session.log    Full session transcript"
    echo "  firmware_handoff.json  Firmware machine-readable handoff"
    echo "  firmware_summary.md    Firmware analysis summary"
    echo "  writeup.md     Challenge writeup"
    echo "  flags.txt      Extracted flags (if found)"
    ;;
esac
