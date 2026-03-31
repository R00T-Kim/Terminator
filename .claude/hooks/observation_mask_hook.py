#!/usr/bin/env python3
"""PostToolUse:Bash|Read — Observation masking hook.

When tool output exceeds 500 lines, saves full output to file
and returns additionalContext with the file path.
"""
import json, sys, os, hashlib
from datetime import datetime

LINE_THRESHOLD = 500
SAVE_DIR = "/home/rootk1m/01_CYAI_Lab/01_Projects/Terminator/.omc/masked_observations"

def main():
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        print(json.dumps({}))
        return

    tool_name = input_data.get("tool_name", "")
    if tool_name not in ("Bash", "Read"):
        print(json.dumps({}))
        return

    output = input_data.get("tool_output", "")
    if not output:
        print(json.dumps({}))
        return

    lines = output.split('\n')
    if len(lines) <= LINE_THRESHOLD:
        print(json.dumps({}))
        return

    os.makedirs(SAVE_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    content_hash = hashlib.sha256(output.encode()).hexdigest()[:8]
    filename = f"{timestamp}_{tool_name}_{content_hash}.txt"
    filepath = os.path.join(SAVE_DIR, filename)

    with open(filepath, 'w') as f:
        f.write(output)

    head = lines[:15]
    tail = lines[-15:]
    elided_count = len(lines) - 30

    summary = '\n'.join(head)
    summary += f'\n\n[... {elided_count} lines elided. Full output: {filepath} ...]\n\n'
    summary += '\n'.join(tail)

    result = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": f"[OBS MASKED] {len(lines)} lines saved to {filepath}. First/last 15 lines shown in tool result."
        }
    }
    print(json.dumps(result))

if __name__ == "__main__":
    main()
