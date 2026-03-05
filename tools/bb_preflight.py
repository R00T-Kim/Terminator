#!/usr/bin/env python3
"""BB Pipeline Gate — Validates prerequisites before phase transitions.

Enforces two structural rules that LLM instructions alone cannot guarantee:
1. Program rules (auth headers, mandatory headers, known issues) must be
   documented BEFORE any agent starts work.
2. Endpoint coverage must reach threshold BEFORE advancing to Phase 2+.

Usage:
    bb_preflight.py init <target_dir>                  Create template files
    bb_preflight.py rules-check <target_dir>           Validate program_rules_summary.md
    bb_preflight.py coverage-check <target_dir> [THR] [--json]  Check endpoint coverage %
    bb_preflight.py inject-rules <target_dir>          Output compact rules for HANDOFF
    bb_preflight.py exclusion-filter <target_dir>      Output exclusion list for analyst

Exit: 0=PASS, 1=FAIL (with specific error message)

Created: 2026-02-25 (NAMUHX retrospective — structural fix for rule compliance & coverage gap)
"""

import sys
import os
import re
import shutil
from pathlib import Path

RULES_FILE = "program_rules_summary.md"
ENDPOINT_MAP = "endpoint_map.md"
COVERAGE_THRESHOLD = 80

REQUIRED_RULES_SECTIONS = [
    "Auth Header Format",
    "Mandatory Headers",
    "Known Issues",
    "Exclusion List",
    "Submission Rules",
]

TEMPLATE_DIR = Path(__file__).parent / "templates"


def init(target_dir: str) -> int:
    """Create template files in target directory."""
    tdir = Path(target_dir)
    tdir.mkdir(parents=True, exist_ok=True)

    rules_src = TEMPLATE_DIR / RULES_FILE
    map_src = TEMPLATE_DIR / ENDPOINT_MAP

    created = []
    for src, name in [(rules_src, RULES_FILE), (map_src, ENDPOINT_MAP)]:
        dst = tdir / name
        if dst.exists():
            print(f"SKIP: {name} already exists in {target_dir}")
            continue
        if src.exists():
            shutil.copy2(src, dst)
        else:
            # Fallback: create minimal template inline
            if name == RULES_FILE:
                dst.write_text(_inline_rules_template(target_dir))
            else:
                dst.write_text(_inline_map_template(target_dir))
        created.append(name)

    if created:
        print(f"CREATED: {', '.join(created)} in {target_dir}")
    else:
        print(f"All templates already exist in {target_dir}")
    return 0


def rules_check(target_dir: str) -> int:
    """Validate program_rules_summary.md exists and has all required sections."""
    rules_path = Path(target_dir) / RULES_FILE
    if not rules_path.exists():
        print(f"FAIL: {RULES_FILE} not found in {target_dir}")
        print(f"  → Run: python3 {__file__} init {target_dir}")
        print(f"  → Then fill in ALL <REQUIRED> fields before spawning agents")
        return 1

    content = rules_path.read_text()

    # Check required sections
    missing = []
    for section in REQUIRED_RULES_SECTIONS:
        if section not in content:
            missing.append(section)

    if missing:
        print(f"FAIL: Missing sections in {RULES_FILE}: {', '.join(missing)}")
        return 1

    # Check for unfilled placeholders
    placeholders = re.findall(r"<(?:TODO|FILL|REQUIRED|PLACEHOLDER)[^>]*>", content)
    if placeholders:
        unique = list(set(placeholders))
        print(f"FAIL: {len(unique)} unfilled placeholder(s): {unique[:5]}")
        print(f"  → Fill ALL <REQUIRED:...> fields in {rules_path}")
        return 1

    # Check minimum content (not just section headers)
    for section in REQUIRED_RULES_SECTIONS:
        # Find section and check it has content after it
        pattern = rf"##\s*{re.escape(section)}\s*\n(.*?)(?=\n##|\Z)"
        match = re.search(pattern, content, re.DOTALL)
        if match:
            body = match.group(1).strip()
            if len(body) < 10:
                print(f"FAIL: Section '{section}' appears empty (< 10 chars)")
                return 1

    print(f"PASS: {RULES_FILE} validated ({len(REQUIRED_RULES_SECTIONS)} sections, no placeholders)")
    return 0


def coverage_check(target_dir: str, threshold: int = COVERAGE_THRESHOLD, json_output: bool = False) -> int:
    """Parse endpoint_map.md and calculate coverage percentage.

    Args:
        target_dir: Path to target directory containing endpoint_map.md
        threshold: Minimum coverage percentage (default 80, 100 for <10 endpoints)
        json_output: If True, output structured JSON instead of text
    Returns:
        0 if PASS, 1 if FAIL
    """
    map_path = Path(target_dir) / ENDPOINT_MAP
    if not map_path.exists():
        if json_output:
            import json
            print(json.dumps({"result": "FAIL", "error": f"{ENDPOINT_MAP} not found", "coverage": 0}))
        else:
            print(f"FAIL: {ENDPOINT_MAP} not found in {target_dir}")
            print(f"  → Scout must generate {ENDPOINT_MAP} during Phase 1")
        return 1

    content = map_path.read_text()
    lines = content.split("\n")

    statuses = {"UNTESTED": 0, "TESTED": 0, "VULN": 0, "SAFE": 0, "EXCLUDED": 0}
    untested_endpoints = []
    total = 0

    # Find Status column index from header row
    status_col = None
    for line in lines:
        if "|" in line and "Status" in line:
            hcells = [c.strip() for c in line.split("|")]
            for idx, cell in enumerate(hcells):
                if cell.upper() == "STATUS":
                    status_col = idx
                    break
            break
    if status_col is None:
        status_col = 4  # Default: | Endpoint | Method | Auth | Status | Notes |

    for line in lines:
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.split("|")]
        if len(cells) <= status_col:
            continue
        # Skip header, separator, empty rows
        if cells[1] in ("", "Endpoint", "---") or cells[1].startswith("-"):
            continue
        if set(cells[1]) <= {"-", " "}:
            continue

        status = cells[status_col].upper()
        if status in statuses:
            statuses[status] += 1
            total += 1
            if status == "UNTESTED":
                untested_endpoints.append(cells[1])

    if total == 0:
        if json_output:
            import json
            print(json.dumps({"result": "FAIL", "error": "No endpoints found", "coverage": 0}))
        else:
            print(f"FAIL: No endpoints found in {ENDPOINT_MAP}")
            print(f"  → Scout must populate the endpoint table")
        return 1

    testable = total - statuses["EXCLUDED"]
    if testable == 0:
        if json_output:
            import json
            print(json.dumps({"result": "FAIL", "error": "All endpoints EXCLUDED", "coverage": 0}))
        else:
            print(f"FAIL: All {total} endpoints are EXCLUDED — nothing to test")
        return 1

    # Auto-adjust threshold for small targets
    effective_threshold = 100 if testable < 10 else threshold

    tested = statuses["TESTED"] + statuses["VULN"] + statuses["SAFE"]
    coverage = (tested / testable) * 100

    passed = coverage >= effective_threshold

    if json_output:
        import json
        print(json.dumps({
            "result": "PASS" if passed else "FAIL",
            "coverage": round(coverage, 1),
            "threshold": effective_threshold,
            "total": total,
            "testable": testable,
            "tested": tested,
            "statuses": statuses,
            "untested_endpoints": untested_endpoints,
            "small_target_override": testable < 10,
        }))
    else:
        print(f"Coverage: {coverage:.1f}% ({tested}/{testable} testable endpoints)")
        print(f"  VULN={statuses['VULN']} SAFE={statuses['SAFE']} "
              f"TESTED={statuses['TESTED']} UNTESTED={statuses['UNTESTED']} "
              f"EXCLUDED={statuses['EXCLUDED']}")
        if testable < 10:
            print(f"  (Small target: <10 endpoints → threshold auto-raised to 100%)")

        if not passed:
            print(f"FAIL: Coverage {coverage:.1f}% < threshold {effective_threshold}%")
            print(f"  → Spawn additional exploiter/analyst round for UNTESTED endpoints")
            if untested_endpoints:
                print(f"  → UNTESTED: {', '.join(untested_endpoints[:20])}")
        else:
            print(f"PASS: Coverage {coverage:.1f}% >= threshold {effective_threshold}%")

    return 0 if passed else 1


def inject_rules(target_dir: str) -> int:
    """Output compact rules for HANDOFF injection (first 3 lines of agent prompt)."""
    rules_path = Path(target_dir) / RULES_FILE
    if not rules_path.exists():
        print(f"FAIL: {RULES_FILE} not found", file=sys.stderr)
        return 1

    content = rules_path.read_text()

    # Extract key fields for compact injection (allow extra text after section name)
    auth_match = re.search(
        r"##\s*Auth Header Format[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )
    headers_match = re.search(
        r"##\s*Mandatory Headers[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )
    curl_match = re.search(
        r"##\s*Verified Curl Template[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )

    print("[PROGRAM RULES — READ FIRST, FOLLOW EXACTLY]")
    if auth_match:
        print(f"AUTH: {auth_match.group(1).strip()[:200]}")
    if headers_match:
        print(f"HEADERS: {headers_match.group(1).strip()[:300]}")
    if curl_match:
        print(f"CURL TEMPLATE:\n{curl_match.group(1).strip()[:500]}")
    print("[END PROGRAM RULES]")
    return 0


def exclusion_filter(target_dir: str) -> int:
    """Output exclusion list for analyst (Known Issues + Exclusion List)."""
    rules_path = Path(target_dir) / RULES_FILE
    if not rules_path.exists():
        print(f"FAIL: {RULES_FILE} not found", file=sys.stderr)
        return 1

    content = rules_path.read_text()

    known_match = re.search(
        r"##\s*Known Issues[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )
    submitted_match = re.search(
        r"##\s*Already Submitted[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )
    excl_match = re.search(
        r"##\s*Exclusion List[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
    )

    print("[EXCLUSION FILTER — Skip findings matching these patterns]")
    if known_match:
        print(f"\n### Known Issues (already reported/acknowledged):")
        print(known_match.group(1).strip())
    if submitted_match:
        print(f"\n### Already Submitted (do NOT duplicate):")
        print(submitted_match.group(1).strip())
    if excl_match:
        print(f"\n### Program Exclusions (out of scope):")
        print(excl_match.group(1).strip())
    print("\n[END EXCLUSION FILTER]")
    return 0


# --- Inline templates (fallback if templates/ dir missing) ---

def _inline_rules_template(target_dir: str) -> str:
    name = Path(target_dir).name.upper()
    return f"""# Program Rules Summary — {name}

## Platform
<REQUIRED: Platform name (FindTheGap, Bugcrowd, H1, Immunefi, etc.)>

## Auth Header Format
<REQUIRED: Exact auth header format used in API requests>
Example: `IdToken: <COGNITO_ID_TOKEN>` (NOT `Authorization: Bearer`)

## Mandatory Headers
<REQUIRED: All required headers for valid requests — copy exact values>
Example:
- `bugbounty: [FindtheGap]security_test_c16508a5-ebcb-4d0f-bf7a-811668fbaa44`

## Known Issues (Exclude from Analysis)
<REQUIRED: List of known issues that are already reported or acknowledged by the program>
1. (none identified yet)

## Exclusion List (Out of Scope)
<REQUIRED: Vulnerability types explicitly excluded by the program>
1. (none identified yet)

## Submission Rules
<REQUIRED: Platform-specific submission rules>
- Bundling: <REQUIRED: "연계 가능한 취약점은 하나의 시나리오" etc.>
- CVSS version: <REQUIRED: 3.1 or 4.0>
- Language: <REQUIRED: Korean, English, etc.>
- Report format: <REQUIRED: Platform-specific format>

## Verified Curl Template
<REQUIRED: A WORKING curl command that demonstrates correct auth — copy from actual successful test>
```bash
curl -s "https://api.example.com/endpoint" \\
  -H "<auth_header>: <token>" \\
  -H "<mandatory_header>: <value>"
```
"""


def _inline_map_template(target_dir: str) -> str:
    name = Path(target_dir).name.upper()
    return f"""# Endpoint Map — {name}

Generated: <DATE>
Total: 0 endpoints
Coverage: 0%

Status values: UNTESTED | TESTED | VULN | SAFE | EXCLUDED

| Endpoint | Method | Auth | Status | Notes |
|----------|--------|------|--------|-------|
| /api/example | GET | Required | UNTESTED | |
"""


# --- Main ---

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    target = sys.argv[2]

    if cmd == "init":
        sys.exit(init(target))
    elif cmd == "rules-check":
        sys.exit(rules_check(target))
    elif cmd == "coverage-check":
        threshold = COVERAGE_THRESHOLD
        json_out = False
        for arg in sys.argv[3:]:
            if arg == "--json":
                json_out = True
            else:
                try:
                    threshold = int(arg)
                except ValueError:
                    pass
        sys.exit(coverage_check(target, threshold, json_out))
    elif cmd == "inject-rules":
        sys.exit(inject_rules(target))
    elif cmd == "exclusion-filter":
        sys.exit(exclusion_filter(target))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
