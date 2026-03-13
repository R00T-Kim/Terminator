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
    bb_preflight.py kill-gate-1 <target_dir> --finding "<desc>"  Pre-validate finding viability
    bb_preflight.py kill-gate-2 <submission_dir>       Pre-validate PoC/evidence quality
    bb_preflight.py workflow-check <target_dir>        Validate workflow_map.md completeness (v12)
    bb_preflight.py fresh-surface-check <target_dir> [--repo <path>]  Check for fresh attack surface (v12)
    bb_preflight.py evidence-tier-check <submission_dir> [--json]     Classify evidence E1-E4 tier (v12)
    bb_preflight.py duplicate-graph-check <target_dir> --finding "<desc>" [--json]  Enhanced duplicate detection (v12)

Exit: 0=PASS, 1=FAIL (with specific error message); kill-gate-*: 0=PASS, 1=WARN (advisory)

Created: 2026-02-25 (NAMUHX retrospective — structural fix for rule compliance & coverage gap)
Updated: 2026-03-14 (v12 — workflow-check, fresh-surface-check, evidence-tier-check, duplicate-graph-check)
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


# --- Kill Gates (advisory pre-validation, exit 0=PASS, 1=WARN) ---

def kill_gate_1(target_dir: str, finding: str) -> int:
    """Pre-validate finding viability before Kill Gate 1.

    Checks:
    - Finding type matches any exclusion entry in program_rules_summary.md
    - Previous submissions (bugcrowd_form.md) share overlapping keywords with finding

    Advisory only — final judgment is by triager-sim agent.
    Returns: 0=PASS, 1=WARN
    """
    warnings = []
    tdir = Path(target_dir)

    # --- Check 1: exclusion list match ---
    rules_path = tdir / RULES_FILE
    if rules_path.exists():
        content = rules_path.read_text()
        excl_match = re.search(
            r"##\s*Exclusion List[^\n]*\n(.*?)(?=\n##|\Z)", content, re.DOTALL
        )
        if excl_match:
            excl_body = excl_match.group(1).strip()
            finding_lower = finding.lower()
            for line in excl_body.splitlines():
                line_clean = line.strip().lstrip("0123456789.-) ").lower()
                if not line_clean or line_clean.startswith("#"):
                    continue
                # Tokenise: split on non-alpha to get meaningful words (>=4 chars)
                excl_words = set(w for w in re.split(r"\W+", line_clean) if len(w) >= 4)
                finding_words = set(w for w in re.split(r"\W+", finding_lower) if len(w) >= 4)
                overlap = excl_words & finding_words
                if overlap:
                    warnings.append(
                        f"[EXCLUSION MATCH] Finding overlaps with exclusion entry: '{line.strip()}'"
                        f" (shared keywords: {', '.join(sorted(overlap))})"
                    )
    else:
        warnings.append(f"[MISSING] {RULES_FILE} not found in {target_dir} — cannot check exclusions")

    # --- Check 2: duplicate against previous submission titles ---
    submission_glob = tdir / "submission"
    form_files = list(submission_glob.glob("report_*/bugcrowd_form.md"))
    if form_files:
        finding_lower = finding.lower()
        finding_words = set(w for w in re.split(r"\W+", finding_lower) if len(w) >= 4)
        for form_path in form_files:
            form_content = form_path.read_text()
            title_match = re.search(r"(?i)^#+\s*Title[:\s]+(.+)$", form_content, re.MULTILINE)
            if not title_match:
                # Fall back: grab any line starting with "Title:"
                title_match = re.search(r"(?i)^Title[:\s]+(.+)$", form_content, re.MULTILINE)
            if not title_match:
                continue
            title = title_match.group(1).strip().lower()
            title_words = set(w for w in re.split(r"\W+", title) if len(w) >= 4)
            overlap = finding_words & title_words
            if len(overlap) >= 2:
                warnings.append(
                    f"[DUPLICATE RISK] Finding shares keywords with previous submission"
                    f" '{form_path.parent.name}/bugcrowd_form.md' title: '{title_match.group(1).strip()}'"
                    f" (overlap: {', '.join(sorted(overlap))})"
                )

    # --- Report ---
    if warnings:
        print(f"WARN: kill-gate-1 raised {len(warnings)} flag(s) for finding: \"{finding}\"")
        for w in warnings:
            print(f"  {w}")
        print("  → Advisory only. Confirm with triager-sim before proceeding.")
        return 1

    print(f"PASS: kill-gate-1 — no exclusion or duplicate flags for: \"{finding}\"")
    return 0


def kill_gate_2(submission_dir: str) -> int:
    """Pre-validate PoC/evidence quality before Kill Gate 2.

    Checks:
    - PoC files (*.py, *.sh) contain mock/fake/simulated/dummy keywords
    - Evidence files (*.md) contain weak-claim language (inferred, would, likely, etc.)
    - Evidence files are non-empty (>0 bytes)

    Advisory only — final judgment is by triager-sim agent.
    Returns: 0=PASS, 1=WARN
    """
    warnings = []
    sdir = Path(submission_dir)

    if not sdir.exists():
        print(f"WARN: submission directory not found: {submission_dir}")
        return 1

    POC_KEYWORDS = ["mock", "simulated", "fake", "dummy"]
    EVIDENCE_WEAK_KEYWORDS = ["inferred", "would", "likely", "probably", "could potentially"]

    # Glob all relevant files
    py_files = list(sdir.glob("**/*.py"))
    sh_files = list(sdir.glob("**/*.sh"))
    md_files = list(sdir.glob("**/*.md"))

    # --- Check 1: PoC files for mock/fake/simulated/dummy ---
    poc_files = py_files + sh_files
    for fpath in poc_files:
        try:
            content = fpath.read_text(errors="replace")
        except OSError:
            continue
        content_lower = content.lower()
        found = [kw for kw in POC_KEYWORDS if kw in content_lower]
        if found:
            warnings.append(
                f"[MOCK POC] {fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath}"
                f" contains: {', '.join(found)}"
            )

    # --- Check 2: Evidence files for weak-claim language + empty check ---
    for fpath in md_files:
        # Empty check
        try:
            size = fpath.stat().st_size
        except OSError:
            continue
        if size == 0:
            warnings.append(
                f"[EMPTY FILE] {fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath}"
                f" is 0 bytes"
            )
            continue

        # Weak-claim language scan
        try:
            content = fpath.read_text(errors="replace")
        except OSError:
            continue
        content_lower = content.lower()
        found = [kw for kw in EVIDENCE_WEAK_KEYWORDS if kw in content_lower]
        if found:
            warnings.append(
                f"[WEAK CLAIM] {fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath}"
                f" contains: {', '.join(found)}"
            )

    # --- Report ---
    scanned = len(poc_files) + len(md_files)
    if warnings:
        print(f"WARN: kill-gate-2 raised {len(warnings)} flag(s) across {scanned} file(s) in {submission_dir}")
        for w in warnings:
            print(f"  {w}")
        print("  → Advisory only. Confirm with triager-sim before proceeding.")
        return 1

    print(f"PASS: kill-gate-2 — {scanned} file(s) scanned, no mock/fake/weak-claim flags in {submission_dir}")
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


# --- v12 Subcommands ---

def workflow_check(target_dir: str) -> int:
    """Check that workflow_map.md exists and has minimum content.

    v12: Validates workflow mapping completeness before Phase 2 handoff.
    Rationale: Business logic bugs (CWE-840, CWE-362) have the highest
    acceptance rate on Bugcrowd but require workflow understanding that
    endpoint scanning alone misses.

    Returns: 0=PASS, 1=FAIL
    """
    target = Path(target_dir)
    wf_path = target / "workflow_map.md"

    if not wf_path.exists():
        print("[FAIL] workflow_map.md not found in", target_dir)
        print("  → Run threat-modeler or workflow-auditor first")
        return 1

    content = wf_path.read_text(encoding="utf-8")
    lines = content.strip().split("\n")

    if len(lines) < 10:
        print("[FAIL] workflow_map.md too short ({} lines) — needs substantive content".format(len(lines)))
        return 1

    # Check for workflow structure markers
    has_workflow = False
    has_states = False
    has_transitions = False

    for line in lines:
        lower = line.lower()
        if "## workflow" in lower or "### workflow" in lower:
            has_workflow = True
        if "state" in lower and ("→" in line or "->" in line or "transition" in lower):
            has_transitions = True
        if any(marker in lower for marker in ["entry", "terminal", "pending", "active", "completed", "init"]):
            has_states = True

    issues = []
    if not has_workflow:
        issues.append("No workflow sections found (expected ## Workflow headers)")
    if not has_states:
        issues.append("No state definitions found (expected entry/terminal states)")
    if not has_transitions:
        issues.append("No transitions found (expected state → state patterns)")

    if issues:
        print("[FAIL] workflow_map.md structure incomplete:")
        for issue in issues:
            print("  →", issue)
        return 1

    print("[PASS] workflow_map.md exists with valid structure ({} lines)".format(len(lines)))
    return 0


def fresh_surface_check(target_dir: str, repo_path: str = None) -> int:
    """Check if a mature target has fresh attack surface worth investigating.

    v12: Enables Fresh-Surface Exception for targets that would otherwise
    be NO-GO due to maturity. Analyzes git history for recent security-relevant
    changes.
    Rationale: 33 CLOSED/ABANDONED targets included cases where mature targets
    had fresh modules that were prematurely skipped.

    Returns: 0=FRESH_SURFACE_FOUND, 1=NO_FRESH_SURFACE
    """
    import subprocess

    target = Path(target_dir)
    repo = Path(repo_path) if repo_path else target

    # Check if it's a git repo
    git_dir = repo / ".git"
    if not git_dir.exists():
        # Try to find git repo in parent directories
        check = repo
        while check != check.parent:
            if (check / ".git").exists():
                repo = check
                git_dir = check / ".git"
                break
            check = check.parent
        else:
            print("[SKIP] Not a git repository:", str(repo))
            print("  → Cannot check for fresh surface without git history")
            return 1

    fresh_indicators = []

    # Check 1: Recent commits (last 6 months) touching security-relevant files
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "--since=6 months ago", "-n", "50",
             "--", "**/*auth*", "**/*middleware*", "**/*permission*", "**/*security*",
             "**/*payment*", "**/*billing*", "**/*admin*", "**/*bridge*", "**/*migration*"],
            capture_output=True, text=True, cwd=str(repo), timeout=30
        )
        recent_security = [l for l in result.stdout.strip().split("\n") if l.strip()]
        if recent_security:
            fresh_indicators.append("Security-relevant commits in last 6mo: {}".format(len(recent_security)))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check 2: New files added in last 6 months
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "--since=6 months ago", "--diff-filter=A", "--name-only", "-n", "50"],
            capture_output=True, text=True, cwd=str(repo), timeout=30
        )
        new_files = [l for l in result.stdout.strip().split("\n") if l.strip() and not l.startswith(" ")]
        # Filter for code files only
        code_extensions = {".py", ".js", ".ts", ".sol", ".go", ".rs", ".java", ".rb", ".php"}
        new_code_files = [f for f in new_files if any(f.endswith(ext) for ext in code_extensions)]
        if new_code_files:
            fresh_indicators.append("New code files in last 6mo: {}".format(len(new_code_files)))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check 3: Check endpoint_map.md for recently added endpoints
    endpoint_map = target / "endpoint_map.md"
    if endpoint_map.exists():
        content = endpoint_map.read_text(encoding="utf-8")
        new_markers = content.lower().count("new") + content.lower().count("added") + content.lower().count("v2")
        if new_markers > 2:
            fresh_indicators.append("Endpoint map contains 'new'/'added' markers: {}".format(new_markers))

    # Check 4: Look for migration/bridge files
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "--since=6 months ago", "-n", "20",
             "--grep=migration\\|bridge\\|upgrade\\|v2\\|new module\\|scope expansion"],
            capture_output=True, text=True, cwd=str(repo), timeout=30
        )
        migration_commits = [l for l in result.stdout.strip().split("\n") if l.strip()]
        if migration_commits:
            fresh_indicators.append("Migration/bridge/upgrade commits: {}".format(len(migration_commits)))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    if fresh_indicators:
        print("[FOUND] Fresh attack surface detected:")
        for indicator in fresh_indicators:
            print("  ✓", indicator)
        print("  → Fresh-Surface Exception may apply. Scope investigation to new surface only.")
        return 0
    else:
        print("[NONE] No fresh surface detected in last 6 months")
        print("  → Original NO-GO assessment stands")
        return 1


def evidence_tier_check(submission_dir: str, json_output: bool = False) -> int:
    """Classify evidence quality into E1-E4 tiers.

    v12: Separates exploration findings from submission-ready findings.
    E1/E2 are submit-ready. E3/E4 need more investigation.
    Rationale: Binary Tier 1-2/3-4 model from v11 silently killed findings
    worth investigating. Evidence tiers create an explore lane for borderline
    findings. (Evidence: Chain-of-Verification, Dhuliawala et al.)

    Returns: 0=E1/E2 (submit-ready), 1=E3/E4 (explore-only)
    """
    import json as json_module

    sub = Path(submission_dir)

    if not sub.exists():
        print("[FAIL] Submission directory not found:", submission_dir)
        return 1

    # Collect evidence signals
    signals = {
        "has_poc_script": False,
        "has_output_file": False,
        "has_real_target_url": False,
        "has_before_after": False,
        "has_invariant_ref": False,
        "has_config_proof": False,
    }

    # Check for PoC scripts
    poc_patterns = ["poc_*.py", "exploit_*.py", "solve.py", "poc_*.sh", "test_*.py"]
    for pattern in poc_patterns:
        if list(sub.glob(pattern)):
            signals["has_poc_script"] = True
            break

    # Check for output/evidence files
    evidence_patterns = ["output_*.txt", "evidence_*.png", "evidence_*.txt", "response_*.txt",
                         "*_evidence.*", "race_evidence_*"]
    for pattern in evidence_patterns:
        if list(sub.glob(pattern)):
            signals["has_output_file"] = True
            break

    # Check PoC content for real target indicators
    for poc_file in sub.glob("*.py"):
        try:
            content = poc_file.read_text(encoding="utf-8", errors="ignore")
            # Real target = actual URLs, not localhost/mock
            if any(marker in content for marker in ["https://", "http://", "remote(", "requests.post", "requests.get"]):
                if "localhost" not in content and "127.0.0.1" not in content and "mock" not in content.lower():
                    signals["has_real_target_url"] = True
            # Before/after evidence
            if any(marker in content.lower() for marker in ["before", "after", "diff", "delta", "comparison"]):
                signals["has_before_after"] = True
            # Invariant reference
            if any(marker in content.lower() for marker in ["invariant", "inv-", "violation", "assertion"]):
                signals["has_invariant_ref"] = True
        except Exception:
            continue

    # Check for config/reachability proof
    for txt_file in sub.glob("*.md"):
        try:
            content = txt_file.read_text(encoding="utf-8", errors="ignore")
            if any(marker in content.lower() for marker in ["config", "enabled", "reachable", "code path"]):
                signals["has_config_proof"] = True
        except Exception:
            continue

    # Classify tier
    tier = "E4"  # Default: lowest
    reasoning = []

    if signals["has_poc_script"] and signals["has_output_file"] and signals["has_real_target_url"]:
        if signals["has_before_after"]:
            tier = "E1"
            reasoning.append("Full live exploit: PoC + output + real target + before/after evidence")
        else:
            tier = "E2"
            reasoning.append("Live differential proof: PoC + output + real target (no before/after)")
    elif signals["has_poc_script"] and signals["has_invariant_ref"]:
        tier = "E3"
        reasoning.append("Invariant violation proof: PoC references invariant but lacks live target evidence")
    elif signals["has_config_proof"] or signals["has_poc_script"]:
        tier = "E4"
        reasoning.append("Config-backed reachability: code path analysis without runtime evidence")
    else:
        tier = "E4"
        reasoning.append("Insufficient evidence: no PoC or config proof found")

    submit_ready = tier in ("E1", "E2")

    if json_output:
        result = {
            "tier": tier,
            "submit_ready": submit_ready,
            "signals": signals,
            "reasoning": reasoning
        }
        print(json_module.dumps(result, indent=2))
    else:
        status = "PASS" if submit_ready else "FAIL"
        print("[{}] Evidence tier: {} ({})".format(status, tier, "submit-ready" if submit_ready else "explore-only"))
        for r in reasoning:
            print("  →", r)
        if not submit_ready:
            print("  → Log to explore_candidates.md for potential re-investigation")

    return 0 if submit_ready else 1


def duplicate_graph_check(target_dir: str, finding: str, json_output: bool = False) -> int:
    """Check finding against all prior submissions and triage feedback.

    v12: Enhanced duplicate detection using submission history, triage feedback,
    and knowledge base. Goes beyond kill-gate-1's keyword overlap by checking
    CWE patterns and root cause descriptions.
    Rationale: bb_preflight v11's kill-gate-1 used title keyword overlap which
    missed semantically identical findings with different wording, and flagged
    different findings with overlapping keywords.

    Returns: 0=PASS (no duplicates), 1=WARN (possible duplicates found)
    """
    import json as json_module

    target = Path(target_dir)
    finding_lower = finding.lower()

    # Extract keywords from finding description
    stop_words = {"the", "a", "an", "is", "in", "on", "at", "to", "for", "of", "and", "or", "via", "by", "with"}
    finding_words = set(re.findall(r'\b[a-z]{3,}\b', finding_lower)) - stop_words

    # Extract CWE if mentioned
    cwe_match = re.search(r'cwe-(\d+)', finding_lower)
    finding_cwe = cwe_match.group(0) if cwe_match else None

    duplicates = []

    # Source 1: Previous submissions in this target
    submission_dir = target / "submission"
    if submission_dir.exists():
        for report_dir in submission_dir.iterdir():
            if not report_dir.is_dir():
                continue
            # Check bugcrowd_form.md
            form = report_dir / "bugcrowd_form.md"
            if form.exists():
                try:
                    content = form.read_text(encoding="utf-8").lower()
                    content_words = set(re.findall(r'\b[a-z]{3,}\b', content)) - stop_words
                    overlap = finding_words & content_words
                    overlap_ratio = len(overlap) / max(len(finding_words), 1)

                    if overlap_ratio > 0.5:
                        duplicates.append({
                            "source": "submission/" + report_dir.name,
                            "overlap_ratio": round(overlap_ratio, 2),
                            "matching_words": sorted(overlap)[:10]
                        })
                except Exception:
                    continue

            # Check report markdown files
            for md_file in report_dir.glob("*.md"):
                if md_file.name == "bugcrowd_form.md":
                    continue
                try:
                    content = md_file.read_text(encoding="utf-8").lower()
                    # CWE match is stronger signal
                    if finding_cwe and finding_cwe in content:
                        duplicates.append({
                            "source": "submission/" + report_dir.name + "/" + md_file.name,
                            "match_type": "CWE match",
                            "cwe": finding_cwe
                        })
                except Exception:
                    continue

    # Source 2: Triage objections (v12)
    objections_dir = Path(target_dir).parent.parent / "knowledge" / "triage_objections"
    if not objections_dir.exists():
        objections_dir = Path("knowledge/triage_objections")

    if objections_dir.exists():
        for obj_file in objections_dir.rglob("*.md"):
            try:
                content = obj_file.read_text(encoding="utf-8").lower()
                content_words = set(re.findall(r'\b[a-z]{3,}\b', content)) - stop_words
                overlap = finding_words & content_words
                overlap_ratio = len(overlap) / max(len(finding_words), 1)

                if overlap_ratio > 0.4:
                    # Check if this was a DUPLICATE rejection
                    is_dup_rejection = "duplicate" in content or "already reported" in content
                    duplicates.append({
                        "source": "triage_objections/" + obj_file.name,
                        "overlap_ratio": round(overlap_ratio, 2),
                        "was_duplicate_rejection": is_dup_rejection
                    })
            except Exception:
                continue

    # Source 3: Knowledge base bugbounty findings
    kb_dir = Path("knowledge/bugbounty")
    if kb_dir.exists():
        for kb_file in kb_dir.rglob("*.md"):
            try:
                content = kb_file.read_text(encoding="utf-8").lower()
                if finding_cwe and finding_cwe in content:
                    duplicates.append({
                        "source": "knowledge/bugbounty/" + kb_file.name,
                        "match_type": "CWE match in knowledge base",
                        "cwe": finding_cwe
                    })
            except Exception:
                continue

    has_duplicates = len(duplicates) > 0

    if json_output:
        result = {
            "finding": finding,
            "duplicates_found": len(duplicates),
            "verdict": "WARN" if has_duplicates else "PASS",
            "matches": duplicates
        }
        print(json_module.dumps(result, indent=2))
    else:
        if has_duplicates:
            print("[WARN] Possible duplicates found: {}".format(len(duplicates)))
            for dup in duplicates[:5]:  # Show top 5
                print("  →", dup.get("source", "unknown"), "| overlap:", dup.get("overlap_ratio", dup.get("match_type", "?")))
            print("  → Review these before submitting. May need differentiation argument.")
        else:
            print("[PASS] No duplicates found for:", finding[:80])

    return 1 if has_duplicates else 0


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
    elif cmd == "kill-gate-1":
        finding = ""
        args = sys.argv[3:]
        for i, arg in enumerate(args):
            if arg == "--finding" and i + 1 < len(args):
                finding = args[i + 1]
                break
        if not finding:
            print("FAIL: kill-gate-1 requires --finding \"<description>\"")
            sys.exit(1)
        sys.exit(kill_gate_1(target, finding))
    elif cmd == "kill-gate-2":
        sys.exit(kill_gate_2(target))
    elif cmd == "workflow-check":
        if len(sys.argv) < 3:
            print("Usage: bb_preflight.py workflow-check <target_dir>")
            sys.exit(1)
        sys.exit(workflow_check(sys.argv[2]))
    elif cmd == "fresh-surface-check":
        repo_path = None
        if "--repo" in sys.argv:
            repo_idx = sys.argv.index("--repo")
            if repo_idx + 1 < len(sys.argv):
                repo_path = sys.argv[repo_idx + 1]
        sys.exit(fresh_surface_check(sys.argv[2], repo_path))
    elif cmd == "evidence-tier-check":
        json_flag = "--json" in sys.argv
        sys.exit(evidence_tier_check(sys.argv[2], json_flag))
    elif cmd == "duplicate-graph-check":
        if "--finding" not in sys.argv:
            print("Usage: bb_preflight.py duplicate-graph-check <target_dir> --finding \"<desc>\" [--json]")
            sys.exit(1)
        finding_idx = sys.argv.index("--finding")
        finding_desc = sys.argv[finding_idx + 1] if finding_idx + 1 < len(sys.argv) else ""
        json_flag = "--json" in sys.argv
        sys.exit(duplicate_graph_check(sys.argv[2], finding_desc, json_flag))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
