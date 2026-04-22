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
    bb_preflight.py research-check <target_dir>        Validate research artifact/source mix before hunting
    bb_preflight.py hypothesis-check <target_dir>      Validate research_hypotheses.md structure and queue coverage
    bb_preflight.py citation-check <report_dir> [--report <path>]     Validate target-specific citations in reports
    bb_preflight.py feature-check <submission_dir>                    Scan draft for by-design / self-ack-latent language (v13.1)
    bb_preflight.py prior-art-diff-check <submission_dir> [--finding "<desc>"]  Require CVE/duplicate differentiator (v13.1)
    bb_preflight.py impact-demonstration-check <submission_dir>       Require concrete final-state proof line (v13.1)
    bb_preflight.py standalone-harness-check <submission_dir>         Reject library-level PoC where program forbids it (v13.1)

Exit: 0=PASS, 1=FAIL (with specific error message); kill-gate-*/feature-check/impact-demonstration-check/standalone-harness-check: 0=PASS, 1=WARN (advisory)

Created: 2026-02-25 (NAMUHX retrospective — structural fix for rule compliance & coverage gap)
Updated: 2026-04-23 (v13 — research-check, hypothesis-check, citation-check, research templates)
"""

import sys
import os
import re
import json
import shutil
from pathlib import Path
from datetime import datetime

RULES_FILE = "program_rules_summary.md"
ENDPOINT_MAP = "endpoint_map.md"
RESEARCH_REGISTRY = "research_source_registry.json"
RESEARCH_BRIEF = "research_brief.md"
RESEARCH_GAP_MATRIX = "research_gap_matrix.md"
RESEARCH_HYPOTHESES = "research_hypotheses.md"
COVERAGE_THRESHOLD = 80

REQUIRED_RULES_SECTIONS = [
    "Auth Header Format",
    "Mandatory Headers",
    "Known Issues",
    "Exclusion List",
    "Submission Rules",
]

RESEARCH_REQUIRED_AUTHORITY_COUNTS = {
    "official": 4,
    "paper": 2,
    "platform": 2,
    "practitioner": 2,
}
RESEARCH_REQUIRED_CAMPAIGN_SOURCES = 4

TEMPLATE_DIR = Path(__file__).parent / "templates"


def init(target_dir: str) -> int:
    """Create template files in target directory."""
    tdir = Path(target_dir)
    tdir.mkdir(parents=True, exist_ok=True)

    rules_src = TEMPLATE_DIR / RULES_FILE
    map_src = TEMPLATE_DIR / ENDPOINT_MAP
    research_templates = [
        (TEMPLATE_DIR / RESEARCH_BRIEF, RESEARCH_BRIEF),
        (TEMPLATE_DIR / RESEARCH_GAP_MATRIX, RESEARCH_GAP_MATRIX),
        (TEMPLATE_DIR / RESEARCH_HYPOTHESES, RESEARCH_HYPOTHESES),
    ]

    created = []
    for src, name in [(rules_src, RULES_FILE), (map_src, ENDPOINT_MAP), *research_templates]:
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
            elif name == ENDPOINT_MAP:
                dst.write_text(_inline_map_template(target_dir))
            elif name == RESEARCH_BRIEF:
                dst.write_text(_inline_research_brief_template(target_dir))
            elif name == RESEARCH_GAP_MATRIX:
                dst.write_text(_inline_research_gap_template(target_dir))
            else:
                dst.write_text(_inline_research_hypotheses_template(target_dir))
        created.append(name)

    registry_file = tdir / RESEARCH_REGISTRY
    if not registry_file.exists():
        registry_file.write_text("[]\n", encoding="utf-8")
        created.append(RESEARCH_REGISTRY)

    # Cost tracking template (SCONE-bench inspired — $1.22/contract benchmark)
    cost_file = tdir / "cost_tracking.json"
    if not cost_file.exists():
        cost_template = {
            "target": os.path.basename(target_dir.rstrip("/")),
            "created": datetime.now().isoformat(),
            "phases": {
                "phase_0": {"tokens": 0, "duration_sec": 0, "api_cost_est": 0.0},
                "phase_1": {"tokens": 0, "duration_sec": 0, "api_cost_est": 0.0},
                "phase_2": {"tokens": 0, "duration_sec": 0, "api_cost_est": 0.0},
                "phase_3_5": {"tokens": 0, "duration_sec": 0, "api_cost_est": 0.0},
            },
            "agents": {},
            "total_tokens": 0,
            "total_cost_est": 0.0,
            "roi": None,
        }
        cost_file.write_text(json.dumps(cost_template, indent=2))
        created.append("cost_tracking.json")

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




def _inline_research_brief_template(target_dir: str) -> str:
    name = Path(target_dir).name.upper()
    return f"""# Research Brief — {name}

Generated: <DATE>

## Summary
- Campaign sources: 0
- Design references: 0
- Tactic references: 0
- Strongest bug classes: none yet
- Surface signals: none yet

## High-value design references
- <Populate via bb_research_sync global-sync + target-sync>

## High-value tactic references
- <Populate via bb_research_sync global-sync + target-sync>

## Target-specific web signals
- <Program page / docs / release notes / repo / blog / API / GraphQL>
"""


def _inline_research_gap_template(target_dir: str) -> str:
    name = Path(target_dir).name.upper()
    return f"""# Research Gap Matrix — {name}

| Class | Public signal | Target signal | Gap | Candidate angle |
|------|---------------|---------------|-----|-----------------|
| Variant hunting | TBD | TBD | TBD | Mine recent fixes and advisories |
| Auth / access control | TBD | TBD | TBD | Session invalidation, BOLA/BFLA, role drift |
| Workflow / business logic | TBD | TBD | TBD | Skip-step, replay, race, rollback abuse |
| GraphQL | TBD | TBD | TBD | Resolver auth, aliases, batching, mutations |
| PoC / validation | TBD | TBD | TBD | E3/E4 → E1/E2 escalation path |
"""


def _inline_research_hypotheses_template(target_dir: str) -> str:
    name = Path(target_dir).name.upper()
    return f"""# Research Hypotheses — {name}

## Variant hypotheses
- <At least one patch / advisory / release-note derived hypothesis>

## Workflow/Auth/GraphQL hypotheses
- <At least one auth / workflow / GraphQL hypothesis>

## PoC/validation hypotheses
- <At least one E3/E4 → E1/E2 escalation path>

## Why now
- <Fresh code / new release / migration / scope gap / underexplored surface>

## What would kill this hypothesis
- <OOS / feature disabled / no live evidence path / duplicate root cause>
"""
def research_check(target_dir: str) -> int:
    """Validate research artifacts and source mix before hunt phases.

    Requires:
    - research_source_registry.json
    - research_brief.md
    - research_gap_matrix.md
    - research_hypotheses.md
    - source mix across official/paper/platform/practitioner authorities
    - minimum target-specific campaign sources
    """
    target = Path(target_dir)
    registry_path = target / RESEARCH_REGISTRY

    missing_files = [
        name for name in (RESEARCH_REGISTRY, RESEARCH_BRIEF, RESEARCH_GAP_MATRIX, RESEARCH_HYPOTHESES)
        if not (target / name).exists()
    ]
    if missing_files:
        print(f"[FAIL] Missing research artifacts: {', '.join(missing_files)}")
        print("  → Run: python3 tools/bb_research_sync.py target-sync <target_dir> --url <target_url>")
        return 1

    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[FAIL] {RESEARCH_REGISTRY} is not valid JSON: {exc}")
        return 1

    if not isinstance(registry, list) or not registry:
        print(f"[FAIL] {RESEARCH_REGISTRY} is empty")
        print("  → Collect official docs, papers, platform guidance, and practitioner sources first")
        return 1

    authority_counts: dict[str, int] = {}
    campaign_sources = 0
    for entry in registry:
        authority = str(entry.get("authority", "")).strip().lower()
        if authority:
            authority_counts[authority] = authority_counts.get(authority, 0) + 1
        if str(entry.get("applicability", "")).strip().lower() == "campaign":
            campaign_sources += 1

    issues = []
    for authority, required in RESEARCH_REQUIRED_AUTHORITY_COUNTS.items():
        actual = authority_counts.get(authority, 0)
        if actual < required:
            issues.append(f"Authority mix too thin: {authority}={actual} (need {required})")

    if campaign_sources < RESEARCH_REQUIRED_CAMPAIGN_SOURCES:
        issues.append(
            f"Target-specific campaign sources too thin: {campaign_sources} (need {RESEARCH_REQUIRED_CAMPAIGN_SOURCES})"
        )

    for filename in (RESEARCH_BRIEF, RESEARCH_GAP_MATRIX, RESEARCH_HYPOTHESES):
        content = (target / filename).read_text(encoding="utf-8", errors="ignore").strip()
        if len(content) < 100 or "<target_name>" in content.lower() or "<at least one" in content.lower():
            issues.append(f"Artifact {filename} appears unpopulated")

    if issues:
        print("[FAIL] Research gate blocked:")
        for issue in issues:
            print("  →", issue)
        return 1

    print("[PASS] research-check passed")
    for authority, required in RESEARCH_REQUIRED_AUTHORITY_COUNTS.items():
        print(f"  ✓ {authority}: {authority_counts.get(authority, 0)} / {required}")
    print(f"  ✓ campaign sources: {campaign_sources} / {RESEARCH_REQUIRED_CAMPAIGN_SOURCES}")
    return 0


def hypothesis_check(target_dir: str) -> int:
    """Validate research_hypotheses.md queue coverage and rationale sections."""
    target = Path(target_dir)
    hyp_path = target / RESEARCH_HYPOTHESES

    if not hyp_path.exists():
        print(f"[FAIL] {RESEARCH_HYPOTHESES} not found in {target_dir}")
        return 1

    content = hyp_path.read_text(encoding="utf-8", errors="ignore")
    headings = {
        "Variant hypotheses": 1,
        "Workflow/Auth/GraphQL hypotheses": 1,
        "PoC/validation hypotheses": 1,
        "Why now": 1,
        "What would kill this hypothesis": 1,
    }
    issues = []
    for heading, minimum in headings.items():
        pattern = rf"##\s*{re.escape(heading)}\s*\n(.*?)(?=\n##|\Z)"
        match = re.search(pattern, content, re.DOTALL)
        if not match:
            issues.append(f"Missing heading: {heading}")
            continue
        body = match.group(1)
        bullets = [
            line for line in body.splitlines()
            if line.strip().startswith("- ") and "<" not in line and "TBD" not in line.upper()
        ]
        if len(bullets) < minimum:
            issues.append(f"Section '{heading}' has {len(bullets)} populated bullet(s); need {minimum}")

    if issues:
        print("[FAIL] hypothesis-check blocked:")
        for issue in issues:
            print("  →", issue)
        return 1

    print("[PASS] hypothesis-check passed")
    return 0


def citation_check(report_dir: str, report_path: str | None = None) -> int:
    """Validate target-specific citations and research framing in a report."""
    root = Path(report_dir)
    report: Path | None = Path(report_path) if report_path else None

    if report is None:
        candidates = []
        candidates.extend(root.glob("report.md"))
        candidates.extend(root.glob("final_report.md"))
        candidates.extend(root.glob("*_submission.md"))
        candidates.extend(root.glob("**/report.md"))
        report = next((candidate for candidate in candidates if candidate.exists()), None)

    if report is None or not report.exists():
        print("[FAIL] citation-check could not find a report markdown file")
        return 1

    text = report.read_text(encoding="utf-8", errors="ignore")
    lower = text.lower()
    issues = []

    required_headers = [
        "## Program Scope Alignment",
        "## Target-Specific Context",
        "## Prior Art & Differentiation",
    ]
    for header in required_headers:
        if header.lower() not in lower:
            issues.append(f"Missing section header: {header}")

    urls = re.findall(r"https?://[^\s)]+", text)
    if len(urls) < 2:
        issues.append("Need at least two concrete URLs in the report (program/docs/changelog/prior art)")

    if not any(token in lower for token in ("scope", "out of scope", "submission rules", "program rules")):
        issues.append("Program scope / rules context missing")
    if not any(token in lower for token in ("release notes", "changelog", "documentation", "docs", "help center", "engineering blog")):
        issues.append("Target-specific docs or release context missing")
    if not any(token in lower for token in ("prior art", "hacktivity", "differentiation", "duplicate", "public report")):
        issues.append("Prior-art / differentiation context missing")

    registry_path = None
    for candidate in [root / RESEARCH_REGISTRY, root.parent / RESEARCH_REGISTRY, root.parent.parent / RESEARCH_REGISTRY]:
        if candidate.exists():
            registry_path = candidate
            break

    if registry_path is not None:
        try:
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            registry = []
        official_domains = {
            str(entry.get("domain", "")).lower()
            for entry in registry
            if str(entry.get("authority", "")).lower() == "official" and str(entry.get("applicability", "")).lower() == "campaign"
        }
        if official_domains and not any(domain and domain in lower for domain in official_domains):
            issues.append("Report does not cite any official target-specific source from research_source_registry.json")

    if issues:
        print("[FAIL] citation-check blocked:")
        for issue in issues:
            print("  →", issue)
        return 1

    print(f"[PASS] citation-check passed for {report}")
    return 0


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


# --- Rejection-catalog gates (v13.1 — from knowledge/triage_objections/) ---
#
# Each gate encodes one or more failure patterns drawn from
# knowledge/triage_objections/<category>/*.md. Advisory (exit 0/1).

# Phrases that triagers interpret as self-acknowledged latency.
# From: vercel_workflow_devalue_cve_latent.md, namuhx_force_change_password_ato.md
SELF_ACKNOWLEDGED_LATENT_PHRASES = [
    "not exploitable",
    "not currently exploitable",
    "no viable exploitation path",
    "latent bug",
    "latent vulnerability",
    "defense-in-depth only",
    "dependency hygiene",
    "theoretical race",
    "theoretical vulnerability",
    "not directly exploitable",
    "unverified without live testing",
    "could not be confirmed",
    "under the current architecture",
]

# Phrases triagers use when declaring a finding to be intended behavior.
# From: vmware_serial_file_redirection.md, oppo_kms_daemon_race_permission.md,
#       namuhx_force_change_password_ato.md
BY_DESIGN_TRIAGER_PHRASES = [
    "by design",
    "as designed",
    "intended behavior",
    "expected behavior",
    "function as designed",
    "OTP 기반 본인 확인",           # NAMUHX pattern
    "인증 수단으로 설계",           # NAMUHX pattern
    "설계된 구조",                  # NAMUHX pattern
]

# Prompt-injection / trusted-component preconditions that triagers kill.
# From: vercel_ai_sdk_oauth_json_deserialization.md, vercel_agent_skills_unauth_deploy.md
TRUSTED_COMPONENT_ASSUMPTION_PHRASES = [
    "attacker-controlled mcp",
    "hostile mcp server",
    "attacker-controlled oauth",
    "malicious oauth server",
    "attacker-controlled registry",
    "successful prompt injection",
    "after prompt injection",
    "attacker already compromised",
    "assume attacker controls",
]

# Program-wide out-of-scope markers (covers HackenProof + FindtheGap phrasing).
# From: hackenproof_dexx_otp_preemptive.md, namuhx_force_change_password_ato.md
POLICY_EXCLUDED_KEYWORDS = [
    "missing rate limit",
    "missing rate limiting",
    "rate limiting 미적용",
    "account pre-takeover",
    "preemptive account",
    "user enumeration",
    "account enumeration",
    "email enumeration",
    "계정 열거",
    "이메일 열거",
    "sim swap",
    "sim-swap",
    "sim 스왑",
    "toll fraud",
    "brute force 우회",
    "brute-force bypass",
]

# Standalone-harness / library-level PoC markers.
# From: mbedtls_aes_sbox_race.md, tf_m_mailbox_outvec.md
STANDALONE_HARNESS_MARKERS = [
    # Build-time linkage of the target as a library rather than running it
    # through its intended platform entrypoint.
    "libmbedcrypto",
    "libmbedtls",
    "tfm_spe_mailbox.c",
    "-fsanitize=thread",
    "calling individual functions",
    "standalone harness",
    "library-level poc",
    "link against libmbed",
    "ctypes.CDLL",
]


def feature_check(submission_dir: str) -> int:
    """Scan draft report/PoC for self-acknowledged latent + by-design phrases.

    Encodes lessons from:
      feature_defense/vmware_serial_file_redirection.md
      feature_defense/vercel_workflow_devalue_cve_latent.md
      severity_defense/oppo_kms_daemon_race_permission.md

    Advisory: 0=PASS, 1=WARN.
    """
    warnings = []
    sdir = Path(submission_dir)
    if not sdir.exists():
        print(f"WARN: feature-check — submission directory not found: {submission_dir}")
        return 1

    md_files = list(sdir.glob("**/*.md"))
    if not md_files:
        print(f"WARN: feature-check — no .md files under {submission_dir}")
        return 1

    for fpath in md_files:
        try:
            content = fpath.read_text(errors="replace")
        except OSError:
            continue
        content_lower = content.lower()

        # 1. Self-acknowledged latent — instant KILL class at Gate 1 Q5
        latent_hits = [p for p in SELF_ACKNOWLEDGED_LATENT_PHRASES if p in content_lower]
        if latent_hits:
            rel = fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath
            warnings.append(
                f"[LATENT-SELF-ACK] {rel}: contains self-admission of non-exploitability: "
                f"{', '.join(sorted(set(latent_hits)))}"
            )

        # 2. Documented by-design behavior — FEATURE_MISS class
        feature_hits = [p for p in BY_DESIGN_TRIAGER_PHRASES if p in content_lower]
        if feature_hits:
            rel = fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath
            warnings.append(
                f"[FEATURE-DEFENSE-RISK] {rel}: language matches triager by-design rejection patterns: "
                f"{', '.join(sorted(set(feature_hits)))}"
            )

        # 3. Trusted-component / prompt-injection prerequisites
        trust_hits = [p for p in TRUSTED_COMPONENT_ASSUMPTION_PHRASES if p in content_lower]
        if trust_hits:
            rel = fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath
            warnings.append(
                f"[TRUSTED-COMPONENT-PREREQ] {rel}: attack model assumes compromised trusted component or prior prompt injection: "
                f"{', '.join(sorted(set(trust_hits)))}"
            )

        # 4. Policy-excluded scopes (rate-limit / enumeration / SIM-swap / toll-fraud)
        policy_hits = [p for p in POLICY_EXCLUDED_KEYWORDS if p in content_lower]
        if policy_hits:
            rel = fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath
            warnings.append(
                f"[POLICY-EXCLUDED] {rel}: contains language matching platform OOS list: "
                f"{', '.join(sorted(set(policy_hits)))}"
            )

    if warnings:
        print(f"WARN: feature-check raised {len(warnings)} flag(s) in {submission_dir}")
        for w in warnings:
            print(f"  {w}")
        print("  → Rewrite or remove flagged language before Gate 2 / Phase 4.5.")
        return 1

    print(f"PASS: feature-check — {len(md_files)} report file(s) scanned, no by-design or latent self-ack flags.")
    return 0


def prior_art_diff_check(submission_dir: str, finding: str = "") -> int:
    """Require explicit differentiator when the report cites any CVE/prior disclosure.

    Encodes lessons from:
      duplicate_defense/grafana_k8s_snapshot_crossorg.md
      duplicate_defense/vercel_workflow_seeded_prng.md
      duplicate_defense/vercel_ai_sdk_downloadassets_ssrf_cve_48985.md

    PASS requires:
      - If any `CVE-YYYY-NNNN` / `GHSA-` / `#<numeric>` / "duplicate of" reference appears
        in any .md file under <submission_dir>, a "Prior Art Differentiator" section
        (or equivalent heading) must also appear, containing non-trivial content.
      - If finding mentions a well-known duplicate-prone class (seedrandom, prototype
        pollution, alg:none, path traversal, open redirect) the section is mandatory
        regardless of whether a CVE is cited.
    """
    sdir = Path(submission_dir)
    if not sdir.exists():
        print(f"WARN: prior-art-diff-check — directory not found: {submission_dir}")
        return 1

    md_files = list(sdir.glob("**/*.md"))
    if not md_files:
        print(f"WARN: prior-art-diff-check — no .md files under {submission_dir}")
        return 1

    prior_art_refs = []  # (file, ref)
    has_diff_section = False
    diff_section_non_trivial = False

    CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
    GHSA_PATTERN = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)
    DUP_OF_PATTERN = re.compile(r"\b(duplicate\s+of|dup\s*of|variant\s+of)\s*[#]?\d+", re.IGNORECASE)
    DIFF_HEADING = re.compile(
        r"^#+\s*(Prior\s+Art(\s+Differentiator)?|Differentiation|Distinct\s+From\s+(CVE|Report)|Why\s+This\s+Is\s+Distinct)",
        re.IGNORECASE | re.MULTILINE,
    )

    for fpath in md_files:
        try:
            content = fpath.read_text(errors="replace")
        except OSError:
            continue
        refs = set(CVE_PATTERN.findall(content)) | set(GHSA_PATTERN.findall(content)) | set(DUP_OF_PATTERN.findall(content))
        for r in refs:
            prior_art_refs.append((str(fpath), r))

        m = DIFF_HEADING.search(content)
        if m:
            has_diff_section = True
            # Require the section to carry more than a heading
            tail = content[m.end():m.end() + 2000]
            if len(tail.strip().splitlines()) >= 3:
                diff_section_non_trivial = True

    # Finding-class heuristic (fires even without an explicit CVE cite)
    high_risk_classes = [
        "seedrandom", "seeded prng", "predictable prng", "predictable random",
        "alg=none", "alg:none", "prototype pollution",
        "path traversal", "open redirect", "directory listing",
        "clickjacking", "password-in-url",
    ]
    finding_l = finding.lower()
    matched_class = [c for c in high_risk_classes if c in finding_l]

    warnings = []
    if prior_art_refs:
        refs_str = ", ".join(sorted({r for _, r in prior_art_refs})[:10])
        if not has_diff_section:
            warnings.append(
                f"[PRIOR-ART NO-DIFF] report cites {len(prior_art_refs)} prior-art reference(s) "
                f"({refs_str}) but has no 'Prior Art Differentiator' / 'Why This Is Distinct' section."
            )
        elif not diff_section_non_trivial:
            warnings.append(
                "[PRIOR-ART WEAK-DIFF] differentiator section is present but contains <3 lines of content."
            )

    if matched_class and not has_diff_section:
        warnings.append(
            f"[HIGH-DUP-RISK-CLASS] finding class is in the well-known duplicate-prone list ({', '.join(matched_class)}) "
            f"— a 'Prior Art Differentiator' section is mandatory even without an explicit CVE citation."
        )

    # Known-CVE table (produced by patch-hunter) must exist
    known_cve_table = sdir.parent / "known_cve_table.json" if sdir.name.startswith("submission") else sdir / "known_cve_table.json"
    if not known_cve_table.exists():
        # fall back: search upward two levels
        for parent in list(sdir.parents)[:3]:
            candidate = parent / "known_cve_table.json"
            if candidate.exists():
                known_cve_table = candidate
                break
    if not known_cve_table.exists():
        warnings.append(
            "[NO CVE-TABLE] patch-hunter did not produce known_cve_table.json for this target — "
            "Gate 1 Q3 cannot verify duplicate risk. Run patch-hunter before Gate 2."
        )

    if warnings:
        print(f"WARN: prior-art-diff-check raised {len(warnings)} flag(s)")
        for w in warnings:
            print(f"  {w}")
        print("  → Add explicit differentiator citing every prior CVE/report, or move finding to explore_candidates.md.")
        return 1

    print(
        f"PASS: prior-art-diff-check — "
        f"{len(prior_art_refs)} prior-art ref(s) found and each backed by a non-trivial differentiator section."
    )
    return 0


def impact_demonstration_check(submission_dir: str) -> int:
    """Require PoC output to contain a concrete final-state proof line.

    Encodes lessons from:
      prereq_vs_impact_defense/vercel_agent_skills_unauth_deploy.md
      prereq_vs_impact_defense/intel_backupbiosupdate_smm_oob.md
      scope_defense/namuhx_force_change_password_ato.md
      severity_defense/namuhx_idor_readonly_low_sensitivity.md

    PASS requires:
      - At least one evidence file (*.txt / *.log / *.md / *.json under evidence/ or poc/)
        contains a line matching a 'final-state proof' pattern, e.g. 'FLAG_FOUND',
        'E2E_CONFIRMED', 'VULN CONFIRMED', 'deleted', 'authenticated as victim',
        or equivalent concrete-past-tense success markers.
      - No orphan 'if ... then ...' conditional claim without a matching proven line.
    """
    sdir = Path(submission_dir)
    if not sdir.exists():
        print(f"WARN: impact-demonstration-check — directory not found: {submission_dir}")
        return 1

    PROOF_PATTERNS = [
        r"\bFLAG_FOUND\b",
        r"\bE2E[_ -]?CONFIRMED\b",
        r"\bVULN[_ -]?CONFIRMED\b",
        r"\bPOC[_ -]?SUCCESS\b",
        r"\bauthenticated as victim\b",
        r"\blogged in as \w+@",
        r"\bdeleted\b.*\b(snapshot|resource|record|object)\b",
        r"\bextracted secret\b",
        r"\bexfiltrated\b",
        r"\baccount takeover (confirmed|succeeded)\b",
        r"\b200 OK\b.*\b(cross-org|crossorg|other user)\b",
        r"\bobserved on live target\b",
        r"\bshell on .+ as root\b",
        r"\buid=0\b",
    ]
    proof_re = re.compile("|".join(PROOF_PATTERNS), re.IGNORECASE)

    CONDITIONAL_PATTERNS = re.compile(
        r"\b(if\s+[^.\n]{3,80}\s+then\b|would\s+(allow|enable|permit)|could\s+potentially|might\s+allow|assuming\s+\w+)",
        re.IGNORECASE,
    )

    proof_hits = []
    conditional_hits = []

    for ext in ("txt", "log", "md", "json", "out"):
        for fpath in sdir.glob(f"**/*.{ext}"):
            try:
                content = fpath.read_text(errors="replace")
            except OSError:
                continue
            rel = fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath
            for m in proof_re.finditer(content):
                proof_hits.append((str(rel), m.group(0)))
            for m in CONDITIONAL_PATTERNS.finditer(content):
                conditional_hits.append((str(rel), m.group(0)))

    warnings = []
    if not proof_hits:
        warnings.append(
            "[NO FINAL-STATE PROOF] no artifact under submission contains a concrete past-tense success line "
            "(FLAG_FOUND / E2E_CONFIRMED / 'authenticated as victim' / 'deleted … cross-org' / 'uid=0' etc.). "
            "Triagers for NAMUHX / Vercel / FindtheGap close any chain that stops before the final impact."
        )

    # Too many conditional claims relative to proof lines — symptom of the agent-skills rejection.
    if len(conditional_hits) > max(3, 2 * len(proof_hits)):
        example = "; ".join(f"{f}: '{m}'" for f, m in conditional_hits[:3])
        warnings.append(
            f"[CONDITIONAL-HEAVY] {len(conditional_hits)} 'if/would/might' claims vs {len(proof_hits)} proof lines. "
            f"Rewrite impact section in past tense with captured evidence. Example offenders: {example}"
        )

    if warnings:
        print(f"WARN: impact-demonstration-check raised {len(warnings)} flag(s)")
        for w in warnings:
            print(f"  {w}")
        print("  → Capture a concrete past-tense 'victim-state-changed' log line before Phase 3.")
        return 1

    print(
        f"PASS: impact-demonstration-check — {len(proof_hits)} final-state proof line(s) found, "
        f"{len(conditional_hits)} conditional claim(s) within acceptable ratio."
    )
    return 0


def standalone_harness_check(submission_dir: str) -> int:
    """Reject library-level PoC for programs requiring legitimate-use exploitation.

    Encodes lessons from:
      scope_defense/mbedtls_aes_sbox_race.md
      scope_defense/tf_m_mailbox_outvec.md

    PASS requires:
      - No PoC script/content matches STANDALONE_HARNESS_MARKERS, OR
      - If a match exists, program_rules_summary.md must explicitly allow library-level PoCs
        (contains a line like 'library-level PoC: allowed' or 'standalone harness OK').
    """
    sdir = Path(submission_dir)
    if not sdir.exists():
        print(f"WARN: standalone-harness-check — directory not found: {submission_dir}")
        return 1

    hits = []
    for ext in ("py", "sh", "c", "h", "cpp", "md", "txt", "log"):
        for fpath in sdir.glob(f"**/*.{ext}"):
            try:
                content = fpath.read_text(errors="replace")
            except OSError:
                continue
            lower = content.lower()
            for marker in STANDALONE_HARNESS_MARKERS:
                if marker.lower() in lower:
                    rel = fpath.relative_to(sdir) if fpath.is_relative_to(sdir) else fpath
                    hits.append((str(rel), marker))

    if not hits:
        print("PASS: standalone-harness-check — no library-level PoC markers detected.")
        return 0

    # Check for explicit program allowance
    allow = False
    # Look for program_rules_summary.md up to 3 parents up
    for parent in [sdir] + list(sdir.parents)[:3]:
        rules_path = parent / RULES_FILE
        if rules_path.exists():
            try:
                rules = rules_path.read_text(errors="replace").lower()
            except OSError:
                rules = ""
            if any(tok in rules for tok in ("library-level poc: allowed", "standalone harness ok",
                                            "library-level pocs allowed", "standalone poc allowed")):
                allow = True
            break

    if allow:
        print(
            f"PASS: standalone-harness-check — {len(hits)} marker(s) matched but program rules "
            "explicitly permit library-level PoCs."
        )
        return 0

    print(f"WARN: standalone-harness-check — {len(hits)} library-level PoC marker(s) detected:")
    # Limit to first 6 to keep output compact
    for rel, marker in hits[:6]:
        print(f"  [STANDALONE-HARNESS] {rel}: '{marker}'")
    if len(hits) > 6:
        print(f"  … {len(hits) - 6} more hits.")
    print("  → Trusted-Firmware / Intigriti class programs reject library-level PoCs.")
    print("    Rewrite PoC to exercise the target through its legitimate platform path,")
    print("    or explicitly mark program_rules_summary.md with 'library-level PoC: allowed'.")
    return 1


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
    elif cmd == "research-check":
        sys.exit(research_check(sys.argv[2]))
    elif cmd == "hypothesis-check":
        sys.exit(hypothesis_check(sys.argv[2]))
    elif cmd == "citation-check":
        report_path = None
        if "--report" in sys.argv:
            report_idx = sys.argv.index("--report")
            if report_idx + 1 < len(sys.argv):
                report_path = sys.argv[report_idx + 1]
        sys.exit(citation_check(sys.argv[2], report_path))
    elif cmd == "feature-check":
        sys.exit(feature_check(sys.argv[2]))
    elif cmd == "prior-art-diff-check":
        finding_desc = ""
        if "--finding" in sys.argv:
            finding_idx = sys.argv.index("--finding")
            if finding_idx + 1 < len(sys.argv):
                finding_desc = sys.argv[finding_idx + 1]
        sys.exit(prior_art_diff_check(sys.argv[2], finding_desc))
    elif cmd == "impact-demonstration-check":
        sys.exit(impact_demonstration_check(sys.argv[2]))
    elif cmd == "standalone-harness-check":
        sys.exit(standalone_harness_check(sys.argv[2]))
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
