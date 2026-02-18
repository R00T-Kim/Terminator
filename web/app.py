"""
Terminator Dashboard - FastAPI Backend
Provides REST API + WebSocket for live session monitoring.
"""

import asyncio
import json
import os
import sys
import glob
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(title="Terminator Dashboard", version="1.0.0")

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
TARGETS_DIR = Path(__file__).resolve().parent.parent / "targets"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _parse_session(session_dir: Path) -> dict:
    """Build a session summary dict from a session directory."""
    summary_file = session_dir / "summary.json"
    if summary_file.exists():
        try:
            with open(summary_file) as f:
                data = json.load(f)
            data["session_id"] = session_dir.name
            return data
        except Exception:
            pass

    # Fallback: derive info from directory contents
    files = [f.name for f in session_dir.iterdir()] if session_dir.is_dir() else []
    status = "completed" if "flags.txt" in files else "unknown"
    flags = []
    if "flags.txt" in files:
        try:
            flags = (session_dir / "flags.txt").read_text().strip().splitlines()
        except Exception:
            pass

    return {
        "session_id": session_dir.name,
        "status": status,
        "files": files,
        "flags": flags,
        "findings_count": 0,
        "mode": "unknown",
        "target": None,
        "duration_seconds": None,
        "timestamp": session_dir.name,  # timestamp IS the dir name
    }


def _cvss_to_severity(score: float) -> str:
    """Convert a CVSS numeric score to a severity label."""
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score >= 0.1:
        return "low"
    return "info"


def _extract_cvss_from_text(text: str) -> Optional[float]:
    """Extract CVSS score from markdown text."""
    import re
    # Match patterns like "CVSS 3.1 **8.6" or "CVSS: 7.5" or "CVSS Score: 9.1"
    patterns = [
        r'CVSS[\s:]+(?:3\.[01]\s+)?\*{0,2}(\d+\.?\d*)',
        r'CVSS[\s_]?(?:Score|Base)?[\s:]+\*{0,2}(\d+\.?\d*)',
        r'cvss_score["\s:]+(\d+\.?\d*)',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
    return None


def _aggregate_findings() -> dict:
    """Walk all sessions and targets to aggregate vulnerability findings."""
    import re
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings = []

    # ── Part 1: Scan reports/ directory (existing behavior) ──
    if REPORTS_DIR.exists():
        for session_dir in sorted(REPORTS_DIR.glob("20*"), reverse=True):
            summary_file = session_dir / "summary.json"
            if summary_file.exists():
                try:
                    with open(summary_file) as f:
                        data = json.load(f)
                    for finding in data.get("findings", []):
                        sev = finding.get("severity", "info").lower()
                        if sev in counts:
                            counts[sev] += 1
                        findings.append({
                            "session_id": session_dir.name,
                            "title": finding.get("title", "Unknown"),
                            "severity": sev,
                            "target": data.get("target"),
                            "source": "reports",
                        })
                except Exception:
                    pass

            flags_file = session_dir / "flags.txt"
            if flags_file.exists():
                try:
                    flag_lines = flags_file.read_text().strip().splitlines()
                    for line in flag_lines:
                        if line.strip():
                            findings.append({
                                "session_id": session_dir.name,
                                "title": f"FLAG: {line.strip()}",
                                "severity": "critical",
                                "target": session_dir.name,
                                "source": "reports",
                            })
                            counts["critical"] += 1
                except Exception:
                    pass

    # ── Part 2: Scan targets/ directory for findings ──
    if TARGETS_DIR.exists():
        for target_dir in sorted(TARGETS_DIR.iterdir()):
            if not target_dir.is_dir():
                continue
            target_name = target_dir.name

            # Scan report_*.md and *_submission.md files
            report_patterns = ["report_*.md", "*_submission.md"]
            for pattern in report_patterns:
                for md_file in target_dir.glob(pattern):
                    try:
                        text = md_file.read_text(errors="replace")[:50000]
                        cvss = _extract_cvss_from_text(text)
                        sev = _cvss_to_severity(cvss) if cvss else "medium"

                        # Extract title from first # header or filename
                        title_match = re.search(r'^#\s+(.+)', text, re.MULTILINE)
                        title = title_match.group(1).strip() if title_match else md_file.stem.replace("_", " ").title()

                        if sev in counts:
                            counts[sev] += 1
                        findings.append({
                            "id": f"{target_name}/{md_file.name}",
                            "title": title[:120],
                            "severity": sev,
                            "target": target_name,
                            "cvss_score": cvss,
                            "file": str(md_file.relative_to(TARGETS_DIR)),
                            "source": "targets",
                        })
                    except Exception:
                        pass

            # Also scan immunefi_reports/ subdirectory
            immunefi_dir = target_dir / "immunefi_reports"
            if immunefi_dir.is_dir():
                for md_file in immunefi_dir.glob("*.md"):
                    try:
                        text = md_file.read_text(errors="replace")[:50000]
                        cvss = _extract_cvss_from_text(text)
                        sev = _cvss_to_severity(cvss) if cvss else "medium"

                        title_match = re.search(r'^#\s+(.+)', text, re.MULTILINE)
                        title = title_match.group(1).strip() if title_match else md_file.stem.replace("_", " ").title()

                        if sev in counts:
                            counts[sev] += 1
                        findings.append({
                            "id": f"{target_name}/immunefi_reports/{md_file.name}",
                            "title": title[:120],
                            "severity": sev,
                            "target": target_name,
                            "cvss_score": cvss,
                            "file": str(md_file.relative_to(TARGETS_DIR)),
                            "source": "targets",
                        })
                    except Exception:
                        pass

            # Parse vulnerability_candidates.md — each ## header is a finding
            vuln_file = target_dir / "vulnerability_candidates.md"
            if vuln_file.exists():
                try:
                    text = vuln_file.read_text(errors="replace")[:100000]
                    # Split by ## headers to extract individual findings
                    sections = re.split(r'^##\s+', text, flags=re.MULTILINE)
                    for section in sections[1:]:  # skip content before first ##
                        lines = section.strip().split("\n")
                        title = lines[0].strip()[:120] if lines else "Unknown Finding"
                        section_text = "\n".join(lines)
                        cvss = _extract_cvss_from_text(section_text)
                        sev = _cvss_to_severity(cvss) if cvss else "info"

                        if sev in counts:
                            counts[sev] += 1
                        findings.append({
                            "id": f"{target_name}/vuln_candidates/{title[:40]}",
                            "title": title,
                            "severity": sev,
                            "target": target_name,
                            "cvss_score": cvss,
                            "file": f"{target_name}/vulnerability_candidates.md",
                            "source": "targets",
                        })
                except Exception:
                    pass

    return {"counts": counts, "findings": findings[:200]}


def _get_health() -> dict:
    """Check availability of local security tools."""
    import shutil

    tools = {
        "Radare2": "r2",
        "GDB": "gdb",
        "Nuclei": "nuclei",
        "SearchSploit": "searchsploit",
        "Semgrep": "semgrep",
        "CodeQL": "codeql",
        "Slither": "slither",
        "Foundry": "forge",
        "Nmap": "nmap",
        "SQLMap": "sqlmap",
        "FFUF": "ffuf",
        "GitHub CLI": "gh",
    }

    result = {}
    for name, binary in tools.items():
        result[name] = "up" if shutil.which(binary) else "down"
    # Dashboard and WebSocket are always up when this code runs
    result["Dashboard"] = "up"
    result["WebSocket"] = "up"
    return result


# ──────────────────────────────────────────────
# REST Endpoints
# ──────────────────────────────────────────────

@app.get("/api/sessions")
async def list_sessions():
    """List all session reports with summary data."""
    if not REPORTS_DIR.exists():
        return {"sessions": []}

    sessions = []
    for session_dir in sorted(REPORTS_DIR.glob("20*"), reverse=True)[:30]:
        sessions.append(_parse_session(session_dir))
    return {"sessions": sessions}


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    """Get detailed session info."""
    session_dir = REPORTS_DIR / session_id
    if not session_dir.exists():
        raise HTTPException(status_code=404, detail="Session not found")

    data = _parse_session(session_dir)

    # Include writeup content if exists
    for candidate in ["writeup.md", "report.md"]:
        wp = session_dir / candidate
        if wp.exists():
            try:
                data["writeup"] = wp.read_text()[:8000]  # cap at 8KB
            except Exception:
                pass
            break

    return data


@app.get("/api/sessions/{session_id}/log")
async def get_session_log(session_id: str, tail: int = 100):
    """Get last N lines of session log."""
    session_dir = REPORTS_DIR / session_id
    if not session_dir.exists():
        raise HTTPException(status_code=404, detail="Session not found")

    log_file = session_dir / "session.log"
    if not log_file.exists():
        # Try other log files
        for candidate in session_dir.glob("*.log"):
            log_file = candidate
            break
        else:
            return {"lines": [], "log_file": None}

    try:
        lines = log_file.read_text(errors="replace").splitlines()
        return {
            "lines": lines[-tail:],
            "log_file": log_file.name,
            "total_lines": len(lines),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/findings")
async def list_findings():
    """Aggregate findings across all sessions."""
    return _aggregate_findings()


@app.get("/api/stats")
async def get_stats():
    """Dashboard statistics."""
    all_sessions = list(REPORTS_DIR.glob("20*")) if REPORTS_DIR.exists() else []
    total_sessions = len(all_sessions)

    flags = 0
    for sd in all_sessions:
        ff = sd / "flags.txt"
        if ff.exists():
            try:
                flags += len([l for l in ff.read_text().splitlines() if l.strip()])
            except Exception:
                pass

    agg = _aggregate_findings()

    # Count missions from targets/
    total_missions = 0
    active_missions = 0
    if TARGETS_DIR.exists():
        for entry in TARGETS_DIR.iterdir():
            if entry.is_dir():
                total_missions += 1
                assess = entry / "target_assessment.md"
                if assess.exists():
                    try:
                        text = assess.read_text(errors="replace")
                        status = _extract_status(text)
                        if status in ("GO", "CONDITIONAL_GO"):
                            active_missions += 1
                    except Exception:
                        pass

    health = _get_health()
    tools_available = sum(1 for v in health.values() if v == "up")

    return {
        "total_sessions": total_sessions,
        "flags_captured": flags,
        "findings": agg["counts"],
        "total_findings": len(agg["findings"]),
        "total_missions": total_missions,
        "active_missions": active_missions,
        "tools_available": tools_available,
        "health": health,
        "reports_dir": str(REPORTS_DIR),
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
    }


@app.get("/api/tools")
async def list_tools():
    """Check which security tools are available."""
    import shutil
    tools = {
        "radare2": shutil.which("r2"),
        "gdb": shutil.which("gdb"),
        "nuclei": shutil.which("nuclei"),
        "searchsploit": shutil.which("searchsploit"),
        "semgrep": shutil.which("semgrep"),
        "codeql": shutil.which("codeql"),
        "slither": shutil.which("slither"),
        "foundry": shutil.which("forge"),
        "nmap": shutil.which("nmap"),
        "sqlmap": shutil.which("sqlmap"),
        "ffuf": shutil.which("ffuf"),
        "gh": shutil.which("gh"),
        "mythril": shutil.which("myth"),
        "trufflehog": shutil.which("trufflehog"),
        "dalfox": shutil.which("dalfox"),
        "httpx": shutil.which("httpx"),
    }
    return {
        "tools": {k: {"available": v is not None, "path": v} for k, v in tools.items()},
        "total_available": sum(1 for v in tools.values() if v),
        "total": len(tools),
    }


# ──────────────────────────────────────────────
# Bug Bounty Mission Helpers
# ──────────────────────────────────────────────

PIPELINE_PHASES = [
    ("Phase 0: Target Assessment", ["target_assessment.md"]),
    ("Phase 1: Reconnaissance",    ["recon_notes.md", "recon_report.json", "recon_report.md"]),
    ("Phase 1: Vuln Candidates",   ["vulnerability_candidates.md"]),
    ("Phase 2: Exploit Results",   ["exploit_results.md", "dynamic_poc_evidence.md"]),
    ("Phase 3: Reports",           ["immunefi_reports", "report_A_*.md", "report_B_*.md", "*_submission.md", "h1_reports"]),
    ("Phase 4: Critic Review",     ["critic_review.md", "critic_review_v2.md"]),
    ("Phase 4: Architect Review",  ["architect_review.md"]),
    ("Phase 5: Final Report",      ["final_report.md", "*_bugcrowd_submission.md"]),
]


def _extract_score(text: str) -> Optional[int]:
    """Extract a score like 8/10 or Score: 8 from assessment text."""
    import re
    m = re.search(r'\b(\d{1,2})\s*/\s*10\b', text)
    if m:
        return int(m.group(1))
    m = re.search(r'[Ss]core[:\s]+(\d{1,2})', text)
    if m:
        return int(m.group(1))
    return None


def _extract_status(text: str) -> str:
    """Extract GO/NO-GO/CONDITIONAL GO from target assessment text."""
    import re
    m = re.search(r'\b(CONDITIONAL\s+GO|NO[- ]?GO|GO)\b', text, re.IGNORECASE)
    if m:
        val = m.group(1).upper().replace(' ', '_').replace('-', '_')
        return val
    return "UNKNOWN"


def _count_findings(vuln_file: Path) -> int:
    """Count findings in vulnerability_candidates.md (count ## headers)."""
    if not vuln_file.exists():
        return 0
    import re
    text = vuln_file.read_text(errors="replace")
    return len(re.findall(r'^##\s+', text, re.MULTILINE))


def _get_pipeline_phase(mission_dir: Path) -> dict:
    """Determine current pipeline phase by checking which artifacts exist."""
    import fnmatch
    phases = []
    for label, patterns in PIPELINE_PHASES:
        # patterns is a list of file/dir names, possibly with wildcards
        complete = False
        matched_artifact = None
        for pattern in patterns:
            if "*" in pattern or "?" in pattern:
                # Glob pattern — check if any file matches
                matches = list(mission_dir.glob(pattern))
                if matches:
                    complete = True
                    matched_artifact = matches[0].name
                    break
            else:
                # Exact path — check existence
                if (mission_dir / pattern).exists():
                    complete = True
                    matched_artifact = pattern
                    break
        artifact_display = matched_artifact or patterns[0]
        phases.append({"label": label, "artifact": artifact_display, "complete": complete})

    completed = [p for p in phases if p["complete"]]
    current_idx = len(completed)
    current = phases[current_idx]["label"] if current_idx < len(phases) else "Complete"

    return {
        "phases": phases,
        "current_phase": current,
        "phases_complete": len(completed),
        "phases_total": len(phases),
    }


def _parse_mission(mission_dir: Path) -> dict:
    """Build a mission summary dict from a targets/ subdirectory."""
    name = mission_dir.name

    assess_file = mission_dir / "target_assessment.md"
    score = None
    status = "UNKNOWN"
    if assess_file.exists():
        try:
            text = assess_file.read_text(errors="replace")
            score = _extract_score(text)
            status = _extract_status(text)
        except Exception:
            pass

    vuln_file = mission_dir / "vulnerability_candidates.md"
    findings_count = _count_findings(vuln_file)

    pipeline = _get_pipeline_phase(mission_dir)

    return {
        "name": name,
        "score": score,
        "status": status,
        "findings_count": findings_count,
        "current_phase": pipeline["current_phase"],
        "phases_complete": pipeline["phases_complete"],
        "phases_total": pipeline["phases_total"],
        "has_assessment": assess_file.exists(),
        "has_exploits": (mission_dir / "exploit_results.md").exists() or (mission_dir / "dynamic_poc_evidence.md").exists(),
        "has_reports": (mission_dir / "immunefi_reports").is_dir() or (mission_dir / "h1_reports").is_dir() or bool(list(mission_dir.glob("report_*.md"))) or bool(list(mission_dir.glob("*_submission.md"))),
    }


# ──────────────────────────────────────────────
# Bug Bounty REST Endpoints
# ──────────────────────────────────────────────

@app.get("/api/bounty/missions")
async def list_missions():
    """List all bounty missions from targets/ directory."""
    if not TARGETS_DIR.exists():
        return {"missions": []}

    missions = []
    for entry in sorted(TARGETS_DIR.iterdir()):
        if not entry.is_dir():
            continue
        # Include any directory that has at least one markdown file
        has_content = any(entry.glob("*.md")) or any(entry.glob("*.json"))
        if not has_content:
            continue
        try:
            missions.append(_parse_mission(entry))
        except Exception:
            pass

    return {"missions": missions}


@app.get("/api/bounty/missions/{name}")
async def get_mission(name: str):
    """Detailed mission view including findings and reports."""
    # Sanitize name to prevent path traversal
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="Invalid mission name")
    mission_dir = TARGETS_DIR / name
    if not mission_dir.is_dir():
        raise HTTPException(status_code=404, detail="Mission not found")

    data = _parse_mission(mission_dir)

    # Assessment
    assess_file = mission_dir / "target_assessment.md"
    if assess_file.exists():
        try:
            data["assessment"] = assess_file.read_text(errors="replace")[:50000]
        except Exception:
            pass

    # Vulnerability candidates
    vuln_file = mission_dir / "vulnerability_candidates.md"
    if vuln_file.exists():
        try:
            data["vulnerability_candidates"] = vuln_file.read_text(errors="replace")[:50000]
        except Exception:
            pass

    # Exploit results
    exploit_file = mission_dir / "exploit_results.md"
    if exploit_file.exists():
        try:
            data["exploit_results"] = exploit_file.read_text(errors="replace")[:50000]
        except Exception:
            pass

    # Report drafts from immunefi_reports/
    reports_dir = mission_dir / "immunefi_reports"
    report_drafts = []
    if reports_dir.is_dir():
        for md in sorted(reports_dir.glob("*.md")):
            try:
                report_drafts.append({
                    "filename": md.name,
                    "content": md.read_text(errors="replace")[:50000],
                })
            except Exception:
                pass
    data["report_drafts"] = report_drafts

    # Review files
    for review_key, review_file in [("critic_review", "critic_review.md"), ("architect_review", "architect_review.md")]:
        rpath = mission_dir / review_file
        if rpath.exists():
            try:
                data[review_key] = rpath.read_text(errors="replace")[:50000]
            except Exception:
                pass

    return data


@app.get("/api/bounty/missions/{name}/pipeline")
async def get_mission_pipeline(name: str):
    """Pipeline phase status for a mission."""
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="Invalid mission name")
    mission_dir = TARGETS_DIR / name
    if not mission_dir.is_dir():
        raise HTTPException(status_code=404, detail="Mission not found")

    return _get_pipeline_phase(mission_dir)


# ──────────────────────────────────────────────
# Infrastructure Helpers
# ──────────────────────────────────────────────

def _get_db_conn():
    import psycopg2
    svc = os.environ.get("SERVICE_DISCOVERY", "docker")
    host = "db" if svc == "docker" else "localhost"
    port = 5432 if svc == "docker" else 5433
    return psycopg2.connect(host=host, port=port, dbname="shadowhunter", user="postgres", password="shadowhunter")


def _get_graph():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.attack_graph.graph import AttackGraph
    return AttackGraph()


# ──────────────────────────────────────────────
# Agent Runs Endpoints
# ──────────────────────────────────────────────

def _get_agent_runs_from_filesystem(limit: int = 50) -> list:
    """Fallback: scan ~/.claude/teams/ for agent team info."""
    runs = []
    teams_dir = Path.home() / ".claude" / "teams"
    if not teams_dir.exists():
        return runs

    for team_dir in sorted(teams_dir.iterdir(), reverse=True):
        if not team_dir.is_dir():
            continue
        config_file = team_dir / "config.json"
        if config_file.exists():
            try:
                with open(config_file) as f:
                    config = json.load(f)
                team_name = config.get("name", team_dir.name)
                members = config.get("members", [])
                mtime = datetime.fromtimestamp(config_file.stat().st_mtime, tz=timezone.utc)
                for member in members:
                    runs.append({
                        "id": member.get("agentId", ""),
                        "session_id": team_name,
                        "agent_role": member.get("name", member.get("agentType", "unknown")),
                        "target": team_name.replace("mission-", ""),
                        "model": member.get("agentType", "unknown"),
                        "status": "COMPLETED",
                        "duration_seconds": None,
                        "tokens_used": None,
                        "output_summary": None,
                        "artifacts": None,
                        "created_at": mtime.isoformat(),
                        "completed_at": mtime.isoformat(),
                    })
            except Exception:
                pass
        if len(runs) >= limit:
            break
    return runs[:limit]


@app.get("/api/agent-runs")
async def list_agent_runs(session: str = None, target: str = None, limit: int = 50):
    """List agent execution history from agent_runs table, with filesystem fallback."""
    try:
        conn = _get_db_conn()
        cur = conn.cursor()
        conditions = []
        params = []
        if session:
            conditions.append("session_id = %s")
            params.append(session)
        if target:
            conditions.append("target = %s")
            params.append(target)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        cur.execute(
            f"""SELECT id, session_id, agent_role, target, model, status,
                       duration_seconds, tokens_used, output_summary, artifacts,
                       created_at, completed_at
                FROM agent_runs {where}
                ORDER BY created_at DESC LIMIT %s""",
            params,
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        for r in rows:
            for k in ("created_at", "completed_at"):
                if r.get(k):
                    r[k] = r[k].isoformat()
        cur.close()
        conn.close()
        return {"runs": rows}
    except Exception:
        # Filesystem fallback
        runs = _get_agent_runs_from_filesystem(limit)
        return {"runs": runs, "source": "filesystem"}


@app.get("/api/agent-runs/active")
async def active_agent_runs():
    """List currently running agents (status=RUNNING)."""
    try:
        conn = _get_db_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, session_id, agent_role, target, model, status,
                      duration_seconds, tokens_used, output_summary, artifacts,
                      created_at, completed_at
               FROM agent_runs WHERE status = 'RUNNING'
               ORDER BY created_at DESC"""
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        for r in rows:
            for k in ("created_at", "completed_at"):
                if r.get(k):
                    r[k] = r[k].isoformat()
        cur.close()
        conn.close()
        return {"active": rows}
    except Exception:
        return {"active": [], "source": "filesystem"}


# ──────────────────────────────────────────────
# Findings CRUD Endpoints
# ──────────────────────────────────────────────

@app.get("/api/db/findings")
async def list_db_findings(target: str = None, status: str = None, limit: int = 50):
    """List findings from DB, with filesystem fallback."""
    try:
        conn = _get_db_conn()
        cur = conn.cursor()
        conditions = []
        params = []
        if target:
            conditions.append("target = %s")
            params.append(target)
        if status:
            conditions.append("status = %s")
            params.append(status)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        cur.execute(
            f"""SELECT id, target, title, severity, status, poc_tier, cvss_score,
                       description, poc_summary, platform, submitted_at,
                       triager_outcome, bounty_amount, created_at, updated_at
                FROM findings {where}
                ORDER BY created_at DESC LIMIT %s""",
            params,
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        for r in rows:
            for k in ("submitted_at", "created_at", "updated_at"):
                if r.get(k):
                    r[k] = r[k].isoformat()
        total = len(rows)
        cur.close()
        conn.close()
        return {"findings": rows, "total": total}
    except Exception:
        # Filesystem fallback: use _aggregate_findings()
        agg = _aggregate_findings()
        fs_findings = agg["findings"]
        if target:
            fs_findings = [f for f in fs_findings if f.get("target") == target]
        return {"findings": fs_findings[:limit], "total": len(fs_findings), "source": "filesystem"}


@app.get("/api/db/findings/stats")
async def findings_stats():
    """Aggregate finding statistics by target and severity."""
    try:
        conn = _get_db_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT target, severity, status, COUNT(*) AS count
               FROM findings
               GROUP BY target, severity, status
               ORDER BY count DESC"""
        )
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        cur.execute("SELECT COUNT(*) FROM findings")
        total = cur.fetchone()[0]
        cur.close()
        conn.close()
        return {"stats": rows, "total": total}
    except Exception:
        # Filesystem fallback: compute stats from _aggregate_findings()
        agg = _aggregate_findings()
        from collections import Counter
        by_target_sev = Counter()
        for f in agg["findings"]:
            key = (f.get("target", "unknown"), f.get("severity", "info"))
            by_target_sev[key] += 1
        stats = [
            {"target": t, "severity": s, "status": "filesystem", "count": c}
            for (t, s), c in by_target_sev.most_common()
        ]
        return {"stats": stats, "total": len(agg["findings"]), "source": "filesystem"}


@app.post("/api/db/findings")
async def create_finding(request: Request):
    """Create a new finding (called by infra_client)."""
    try:
        body = await request.json()
        conn = _get_db_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO findings
               (target, title, severity, status, poc_tier, cvss_score,
                description, poc_summary, platform, submitted_at,
                triager_outcome, bounty_amount)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (
                body.get("target"),
                body.get("title"),
                body.get("severity"),
                body.get("status", "new"),
                body.get("poc_tier"),
                body.get("cvss_score"),
                body.get("description"),
                body.get("poc_summary"),
                body.get("platform"),
                body.get("submitted_at"),
                body.get("triager_outcome"),
                body.get("bounty_amount"),
            ),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        return {"id": new_id, "status": "created"}
    except Exception:
        return JSONResponse(status_code=503, content={
            "error": "Database not available. Start Docker services for write operations."
        })


@app.patch("/api/db/findings/{finding_id}")
async def update_finding(finding_id: int, request: Request):
    """Update finding status/outcome."""
    try:
        body = await request.json()
        if not body:
            raise ValueError("Empty request body")
        allowed = {"status", "triager_outcome", "bounty_amount", "poc_tier",
                   "cvss_score", "description", "poc_summary", "submitted_at"}
        fields = {k: v for k, v in body.items() if k in allowed}
        if not fields:
            return JSONResponse(status_code=400, content={"error": "No updatable fields provided"})
        conn = _get_db_conn()
        cur = conn.cursor()
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        params = list(fields.values()) + [finding_id]
        cur.execute(
            f"UPDATE findings SET {set_clause}, updated_at = NOW() WHERE id = %s",
            params,
        )
        if cur.rowcount == 0:
            cur.close()
            conn.close()
            return JSONResponse(status_code=404, content={"error": "Finding not found"})
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "updated"}
    except Exception:
        return JSONResponse(status_code=503, content={
            "error": "Database not available. Start Docker services for write operations."
        })


# ──────────────────────────────────────────────
# Attack Graph Endpoints (Neo4j proxy)
# ──────────────────────────────────────────────

def _build_graph_from_filesystem(target: str = None) -> dict:
    """Build a graph data structure from targets/ filesystem data."""
    import re
    nodes = []
    links = []
    node_ids = set()

    def add_node(nid, label, ntype, **extra):
        if nid not in node_ids:
            node_ids.add(nid)
            node = {"id": nid, "label": label, "type": ntype}
            node.update(extra)
            nodes.append(node)

    def add_link(source, target_id, rel="related"):
        links.append({"source": source, "target": target_id, "relationship": rel})

    scan_dirs = []
    if target and TARGETS_DIR.exists():
        td = TARGETS_DIR / target
        if td.is_dir():
            scan_dirs = [td]
    elif TARGETS_DIR.exists():
        scan_dirs = [d for d in TARGETS_DIR.iterdir() if d.is_dir()]

    for tdir in scan_dirs:
        tname = tdir.name
        add_node(f"target:{tname}", tname, "target")

        # Findings from vulnerability_candidates.md
        vuln_file = tdir / "vulnerability_candidates.md"
        if vuln_file.exists():
            try:
                text = vuln_file.read_text(errors="replace")[:100000]
                sections = re.split(r'^##\s+', text, flags=re.MULTILINE)
                for i, section in enumerate(sections[1:], 1):
                    lines = section.strip().split("\n")
                    title = lines[0].strip()[:80] if lines else f"Finding {i}"
                    section_text = "\n".join(lines)
                    cvss = _extract_cvss_from_text(section_text)
                    sev = _cvss_to_severity(cvss) if cvss else "info"
                    fid = f"finding:{tname}:{i}"
                    add_node(fid, title, "finding", severity=sev, cvss=cvss)
                    add_link(f"target:{tname}", fid, "has_finding")
            except Exception:
                pass

        # Reports as technique nodes
        report_patterns = ["report_*.md", "*_submission.md"]
        for pattern in report_patterns:
            for md_file in tdir.glob(pattern):
                try:
                    text = md_file.read_text(errors="replace")[:20000]
                    title_match = re.search(r'^#\s+(.+)', text, re.MULTILINE)
                    title = title_match.group(1).strip()[:60] if title_match else md_file.stem
                    cvss = _extract_cvss_from_text(text)
                    sev = _cvss_to_severity(cvss) if cvss else "medium"
                    rid = f"report:{tname}:{md_file.stem}"
                    add_node(rid, title, "technique", severity=sev, cvss=cvss)
                    # Link findings to techniques
                    finding_nodes = [n["id"] for n in nodes if n["type"] == "finding" and tname in n["id"]]
                    if finding_nodes:
                        add_link(finding_nodes[0], rid, "exploited_by")
                    else:
                        add_link(f"target:{tname}", rid, "has_technique")
                except Exception:
                    pass

        # Recon data for services
        recon_file = tdir / "recon_notes.md"
        if not recon_file.exists():
            recon_file = tdir / "recon_report.json"
        if recon_file.exists():
            try:
                text = recon_file.read_text(errors="replace")[:30000]
                # Extract service/port mentions
                ports = re.findall(r'(?:port|service)[:\s]+(\d+)(?:/(\w+))?', text, re.IGNORECASE)
                for port, proto in ports[:10]:
                    sid = f"service:{tname}:{port}"
                    add_node(sid, f"{proto or 'tcp'}:{port}", "service")
                    add_link(f"target:{tname}", sid, "has_service")
            except Exception:
                pass

    return {"nodes": nodes, "links": links}


@app.get("/api/graph/summary")
async def graph_summary(target: str):
    """Get attack surface summary, with filesystem fallback."""
    try:
        graph = _get_graph()
        return graph.get_attack_surface_summary(target)
    except Exception:
        # Filesystem fallback
        graph_data = _build_graph_from_filesystem(target)
        finding_nodes = [n for n in graph_data["nodes"] if n["type"] == "finding"]
        technique_nodes = [n for n in graph_data["nodes"] if n["type"] == "technique"]
        service_nodes = [n for n in graph_data["nodes"] if n["type"] == "service"]
        return {
            "hosts": 1,
            "services": len(service_nodes),
            "endpoints": 0,
            "vulnerabilities": len(finding_nodes),
            "findings": len(finding_nodes) + len(technique_nodes),
            "source": "filesystem",
        }


@app.get("/api/graph/critical-vulns")
async def graph_critical_vulns(target: str = None):
    """Get critical vulnerabilities, with filesystem fallback."""
    try:
        graph = _get_graph()
        return graph.get_critical_vulns(target)
    except Exception:
        graph_data = _build_graph_from_filesystem(target)
        critical = []
        for n in graph_data["nodes"]:
            if n["type"] in ("finding", "technique"):
                cvss = n.get("cvss")
                if cvss and cvss >= 7.0:
                    critical.append({
                        "cve_id": n["label"],
                        "description": n["label"],
                        "severity": n.get("severity", "high").upper(),
                        "cvss": cvss,
                    })
        return critical


@app.get("/api/graph/attack-paths")
async def graph_attack_paths(target: str):
    """Get attack paths, with filesystem fallback."""
    try:
        graph = _get_graph()
        return graph.get_attack_paths(target)
    except Exception:
        graph_data = _build_graph_from_filesystem(target)
        paths = []
        for link in graph_data["links"]:
            paths.append({
                "from": link["source"],
                "to": link["target"],
                "relationship": link["relationship"],
            })
        return {"paths": paths, "source": "filesystem"}


@app.get("/api/graph/export")
async def graph_export(target: str):
    """Export full attack graph as d3-compatible JSON, with filesystem fallback."""
    try:
        graph = _get_graph()
        return graph.export_to_json(target)
    except Exception:
        graph_data = _build_graph_from_filesystem(target)
        return {
            "target": target,
            "nodes": graph_data["nodes"],
            "links": graph_data["links"],
            "source": "filesystem",
        }


# ──────────────────────────────────────────────
# RAG Proxy Endpoints
# ──────────────────────────────────────────────

@app.post("/api/rag/search")
async def rag_search(request: Request):
    """Proxy search to RAG API."""
    import httpx
    svc = os.environ.get("SERVICE_DISCOVERY", "docker")
    rag_url = os.environ.get(
        "RAG_API_URL",
        "http://rag-api:8100" if svc == "docker" else "http://localhost:8100",
    )
    try:
        body = await request.json()
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{rag_url}/query", json=body)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


@app.get("/api/rag/stats")
async def rag_stats():
    """Get RAG knowledge base statistics."""
    try:
        conn = _get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM exploit_vectors")
        ev_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM failure_memory")
        fm_count = cur.fetchone()[0]
        cur.close()
        conn.close()
        return {"exploit_vectors": ev_count, "failure_memory": fm_count}
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e), "exploit_vectors": 0, "failure_memory": 0})


# ──────────────────────────────────────────────
# WebSocket: Live Log Tailing
# ──────────────────────────────────────────────

active_connections: list[WebSocket] = []


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for live session monitoring — tails the latest session log."""
    await websocket.accept()
    active_connections.append(websocket)

    try:
        # Find the most recent session log
        log_file: Optional[Path] = None
        position = 0

        while True:
            # Refresh: pick the newest session directory
            if REPORTS_DIR.exists():
                sessions = sorted(REPORTS_DIR.glob("20*"), reverse=True)
                for sd in sessions:
                    candidate = sd / "session.log"
                    if candidate.exists():
                        if candidate != log_file:
                            log_file = candidate
                            position = 0  # reset on new file
                        break

            if log_file and log_file.exists():
                try:
                    size = log_file.stat().st_size
                    if size > position:
                        with open(log_file, errors="replace") as f:
                            f.seek(position)
                            new_data = f.read(65536)  # max 64KB per tick
                        position = log_file.stat().st_size
                        if new_data:
                            await websocket.send_json({
                                "type": "log",
                                "session": log_file.parent.name,
                                "data": new_data,
                                "ts": datetime.now(timezone.utc).isoformat() + "Z",
                            })
                except Exception as e:
                    await websocket.send_json({"type": "error", "message": str(e)})
            else:
                await websocket.send_json({
                    "type": "idle",
                    "message": "No active session log found.",
                    "ts": datetime.now(timezone.utc).isoformat() + "Z",
                })

            await asyncio.sleep(1)

    except WebSocketDisconnect:
        pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)


@app.websocket("/ws/agents")
async def ws_agents(websocket: WebSocket):
    """Real-time agent status stream — polls agent_runs table for changes."""
    await websocket.accept()
    last_check: dict = {}
    try:
        while True:
            try:
                conn = _get_db_conn()
                cur = conn.cursor()
                cur.execute(
                    """SELECT id, session_id, agent_role, target, model, status,
                              duration_seconds, tokens_used, output_summary, artifacts,
                              created_at, completed_at
                       FROM agent_runs
                       WHERE status = 'RUNNING'
                          OR (completed_at IS NOT NULL
                              AND completed_at > NOW() - INTERVAL '30 seconds')
                       ORDER BY created_at DESC"""
                )
                cols = [d[0] for d in cur.description]
                rows = [dict(zip(cols, row)) for row in cur.fetchall()]
                cur.close()
                conn.close()

                # Serialize datetimes
                for r in rows:
                    for k in ("created_at", "completed_at"):
                        if r.get(k):
                            r[k] = r[k].isoformat()

                # Detect deltas vs last_check
                current_ids = {r["id"]: r for r in rows}
                changed = [r for r in rows if last_check.get(r["id"]) != r]
                last_check = current_ids

                if changed:
                    await websocket.send_json({
                        "type": "agent_update",
                        "runs": changed,
                        "ts": datetime.now(timezone.utc).isoformat() + "Z",
                    })
            except Exception as e:
                await websocket.send_json({
                    "type": "error",
                    "message": str(e),
                    "ts": datetime.now(timezone.utc).isoformat() + "Z",
                })

            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass


# ──────────────────────────────────────────────
# Static files + SPA fallback
# ──────────────────────────────────────────────

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse({"message": "Terminator Dashboard API", "docs": "/docs"})


@app.get("/health")
async def health():
    return {"status": "ok", "service": "terminator-web-ui"}
