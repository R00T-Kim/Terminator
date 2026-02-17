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


def _aggregate_findings() -> dict:
    """Walk all sessions and aggregate vulnerability severity counts."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings = []

    if not REPORTS_DIR.exists():
        return {"counts": counts, "findings": findings}

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
                    })
            except Exception:
                pass

        # Also check writeup.md for flags
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
                        })
                        counts["critical"] += 1
            except Exception:
                pass

    return {"counts": counts, "findings": findings[:50]}  # cap at 50


def _get_health() -> dict:
    """Check health of known services (best-effort, no network calls)."""
    import socket

    def port_open(host: str, port: int, timeout: float = 0.5) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    # Use Docker service names when running in container, localhost otherwise
    svc_host = os.environ.get("SERVICE_DISCOVERY", "docker")
    if svc_host == "docker":
        services = {
            "RAG API": {"host": "rag-api", "port": 8100},
            "Neo4j": {"host": "neo4j", "port": 7474},
            "Ollama": {"host": "ollama", "port": 11434},
            "LiteLLM": {"host": "litellm", "port": 4000},
            "PostgreSQL": {"host": "db", "port": 5432},
        }
    else:
        services = {
            "RAG API": {"host": "localhost", "port": 8100},
            "Neo4j": {"host": "localhost", "port": 7474},
            "Ollama": {"host": "localhost", "port": 11434},
            "LiteLLM": {"host": "localhost", "port": 4000},
            "PostgreSQL": {"host": "localhost", "port": 5433},
        }

    result = {}
    for name, cfg in services.items():
        result[name] = "up" if port_open(cfg["host"], cfg["port"]) else "down"
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
    if not REPORTS_DIR.exists():
        return {
            "total_sessions": 0,
            "flags_captured": 0,
            "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "health": _get_health(),
        }

    all_sessions = list(REPORTS_DIR.glob("20*"))
    total = len(all_sessions)

    flags = 0
    for sd in all_sessions:
        ff = sd / "flags.txt"
        if ff.exists():
            try:
                flags += len([l for l in ff.read_text().splitlines() if l.strip()])
            except Exception:
                pass

    agg = _aggregate_findings()

    return {
        "total_sessions": total,
        "flags_captured": flags,
        "findings": agg["counts"],
        "health": _get_health(),
        "reports_dir": str(REPORTS_DIR),
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
    }


# ──────────────────────────────────────────────
# Bug Bounty Mission Helpers
# ──────────────────────────────────────────────

PIPELINE_PHASES = [
    ("Phase 0: Target Assessment", "target_assessment.md"),
    ("Phase 1: Reconnaissance",    "recon_notes.md"),
    ("Phase 1: Vuln Candidates",   "vulnerability_candidates.md"),
    ("Phase 2: Exploit Results",   "exploit_results.md"),
    ("Phase 3: Reports",           "immunefi_reports"),
    ("Phase 4: Critic Review",     "critic_review.md"),
    ("Phase 4: Architect Review",  "architect_review.md"),
    ("Phase 5: Final Report",      "final_report.md"),
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
    phases = []
    for label, artifact in PIPELINE_PHASES:
        path = mission_dir / artifact
        complete = path.exists()
        phases.append({"label": label, "artifact": artifact, "complete": complete})

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
        "has_exploits": (mission_dir / "exploit_results.md").exists(),
        "has_reports": (mission_dir / "immunefi_reports").exists(),
    }


# ──────────────────────────────────────────────
# Bug Bounty REST Endpoints
# ──────────────────────────────────────────────

@app.get("/api/bounty/missions")
async def list_missions():
    """List all active bounty missions from targets/ directory."""
    if not TARGETS_DIR.exists():
        return {"missions": []}

    missions = []
    for entry in sorted(TARGETS_DIR.iterdir()):
        if not entry.is_dir():
            continue
        # Must have target_assessment.md to count as a mission
        if not (entry / "target_assessment.md").exists():
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

@app.get("/api/agent-runs")
async def list_agent_runs(session: str = None, target: str = None, limit: int = 50):
    """List agent execution history from agent_runs table."""
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
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e), "runs": []})


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
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e), "active": []})


# ──────────────────────────────────────────────
# Findings CRUD Endpoints
# ──────────────────────────────────────────────

@app.get("/api/db/findings")
async def list_db_findings(target: str = None, status: str = None, limit: int = 50):
    """List findings from DB (not file-based)."""
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
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e), "findings": [], "total": 0})


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
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e), "stats": [], "total": 0})


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
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


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
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


# ──────────────────────────────────────────────
# Attack Graph Endpoints (Neo4j proxy)
# ──────────────────────────────────────────────

@app.get("/api/graph/summary")
async def graph_summary(target: str):
    """Get attack surface summary from Neo4j."""
    try:
        graph = _get_graph()
        return graph.get_attack_surface_summary(target)
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


@app.get("/api/graph/critical-vulns")
async def graph_critical_vulns(target: str = None):
    """Get critical vulnerabilities from Neo4j."""
    try:
        graph = _get_graph()
        return graph.get_critical_vulns(target)
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


@app.get("/api/graph/attack-paths")
async def graph_attack_paths(target: str):
    """Get attack paths from Neo4j."""
    try:
        graph = _get_graph()
        return graph.get_attack_paths(target)
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


@app.get("/api/graph/export")
async def graph_export(target: str):
    """Export full attack graph as JSON."""
    try:
        graph = _get_graph()
        return graph.export_to_json(target)
    except Exception as e:
        return JSONResponse(status_code=503, content={"error": str(e)})


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
