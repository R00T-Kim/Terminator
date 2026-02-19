"""
Terminator Dashboard - Database Service
PostgreSQL connection and all DB query helpers.
"""

import logging
from typing import Optional

from web.config import DB_CONFIG

logger = logging.getLogger(__name__)


def get_connection():
    """Get a PostgreSQL connection using psycopg2.

    Returns a new connection each call. Caller is responsible for closing.
    Raises ImportError if psycopg2 is not installed,
    or psycopg2.OperationalError if the DB is unreachable.
    """
    import psycopg2
    return psycopg2.connect(**DB_CONFIG)


# ── Agent Runs ──

def list_agent_runs(session: Optional[str] = None, target: Optional[str] = None, limit: int = 50) -> list:
    """Fetch agent runs from the agent_runs table."""
    conn = get_connection()
    try:
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
        return rows
    finally:
        conn.close()


def list_active_agent_runs() -> list:
    """Fetch currently running agents (status=RUNNING)."""
    conn = get_connection()
    try:
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
        return rows
    finally:
        conn.close()


def list_recent_and_running_agents() -> list:
    """Fetch running + recently completed agents (for WebSocket streaming)."""
    conn = get_connection()
    try:
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
        for r in rows:
            for k in ("created_at", "completed_at"):
                if r.get(k):
                    r[k] = r[k].isoformat()
        cur.close()
        return rows
    finally:
        conn.close()


# ── Findings CRUD ──

def list_findings(target: Optional[str] = None, status: Optional[str] = None, limit: int = 50) -> tuple:
    """Fetch findings from the findings table. Returns (rows, total)."""
    conn = get_connection()
    try:
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
        return rows, total
    finally:
        conn.close()


def get_findings_stats() -> tuple:
    """Aggregate finding statistics. Returns (stats_rows, total)."""
    conn = get_connection()
    try:
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
        return rows, total
    finally:
        conn.close()


def create_finding(body: dict) -> int:
    """Insert a new finding. Returns the new ID."""
    conn = get_connection()
    try:
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
        return new_id
    finally:
        conn.close()


def update_finding(finding_id: int, fields: dict) -> int:
    """Update a finding by ID. Returns rowcount (0 = not found)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        params = list(fields.values()) + [finding_id]
        cur.execute(
            f"UPDATE findings SET {set_clause}, updated_at = NOW() WHERE id = %s",
            params,
        )
        rowcount = cur.rowcount
        conn.commit()
        cur.close()
        return rowcount
    finally:
        conn.close()


# ── RAG Stats ──

def get_rag_stats() -> dict:
    """Get exploit_vectors and failure_memory counts."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM exploit_vectors")
        ev_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM failure_memory")
        fm_count = cur.fetchone()[0]
        cur.close()
        return {"exploit_vectors": ev_count, "failure_memory": fm_count}
    finally:
        conn.close()
