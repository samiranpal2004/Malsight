# Phase 4: PostgreSQL helpers using psycopg2 (sync — correct for RQ worker context).
# FastAPI async routes call these via asyncio.to_thread() to avoid blocking the event loop.
import json
from contextlib import contextmanager
from datetime import datetime
from typing import Any

import psycopg2
import psycopg2.extensions
import psycopg2.extras
import psycopg2.pool

from malsight.config import DATABASE_URL

_pool: psycopg2.pool.ThreadedConnectionPool | None = None


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(2, 20, DATABASE_URL())
    return _pool


@contextmanager
def _conn():
    """Borrow a connection from the pool, auto-commit or rollback, then return it."""
    pool = _get_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def get_db_connection() -> psycopg2.extensions.connection:
    """Return a fresh, non-pooled connection. Caller must close() it."""
    return psycopg2.connect(DATABASE_URL())


def init_tables() -> None:
    """No-op stub kept for startup compatibility — schema is managed externally."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")


# ---------------------------------------------------------------------------
# Job helpers
# ---------------------------------------------------------------------------

def insert_job(
    job_id: str,
    status: str,
    mode: str,
    filename: str,
    sha256: str | None = None,
    file_size_bytes: int = 0,
    mime_type: str = "",
    staging_path: str = "",
) -> None:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO jobs
                    (id, status, mode, filename, sha256,
                     file_size_bytes, mime_type, staging_path)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (job_id, status, mode, filename, sha256,
                 file_size_bytes, mime_type, staging_path),
            )


def update_job_status(
    job_id: str,
    status: str,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    error: str | None = None,
    current_step: int | None = None,
    current_action: str | None = None,
) -> None:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE jobs
                   SET status         = %s,
                       updated_at     = NOW(),
                       started_at     = COALESCE(%s, started_at),
                       completed_at   = COALESCE(%s, completed_at),
                       error_message  = COALESCE(%s, error_message),
                       current_step   = COALESCE(%s, current_step),
                       current_action = COALESCE(%s, current_action)
                 WHERE id = %s
                """,
                (status, started_at, completed_at, error,
                 current_step, current_action, job_id),
            )


def get_job(job_id: str) -> dict | None:
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
            row = cur.fetchone()
            if row is None:
                return None
            d = dict(row)
            d["job_id"] = d["id"]           # backward-compat alias
            d["error"] = d.get("error_message")  # backward-compat alias
            return d


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------

def insert_report(job_id: str, report_dict: dict) -> None:
    reasoning_chain = report_dict.get("reasoning_chain", {})
    incomplete = bool(report_dict.get("incomplete_analysis", False))
    analysis_mode = report_dict.get("mode", "standard")

    # Store everything except reasoning_chain in report_json to avoid duplication
    report_for_json = {k: v for k, v in report_dict.items() if k != "reasoning_chain"}

    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reports
                    (job_id, verdict, confidence, threat_category, severity,
                     summary, recommended_action, tools_called, analysis_mode,
                     incomplete, report_json, reasoning_chain)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (job_id) DO UPDATE SET
                    verdict           = EXCLUDED.verdict,
                    confidence        = EXCLUDED.confidence,
                    threat_category   = EXCLUDED.threat_category,
                    severity          = EXCLUDED.severity,
                    summary           = EXCLUDED.summary,
                    recommended_action= EXCLUDED.recommended_action,
                    tools_called      = EXCLUDED.tools_called,
                    analysis_mode     = EXCLUDED.analysis_mode,
                    incomplete        = EXCLUDED.incomplete,
                    report_json       = EXCLUDED.report_json,
                    reasoning_chain   = EXCLUDED.reasoning_chain
                """,
                (
                    job_id,
                    report_dict.get("verdict"),
                    report_dict.get("confidence"),
                    report_dict.get("threat_category"),
                    report_dict.get("severity"),
                    report_dict.get("summary"),
                    report_dict.get("recommended_action"),
                    report_dict.get("tools_called"),
                    analysis_mode,
                    incomplete,
                    psycopg2.extras.Json(report_for_json),
                    psycopg2.extras.Json(reasoning_chain),
                ),
            )


def get_report(job_id: str) -> dict | None:
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT r.*, j.filename, j.mode, j.status
                  FROM reports r
                  JOIN jobs    j ON r.job_id = j.id
                 WHERE r.job_id = %s
                """,
                (job_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            d = dict(row)
            if isinstance(d.get("report_json"), str):
                d["report_json"] = json.loads(d["report_json"])
            return d


def list_reports(
    page: int,
    page_size: int,
    verdict_filter: str | None,
    mode_filter: str | None,
) -> tuple[list[dict], int]:
    conditions: list[str] = []
    params: list[Any] = []

    if verdict_filter:
        conditions.append("r.verdict = %s")
        params.append(verdict_filter)
    if mode_filter:
        conditions.append("j.mode = %s")
        params.append(mode_filter)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    offset = (page - 1) * page_size

    list_sql = f"""
        SELECT r.job_id,
               j.filename,
               j.mode,
               r.verdict,
               r.confidence,
               r.threat_category,
               r.severity,
               r.tools_called,
               j.completed_at AS created_at
          FROM reports r
          JOIN jobs    j ON r.job_id = j.id
        {where}
         ORDER BY j.created_at DESC
         LIMIT %s OFFSET %s
    """
    count_sql = f"""
        SELECT COUNT(*)
          FROM reports r
          JOIN jobs    j ON r.job_id = j.id
        {where}
    """

    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(count_sql, params)
            total: int = cur.fetchone()["count"]  # type: ignore[index]
            cur.execute(list_sql, params + [page_size, offset])
            rows = [dict(r) for r in cur.fetchall()]

    for row in rows:
        if isinstance(row.get("created_at"), datetime):
            row["created_at"] = row["created_at"].isoformat()

    return rows, total


def delete_report(job_id: str) -> bool:
    """Delete the report and job rows (reports first due to FK). Returns True if job existed."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM reports WHERE job_id = %s", (job_id,))
            cur.execute("DELETE FROM jobs    WHERE id = %s", (job_id,))
            return cur.rowcount > 0
