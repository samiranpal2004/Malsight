# Phase 4: PostgreSQL helpers using psycopg2 (sync — correct for RQ worker context).
# FastAPI async routes call these via asyncio.to_thread() to avoid blocking the event loop.
import json
import os
from contextlib import contextmanager
from datetime import datetime
from typing import Any

import psycopg2
import psycopg2.extras
import psycopg2.pool

_pool: psycopg2.pool.ThreadedConnectionPool | None = None


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        url = os.environ.get(
            "DATABASE_URL",
            "postgresql://malsight:malsight@localhost:5432/malsight",
        )
        _pool = psycopg2.pool.ThreadedConnectionPool(2, 20, url)
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


# ---------------------------------------------------------------------------
# DDL — create tables on first startup
# ---------------------------------------------------------------------------

_CREATE_JOBS = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id       TEXT PRIMARY KEY,
    status       TEXT    NOT NULL,
    mode         TEXT    NOT NULL,
    filename     TEXT    NOT NULL,
    sha256       TEXT,
    created_at   TIMESTAMP DEFAULT NOW(),
    started_at   TIMESTAMP,
    completed_at TIMESTAMP,
    error        TEXT
)
"""

_CREATE_REPORTS = """
CREATE TABLE IF NOT EXISTS reports (
    job_id      TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
    report_json JSONB    NOT NULL,
    verdict     TEXT,
    confidence  INTEGER,
    mode        TEXT,
    created_at  TIMESTAMP DEFAULT NOW()
)
"""


def init_tables() -> None:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(_CREATE_JOBS)
            cur.execute(_CREATE_REPORTS)


# ---------------------------------------------------------------------------
# Job helpers
# ---------------------------------------------------------------------------

def insert_job(
    job_id: str,
    status: str,
    mode: str,
    filename: str,
    sha256: str | None = None,
) -> None:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO jobs (job_id, status, mode, filename, sha256)"
                " VALUES (%s, %s, %s, %s, %s)",
                (job_id, status, mode, filename, sha256),
            )


def update_job_status(
    job_id: str,
    status: str,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    error: str | None = None,
) -> None:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE jobs
                   SET status       = %s,
                       started_at   = COALESCE(%s, started_at),
                       completed_at = COALESCE(%s, completed_at),
                       error        = COALESCE(%s, error)
                 WHERE job_id = %s
                """,
                (status, started_at, completed_at, error, job_id),
            )


def get_job(job_id: str) -> dict | None:
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM jobs WHERE job_id = %s", (job_id,))
            row = cur.fetchone()
            return dict(row) if row else None


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------

def insert_report(job_id: str, report_dict: dict) -> None:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reports (job_id, report_json, verdict, confidence, mode)
                     VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (job_id) DO UPDATE
                    SET report_json = EXCLUDED.report_json,
                        verdict     = EXCLUDED.verdict,
                        confidence  = EXCLUDED.confidence,
                        mode        = EXCLUDED.mode
                """,
                (
                    job_id,
                    json.dumps(report_dict, default=str),
                    report_dict.get("verdict"),
                    report_dict.get("confidence"),
                    report_dict.get("mode"),
                ),
            )


def get_report(job_id: str) -> dict | None:
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM reports WHERE job_id = %s", (job_id,))
            row = cur.fetchone()
            if row is None:
                return None
            d = dict(row)
            # report_json comes back as a dict when psycopg2 uses JSONB
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
        conditions.append("r.mode = %s")
        params.append(mode_filter)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    offset = (page - 1) * page_size

    list_sql = f"""
        SELECT j.job_id,
               j.filename,
               j.mode,
               r.verdict,
               r.confidence,
               r.report_json ->> 'threat_category'              AS threat_category,
               r.report_json ->> 'severity'                     AS severity,
               (r.report_json ->> 'tools_called')::INTEGER      AS tools_called,
               (r.report_json ->> 'analysis_time_seconds')::INTEGER
                                                                AS analysis_time_seconds,
               j.created_at
          FROM reports r
          JOIN jobs    j USING (job_id)
        {where}
         ORDER BY j.created_at DESC
         LIMIT %s OFFSET %s
    """
    count_sql = f"""
        SELECT COUNT(*)
          FROM reports r
          JOIN jobs    j USING (job_id)
        {where}
    """

    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(count_sql, params)
            total: int = cur.fetchone()["count"]  # type: ignore[index]
            cur.execute(list_sql, params + [page_size, offset])
            rows = [dict(r) for r in cur.fetchall()]

    # Serialize datetimes to ISO strings
    for row in rows:
        if isinstance(row.get("created_at"), datetime):
            row["created_at"] = row["created_at"].isoformat()

    return rows, total


def delete_report(job_id: str) -> bool:
    """Delete the report and job rows (reports first due to FK). Returns True if job existed."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM reports WHERE job_id = %s", (job_id,))
            cur.execute("DELETE FROM jobs    WHERE job_id = %s", (job_id,))
            return cur.rowcount > 0
