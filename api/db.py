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


# ---------------------------------------------------------------------------
# Email gateway — table init
# ---------------------------------------------------------------------------

_EMAIL_GATEWAY_DDL = """
CREATE TABLE IF NOT EXISTS emails (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    received_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mail_from         TEXT        NOT NULL,
    rcpt_to           TEXT[]      NOT NULL,
    subject           TEXT,
    sender_display    TEXT,
    reply_to          TEXT,
    body_text         TEXT,
    body_html         TEXT,
    raw_message       BYTEA,
    delivery_status   TEXT        NOT NULL DEFAULT 'held'
                      CHECK (delivery_status IN ('held', 'delivered', 'warned', 'quarantined')),
    recipient_address TEXT        NOT NULL,
    source            TEXT        NOT NULL DEFAULT 'smtp'
                      CHECK (source IN ('smtp', 'gmail')),
    gmail_message_id  TEXT
);

CREATE TABLE IF NOT EXISTS email_attachments (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id        UUID        NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    filename        TEXT        NOT NULL,
    content_type    TEXT,
    file_size_bytes BIGINT,
    sha256          CHAR(64),
    job_id          UUID        REFERENCES jobs(id) ON DELETE SET NULL,
    verdict         TEXT        CHECK (verdict IN ('benign', 'suspicious', 'malicious')),
    confidence      INTEGER,
    threat_category TEXT,
    severity        TEXT,
    staging_path    TEXT
);

CREATE TABLE IF NOT EXISTS quarantine_log (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    quarantined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    email_id         UUID        NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    attachment_id    UUID        REFERENCES email_attachments(id) ON DELETE SET NULL,
    reason           TEXT,
    verdict          TEXT,
    mitre_techniques JSONB
);

CREATE INDEX IF NOT EXISTS idx_emails_recipient  ON emails (recipient_address);
CREATE INDEX IF NOT EXISTS idx_emails_status     ON emails (delivery_status);
CREATE INDEX IF NOT EXISTS idx_emails_received   ON emails (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_attachments_job   ON email_attachments (job_id);
CREATE INDEX IF NOT EXISTS idx_attachments_email ON email_attachments (email_id);
"""


def init_tables() -> None:
    """Create email gateway tables on startup (idempotent)."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(_EMAIL_GATEWAY_DDL)


# ---------------------------------------------------------------------------
# Email gateway — query helpers
# ---------------------------------------------------------------------------

def list_emails(
    recipient: str,
    page: int,
    page_size: int,
) -> tuple[list[dict], int]:
    offset = (page - 1) * page_size

    list_sql = """
        SELECT
            e.id            AS email_id,
            e.received_at,
            e.mail_from,
            e.sender_display,
            e.subject,
            e.delivery_status,
            COALESCE(
                json_agg(
                    json_build_object(
                        'id',             a.id::text,
                        'filename',       a.filename,
                        'verdict',        a.verdict,
                        'confidence',     a.confidence,
                        'threat_category',a.threat_category,
                        'severity',       a.severity
                    ) ORDER BY a.created_at
                ) FILTER (WHERE a.id IS NOT NULL),
                '[]'::json
            ) AS attachments
        FROM emails e
        LEFT JOIN email_attachments a ON a.email_id = e.id
        WHERE e.recipient_address = %s
        GROUP BY e.id
        ORDER BY e.received_at DESC
        LIMIT %s OFFSET %s
    """
    count_sql = "SELECT COUNT(*) FROM emails WHERE recipient_address = %s"

    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(count_sql, (recipient,))
            total: int = cur.fetchone()["count"]  # type: ignore[index]
            cur.execute(list_sql, (recipient, page_size, offset))
            rows = [dict(r) for r in cur.fetchall()]

    for row in rows:
        if isinstance(row.get("received_at"), datetime):
            row["received_at"] = row["received_at"].isoformat()

    return rows, total


def get_email_with_attachments(email_id: str) -> dict | None:
    sql = """
        SELECT
            e.id            AS email_id,
            e.received_at,
            e.mail_from,
            e.sender_display,
            e.subject,
            e.reply_to,
            e.body_text,
            e.body_html,
            e.delivery_status,
            e.recipient_address,
            COALESCE(
                json_agg(
                    json_build_object(
                        'id',             a.id::text,
                        'filename',       a.filename,
                        'content_type',   a.content_type,
                        'file_size_bytes',a.file_size_bytes,
                        'verdict',        a.verdict,
                        'confidence',     a.confidence,
                        'threat_category',a.threat_category,
                        'severity',       a.severity,
                        'job_id',         a.job_id::text
                    ) ORDER BY a.created_at
                ) FILTER (WHERE a.id IS NOT NULL),
                '[]'::json
            ) AS attachments
        FROM emails e
        LEFT JOIN email_attachments a ON a.email_id = e.id
        WHERE e.id = %s
        GROUP BY e.id
    """
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (email_id,))
            row = cur.fetchone()
            if row is None:
                return None
            d = dict(row)
            if isinstance(d.get("received_at"), datetime):
                d["received_at"] = d["received_at"].isoformat()
            return d


def get_attachment_with_report(attachment_id: str) -> dict | None:
    sql = """
        SELECT
            a.id::text          AS attachment_id,
            a.filename,
            a.content_type,
            a.file_size_bytes,
            a.sha256,
            a.verdict,
            a.confidence,
            a.threat_category,
            a.severity,
            a.job_id::text      AS job_id,
            r.report_json
        FROM email_attachments a
        LEFT JOIN reports r ON r.job_id = a.job_id
        WHERE a.id = %s
    """
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (attachment_id,))
            row = cur.fetchone()
            if row is None:
                return None
            d = dict(row)
            if isinstance(d.get("report_json"), str):
                import json as _json
                d["report_json"] = _json.loads(d["report_json"])
            return d


def list_quarantine(page: int, page_size: int) -> tuple[list[dict], int]:
    offset = (page - 1) * page_size
    list_sql = """
        SELECT
            q.id::text          AS quarantine_id,
            q.quarantined_at,
            q.reason,
            q.verdict,
            q.mitre_techniques,
            e.id::text          AS email_id,
            e.mail_from,
            e.sender_display,
            e.subject,
            e.received_at,
            a.filename,
            a.id::text          AS attachment_id
        FROM quarantine_log q
        JOIN emails e ON e.id = q.email_id
        LEFT JOIN email_attachments a ON a.id = q.attachment_id
        ORDER BY q.quarantined_at DESC
        LIMIT %s OFFSET %s
    """
    count_sql = "SELECT COUNT(*) FROM quarantine_log"

    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(count_sql)
            total: int = cur.fetchone()["count"]  # type: ignore[index]
            cur.execute(list_sql, (page_size, offset))
            rows = [dict(r) for r in cur.fetchall()]

    for row in rows:
        for key in ("quarantined_at", "received_at"):
            if isinstance(row.get(key), datetime):
                row[key] = row[key].isoformat()

    return rows, total


def release_quarantine_email(email_id: str) -> bool:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE emails SET delivery_status = 'warned'
                 WHERE id = %s AND delivery_status = 'quarantined'
                """,
                (email_id,),
            )
            return cur.rowcount > 0


def get_mail_stats() -> dict:
    email_sql = """
        SELECT
            COUNT(*)                                        AS total,
            COUNT(*) FILTER (WHERE delivery_status='held') AS held,
            COUNT(*) FILTER (WHERE delivery_status='delivered') AS delivered,
            COUNT(*) FILTER (WHERE delivery_status='warned')    AS warned,
            COUNT(*) FILTER (WHERE delivery_status='quarantined') AS quarantined
        FROM emails
    """
    attachment_sql = """
        SELECT
            COUNT(*)                                          AS total,
            COUNT(*) FILTER (WHERE verdict='malicious')      AS malicious,
            COUNT(*) FILTER (WHERE verdict='suspicious')     AS suspicious,
            COUNT(*) FILTER (WHERE verdict='benign')         AS benign
        FROM email_attachments
    """
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(email_sql)
            email_stats = dict(cur.fetchone())  # type: ignore[arg-type]
            cur.execute(attachment_sql)
            att_stats = dict(cur.fetchone())  # type: ignore[arg-type]

    return {"emails": email_stats, "attachments": att_stats}
