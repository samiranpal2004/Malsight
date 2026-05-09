"""PostgreSQL helpers for the mail processor worker."""
import os
import uuid

import psycopg2
import psycopg2.pool
import psycopg2.extras

DATABASE_URL = os.environ.get("DATABASE_URL")
_pool: psycopg2.pool.ThreadedConnectionPool | None = None


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(2, 10, DATABASE_URL)
    return _pool


def _exec(sql: str, params: tuple, fetch: bool = False):
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            result = cur.fetchall() if fetch else None
        conn.commit()
        return [dict(r) for r in result] if result is not None else None
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def get_email(email_id: str) -> dict | None:
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM emails WHERE id = %s", (email_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def save_email_attachment(
    email_id: str,
    filename: str,
    content_type: str,
    file_size: int,
    sha256: str,
    staging_path: str,
) -> str:
    attachment_id = str(uuid.uuid4())
    _exec(
        """
        INSERT INTO email_attachments
            (id, email_id, filename, content_type, file_size_bytes, sha256, staging_path)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (attachment_id, email_id, filename, content_type, file_size, sha256, staging_path),
    )
    return attachment_id


def update_attachment_job(attachment_id: str, job_id: str) -> None:
    _exec(
        "UPDATE email_attachments SET job_id = %s WHERE id = %s",
        (job_id, attachment_id),
    )


def update_attachment_verdict(
    attachment_id: str,
    verdict: str,
    confidence: int,
    threat_category: str,
    severity: str,
) -> None:
    _exec(
        """
        UPDATE email_attachments
           SET verdict = %s, confidence = %s, threat_category = %s, severity = %s
         WHERE id = %s
        """,
        (verdict, confidence, threat_category, severity, attachment_id),
    )


def get_attachments_for_email(email_id: str) -> list[dict]:
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM email_attachments WHERE email_id = %s",
                (email_id,),
            )
            return [dict(r) for r in cur.fetchall()]
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)


def update_email_status(email_id: str, status: str) -> None:
    _exec(
        "UPDATE emails SET delivery_status = %s WHERE id = %s",
        (status, email_id),
    )


def create_quarantine_log(
    email_id: str,
    attachment_id: str,
    reason: str,
    verdict: str,
    mitre_techniques: list | None = None,
) -> None:
    _exec(
        """
        INSERT INTO quarantine_log (email_id, attachment_id, reason, verdict, mitre_techniques)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            email_id, attachment_id, reason, verdict,
            psycopg2.extras.Json(mitre_techniques or []),
        ),
    )
