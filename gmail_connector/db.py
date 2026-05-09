"""PostgreSQL helpers for the Gmail connector."""
import os
import uuid

import psycopg2
import psycopg2.extras
import psycopg2.pool

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


# ── Gmail account helpers ─────────────────────────────────────────────────────

def upsert_gmail_account(
    email_address: str,
    access_token: str,
    refresh_token: str,
    token_expiry,
) -> None:
    _exec(
        """
        INSERT INTO gmail_accounts (email_address, access_token, refresh_token, token_expiry)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (email_address) DO UPDATE
            SET access_token  = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                token_expiry  = EXCLUDED.token_expiry,
                active        = TRUE
        """,
        (email_address, access_token, refresh_token, token_expiry),
    )


def get_gmail_account(email_address: str) -> dict | None:
    rows = _exec(
        "SELECT * FROM gmail_accounts WHERE email_address = %s AND active = TRUE",
        (email_address,),
        fetch=True,
    )
    return rows[0] if rows else None


def get_all_active_accounts() -> list[dict]:
    rows = _exec(
        "SELECT * FROM gmail_accounts WHERE active = TRUE",
        (),
        fetch=True,
    )
    return rows or []


def update_account_labels(
    email_address: str,
    label_clean: str | None,
    label_suspicious: str | None,
    label_malicious: str | None,
    label_quarantine: str | None,
    label_scanning: str | None,
) -> None:
    _exec(
        """
        UPDATE gmail_accounts
           SET label_clean      = %s,
               label_suspicious = %s,
               label_malicious  = %s,
               label_quarantine = %s,
               label_scanning   = %s
         WHERE email_address = %s
        """,
        (label_clean, label_suspicious, label_malicious, label_quarantine, label_scanning, email_address),
    )


def update_history_id(email_address: str, history_id: str) -> None:
    _exec(
        "UPDATE gmail_accounts SET last_history_id = %s WHERE email_address = %s",
        (history_id, email_address),
    )


def update_watch_expiry(email_address: str, watch_expiry, history_id: str | None = None) -> None:
    if history_id:
        _exec(
            """
            UPDATE gmail_accounts
               SET watch_expiry = %s, last_history_id = %s
             WHERE email_address = %s
            """,
            (watch_expiry, history_id, email_address),
        )
    else:
        _exec(
            "UPDATE gmail_accounts SET watch_expiry = %s WHERE email_address = %s",
            (watch_expiry, email_address),
        )


def update_access_token(email_address: str, access_token: str, token_expiry) -> None:
    _exec(
        """
        UPDATE gmail_accounts
           SET access_token = %s, token_expiry = %s
         WHERE email_address = %s
        """,
        (access_token, token_expiry, email_address),
    )


def deactivate_account(email_address: str) -> None:
    _exec(
        "UPDATE gmail_accounts SET active = FALSE WHERE email_address = %s",
        (email_address,),
    )


# ── Email / attachment helpers (mirrors mail_processor/db.py) ────────────────

def gmail_message_exists(gmail_message_id: str) -> bool:
    rows = _exec(
        "SELECT id FROM emails WHERE gmail_message_id = %s",
        (gmail_message_id,),
        fetch=True,
    )
    return bool(rows)


def save_gmail_email(
    mail_from: str,
    rcpt_to: list[str],
    subject: str,
    sender_display: str,
    body_text: str,
    body_html: str,
    gmail_message_id: str,
    recipient_address: str,
) -> str:
    email_id = str(uuid.uuid4())
    _exec(
        """
        INSERT INTO emails
            (id, mail_from, rcpt_to, subject, sender_display,
             body_text, body_html, gmail_message_id,
             recipient_address, source, delivery_status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'gmail', 'held')
        """,
        (
            email_id, mail_from, rcpt_to, subject, sender_display,
            body_text, body_html, gmail_message_id, recipient_address,
        ),
    )
    return email_id


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
    rows = _exec(
        "SELECT * FROM email_attachments WHERE email_id = %s",
        (email_id,),
        fetch=True,
    )
    return rows or []


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
