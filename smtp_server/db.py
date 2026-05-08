"""PostgreSQL helpers for the SMTP server — saves raw inbound email."""
import os
import uuid

import psycopg2
import psycopg2.pool
from email import message_from_bytes
from email.header import decode_header, make_header

DATABASE_URL = os.environ.get("DATABASE_URL")
_pool: psycopg2.pool.ThreadedConnectionPool | None = None


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(2, 10, DATABASE_URL)
    return _pool


def _decode_mime_words(s: str | None) -> str:
    if not s:
        return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s or ""


def _extract_bodies(msg) -> tuple[str | None, str | None]:
    body_text: str | None = None
    body_html: str | None = None

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            charset = part.get_content_charset("utf-8") or "utf-8"
            if ct == "text/plain" and body_text is None:
                try:
                    body_text = part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    pass
            elif ct == "text/html" and body_html is None:
                try:
                    body_html = part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    pass
    else:
        ct = msg.get_content_type()
        charset = msg.get_content_charset("utf-8") or "utf-8"
        try:
            payload = msg.get_payload(decode=True).decode(charset, errors="replace")
        except Exception:
            payload = ""
        if ct == "text/html":
            body_html = payload
        else:
            body_text = payload

    return body_text, body_html


def save_email_to_db(
    mail_from: str,
    rcpt_to: list[str],
    raw_message: bytes | str,
) -> str:
    """Parse raw email and persist to emails table. Returns the new email UUID."""
    email_id = str(uuid.uuid4())

    if isinstance(raw_message, str):
        raw_message = raw_message.encode("utf-8", errors="replace")

    msg = message_from_bytes(raw_message)
    subject = _decode_mime_words(msg.get("Subject"))
    sender_display = _decode_mime_words(msg.get("From"))
    reply_to = _decode_mime_words(msg.get("Reply-To"))
    body_text, body_html = _extract_bodies(msg)
    recipient_address = rcpt_to[0] if rcpt_to else mail_from

    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO emails
                    (id, mail_from, rcpt_to, subject, sender_display, reply_to,
                     body_text, body_html, raw_message, recipient_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    email_id, mail_from, rcpt_to, subject, sender_display, reply_to,
                    body_text, body_html, psycopg2.Binary(raw_message), recipient_address,
                ),
            )
        conn.commit()
        return email_id
    except Exception:
        conn.rollback()
        raise
    finally:
        pool.putconn(conn)
