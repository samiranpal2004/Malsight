"""MalSight mail processor — RQ worker that scans email attachments."""
import hashlib
import logging
import os
import time
from email import message_from_bytes
from email.header import decode_header, make_header

import requests
from dotenv import load_dotenv

load_dotenv()

from db import (
    create_quarantine_log,
    get_attachments_for_email,
    get_email,
    save_email_attachment,
    update_attachment_job,
    update_attachment_verdict,
    update_email_status,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MALSIGHT_API_URL = os.environ.get("MALSIGHT_API_URL", "http://localhost:8000")
# Support both MALSIGHT_API_KEYS (comma-separated, same as the API server) and
# the legacy single-key MALSIGHT_API_KEY.  Take the first non-empty key.
_api_keys_raw = os.environ.get("MALSIGHT_API_KEYS") or os.environ.get("MALSIGHT_API_KEY", "")
MALSIGHT_API_KEY = _api_keys_raw.split(",")[0].strip()
UPLOAD_DIR = os.environ.get(
    "UPLOAD_DIR",
    os.path.join(os.path.normpath(os.environ.get("TEMP", os.environ.get("TMPDIR", "/tmp"))), "malsight_uploads"),
)

SUPPORTED_EXTENSIONS = {
    ".exe", ".dll", ".pdf", ".zip", ".py",
    ".sh", ".bash", ".doc", ".docx", ".xls", ".xlsx",
}

_HEADERS = {"X-API-Key": MALSIGHT_API_KEY}


def _decode_mime_words(s: str | None) -> str:
    if not s:
        return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s or ""


def _extract_attachments(msg):
    """Yield (filename, content_type, data) for each supported attachment."""
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        filename = _decode_mime_words(filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            logger.info("Skipping unsupported attachment: %s", filename)
            continue
        data = part.get_payload(decode=True)
        if data:
            yield filename, part.get_content_type() or "application/octet-stream", data


def _submit_for_analysis(file_path: str, filename: str) -> str | None:
    """POST file to /analyze. Returns job_id or None on failure."""
    try:
        with open(file_path, "rb") as fh:
            resp = requests.post(
                f"{MALSIGHT_API_URL}/analyze",
                files={"file": (filename, fh, "application/octet-stream")},
                data={"mode": "standard"},
                headers=_HEADERS,
                timeout=30,
            )
        resp.raise_for_status()
        return resp.json().get("job_id")
    except Exception as exc:
        logger.error("Failed to submit %s: %s", filename, exc)
        return None


def _poll_for_verdict(job_id: str, max_wait: int = 180, interval: int = 5) -> dict | None:
    """Poll /report/{job_id} until complete or timeout. Returns report dict or None."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            resp = requests.get(
                f"{MALSIGHT_API_URL}/report/{job_id}",
                headers=_HEADERS,
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "complete":
                return data.get("report", {})
            if data.get("status") == "failed":
                logger.warning("Job %s failed: %s", job_id, data.get("error"))
                return None
        except Exception as exc:
            logger.warning("Poll error for %s: %s", job_id, exc)
        time.sleep(interval)
    logger.warning("Job %s timed out after %ds", job_id, max_wait)
    return None


def process_email(email_id: str) -> None:
    """Entry point called by RQ worker. Scans all attachments and updates delivery status."""
    logger.info("Processing email %s", email_id)

    email = get_email(email_id)
    if email is None:
        logger.error("Email %s not found in DB", email_id)
        return

    raw = email.get("raw_message")
    if isinstance(raw, memoryview):
        raw = bytes(raw)

    if not raw:
        update_email_status(email_id, "delivered")
        return

    msg = message_from_bytes(raw)
    attachments_list = list(_extract_attachments(msg))

    if not attachments_list:
        logger.info("Email %s: no scannable attachments — delivering", email_id)
        update_email_status(email_id, "delivered")
        return

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # ── Submit all attachments ────────────────────────────────────────────────
    submitted: list[tuple[str, str | None, str]] = []  # (attachment_id, job_id, filename)

    for filename, content_type, data in attachments_list:
        sha256 = hashlib.sha256(data).hexdigest()
        staging_path = os.path.join(UPLOAD_DIR, f"{email_id}_{sha256[:8]}_{filename}")

        with open(staging_path, "wb") as fh:
            fh.write(data)

        attachment_id = save_email_attachment(
            email_id, filename, content_type, len(data), sha256, staging_path,
        )

        job_id = _submit_for_analysis(staging_path, filename)
        if job_id:
            update_attachment_job(attachment_id, job_id)
        else:
            # Submission failed — mark suspicious as safe default
            update_attachment_verdict(attachment_id, "suspicious", 0, "scan_error", "medium")

        submitted.append((attachment_id, job_id, filename))

    # ── Poll for verdicts ─────────────────────────────────────────────────────
    for attachment_id, job_id, filename in submitted:
        if job_id is None:
            continue

        report = _poll_for_verdict(job_id)
        if report:
            verdict = report.get("verdict", "suspicious")
            confidence = report.get("confidence", 0)
            threat_category = report.get("threat_category", "")
            severity = report.get("severity", "medium")
            mitre = report.get("mitre_techniques", [])
        else:
            verdict, confidence, threat_category, severity, mitre = (
                "suspicious", 0, "scan_timeout", "medium", []
            )

        update_attachment_verdict(attachment_id, verdict, confidence, threat_category, severity)

        if verdict == "malicious":
            create_quarantine_log(
                email_id, attachment_id,
                f"Malicious: {threat_category or 'unknown'}",
                verdict, mitre,
            )

    # ── Delivery decision ─────────────────────────────────────────────────────
    attachments = get_attachments_for_email(email_id)
    verdicts = [a["verdict"] for a in attachments if a.get("verdict")]

    if "malicious" in verdicts:
        update_email_status(email_id, "quarantined")
        logger.info("Email %s QUARANTINED — malicious attachment", email_id)
    elif "suspicious" in verdicts:
        update_email_status(email_id, "warned")
        logger.info("Email %s WARNED — suspicious attachment", email_id)
    else:
        update_email_status(email_id, "delivered")
        logger.info("Email %s DELIVERED — all clean", email_id)

    # ── Cleanup staging files ─────────────────────────────────────────────────
    for a in get_attachments_for_email(email_id):
        path = a.get("staging_path")
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
