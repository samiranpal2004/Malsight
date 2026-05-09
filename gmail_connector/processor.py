"""
Gmail message processor — RQ worker entry point.

Called by the RQ worker when the webhook or polling loop detects new messages.
Fetches messages since last historyId, extracts attachments, submits to
/analyze, polls for verdicts, applies Gmail labels, and updates the DB.
"""
import base64
import hashlib
import logging
import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

from gmail_connector import oauth
from gmail_connector.db import (
    create_quarantine_log,
    get_attachments_for_email,
    get_gmail_account,
    gmail_message_exists,
    save_email_attachment,
    save_gmail_email,
    update_access_token,
    update_attachment_job,
    update_attachment_verdict,
    update_email_status,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MALSIGHT_API_URL = os.environ.get("MALSIGHT_API_URL", "http://localhost:8000")
_api_keys_raw = os.environ.get("MALSIGHT_API_KEYS") or os.environ.get("MALSIGHT_API_KEY", "")
MALSIGHT_API_KEY = _api_keys_raw.split(",")[0].strip()
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/tmp/malsight_uploads")

SUPPORTED_EXTENSIONS = {
    ".exe", ".dll", ".pdf", ".zip", ".py",
    ".sh", ".bash", ".doc", ".docx", ".xls", ".xlsx",
}

_HEADERS = {"X-API-Key": MALSIGHT_API_KEY}


# ── Public entry point ────────────────────────────────────────────────────────

def process_new_messages(email_address: str, start_history_id: str, end_history_id: str) -> None:
    """
    RQ worker entry point.
    Fetches Gmail history between start_history_id and end_history_id and processes new messages.
    start_history_id: the last known historyId (startHistoryId for the History API call)
    end_history_id: the current historyId captured by the poller (already saved to DB)
    """
    logger.info(
        "Processing Gmail messages for %s (%s → %s)",
        email_address, start_history_id, end_history_id,
    )

    account = get_gmail_account(email_address)
    if not account:
        logger.warning("No active Gmail account for %s — skipping", email_address)
        return

    service, creds = oauth.build_service(
        account["access_token"],
        account["refresh_token"],
        account.get("token_expiry"),
    )
    service, creds = oauth.refresh_if_needed(
        service, creds,
        lambda token, expiry: update_access_token(email_address, token, expiry),
    )

    try:
        history_resp = service.users().history().list(
            userId="me",
            startHistoryId=start_history_id,
            historyTypes=["messageAdded"],
            labelId="INBOX",
        ).execute()
    except Exception as exc:
        logger.error("Failed to fetch Gmail history for %s: %s", email_address, exc)
        return

    for record in history_resp.get("history", []):
        for msg_ref in record.get("messagesAdded", []):
            msg_id = msg_ref["message"]["id"]
            if gmail_message_exists(msg_id):
                logger.debug("Message %s already processed — skipping", msg_id)
                continue
            try:
                _process_single_message(service, msg_id, email_address, account)
            except Exception as exc:
                logger.error("Failed to process message %s: %s", msg_id, exc)


# ── Single message processing ─────────────────────────────────────────────────

def _process_single_message(
    service, message_id: str, email_address: str, account: dict
) -> None:
    message = service.users().messages().get(
        userId="me", id=message_id, format="full"
    ).execute()

    headers = {
        h["name"].lower(): h["value"]
        for h in message.get("payload", {}).get("headers", [])
    }
    subject        = headers.get("subject", "(no subject)")
    mail_from      = headers.get("from", "unknown@unknown.com")
    sender_display = mail_from.split("<")[0].strip().strip('"')
    rcpt_to        = [email_address]

    body_text, body_html = _extract_body(message.get("payload", {}))
    attachments = list(_extract_attachments(service, message_id, message.get("payload", {})))

    if not attachments:
        logger.info("Message %s has no scannable attachments — skipping", message_id)
        return

    email_id = save_gmail_email(
        mail_from=mail_from,
        rcpt_to=rcpt_to,
        subject=subject,
        sender_display=sender_display,
        body_text=body_text,
        body_html=body_html,
        gmail_message_id=message_id,
        recipient_address=email_address,
    )
    logger.info("Saved Gmail message %s as email %s", message_id, email_id)

    # Apply SCANNING label immediately so the user sees activity
    if account.get("label_scanning"):
        try:
            service.users().messages().modify(
                userId="me",
                id=message_id,
                body={"addLabelIds": [account["label_scanning"]]},
            ).execute()
        except Exception as exc:
            logger.warning("Could not apply SCANNING label: %s", exc)

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # Submit all attachments for analysis
    submitted: list[tuple[str, str | None, str]] = []
    for filename, content_type, data in attachments:
        sha256       = hashlib.sha256(data).hexdigest()
        staging_path = os.path.join(UPLOAD_DIR, f"gmail_{email_id}_{sha256[:8]}_{filename}")
        with open(staging_path, "wb") as fh:
            fh.write(data)

        attachment_id = save_email_attachment(
            email_id, filename, content_type, len(data), sha256, staging_path,
        )
        job_id = _submit_for_analysis(staging_path, filename)
        if job_id:
            update_attachment_job(attachment_id, job_id)
        else:
            update_attachment_verdict(attachment_id, "suspicious", 0, "scan_error", "medium")

        submitted.append((attachment_id, job_id, filename))

    # Poll for verdicts
    for attachment_id, job_id, filename in submitted:
        if job_id is None:
            continue
        report = _poll_for_verdict(job_id)
        if report:
            verdict         = report.get("verdict", "suspicious")
            confidence      = report.get("confidence", 0)
            threat_category = report.get("threat_category", "")
            severity        = report.get("severity", "medium")
            mitre           = report.get("mitre_techniques", [])
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

    # Delivery decision
    all_attachments = get_attachments_for_email(email_id)
    verdicts = [a["verdict"] for a in all_attachments if a.get("verdict")]

    if "malicious" in verdicts:
        update_email_status(email_id, "quarantined")
        _apply_gmail_labels(service, message_id, "malicious", account)
        logger.info("Gmail message %s QUARANTINED", message_id)
    elif "suspicious" in verdicts:
        update_email_status(email_id, "warned")
        _apply_gmail_labels(service, message_id, "suspicious", account)
        logger.info("Gmail message %s WARNED", message_id)
    else:
        update_email_status(email_id, "delivered")
        _apply_gmail_labels(service, message_id, "benign", account)
        logger.info("Gmail message %s CLEAN", message_id)

    # Cleanup staging files
    for a in get_attachments_for_email(email_id):
        path = a.get("staging_path")
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass


def _apply_gmail_labels(
    service, message_id: str, worst_verdict: str, account: dict
) -> None:
    """Remove SCANNING label, add verdict label; quarantine malicious messages."""
    add_labels:    list[str] = []
    remove_labels: list[str] = []

    if account.get("label_scanning"):
        remove_labels.append(account["label_scanning"])

    if worst_verdict == "malicious":
        if account.get("label_malicious"):
            add_labels.append(account["label_malicious"])
        if account.get("label_quarantine"):
            add_labels.append(account["label_quarantine"])
        remove_labels.append("INBOX")
    elif worst_verdict == "suspicious":
        if account.get("label_suspicious"):
            add_labels.append(account["label_suspicious"])
    else:
        if account.get("label_clean"):
            add_labels.append(account["label_clean"])

    if add_labels or remove_labels:
        try:
            service.users().messages().modify(
                userId="me",
                id=message_id,
                body={"addLabelIds": add_labels, "removeLabelIds": remove_labels},
            ).execute()
        except Exception as exc:
            logger.error("Failed to apply Gmail labels to %s: %s", message_id, exc)


# ── MIME helpers ──────────────────────────────────────────────────────────────

def _extract_body(payload: dict) -> tuple[str, str]:
    body_text = ""
    body_html = ""
    mime_type = payload.get("mimeType", "")

    if mime_type == "text/plain":
        data = payload.get("body", {}).get("data", "")
        if data:
            body_text = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
    elif mime_type == "text/html":
        data = payload.get("body", {}).get("data", "")
        if data:
            body_html = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
    elif "parts" in payload:
        for part in payload["parts"]:
            t, h = _extract_body(part)
            body_text = body_text or t
            body_html = body_html or h

    return body_text, body_html


def _extract_attachments(service, message_id: str, payload: dict):
    """Yield (filename, content_type, data) for each supported attachment."""
    filename = payload.get("filename", "")
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext in SUPPORTED_EXTENSIONS:
            body          = payload.get("body", {})
            attachment_id = body.get("attachmentId")
            if attachment_id:
                att  = service.users().messages().attachments().get(
                    userId="me", messageId=message_id, id=attachment_id
                ).execute()
                data = base64.urlsafe_b64decode(att["data"] + "==")
            else:
                raw  = body.get("data", "")
                data = base64.urlsafe_b64decode(raw + "==") if raw else b""
            if data:
                yield filename, payload.get("mimeType", "application/octet-stream"), data

    for part in payload.get("parts", []):
        yield from _extract_attachments(service, message_id, part)


# ── API helpers ───────────────────────────────────────────────────────────────

def _submit_for_analysis(file_path: str, filename: str) -> str | None:
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
                logger.warning("Job %s failed", job_id)
                return None
        except Exception as exc:
            logger.warning("Poll error for %s: %s", job_id, exc)
        time.sleep(interval)
    logger.warning("Job %s timed out after %ds", job_id, max_wait)
    return None
