"""FastAPI routes for the email gateway webmail interface."""
import asyncio
import logging

from fastapi import APIRouter, Header, HTTPException

from api import db
from api.routes import _require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mail", tags=["mail"])


@router.get("/inbox")
async def get_inbox(
    recipient: str,
    page: int = 1,
    page_size: int = 20,
    x_api_key: str | None = Header(None),
) -> dict:
    """List emails for a recipient address, newest first."""
    _require_api_key(x_api_key)
    if page < 1:
        raise HTTPException(status_code=400, detail="page must be >= 1")
    items, total = await asyncio.to_thread(db.list_emails, recipient, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/email/{email_id}")
async def get_email(
    email_id: str,
    x_api_key: str | None = Header(None),
) -> dict:
    """Full email detail including body and per-attachment verdicts."""
    _require_api_key(x_api_key)
    email = await asyncio.to_thread(db.get_email_with_attachments, email_id)
    if email is None:
        raise HTTPException(status_code=404, detail="Email not found")
    return email


@router.get("/attachment/{attachment_id}/report")
async def get_attachment_report(
    attachment_id: str,
    x_api_key: str | None = Header(None),
) -> dict:
    """Full MalSight report for a specific email attachment."""
    _require_api_key(x_api_key)
    result = await asyncio.to_thread(db.get_attachment_with_report, attachment_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    return result


@router.get("/quarantine")
async def list_quarantine(
    page: int = 1,
    page_size: int = 20,
    x_api_key: str | None = Header(None),
) -> dict:
    """Admin: list all quarantined emails."""
    _require_api_key(x_api_key)
    items, total = await asyncio.to_thread(db.list_quarantine, page, page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.post("/quarantine/{email_id}/release")
async def release_quarantine(
    email_id: str,
    x_api_key: str | None = Header(None),
) -> dict:
    """Admin: release a quarantined email back to the inbox (false positive)."""
    _require_api_key(x_api_key)
    ok = await asyncio.to_thread(db.release_quarantine_email, email_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Email not found or not quarantined")
    return {"released": True, "email_id": email_id}


@router.get("/stats")
async def get_mail_stats(
    x_api_key: str | None = Header(None),
) -> dict:
    """Email gateway statistics: counts by status and verdict."""
    _require_api_key(x_api_key)
    return await asyncio.to_thread(db.get_mail_stats)
