"""FastAPI routes for Gmail OAuth integration and Pub/Sub webhook."""
import asyncio
import base64
import json
import logging
import os
import secrets

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import RedirectResponse

from api import db
from api.routes import _require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gmail", tags=["gmail"])

FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")
REDIS_URL    = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _get_gmail_modules():
    """Lazy-import gmail_connector — returns (oauth, gmail_db) or raises 503."""
    try:
        from gmail_connector import oauth as _oauth
        from gmail_connector import db as _db
        return _oauth, _db
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Gmail connector unavailable — ensure GMAIL_CLIENT_ID/SECRET are set: {exc}",
        )


# ── OAuth flow ────────────────────────────────────────────────────────────────

@router.get("/connect")
async def gmail_connect():
    """Redirect the browser to Google OAuth consent screen."""
    gmail_oauth, _ = _get_gmail_modules()
    state = secrets.token_urlsafe(16)
    url, code_verifier = await asyncio.to_thread(gmail_oauth.get_auth_url, state)

    # Persist PKCE code_verifier so the callback can complete the token exchange
    if code_verifier:
        try:
            import redis as redis_lib
            redis_conn = redis_lib.from_url(REDIS_URL)
            redis_conn.setex(f"gmail_pkce:{state}", 600, code_verifier)
        except Exception as exc:
            logger.warning("Could not store PKCE verifier in Redis: %s", exc)

    return RedirectResponse(url)


@router.get("/oauth/callback")
async def gmail_oauth_callback(
    code:  str | None = None,
    error: str | None = None,
    state: str | None = None,
):
    """
    Google redirects here after the user approves (or denies) consent.
    Exchange the code for tokens, persist the account, create labels,
    and start Pub/Sub watch() (best-effort — falls back to poll mode).
    """
    if error or not code:
        return RedirectResponse(
            f"{FRONTEND_URL}/gmail/connect?error={error or 'missing_code'}"
        )

    gmail_oauth, gmail_db = _get_gmail_modules()

    try:
        # 1. Retrieve PKCE code_verifier stored during /gmail/connect
        code_verifier: str | None = None
        if state:
            try:
                import redis as redis_lib
                redis_conn = redis_lib.from_url(REDIS_URL)
                cv = redis_conn.get(f"gmail_pkce:{state}")
                if cv:
                    code_verifier = cv.decode() if isinstance(cv, bytes) else cv
                    redis_conn.delete(f"gmail_pkce:{state}")
            except Exception as exc:
                logger.warning("Could not retrieve PKCE verifier from Redis: %s", exc)

        # 2. Exchange code for tokens
        tokens = await asyncio.to_thread(gmail_oauth.exchange_code, code, code_verifier)

        # 2. Build service and get the user's email address
        service, creds = gmail_oauth.build_service(
            tokens["access_token"],
            tokens["refresh_token"],
            tokens.get("token_expiry"),
        )
        email_address = await asyncio.to_thread(gmail_oauth.get_email_address, service)

        # 3. Persist account
        await asyncio.to_thread(
            gmail_db.upsert_gmail_account,
            email_address,
            tokens["access_token"],
            tokens["refresh_token"],
            tokens.get("token_expiry"),
        )

        # 4. Create / resolve MalSight labels
        labels = await asyncio.to_thread(gmail_oauth.ensure_labels, service)
        await asyncio.to_thread(
            gmail_db.update_account_labels,
            email_address,
            labels.get("label_clean"),
            labels.get("label_suspicious"),
            labels.get("label_malicious"),
            labels.get("label_quarantine"),
            labels.get("label_scanning"),
        )

        # 5. Start Pub/Sub watch (best-effort)
        try:
            history_id, watch_expiry = await asyncio.to_thread(
                gmail_oauth.start_watching, service
            )
            await asyncio.to_thread(
                gmail_db.update_watch_expiry, email_address, watch_expiry, history_id
            )
            logger.info("watch() started for %s — historyId=%s", email_address, history_id)
        except Exception as exc:
            logger.warning(
                "watch() failed for %s (Pub/Sub not configured — poll mode will be used): %s",
                email_address, exc,
            )
            # Fall back: capture current historyId so polling can detect future messages
            try:
                profile    = await asyncio.to_thread(
                    lambda: service.users().getProfile(userId="me").execute()
                )
                history_id = str(profile.get("historyId", ""))
                await asyncio.to_thread(gmail_db.update_history_id, email_address, history_id)
            except Exception:
                pass

        return RedirectResponse(
            f"{FRONTEND_URL}/gmail/connect?connected={email_address}"
        )

    except Exception as exc:
        import traceback
        logger.error("OAuth callback failed: %s\n%s", exc, traceback.format_exc())
        # Include the short error message in the redirect so it shows in the UI
        safe_msg = str(exc).replace("&", "").replace("=", "").replace(" ", "+")[:120]
        return RedirectResponse(f"{FRONTEND_URL}/gmail/connect?error={safe_msg}")


# ── Pub/Sub webhook ───────────────────────────────────────────────────────────

@router.post("/webhook")
async def gmail_webhook(request: Request):
    """
    Google Cloud Pub/Sub push endpoint.
    Always returns 200 — Pub/Sub will retry on non-2xx, so we absorb all errors.
    """
    try:
        body      = await request.json()
        message   = body.get("message", {})
        data_b64  = message.get("data", "")
        if not data_b64:
            return {"status": "ok"}

        data          = json.loads(base64.b64decode(data_b64).decode())
        email_address = data.get("emailAddress")
        history_id    = str(data.get("historyId", ""))

        if not email_address:
            return {"status": "ok"}
    except Exception as exc:
        logger.error("Webhook parse error: %s", exc)
        return {"status": "ok"}

    try:
        # Look up the last known historyId so the processor knows where to start.
        # Then advance the stored pointer to avoid reprocessing on the next push.
        _, gmail_db = _get_gmail_modules()
        account = await asyncio.to_thread(gmail_db.get_gmail_account, email_address)
        start_history_id = account.get("last_history_id") if account else None

        if not start_history_id:
            # No baseline yet — record this as the new baseline and skip processing.
            await asyncio.to_thread(gmail_db.update_history_id, email_address, history_id)
            logger.info("Recorded baseline historyId=%s for %s (webhook)", history_id, email_address)
            return {"status": "ok"}

        # Advance pointer before enqueueing to prevent duplicates if the webhook fires twice.
        await asyncio.to_thread(gmail_db.update_history_id, email_address, history_id)

        import redis as redis_lib
        from rq import Queue

        redis_conn = redis_lib.from_url(REDIS_URL)
        # Use the dedicated 'gmail' queue so these jobs are processed by the
        # gmail-connector worker (which has Google API deps) rather than the
        # main malsight worker (which does not), avoiding a single-worker deadlock.
        q = Queue("gmail", connection=redis_conn)
        q.enqueue(
            "gmail_connector.processor.process_new_messages",
            email_address,
            start_history_id,   # where History API should start
            history_id,         # end marker (already saved to DB)
            job_timeout=600,
        )
        logger.info(
            "Queued Gmail processing for %s (%s → %s)",
            email_address, start_history_id, history_id,
        )
    except Exception as exc:
        logger.error("Failed to enqueue Gmail job: %s", exc)

    return {"status": "ok"}


# ── Account management ────────────────────────────────────────────────────────

@router.get("/accounts")
async def list_gmail_accounts(x_api_key: str | None = Header(None)) -> dict:
    """List all connected Gmail accounts."""
    _require_api_key(x_api_key)
    accounts = await asyncio.to_thread(db.list_gmail_accounts)
    return {"accounts": accounts}


@router.delete("/accounts/{email_address}")
async def disconnect_gmail_account(
    email_address: str,
    x_api_key: str | None = Header(None),
) -> dict:
    """Disconnect a Gmail account and stop Pub/Sub watch."""
    _require_api_key(x_api_key)
    gmail_oauth, gmail_db = _get_gmail_modules()

    account = await asyncio.to_thread(gmail_db.get_gmail_account, email_address)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    # Best-effort: stop watch — may fail if token is expired or Pub/Sub not configured
    try:
        service, _ = gmail_oauth.build_service(
            account["access_token"], account["refresh_token"]
        )
        await asyncio.to_thread(gmail_oauth.stop_watching, service)
    except Exception as exc:
        logger.warning("Could not stop watch for %s: %s", email_address, exc)

    await asyncio.to_thread(gmail_db.deactivate_account, email_address)
    return {"disconnected": True, "email": email_address}


@router.post("/release/{gmail_message_id}")
async def release_gmail_quarantine(
    gmail_message_id: str,
    x_api_key: str | None = Header(None),
) -> dict:
    """Move a quarantined Gmail message back to INBOX (admin false-positive release)."""
    _require_api_key(x_api_key)
    gmail_oauth, gmail_db = _get_gmail_modules()

    email = await asyncio.to_thread(db.get_email_by_gmail_id, gmail_message_id)
    if not email:
        raise HTTPException(status_code=404, detail="Message not found")

    account = await asyncio.to_thread(gmail_db.get_gmail_account, email["recipient_address"])
    if not account:
        raise HTTPException(status_code=404, detail="Gmail account not found")

    try:
        service, _ = gmail_oauth.build_service(
            account["access_token"], account["refresh_token"]
        )
        quarantine_label_id = account.get("label_quarantine")
        malicious_label_id  = account.get("label_malicious")
        remove_ids = [lid for lid in [quarantine_label_id, malicious_label_id] if lid]

        await asyncio.to_thread(
            lambda: service.users().messages().modify(
                userId="me",
                id=gmail_message_id,
                body={"addLabelIds": ["INBOX"], "removeLabelIds": remove_ids},
            ).execute()
        )
        # Update MalSight DB status
        await asyncio.to_thread(db.release_quarantine_email, email["email_id"])
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to release message: {exc}")

    return {"released": True, "gmail_message_id": gmail_message_id}
