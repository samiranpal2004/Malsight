"""
Gmail watch renewal + polling worker.

Runs on a loop (GMAIL_POLL_INTERVAL seconds, default 60).

Two modes:
  1. Renewal only (default): renews gmail.users.watch() for accounts expiring
     within 24 hours.  Requires Pub/Sub push to be configured.

  2. Poll mode (GMAIL_POLL_MODE=true): additionally polls each account's
     Gmail inbox for new messages.  Use this when Pub/Sub webhooks are not
     reachable (e.g. localhost / hackathon demo without ngrok).
"""
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv()

# Support both: standalone `python renewal.py` (from project root or gmail_connector/)
# and package import `from gmail_connector import renewal`
if __package__:
    from gmail_connector import oauth
    from gmail_connector.db import get_all_active_accounts, update_access_token, update_watch_expiry, update_history_id
else:
    # Running as __main__ — ensure the project root is on the path
    _project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)
    from gmail_connector import oauth
    from gmail_connector.db import get_all_active_accounts, update_access_token, update_watch_expiry, update_history_id

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

POLL_INTERVAL  = int(os.environ.get("GMAIL_POLL_INTERVAL", "60"))
GMAIL_POLL_MODE = os.environ.get("GMAIL_POLL_MODE", "false").lower() == "true"
REDIS_URL      = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def renew_watches() -> None:
    """Renew watch() for accounts whose expiry is within the next 24 hours."""
    accounts = get_all_active_accounts()
    cutoff   = datetime.now(timezone.utc) + timedelta(hours=24)

    for account in accounts:
        expiry = account.get("watch_expiry")
        if expiry:
            if isinstance(expiry, datetime):
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry > cutoff:
                    continue  # Still valid for more than 24 hours
        # Expired or no watch registered — renew
        email_address = account["email_address"]
        try:
            service, creds = oauth.build_service(
                account["access_token"],
                account["refresh_token"],
                account.get("token_expiry"),
            )
            service, creds = oauth.refresh_if_needed(
                service, creds,
                lambda t, e, ea=email_address: update_access_token(ea, t, e),
            )
            history_id, watch_expiry = oauth.start_watching(service)
            update_watch_expiry(email_address, watch_expiry)
            logger.info("Renewed watch for %s — expires %s", email_address, watch_expiry)
        except Exception as exc:
            logger.error("Failed to renew watch for %s: %s", email_address, exc)


def poll_new_messages() -> None:
    """
    Poll each active account for new messages and process them directly in a
    background thread.  We intentionally avoid enqueuing to the main 'malsight'
    RQ queue here because process_new_messages blocks for up to 180 s waiting
    for the scan verdict — if both the gmail job and the analyze_file_job land
    on the same single-worker queue the analyze job can never start, causing
    the gmail job to time-out and be marked as AbandonedJobError.
    Running in a thread inside this container is fine: the gmail_connector image
    already has all required Google API dependencies.
    """
    import threading
    from gmail_connector.processor import process_new_messages

    accounts = get_all_active_accounts()
    for account in accounts:
        email_address = account["email_address"]
        try:
            service, creds = oauth.build_service(
                account["access_token"],
                account["refresh_token"],
                account.get("token_expiry"),
            )
            service, creds = oauth.refresh_if_needed(
                service, creds,
                lambda t, e, ea=email_address: update_access_token(ea, t, e),
            )
            profile         = service.users().getProfile(userId="me").execute()
            current_history = str(profile["historyId"])
            last_history    = account.get("last_history_id")

            if not last_history:
                # First poll — record baseline historyId; process on next cycle
                update_history_id(email_address, current_history)
                logger.info(
                    "Recorded baseline historyId=%s for %s", current_history, email_address
                )
            elif current_history != last_history:
                logger.info(
                    "New messages detected for %s (%s → %s) — spawning thread",
                    email_address, last_history, current_history,
                )
                # Update history before spawning to avoid duplicate processing on next poll
                update_history_id(email_address, current_history)
                threading.Thread(
                    target=process_new_messages,
                    args=(email_address, last_history, current_history),
                    daemon=True,
                    name=f"gmail-proc-{email_address}",
                ).start()
            else:
                logger.debug("No new messages for %s (historyId=%s)", email_address, current_history)
        except Exception as exc:
            logger.error("Poll error for %s: %s", email_address, exc)


if __name__ == "__main__":
    logger.info(
        "Gmail renewal worker started — interval=%ds  poll_mode=%s",
        POLL_INTERVAL, GMAIL_POLL_MODE,
    )
    while True:
        try:
            if not GMAIL_POLL_MODE:
                renew_watches()
            if GMAIL_POLL_MODE:
                poll_new_messages()
        except Exception as exc:
            logger.error("Renewal loop error: %s", exc)
            if "connection" in str(exc).lower():
                try:
                    from api.db import _pool
                    if _pool:
                        _pool.closeall()
                except Exception:
                    pass
            time.sleep(POLL_INTERVAL)
            continue
        time.sleep(POLL_INTERVAL)
