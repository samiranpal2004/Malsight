"""Gmail OAuth 2.0 flow, watch() registration, and label management."""
import logging
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

GMAIL_CLIENT_ID     = os.environ.get("GMAIL_CLIENT_ID", "")
GMAIL_CLIENT_SECRET = os.environ.get("GMAIL_CLIENT_SECRET", "")
GCP_PROJECT_ID      = os.environ.get("GCP_PROJECT_ID", "")
PUBSUB_TOPIC        = os.environ.get("PUBSUB_TOPIC", "malsight-gmail-notifications")
REDIRECT_URI        = os.environ.get(
    "GMAIL_REDIRECT_URI", "http://localhost:8000/gmail/oauth/callback"
)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]

# Label definitions: field_key → Gmail label spec
# All colors must be from Gmail's fixed palette:
# https://developers.google.com/gmail/api/reference/rest/v1/users.labels
MALSIGHT_LABELS: dict[str, dict] = {
    "label_scanning": {
        "name": "MALSIGHT_SCANNING",
        "color": {"textColor": "#ffffff", "backgroundColor": "#4a86e8"},  # blue
    },
    "label_clean": {
        "name": "MALSIGHT_CLEAN",
        "color": {"textColor": "#ffffff", "backgroundColor": "#16a766"},  # green
    },
    "label_suspicious": {
        "name": "MALSIGHT_SUSPICIOUS",
        "color": {"textColor": "#000000", "backgroundColor": "#ffad47"},  # orange
    },
    "label_malicious": {
        "name": "MALSIGHT_MALICIOUS",
        "color": {"textColor": "#ffffff", "backgroundColor": "#e07798"},  # red
    },
    "label_quarantine": {
        "name": "MALSIGHT_QUARANTINE",
        "color": {"textColor": "#ffffff", "backgroundColor": "#cc3a21"},  # dark red
    },
}


def _client_config() -> dict:
    return {
        "web": {
            "client_id": GMAIL_CLIENT_ID,
            "client_secret": GMAIL_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI],
        }
    }


def get_auth_url(state: str) -> tuple[str, str | None]:
    """
    Build the Google OAuth consent URL.
    Returns (url, code_verifier).
    google-auth-oauthlib 1.x auto-generates PKCE — we must capture the
    code_verifier here and pass it back to exchange_code() later.
    """
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=REDIRECT_URI)
    url, _ = flow.authorization_url(access_type="offline", prompt="consent", state=state)

    # google-auth-oauthlib 1.x exposes code_verifier directly on the Flow object
    code_verifier: str | None = getattr(flow, "code_verifier", None)

    # Fallback: check the underlying OAuth2Session and its internal client
    if not code_verifier:
        session = getattr(flow, "oauth2session", None)
        if session is not None:
            code_verifier = getattr(session, "code_verifier", None) or getattr(
                getattr(session, "_client", None), "code_verifier", None
            )

    logger.debug("get_auth_url: code_verifier extracted = %s", bool(code_verifier))
    return url, code_verifier


def exchange_code(code: str, code_verifier: str | None = None) -> dict:
    """
    Exchange an authorization code for tokens.
    code_verifier must be supplied when the auth URL was built with PKCE (S256).
    """
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=REDIRECT_URI)

    # Pass code_verifier directly as a kwarg — flow.fetch_token forwards **kwargs
    # to oauth2session.fetch_token, which includes it in the POST body.
    fetch_kwargs: dict = {"code": code}
    if code_verifier:
        fetch_kwargs["code_verifier"] = code_verifier
    logger.debug("exchange_code: code_verifier present = %s", bool(code_verifier))

    flow.fetch_token(**fetch_kwargs)
    creds = flow.credentials
    return {
        "access_token":  creds.token,
        "refresh_token": creds.refresh_token,
        "token_expiry":  creds.expiry,
    }


def build_service(
    access_token: str,
    refresh_token: str,
    token_expiry=None,
):
    """Build an authorized Gmail API service object. Returns (service, creds)."""
    expiry = None
    if token_expiry:
        if isinstance(token_expiry, datetime):
            # psycopg2 returns timezone-aware; google-auth needs naive UTC
            expiry = token_expiry.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            expiry = token_expiry

    creds = Credentials(
        token=access_token,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GMAIL_CLIENT_ID,
        client_secret=GMAIL_CLIENT_SECRET,
        scopes=SCOPES,
        expiry=expiry,
    )
    service = build("gmail", "v1", credentials=creds, cache_discovery=False)
    return service, creds


def refresh_if_needed(service, creds, db_update_fn=None):
    """Refresh the access token if expired. Calls db_update_fn(token, expiry) on refresh."""
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        logger.info("Access token refreshed")
        if db_update_fn:
            db_update_fn(creds.token, creds.expiry)
        # Rebuild service with refreshed creds
        service = build("gmail", "v1", credentials=creds, cache_discovery=False)
    return service, creds


def get_email_address(service) -> str:
    """Return the authenticated user's email address."""
    profile = service.users().getProfile(userId="me").execute()
    return profile["emailAddress"]


def start_watching(service) -> tuple[str, datetime]:
    """
    Register Pub/Sub push notifications for the account.
    Returns (historyId, watch_expiry).
    watch() expires after 7 days — must be renewed.
    """
    body = {
        "topicName": f"projects/{GCP_PROJECT_ID}/topics/{PUBSUB_TOPIC}",
        "labelIds": ["INBOX"],
        "labelFilterBehavior": "INCLUDE",
    }
    response = service.users().watch(userId="me", body=body).execute()
    expiry = datetime.fromtimestamp(int(response["expiration"]) / 1000, tz=timezone.utc)
    return str(response["historyId"]), expiry


def stop_watching(service) -> None:
    """Stop push notifications for the authenticated user."""
    try:
        service.users().stop(userId="me").execute()
    except Exception as exc:
        logger.warning("stop() call failed (may already be stopped): %s", exc)


def ensure_labels(service) -> dict[str, str]:
    """
    Create MalSight labels in the user's Gmail if they don't exist.
    Returns mapping of label_key → Gmail label ID.
    """
    existing = service.users().labels().list(userId="me").execute().get("labels", [])
    name_to_id = {lbl["name"]: lbl["id"] for lbl in existing}

    result: dict[str, str] = {}
    for key, spec in MALSIGHT_LABELS.items():
        name = spec["name"]
        if name in name_to_id:
            result[key] = name_to_id[name]
            logger.debug("Label %s already exists: %s", name, name_to_id[name])
        else:
            created = service.users().labels().create(
                userId="me",
                body={
                    "name": name,
                    "labelListVisibility": "labelShow",
                    "messageListVisibility": "show",
                    "color": spec["color"],
                },
            ).execute()
            result[key] = created["id"]
            logger.info("Created Gmail label: %s → %s", name, created["id"])

    return result
