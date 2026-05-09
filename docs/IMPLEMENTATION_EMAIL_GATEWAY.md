# MalSight — Email Gateway & Webmail Client
## Implementation Plan v1.1

**Feature:** Automatic attachment scanning via a custom SMTP mail server + Gmail integration + webmail client  
**Status:** Planning  
**Builds on:** MalSight PRD v2.1 (core pipeline + Gemini Agent Brain)

---

## 1. What This Feature Does

Every email that arrives at the MalSight mail server is intercepted before delivery.
If it has an attachment, the attachment is **automatically submitted to the MalSight
sandbox** for analysis. The email is **held** while analysis runs. The webmail client
shows the email in the inbox — with an inline verdict badge next to every attachment —
and only fully delivers it once the verdict is known.

```
Sender → [Internet] → MalSight SMTP Server
                              │
                    ┌─────────▼──────────┐
                    │  MIME Parser        │
                    │  Extract attachments│
                    └─────────┬──────────┘
                              │  for each attachment
                    ┌─────────▼──────────┐
                    │  MalSight API       │
                    │  POST /analyze      │
                    │  (auto-submitted)   │
                    └─────────┬──────────┘
                              │
              ┌───────────────▼───────────────┐
              │         Verdict?               │
              ├──────────┬────────────────────┤
              │ benign   │ suspicious/malicious│
              │          │                    │
              ▼          ▼                    ▼
         Deliver to   Deliver with        Quarantine
         inbox        ⚠️ warning badge    🔴 block + alert
              │
              └──── Webmail client shows verdict inline
```

---

## 2. Architecture Overview

### 2.1 New Services (add to docker-compose.yml)

| Service | Technology | Responsibility |
|---|---|---|
| `smtp-server` | Python `aiosmtpd` | Receives inbound SMTP on port 25/587. Intercepts all email. |
| `mail-processor` | Python (RQ worker) | Parses MIME, extracts attachments, submits to MalSight API, updates DB. |
| `webmail-api` | FastAPI (extend existing) | New routes for inbox, email detail, attachment verdict status. |
| `webmail-client` | React + Tailwind | Inbox showing emails with inline sandbox verdicts on attachments. |

### 2.2 How It Fits With Existing MalSight

```
Existing:   [React Upload UI] → [FastAPI /analyze] → [Redis RQ] → [Worker + Agent] → [PostgreSQL]

New layer:  [SMTP Server] → [Mail Processor] → [FastAPI /analyze] → (same pipeline)
                                    ↑
                            calls existing API
                            no changes to core engine
```

The email gateway is a **new input channel** to the existing analysis pipeline.
It calls `POST /analyze` the same way the web UI does. The core agent, tools,
and reports are completely unchanged.

---

## 3. Database Schema (New Tables)

```sql
-- Stores every inbound email (with or without attachments)
CREATE TABLE emails (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Envelope
    mail_from       TEXT        NOT NULL,   -- SMTP MAIL FROM
    rcpt_to         TEXT[]      NOT NULL,   -- SMTP RCPT TO (can be multiple)

    -- Headers
    subject         TEXT,
    sender_display  TEXT,                   -- "From:" display name
    reply_to        TEXT,

    -- Body
    body_text       TEXT,                   -- plaintext version
    body_html       TEXT,                   -- HTML version
    raw_message     BYTEA,                  -- full raw MIME (for redelivery)

    -- Delivery state
    -- held       = attachments being scanned, email waiting
    -- delivered  = all attachments clean, email shown in inbox
    -- warned     = delivered but ≥1 attachment suspicious
    -- quarantine = ≥1 attachment malicious, email blocked
    delivery_status TEXT NOT NULL DEFAULT 'held'
                    CHECK (delivery_status IN ('held', 'delivered', 'warned', 'quarantined')),

    -- Who it belongs to (maps to a MalSight user/org)
    recipient_address TEXT NOT NULL
);

-- One row per attachment per email
-- Links email ↔ MalSight analysis job
CREATE TABLE email_attachments (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id        UUID        NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- File metadata
    filename        TEXT        NOT NULL,
    content_type    TEXT,
    file_size_bytes BIGINT,
    sha256          CHAR(64),

    -- Link to existing MalSight jobs table
    -- NULL while analysis is queued/running
    job_id          UUID        REFERENCES jobs(id) ON DELETE SET NULL,

    -- Denormalized verdict for fast inbox queries (copied from reports table)
    -- NULL = still scanning
    verdict         TEXT        CHECK (verdict IN ('benign', 'suspicious', 'malicious')),
    confidence      INTEGER,
    threat_category TEXT,
    severity        TEXT,

    -- Where the attachment file is stored (staging area, deleted after analysis)
    staging_path    TEXT
);

-- Quarantine log — records every blocked email and why
CREATE TABLE quarantine_log (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    quarantined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    email_id        UUID        NOT NULL REFERENCES emails(id),
    attachment_id   UUID        REFERENCES email_attachments(id),
    reason          TEXT,       -- e.g. "Malicious: UPX-packed trojan, C2 detected"
    verdict         TEXT,
    mitre_techniques JSONB      -- top techniques from the report
);

-- Indexes
CREATE INDEX idx_emails_recipient   ON emails (recipient_address);
CREATE INDEX idx_emails_status      ON emails (delivery_status);
CREATE INDEX idx_emails_received    ON emails (received_at DESC);
CREATE INDEX idx_attachments_job    ON email_attachments (job_id);
CREATE INDEX idx_attachments_email  ON email_attachments (email_id);
```

---

## 4. Component Implementations

### 4.1 SMTP Server (`smtp_server.py`)

Uses Python's `aiosmtpd` — a minimal async SMTP server you control completely.
No Postfix needed. Runs on port 25 (or 587 for submission).

```
Architecture decision: aiosmtpd vs Postfix
- Postfix: production-grade but complex to configure for custom handlers
- aiosmtpd: pure Python, async, you write the handler in 50 lines
- For MalSight: aiosmtpd is the right call — we own the interception logic
```

**Flow:**
1. Client connects, sends email via SMTP
2. `MalSightHandler.handle_DATA()` fires on receipt of full message
3. Save raw message to DB (`delivery_status = 'held'`)
4. Enqueue `process_email` job in Redis
5. Respond `250 OK` to sender (always accept — never reject at SMTP layer)

**Key design:** always accept the email at SMTP level. Never reject or bounce.
Analysis happens async after acceptance. This prevents senders from knowing
your mail server exists / is running analysis.

```python
# smtp_server/smtp_server.py (skeleton)
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage
import asyncio, uuid
from db import save_email_to_db
from rq import Queue

class MalSightHandler(AsyncMessage):
    async def handle_DATA(self, server, session, envelope):
        email_id = await save_email_to_db(
            mail_from=envelope.mail_from,
            rcpt_to=envelope.rcpt_tos,
            raw_message=envelope.content,
        )
        # Enqueue async processing
        q = Queue('malsight', connection=redis_conn)
        q.enqueue('mail_processor.process_email', email_id)
        return '250 Message accepted for delivery'

controller = Controller(MalSightHandler(), hostname='0.0.0.0', port=25)
controller.start()
asyncio.get_event_loop().run_forever()
```

---

### 4.2 Mail Processor (`mail_processor.py`)

Called by RQ worker when a new email job is enqueued.

**Steps:**
1. Load raw email from DB
2. Parse MIME using Python `email` stdlib
3. Extract all attachments matching supported types (`.exe .dll .pdf .zip .py .sh .doc .docx .xls .xlsx`)
4. For each attachment:
   - Save to staging area (`/tmp/malsight_uploads/`)
   - Call `POST /analyze` on MalSight API
   - Store returned `job_id` in `email_attachments.job_id`
5. Start polling loop — watch for all jobs to complete
6. Once all verdicts are in, compute overall email delivery decision:

```
Delivery Decision Logic:
  - ANY attachment = malicious  →  quarantine email + alert admin
  - ANY attachment = suspicious →  deliver with ⚠️ warning banner
  - ALL attachments = benign    →  deliver normally
  - No attachments              →  deliver immediately (skip analysis)
```

7. Update `emails.delivery_status` and `email_attachments.verdict`
8. If delivering: mark as `delivered` or `warned`
9. If quarantining: write to `quarantine_log`, send alert to admin

---

### 4.3 New API Routes (extend existing FastAPI)

```
GET  /mail/inbox                     List emails for a recipient (paginated)
GET  /mail/email/{email_id}          Full email detail + attachment verdicts
GET  /mail/email/{email_id}/raw      Download raw MIME message
GET  /mail/attachment/{id}/report    Full MalSight report for this attachment
POST /mail/quarantine/{email_id}/release   Admin: release quarantined email
GET  /mail/quarantine                Admin: quarantine log
GET  /mail/stats                     Emails received, scanned, quarantined counts
```

**Key route — inbox:**
```json
GET /mail/inbox?recipient=user@company.com

[
  {
    "email_id": "uuid",
    "received_at": "2026-05-09T10:32:00Z",
    "from": "vendor@supplier.com",
    "subject": "Invoice #4421",
    "delivery_status": "delivered",
    "attachments": [
      {
        "filename": "invoice_4421.pdf",
        "verdict": "benign",
        "confidence": 94,
        "scan_time_seconds": 8
      }
    ]
  },
  {
    "email_id": "uuid",
    "received_at": "2026-05-09T10:28:00Z",
    "from": "unknown@protonmail.com",
    "subject": "Urgent: Please open attachment",
    "delivery_status": "quarantined",
    "attachments": [
      {
        "filename": "invoice.exe",
        "verdict": "malicious",
        "confidence": 97,
        "threat_category": "trojan",
        "severity": "critical",
        "scan_time_seconds": 45
      }
    ]
  }
]
```

---

### 4.4 Webmail Client (React)

Three views:

**Inbox View**
- Email list sorted by received time
- Each row shows: sender, subject, timestamp, delivery status badge
- Attachment chip inline on each row: `📎 invoice.exe 🔴 MALICIOUS` or `📎 report.pdf 🟢 clean`
- Emails with `delivery_status = 'held'` show a scanning spinner: `📎 data.zip 🔄 Scanning...`
- Auto-refreshes every 3s while any email is `held`

**Email Detail View**
- Full email rendered (HTML body sandboxed in iframe)
- Attachment section shows each file with:
  - Verdict badge + confidence %
  - Threat category + severity
  - "View Full Report" button → opens MalSight report view (already built)
  - Download button (only enabled for benign/warned files)
- Quarantined emails show red banner: `🚨 This email was quarantined. One or more attachments were identified as malicious.`

**Quarantine Dashboard (Admin)**
- Table of all quarantined emails
- Per-row: sender, subject, filename, threat category, ATT&CK techniques
- "Release" button for false positives (requires confirmation)
- Export to CSV

---

## 5. DNS & Mail Server Setup

To receive real email you need two things outside Docker:

### 5.1 Domain Setup

```
# DNS records needed (at your domain registrar / Cloudflare):

# MX record — tells the world where to send email for your domain
company.com.    MX    10    mail.company.com.

# A record — points mail.company.com to your server IP
mail.company.com.    A    YOUR_SERVER_IP

# SPF record — prevents spoofing of outbound mail
company.com.    TXT    "v=spf1 ip4:YOUR_SERVER_IP -all"
```

### 5.2 Port Setup

```bash
# Open port 25 on your server firewall (inbound SMTP)
sudo ufw allow 25/tcp
sudo ufw allow 587/tcp   # submission port (authenticated clients)

# Most cloud providers (AWS, GCP, Azure) BLOCK port 25 by default.
# You need to request it to be unblocked via a support ticket.
# Alternative: use port 2525 for testing, 587 for production.
```

### 5.3 For Hackathon Demo (No Real Domain Needed)

Use a local DNS override + Swaks to simulate inbound email:

```bash
# Install swaks (SMTP testing tool)
sudo apt install swaks

# Send a test email directly to your SMTP server
swaks \
  --to user@company.com \
  --from attacker@evil.com \
  --server localhost:25 \
  --header "Subject: Urgent Invoice" \
  --attach @/path/to/test_payload.exe \
  --body "Please find attached."

# Watch the inbox — attachment should appear as 'held' → verdict appears in ~30s
```

---

## 6. docker-compose.yml Additions

```yaml
# Add these services to existing docker-compose.yml

  smtp-server:
    build:
      context: ./smtp_server
      dockerfile: Dockerfile
    container_name: malsight-smtp
    restart: unless-stopped
    env_file: .env
    environment:
      DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      REDIS_URL: redis://redis:6379/0
      MALSIGHT_API_URL: http://api:8000
      MALSIGHT_API_KEY: ${API_KEY}
      SMTP_HOSTNAME: ${SMTP_HOSTNAME:-mail.company.com}
    ports:
      - "25:25"
      - "587:587"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  mail-processor:
    build:
      context: ./mail_processor
      dockerfile: Dockerfile
    container_name: malsight-mail-processor
    restart: unless-stopped
    env_file: .env
    environment:
      DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      REDIS_URL: redis://redis:6379/0
      MALSIGHT_API_URL: http://api:8000
      MALSIGHT_API_KEY: ${API_KEY}
      UPLOAD_DIR: /tmp/malsight_uploads
    volumes:
      - upload_staging:/tmp/malsight_uploads
    depends_on:
      - smtp-server
      - redis
      - postgres
```

---

## 7. Build Phases

This feature adds **3 new phases** after the existing Phase 6:

### Phase 7 — SMTP Server & Mail Processor (4–5 hours)

- Implement `smtp_server.py` using `aiosmtpd`
- Implement `mail_processor.py` — MIME parsing + attachment extraction
- Add `emails` and `email_attachments` tables to PostgreSQL schema
- Wire mail processor → `POST /analyze` on MalSight API
- Wire verdict polling → update `email_attachments.verdict` when job completes
- Implement delivery decision logic (benign/warned/quarantine)
- Test with Swaks: send emails with EICAR attachment, verify it reaches sandbox

### Phase 8 — Webmail API Routes (2–3 hours)

- Add `/mail/inbox`, `/mail/email/{id}`, `/mail/quarantine` to FastAPI
- Implement verdict propagation: when a job completes, update denormalized
  verdict fields in `email_attachments` via a DB trigger or RQ callback
- Add `quarantine_log` entries + admin release endpoint

### Phase 9 — Webmail Client (4–5 hours)

- Build Inbox view with scanning spinner + verdict badges
- Build Email Detail view with attachment report links
- Build Quarantine Dashboard
- Connect to new API routes
- Auto-refresh logic for `held` emails (poll every 3s)

---

## 8. Key Edge Cases to Handle

| Scenario | Handling |
|---|---|
| Email with no attachments | Deliver immediately, no analysis |
| Attachment type not supported by MalSight | Deliver with note: "File type not scanned" |
| Analysis times out (>90s standard) | Deliver with ⚠️ "Scan inconclusive" warning |
| Same SHA-256 seen before | Look up existing report — skip re-analysis (fast-track) |
| Multi-part ZIP with nested malware | Submit ZIP to MalSight — agent calls `get_dropped_files()` in Deep Scan |
| Email with 5 attachments | Submit all 5 in parallel, hold until ALL complete |
| Malicious email released by admin | Log release in `quarantine_log`, audit trail preserved |
| SMTP flood / spam | Rate-limit by sender IP at SMTP layer (aiosmtpd middleware) |
| HTML-only email, no attachments | Deliver immediately, optionally scan URLs inline (v2 feature) |

---

## 9. Demo Script (Hackathon)

```
1. Open MalSight webmail in browser — show empty inbox

2. Run swaks command:
   swaks --to analyst@company.com --from cfo@evil.com \
         --server localhost:25 \
         --header "Subject: Q2 Financial Report" \
         --attach @invoice_real.pdf \     ← benign
         --attach @payload.exe \          ← EICAR or test malware
         --body "Please review before Monday."

3. Watch inbox — email appears immediately with:
   📎 invoice_real.pdf  🔄 Scanning...
   📎 payload.exe       🔄 Scanning...

4. After ~10s — invoice.pdf flips to 🟢 clean
   After ~30s — payload.exe flips to 🔴 MALICIOUS

5. Email row shows delivery_status = QUARANTINED (red badge)

6. Click "View Full Report" on payload.exe:
   → Full MalSight report with Gemini reasoning chain
   → MITRE ATT&CK techniques
   → IOCs extracted

7. Show quarantine dashboard — email is logged there

Pitch line:
"Zero human action required. The email arrived, the attachment was
analyzed automatically, and the threat was stopped before it ever
reached the analyst's inbox."
```

---

## 10. Gmail Integration

Yes — Gmail attachments can be scanned automatically. Here's how it works and
exactly what to build.

### 10.1 The Key Difference vs Custom SMTP

With your own SMTP server you **intercept before delivery** — the email is held
while analysis runs. With Gmail, **Google delivers the email first** — you cannot
stop that. What you do instead:

```
Custom SMTP:
  Email arrives → HELD → scan → deliver or quarantine

Gmail API:
  Email arrives → Gmail delivers to inbox immediately
                         ↓
              MalSight notified via Pub/Sub webhook (~1-3s delay)
                         ↓
              Attachment downloaded + scanned
                         ↓
              Gmail label applied: 🟢 CLEAN / ⚠️ SUSPICIOUS / 🔴 MALICIOUS
              Malicious emails moved to MALSIGHT_QUARANTINE folder automatically
```

In practice for enterprise use this is still very effective — the label + folder
move happens within ~30-60 seconds of delivery, before a human would typically
open a suspicious file.

---

### 10.2 How Gmail API Scanning Works

Three Gmail API capabilities power this:

**1. Gmail Push Notifications (via Google Cloud Pub/Sub)**
Instead of polling, Gmail pushes a notification to your webhook every time a
new email arrives. This is the right approach — polling the Gmail API every few
seconds would hit rate limits fast.

**2. Gmail API `messages.get()`**
Fetch the full email including MIME parts (attachments) when notified.

**3. Gmail API `users.messages.modify()`**
Apply labels and move emails after scanning completes.

---

### 10.3 Architecture

```
[Gmail Inbox]
     │
     │  Google pushes notification when new mail arrives
     ▼
[Google Cloud Pub/Sub Topic]
     │
     │  Pub/Sub delivers to your webhook (< 3 seconds)
     ▼
[MalSight Webhook: POST /gmail/webhook]  ← new FastAPI route
     │
     │  Fetch full email via Gmail API
     ▼
[Gmail Connector Service]
     │  Extract attachments from MIME
     │  Download each attachment
     ▼
[POST /analyze]  ← existing MalSight API, unchanged
     │
     ▼
[Gemini Agent runs analysis]
     │
     ▼
[Verdict returned]
     │
     ├── benign      → Apply label: MALSIGHT_CLEAN (green)
     ├── suspicious  → Apply label: MALSIGHT_SUSPICIOUS (yellow) + alert
     └── malicious   → Apply label: MALSIGHT_MALICIOUS (red)
                       Move email to label: MALSIGHT_QUARANTINE
                       Send alert to admin
```

---

### 10.4 Setup Steps

#### Step 1 — Google Cloud Project

```
1. Go to https://console.cloud.google.com
2. Create a new project: "MalSight"
3. Enable APIs:
   - Gmail API
   - Cloud Pub/Sub API
4. Create OAuth 2.0 credentials:
   - Type: Web Application
   - Authorized redirect URI: http://localhost:8000/gmail/oauth/callback
   - Download credentials.json
```

#### Step 2 — Create a Pub/Sub Topic

```bash
# Install gcloud CLI then:
gcloud pubsub topics create malsight-gmail-notifications
gcloud pubsub subscriptions create malsight-gmail-sub \
    --topic malsight-gmail-notifications \
    --push-endpoint https://YOUR_SERVER/gmail/webhook \
    --ack-deadline 60

# Grant Gmail permission to publish to your topic
gcloud pubsub topics add-iam-policy-binding malsight-gmail-notifications \
    --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
    --role="roles/pubsub.publisher"
```

#### Step 3 — User OAuth Flow

Users connect their Gmail account through MalSight's UI:

```
1. User clicks "Connect Gmail" in MalSight dashboard
2. MalSight redirects to Google OAuth consent screen
3. User grants permissions:
   - gmail.readonly      (read emails + attachments)
   - gmail.modify        (apply labels, move to quarantine)
   - gmail.labels        (create MalSight labels)
4. Google redirects back to /gmail/oauth/callback with auth code
5. MalSight exchanges code for access_token + refresh_token
6. Tokens stored encrypted in PostgreSQL (gmail_accounts table)
7. MalSight calls gmail.users.watch() to start push notifications
```

Required OAuth scopes:
```
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/gmail.modify
```

#### Step 4 — Start Watching (gmail.users.watch)

Called once per connected account. Tells Gmail to push notifications to your
Pub/Sub topic when new emails arrive.

```python
# gmail_connector/gmail_connector.py

from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

def start_watching(access_token: str, refresh_token: str):
    creds = Credentials(
        token=access_token,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GMAIL_CLIENT_ID,
        client_secret=GMAIL_CLIENT_SECRET,
    )
    service = build("gmail", "v1", credentials=creds)

    response = service.users().watch(
        userId="me",
        body={
            "topicName": "projects/YOUR_PROJECT/topics/malsight-gmail-notifications",
            "labelIds": ["INBOX"],          # only watch inbox
            "labelFilterBehavior": "INCLUDE"
        }
    ).execute()

    # watch() expires after 7 days — store expiration and renew via cron
    return response["historyId"], response["expiration"]
```

`watch()` must be renewed every 7 days. Add a daily cron job in the worker
that renews all active watches.

---

### 10.5 New Service: Gmail Connector

```python
# gmail_connector/webhook_handler.py

# Called by FastAPI POST /gmail/webhook (new route)
# Pub/Sub delivers here when a new Gmail message arrives

import base64, json
from fastapi import Request
from googleapiclient.discovery import build

async def handle_pubsub_push(request: Request):
    body = await request.json()

    # Decode Pub/Sub message
    data = base64.b64decode(body["message"]["data"]).decode()
    notification = json.loads(data)
    # notification = {"emailAddress": "user@gmail.com", "historyId": "12345"}

    email_address = notification["emailAddress"]
    history_id    = notification["historyId"]

    # Enqueue processing job
    q.enqueue("gmail_processor.process_new_messages", email_address, history_id)
    return {"status": "ok"}


# gmail_connector/gmail_processor.py

def process_new_messages(email_address: str, history_id: str):
    """
    Called by RQ worker. Fetches new messages since last historyId,
    extracts attachments, submits each to MalSight /analyze.
    """
    account = db.get_gmail_account(email_address)
    service = build_gmail_service(account.access_token, account.refresh_token)

    # Fetch history since last known historyId
    history = service.users().history().list(
        userId="me",
        startHistoryId=account.last_history_id,
        historyTypes=["messageAdded"],
        labelId="INBOX"
    ).execute()

    for record in history.get("history", []):
        for msg in record.get("messagesAdded", []):
            process_single_message(service, msg["message"]["id"], account)

    # Update last_history_id so next notification picks up from here
    db.update_last_history_id(email_address, history_id)


def process_single_message(service, message_id: str, account):
    # Fetch full message with attachment data
    message = service.users().messages().get(
        userId="me",
        id=message_id,
        format="full"
    ).execute()

    attachments = extract_attachments(service, message)
    if not attachments:
        return  # no attachments — nothing to scan

    # Save email record to DB
    email_id = db.save_gmail_email(message, account.email_address)

    # Submit each attachment to MalSight
    for attachment in attachments:
        file_path = save_attachment_to_staging(attachment)
        response = requests.post(
            f"{MALSIGHT_API_URL}/analyze",
            files={"file": open(file_path, "rb")},
            data={"mode": "standard"},
            headers={"X-API-Key": MALSIGHT_API_KEY}
        )
        job_id = response.json()["job_id"]
        db.save_gmail_attachment(email_id, attachment, job_id)

    # Poll until all jobs complete, then apply Gmail labels
    wait_and_apply_labels(service, message_id, email_id, account)


def wait_and_apply_labels(service, gmail_message_id, email_id, account):
    """Poll MalSight until all attachments for this email have verdicts."""
    while True:
        attachments = db.get_attachments_for_email(email_id)
        pending = [a for a in attachments if a.verdict is None]
        if not pending:
            break
        time.sleep(3)

    # Compute overall verdict
    verdicts = [a.verdict for a in attachments]
    if "malicious" in verdicts:
        label = "MALSIGHT_MALICIOUS"
        also_quarantine = True
    elif "suspicious" in verdicts:
        label = "MALSIGHT_SUSPICIOUS"
        also_quarantine = False
    else:
        label = "MALSIGHT_CLEAN"
        also_quarantine = False

    # Apply label
    label_id = get_or_create_label(service, label)
    service.users().messages().modify(
        userId="me",
        id=gmail_message_id,
        body={"addLabelIds": [label_id]}
    ).execute()

    # Move malicious email out of INBOX into quarantine folder
    if also_quarantine:
        quarantine_label_id = get_or_create_label(service, "MALSIGHT_QUARANTINE")
        service.users().messages().modify(
            userId="me",
            id=gmail_message_id,
            body={
                "addLabelIds": [quarantine_label_id],
                "removeLabelIds": ["INBOX"]
            }
        ).execute()
```

---

### 10.6 Gmail Labels Created in User's Account

MalSight creates these labels automatically on first connection:

| Label | Color | Meaning |
|---|---|---|
| `MALSIGHT_CLEAN` | Green | All attachments scanned — benign |
| `MALSIGHT_SUSPICIOUS` | Yellow | ≥1 attachment flagged suspicious |
| `MALSIGHT_MALICIOUS` | Red | ≥1 attachment confirmed malicious |
| `MALSIGHT_QUARANTINE` | Dark red | Email removed from INBOX — malicious |
| `MALSIGHT_SCANNING` | Blue | Applied on receipt, removed when scan completes |

In Gmail's sidebar the user sees their MalSight labels like any other label folder.
The MALSIGHT_QUARANTINE folder works like a spam folder — email is there but out
of the main inbox.

---

### 10.7 New Database Table

```sql
-- Tracks connected Gmail accounts
CREATE TABLE gmail_accounts (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    connected_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    email_address       TEXT        NOT NULL UNIQUE,

    -- OAuth tokens (store encrypted in production)
    access_token        TEXT        NOT NULL,
    refresh_token       TEXT        NOT NULL,
    token_expiry        TIMESTAMPTZ,

    -- Gmail watch state
    last_history_id     TEXT,       -- last Pub/Sub historyId processed
    watch_expiry        TIMESTAMPTZ,-- watch() expires every 7 days — renew via cron

    -- Status
    active              BOOLEAN     NOT NULL DEFAULT TRUE,

    -- Gmail label IDs (stored after first-time creation)
    label_clean         TEXT,
    label_suspicious    TEXT,
    label_malicious     TEXT,
    label_quarantine    TEXT,
    label_scanning      TEXT
);
```

The `emails` and `email_attachments` tables from Section 3 are reused unchanged.
Add a `source` column to `emails`:

```sql
ALTER TABLE emails ADD COLUMN source TEXT NOT NULL DEFAULT 'smtp'
    CHECK (source IN ('smtp', 'gmail'));
ALTER TABLE emails ADD COLUMN gmail_message_id TEXT;  -- Gmail's message ID
```

---

### 10.8 New API Routes

```
GET  /gmail/connect                  Redirect to Google OAuth consent
GET  /gmail/oauth/callback           Handle OAuth code exchange, start watch()
POST /gmail/webhook                  Pub/Sub push endpoint (called by Google)
GET  /gmail/accounts                 List connected Gmail accounts
DELETE /gmail/accounts/{email}       Disconnect a Gmail account (stop watch)
GET  /gmail/quarantine/{email}       Gmail quarantine folder contents
POST /gmail/release/{gmail_msg_id}   Move email back to INBOX (admin release)
```

---

### 10.9 New docker-compose Service

```yaml
  gmail-connector:
    build:
      context: ./gmail_connector
      dockerfile: Dockerfile
    container_name: malsight-gmail-connector
    restart: unless-stopped
    env_file: .env
    environment:
      DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      REDIS_URL: redis://redis:6379/0
      MALSIGHT_API_URL: http://api:8000
      MALSIGHT_API_KEY: ${API_KEY}
      GMAIL_CLIENT_ID: ${GMAIL_CLIENT_ID}
      GMAIL_CLIENT_SECRET: ${GMAIL_CLIENT_SECRET}
      PUBSUB_PROJECT: ${GCP_PROJECT_ID}
      PUBSUB_TOPIC: malsight-gmail-notifications
      UPLOAD_DIR: /tmp/malsight_uploads
    volumes:
      - upload_staging:/tmp/malsight_uploads
    depends_on:
      - redis
      - postgres
```

Add to `.env.example`:
```
GMAIL_CLIENT_ID=your_google_oauth_client_id
GMAIL_CLIENT_SECRET=your_google_oauth_client_secret
GCP_PROJECT_ID=your_gcp_project_id
```

---

### 10.10 Custom SMTP vs Gmail — Comparison

| Capability | Custom SMTP Server | Gmail Integration |
|---|---|---|
| Intercept before delivery | ✅ Yes — email held during scan | ❌ No — Gmail delivers first |
| Works with existing Gmail accounts | ❌ Requires MX record change | ✅ Yes — connect any Gmail account |
| Setup complexity | Medium (DNS + port 25) | Medium (GCP project + OAuth) |
| Scan delay before user sees email | 0–60s (held) | ~30–60s after delivery |
| Quarantine method | Email never reaches inbox | Email moved to MALSIGHT_QUARANTINE folder |
| Who it's for | Companies owning their domain + MX | Anyone with a Gmail account |
| Works for Google Workspace | ❌ (Workspace uses Google's SMTP) | ✅ Workspace accounts supported |
| Real-time label in Gmail UI | N/A (custom webmail) | ✅ Native Gmail labels |
| Requires cloud infrastructure | Just the server | GCP Pub/Sub (free tier sufficient) |

**Recommendation for MalSight:**

Build both. They serve different customers:
- **Custom SMTP** → companies that own their domain and want full pre-delivery interception
- **Gmail connector** → individuals and teams already on Gmail/Google Workspace who don't control their MX records

The core scanning pipeline, database, and reports are **identical** for both.
The only difference is the input channel.

---

### 10.11 Build Phase (Phase 10)

Add to build plan after Phase 9:

**Phase 10 — Gmail Connector (3–4 hours)**

- Create GCP project, enable Gmail API + Pub/Sub, download `credentials.json`
- Add `gmail_accounts` table migration
- Implement OAuth flow: `/gmail/connect` → consent → `/gmail/oauth/callback` → token store + `watch()`
- Implement Pub/Sub webhook handler: `/gmail/webhook` → decode notification → enqueue job
- Implement `gmail_processor.py`: history fetch → attachment extract → POST /analyze → poll → label
- Create Gmail labels on first account connection
- Add 7-day watch renewal cron job
- Test: connect real Gmail account, send email with EICAR attachment, verify label appears

**Demo addition for hackathon:**
Show Gmail integration alongside the custom SMTP demo.
Send a test email to the connected Gmail account from another address.
Watch the `MALSIGHT_SCANNING` label appear, flip to `MALSIGHT_MALICIOUS`,
and the email disappear from INBOX into `MALSIGHT_QUARANTINE` — all live.

---

## 11. Future Extensions (Post-Hackathon)

- **URL scanning** — extract all links from email body, check domain reputation
- **Sender reputation** — track per-sender malicious rate, auto-flag repeat offenders
- **DKIM / DMARC validation** — flag spoofed senders before even analyzing attachments
- **Slack / Teams alert** — push quarantine notifications to security team channel
- **SIEM integration** — forward all verdicts as structured events to Splunk / ELK
- **Outlook / Microsoft 365** — same pattern as Gmail using Microsoft Graph API + webhook subscriptions instead of Pub/Sub
- **ProtonMail Bridge** — ProtonMail exposes a local IMAP/SMTP bridge; MalSight can connect to it the same way as the custom SMTP server
