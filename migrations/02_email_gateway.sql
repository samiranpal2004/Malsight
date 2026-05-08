-- MalSight email gateway schema
-- Depends on 01_base_schema.sql (jobs table must exist)

CREATE TABLE IF NOT EXISTS emails (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    received_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mail_from         TEXT        NOT NULL,
    rcpt_to           TEXT[]      NOT NULL,
    subject           TEXT,
    sender_display    TEXT,
    reply_to          TEXT,
    body_text         TEXT,
    body_html         TEXT,
    raw_message       BYTEA,
    delivery_status   TEXT        NOT NULL DEFAULT 'held'
                      CHECK (delivery_status IN ('held', 'delivered', 'warned', 'quarantined')),
    recipient_address TEXT        NOT NULL,
    source            TEXT        NOT NULL DEFAULT 'smtp'
                      CHECK (source IN ('smtp', 'gmail')),
    gmail_message_id  TEXT
);

CREATE TABLE IF NOT EXISTS email_attachments (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id        UUID        NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    filename        TEXT        NOT NULL,
    content_type    TEXT,
    file_size_bytes BIGINT,
    sha256          CHAR(64),
    job_id          UUID        REFERENCES jobs(id) ON DELETE SET NULL,
    verdict         TEXT        CHECK (verdict IN ('benign', 'suspicious', 'malicious')),
    confidence      INTEGER,
    threat_category TEXT,
    severity        TEXT,
    staging_path    TEXT
);

CREATE TABLE IF NOT EXISTS quarantine_log (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    quarantined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    email_id         UUID        NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    attachment_id    UUID        REFERENCES email_attachments(id) ON DELETE SET NULL,
    reason           TEXT,
    verdict          TEXT,
    mitre_techniques JSONB
);

CREATE INDEX IF NOT EXISTS idx_emails_recipient  ON emails (recipient_address);
CREATE INDEX IF NOT EXISTS idx_emails_status     ON emails (delivery_status);
CREATE INDEX IF NOT EXISTS idx_emails_received   ON emails (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_attachments_job   ON email_attachments (job_id);
CREATE INDEX IF NOT EXISTS idx_attachments_email ON email_attachments (email_id);
