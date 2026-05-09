-- MalSight Gmail connector schema
-- Depends on 02_email_gateway.sql (emails table must exist)

CREATE TABLE IF NOT EXISTS gmail_accounts (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    connected_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    email_address       TEXT        NOT NULL UNIQUE,
    access_token        TEXT        NOT NULL,
    refresh_token       TEXT        NOT NULL,
    token_expiry        TIMESTAMPTZ,
    last_history_id     TEXT,
    watch_expiry        TIMESTAMPTZ,
    active              BOOLEAN     NOT NULL DEFAULT TRUE,
    label_clean         TEXT,
    label_suspicious    TEXT,
    label_malicious     TEXT,
    label_quarantine    TEXT,
    label_scanning      TEXT
);

CREATE INDEX IF NOT EXISTS idx_gmail_accounts_email  ON gmail_accounts (email_address);
CREATE INDEX IF NOT EXISTS idx_gmail_accounts_active ON gmail_accounts (active);
