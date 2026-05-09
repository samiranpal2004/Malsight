-- MalSight base schema: jobs + reports tables
-- Run once on fresh PostgreSQL instance

CREATE TABLE IF NOT EXISTS jobs (
    id              UUID        PRIMARY KEY,
    status          TEXT        NOT NULL DEFAULT 'queued',
    mode            TEXT        NOT NULL DEFAULT 'standard',
    filename        TEXT        NOT NULL,
    sha256          TEXT,
    file_size_bytes BIGINT      DEFAULT 0,
    mime_type       TEXT        DEFAULT '',
    staging_path    TEXT        DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    current_step    INTEGER,
    current_action  TEXT
);

CREATE TABLE IF NOT EXISTS reports (
    job_id              UUID    PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    verdict             TEXT,
    confidence          INTEGER,
    threat_category     TEXT,
    severity            TEXT,
    summary             TEXT,
    recommended_action  TEXT,
    tools_called        INTEGER,
    analysis_mode       TEXT,
    incomplete          BOOLEAN DEFAULT FALSE,
    report_json         JSONB,
    reasoning_chain     JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
