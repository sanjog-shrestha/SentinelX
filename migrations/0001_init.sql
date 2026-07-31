CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL       PRIMARY KEY,
    source      TEXT            NOT NULL,
    category    TEXT            NOT NULL DEFAULT 'generic',
    severity    TEXT            NOT NULL DEFAULT 'info',
    message     TEXT            NOT NULL,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_created_at ON events (created_at DESC);