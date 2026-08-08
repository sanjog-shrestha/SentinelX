CREATE TABLE IF NOT EXISTS indicators (
    id         BIGSERIAL PRIMARY KEY,
    indicator  TEXT        NOT NULL,
    kind       TEXT        NOT NULL,
    source     TEXT        NOT NULL,
    category   TEXT        NOT NULL DEFAULT 'unknown',
    confidence INT         NOT NULL DEFAULT 50,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (indicator, source)
);

CREATE INDEX IF NOT EXISTS idx_indicators_active
    ON indicators (indicator, expires_at);

ALTER TABLE events
    ADD COLUMN IF NOT EXISTS intel_match      BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS intel_source     TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS intel_category   TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS intel_confidence INT     NOT NULL DEFAULT 0;