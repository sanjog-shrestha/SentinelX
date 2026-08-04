CREATE TABLE IF NOT EXISTS assets (
    id         BIGSERIAL PRIMARY KEY,
    host       TEXT        NOT NULL,
    hostname   TEXT        NOT NULL DEFAULT '',
    proto      TEXT        NOT NULL,
    port       INT         NOT NULL,
    service    TEXT        NOT NULL DEFAULT '',
    state      TEXT        NOT NULL DEFAULT 'open',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host, proto, port)
);

CREATE INDEX IF NOT EXISTS idx_assets_host ON assets (host);

CREATE TABLE IF NOT EXISTS asset_changes (
    id          BIGSERIAL PRIMARY KEY,
    change_id   TEXT        NOT NULL UNIQUE,
    kind        TEXT        NOT NULL,
    host        TEXT        NOT NULL,
    proto       TEXT        NOT NULL DEFAULT '',
    port        INT         NOT NULL DEFAULT 0,
    detail      TEXT        NOT NULL DEFAULT '',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asset_changes_detected ON asset_changes (detected_at DESC);