CREATE TABLE IF NOT EXISTS incidents (
    id          BIGSERIAL PRIMARY KEY,
    incident_id TEXT        NOT NULL UNIQUE,
    entity      TEXT        NOT NULL,
    title       TEXT        NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'open',
    severity    TEXT        NOT NULL DEFAULT 'low',
    score       INT         NOT NULL DEFAULT 0,
    stages      JSONB       NOT NULL DEFAULT '[]',
    alert_count INT         NOT NULL DEFAULT 0,
    first_seen  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL,
    closed_at   TIMESTAMPTZ
);


CREATE INDEX IF NOT EXISTS idx_incidents_open_entity
    ON incidents (entity, last_seen DESC) WHERE status = 'open';

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT        NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    alert_id    TEXT        NOT NULL,
    rule_id     TEXT        NOT NULL,
    stage       TEXT        NOT NULL,
    title       TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (incident_id, alert_id)
);