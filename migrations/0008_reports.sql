CREATE TABLE IF NOT EXISTS incident_reports (
    id            BIGSERIAL PRIMARY KEY,
    incident_id   TEXT        NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    model         TEXT        NOT NULL,
    summary       TEXT        NOT NULL,
    assessment    TEXT        NOT NULL DEFAULT '',
    confidence    TEXT        NOT NULL DEFAULT 'unknown',
    false_positive_likelihood TEXT NOT NULL DEFAULT 'unknown',
    recommendations JSONB     NOT NULL DEFAULT '[]',
    score_at_generation INT   NOT NULL DEFAULT 0,
    generated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (incident_id)
);