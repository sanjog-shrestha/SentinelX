CREATE TABLE IF NOT EXISTS alerts(
    id BIGSERIAL PRIMARY KEY,
    alert_id TEXT NOT NULL UNIQUE,
    rule_Id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    entity TEXT NOT NULL,
    match_count INT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    evidence JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_entity ON alerts (entity);