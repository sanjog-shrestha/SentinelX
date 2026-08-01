ALTER TABLE events ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE events SET event_id = 'legacy-' || id WHERE event_id IS NULL;
ALTER TABLE events ALTER COLUMN event_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_id ON events (event_id);