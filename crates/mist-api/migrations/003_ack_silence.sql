-- Alert ack + silence rules: ack attribution on alerts, mute windows table.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acked_by TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ack_note TEXT;
CREATE TABLE IF NOT EXISTS silences (
    id BIGSERIAL PRIMARY KEY,
    severity TEXT,
    title_contains TEXT,
    alert_id TEXT,
    label_key TEXT,
    label_value TEXT,
    starts_at_ms BIGINT NOT NULL,
    ends_at_ms BIGINT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    comment TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS silences_ends_idx ON silences (ends_at_ms);
