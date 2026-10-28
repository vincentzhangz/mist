-- mist-api initial schema: flow history + alert lifecycle.
CREATE TABLE IF NOT EXISTS flows (
    id BIGSERIAL PRIMARY KEY,
    node TEXT NOT NULL,
    src_ip INET NOT NULL,
    src_port INT NOT NULL,
    dst_ip INET NOT NULL,
    dst_port INT NOT NULL,
    protocol SMALLINT NOT NULL,
    direction TEXT NOT NULL,
    bytes BIGINT NOT NULL,
    packets BIGINT NOT NULL,
    start_ms BIGINT NOT NULL,
    last_seen_ms BIGINT NOT NULL,
    src_namespace TEXT,
    src_pod TEXT,
    dst_namespace TEXT,
    dst_pod TEXT,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS flows_last_seen_idx ON flows (last_seen_ms DESC);
CREATE INDEX IF NOT EXISTS flows_node_idx ON flows (node, last_seen_ms DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    first_seen_ms BIGINT NOT NULL,
    last_seen_ms BIGINT NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}',
    explanation TEXT,
    state TEXT NOT NULL DEFAULT 'firing',
    occurrences BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alerts_state_idx ON alerts (state, last_seen_ms DESC);
