-- Pod labels on flow endpoints for per-workload policy scoping.
ALTER TABLE flows ADD COLUMN IF NOT EXISTS src_labels JSONB NOT NULL DEFAULT '{}';
ALTER TABLE flows ADD COLUMN IF NOT EXISTS dst_labels JSONB NOT NULL DEFAULT '{}';
