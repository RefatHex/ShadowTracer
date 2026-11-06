-- Phase 7.0 (docs/ML_FOUNDATION.md): per-incident features (one row per incident and feature
-- version, computed only from data up to the incident's close), replayed-event metadata
-- (the dataset's original timestamp per injected event) and hourly feature statistics for
-- input-drift monitoring.
CREATE TABLE IF NOT EXISTS __DATABASE__.ml_incident_features ON CLUSTER lab_cluster
(
    tenant_id       LowCardinality(String),
    incident_id     UInt64,
    feature_version LowCardinality(String),
    closed_at       DateTime64(3),
    computed_at     DateTime64(3),
    features        Map(String, Float64)
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/__KEEPER_PREFIX__{shard}/ml_incident_features', '{replica}', computed_at)
PARTITION BY toYYYYMM(closed_at)
ORDER BY (tenant_id, feature_version, incident_id);
