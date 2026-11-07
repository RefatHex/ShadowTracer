-- Phase 7.1: the ml-scorer's live HalfSpaceTrees anomaly score per alert (0..1, higher = more
-- anomalous). ReplacingMergeTree on the alert's identity + model version, so reprocessing after
-- a restart (the scorer replays its group from the last committed offset) overwrites rather than
-- duplicates. `warm` is 0 while the tenant's model is still in warm-up (score then is 0 and unused).
CREATE TABLE IF NOT EXISTS __DATABASE__.ml_scores ON CLUSTER lab_cluster
(
    tenant_id     LowCardinality(String),
    cluster_node  LowCardinality(String),
    alert_id      String,
    model_version LowCardinality(String),
    score         Float64,
    warm          UInt8,
    reasons       String,                 -- JSON array of {feature, value, mean}
    computed_at   DateTime64(3)
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/__KEEPER_PREFIX__{shard}/ml_scores', '{replica}', computed_at)
ORDER BY (tenant_id, cluster_node, alert_id, model_version);
