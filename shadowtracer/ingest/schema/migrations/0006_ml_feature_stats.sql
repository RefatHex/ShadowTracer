-- Phase 7.0: hourly statistics of every model input as served (count, sum, sum of squares),
-- the hook for input-drift detection (ADWIN, 7.2).
CREATE TABLE IF NOT EXISTS __DATABASE__.ml_feature_stats ON CLUSTER lab_cluster
(
    hour            DateTime,
    feature_version LowCardinality(String),
    feature         LowCardinality(String),
    n               UInt64,
    sum             Float64,
    sum_sq          Float64
)
ENGINE = ReplicatedSummingMergeTree('/clickhouse/tables/__KEEPER_PREFIX__{shard}/ml_feature_stats', '{replica}')
ORDER BY (feature_version, feature, hour);
