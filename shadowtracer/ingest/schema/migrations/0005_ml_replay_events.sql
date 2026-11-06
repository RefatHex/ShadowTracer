-- Phase 7.0: one row per replayed dataset event: which run and dataset, the replay agent, the
-- ATT&CK label, the event's ORIGINAL time (from the dataset) and when it was injected.
CREATE TABLE IF NOT EXISTS __DATABASE__.ml_replay_events ON CLUSTER lab_cluster
(
    run_id        String,
    dataset_id    LowCardinality(String),
    seq           UInt64,
    agent_id      LowCardinality(String),
    technique     LowCardinality(String),
    original_time Nullable(DateTime64(3)),
    injected_at   DateTime64(3),
    line_sha256   String
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/__KEEPER_PREFIX__{shard}/ml_replay_events', '{replica}')
PARTITION BY toYYYYMM(injected_at)
ORDER BY (run_id, seq);
