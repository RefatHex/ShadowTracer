-- Phase 6.1c: ti-matcher hits (THREAT_INTEL.md §3.1). One row per (alert, IOC):
-- ReplacingMergeTree keyed on alert identity + IOC id, so a replay of the alert topic
-- or a redelivered batch collapses to one row (read with FINAL or uniqExact over the
-- key). alert_time decides the partition, and the same alert always has the same
-- alert_time, so duplicates always meet in one partition. matched_at is the version:
-- the latest annotation (current sources/confidence) wins.
CREATE TABLE IF NOT EXISTS __DATABASE__.ti_matches ON CLUSTER lab_cluster
(
    tenant_id       LowCardinality(String),
    cluster_node    String,
    alert_id        String,
    ioc_id          UInt64,
    alert_time      DateTime64(3),
    rule_id         LowCardinality(String),
    field           LowCardinality(String),
    observable_type LowCardinality(String),
    observable      String,
    ioc_value       String,
    sources         Array(String),
    confidence      UInt8,
    origin          LowCardinality(String),
    matched_at      DateTime64(3)
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/__KEEPER_PREFIX__{shard}/ti_matches', '{replica}', matched_at)
PARTITION BY toYYYYMM(alert_time)
ORDER BY (tenant_id, cluster_node, alert_id, ioc_id);
