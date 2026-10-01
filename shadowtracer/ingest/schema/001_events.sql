-- Phase 3 data platform: the events table and its hourly rollups.
-- Applied once with `ON CLUSTER lab_cluster` so both lab replicas get it in
-- one statement (see deploy/lab/clickhouse/config.d/cluster.xml).
--
-- Dedup design (see shadowtracer/docs/PHASE3_DATA_PLATFORM.md for the full
-- writeup): identity is (tenant_id, cluster_node, alert_id). We use
-- ReplacingMergeTree, which dedups rows that share an identical ORDER BY
-- tuple at merge time. `time` is included in that tuple for query
-- performance (range queries are the common case), which is safe for dedup
-- because a genuine duplicate - a retried produce, a replayed Kafka range -
-- always carries the *same original* `time` as the first copy; it is not a
-- second identity component. Because merges are asynchronous, proving "no
-- duplicate rows" requires querying with FINAL (or running OPTIMIZE ...
-- FINAL first) - see the Step 6 replay test. A production deployment with
-- heavier query load should move dedup counting to the hourly rollups
-- (already duplicate-safe, see below) rather than running FINAL on the raw
-- table at scale.

CREATE TABLE IF NOT EXISTS shadowtracer.events ON CLUSTER lab_cluster
(
    tenant_id       LowCardinality(String),
    time            DateTime64(3),
    cluster_node    LowCardinality(String),
    manager_name    LowCardinality(String),
    alert_id        String,

    agent_id        LowCardinality(String),
    agent_name      LowCardinality(String),
    agent_ip        String,

    rule_id         String,
    rule_level      UInt8,
    rule_description String,
    rule_groups     Array(LowCardinality(String)),

    mitre_ids       Array(LowCardinality(String)),
    mitre_tactics   Array(LowCardinality(String)),
    mitre_techniques Array(LowCardinality(String)),

    -- OCSF-aligned names (clear 1:1 matches only - see DECISIONS.md):
    -- time, message, src_endpoint/dst_endpoint. Everything else keeps its
    -- Wazuh name; most of this schema has no clean OCSF equivalent.
    src_endpoint_ip   String,
    src_endpoint_port UInt32,
    dst_endpoint_ip   String,
    dst_endpoint_port UInt32,
    actor_user        String,
    target_user       String,

    decoder_name    LowCardinality(String),
    location        LowCardinality(String),

    message         String CODEC(ZSTD(3)),

    -- Every conditional top-level object the real 4.14.8 shape produces -
    -- not just `data.*`. Fixture evidence (shadowtracer/ingest/fixtures/)
    -- shows FIM puts its payload in a top-level `syscheck` object, not
    -- under `data`; this Map holds both, dot-flattened and prefixed by
    -- source object (e.g. "data.sca.policy_id", "syscheck.sha256_after").
    extra_fields    Map(String, String),

    raw_event       String CODEC(ZSTD(3)),

    ingested_at     DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/{shard}/events', '{replica}', ingested_at)
PARTITION BY (tenant_id, toYYYYMM(time))
ORDER BY (tenant_id, time, cluster_node, alert_id)
TTL toDateTime(time) + INTERVAL 90 DAY TO VOLUME 'cold',
    toDateTime(time) + INTERVAL 1 YEAR DELETE
SETTINGS storage_policy = 'hot_cold';

-- Hourly rollups, replicated (so each replica's local rollup table also
-- survives losing the other replica) and duplicate-safe (see
-- PHASE3_DATA_PLATFORM.md): a standard MATERIALIZED VIEW only fires on
-- local INSERTs to its source table, not on rows arriving via replication,
-- so a row inserted once into one `events` replica contributes to the
-- rollup exactly once even though `events` itself is replicated.

CREATE TABLE IF NOT EXISTS shadowtracer.events_hourly_rollup ON CLUSTER lab_cluster
(
    tenant_id    LowCardinality(String),
    hour         DateTime,
    agent_id     LowCardinality(String),
    agent_name   LowCardinality(String),
    rule_id      String,
    rule_level   UInt8,
    event_count  UInt64
)
ENGINE = ReplicatedSummingMergeTree('/clickhouse/tables/{shard}/events_hourly_rollup', '{replica}', event_count)
PARTITION BY (tenant_id, toYYYYMM(hour))
ORDER BY (tenant_id, hour, agent_id, rule_id, rule_level);

CREATE MATERIALIZED VIEW IF NOT EXISTS shadowtracer.events_hourly_rollup_mv ON CLUSTER lab_cluster
TO shadowtracer.events_hourly_rollup
AS
SELECT
    tenant_id,
    toStartOfHour(toDateTime(time)) AS hour,
    agent_id,
    agent_name,
    rule_id,
    rule_level,
    count() AS event_count
FROM shadowtracer.events
GROUP BY tenant_id, hour, agent_id, agent_name, rule_id, rule_level;
