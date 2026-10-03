-- Test-only schema for the isolated shadowtracer_test ClickHouse database
-- (never the real one - see each test suite's conftest.py guard). Same
-- columns, ORDER BY and engine family as
-- shadowtracer/ingest/schema/001_events.sql and 002_rollup_dedup_fix.sql,
-- deliberately still Replicated and ON CLUSTER (not a plain MergeTree):
-- insert_deduplication_token block-level dedup - what
-- test_replay_does_not_inflate_base_table_or_rollup in
-- shadowtracer/ingest/tests/test_writer.py actually proves - is a
-- Replicated*MergeTree-only feature - a plain MergeTree never deduplicates
-- inserted blocks at all - found the hard way when that test still failed
-- (20 rows instead of 10 after a replay) with a non-replicated engine.
-- The Keeper path includes __KEEPER_SESSION__, substituted by the test
-- fixture with a fresh random token every session - a Replicated engine's
-- Keeper path is not namespaced by database, so a fixed path would race
-- its own previous session's DROP DATABASE: Keeper's replica cleanup is
-- asynchronous, and recreating a table at the same path before Keeper has
-- forgotten the old replica fails with REPLICA_ALREADY_EXISTS (hit this
-- for real - the exact class of race 002's own header documents for the
-- production tables, worked around there with a path suffix bump). A
-- fresh path every session sidesteps the race entirely instead of racing
-- it with DROP ... SYNC.

CREATE DATABASE IF NOT EXISTS shadowtracer_test ON CLUSTER lab_cluster;

CREATE TABLE IF NOT EXISTS shadowtracer_test.events ON CLUSTER lab_cluster
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

    src_endpoint_ip   String,
    src_endpoint_port UInt32,
    dst_endpoint_ip   String,
    dst_endpoint_port UInt32,
    actor_user        String,
    target_user       String,

    decoder_name    LowCardinality(String),
    location        LowCardinality(String),

    message         String CODEC(ZSTD(3)),
    extra_fields    Map(String, String),
    raw_event       String CODEC(ZSTD(3)),

    ingested_at     DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/test-__KEEPER_SESSION__/{shard}/events', '{replica}', ingested_at)
PARTITION BY (tenant_id, toYYYYMM(time))
ORDER BY (tenant_id, time, cluster_node, alert_id);

CREATE TABLE IF NOT EXISTS shadowtracer_test.events_hourly_rollup ON CLUSTER lab_cluster
(
    tenant_id    LowCardinality(String),
    hour         DateTime,
    agent_id     LowCardinality(String),
    agent_name   LowCardinality(String),
    rule_id      String,
    rule_level   UInt8,
    identity_state AggregateFunction(uniqExact, String, String)
)
ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/test-__KEEPER_SESSION__/{shard}/events_hourly_rollup', '{replica}')
PARTITION BY (tenant_id, toYYYYMM(hour))
ORDER BY (tenant_id, hour, agent_id, rule_id, rule_level);

CREATE MATERIALIZED VIEW IF NOT EXISTS shadowtracer_test.events_hourly_rollup_mv ON CLUSTER lab_cluster
TO shadowtracer_test.events_hourly_rollup
AS
SELECT
    tenant_id,
    toStartOfHour(toDateTime(time)) AS hour,
    agent_id,
    agent_name,
    rule_id,
    rule_level,
    uniqExactState(cluster_node, alert_id) AS identity_state
FROM shadowtracer_test.events
GROUP BY tenant_id, hour, agent_id, agent_name, rule_id, rule_level;
