-- Phase 3 data platform: the events table and its hourly rollups. The
-- ONE schema source (Phase 5A Step 0) - applied to both the lab's real
-- database and the isolated test database by substituting the two
-- placeholders below, so the two environments can never silently drift
-- apart the way schema/001_events.sql and
-- schema/test_only_clickhouse_schema.sql used to (superseded by this
-- file - see shadowtracer_ingest/clickhouse_schema.py for the Python
-- side that does the substitution, used by both
-- shadowtracer/ingest/tests/conftest.py and
-- shadowtracer/console/backend/tests/conftest.py, and by
-- deploy/lab/create-clickhouse-schema.py for the lab).
--
--   __DATABASE__      - "shadowtracer" in the lab, "shadowtracer_test" in
--                        tests.
--   __KEEPER_PREFIX__ - "" in the lab, a fresh random token + "/" in
--                        tests every session. A Replicated*MergeTree's
--                        Keeper path is not namespaced by database, so a
--                        shared/fixed path would either collide with the
--                        lab's real tables (test) or race a previous
--                        session's own DROP DATABASE (Keeper's replica
--                        cleanup is asynchronous) - see
--                        shadowtracer_ingest/clickhouse_schema.py.
--
-- Applied with `ON CLUSTER lab_cluster` so both lab replicas get it in
-- one statement (see deploy/lab/clickhouse/config.d/cluster.xml) - this
-- also means a Replicated engine is required (not a plain MergeTree)
-- even for the test database: insert_deduplication_token's block-level
-- dedup, which shadowtracer/ingest/tests/test_writer.py's replay test
-- depends on, is a Replicated*MergeTree-only feature - a plain
-- MergeTree never deduplicates inserted blocks at all (found the hard
-- way building the test schema before this consolidation).
--
-- Dedup design (see shadowtracer/docs/PHASE3_DATA_PLATFORM.md for the
-- full writeup): identity is (tenant_id, cluster_node, alert_id). We use
-- ReplacingMergeTree, which dedups rows that share an identical ORDER BY
-- tuple at merge time. `time` is included in that tuple for query
-- performance (range queries are the common case), which is safe for
-- dedup because a genuine duplicate - a retried produce, a replayed
-- Kafka range - always carries the *same original* `time` as the first
-- copy, it is not a second identity component. Because merges are
-- asynchronous, proving "no duplicate rows" requires querying with FINAL
-- (or running OPTIMIZE ... FINAL first) - see the Step 6 replay test. A
-- production deployment with heavier query load should move dedup
-- counting to the hourly rollups (already duplicate-safe, see below)
-- rather than running FINAL on the raw table at scale.

CREATE DATABASE IF NOT EXISTS __DATABASE__ ON CLUSTER lab_cluster;

CREATE TABLE IF NOT EXISTS __DATABASE__.events ON CLUSTER lab_cluster
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
ENGINE = ReplicatedReplacingMergeTree('/clickhouse/tables/__KEEPER_PREFIX__{shard}/events', '{replica}', ingested_at)
PARTITION BY (tenant_id, toYYYYMM(time))
ORDER BY (tenant_id, time, cluster_node, alert_id)
TTL toDateTime(time) + INTERVAL 90 DAY TO VOLUME 'cold',
    toDateTime(time) + INTERVAL 1 YEAR DELETE
SETTINGS storage_policy = 'hot_cold';

-- Hourly rollups, replicated (so each replica's local rollup table also
-- survives losing the other replica) and duplicate-safe against BOTH
-- cross-replica replication (a standard MATERIALIZED VIEW only fires on
-- local INSERTs, not on rows arriving via replication) AND a replayed
-- Kafka range re-inserting the same alerts (see "the rollup
-- double-counted on replay" in PHASE3_DATA_PLATFORM.md for the bug this
-- previously had, and why uniqExact, not count(), is what makes it safe:
-- a uniqExact state can be fed the same (cluster_node, alert_id) from
-- any number of separate insert blocks and the merged result is still
-- the exact distinct count). The "_v2" Keeper path component (before
-- __KEEPER_PREFIX__) is historical: recreating a Replicated table at the
-- same Keeper path it just occupied races the DROP's ZK cleanup - a
-- fresh path sidesteps the race (see the former
-- schema/002_rollup_dedup_fix.sql for the incident this fixed).

CREATE TABLE IF NOT EXISTS __DATABASE__.events_hourly_rollup ON CLUSTER lab_cluster
(
    tenant_id    LowCardinality(String),
    hour         DateTime,
    agent_id     LowCardinality(String),
    agent_name   LowCardinality(String),
    rule_id      String,
    rule_level   UInt8,
    identity_state AggregateFunction(uniqExact, String, String)
)
ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/__KEEPER_PREFIX__{shard}/events_hourly_rollup_v2', '{replica}')
PARTITION BY (tenant_id, toYYYYMM(hour))
ORDER BY (tenant_id, hour, agent_id, rule_id, rule_level);

CREATE MATERIALIZED VIEW IF NOT EXISTS __DATABASE__.events_hourly_rollup_mv ON CLUSTER lab_cluster
TO __DATABASE__.events_hourly_rollup
AS
SELECT
    tenant_id,
    toStartOfHour(toDateTime(time)) AS hour,
    agent_id,
    agent_name,
    rule_id,
    rule_level,
    uniqExactState(cluster_node, alert_id) AS identity_state
FROM __DATABASE__.events
GROUP BY tenant_id, hour, agent_id, agent_name, rule_id, rule_level;

-- Console rule: always read this rollup as
--   SELECT ..., uniqExactMerge(identity_state) AS event_count
--   FROM __DATABASE__.events_hourly_rollup GROUP BY ...
-- never raw sum(event_count) - there is no such column any more.

-- Phase 5A Step 3: one row per closed incident - the Attack Library's
-- occurrence history. Mutable fingerprint state (label, notes, verdicts,
-- suppression) lives in PostgreSQL; occurrence COUNTS come from here,
-- not a counter column anywhere, so a closer retrying after a crash
-- between this insert and its own PostgreSQL commit can never desync the
-- two - see closer.py. Deliberately a plain (non-deduplicating)
-- ReplicatedMergeTree: always read occurrence counts via
-- uniqExact(incident_id), the same "exact count immune to duplicate
-- insert blocks" pattern events_hourly_rollup already uses, rather than
-- relying on merge-time row dedup.
CREATE TABLE IF NOT EXISTS __DATABASE__.fingerprint_occurrences ON CLUSTER lab_cluster
(
    tenant_id       LowCardinality(String),
    fingerprint_key String,
    incident_id     UInt64,
    closed_at       DateTime64(3),
    alert_count     UInt32
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/__KEEPER_PREFIX__{shard}/fingerprint_occurrences', '{replica}')
PARTITION BY toYYYYMM(closed_at)
ORDER BY (tenant_id, fingerprint_key, incident_id);

-- Console rule: always read occurrence counts as
--   SELECT tenant_id, fingerprint_key, uniqExact(incident_id) AS occurrences
--   FROM __DATABASE__.fingerprint_occurrences GROUP BY tenant_id, fingerprint_key
-- never a plain count() - see this table's own header.

-- No single event may stop the pipeline: one row per dead-lettered event
-- - shipper, writer and correlator all write here directly (dual-write,
-- same call site as the Kafka dead-letter topic produce -
-- shadowtracer_ingest/dead_letter.py) whenever an event fails parsing,
-- normalizing or processing in a way that will never succeed no matter
-- how many times it's retried (a permanently malformed field - NOT a
-- transient failure like ClickHouse/Postgres being briefly unreachable,
-- which retries with backoff instead and never reaches this table at
-- all). /health/detail reads per-tenant counts from here, not from any
-- single component's in-process counter, since those don't survive a
-- restart or aggregate across replicas.
--
-- raw_event_preview is a CAPPED preview (4 KB, dead_letter.py), never the
-- full payload - this table must not become an indefinite store of full
-- attacker-controlled data. raw_event_size/raw_event_sha256 describe the
-- full original payload (sha256 lets anyone who needs it match this row
-- against a replayed/re-shipped copy). TTL bounds how long even the
-- preview is kept - 30 days, this is diagnostic data, not an audit trail.
CREATE TABLE IF NOT EXISTS __DATABASE__.dead_letter_events ON CLUSTER lab_cluster
(
    tenant_id         LowCardinality(String),
    component         LowCardinality(String),
    source_location   String,
    error             String,
    raw_event_preview String CODEC(ZSTD(3)),
    raw_event_size    UInt32,
    raw_event_sha256  FixedString(64),
    failed_at         DateTime64(3)
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/__KEEPER_PREFIX__{shard}/dead_letter_events', '{replica}')
PARTITION BY toYYYYMM(failed_at)
ORDER BY (tenant_id, failed_at)
TTL toDateTime(failed_at) + INTERVAL 30 DAY;
