-- HISTORICAL RECORD ONLY - superseded by schema/events_schema.sql (Phase
-- 5A Step 0 consolidated this and schema/001_events.sql, which had since
-- absorbed this fix directly, into one parameterized source). Nothing
-- applies this file any more; kept for the incident narrative below.
--
-- Phase 3 follow-up 1: the hourly rollup double-counted on replay.
--
-- Root cause: a MATERIALIZED VIEW fires once per inserted block, before
-- ReplacingMergeTree's merge-time dedup ever runs. Replaying the same
-- Kafka range re-inserts the same alerts into `events` (caught correctly
-- by FINAL there), but the rollup's SummingMergeTree had already summed
-- both copies by the time any merge could have removed the duplicate -
-- there is no FINAL-equivalent for a SummingMergeTree that undoes an
-- already-summed value. Reproduced before this fix: 20 known events,
-- replayed once -> raw events 40 / FINAL events 20 (correct) / rollup sum
-- 40 (wrong - see shadowtracer/docs/PHASE3_DATA_PLATFORM.md).
--
-- Fix: count DISTINCT alert identity (cluster_node, alert_id) using
-- uniqExact's merge-safe aggregate state instead of a plain count(). A
-- uniqExact state can be fed the same identity any number of times, from
-- any number of separate insert blocks, and the merged result is still
-- the exact distinct count - duplicates genuinely cannot inflate it,
-- independent of whether merges have run, independent of the insert-time
-- dedup token fix in writer.py (belt and suspenders, not a replacement for
-- it: the token reduces how often a duplicate row is created at all; this
-- makes the rollup correct even when one slips through).

DROP TABLE IF EXISTS shadowtracer.events_hourly_rollup_mv ON CLUSTER lab_cluster;
DROP TABLE IF EXISTS shadowtracer.events_hourly_rollup ON CLUSTER lab_cluster;

CREATE TABLE shadowtracer.events_hourly_rollup ON CLUSTER lab_cluster
(
    tenant_id    LowCardinality(String),
    hour         DateTime,
    agent_id     LowCardinality(String),
    agent_name   LowCardinality(String),
    rule_id      String,
    rule_level   UInt8,
    identity_state AggregateFunction(uniqExact, String, String)
)
-- "_v2" Keeper path, not table name: recreating a Replicated table at the
-- same Keeper path it just occupied races the DROP's ZK cleanup - CREATE
-- can land before Keeper has forgotten the old table's engine metadata
-- (hit this for real: "METADATA_MISMATCH ... mode of merge operation:
-- Stored in ZooKeeper: 2, local: 3"). A fresh path sidesteps the race.
ENGINE = ReplicatedAggregatingMergeTree('/clickhouse/tables/{shard}/events_hourly_rollup_v2', '{replica}')
PARTITION BY (tenant_id, toYYYYMM(hour))
ORDER BY (tenant_id, hour, agent_id, rule_id, rule_level);

CREATE MATERIALIZED VIEW shadowtracer.events_hourly_rollup_mv ON CLUSTER lab_cluster
TO shadowtracer.events_hourly_rollup
AS
SELECT
    tenant_id,
    toStartOfHour(toDateTime(time)) AS hour,
    agent_id,
    agent_name,
    rule_id,
    rule_level,
    uniqExactState(cluster_node, alert_id) AS identity_state
FROM shadowtracer.events
GROUP BY tenant_id, hour, agent_id, agent_name, rule_id, rule_level;

-- Console rule (see PHASE3_DATA_PLATFORM.md): read the rollup only through
-- this kind of query - uniqExactMerge forces a correct merge of every
-- matching state regardless of which background merges have happened:
--
--   SELECT tenant_id, hour, agent_id, rule_id, rule_level,
--          uniqExactMerge(identity_state) AS event_count
--   FROM shadowtracer.events_hourly_rollup
--   GROUP BY tenant_id, hour, agent_id, rule_id, rule_level
