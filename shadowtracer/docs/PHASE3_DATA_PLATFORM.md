# Phase 3 — data platform

The path from a Wazuh manager's `alerts.json` to ClickHouse, through Kafka,
with no lost and no duplicate events. Lab: `deploy/lab/`. Code:
`shadowtracer/ingest/`.

## Design

```
alerts.json (per manager) --[shipper, one per manager]--> Kafka --[writer, consumer group]--> ClickHouse (2 replicas)
```

- **Shipper** (`shadowtracer_ingest/shipper.py`, run via `run_shipper.py`):
  one process per manager node. Tails `alerts.json` (and `archives.json`
  only when raw events are enabled for the tenant) by `(inode, byte
  offset)`, so it survives log rotation without re-reading or skipping
  data. Produces to Kafka with `acks=all`, keyed by `tenant_id:agent_id`.
  Persists its offset only after `producer.flush()` confirms the whole
  batch - see "A real bug this found" below. Malformed lines are skipped
  with a counted warning, never crash the process.
- **Writer** (`shadowtracer_ingest/writer.py`, run via `run_writer.py`): a
  Kafka consumer group that batch-inserts normalised rows into ClickHouse
  (one `client.insert()` call per Kafka partition per batch, never row by
  row - see "Phase 3 follow-up 1" below for why it's per-partition) and
  commits offsets only after every insert in the batch returns
  successfully. Fails over across configured ClickHouse replicas per
  insert (`_FailoverClickHouse`) so losing one replica doesn't stop
  ingestion.
- **Normaliser** (`shadowtracer_ingest/normalizer.py`): parses the real
  4.14.8 alert shape into a ClickHouse row. See "Real shape, not assumed"
  below for what differs from the task's own description of that shape.

## Real shape, not assumed

The normaliser's test fixtures (`shadowtracer/ingest/fixtures/real_alerts_4.14.8.jsonl`)
are 10 alerts captured live from the lab, not hand-written. Two things the
task's own description of the 4.14.8 shape didn't mention, found by
inspecting them:

1. **FIM events put their payload in a top-level `syscheck` object, not
   under `data`.** `data.*` is conditional as described, but it is not the
   only conditional top-level object the real format produces. The
   normaliser flattens both `data.*` and `syscheck.*` into one
   `extra_fields` Map column, dot-prefixed by source
   (`data.sca.policy_id`, `syscheck.sha256_after`), so a future conditional
   top-level key is at least captured (in `extra_fields`) even before
   anyone adds it to the normaliser by name.
2. **`rule.mitre` nests `id`/`tactic`/`technique` as parallel arrays**, not
   a list of objects - confirmed against a real sshd alert
   (`T1110.001`/`Credential Access`/`Password Guessing`, each in its own
   array, matched positionally).

## Alert identity and dedup

Identity is **(tenant_id, cluster_node, alert_id)** per `DECISIONS.md`.
`events` uses `ReplicatedReplacingMergeTree` with
`ORDER BY (tenant_id, time, cluster_node, alert_id)`. `time` is in the sort
key for query performance (time-range queries are the common case), not as
a second identity component - a genuine duplicate (a retried produce, a
replayed Kafka range) always carries the *same original* `time` as the
first copy, so including it in the sort key doesn't weaken the dedup.

**ReplacingMergeTree dedups at merge time, which is asynchronous.** Proving
"no duplicate rows" therefore requires querying with `FINAL` (or running
`OPTIMIZE TABLE ... FINAL` first) - see the Step 6 results below, where
`FINAL` is exactly what distinguishes "2 raw rows" from "1 logical event."
This is a real operational tradeoff: `FINAL` has a non-trivial cost, and a
high-query-load production deployment should move exact counting to the
hourly rollups rather than running `FINAL` on the raw table at scale.

**The hourly rollup had a known gap the raw table doesn't - fixed, Phase 3
follow-up 1.** A `MATERIALIZED VIEW` fires once per local `INSERT`, before
merge-time dedup happens. The original rollup (`SummingMergeTree` +
`count()`) summed every inserted block regardless of later merges -
reproduced directly: 20 known events, consumer group reset to earliest and
replayed once -> raw `events` 40 rows / `FINAL` 20 (correct) / rollup sum
**40 (wrong)**. Fixed in two layers, per the follow-up task:

1. **`events_hourly_rollup` now counts `uniqExactState(cluster_node,
   alert_id)`** (an `AggregatingMergeTree`), not `count()`. A `uniqExact`
   state can be fed the same identity from any number of separate insert
   blocks and the merged result (`uniqExactMerge(identity_state)`) is still
   the exact distinct count - this alone fixed the replay test (confirmed:
   same 20-event replay afterward -> rollup **20**, raw table unchanged at
   40 since this layer doesn't touch the base table). **Console rule: read
   this rollup only via `uniqExactMerge(identity_state) ... GROUP BY ...`
   - there is no plain `event_count` column any more, and summing
   `identity_state` directly is meaningless (it's an opaque aggregate
   state, not a number).**
2. **The writer now inserts one batch per Kafka partition**, each with
   `insert_deduplication_token` set to `f"{topic}:{partition}:{min_offset}-{max_offset}"`.
   A retry/replay that reproduces the same committed offset range produces
   the same token, and ClickHouse drops the duplicate `INSERT` at the block
   level - confirmed empirically (not assumed from docs) that this also
   protects `events_hourly_rollup_mv`, and that
   `deduplicate_blocks_in_dependent_materialized_views` made no observable
   difference either way in this setup (tested both `0`, the default, and
   `1`): an insert rejected by its token is rejected wholesale, before it
   or its dependent MV sees any data, regardless of that setting. That
   setting appears to matter for a different case than ours (the
   MV's own separately-hashed block, not an explicit caller-supplied
   token) - not exercised here. With this layer, the base table recovered
   too: replaying the same range now leaves `events` **unchanged even
   without `FINAL`** - re-verified with the real writer in
   `tests/test_writer.py::test_replay_does_not_inflate_base_table_or_rollup`.

**Why both layers, not just the simpler one:** the token only protects a
replay that reproduces the exact same per-partition offset grouping - true
for a live writer restart/retry (always resumes from the last committed
offset), not guaranteed for every conceivable replay (a different batch
size, a manual partial-range replay, a future code change to the batching
logic). `uniqExact` dedups by identity, not by batch shape, so it holds
even when the token doesn't apply. `FINAL` (or `OPTIMIZE ... FINAL`) is
still the right tool for ad hoc raw-table queries where identity-based
dedup matters and the token didn't catch it - the token reduces how often
that's needed, it doesn't replace `FINAL`/`uniqExact` as the source of
truth.

**Which queries need `FINAL`, which need `argMax`, which need neither:**

| Query shape | Use | Why |
|---|---|---|
| Row content for a specific alert or a small, time-bounded investigation (e.g. "show agent X's alerts in the last hour", "what are this alert's current field values") | `events ... FINAL`, scoped to a bounded `WHERE time BETWEEN ...` | Simplest correct option; over a small bounded range the merge cost `FINAL` adds is acceptable, and you want the actual columns, not just a count. |
| The same, but `FINAL` is measurably too slow even bounded | `argMax(col, ingested_at)` per `(tenant_id, cluster_node, alert_id)`, same bounded `WHERE` | `argMax` is a streaming aggregation, not a merge-time reconciliation - cheaper than `FINAL` for the same bounded range when you only need specific columns, not the whole row. Still scans every matching row, so it still needs a bound; it's cheaper than `FINAL`, not free. |
| Counts/aggregates over a large or unbounded time range (dashboards, "all time" totals, compliance reporting) | `events_hourly_rollup` with `uniqExactMerge(identity_state)` | Pre-aggregated hourly - cost is proportional to the number of rollup buckets touched, not the number of raw events underneath them. This is the only option of the three that's actually safe unbounded. |
| A simple `count()` of distinct alerts, no column content needed, any range | `events` `GROUP BY (tenant_id, cluster_node, alert_id)` with `count()`, no `FINAL` | Grouping by the full identity already collapses duplicates for a bare count - `FINAL`'s extra merge work buys nothing here. Still bound the range for cost, same as any raw-table query. |

**Console rule, stated once for both tables:** never run `FINAL` over an
unbounded time range on `events` - it forces a full merge of however much
data matches, with no bound on cost. Queries over a bounded, indexed range
(a dashboard's "last 24h", an investigation's specific window) can afford
it; anything scanning "all time" should go through `events_hourly_rollup`
(`uniqExactMerge`) instead, which is cheap regardless of the total
underlying row count.

## OCSF naming

Adopted only where there's a clean 1:1 match, per the task's own
qualifier ("where a clear match exists"): `time`, `message` (`full_log`),
`src_endpoint_ip`/`src_endpoint_port`, `dst_endpoint_ip`/`dst_endpoint_port`.
Everything else (rule/agent/mitre/decoder fields) keeps its Wazuh name -
most of this schema has no clean OCSF equivalent, and forcing one would
have meant guessing at a mapping rather than reporting one.

## A real bug this found: `producer.flush()`'s return value was ignored

While building the Step 6 Kafka-outage test, found that `shipper.py`
checked only `delivery_errors` (populated by Kafka's per-message delivery
callback) before deciding whether to persist its offset - not
`flush()`'s own return value (the count of messages still undelivered when
the timeout elapsed). `confluent_kafka` does not invoke the delivery
callback with an error until `message.timeout.ms` elapses (default 5
minutes) - so during a broker outage shorter than that, a 30-second
`flush()` call times out with messages still genuinely in flight,
`delivery_errors` stays empty, and the old code would have advanced the
persisted offset past messages Kafka had never actually acknowledged. Exactly
the loss this shipper exists to prevent. Fixed by also treating a nonzero
`flush()` return as "don't advance the offset yet." Also raised
`message.timeout.ms` to 20 minutes, comfortably clear of the 5-minute
outage test, so no message times out mid-test for reasons unrelated to the
property under test.

## Lab memory

Measured with the full lab up (3 Wazuh managers, 4 agents, the LB, Kafka,
2x ClickHouse, Keeper, Postgres) at idle, before any Phase 3 traffic:
~2.1 GiB of the 7.355 GiB Docker budget. Re-measured after the full Step 6
chaos-test run (every container's memory footprint had grown from real
ingest/replication/replay activity): ~2.7 GiB - still comfortably under
40% of budget. ClickHouse's per-replica memory ceiling went through two upward
revisions during Step 6 testing (600 MiB, then ~858 MiB, then 1800 MiB) -
the first two numbers were undershooting ClickHouse's own baseline
footprint for a 2-replica setup (caches, replication queues, merge
threads), not actual query working set; confirmed via `system.parts`
showing only 2 parts / 840 rows when a trivial query still hit the ceiling.
1800 MiB per replica (2304 MiB container limit) still leaves the lab
comfortably inside budget.

## Step 6 — proof

All seven scenarios below were run against the real lab: real Wazuh
managers and agents, real Kafka (`apache/kafka:3.9.0`, 1 broker KRaft),
real ClickHouse (2 replicas + Keeper), the actual `run_shipper.py` /
`run_writer.py` processes - no mocks, no SQLite. Each test used a unique
marker in the triggering event (e.g. `countproof7@localhost` as an SSH
username, landing in `actor_user`) so expected rows could be counted
exactly rather than inferred from total counts.

| # | Scenario | Expected | Actual | Notes |
|---|---|---|---|---|
| 1 | Count test: 10 deliberate failed SSH logins (`countproof1..10`) on agent-ubuntu-1 | 10 rows | **10** | Landed within 3s of triggering. |
| 2 | Kill the writer mid-ingest (`kill -9` after the 7th of 15 events), restart | 15 rows, 0 duplicates | **15** | 0 rows had landed before the kill (writer died inside its first 2s batch window, nothing yet flushed) - restart with the same consumer group drained all 15 cleanly. |
| 3 | Kill one ClickHouse replica (`ch-clickhouse-1`, the writer's preferred host) mid-ingest | inserts continue, queries work against the survivor, no loss once rejoined | **8/8** landed on `ch-clickhouse-2` while `ch-clickhouse-1` was down (confirmed `ch-clickhouse-1` genuinely unreachable: `Connection refused`); after `docker start`, `ch-clickhouse-1` showed **8/8** within 6s via normal replication | Required adding `_FailoverClickHouse` to the writer - it had no path to the second replica before this test. |
| 4 | Kill Kafka for exactly 5 minutes (03:54:32-03:59:30 UTC), generating events throughout (start/middle/end: `kafkaoutage1..10`) | shippers hold their offset, catch up fully once Kafka returns | **10/10** landed within 39s of Kafka coming back | Found and fixed a real bug: `shipper.py` checked only the delivery-callback error list before persisting its offset, not `producer.flush()`'s own return value (messages still outstanding after its timeout). `confluent_kafka` doesn't fire a delivery error until `message.timeout.ms` elapses (default 5 min), so a 30s `flush()` during the outage returned with messages still genuinely pending and an empty error list - the old code would have advanced the offset past unacknowledged messages. Fixed before running this test for real (see `shipper.py`'s `still_pending` check). **Second finding, left as documented behavior, not a bug:** a batch whose `flush()` times out has already advanced the shipper's *in-memory* read position (independent of whether the offset *file* was persisted); any message that batch sent still gets delivered by librdkafka asynchronously in the background and is not lost, but the shipper won't retry it in its own batch loop and the offset file only catches up once a *later* batch (triggered by new lines) fully confirms. Observed directly: 10 events landed in ClickHouse while the offset file still pointed to a position 11KB behind; one more trigger event caused the next successful flush to jump the persisted offset straight to end-of-file, implicitly covering the earlier 10 in one step. No loss in any case (unconfirmed-but-delivered messages are real Kafka messages, and a restart during the gap would just re-send them - absorbed by ClickHouse's dedup) - just a bookkeeping lag, documented as an open item. |
| 5 | Kill a shipper mid-file (`kill -9` right after producing 5 of 10 events, 5 more written to the file while it was dead), restart | resumes at the right byte offset, no loss, no duplicates | **10/10** within 3s of restart | Offset file was frozen at the pre-kill position while dead, confirming no phantom progress; resumed and drained the full backlog (pre- and post-kill lines) in one batch. |
| 6 | Replay the same Kafka range twice (reset consumer group `shadowtracer-writer` to earliest, replayed the full 536-message topic history) | no duplicate rows under `FINAL` | Raw (pre-merge) count went from 536 to **1072** (genuine duplicates inserted) - `FINAL` count stayed exactly **536** | The cleanest single proof of the dedup design: real duplicate rows physically exist in the table, and `ReplicatedReplacingMergeTree` + `FINAL` collapses them back to the original count. |
| 7 | Rotate `alerts.json` mid-ingest (5 events pre-rotation, `mv` + fresh file via the container's own root - the same operation Wazuh's internal day-boundary rotation performs, since nothing external triggers it on demand - 5 more events written post-rotation) | nothing lost | **5 pre + 5 post = 10/10**, all within 3s of the post-rotation write | Confirmed via the persisted offset file switching to the new inode (`1090710`, was `907376`) at the new file's exact size - the shipper fully drained the old inode before switching, per `tests/test_shipper.py::test_shipper_survives_log_rotation`'s synthetic proof, now also confirmed against a live bind-mounted manager log. |

Every count above was read directly from ClickHouse via `SELECT count() FROM
events FINAL WHERE actor_user LIKE '<marker>%'` (or the unfiltered total
for scenario 6), against the real lab - not from the pytest suite, which
covers the same properties with synthetic data and runs separately (13
tests, `shadowtracer/ingest/tests/`).

## Open items

- The shipper's offset-file bookkeeping can lag behind what's actually
  been delivered to Kafka when a batch's `flush()` times out but the
  messages are still delivered asynchronously afterward (see Step 6 test
  4). Not a data-loss risk (undelivered-per-the-shipper but
  actually-delivered messages are real, and any resulting re-send on
  restart is deduped at the ClickHouse layer) - just means the persisted
  offset isn't always the tightest possible bound on "safely sent." Closing
  it fully would need per-message delivery tracking across batches instead
  of a single shared error list, which Phase 3's scope doesn't need yet.
- ~~The hourly rollup's crash-duplicate gap~~ - **fixed**, see "Phase 3
  follow-up 1" above (`uniqExact` identity counting + per-partition
  `insert_deduplication_token`).
- The per-partition dedup token assumes a replay reproduces the same
  offset grouping the original batch had - true for a writer
  restart/retry, not guaranteed for an arbitrary manual replay (a
  different batch size, a partial-range replay). The rollup's `uniqExact`
  counting doesn't share that assumption and is the real backstop; the
  token is a (confirmed working) optimization on top of it, not a
  substitute.
- The shipper/host permission shim (`chmod o+r` loop in
  `entrypoint-manager.sh`) is lab-only, needed because the shipper runs on
  the host while the manager's `wazuh` user is a different uid inside the
  container. A real deployment runs the shipper as a sidecar inside the
  same pod/host as the manager, sharing its uid, and doesn't need this.
- Kafka's `auto.create.topics.enable` is left at its default (on) for lab
  convenience. A production deployment should disable it and provision
  topics explicitly (partition count, retention) via IaC instead.
- PostgreSQL has only the empty Alembic baseline - application tables are
  out of scope for Phase 3 per `DECISIONS.md`.
- ClickHouse Keeper and Kafka both run as a single node in the lab;
  production needs 3 of each for real quorum tolerance (documented in
  `DECISIONS.md` for Kafka; the same caveat applies to Keeper and isn't
  yet written down anywhere else).
