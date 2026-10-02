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
  (one `client.insert()` call per batch, never row by row) and commits
  offsets only after that insert returns successfully. Fails over across
  configured ClickHouse replicas per batch (`_FailoverClickHouse`) so
  losing one replica doesn't stop ingestion.
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

**The hourly rollup has a known gap the raw table doesn't:** a
`MATERIALIZED VIEW` fires once per local `INSERT`, before merge-time dedup
happens. If the writer ever inserts a genuine duplicate batch (the
crash-between-insert-and-commit case the writer's own ordering is built to
make rare, not impossible), the raw table dedups it under `FINAL` but the
rollup's `SummingMergeTree` will have summed both copies - there is no
retroactive correction once that sum has merged. This is an accepted,
documented tradeoff for Phase 3's scope, not something papered over: exact
counts live in the raw table under `FINAL`; the rollup is a fast
approximation that assumes writer crashes-after-insert are rare. A
production fix would periodically rebuild the rollup from `FINAL` data
instead of trusting the realtime MV for exact figures - open item for a
later phase.

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
2x ClickHouse, Keeper, Postgres) at idle: ~2.1 GiB of the 7.355 GiB Docker
budget. ClickHouse's per-replica memory ceiling went through two upward
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
- The hourly rollup's crash-duplicate gap (above) - acceptable for Phase 3,
  needs a periodic-rebuild-from-FINAL fix before it's load-bearing for
  billing or alerting thresholds.
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
