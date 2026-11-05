# Throughput fixes (Phase 5.6, after the baseline)

Inputs: `docs/THROUGHPUT_BASELINE.md`. On the lab the pipeline
sustained ~100 events/s end to end; the limits were per-event database round
trips in the two Kafka consumers, on a single partition:

- **Writer:** 92–99.8% of ClickHouse insert calls were 1-row inserts
  (~60–100 ms each into a replicated table); ~100–120 rows/s saturated.
- **Correlator:** one Postgres transaction per alert (two `SELECT … FOR
  UPDATE`, a membership insert, an incident update), ~210/s on 3 partitions,
  ~80–86/s on one.
- **Partitioning:** every syslog-originated event from a manager carries
  `agent.id = "000"`, so it all lands on one partition and one replica of
  each consumer.

This note says what changes, what must stay true, and how each guarantee is
re-proved. Limits are starting values to be checked by the rerun (4d).

## 4a. Writer: batch by size and time, let the table deduplicate

### Today

`writer.py` buckets rows by `offset // 100` per partition. A complete
100-offset bucket is one insert; every row of an incomplete bucket is its own
insert with `insert_deduplication_token = topic:partition:offset`. The point
was that a replay re-forms exactly the same insert blocks, so ClickHouse's
block-level dedup drops them. The cost is the 1-row path, and it is the
common path: consume batches are cut at arbitrary offsets, so most rows sit
in incomplete buckets (measured: 92% of insert calls during a 400k backlog
drain).

### Change

- Collect up to **`BATCH_MAX_ROWS = 5000`** messages or **`BATCH_MAX_SECONDS
  = 1.0`** since the first message of the batch (whichever first), and flush
  early on an idle poll as today.
- **One `INSERT` per batch** for all its rows, whatever topics and partitions
  they came from. ClickHouse splits the block into parts per table partition
  itself.
- `insert_deduplication_token` = hash of the batch's sorted `(topic,
  partition, first_offset, last_offset)` list. It stays as a best-effort fast
  path: an exact retry of the same batch (insert retried after a timeout) is
  dropped at insert. It is no longer relied on for correctness.
- Offsets are committed after the insert returns, as today.
- `clear_stuck()` (a Postgres DELETE) only runs if this batch actually went
  through a retry, instead of after every insert.
- The offset-bucket code and the per-row insert path are removed.

### Why counts stay correct

Duplicates come from a range being consumed twice (crash before commit,
rebalance, manual replay). With size/time batching the second pass may cut
the range differently, so its token differs and ClickHouse accepts the rows
again. Correctness rests on the table and the readers, as it already did
beyond the dedup window (Phase 5.6 Item 3):

- `events` is `ReplicatedReplacingMergeTree(ingested_at) ORDER BY (tenant_id,
  time, cluster_node, alert_id)` — duplicates of an alert collapse on merge.
- `events_hourly_rollup` stores `uniqExactState(cluster_node, alert_id)`, so
  rollup counts are exact before any merge.
- Readers: the alerts list deliberately tolerates an unmerged duplicate (its
  own docstring; never `FINAL` over an unbounded range); the incident detail
  view fetches alerts by `(cluster_node, alert_id)` and now adds `LIMIT 1 BY
  cluster_node, alert_id`; the health latency is a median.

So this does not weaken a guarantee that readers rely on: unmerged
duplicates were already possible and already tolerated; they become more
frequent on replays only.

### Proof (tests, `ingest/tests`)

1. Replay the same Kafka range twice through the writer with different batch
   cuts: `uniqExact(cluster_node, alert_id)` = N, `count() FINAL` = N, rollup
   `uniqExactMerge` = N, and after `OPTIMIZE … FINAL` raw `count()` = N.
2. Replay beyond the dedup window (window shrunk to 1 block for the test):
   same assertions.

## 4b. Correlator: one transaction per poll batch

### Change

- `consumer.consume(num_messages=500, timeout=1.0)` instead of one `poll()`
  per message.
- Header, tenant, envelope, `normalize_alert` and timestamp checks run per
  message **before** the batch transaction. Bad messages are dead-lettered
  inline, as today.
- `process_batch(db, events)` runs everything in **one transaction**:
  1. Drop alerts already in `incident_alerts` (one lookup on
     `(tenant_key, node, alert_id)` for the whole batch) and repeats within
     the batch; they are `duplicate` and return the original incident id.
  2. Group the rest by `(tenant, agent, correlation_key, basis)`. Process
     groups in sorted key order (deterministic lock order, so two replicas
     overlapping during a rebalance cannot deadlock on each other), and lock
     each group's open incidents with **one** `SELECT … FOR UPDATE`.
  3. Walk each group's events in arrival order with exactly
     `process_event`'s rules: join the first open incident whose `[first_seen
     − gap, last_seen + gap]` contains the alert time if the span stays
     within `max_span`, otherwise start a new incident (inserted once, `RETURNING
     id`). Incidents created earlier in the batch are candidates for later
     events, as they would be if committed one by one.
  4. **Bulk** membership insert, `ON CONFLICT DO NOTHING RETURNING`. Only
     rows actually inserted are counted, so a concurrent replica inserting
     the same alert still cannot double-count it. An incident the batch
     created whose every alert lost that race is deleted in the same
     transaction. Before 2026-11-05 it was committed empty (`alert_count
     0`) next to the winner's (`test_correlator.py::test_replica_that_loses_the_race_for_a_new_incident_leaves_no_empty_incident`).
  5. Sequence detection (5B) still runs per newly inserted alert, in
     arrival order, inside the same transaction, exactly as before.
  6. **One `UPDATE` per touched incident** with the folded aggregates
     (min/max times, count, max level, ordered de-duplicated rule/MITRE
     lists, capped source-IP/user samples with their totals).
- After the transaction commits, offsets are committed per partition at the
  highest handled offset, covering processed and dead-lettered messages
  alike. Any transient failure rolls back the whole batch, which is retried
  in place with the existing backoff. That is safe because step 1 makes it
  idempotent.
- `process_event(db, event)` stays as `process_batch(db, [event])[0]`, so
  every existing test keeps exercising the real path.

### Guarantees and how they are re-proved

| guarantee (5A/5B) | how it holds | proved by |
|---|---|---|
| offsets committed only after the DB write | commit after the batch transaction | test_consumer, verify-correlator-chaos.sh |
| replay never duplicates membership or counts | pre-lookup + `ON CONFLICT DO NOTHING RETURNING` | test_correlator replay test, test_consumer replay test |
| rebalance/kill mid-stream loses nothing, double-counts nothing | uncommitted batch is redelivered, idempotent | verify-correlator-chaos.sh |
| sequence progress commits atomically with its incident write | same transaction, same order | test_sequences, verify-phase5b.sh |
| bad data never wedges a partition | dead-lettered before the batch, offset committed with it | test_consumer |

One behaviour difference, intentional: a replayed alert whose incident is
no longer open used to create an empty `alert_count = 0` incident before
the membership conflict was found. The pre-lookup now returns `duplicate`
without creating anything.

## Found while implementing 4a/4b

- **Test consumers read the lab's topics.** Both `writer.run` and
  `consumer.run` pattern-subscribe to every `shadowtracer.t.*.alerts`
  topic, so a test's consumer also started on the lab's retained traffic at
  the earliest offset. It dead-lettered thousands of lab messages before
  reaching its own; the writer suite failed this way on the *unchanged*
  writer too, once the test tenant's topic held a backlog. `run()` now takes
  an optional `topic_pattern` (default unchanged), and the suites pass
  `^shadowtracer\.t\.test-.+\.alerts$`. Every test tenant key starts with
  `test-`.
- **The lab's consumers read the suites' topics.** The production pattern
  also matches test topics. A lab consumer that picked up a test message
  for an unknown tenant, after the suite had deleted that topic, used to
  retry the dead-letter publish forever. This is the same bug as tenant
  offboarding and is fixed there (`docs/design/TENANCY.md` §6). The message
  is now recorded in ClickHouse and skipped. Narrowing the production
  pattern (32-hex tenant keys) remains a separate hygiene proposal.
- **Stale stuck rows outlived a restart.** `clear_stuck()` now runs once at
  writer and correlator start-up. A fresh process isn't in a retry, and
  with 4a's "clear only after a retried insert" the writer would never have
  cleared a row left by its previous incarnation. The correlator never did.
- **Dead letters inside a batch** are committed with the batch, not
  immediately. If the process dies between a dead-letter publish and the
  batch commit, that message is dead-lettered again on redelivery. That's
  harmless: `dead_letter_events` deduplicates on `source_location`
  (ReplacingMergeTree).

## 4c. Partitioning — agent "000" keyed by sender (implemented 2026-11-05, owner decision)

**Old key** (`shipper.py`): `agent.id`. Every alert a manager produces from
remote syslog, or from its own logs, carries `agent.id = "000"`. Measured
skew: 100% of a syslog end-to-end run landed on partition 2, while
partitions 0 and 1 got 0 (`THROUGHPUT_BASELINE.md` §12.5).

**New key** (`shipper.partition_key`), for `agent.id == "000"` only:
`<tenant_key>|<location>`. For remote syslog, Wazuh's remoted sets
`location` to the **sending device's IP**. Example from ClickHouse:
`{"agent": {"id": "000", "name": "shadowtracer-worker-test"},
"location": "172.28.0.1", "predecoder.hostname": "load-test-host"}`.

That IP comes from the connection, not from the message text, so a device
can't claim another device's key. `predecoder.hostname` was rejected: it
comes from the syslog header text, which can be forged, and is missing in
some formats. For the manager's own logs, `location` is the log source
(e.g. `rootcheck`, a file path). Real agents keep `agent.id`.

**What changed in guarantees** (owner-accepted): one device's events stay
ordered; agent `000`'s events from *different* devices are no longer
consumed in a fixed relative order, or by one replica. Incidents keyed
`(000, srcip/user)` can therefore be updated from two partitions. That
stays correct because each batch locks its correlation keys in sorted
order (`SELECT … FOR UPDATE`).

**Measured** (12-device syslog fleet, 600/s × 60 s, `deploy/load/syslog_fleet.sh`):

- **Spread:** test topic partition growth `[18000, 6000, 12001]` = 50.0% /
  16.7% / 33.3%, against 100% on one partition before. 12 distinct `location`s,
  3,000 alerts each.
- **Correctness**, in Postgres for those agent-000 incidents:
  - 5 incidents for 5 keys;
  - Σ alert_count 36,001 = 36,001 memberships;
  - 0 duplicate memberships;
  - 0 overlapping open incidents for the same key.

**Partitions per tenant by size (proposal):** partitions ≥ 2 × consumer
replicas, and ≥ peak events/s ÷ the per-partition consumer ceiling measured
after 4a/4b (§4d of the baseline doc).

| tenant peak | partitions |
|---|---|
| < 200 events/s | 3 (today's default) |
| 200 – 2,000 events/s | 6 |
| > 2,000 events/s | 12, revisited with measurements |

Partitions can be added to a topic but never removed, and adding them
re-maps keys (ordering per agent breaks once at the change). So it is a
per-tenant provisioning decision in `create-kafka-topics.sh`, not a runtime
knob.

## 4d. Rerun

The same tooling (`deploy/load/`), stage tests and end-to-end steps.
Before/after side by side in `docs/THROUGHPUT_BASELINE.md` §12.

## 5. Correlator profile at its ceiling (2026-11-05) — and the next fix (proposal, not implemented)

**How measured:**
- **Correlator side:** `shadowtracer_correlate/profiling.py`, opt-in with
  `SHADOWTRACER_PROFILE_BATCHES=1` and a no-op by default. It writes one JSON
  line per batch with:
  - wall time per phase (consume / prepare / `process_batch` / commit);
  - process CPU time during `process_batch`;
  - time inside SQL round trips, classified by statement.
- **Postgres side:** `pg_stat_activity` sampled every 0.25 s for the two
  correlator connections, with `pg_blocking_pids()` naming the blocker.
- **Load and setup:** Stage-4 style (writers stopped), Kafka-direct 1,600/s
  for 160 s, about twice the ceiling, 50 agents. The test topic had 3
  partitions at the time, split 1:2 between the two replicas.

**Per replica:**
- correlate-2 (two partitions) was saturated: 241 batches of 500,
  **720 msg/s**, `process_batch` 96.0% of wall.
- correlate-1 (one partition) spent 92.5 of 161 s waiting in `consume`.
  That is partition imbalance, not a cost.

**Inside `process_batch`** on the saturated replica (160.7 s):

| | seconds | share |
|---|---|---|
| SQL round trips | 102.7 | 63.9% |
| Python CPU | 76.4 | 47.5% |
| (overlap: CPU spent inside psycopg2 calls) | −18.4 | |

| statement kind | per batch | ms each | share of SQL time |
|---|---|---|---|
| incident lock `SELECT … FOR UPDATE` (one per correlation key) | 79.0 | 2.43 | **45.1%** |
| membership lookup (one, 500 identity tuples) | 1.0 | **104.4** | **24.5%** |
| incident `UPDATE` (one per touched incident) | 241.8 | 0.37 | **20.8%** |
| membership bulk insert | 1.0 | 26.8 | 6.3% |
| sequence progress | 22.4 | 0.34 | 1.8% |
| incident insert | 10.2 | 0.60 | 1.4% |

Median batch: wall 0.665 s, CPU 0.315 s, SQL 0.387 s. That is ~340 SQL
statements per 500-alert batch on this synthetic stream: 50 agents × many
source IPs/users means ~240 distinct incidents per batch.

**Postgres side** (673 samples). Correlator connections were often "idle in
transaction" (Postgres waiting on the correlator's Python), and
**`active | Lock | transactionid`** appeared in 130 samples. Every lock wait
was a correlator `SELECT … FROM incidents … FOR UPDATE` blocked by a
**closer** (closer-1/2), shown "idle in transaction" on
`SELECT tenant_alert_settings…` / `SELECT fingerprints.suppression_state…`.

**Two findings behind the numbers:**

- **The membership lookup is 90% planning.** `EXPLAIN ANALYZE` of the same
  500-tuple `(tenant_key, node, alert_id) IN ((…),(…),…)` against the
  3.2M-row `incident_alerts`: **Planning 74.9 / 76.2 / 78.9 ms,
  Execution 9.2 / 9.9 / 9.5 ms**. The planner builds a 500-branch bitmap
  OR. The same identities as `JOIN (VALUES …) v(t,n,a)` take
  **Planning 2.0 ms, Execution 3.1 ms**, using index nested-loop lookups.
- **The closer holds incident row locks across ClickHouse round trips.**
  `closer.py` takes `SELECT … FOR UPDATE` on the incident, then, in the
  same transaction, evaluates rarity (Postgres settings plus a ClickHouse
  `uniqExact` query), inserts `fingerprint_occurrences` (an fsynced
  ClickHouse insert), updates the incident and links campaigns. A
  correlator alert for that incident waits the whole time. The load
  generator's historical timestamps make every incident closable while
  it is still receiving alerts, which exaggerates this. In production
  only incidents inactive for `session_gap` get closed, but a late alert
  still waits.

**Proposed next fix, in order of measured payoff:**

1. **Lookup as a `VALUES` (or `unnest` of three arrays) join.** About −100 ms
   per batch, ~25% of SQL time, ~15% of batch wall. One-line change in
   `process_batch`.
2. **Lock all of a batch's keys in one statement.** `SELECT … WHERE
   (tenant_key, agent_id, correlation_key, correlation_basis) IN (VALUES …)
   AND state = 'open' ORDER BY tenant_key, agent_id, correlation_key,
   correlation_basis, id FOR UPDATE`. That is 79 round trips → 1, with the
   same deterministic lock order. Expect most of the 45%.
3. **Update all touched incidents in one statement.** `UPDATE incidents SET
   … FROM (VALUES …) v WHERE incidents.id = v.id`. That is 242 round trips →
   1, and much of the Python CPU, which is mostly per-statement SQLAlchemy
   construction.
4. **Closer: no row lock across ClickHouse.** Compute the fingerprint and
   evaluate rarity before taking the incident lock, then lock, re-check
   `last_seen`, write and commit. Alternatively, lock with `SKIP LOCKED` so
   the closer never makes a correlator wait.
5. **Partitions ≥ 2 × replicas.** 3 partitions over 2 replicas left one
   replica idle 57% of the time.

Together, items 1–3 take a batch from ~340 SQL statements to ~6. The
estimate (not measured) is that the correlator becomes CPU-bound on its
in-memory work, with its ceiling set by Python CPU and the single bulk
statements rather than by round trips.
