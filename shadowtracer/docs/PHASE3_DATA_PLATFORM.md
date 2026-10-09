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

## Phase 3 follow-up: agent send-failure fix, re-running Phase 1 item 15

See `DECISIONS.md`'s "Phase 3 follow-up: agent send-failure fix" section
for the root cause and the duplicate-vs-loss trade-off. This section is
just the re-test output.

Exact repeat of Phase 1 item 15: `agent-ubuntu-1` (primary `wazuh-worker1`,
fallback `wazuh-worker2`) with `wazuh-worker1` stopped for the duration,
20 deliberate failed SSH logins (uniquely marked `sendfix3_1`..`sendfix3_20`)
generated roughly every 15s throughout the outage.

- `wazuh-worker1` stopped: 14:56:09 UTC.
- First delivery (a buffered burst of 2) arrived at `wazuh-worker2`:
  14:59:56 UTC - 3m47s later, consistent with Phase 1's original ~3m36s
  figure and the same already-documented cause (a stopped container's
  hostname fails DNS resolution slowly, consumed entirely retrying the
  dead primary before the agent's connection logic ever tries the
  fallback - unrelated to this fix, not re-investigated here).
- Last event delivered: 15:00:55 UTC.
- **Result: 20 of 20 events delivered, individually confirmed present
  (`sendfix3_1` through `sendfix3_20`, no gaps), zero on `wazuh-worker1`
  (never came back up during the window), all 20 on `wazuh-worker2`.**
  Previous result (Phase 1, before this fix): 19 of 20.

Two earlier attempts at this specific re-test were invalidated by an
unrelated environmental issue before this result: recreating the agent
containers left stale `Duplicate IP` registrations on the master (the
exact failure mode Phase 1's own "eighth finding" already documented -
`manage_agents -r <id>` is required after force-recreating an agent
container, which we'd forgotten to do), so the agent spent both of those
windows stuck in a password-less re-enrollment loop, never actually
connected to anything. Caught by checking `client.keys` was empty rather
than trusting `agent_control -l`'s `Active` status, which can lag a real
disconnection. Re-enrolling cleanly (remove stale IDs, recreate, confirm
`client.keys` populated and a real alert lands before starting the test)
fixed it for the third, reported attempt.

**Regression test:** none added to the CMocka suite - `send_msg()`/
`dispatch_buffer()` have no existing test harness (no mock for
`send_msg()`'s network behavior), and building one to exercise what is
fundamentally a real-network-timing bug would have grown the "minimal
change" well beyond the fix itself, largely testing the mock rather than
the behavior. The live re-test above is the validation, as directed.

## Phase 3 follow-up: load-balancer NULL-pointer fix, agents back behind the LB

See `DECISIONS.md`/`UPSTREAM.md` for the root cause
(`OS_IsValidIP()`/`isSingleHost()` in `src/shared/validate_op.c`). This
section is the re-test output.

> **CMocka regression test status: NOT YET RUN.** The test exists in
> `src/unit_tests/shared/test_validate_op.c` and is believed correct by
> inspection, but it has never actually executed, anywhere, with a pass or
> fail result. Do not cite it as proof this fix works - the live re-test
> below (20/20 through a real load balancer) is the only validation that
> has actually run. This status flips to RUN + result only once it's
> executed on a host where the full CMocka suite builds (see the four
> build failures described just below for what is blocking that here).

**Unit regression test:** written
(`src/unit_tests/shared/test_validate_op.c` - updated the one existing
test that asserted the buggy behavior as correct, `OS_IsValidIP_any_struct`,
and added a direct `isSingleHost()` assertion) but **could not be executed
in this environment**. Running Wazuh's CMocka suite requires the full
`build_wazuh_cmake` dependency graph, which pulls in `syscollector`'s
`data_provider` tests - unrelated to `validate_op.c` - and those need a
prebuilt `gtest`/`gmock` that this environment's `make deps` doesn't fetch.
Four distinct build failures across three independent attempts
(`libcmocka-dev` missing - fixed, a real gap; without `DEBUG=YES` - same
failure, different symptom; `DISABLE_SYSC=YES`, the Makefile's own escape
hatch - doesn't fully remove `build_syscollector` from
`build_wazuh_cmake`'s prerequisites), past the project's "stop after two
failures" rule. The test is correct and matches existing conventions; it
will run in any environment where the full suite already builds.

**Live re-test (the fix's actual required validation):**

1. Switched `deploy/lab/docker-compose.yml`'s agents from a static IP per
   worker (the Phase 1/2 workaround) to `AGENT_MANAGER_DATA_HOST:
   shadowtracer-lb`, and `entrypoint-agent.sh`'s enrollment to dynamic
   ("any") IP - no `-I` flag.
2. Rebuilt the agent image with both this fix and the agent send-failure
   fix (follow-up 2) included, recreated the agents.
3. **Both `agent-ubuntu-1` and `agent-ubuntu-2` reached `Active` with
   `IP: any`, behind the same shared load-balancer address** - previously
   impossible (every "any"-registered agent got stuck in a
   connect-close-retry loop, Phase 1 Step 2). Confirmed with real traffic,
   not just status: one SSH-failure event from each agent landed correctly
   attributed (`agent-ubuntu-1`'s on `wazuh-worker1`, `agent-ubuntu-2`'s on
   `wazuh-worker2`) despite both passing through the identical LB frontend.
4. **Re-ran Phase 1 item 15 through the load balancer:** stopped
   `wazuh-worker1` at 15:17:50 UTC, generated 20 marked events
   (`lbtest_1`..`lbtest_20`) on `agent-ubuntu-1` roughly every 15s. **Result:
   20 of 20 delivered**, individually confirmed with no gaps, all on
   `wazuh-worker2` (HAProxy's own health check routed every connection
   there once it detected `wazuh-worker1` down).
5. **Unexpected but explainable bonus: failover took 26 seconds, not
   ~3m36s.** The original Phase 1 delay was traced to the agent's
   configured server hostname (`wazuh-worker1`) itself failing DNS
   resolution slowly once that specific container stopped, consumed across
   several retries before the agent's connection logic ever tried a
   fallback. With the LB in front, the agent's one configured address
   (`shadowtracer-lb`) never stops resolving - only the proxied TCP
   connection breaks, and HAProxy redirects the *next* connection attempt
   to the surviving worker almost immediately. The old slow-failover
   characteristic was an artifact of the workaround, not of the data path.

**Workaround removed, as directed:** `AGENT_MANAGER_DATA_HOST_FALLBACK`
(the per-agent second `<server>` block) is gone - redundant now that
HAProxy's backend health check does the same job in front of the agent
instead of behind it. All four agents (including the still-glibc-broken
Rocky ones, follow-up 4) now point at `shadowtracer-lb` with dynamic IP
registration, for consistency - nothing agent-type-specific about this fix.

**Setback along the way, same root cause as follow-up 2's:** the first
attempt to bring agents up behind the LB failed with "Duplicate agent
name" / "Duplicate IP" - stale registrations left over from earlier
testing sessions, same Phase 1 "eighth finding" as before. Cleared with
`manage_agents -r <id>` before each fresh enrollment; confirmed via
`client.keys` content and a real landed alert, not `agent_control -l`
status alone, which can read `Active` from stale state.

## Phase 3 follow-up 4: Rocky agents fixed - but not the way the task expected

The task's hypothesis was "build on Rocky 9 itself instead of Ubuntu
22.04." **`deploy/lab/agent-rocky.Dockerfile`'s builder stage was already
`FROM rockylinux:9`** - not Ubuntu. Investigated the real cause instead of
assuming the hypothesis was right, since the premise didn't match what was
actually in the Dockerfile.

**Real root cause, confirmed on a bare, unmodified `rockylinux:9`
container with no Wazuh code involved at all:** Rocky 9's currently
published `libgcc` package (`11.5.0-14.el9`, pulled in as a dependency the
moment `gcc-c++` is installed) requires `GLIBC_2.35` - a symbol version
that doesn't exist in Rocky 9's own glibc, which is frozen at the `2.34`
ABI line for the life of the RHEL 9 major release. This is a genuine
defect in Rocky/RHEL 9's own published repositories, not anything in our
build, our Dockerfile, or Wazuh's `Makefile`. Reproduced identically on a
stock `rockylinux:9` + `dnf install gcc-c++`, confirmed `dnf update`
doesn't fix it (no older `libgcc` build is available in the repos to roll
back to), and confirmed the *base* Docker image's pre-installed `libgcc`
(`11.4.1-2.1.el9`, present before any dev-tool package pulls in the newer
one) only needs up to `GLIBC_2.34` and works correctly.

Wazuh's `Makefile` bundles whatever `g++ --print-file-name=libgcc_s.so.1`
resolves to (in the builder stage, so the broken `11.5.0` one) into
`/var/ossec/lib/libgcc_s.so.1`, and the Dockerfile's `COPY --from=builder`
carries that broken copy into the final runtime image, **overwriting** the
runtime stage's own correct system `libgcc_s.so.1` that was sitting right
there the whole time. Fixed with one line in our own Dockerfile (no
inherited Wazuh source touched - this never needed an `UPSTREAM.md` entry):

```dockerfile
RUN cp -f /usr/lib64/libgcc_s.so.1 /var/ossec/lib/libgcc_s.so.1
```

**A second, independent bug found getting a full capability test working:**
Rocky 9's stock `rsyslog.conf` ships `imuxsock` with `SysSock.Use="off"`,
deferring all local log collection to `systemd-journald` ("local messages
are retrieved through imjournal now" - its own comment). There is no
journald in this container (no systemd, no `/run/systemd/journal/`
socket), so neither path ever delivered anything - confirmed via `logger`
landing nowhere and `/dev/log` not existing at all. Fixed in
`entrypoint-agent.sh` by flipping `SysSock.Use` back to `"on"` before
starting rsyslog (guarded on the string being present, so it's a no-op on
Debian/Ubuntu's different default). Also noted along the way: EL9's
OpenSSH logs as `sshd-session[pid]`, not `sshd[pid]` - Wazuh's existing
`sshd` decoder (`ruleset/decoders/0310-ssh_decoders.xml`) already matches
on the prefix `^sshd`, so this needed no decoder change, just confirmed it
wasn't a second blocker.

**Result, with both fixes:** both `agent-rocky-1` and `agent-rocky-2`
reach Docker-`healthy`, register `Active` behind the same load balancer
with dynamic IP (same as the Ubuntu agents, follow-up 3), and send real,
correctly-decoded alerts - confirmed with `wazuh-syscheckd` running
without crashing (previously `/lib64/libc.so.6: version 'GLIBC_2.35' not
found`), real FIM/SCA/osquery alert volume (199 and 168 alerts for
rocky-1/rocky-2 respectively within the first 20s of being Active), and a
deliberate SSH failure landing as a fully-decoded rule `5710` alert (MITRE
T1110.001) end to end.

**Production packaging remains open, as flagged in Step 0** - this follow-up
only touches the lab's Docker-based agent, not the `.deb`/`.rpm` packaging
path, which is still blocked on this host's lack of `vsyscall` support
(needed by the `debian:7` packaging base image). Needs a real Linux build
machine (or VM) with `vsyscall=emulate` available, not this WSL2 setup -
unchanged conclusion from Step 0 and Phase 2, re-confirmed, not re-litigated
here.

## Pre-Phase-4 check: the rollup's distinct-count layer, tested in isolation

Follow-up 1's replay test (the writer re-consuming the same Kafka range)
exercised the rollup together with the writer's `insert_deduplication_token`
layer - which meant it never actually proved the rollup survives on its
own, independent of that other defense. This check isolates it.

**How `events_hourly_rollup` actually stores the count:**

```sql
SHOW CREATE TABLE events_hourly_rollup
-- identity_state AggregateFunction(uniqExact, String, String)
-- ENGINE = ReplicatedAggregatingMergeTree(...)
```

It's a genuine aggregate **state**, not a finished number - `identity_state`
is an opaque, mergeable intermediate representation of `uniqExact`'s
internal exact-distinct-count algorithm. There is no plain integer "count"
column at all; every read goes through `uniqExactMerge(identity_state)` to
finalize a state (or several, summed across GROUP BY rows) into an actual
number. This is what makes it safe to feed from separate insert blocks -
confirmed below, not just asserted.

**Test: token disabled, same 20 events inserted twice in different batch
shapes.** Inserted 20 synthetic events directly via `clickhouse-connect`
(bypassing `writer.py` entirely, so no `insert_deduplication_token` was
ever set on either insert) as one batch of 20, then "replayed" the exact
same 20 identities as three separate batches of 3, 7, and 10 - a
deliberately different grouping from the original, not just a repeat of
the same batch boundaries.

| Query | Result |
|---|---|
| `SELECT count() FROM events` (raw, no token used) | **40** - confirms the token really was disabled; nothing silently deduplicated the second insert at the block level |
| `SELECT count() FROM events FINAL` | **20** - base table's identity dedup, as always |
| `SELECT uniqExactMerge(identity_state) FROM events_hourly_rollup` | **20** - correct, across 4 separate insert blocks (1 + 3) with no token protection at all |

The rollup held the correct count with zero help from the token layer,
confirming the `uniqExact` design is sound on its own and doesn't
secretly depend on the writer's batching behavior to stay correct. No
schema change needed - this was a verification, not a fix.

**Storage size relative to the base table.** Measured with two synthetic
20,000-row datasets built from the real fixture alerts (not the tiny
20-row correctness test above, which is too small to measure meaningfully):

| Dataset | Rollup buckets | `events` compressed | `events_hourly_rollup` compressed | Ratio |
|---|---|---|---|---|
| High cardinality (hour spread over 14 days, mostly 1-2 rows/bucket) | 10,470 | 1.57 MiB | 351.41 KiB | 21.9% |
| Realistic concentration (single day, ~20.8 rows/bucket average) | 960 | 1.41 MiB | 315.30 KiB | 21.8% |

**The ratio barely moved even though bucket count dropped 11x (10,470 ->
960).** That's the real finding, and it's worth understanding rather than
just citing the percentage: `uniqExact` stores the *exact* hash of every
distinct value it's seen, not a fixed-size probabilistic sketch (unlike
`uniq`/`uniqCombined`, which trade exactness for O(1)-ish state size). Its
total storage scales with the number of **distinct identities accumulated
across the table**, not with the number of buckets they're grouped into -
collapsing 20,000 events into fewer, fatter buckets doesn't shrink the
rollup the way it would for a plain `count()`-based `SummingMergeTree`
(which really is one integer per bucket, genuinely O(buckets)). The ~22%
figure here is coming almost entirely from *not storing the big columns*
(`message`, `raw_event`, the MITRE arrays) at all in the rollup, not from
aggregation compression.

**Consequence worth flagging for later, not fixed now:** at much higher
sustained event volume, this rollup's storage will track total distinct
event count, not query-relevant bucket count - a security product doing
real volume (millions of events/day) would see this rollup grow roughly
linearly with ingest rate, same as the base table, just with a smaller
constant factor. If long-term storage cost (not correctness) becomes the
binding constraint, a cheaper two-tier design is worth considering then: a
plain `count()`/`SummingMergeTree` rollup for routine dashboards (accepting
the rare writer-crash-duplicate inflation this phase's own testing found),
falling back to this `uniqExact` rollup or `FINAL` only for the specific
queries that need exactness. Out of scope for Phase 3 - noted so it isn't
rediscovered cold later.

## Phase 5A Step 0: one ClickHouse schema source

`schema/001_events.sql` (the lab) and `schema/test_only_clickhouse_schema.sql`
(the isolated test database, Phase 4 follow-ups) were two independently
hand-maintained files describing what was supposed to be the same table
shape - exactly the kind of pair that drifts silently. Consolidated into
`schema/events_schema.sql`, parameterized by `__DATABASE__` and
`__KEEPER_PREFIX__` (empty in the lab, a fresh random token per session
in tests - a Replicated engine's Keeper path isn't namespaced by
database, so a shared/fixed path would either collide with the lab's
real tables or race a previous test session's own `DROP DATABASE`).
`shadowtracer_ingest/clickhouse_schema.py` renders and applies it;
`deploy/lab/create-clickhouse-schema.sh` uses it for the lab (new -
previously this schema was applied to the lab by hand, once, with no
reproducible record at all), both test suites' `conftest.py` use it for
`shadowtracer_test`. `check-project.sh` fails if either superseded file
comes back or if any of the three consumers stops referencing this one
source.

A real bug found consolidating: naively splitting the rendered SQL on
every literal `;` broke on the file's own prose comments, which contain
semicolons in ordinary sentences ("safe for dedup; a retried produce...")
- this silently cut a `CREATE TABLE` statement's column list in half
mid-render. Fixed by stripping `-- ...` line comments before splitting,
not by scrubbing semicolons out of the prose.

## Dead-letter-ClickHouse incident (2026-10-08)

**Cause.** During the dead-letter preview/sha256/TTL schema migration, a
`DROP`+recreate of `dead_letter_events` hit a stale-znode error
("Existing table metadata in ZooKeeper differs in TTL"). Instead of
going through ClickHouse's own DDL, this was "fixed" by hand-deleting the
stale znode directly in Keeper (`clickhouse-keeper-client ... rmr
'/clickhouse/tables/01/dead_letter_events'`) - this is the root cause.
It left the table's own `/log` znode missing/corrupted, which only
surfaced later as `zookeeper_exception: Transaction failed (No node):
Op #0, path: /clickhouse/tables/01/dead_letter_events/log` and
`TABLE_IS_READ_ONLY` on insert.

**Discovery and impact window.** Found when the Phase 5B VERIFY replay
consumer hit a real `TABLE_IS_READ_ONLY` error while dead-lettering -
reported before any fix was applied, per standing project rule. Scoped
first, read-only: `system.replicas` on both replicas, for every
replicated table, showed only `dead_letter_events` affected - every other
table (`events`, `events_hourly_rollup`, `fingerprint_occurrences`,
`sequence_firings`) was healthy on both replicas. Both replicas' copies
of `dead_letter_events` were confirmed empty (0 rows, exported to
`deploy/lab/incident-2026-10-08-dead-letter-readonly/*.csv` before
touching anything) at the moment of discovery - **but that emptiness is
itself a consequence of the migration, not evidence nothing had ever
been dead-lettered**: the `DROP`+recreate above discarded whatever rows
`dead_letter_events` already held, including the original Phase 3
hostile-input test's own rows from 2026-10-04. Those ClickHouse-side
rows are genuinely gone (the table they lived in no longer exists in the
form it was written to); their Kafka dead-letter topic copies survived
independently and are still on the topic today.

Identified the exact message the VERIFY replay consumer got stuck on:
the one-off consumer group `verify-replay-1791385211` (created
2026-10-07, read-only against `shadowtracer.events.raw` from earliest)
shows committed offset 74 on partition 17 with the rest of that
partition (up to log-end offset 399) never consumed - i.e. it crashed
processing offset 74 and never advanced past it. That message is
`hostile1791131955.good.missing-ts` (a deliberately timestamp-less event
from an earlier hostile-input smoke-test run, agent
`hostile-agent-hostile1791131955`) - `normalize_alert` fails on it
(`KeyError: 'timestamp'`), which is exactly the permanent-bad-data path
`send_to_dead_letter` exists for. Its Kafka dead-letter topic copy
**does exist** - three records for
`source_location=shadowtracer.events.raw:17:74` are on the topic
(`deploy/lab/incident-2026-10-08-dead-letter-readonly/kafka_dead_letter_topic_full_dump.jsonl`):
two from the original 2026-10-04 hostile-input run (`writer` and
`correlator`, old schema), and one from the VERIFY replay itself
(`correlator`, `failed_at: 2026-10-07T15:00:15Z`, new preview/sha256
schema) - matching the replay consumer group's own creation time. **Not
lost**: the Kafka publish (step 1 of `send_to_dead_letter`'s ordering)
succeeded before the crash; only the subsequent ClickHouse insert (step
2) hit the then-read-only table and raised uncaught in the
pre-hardening code, killing the one-off replay consumer thread before it
could commit offset 74 or continue past it. The live production
`shadowtracer-writer`/`shadowtracer-correlate` consumer groups were
never stuck this way - confirming, independently of the scoping above,
**zero real-pipeline impact**: the only casualty was this throwaway
verification consumer.

**Fix.** `SYSTEM RESTORE REPLICA dead_letter_events` on each affected
replica, one at a time - the supported recovery for exactly this
"metadata not found in Keeper" state, never more manual Keeper surgery.
Verified both replicas back to `is_readonly=0` with matching row counts,
then inserted a real row through the actual writer's dead-letter path
(not a manual `INSERT`) and confirmed it landed on both.

**Hardening.** `send_to_dead_letter` (`shadowtracer_ingest/dead_letter.py`)
now dual-writes with an explicit durability order instead of treating
both sinks as equals: the Kafka dead-letter topic first (the durable
record - a failure here re-raises, and every caller retries forever with
backoff, never committing the triggering message's offset in the
meantime), ClickHouse second (the queryable per-tenant count - a failure
here is caught inside the function, logged, and counted on a new
`dead_letter_ch_failures` metric, but never propagated). Writer, shipper,
and the correlator's consumer loop all wrap the call the same way.
Along the way, found that `confluent_kafka`'s `produce()`/`flush()`
alone do **not** reliably detect a broker-unreachable delivery failure -
confirmed empirically that `flush()` can return `0` ("nothing still
queued") even when the message actually timed out undelivered, because
that failure is only ever reported through an `on_delivery` callback.
Without catching that, the "retry forever on Kafka failure" guarantee
above would have been silently broken for the exact case it exists to
protect against - fixed by registering `on_delivery` and checking it
alongside `flush()`'s return value.

A new idempotent backfill script
(`shadowtracer/ingest/backfill_dead_letter_events.py`) replays the Kafka
dead-letter topic into `dead_letter_events`, so a future ClickHouse-side
outage doesn't leave a permanent hole in the queryable copy once
ClickHouse recovers - safe to re-run any number of times (a committed
Kafka consumer group position plus `insert_deduplication_token`, the
same two-layer idempotency `events` inserts already use).

**Why the existing hostile-input smoke test didn't catch this.** Both
reasons originally suspected turned out true, confirmed by the timeline
above rather than guessed: the smoke test's hostile-input run that
produced the 2026-10-04 dead-letter rows predates the migration/incident
by three days, and was never re-run in between - so its passing result
from that day says nothing about the state the migration later broke;
there is no run in between for it to have caught. Separately, and true
regardless of timing: it queried `dead_letter_events` only via `docker
exec` into the `ch-clickhouse-1` container specifically, and only ever
checked row *counts* - never `is_readonly`, never `ch-clickhouse-2`,
never the Kafka dead-letter topic itself. Even a same-day re-run could
have passed by coincidence (whichever replica it happened to query, and
whatever count it happened to see, staying consistent) without ever
checking the one thing that was actually broken. `smoke-test.sh` now
asserts `is_readonly=0` and
`is_session_expired=0` for every replicated table on **both** real
ClickHouse replicas directly (a new, separate check, every run), and its
hostile-input round-trip now also checks `ch-clickhouse-2`'s count and
the dead-letter Kafka topic's own offset delta, not just
`ch-clickhouse-1`'s ClickHouse count.

`/health/detail` and `/health/ready` gained the same replica-health
check (`clickhouse_replica_health` in
`shadowtracer/console/backend/app/health.py`) - every replicated table on
every configured ClickHouse host, feeding into `/health/ready`'s 503 so
a stuck-read-only replica now fails readiness instead of only showing up
in an admin-only detail view.

**Lessons.**
- Never hand-edit Keeper (manual znode deletion) to work around a schema
  migration mismatch, even as a quick unblock - it leaves a replica's
  coordination state inconsistent in ways that only surface later. If a
  replicated table's ZooKeeper-recorded metadata genuinely disagrees with
  the schema, resolve it through ClickHouse's own DDL (a real `DROP
  TABLE ... SYNC` + recreate, or a fresh Keeper path prefix - see Phase
  5A Step 0's `__KEEPER_PREFIX__` for why tests already do this) - never
  through direct Keeper surgery.
- A migration (or any DDL) touching a `ReplicatedMergeTree` table must be
  followed by an explicit write/health check - `is_readonly=0` on every
  replica, confirmed by the same path production traffic uses - before
  considering the migration done. "The `CREATE TABLE` didn't error" is
  not that check.

(Unrelated side finding during this session's recovery, not part of this
incident: the lab's whole docker-compose stack had independently gone
down from a host/WSL2 restart; when it came back up, `wazuh-worker1`/
`wazuh-worker2` had several daemons - `wazuh-execd`, `wazuh-authd` -
silently fail to (re)start, leaving them `unhealthy` and blocking
`smoke-test.sh`'s own wait loop. Fixed with a clean
`shadowtracer-control restart` on each; noted here only because it's
what `smoke-test.sh`'s history would otherwise show as an unrelated
failure around the same time.)

**Follow-up: two more real bugs found closing this out.** Proving the
ingest and correlate test suites could run concurrently (they couldn't
yet - see [[project_test_suite_db_race]]) surfaced the first: both
suites' `conftest.py` independently `DROP DATABASE IF EXISTS
shadowtracer_test ... RECREATE` against the same real cluster under the
same hardcoded name - running them at the same time let one suite's
session-start DROP race the other's, producing a `test_shipper.py`
failure that had nothing to do with the code under test. Fixed by
generating a session-unique `shadowtracer_test_<token>` name per suite
(same pattern as the Keeper path prefix already used for the same
reason) and dropping it at session end so it doesn't orphan a database
per run; `shadowtracer/console/backend`'s conftest got the identical fix
for consistency, though it wasn't part of the concurrency being proved.
Fixing this also exposed a second, independent bug: `test_rarity.py`,
`test_sequences.py`, and `test_campaigns.py` each had their own
hardcoded `TEST_CH_DB`/`CH_DB = "shadowtracer_test"` literal, never
sourced from conftest's constant - invisible while both strings happened
to match, and silently pointing at the wrong (now nonexistent-by-that-
name) database once conftest's value became dynamic. Fixed by importing
conftest's `TEST_CLICKHOUSE_DB` instead of re-declaring it.

Separately, `verify-phase5b.sh`'s cleanup (the FK-order bug fixed above)
was rewritten again: campaign/sequence-test data now runs under one
dedicated throwaway `VERIFY_TENANT_KEY` per run (no `tenants`/`users`
row needed - `incidents`/`campaigns`/etc. have a plain `tenant_key`
string column with no foreign key into `tenants`) instead of the real
lab tenant, and cleanup deletes by `tenant_key`/`tenant_id` alone across
every table, in FK-safe order - never by `agent_id` name pattern, which
is what let the sequence-test incident's campaign link slip through
cleanup in the first place. The script now also directly proves zero
leftover rows for its tenant(s) in both Postgres and ClickHouse after
cleanup (not just that the DELETEs didn't error) - the ClickHouse side
needed a short poll, since `ALTER TABLE ... DELETE` is an asynchronous
mutation there, not an immediate one.

## Phase 5C Step 0: tenant integrity, dead-letter dedup, rarity cleanup

**Tenant integrity.** Every tenant-scoped Postgres table (`incidents`,
`incident_alerts`, `fingerprints`, `fingerprint_verdicts`,
`agent_role_tags`, `tenant_alert_settings`, `sequence_progress`,
`campaigns`, `campaign_incidents`) carried `tenant_key` as a plain string
with no FK into `tenants` - a forged, stale, or already-deleted
tenant_key could silently create orphaned rows. Added FKs on all nine
(`tenant_key -> tenants.tenant_key`, a unique non-PK column, so each FK
needed an explicit column list rather than the bare `tenants.id` most
other FKs here use). The writer and correlator now both check tenant
existence before processing (`shadowtracer_ingest/tenants.py`'s
`TenantCache` - a periodically-refreshed set, not a Postgres round trip
per message) and dead-letter with `error="unknown_tenant"` on a miss,
same permanent-bad-data path as a bad timestamp. The writer gained a
real Postgres dependency it didn't have before (ClickHouse+Kafka only,
until now).

Applying the FK migration surfaced the actual orphans already sitting in
the real lab: investigating them traced back to a real bug in
`verify-phase5b.sh`'s own "replay safety" section, which read the entire
`shadowtracer.events.raw` topic from absolute earliest (7-day retention,
1471+ messages accumulated across every past session) instead of just
the run's own freshly-produced messages - every run was silently
re-processing every past run's test traffic, recreating incidents for
tenants whose cleanup had already run. This is also the dominant source
of what turned out to be the real lab tenant's entire incident count
(451+ at last count, confirmed 100% test/verification traffic - chaos
tests, hostile-input smoke tests, and repeated VERIFY runs, zero genuine
production activity): every `verify-phase5b.sh` run inflated it further.
Fixed by pre-seeding the replay consumer group's committed offsets to a
watermark snapshot taken immediately before producing its own test
messages, so it only ever replays what this run itself produced.
Orphaned rows and the real tenant's accumulated test-incident history
were cleaned up directly; a retroactive bulk-delete of the real tenant's
remaining historical test incidents was attempted but blocked by the
session's own safety tooling (a mass-delete classifier) - left for the
user to decide on, not forced through.

**Dead-letter dedup.** `dead_letter_events` was a plain
`ReplicatedMergeTree` with no identity concept at all - a replay that
re-dead-letters the same message (same component, same
`topic:partition:offset`-shaped `source_location`) inserted a genuine
duplicate row, inflating `/health/detail`'s dead-letter counts every
time. Changed to `ReplicatedReplacingMergeTree` keyed on `(tenant_id,
component, source_location)` with `failed_at` as the version column -
the same dedup idiom `events` already uses for the same reason. Applied
to the real lab via a real `DROP TABLE ... SYNC` + `CREATE TABLE` (never
Keeper surgery - the lesson from the incident above), losing only the
day's own test/debug rows, nothing of lasting value.
`dead_letter_counts_per_tenant` now counts `uniqExact(source_location)`
instead of a plain `count()`, correct immediately rather than only after
a background merge - same fix `events_hourly_rollup` needed (Phase 3
follow-up 1), for the same underlying reason.

Found a second, narrow timing flake while verifying this: `smoke-test.sh`'s
own Kafka-side dead-letter check (added in the prior incident response)
took one watermark snapshot right after its ClickHouse-side loop
confirmed completion - reliable with any normal gap between runs, but
occasionally a beat early when `smoke-test.sh` is run several times in
tight succession (observed once, not reproduced on either side of it).
Made it poll like the other eventual-consistency checks in this script
instead of asserting a single snapshot; confirmed fixed by reproducing
the tight-succession condition twice in a row afterward, both clean.

**Rarity/warm-up cleanup.** `rare_pattern_occurrence_count` never
actually counted anything beyond 0 - `evaluate_rare_pattern` only ever
flags on `prior_count == 0` ("never seen before"), a strict boolean, not
a threshold comparison. Renamed to `prior_occurrences` (column, API
response field, TS type, UI string) via a real migration; the existing
boundary tests (0 -> flagged, exactly 1 -> not) already covered the only
real threshold in this logic, plus one more added for several prior
occurrences, confirming "not flagged" holds generally, not just at
exactly 1. `tenant_alert_settings` had no write endpoint at all before
this - added one (`PUT /api/rare-pattern-warmup-override`), admin-only
and audited, same pattern as `agents.py`'s existing role-tag endpoint
(upsert + `append_entry` in the same transaction).

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
