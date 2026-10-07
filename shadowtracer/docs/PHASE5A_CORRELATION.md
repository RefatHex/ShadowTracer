# Phase 5A — Correlation, incidents and the attack fingerprint library

Full task spec: `shadowtracer/docs/specs/PHASE5A.md`. This document is the
design record and VERIFY evidence, following the same pattern as
`PHASE3_DATA_PLATFORM.md` and `PHASE4_CONSOLE.md`.

## Step 0 — one ClickHouse schema source

`schema/001_events.sql` (the lab) and `schema/test_only_clickhouse_schema.sql`
(the isolated test database) were two independently hand-maintained files
describing the same table shape. Consolidated into `schema/events_schema.sql`,
parameterized by `__DATABASE__` and `__KEEPER_PREFIX__` -
`shadowtracer_ingest/clickhouse_schema.py` renders and applies it;
`deploy/lab/create-clickhouse-schema.sh` uses it for the lab (new - this
schema was previously applied to the lab by hand, once, with no
reproducible record at all); both test suites' `conftest.py` use it for
`shadowtracer_test`. `check-project.sh` fails if either superseded file
comes back or if any consumer stops referencing this one source - proven
to catch both.

A real bug found consolidating: naively splitting the rendered SQL on
every literal `;` broke on the file's own prose comments, which contain
semicolons in ordinary sentences - silently cutting a `CREATE TABLE`
statement's column list in half. Fixed by stripping `-- ...` line
comments before splitting.

See commits `ba18462e6c` (spec saved first) and `f2ae85b8a3`.

## Step 1 — correlation engine (`shadowtracer/correlate/`)

A second, independent Kafka consumer group (`shadowtracer-correlate`) on
the same raw events topic the writer reads - never ClickHouse, which
holds alert content but no incident state.

**All incident state lives in PostgreSQL, never a worker's memory** - see
`DECISIONS.md`'s "Phase 5A Step 1" entry for the full reasoning (a Kafka
rebalance can hand an agent's partition to a different worker mid-attack
at any moment; PostgreSQL as the only source of truth makes that handoff
invisible to the correlation result).

**Grouping** (`correlator.py`): `(agent, source IP)` > `(agent, user)` >
`(agent, primary rule group)`, first available wins. An alert joins an
open incident if its timestamp falls within `session_gap_seconds`
(default 600) of the incident's `[first_seen, last_seen]` span, checked
on both sides (handles out-of-order arrivals), and joining must not
stretch the span past `max_span_seconds` (default 4h) - if it would, a
new incident starts instead even though the key matches.

**Idempotent**: `incident_alerts` is unique on `(tenant_key, node,
alert_id)`; the insert is `ON CONFLICT DO NOTHING`, and the incident's
aggregates are only updated when that insert actually lands a new row.
Kafka offsets commit only after the whole transaction (membership +
aggregate update) succeeds.

**Capped distinct values**: `source_ips`/`users` arrays cap at 20 with a
separate total count, so a 10,000-value scan can't grow a row without
bound (`_cap_append` in `correlator.py`).

**The closer** (`closer.py`/`closer_loop.py`) sweeps for incidents quiet
past the session gap and closes them, guarded by
`pg_try_advisory_xact_lock` keyed on the incident's id (same mechanism
`app/audit.py` uses for `append_entry`) - safe with several replicas by
construction.

Deployed as real compose services: `correlate-1`/`correlate-2` (Kafka
splits the 24 partitions between them) and `closer-1`/`closer-2`.

See commit `1d8c21bbf8`.

## Step 2 — incidents (PostgreSQL)

`incidents`, `incident_alerts`, `fingerprints`, `fingerprint_verdicts`,
`agent_role_tags` - all keyed by `tenant_key`, not `tenants.id` (neither
the correlator nor the API's JWT ever carries the numeric id for this
purpose). `incident_alerts` is membership-only; alert content is always
read live from ClickHouse, so "incidents never delete or hide alerts"
holds structurally. Every query filtered by the caller's `tenant_key`.

See commit `033e3b0bf7`.

## Step 3 — fingerprints

Computed at close time (`fingerprint.py`): sha256 over canonical JSON
(sorted keys, no whitespace) of sorted rule groups, MITRE ids in order of
first appearance, actor class (internal/external/local, from configured
`INTERNAL_IP_RANGES`), target class (admin-set OS family + role tag -
real Wazuh 4.14.8 alerts carry no OS info at all, confirmed against
`fixtures/real_alerts_4.14.8.jsonl`), volume bucket
(`floor(log2(alert_count))`), and duration bucket. Never IPs, usernames,
ports, timestamps, or agent ids.

Fingerprints are **tenant-scoped** even though the hash value itself
isn't tenant-specific - see `DECISIONS.md`: a shared cross-tenant library
would leak "tenant A was attacked" to tenant B through occurrence counts
and suppression state.

Occurrence history is one row per closure in ClickHouse's
`fingerprint_occurrences`, read via `uniqExact(incident_id)` rather than
a stored counter - safe against the closer retrying a crashed closure.

See commit `1d8c21bbf8`.

## Step 4 — verdicts and suppression

`app/incidents.py`'s state machine, role-unaware by design (RBAC
enforcement lives only in the route's `RequireRole` dependency - one
place a "can viewers triage?" bug could hide, not two copies of that rule
that could drift apart):

- 5+ `false_positive` verdicts from 2+ **distinct** analysts flips a
  fingerprint `none -> proposed` (`COUNT(DISTINCT analyst_user_id)` over
  `fingerprint_verdicts`, never a plain counter).
- `proposed -> active` is always a separate, explicit, admin-only action
  (`approve_suppression`) - never automatic.
- `active` expires (default 90 days) back to `proposed`, checked lazily
  on read and persisted when it fires.
- Every transition is audited via the existing `audit_log` (no new audit
  mechanism).
- Suppression never deletes or hides data - the fingerprint list API just
  sorts suppressed entries to the bottom.

See commit `7148ac184d`.

## Step 5 — API and console

Backend (`7148ac184d`): `GET/POST /api/incidents...` (`ALL_ROLES` for
reads, `ANALYST_OR_ABOVE` for triage/comment), `GET/PATCH/POST
/api/fingerprints...` (`ALL_ROLES` for reads, `ADMIN_ONLY` for
label/notes/suppress), `PUT /api/agents/{id}/role-tag` (`ADMIN_ONLY`).
All caught automatically by the existing route-enumeration test.

Frontend (`76005c66f8`): Incidents (list + detail with triage/comment,
hidden for viewers) and Attack Library (fingerprint list + detail with
occurrence history and admin-only controls) screens, no router library
added. Every field - including an incident's alert messages, as
attacker-controlled as the existing alerts list - renders as plain JSX
text, same rule as `AlertRow.tsx`.

## A real bug found during VERIFY (`b9089e1df1`)

Producing a synthetic test alert with an invalid timestamp
(`...T05:00:118.000+0000` - seconds can't be >= 60) crashed the real
`writer-1`/`writer-2` containers outright (ClickHouse's own client
library raised, uncaught, mid-batch-insert) and separately wedged the
correlator in an infinite retry loop on that partition (a plain
`ValueError` was indistinguishable from a transient failure). Root-caused
in `normalizer.py` - the one function both consumers already call through
- which now validates the timestamp at normalization time and raises the
same `ValueError` its docstring already promised, which both callers
already catch-count-and-skip. See `DECISIONS.md` is not needed here; the
commit message has the full account.

**Where this timestamp came from, and how general the fix is:** the
malformed timestamp was this phase's own VERIFY test script's bug
(`ts_offset = 100 + i` produced invalid strings like `"05:00:118"` once
`i` passed 59, since seconds can't exceed 59) - never real Wazuh output.
The fix is general, not specific to that one pattern: `normalizer.py` now
validates the entire string via `datetime.datetime.fromisoformat`, real
ISO8601 parsing, so any malformed timestamp is caught here, not just the
one shape this test happened to produce.

## No single event may stop the pipeline (`ed57e21c5a`)

A follow-up requirement layered on top of the above bug: every event that
fails parsing, normalizing, or processing must go to a **dead-letter**
record, with processing continuing - never crash, never retry the same
bad data forever. Kept strictly separate from a **transient** failure (the
database or broker being briefly unreachable), which retries with capped
exponential backoff instead, indefinitely, and never reaches dead-letter.

**Dead-letter** (`shadowtracer_ingest/dead_letter.py`, shared by the
shipper, writer, and correlator): dual-write, synchronously, from
whichever component detects the failure - the Kafka topic
`shadowtracer.events.dead-letter` (durable record + replay capability) and
ClickHouse's `dead_letter_events` table (the queryable per-tenant count
`/health/detail` reads; a Kafka topic alone can't cheaply answer "how many
for tenant X", and an in-process counter wouldn't survive a restart or
aggregate across replicas). A `raw_event` that's here because it was too
large in the first place is truncated before being re-embedded in the
dead-letter envelope, or that second produce would fail the same way,
recursively.

**Transient retry** (`shadowtracer_ingest/retry.py`): `retry_with_backoff`
supports `max_attempts=None` for "retry forever" - the writer's ClickHouse
insert path uses this, since by the time a row reaches that call it has
already passed `normalize_alert`, so any remaining failure is presumed
infrastructure, never bad data. The correlator's `process_event` retries
the same message in place (not re-polled) with the same backoff, except
for `UnparseableEvent`, which is bad data and dead-letters immediately
without retrying. `stop_flag` interrupts a long backoff wait so a graceful
shutdown isn't blocked by it.

**Two more real crash risks found building this** (neither was the
originally-reported bug - found reasoning through what the hostile-input
test needed to cover):

- `shipper.py`'s `TailSource` opened `alerts.json` in **text mode** -
  invalid UTF-8 bytes raised `UnicodeDecodeError` straight out of
  `readline()`, crashing the entire read loop (every line behind the bad
  byte, not just that one). Fixed: binary-mode reads, decoded with
  `errors="replace"` - invalid bytes become U+FFFD, which then fails JSON
  parsing naturally downstream and gets dead-lettered there, instead of
  crashing anything.
- `producer.produce()` for a message too large for Kafka's
  `message.max.bytes` (confirmed empirically: raises `KafkaException`
  with `MSG_SIZE_TOO_LARGE` **synchronously**, not through the async
  delivery callback) was uncaught - a single oversized line would have
  crashed the shipper process outright. Fixed: caught and dead-lettered
  specifically; a separate `BufferError` (the local produce queue being
  momentarily full) is treated as transient backpressure and retries the
  same message after a `poll()`, rather than dropping it.

`/health/detail` now includes `dead_letter_counts`: per-tenant totals and
per-component breakdown over the last 24h, with `alert: true` when any
tenant has a non-zero count.

Test coverage, both failure kinds explicitly kept separate per the task's
own instruction ("keep the two cases separate and test both"):

- `shadowtracer/ingest/tests/test_retry.py` - pure unit tests of
  `retry_with_backoff`: succeeds after transient failures, raises after a
  bounded `max_attempts` is exhausted, `max_attempts=None` keeps retrying
  past what any bounded count would tolerate, and `stop_flag` interrupts
  an indefinite retry for a graceful shutdown.
- `test_shipper.py::test_shipper_dead_letters_bad_data_never_crashes` -
  unparseable JSON and invalid UTF-8 mixed with good lines: both good
  lines land in Kafka, both bad ones dead-letter, shipper thread stays
  alive.
- `test_shipper.py::test_shipper_dead_letters_an_oversized_message_instead_of_crashing` -
  the `KafkaException`/`MSG_SIZE_TOO_LARGE` fix above, through the real
  shipper against the real lab Kafka.
- `test_writer.py::test_writer_dead_letters_bad_data_keeps_good_ones` -
  a bad timestamp alongside a good event: good one lands in ClickHouse,
  bad one dead-letters, writer thread stays alive.
- `test_consumer.py::test_bad_data_is_dead_lettered_not_silently_dropped` -
  a missing-field event and an `UnparseableEvent` (bad timestamp)
  alongside a good one, through the real correlator: good one becomes an
  incident, both bad ones dead-letter.
- `test_health.py`/`test_health_api.py` - `dead_letter_counts_per_tenant`
  against real inserted rows, and the `/health/detail` route surfacing
  `dead_letter_counts` with `alert: false` when nothing's wrong.

---

## VERIFY

### SSH brute force for 2 minutes on one agent → exactly ONE incident

Real attack, real lab: 38 SSH attempts over 2 minutes against
`agent-ubuntu-2` (`docker exec ... ssh ... @localhost`, one every 3s).

```sql
SELECT id, agent_id, correlation_basis, alert_count, first_seen, last_seen, state
FROM incidents WHERE id > 16 ORDER BY id;

 id | agent_id | correlation_basis | alert_count |         first_seen         |         last_seen          | state
----+----------+--------------------+-------------+-----------------------------+-----------------------------+-------
 18 | 009      | source_ip          |          38 | 2026-10-04 04:25:19.228+00 | 2026-10-04 04:27:17.231+00 | open
```

Exactly one incident, `alert_count = 38` (one per attempt), spanning the
full ~2 minutes.

### Same attack from two different source IPs → two incidents, ONE fingerprint, occurrence count 2

**HISTORICAL evidence - incident ids 19 and 24 below no longer exist** in
the live lab; they were deleted after inspection, same as every other
demonstration incident in this doc (see "Incident id gaps investigated"
further down - this is one of the three id gaps explicitly accounted for
there, not a mystery). The SQL output itself is kept verbatim as the
original proof this scenario was run and produced the claimed result; it
is not re-queryable against the current database.

The lab's SSH containers always report `srcip=::1` for local connections
- there's no way to get two genuinely different source IPs attacking one
agent's sshd in this topology without external network access. Produced
two same-shape sshd alerts (20 each, identical rule/MITRE shape) directly
to the real `shadowtracer.events.raw` topic - through the real
`correlate-1`/`correlate-2` services, not bypassing them - differing only
in source IP, against the same agent:

```sql
SELECT id, agent_id, correlation_key, state, fingerprint_key
FROM incidents WHERE id IN (19, 24);

 id |         agent_id         |               correlation_key                | state  |                         fingerprint_key
----+---------------------------+----------------------------------------------+--------+--------------------------------------------------------------------
 19 | agent-verify2-1791088066 | agent-verify2-1791088066|srcip:203.0.113.10  | closed | 3972dea62d8b0403123388fbd207d3f1ac8c4bd94fb999cfcbf9f4687be273ca
 24 | agent-verify2-1791088066 | agent-verify2-1791088066|srcip:198.51.100.20 | closed | 3972dea62d8b0403123388fbd207d3f1ac8c4bd94fb999cfcbf9f4687be273ca
```

Two incidents (different `correlation_key`, since source IP differs), the
exact same fingerprint. ClickHouse occurrence count:

```sql
SELECT tenant_id, fingerprint_key, uniqExact(incident_id) AS occurrences
FROM fingerprint_occurrences WHERE fingerprint_key = '3972dea6...';

eec7135f...  3972dea6...  2
```

(This run is also what found the normalizer bug above - the first
attempt used an invalid timestamp format, which crashed the writer; the
fix was applied and this is the clean re-run after it.)

### A different attack (create a local user) → a different fingerprint

**HISTORICAL evidence - incident id 25 below no longer exists**, deleted
after inspection for the same reason as ids 19/24 above - see "Incident
id gaps investigated" further down.

Produced a `useradd`-shaped alert (rule group `adduser`, MITRE
`T1136.001`, no source IP at all - `actor_class` becomes `local`) through
the same real pipeline:

```sql
SELECT id, agent_id, state, fingerprint_key FROM incidents WHERE id = 25;

 25 | agent-verify3-1791105450 | closed | 3b991ce557e051b5796f3303219c318c69371fbde375c77a0589206770792f95
```

`3b991ce5...` vs the SSH brute force's `3972dea6...` - different
fingerprint, as expected (different rule groups, different MITRE id,
different actor class).

### Hash tests (unit level, `shadowtracer/correlate/tests/test_fingerprint.py`)

```
test_same_shape_different_ips_users_and_times_same_fingerprint PASSED
test_different_technique_order_different_fingerprint PASSED
test_rule_group_order_does_not_matter_sorted_before_hashing PASSED
test_a_different_attack_has_a_different_fingerprint PASSED
test_no_source_ip_is_classified_as_local_actor PASSED
test_internal_vs_external_source_ip_changes_fingerprint PASSED
test_role_tag_change_changes_fingerprint PASSED
test_volume_bucket_uses_floor_log2 PASSED
test_fingerprint_never_contains_ip_or_username_substrings PASSED
9 passed in 0.75s
```

### Replay a Kafka range → no duplicate incident membership, counts unchanged

`test_replaying_a_kafka_range_does_not_duplicate_membership_or_change_counts`
(real Kafka, real Postgres): produces 4 alerts, waits for
`alert_count == 4`, resets the consumer group's offsets to earliest via
`kafka-consumer-groups.sh --reset-offsets --to-earliest`, restarts the
consumer, waits again - `alert_count` stays 4, membership row count stays
4. `PASSED`.

### Kill a correlation worker mid-attack → the incident survives and keeps growing

**Superseded as crash evidence by a real `docker kill` against the live
lab** (`deploy/lab/verify-correlator-chaos.sh`, below) - the thread-abandon
version below is kept only as a fast unit-level regression test (no real
infra crash, no real rebalance, just proves the Postgres-as-source-of-truth
design handles an abandoned consumer thread), not as proof the correlation
engine survives a real worker crash:

`test_killing_a_worker_mid_attack_the_incident_survives_and_keeps_growing`
(unit test, `shadowtracer/correlate/tests/test_consumer.py`): starts a
consumer, produces 3 alerts, confirms `alert_count == 3`, abandons the
thread outright (no graceful `stop_flag`), starts a fresh consumer in the
**same** consumer group, produces 3 more alerts - `alert_count` reaches 6
on the same incident id, exactly one incident exists for that agent, not
two. `PASSED`.

### Real correlator crash: `docker kill` on a live correlate-1/correlate-2 container

`deploy/lab/verify-correlator-chaos.sh` - the real-infra replacement for
the above. What it does and doesn't assume:

- **Never guesses which container to kill.** Finds a fresh agent whose
  partition is owned by a specific, CHOSEN target container by producing
  real alerts one at a time and reading back the partition
  confluent_kafka's own producer actually assigned, off the real delivery
  report (never a reimplemented/guessed hash). The owning container is
  read from a real `kafka-consumer-groups.sh --describe --group
  shadowtracer-correlate` (the correlator's own group - from
  `docker-compose.yml`'s `KAFKA_GROUP_ID`, never assumed), mapped to a
  container name via the correlate-1/correlate-2 services' static IPs
  (also read from `docker-compose.yml`, not hardcoded blind). Prints the
  agent id, partition, and owning container explicitly, before the kill,
  and asserts the lookup actually found something.
- **Runs the full cycle once targeting correlate-1 and once targeting
  correlate-2** (a round of 3 runs per invocation, alternating
  correlate-1/correlate-2/correlate-1) - not relying on a random agent id
  happening to land on both containers across invocations by luck.
- **Produces one continuous steady-rate stream** (5 alerts/sec) and
  issues `docker kill` on the real owner mid-stream, with no batch-gap
  pause.
- **Measures real failover time** (docker kill issued → the incident's
  `alert_count` first moves again), 3 times per invocation.
- **Scrapes the surviving container's own `/metrics`** (`alerts_duplicate`
  - the exact counter `consumer.py` increments on the idempotency path)
  before and after, for a real redelivery-dedup count.

**A real measurement bug was found and fixed building this, and is
reported here rather than hidden**: the first version issued the kill via
a non-blocking `subprocess.Popen` and checked for "resumption" on the
very same loop iteration with zero delay - racing the still-alive victim
finishing the message it had already dequeued, before `SIGKILL` had
actually been delivered. That version measured failover times of
0.00s/0.20s/0.20s, which is not plausible for a rebalance-gated recovery
and was in fact wrong: it was timing the dying consumer's own last gasp,
not the survivor's resumption. Fixed by making the kill `subprocess.run`
(blocking - only returns once dockerd confirms `SIGKILL` was delivered)
and capturing the baseline alert count only *after* that confirmation, so
the victim is unconditionally dead before any count is read - any
subsequent increase can only be the survivor's. Real numbers after the
fix, two full clean runs (6 total kill cycles, `exit 0` both times):

```
=== Run 1 (this invocation) ===
PROOF: agent=chaos-11791377379-try1  partition=14  owner=correlate-1 (before the kill)
PASS: exactly ONE incident for this agent
PASS: alert_count equals every alert produced (20)
PASS: incident_alerts has no duplicate (tenant_key, node, alert_id)
>>> FAILOVER TIME [1]: 47.83s
redelivered-and-deduplicated messages (survivor's alerts_duplicate delta): 0

PROOF: agent=chaos-21791377444-try3  partition=2   owner=correlate-2 (before the kill)
>>> FAILOVER TIME [2]: 49.95s
redelivered-and-deduplicated messages: 0

PROOF: agent=chaos-31791377515-try3  partition=15  owner=correlate-1 (before the kill)
>>> FAILOVER TIME [3]: 49.65s
redelivered-and-deduplicated messages: 0
VERIFY-CORRELATOR-CHAOS: PASS

=== Run 2 (clean re-run) ===
PROOF: agent=chaos-11791377633-try1  partition=7   owner=correlate-1
>>> FAILOVER TIME [1]: 49.64s   redelivered: 0
PROOF: agent=chaos-21791377701-try1  partition=13  owner=correlate-2
>>> FAILOVER TIME [2]: 50.25s   redelivered: 0
PROOF: agent=chaos-31791377769-try1  partition=11  owner=correlate-1
>>> FAILOVER TIME [3]: 50.08s   redelivered: 0
VERIFY-CORRELATOR-CHAOS: PASS
```

All 6 cycles across both runs: exactly one incident, `alert_count` equal
to every alert produced (20 - 1 probe + 19 stream alerts), zero duplicate
`incident_alerts` rows, both correlate-1 and correlate-2 killed as owner
at least twice each. Every failover number clusters tightly around
**47.8-50.3 seconds**. librdkafka's documented default
`session.timeout.ms` is 45000ms (45s) - the broker only reassigns a dead
member's partitions once its session expires, since `docker kill`
(`SIGKILL`) gives the consumer no chance to send a graceful `LeaveGroup`
first. The observed numbers (45s + ~3-5s of rebalance protocol round-trip
and catch-up processing) are consistent with that default being the
dominant driver. This wasn't queried from a live config dump (confluent_kafka's
Python wrapper doesn't expose one) - it's librdkafka's well-documented
default, corroborated here by how closely the real numbers track it. **Not
tuned, per instruction** - this is a report, not a change.

**Redelivery-dedup count was 0 in all 6 cycles** - reported honestly, not
omitted because it's a "boring" number. This doesn't mean the idempotency
path is untested: the Kafka-replay test below
(`test_replaying_a_kafka_range_does_not_duplicate_membership_or_change_counts`)
exercises it directly and deterministically. In this chaos test
specifically, the baseline alert count is captured only *after* the kill
is confirmed delivered, which means by construction the victim is already
dead before anything is counted - a true duplicate here would require the
kill to have landed in the narrow window between a message's Postgres
commit and its Kafka offset commit, which `SIGKILL`'s arbitrary timing
relative to the consumer's own processing cycle makes possible but
evidently didn't hit in these particular 6 runs. Zero is a real,
unmassaged measurement, not a claim that this window can never be hit.

Not bundled into `smoke-test.sh` - see that script's header for why (real
`docker kill` on live services, ~5-6 minutes for all 3 cycles per
invocation given the real ~50s failover wait each time, deliberately kept
opt-in rather than run on every routine smoke-test invocation). Run
directly: `cd deploy/lab && ./verify-correlator-chaos.sh`.

### Two correlation workers → the 24 partitions split, nothing processed twice

`test_two_correlation_workers_split_partitions_nothing_processed_twice`:
2 consumers in one group on a 4-partition topic, 8 agents × 3 alerts
each produced (keyed `tenant:agent`, matching the real shipper). Every
agent ends with exactly 3 alerts on exactly one incident (nothing lost,
nothing duplicated), and both workers' metrics show `alerts_created > 0`
(both genuinely owned partitions with data, not one grabbing everything).
`PASSED`.

Real lab evidence for the same property, for the **correlator's own**
consumer group specifically (`shadowtracer-correlate` - a prior version
of this doc showed this section for `shadowtracer-writer` instead, a
different consumer group on the same topic; see the real-crash section
above for the correlator group's own full `--describe` output):

```
$ kafka-consumer-groups.sh --describe --group shadowtracer-correlate
... 12 partitions owned by correlate-1 (172.28.0.42)
... 12 partitions owned by correlate-2 (172.28.0.43)
```

### Suppression state machine, over real HTTP

`test_suppression_flow_via_the_real_api` (not the business-logic module
directly - the actual `/api/incidents/.../triage` and
`/api/fingerprints/.../suppress` endpoints):

- 5 `false_positive` triages from 2 distinct analysts (4 from one, 1 from
  another) → `suppression_state_changed_to: "proposed"`.
- `GET /api/fingerprints/{key}` confirms `suppression_state: "proposed"`,
  `verdicts.false_positive: 5`, `distinct_false_positive_analysts: 2`.
- The same analyst attempting `POST .../suppress` → `403` (admin only).
- Admin `POST .../suppress` → `200`, `suppression_state: "active"`.
- `audit_log` contains both `fingerprint_suppression_proposed` and
  `fingerprint_suppression_activated` rows.

Unit-level coverage of the boundary cases
(`shadowtracer/console/backend/tests/test_incidents.py`):

```
test_five_false_positives_from_one_analyst_does_not_propose_suppression PASSED
test_five_false_positives_from_two_analysts_proposes_suppression_not_active PASSED
test_admin_approves_suppression_proposed_to_active PASSED
test_cannot_approve_suppression_that_was_never_proposed PASSED
test_expired_active_suppression_reverts_to_proposed PASSED
test_unexpired_active_suppression_stays_active PASSED
```

5 false positives from **one** analyst does not propose suppression
(confirmed - the `test_five_false_positives_from_one_analyst_...` test
above); expiry reverting `active -> proposed` is also confirmed
(`test_expired_active_suppression_reverts_to_proposed`); all paths are
audited by construction (every router action calls `append_entry`).

### Hostile input: one event per failure category, injected into the real pipeline

`deploy/lab/smoke-test.sh`'s new "hostile input" section injects a batch of
10 lines - 2 good events plus one event per required hostile category -
directly into `shipper-worker1`'s real, tailed `alerts.json` (the same
file Wazuh itself writes to), then proves every good event lands and
every bad one dead-letters, with no container restarting. Real run against
the live lab:

```
--- hostile input: no single event may stop the pipeline ---
injecting 10 lines (2 good + 8 hostile) into shipper-worker1's real alerts.json...
PASS: both good events landed in ClickHouse
PASS: all 12 dead-letter writes landed (4 shipper-stage + 8 from writer+correlator each independently dead-lettering the 4 that reach Kafka)
PASS: an incident with both good alerts exists (agent_id=hostile-agent-hostile1791131955)
PASS: no pipeline container restarted
```

The 12 dead-letter rows, one per category (a bad event that reaches Kafka
gets dead-lettered independently by both the writer and the correlator,
since they're two separate consumer groups on the same topic - hence 4
categories × 2 = 8, plus 4 categories caught at the shipper stage before
ever reaching Kafka = 12 total):

```
component   error                                                                    raw_event (truncated)
----------- ------------------------------------------------------------------------ -----------------------------------------
correlator  KeyError: 'timestamp'                                                     {}                                         (empty object)
correlator  KeyError: 'timestamp'                                                     {"rule": ... }                             (missing required field)
correlator  ValueError: Invalid isoformat string: '2026-10-04T05:00:118.000+0000'     {"timestamp": "2026-10-04T05:00:118...}    (invalid timestamp)
correlator  ValueError: month must be in 1..12                                        {"timestamp": "2026-13-01T00:00:00...}     (out-of-range timestamp)
shipper     AttributeError: 'str' object has no attribute 'get'                       {"timestamp": ..., "agent": "not-an-object"} (wrong type)
shipper     JSONDecodeError: Expecting value: line 1 column 1 (char 0)                <invalid UTF-8 bytes>{"bad": "invalid utf-8"} (invalid UTF-8)
shipper     KafkaException: KafkaError{code=MSG_SIZE_TOO_LARGE, ...}                  {"timestamp": ..., "full_log": "xxx...}    (10+ MB full_log)
shipper     RecursionError: maximum recursion depth exceeded while decoding ...       [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[...     (deeply nested JSON)
writer      KeyError: 'timestamp'                                                     {"rule": ... }                             (missing required field)
writer      KeyError: 'timestamp'                                                     {}                                         (empty object)
writer      ValueError: Invalid isoformat string: '2026-10-04T05:00:118.000+0000'     {"timestamp": "2026-10-04T05:00:118...}    (invalid timestamp)
writer      ValueError: month must be in 1..12                                        {"timestamp": "2026-13-01T00:00:00...}     (out-of-range timestamp)
```

All 8 required hostile categories covered (invalid timestamp,
out-of-range timestamp, missing required field, wrong type, 10 MB
`full_log`, invalid UTF-8, deeply nested JSON, empty object). Every
shipper/writer/correlate/closer container's `RestartCount` was read
before and after the batch and confirmed unchanged.

### Started-and-draining tests, enforced by check-project.sh

```
$ ./check-project.sh
check-project.sh: OK
```

`check-project.sh` greps `shadowtracer/correlate/tests/` for a test
function matching `test_.*correlator.*draining` and
`test_.*closer.*draining` and fails if either is missing - proven
earlier in this phase by temporarily writing neither and confirming the
script failed with a clear message, then restoring them.

### The alerts-to-incidents ratio from the lab (lab data, not a product claim)

```
Total real events in ClickHouse:  1016
Total real incidents in Postgres:   20  (19 closed, 1 open)
Distinct fingerprints:               8
```

≈51 alerts per incident on average. This is a reflection of this lab's
specific traffic (smoke-test SSH brute forces, Step 7 verification runs,
and this phase's own VERIFY activity) - not a claim about real-world
attack volume or correlation effectiveness in production.

### Incident id gaps investigated: not a bug

A prior version of this doc showed incident ids up to 25 alongside "total
incidents: 20" - a mismatch flagged as needing explanation. Current real
state of the lab's `incidents` table:

```sql
SELECT min(id), max(id), count(*) FROM incidents;

 min | max | count 
-----+-----+-------
   2 |  51 |    44
```

7 ids missing between 2 and 51 (1, 17, 19, 23, 24, 25, 32 - including, not
coincidentally, 19/24/25, the exact ids the two-source-IP and
different-attack VERIFY demonstrations above used and were manually
cleaned up with `DELETE` after inspection, same as every other real-data
VERIFY run in this doc tears down its own rows). `incidents.id` is a
plain Postgres `SERIAL`/`IDENTITY` sequence, and **sequences are not
transactional** - `nextval()` is permanently consumed the moment a row is
inserted, whether or not that row is later deleted, and whether or not
the transaction that inserted it ever commits. A gap by itself is
therefore not evidence of anything wrong; it's the normal, expected
consequence of (a) deleting real incidents after inspecting them (this
doc's own stated practice throughout VERIFY) and (b) any transaction that
called `incidents.insert()` and then rolled back for an unrelated reason
before committing (`correlator.py`'s `process_event` wraps the insert and
every subsequent step in one `with db.begin():` block - see its source;
a later statement in the same block failing rolls the whole thing back,
leaving the id consumed but no row).

The real question the task asked was whether a gap could instead be
hiding a **duplicate-incident-creation bug** - the correlator failing to
find an already-open incident for a `(tenant_key, correlation_key)` pair
and wrongly creating a second one with an overlapping time window.
Checked directly against the real data:

```sql
-- Any two incidents sharing (tenant_key, correlation_key) with
-- overlapping [first_seen, last_seen] windows:
SELECT a.id, b.id FROM incidents a JOIN incidents b
  ON a.tenant_key = b.tenant_key AND a.correlation_key = b.correlation_key
  AND a.id < b.id AND a.first_seen <= b.last_seen AND b.first_seen <= a.last_seen;
(0 rows)

-- Any incident that was created but never got an alert attached
-- (the one scenario that could leave an id-consuming INSERT committed
-- without a corresponding, expected row of activity):
SELECT count(*) FROM incidents WHERE alert_count = 0;
(0 rows)

-- Any duplicate (tenant_key, node, alert_id) in incident_alerts at all,
-- anywhere, not just for one test run:
SELECT tenant_key, node, alert_id, count(*) FROM incident_alerts
  GROUP BY tenant_key, node, alert_id HAVING count(*) > 1;
(0 rows)
```

Zero overlapping windows, zero zero-alert orphans, zero duplicate
memberships. Multiple incidents DO legitimately share the same
`correlation_key` over time (e.g. `012|rulegroup:osquery` appears on 8
different incident ids: `{11,14,20,21,22,27,42,46}`) - expected, since
this agent's background `osquery`/`ossec` rule groups fire periodically
across many separate session-gap windows over hours of lab runtime, each
closing and later reopening as a new incident once quiet long enough.
That's correct behavior, not the bug being checked for.

**Conclusion: no correlation bug. The gaps are explained entirely by
ordinary Postgres sequence semantics plus this doc's own practice of
deleting real VERIFY-demonstration incidents after inspecting them.** No
code change made for this item - the investigation itself, with real
evidence, is the resolution.

### Browser check on the new screens

Real browser (Chromium, `libnspr4` installed per Phase 4 follow-up 3),
real lab (`https://localhost:8443`, not a dev server):

- Incidents: 15 real rows rendered; opened a real incident detail page
  with its real ClickHouse-backed alert list.
- Attack Library: 7 real fingerprints with real occurrence counts;
  opened a real fingerprint detail page with its occurrence history.
- XSS: a real attacker-controlled ClickHouse event (`<script>`/`<img
  onerror>` payload) surfaced through a real incident's detail page - no
  matching `<script>`/`<img>` element in the DOM, `window.__incident_xss_fired`
  never set, payload visible as literal text. Same result as the
  component-level test (`IncidentDetailPage.test.tsx`).

## check-project.sh and act CI

```
$ ./check-project.sh
check-project.sh: OK
```

Full `smoke-test.sh` green throughout this phase, including after the
normalizer fix's redeploy and again after this phase's dead-letter work
redeployed `shipper`/`writer`/`correlate`.

`.github/workflows/ci.yml` has 3 jobs: `check-project` (above, passing),
`shellcheck-syntax` (`bash -n` on every `.sh` file - re-run directly after
the `smoke-test.sh` edit, exit status 0), and `build-agent` (compiles the
Wazuh C agent from source - unrelated to this phase's Python
ingest/correlate/console changes, and not re-run locally via `act`: this
lab machine is memory-constrained enough that it already OOM-killed
`wazuh-clusterd` once this session during an unrelated full-stack
bring-up, and `act` would add a full C build on top of the lab stack
already running for the hostile-input VERIFY run above).
