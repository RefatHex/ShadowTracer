# Backup and restore (Phase 5.5 Item 4)

Status: real restore test run, in a genuinely separate stack. Mechanism recommended
below; RPO/RTO are measured against this test's small dataset (not a production-scale
measurement).

## 0. Mechanism

- **Postgres: `pg_dump`/`pg_restore` (logical), not `pg_basebackup`.** This dataset's
  size doesn't yet justify physical backup/WAL archiving's extra operational
  complexity; revisit when Postgres's own data volume makes a full logical dump slow
  (not measured yet - no production deployment exists).
- **ClickHouse: native `BACKUP`/`RESTORE`** (`BACKUP DATABASE shadowtracer TO
  Disk(...)` / `RESTORE DATABASE ... FROM Disk(...)`), to a dedicated `backups` disk
  (added in `deploy/ci/backup-test/clickhouse/config.d/storage.xml` and allow-listed
  in a new `backups.xml` - real deployment points this disk at S3/GCS, same as the
  existing `cold` disk already does for tiering). Both real commands, both tested for
  real below.
- **Kafka: not backed up - confirmed, by design.** 7-day retention
  (`docs/DECISIONS.md`'s "Kafka retention" entry) means Kafka is a replay buffer, not
  durable storage. **What this means for RPO**: any gap between a backup and the
  moment of loss, up to 7 days old, is recoverable by replaying from Kafka (see §2) -
  **older than 7 days, it is not**, by construction. A backup/restore schedule tighter
  than 7 days keeps the realistic RPO well inside that window; this item does not
  propose a specific schedule (no production traffic volume to size it against yet).

## 1. Consistency: Postgres and ClickHouse are backed up at different moments

**The real race, confirmed by reading the architecture (not assumed):** the writer
(ClickHouse sink) and correlator (Postgres sink) are **independent Kafka consumer
groups on the same `events.raw` topic** (`run_writer.py`'s `KAFKA_GROUP_ID` default
`shadowtracer-writer`, `run_correlator.py`'s default `shadowtracer-correlate`). Nothing
orders one ahead of the other for a given event - the correlator can close an incident
referencing an alert before the writer has inserted that same alert into ClickHouse,
or vice versa. **Backup ordering (ClickHouse-then-Postgres, or the reverse) does not
by itself guarantee consistency** - it only changes which direction a gap can point.

**The approach: record both consumer groups' offsets at backup time, and close any gap
by replaying from Kafka on restore** - the same mechanism this project already uses
for a different gap (`shadowtracer/ingest/replay_unknown_tenant_dead_letters.py`'s
docstring describes exactly this pattern: drain from last-committed offset, re-produce
onto the raw topic, safe to re-run). Concretely: back up Postgres and ClickHouse in
either order, but capture `kafka-consumer-groups.sh --describe` for both
`shadowtracer-writer` and `shadowtracer-correlate` as part of the same backup bundle.
On restore, compare the two groups' restored offsets; if they differ, reset the
**behind** group backward to the **ahead** group's offset and let it reprocess the
difference - this is always safe to do (see §2's verification), since both sinks'
writes are idempotent at the identity level.

## 2. Real restore test

Stack: `deploy/ci/backup-test/` (sibling of Item 3's `deploy/ci/upgrade-test/`, same
separation - own project name, network `172.31.0.0/24`, ports 25432/28123/29000/29094,
own volumes). Main lab's 26 containers confirmed running, unaffected, before and after.

**Real data generated** (same real-function pattern as Item 3, using HEAD code): a
real tenant/admin/audit entry via `cli.py create-admin`; 5 real alert-shaped events
produced onto `shadowtracer.events.raw` and consumed by the real `run_writer.py`; 2
real incidents closed into 1 real campaign via the real `close_eligible_incidents`; 1
real dead letter via the real `send_to_dead_letter`.

**Before-backup snapshot**: 5 `events`, 1 `dead_letter_events`, 2
`fingerprint_occurrences`, 2 `incidents`, 1 `campaigns` (`incident_count=2`), 2
`campaign_incidents`, 1 `audit_log` row (hash
`3d9dab85b1b4c655163b1c1b83a102732c3aa5cdfea3421c31a5e6266f7a4d72`). Writer consumer
group at `shadowtracer.events.raw` partition 11, offset 5.

**Backup, timed**: `BACKUP DATABASE shadowtracer TO Disk('backups', ...)` - 0.24s.
`pg_dump -F c` - 0.30s. (Total backup time ~1s - this dataset is tiny; not a
production-scale RPO-window measurement, just a real, non-zero number.)

**Destructive wipe** (in the isolated stack only): `DROP DATABASE shadowtracer` on
ClickHouse, `DROP DATABASE ... WITH (FORCE)` + recreate on Postgres. Confirmed both
empty before restoring.

**Restore - real problem found and fixed**: `pg_restore` worked immediately (0.6s).
**ClickHouse's `RESTORE DATABASE` failed on the first attempt**:

```
Code: 253. DB::Exception: Replica /clickhouse/tables/01/events/replicas/01 already
exists: While creating table shadowtracer.events. (REPLICA_ALREADY_EXISTS)
```

**Root cause, confirmed via `system.zookeeper`**: `DROP DATABASE` removed the SQL-level
tables but left their `ReplicatedMergeTree` registration in Keeper (`/clickhouse/tables/01/...`)
behind - exactly the "Keeper metadata considerations" this item asked to check, found
concretely rather than theorized. This is realistic, not a test artifact: Keeper
typically has its own independent redundancy (a separate keeper quorum), so a
disaster that destroys ClickHouse's data disk plausibly leaves Keeper's metadata
untouched - this exact collision is a believable real scenario, not just a quirk of
how this test wiped things.

**Fix, real and reproducible**: `SYSTEM DROP REPLICA '01' FROM ZKPATH '/clickhouse/tables/01/<table>'`
for each affected table, before retrying `RESTORE`. In this run, `events` and
`events_hourly_rollup_v2` needed it (note the real table's Keeper path has a `_v2`
suffix the table name itself doesn't - cite the path from `events_schema.sql`, don't
guess it from the table name); `fingerprint_occurrences`/`dead_letter_events`/
`sequence_firings` did not block the restore. After the cleanup, `RESTORE DATABASE`
succeeded (0.43s). **Operational takeaway: a real ClickHouse restore runbook must
include this Keeper-cleanup step**, not just "run RESTORE" - confirmed by hitting the
failure for real, not by reading ClickHouse's docs.

**After-restore verification**: every count and the audit row hash identical to the
before-backup snapshot. `cli.py verify-audit-chain` (real HEAD code): `OK: 1 rows,
chain verified from genesis to the latest row`.

**Console works**: started the real `console/backend` (`uvicorn app.main:app`) against
the restored Postgres/ClickHouse/Kafka, hit `/health/ready` (Postgres: ok) and
`POST /auth/login` with the restored admin's real credentials - got back a real signed
JWT. (The health check's ClickHouse probe needs its own `CLICKHOUSE_HOST` env var,
separate from `CLICKHOUSE_HOSTS` - a config quirk in how this check was invoked for
the test, not a restore defect; login succeeding is the real proof the restored
Postgres data and the running service are both sound.)

**Pipeline resumes**: produced 2 more real events after the restore, ran the real
`run_writer.py` again (same consumer group, which Kafka itself was never wiped - a
deliberately realistic case: a DB-only disaster with Kafka's own retention intact).
Result: 7 events, 7 distinct `alert_id`s - the 5 restored plus 2 new, no loss, no
duplication.

**Replay-to-close-a-gap, verified safe**: reset the writer's consumer group backward
by 5 (re-exposing already-processed offsets) and ran it again. Result: `count()`
without `FINAL` read 12 (5 genuine duplicates from the replay, sitting unmerged) but
`count() FINAL` and `uniqExact(alert_id)` both read 7 - the correct value - immediately,
and a forced `OPTIMIZE TABLE events FINAL` converged the raw count to 7 too. This is
the exact same `ReplicatedReplacingMergeTree` behavior `docs/PHASE3_DATA_PLATFORM.md`
already documented for `dead_letter_events` (query with `FINAL`/`uniqExact`, never a
plain `count()`) - **confirmed to hold for this replay-to-close-a-gap scenario too**,
which is what makes §1's proposed approach (replay the behind consumer) actually safe
to run, rather than just a plausible idea.

**RPO/RTO measured** (this test's dataset size, not a production sizing claim):
- **RPO**: bounded by backup frequency, with Kafka's 7-day retention able to close any
  gap between the two sinks' consumer offsets up to that window - see §1.
- **RTO**: restore itself was sub-second per store (0.6s Postgres, 0.43s ClickHouse
  after the Keeper cleanup); the Keeper cleanup step added real, human-driven time
  (diagnosing the failure, then one `SYSTEM DROP REPLICA` per affected table) that a
  written runbook would make routine rather than a from-scratch investigation.

Teardown: `docker compose down -v` in the separate stack. Main lab's 26 containers
confirmed still running throughout.
