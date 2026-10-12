# Versioning, schema inventory, and upgrade/rollback (Phase 5.5 Item 3)

Status: scheme and inventory are a recommendation (not yet decided); the upgrade and
rollback tests described in §3 were run for real, against a genuinely separate stack,
with real results pasted below.

## 0. Where things stand today (verified, not assumed)

Checked every place a version marker could live:

- `shadowtracer/VERSION` contains `1.0.0-dev` - **referenced nowhere**. Not read by any
  Python module, not baked into any Docker image, not surfaced by the API or console.
- `shadowtracer/console/frontend/package.json`'s `"version": "0.0.0"` - npm's own
  placeholder default, never bumped, not surfaced in the UI.
- The FastAPI app (`shadowtracer/console/backend/app/main.py:22`) is constructed as
  `FastAPI(title="ShadowTracer console API")` - no `version=` kwarg, so FastAPI's own
  default (`"0.1.0"`) is whatever `/openapi.json` reports, which is also never checked
  against anything.
- The Kafka message envelope has **no version field at all**. Confirmed by reading the
  producer side directly: `shadowtracer/ingest/shadowtracer_ingest/shipper.py:216-221`
  sets three headers (`tenant_id`, `source_manager`, `source_file`) and the message
  value is just the raw alert line, unwrapped. The dead-letter envelope
  (`shadowtracer_ingest/dead_letter.py:92-95`) is a JSON dict with `component`,
  `error`, `raw_event_preview`, `raw_event_size`, `raw_event_sha256`, `failed_at` -
  also no version key.
- **This absence has already caused real, permanent data loss once**: per
  `shadowtracer/docs/PHASE3_DATA_PLATFORM.md` (line ~794), a backfill run against the
  real lab recovered 609 of 655 dead-letter messages; 46 were old test data from
  *before the preview/sha256 envelope schema existed*, had no `raw_event_preview`
  field for the newer backfill script to read, and were **not recoverable through that
  path at all** - exactly what an envelope version field exists to prevent (the reader
  could have branched on version instead of guessing a shape that wasn't there).

So: version lives nowhere coherent today. This item proposes where it should.

## 1. Version scheme

**Scheme: semantic versioning (`MAJOR.MINOR.PATCH`, e.g. `1.4.2`), one version number
for the whole product**, not independently-versioned components - this is a single
deployable system (manager + console + ingest + correlate), not a library with
independent consumers, so component-level version skew inside one deployment is a bug
to prevent, not a feature to support.

**Where it lives:**

- **Source of truth: `shadowtracer/VERSION`** (already exists, currently unused)
  becomes the one place a release is cut. Everything else below reads from it rather
  than duplicating the number.
- **API**: `FastAPI(version=...)` reads `shadowtracer/VERSION` at import time, so
  `/openapi.json` and a new `GET /health/version` endpoint both report the real
  running version - useful for exactly the question this item's own upgrade test had
  to answer by inspecting git history instead: "what version is this deployment
  actually running?"
- **Console**: the frontend build pulls the same value in (Vite's `define`, injected
  at build time from `shadowtracer/VERSION` via a tiny prebuild step - not hand-copied
  into `package.json`, which drifts) and shows it in the UI footer/about panel.
- **Packages** (.deb/.rpm, Phase 10+ per the local-CI entry's own note): package
  version = `shadowtracer/VERSION`'s value, with the upstream Wazuh base version
  (`v4.14.8`) kept as a separate, visible build metadata field (e.g.
  `1.4.2+wazuh4.14.8`) - operators upgrading need to know both numbers, since a
  ShadowTracer release can ship without a Wazuh base bump and vice versa.
- **Kafka envelope**: a new integer `envelope_version` header (alongside the existing
  `tenant_id`/`source_manager`/`source_file` headers on `events.raw`, and a new
  top-level `envelope_version` key in the dead-letter JSON envelope) - headers, not
  the message value, so a consumer can branch on version before even deserializing
  the payload. Starts at `1` for the current (unversioned) shape; every future shape
  change bumps it. This directly closes the gap that caused the 46 unrecoverable dead
  letters (see §0) - a future reader could dispatch on `envelope_version` instead of
  guessing.

## 2. Schema inventory

| Schema | Mechanism today | Versioned? | Verdict |
|---|---|---|---|
| **Postgres** | Alembic, 13 real migrations across Phase 4/5A/5B/5C | **Yes** - linear revision chain, `alembic_version` table tracks applied state | Working well, verified for real in §3 |
| **ClickHouse** | `apply_schema()` runs the one `events_schema.sql` file's `CREATE TABLE IF NOT EXISTS` statements (`shadowtracer/ingest/shadowtracer_ingest/clickhouse_schema.py:36-43`) | **No** - nothing tracks which version of the schema a given database has | **Real gap, proposed fix below** |
| **Kafka envelope** | None - a fixed set of headers/JSON keys | **No** | Proposed fix in §1 |
| **Config files** (`.env`) | None - hand-maintained, `.env.example` as a template | **No**, and lower priority: wrong/missing config fails loudly at process start (every service's env-var reads either have a default or raise immediately - see every `os.environ[...]` without `.get()` across `run_writer.py`/`run_correlator.py`/`cli.py`), unlike a silent schema mismatch | Not proposing a mechanism - the failure mode is already loud |

**ClickHouse gap, demonstrated concretely (not just read from code):** created an
isolated test table, inserted a row, then re-ran `CREATE TABLE IF NOT EXISTS` with an
extra column added to the definition - the column was **silently not added**:

```
before: [('id', 'UInt32', ...), ('name', 'String', ...)]
after IF NOT EXISTS re-apply with a new column added: [('id', 'UInt32', ...), ('name', 'String', ...)]
```

Checked whether this has bitten anyone yet: `git log` on `events_schema.sql` shows 6
real commits changing it across every phase from 5A through 5C Step 0 - **every one of
them added a whole new table** (`dead_letter_events`, `sequence_firings`, etc.), never
a column to an existing one. `CREATE TABLE IF NOT EXISTS` happens to handle "new table"
correctly (it doesn't exist yet, so it gets created) - the gap has simply never been
exercised by a real column change, not because it doesn't exist.

**Proposed ClickHouse migration mechanism**: a `schema_migrations` tracking table
(`(version UInt32, applied_at DateTime) ENGINE = MergeTree ORDER BY version`, same
idea as Alembic's `alembic_version` but append-only since ClickHouse has no
transactional DDL to roll back) plus a `shadowtracer/ingest/schema/migrations/NNNN_description.sql`
directory (numbered, applied in order, each one a real `ALTER TABLE` or `CREATE TABLE`
statement) - a small runner checks the tracking table's max applied version and runs
every migration file numbered higher than it, in order, recording each as it succeeds.
`events_schema.sql` stops being hand-edited directly; it becomes the *generated*
union of all applied migrations (or is retired in favor of "replay every migration
from empty" for a fresh install - either works, not deciding which here).

## 3. Real upgrade and rollback test

Run in a genuinely separate stack: `deploy/ci/upgrade-test/docker-compose.yml`, own
project name (`shadowtracer-upgrade-test`), own network (`172.30.0.0/24`, the lab is
`172.28.0.0/24`), own host ports (15432/18123/19000/19094, the lab uses
5432/8123/9000/9094), own volumes. The lab's 26 containers were confirmed still running
throughout and after (`docker ps | grep -c shadowtracer-lab- -> 26`, before and after).

**"Old" version**: commit `a233b161ce` (Phase 5B Step 5: campaign linking - the last
commit before Phase 5C Step 0's schema changes), checked out into a separate `git
worktree` (not the main working tree). **"New" version**: HEAD (through `5fba58e0b4`,
Phase 5C Step 0 follow-ups) - 3 real Alembic migrations apart
(`84445ac086c4`/`b5fc98460501`/`8638c1abc22b`).

**Real data generated with the OLD code**, against the fresh stack:
- A real tenant + admin user via the OLD `console/backend/cli.py create-admin` (real
  row in `tenants`, `users`, and a real `audit_log` entry with a real hash-chain
  genesis).
- 2 real incidents closed via the OLD `shadowtracer_correlate.closer.close_eligible_incidents`
  (the actual production closing/fingerprinting/campaign-linking function, not a raw
  SQL stand-in) - same actor, same fingerprint, within 24h, producing 1 real campaign
  linking both incidents (`campaign_incidents` has 2 rows).
- A real dead letter via the OLD `shadowtracer_ingest.dead_letter.send_to_dead_letter`
  (the actual function `run_shipper.py`/`run_writer.py` call on a permanent failure) -
  landed in both ClickHouse's `dead_letter_events` and the real Kafka dead-letter
  topic.

**Before-upgrade snapshot**: 2 incidents, 1 campaign (`incident_count=2`), 2
`campaign_incidents`, 1 audit_log row (hash
`6513461ff852bdc8c004270c5f29d0199225a6f6115a814150071c2a5f306a98`), 1 tenant, 2
dead-letter events, 2 fingerprint_occurrences. Audit chain verified via the real
`cli.py verify-audit-chain`: `OK: 1 rows, chain verified from genesis to the latest row`.

**Upgrade**: switched to HEAD code, ran `alembic upgrade head` for real (output below)
and re-applied HEAD's `events_schema.sql` (no ClickHouse table changes exist in this
particular commit range - confirmed table list unchanged, consistent with §2's finding
that no column-altering change has happened yet in this project's real history).

```
Running upgrade 812d014c3490 -> 84445ac086c4, phase 5c step 0 tenant integrity fks
Running upgrade 84445ac086c4 -> b5fc98460501, phase 5c step 0 rename rare pattern occurrence count
Running upgrade b5fc98460501 -> 8638c1abc22b, phase 5c step 0 followup rare pattern prior occurrence threshold
```

**After-upgrade verification**: every count and every row identical to the
before-upgrade snapshot (2 incidents with the same ids, 1 campaign with
`incident_count=2`, the exact same audit row hash). Audit chain re-verified with
HEAD's own `cli.py verify-audit-chain`: same `OK` result.

**Pipeline resumption** (no loss or duplicates): produced 3 real sample alert lines
onto `shadowtracer.events.raw` (real shipper wire format - same key/header shape as
`shipper.py`), ran HEAD's real `run_writer.py` entrypoint for 15s, confirmed 3 events
landed. **Killed it, produced 4 more, ran it again** (same consumer group, fresh
process - a real restart). Result: **7 events total, 7 distinct `alert_id`s** - exactly
once each, no loss, no duplication across the restart.

**Rollback**: ran `alembic downgrade 812d014c3490` for real - all 3 downgrades have
real implementations (not `pass` stubs), and all 3 ran cleanly:

```
Running downgrade 8638c1abc22b -> b5fc98460501, ...
Running downgrade b5fc98460501 -> 84445ac086c4, ...
Running downgrade 84445ac086c4 -> 812d014c3490, ...
```

Data and audit chain re-verified intact after rollback (same counts, same hash, same
`OK` from `verify-audit-chain`). **Real caveat found**: `8638c1abc22b`'s downgrade does
`op.drop_column("tenant_alert_settings", "rare_alert_prior_occurrence_threshold")` -
this is a genuine, one-way data-loss point on rollback for any tenant that had actually
set a non-default value for that column (this test's tenant never touched it, so
nothing was visibly lost here, but a real production rollback could lose real
operator-configured values this way). **Rollback mechanism verdict: down-migrations,
not restore-from-backup**, for Postgres - they work and are already implemented for
every migration in this project's history, but any down-migration that drops a column
needs this flagged as a real, not theoretical, data-loss risk before a production
rollback runs one.

Re-ran `alembic upgrade head` afterward to leave the test stack at a consistent final
state before tearing it down (`docker compose down -v`).

**What this test did NOT cover**: no ClickHouse `ALTER TABLE`-style column migration
happened for real (none exists yet in this project's history, per §2) - that part of
§2's proposed mechanism is a design, not yet proven under a real upgrade the way
Postgres's Alembic path just was.
