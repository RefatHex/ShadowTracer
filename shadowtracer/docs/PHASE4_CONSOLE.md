# Phase 4 — platform core and walking skeleton

One real alert travels from an agent to a screen, behind real auth, with
an audit trail. Backend: `shadowtracer/console/backend/` (FastAPI).
Frontend: `shadowtracer/console/frontend/` (React + Vite + TS + Tailwind,
Step 6). Lab: `deploy/lab/`.

## Design

- **Database roles, not just code, enforce the audit log's append-only
  property.** The console connects as `shadowtracer_app`, a restricted
  PostgreSQL role with SELECT/INSERT/UPDATE/DELETE on the ordinary tables
  but only SELECT/INSERT on `audit_log` - no UPDATE/DELETE grant exists at
  all. The table-owning role (`POSTGRES_USER`) keeps full rights, for
  migrations and as the lab's stand-in for "superuser" access.
- **RBAC is one dependency, not a per-route habit.** `RequireRole(*roles)`
  decodes the access token, checks role membership, and is the only
  sanctioned way a route handler learns the caller's `tenant_id` - every
  downstream query is scoped by construction. A route with no requirement
  (login, health liveness) must say so explicitly via `Depends(mark_public)`;
  there is no third, silent way to be exempt, and an automated test
  enumerates every route to prove it.
- **Refresh tokens rotate and detect replay.** Each redemption issues a
  new token in the same family and marks the old one used; presenting an
  already-used token revokes the *entire* family, not just that token -
  verified by confirming the next legitimate token is rejected too.

## Step 1 — config and secrets

Settings load from env vars or `*_FILE` paths (the `_FILE` variant always
wins when both are set - the Docker secrets convention). Refuses to start
(`WeakSecretError`) on a JWT secret that's missing, a known placeholder
(`changeme`, `secret`, `password`, `dev`, ...), or under 32 characters -
same check for the Postgres/ClickHouse passwords.

Log redaction (`app/logging_redact.py`) has two layers: an explicit
registry of known secret values (exact substring match, populated from
config and every issued token) and a regex backstop for
`password=`/`token=`/`Authorization: Bearer` patterns that were never
explicitly registered. Verified with a known secret value never appearing
in captured log output, plus the backstop patterns independently.

## Step 2 — auth (PostgreSQL)

Schema: `tenants`, `users` (role check constraint: `admin`/`analyst`/
`viewer`), `refresh_tokens` (family-based rotation), `login_attempts`
(the lockout source of truth - counted directly, never a separate
drift-prone counter).

- **argon2id is pinned explicitly** (`Type.ID` passed to `PasswordHasher`,
  not relying on today's library default). `verify_password()` catches
  every argon2 exception class and returns `False` uniformly - a
  corrupted stored hash can never surface as a 500. `needs_rehash()` is
  wired into `authenticate()` so a successful login against a
  weaker-than-current-policy hash transparently upgrades it.
- **Lockout checks both per-IP and per-account** recent failure counts
  independently - either one blocks, regardless of which varies (same IP
  hitting many accounts, or one account hit from many IPs).
- **Refresh token** travels only in an httpOnly+Secure+SameSite=strict
  cookie scoped to `/auth`, never in the JSON body.
- **No default admin anywhere in the codebase.** `cli.py create-admin` is
  the only way one gets created, and it always prompts for the password
  interactively (`getpass`, never a CLI argument).

## Step 3 — RBAC

`RequireRole` returns a `CurrentUser(user_id, tenant_id, role)`. The
required enumeration test (`test_rbac_enumeration.py`) walks every
registered route via `app.routes` and fails if any route's dependency
tree contains neither a `RequireRole` instance nor `mark_public`.

## Step 4 — audit log

See "Design" above for the grant structure. `app/audit.py`'s hash chain:
each row's `row_hash` covers its own fields plus the previous row's
`row_hash` (genesis = 64 zeros for the first row).

**A real bug found building this:** appends originally serialized
concurrent writers with `SELECT ... FOR UPDATE` on the last row - which
turned out to require **UPDATE privilege** on the table in PostgreSQL,
even just to take the row lock. Using it would have meant granting the
app role UPDATE on `audit_log` just to make appends safe, defeating the
entire point of the append-only grant. Fixed with a Postgres advisory
lock (`pg_advisory_xact_lock`), which needs no table privilege at all.
Added a regression test that connects as the actual restricted role, not
the table owner, to catch this if it ever regresses.

## Step 5 — health

- `GET /health` - liveness only, no dependency checks, always 200 while
  the process is up.
- `GET /health/ready` - checks PostgreSQL, ClickHouse, and Kafka for
  real; 200 only if all three are reachable, 503 with per-dependency
  detail otherwise.
- `GET /health/detail` - admin-only (`RequireRole("admin")`): shipper lag
  per node (polls each shipper's own metrics HTTP endpoint from Phase 3),
  writer consumer-group lag (via Kafka's admin API), and last event time
  per tenant (ClickHouse).

## Step 6 — walking skeleton

- `GET /api/alerts` - recent alerts for the caller's tenant (taken only
  from the validated token, never a query parameter), keyset-paginated on
  `(time, alert_id)`. Deliberately never uses `FINAL` - keyset pagination
  lets a caller scroll arbitrarily far back, making this an unbounded
  range by construction, and the console rule from Phase 3 is never
  `FINAL` over an unbounded range.
- Security headers (CSP, HSTS, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy`) on every response via
  middleware; a catch-all exception handler logs the real exception
  server-side but only ever returns a generic `{"detail": "internal
  server error"}` - verified a route that genuinely raises never leaks
  the exception type, message, or a traceback.
- Explicit CORS allowlist (`CORS_ALLOW_ORIGINS`, comma-separated, no
  wildcard) - empty until `deploy/lab/.env` sets it to the real origin.
- Frontend (`shadowtracer/console/frontend/`): React + Vite + TypeScript +
  Tailwind. One screen - login, then a polling (5s) live alert list.
  Access token lives only in React state (never localStorage/
  sessionStorage, which a successful XSS could read); the refresh token
  never reaches JavaScript at all (httpOnly cookie).

**Alert text is rendered as text only, never HTML** - every field
(`message`/`full_log`, `rule_description`, `agent_name`, ...) goes through
a plain `{value}` JSX text child in `AlertRow.tsx`, never
`dangerouslySetInnerHTML` and never interpolated into an attribute.
`AlertRow.test.tsx` renders an alert whose `message` contains a real
`<script>` tag and an `<img onerror=...>` payload and asserts: no
`<script>` element exists anywhere in the rendered DOM, no `<img>` element
exists either (so `onerror` never gets a chance to fire), the injected
JavaScript never actually executes (checked via a global flag the payload
would have set), and the payload is still visible to the user as literal
text (proving it was rendered, not silently dropped).

**Honest limitation:** full interactive browser verification (per this
project's "start the dev server and use the feature in a browser" rule)
could not be completed in this sandboxed environment - Playwright's
Chromium needs system shared libraries (`libnspr4`, etc.) that require
`apt`/sudo to install, and this environment has no passwordless sudo
(same class of blocker as Phase 3's pip issue, resolved there with a
user-space tool; no equivalent exists for system shared libraries). What
*was* verified for real: the production build (`tsc -b && vite build`)
succeeds cleanly, the Vite dev server serves the app correctly, and the
component tests run against a real DOM implementation (jsdom) exercising
the actual React rendering and `document.querySelector` calls that matter
for the XSS property specifically - not a mock of the DOM. A full
visual/click-through check is still owed once a host with the right
shared libraries (or `--with-deps` sudo access) is available.

## Step 7 — lab and checks

- `deploy/lab/console-backend.Dockerfile` builds the FastAPI backend;
  `deploy/lab/console-caddy.Dockerfile` builds the frontend (`npm run
  build`) and serves the static output from Caddy, which also reverse-
  proxies `/auth`, `/api`, `/health` to the backend replicas.
- `docker-compose.yml` runs `console-backend-1` and `console-backend-2` -
  byte-identical (same image, same `x-console-backend-env` block, nothing
  replica-specific) - behind `caddy`, which round-robins between them by
  default. Identical behavior from either replica is what makes "the
  console is stateless" an actual property of the deployment, not just a
  claim about the code.
- `deploy/lab/Caddyfile` terminates TLS with `tls internal` (self-signed,
  no real domain in the lab). The site address must be an explicit
  hostname (`localhost:8443`), not a bare `:8443` - a bare port-only
  address gives Caddy no hostname to issue an internal certificate for up
  front, so it falls back to per-connection matching by SNI/local-IP
  identifier, which fails outright for an empty SNI or a raw-IP
  connection ("no certificate matching TLS ClientHello"). An explicit
  hostname lets Caddy issue and cache one real certificate at startup,
  matching `CORS_ALLOW_ORIGINS`.
- `smoke-test.sh` gained a console section: Caddy reachability and
  `/health/ready` over TLS, then an end-to-end check - log in as a real
  admin user, trigger a real SSH brute force against `agent-ubuntu-1`,
  and poll `/api/alerts` for up to 30s for the resulting alert. This
  needs Phase 3's shipper (one per manager node) and writer actually
  running; the script starts them as host processes if they aren't
  already up (matching how Phase 3 runs them - not containerized in this
  lab), reusing a running instance instead of starting a duplicate.

**Real bug found and fixed while getting the end-to-end check to pass:**
the console's JWT carries Postgres's numeric `tenants.id` (e.g. `1`), but
Phase 3's ingest pipeline stamps ClickHouse's `events.tenant_id` column
with the tenant's *name* (the `TENANT_ID` string given to the shipper,
e.g. `"lab"`) - two different identifiers for the same tenant that were
never reconciled. `GET /api/alerts` was filtering ClickHouse with
`str(current_user.tenant_id)` (`"1"`), which never matches any row, so
the endpoint silently returned an empty list for every caller regardless
of timing. The alert was genuinely landing in ClickHouse the whole time
(confirmed directly with `clickhouse-client`); the API just couldn't find
it. Fixed by having the route look up the caller's tenant *name* from
Postgres (`SELECT name FROM tenants WHERE id = :tenant_id`) and filtering
ClickHouse with that, matching what the real ingest pipeline actually
writes. `tests/test_alerts_api.py` previously encoded the same wrong
assumption (using `str(pg_tenant_id)` as the ClickHouse value in its
fixtures) and has been corrected to use the tenant name, so it would have
caught this had it matched the lab's real tagging from the start.

**Superseded by the follow-ups below:** filtering by the tenant's *name*
was itself a stopgap - a name is supposed to be a renameable, display-only
label, not a stable identifier, and this design required a Postgres
lookup on every single `/api/alerts` call. The tenant-key follow-up
replaces this with a permanent, immutable identifier carried in the token
itself.

## VERIFY

### Route-enumeration test fails when a role is removed, then passes

Removed `dependencies=[Depends(mark_public)]` from the real `/auth`
router (the literal file, not a copy) and ran the enumeration test:

```
FAILED tests/test_rbac_enumeration.py::test_every_route_has_a_role_assertion_or_an_explicit_public_marker
AssertionError: these routes have neither a RequireRole dependency nor an
explicit Depends(mark_public) marker: ['/auth/login', '/auth/refresh', '/auth/logout']
```

Restored it, ran again:

```
tests/test_rbac_enumeration.py::test_every_route_has_a_role_assertion_or_an_explicit_public_marker PASSED
```

### A viewer token gets 403 on an admin endpoint

`tests/test_health_api.py::test_health_detail_viewer_gets_403` - a real
viewer-role user logs in over HTTP, presents that access token to
`/health/detail` (admin-only), gets 403. Passing in the suite below.

### Refresh-token replay revokes the family

`tests/test_auth_api.py::test_refresh_rotates_token_and_replay_revokes_family` -
logs in, rotates once, replays the *first* (already-rotated-away) cookie
(401), then confirms the *second*, legitimate, rotated-to token is
rejected too (401) - the whole family was revoked, not just the replayed
token.

### Lockout triggers after repeated failures spread across several IPs

`tests/test_auth.py::test_lockout_per_account_across_different_ips` -
5 failed attempts against the same account from 5 different IPs trips
account-based lockout; `test_lockout_per_ip_across_different_accounts`
proves the IP-based side independently (5 different accounts, same IP).

### The audit chain verifies, then catches a tampered row

Real end-to-end run against the live server and real lab Postgres (not
just the automated tests): logged in twice (one failed, one successful)
plus one `create-admin` CLI run, producing 5 real chained rows.

```
$ python cli.py verify-audit-chain
OK: 5 rows, chain verified from genesis to the latest row
```

Tampered with row 3 directly via `psql` as the table-owning role
(bypassing the app and its restricted role entirely):

```sql
UPDATE audit_log SET target = 'root@evil.com' WHERE id = 3;
```

```
$ python cli.py verify-audit-chain
BROKEN CHAIN: first bad row is id=3
reason: row 3: stored row_hash does not match its own content
(expected a9e2b06a2eeb3e2b8a47e9a0d4d41fa7f796bb12a6e0276a6600a8fcc08086f9,
 got 0165b892646451a4298e485d4ed140e7cac81cccf6c2372e39f4d3c5d0abe344)
exit code: 1
```

Also proved directly, via `psql` connected *as* `shadowtracer_app`
(the app's actual role, not the owner): `INSERT` succeeds, `UPDATE` and
`DELETE` both come back `permission denied for table audit_log` - a
database-level rejection a code bug cannot bypass.

### Readiness reports each broken dependency

Real server, real lab services, stopped one at a time via `docker stop`
and confirmed with `curl` before restoring each:

| Dependency stopped | `/health/ready` status | `checks` body (abridged) |
|---|---|---|
| (baseline) | 200 | `postgres: ok, clickhouse: ok, kafka: ok` |
| PostgreSQL | 503 | `postgres: false ("Connection refused" via psycopg2), clickhouse: ok, kafka: ok` |
| ClickHouse (both replicas) | 503 | `postgres: ok, clickhouse: false ("Connection refused"), kafka: ok` |
| Kafka | 503 | `postgres: ok, clickhouse: ok, kafka: false ("Broker transport failure")` |
| (all restored) | 200 | `postgres: ok, clickhouse: ok, kafka: ok` |

Full real JSON bodies for each step are in the commit this doc ships
with.

### The XSS render test passes

```
$ npx vitest run src/AlertRow.test.tsx

 ✓ src/AlertRow.test.tsx (5 tests) 15ms
   ✓ AlertRow renders attacker-controlled text safely > does not create a real <script> element anywhere in the rendered output
   ✓ AlertRow renders attacker-controlled text safely > does not create a real <img> element (onerror never gets a chance to fire)
   ✓ AlertRow renders attacker-controlled text safely > never actually executes the injected script/onerror payload
   ✓ AlertRow renders attacker-controlled text safely > shows the payload as visible, literal text instead of silently dropping it
   ✓ AlertRow renders attacker-controlled text safely > does not inject markup for attacker-controlled fields other than message either

 Test Files  1 passed (1)
      Tests  5 passed (5)
```

### Smoke test green with 2 console replicas behind Caddy

```
--- console (Step 7) ---
PASS: caddy reachable (TLS)
PASS: console readiness (Postgres/ClickHouse/Kafka all reachable)
--- end-to-end: login, SSH brute force, alert through the API ---
PASS: alert for smoketest1791005798 appears through /api/alerts within 30s
---
SMOKE TEST: PASS
```

### check-project.sh and act CI

```
$ ./check-project.sh
check-project.sh: OK
```

## Phase 4 follow-ups

### 1. One permanent tenant key

`tenants.tenant_key` (migration `6d5b50d3e5b5`): a random 32-hex-char
value generated once, when `cli.py create-admin` creates a new tenant,
and never exposed through any update path - `tenants.name` stays
display-only and freely renameable. The access token now carries
`tenant_key` directly (`security.create_access_token`,
`rbac.CurrentUser`), and `GET /api/alerts` filters ClickHouse with
`current_user.tenant_key` with no Postgres lookup at all - replacing the
Step 7 fix's per-request `SELECT name FROM tenants WHERE id = ...`. The
shipper is configured with `TENANT_ID=<tenant_key>` (printed by
`create-admin`) instead of a human tenant name, so what ClickHouse's
`events.tenant_id` column holds is the same immutable value, end to end.

Verified:

```
$ python -m pytest tests/test_alerts_api.py -q
......                                                              [100%]
6 passed
```

- `test_alerts_scoped_to_callers_tenant` - two tenants, each with its own
  `tenant_key`-tagged events in ClickHouse; a viewer from tenant A sees
  only tenant A's alerts.
- `test_renaming_a_tenant_does_not_change_which_events_it_sees` - creates
  a tenant, confirms its alerts are visible, renames it with a raw
  `UPDATE tenants SET name = ...` (there is no rename endpoint), logs in
  again, confirms the exact same alerts are still visible - the rename
  touched nothing about visibility because nothing was ever keyed on the
  name.

Full suite still green after the schema/token change (64 tests), and the
real lab smoke test end-to-end check passes with the admin's actual
generated `tenant_key` (`6ec120578e113843244dbe369869eaf3` for this lab)
wired into the shipper via `deploy/lab/.env`'s new `TENANT_KEY`:

```
--- end-to-end: login, SSH brute force, alert through the API ---
PASS: alert for smoketest1791006551 appears through /api/alerts within 30s
---
SMOKE TEST: PASS
```

### 2. The ingest pipeline as services

Phase 3's shipper and writer ran as host processes throughout Phase 3 and
Step 7 (`shadowtracer/ingest` has no Dockerfile of its own; `smoke-test.sh`
started them itself as a fallback). That's gone now: `deploy/lab/ingest.Dockerfile`
builds one shared image for both (same package, different entrypoint
script via each compose service's `command:`), and `docker-compose.yml`
runs:

- `shipper-worker1`, `shipper-worker2` - one per manager node, each
  mounting that node's `./alerts-worker*` directory **read-only** (it has
  no business writing to a manager's alert log) and writing its offset
  file to its own named volume (`shipper-worker*-offsets`) so a restart
  resumes instead of re-shipping the whole backlog. `TENANT_ID` is the
  tenant's `tenant_key` (follow-up 1) from `deploy/lab/.env`'s `TENANT_KEY`.
- `writer-1`, `writer-2` - same image, same `KAFKA_GROUP_ID` - Kafka
  splits the topic's partitions between them, not duplicate work.
- `/health/detail`'s `SHIPPER_METRICS_URLS` now points at
  `shipper-worker1`/`shipper-worker2` by compose service name, over the
  same network as everything else - no `host.docker.internal` needed, and
  the `extra_hosts: host-gateway` entries on the console backends are gone.
- `smoke-test.sh` no longer starts anything - the pipeline is just
  compose services like everything else in the lab now, included in the
  existing health-wait loop (same 180s-per-service pattern already used
  for the manager/agent containers) alongside the rest.

**A real bug found getting the writer healthy:** the image's
`HEALTHCHECK` defaults to polling port 9101 (the shipper's default metrics
port) unless `METRICS_PORT` is set, but `run_writer.py`'s own default is
9102 - so a writer container ran correctly but never reported healthy,
and the smoke test's wait loop would eventually time out against it.
Fixed by setting `METRICS_PORT: "9102"` explicitly in the writer's env
block.

Verified for real:

- **The writer replicas genuinely split partitions, not duplicate work** -
  `shadowtracer.events.raw` has 3 partitions; `kafka-consumer-groups.sh
  --describe --group shadowtracer-writer` shows partitions 0 and 1 owned
  by `writer-1` (172.28.0.40) and partition 2 owned by `writer-2`
  (172.28.0.41) - two different consumer IDs, two different hosts, one
  shared group.
- **The smoke test genuinely fails when the pipeline isn't running** -
  stopped all 4 pipeline containers (`docker compose stop
  shipper-worker1 shipper-worker2 writer-1 writer-2`), ran the exact
  login → SSH-brute-force → 30s-poll sequence by hand (bypassing only the
  script's own `docker compose up -d`, which would otherwise just restart
  them): `found=0` - no alert, as expected, nothing silently covers for a
  missing pipeline any more. Restarted the 4 containers and the full
  `smoke-test.sh` passed again end to end.
- Full suite still green (64 tests, unaffected by this follow-up),
  `check-project.sh: OK`, act's `shellcheck-syntax` job green.

```
--- end-to-end: login, SSH brute force, alert through the API ---
PASS: alert for smoketest1791007588 appears through /api/alerts within 30s
---
SMOKE TEST: PASS
```

Recorded separately (`shadowtracer/docs/DECISIONS.md`, "Phase 4 follow-up
2: the shipper in production is a sidecar, not this lab's container"):
these lab containers are a convenience, not the production shape - a real
deployment installs the shipper as a sidecar alongside the manager,
sharing its host/pod and uid, not as a standalone container reading over
a shared volume.

### 3. Closing the open items

- **The two pre-Phase-4 checks were already done, before this phase
  started** (commits `36bdd0bdbd`, `50af5f4544`) - not skipped, just
  reporting them here as asked. (1) The rollup's `uniqExact` distinct-count
  layer was tested in total isolation from the writer's
  `insert_deduplication_token` (token disabled, 20 synthetic events
  inserted once as a batch of 20 then replayed as three batches of
  3/7/10): `uniqExactMerge` still read back the correct count of 20 with
  zero help from the token, and storage was measured at ~22% of the base
  table's compressed size on two 20,000-row datasets - full detail and
  tables in `PHASE3_DATA_PLATFORM.md`'s "Pre-Phase-4 check" section. (2)
  The load-balancer fix's CMocka regression test is explicitly marked
  **NOT YET RUN** in both `PHASE3_DATA_PLATFORM.md` and `UPSTREAM.md` -
  it still can't execute in this environment (the full CMocka suite pulls
  in unrelated `syscollector`/`data_provider` build dependencies that
  don't build here); the live re-test (20/20 through the real load
  balancer) remains the only validation that has actually run. Still
  open, unchanged from before Phase 4.
- **act CI, full run, after clearing a stale local `act` container**
  (`act-ShadowTracer-CI-build-agent-...`, left running from an earlier
  invocation in this environment with a CMake cache baked for a different
  checkout path - `docker rm -f` on that container, then a clean `act`
  run; not a real regression, a local-runner artifact):

  ```
  $ act
  [ShadowTracer CI/shellcheck-syntax]   ✅  Success - Main actions/checkout@v4 [54.33s]
  [ShadowTracer CI/shellcheck-syntax]   ✅  Success - Main status=0
  [ShadowTracer CI/shellcheck-syntax] 🏁  Job succeeded

  [ShadowTracer CI/check-project    ]   ✅  Success - Main actions/checkout@v4 [56.30s]
  [ShadowTracer CI/check-project    ]   ✅  Success - Main git fetch https://github.com/wazuh/wazuh.git tag v4.14.8 [1.17s]
  [ShadowTracer CI/check-project    ]   ✅  Success - Main bash check-project.sh [3.98s]
  [ShadowTracer CI/check-project    ] 🏁  Job succeeded

  [ShadowTracer CI/build-agent      ]   ✅  Success - Main actions/checkout@v4 [56.30s]
  [ShadowTracer CI/build-agent      ]   ✅  Success - Main sudo apt-get update -qq / install build deps
  [ShadowTracer CI/build-agent      ]   ✅  Success - Main cd src && make deps TARGET=agent [23.00s]
  [ShadowTracer CI/build-agent      ]   ✅  Success - Main cd src && make TARGET=agent -j$(nproc) [12m0.55s]
  [ShadowTracer CI/build-agent      ] 🏁  Job succeeded
  ```

  All 3 jobs green.
- **The browser check is still blocked, not newly broken.** Re-attempted
  with `@playwright/test` and a fresh Chromium install: launching still
  fails with the identical `libnspr4.so: cannot open shared object file`
  error as the original Step 6 attempt - confirmed for real this time
  (`find / -iname libnspr4*` and `dpkg -l | grep nspr` both come back
  empty; no passwordless sudo to install it from here). Still open,
  pending the system packages actually landing in this environment.
- Open items, corrected to reflect what's actually still open as of this
  follow-up (not Phase 3's own tracked items in `PHASE3_DATA_PLATFORM.md`,
  which are separate and unchanged):

### 4. Tenant key immutability, enforced by the database

Follow-up 1 made `tenant_key` permanent by convention - the application
code never updates it, but the blanket table-level `GRANT UPDATE ON
tenants` from migration `5f408777ad31` meant the restricted app role
*could* have, if a bug or a compromised process ever tried. Migration
`6cb09091c77c` revokes that and grants `UPDATE (name)` instead - a
column-level grant, the same enforcement style as `audit_log`'s
append-only grant (Step 4): the one column that's actually meant to be
editable (`name`, display-only) is writable, `tenant_key` is not, at the
database level, independent of the Python code.

Verified for real, connected as `shadowtracer_app` (the lab's own, not a
copy):

```
$ psql -U shadowtracer_app -d shadowtracer -c "UPDATE tenants SET name = 'lab' WHERE id = 1;"
UPDATE 1

$ psql -U shadowtracer_app -d shadowtracer -c "UPDATE tenants SET tenant_key = 'hacked' WHERE id = 1;"
ERROR:  permission denied for table tenants
```

`tenant_key` confirmed unchanged afterward. A permanent regression test
(`test_tenant_key_cannot_be_updated_even_by_the_app_role`) connects as
the restricted role the same way and asserts both halves - full suite
green (65 tests).

### 5. Kafka partition count

`shadowtracer.events.raw` was running on 1 (or, by the time anyone
checked, 3) partitions - never explicitly set, just whatever
`auto.create.topics.enable` happened to create on first use.
`deploy/lab/create-kafka-topics.sh` now provisions it explicitly at 24
partitions, called from `smoke-test.sh` right after Kafka itself comes
up and before anything else starts (so shipper/writer never race
auto-create). The key (`tenant_key:agent_id`, unchanged) is why this had
to be decided deliberately rather than tuned later - see DECISIONS.md's
"Kafka partition count" entry for the full reasoning (parallelism
ceiling, and why growing the count later reshuffles per-agent ordering).

Verified for real: deleted the old topic, ran `create-kafka-topics.sh`,
confirmed 24 partitions via `kafka-topics.sh --describe`, restarted
`writer-1`/`writer-2` and confirmed the split:

```
$ kafka-consumer-groups.sh --describe --group shadowtracer-writer
... 12 partitions owned by writer-1 (172.28.0.40)
... 12 partitions owned by writer-2 (172.28.0.41)
```

Full `smoke-test.sh` green afterward, and a second run confirms
`create-kafka-topics.sh` is idempotent (`"... already exists, leaving it
alone"`) rather than re-creating or resizing on every lab bring-up.

## Open items

- **Full interactive browser verification is still not done.** Blocked on
  Chromium's missing shared libraries (`libnspr4` and likely others) in
  this sandboxed environment, with no passwordless sudo to install them.
  What *is* verified for real (Step 6, unchanged): production build
  succeeds, Vite dev server serves the app, component tests exercise a
  real DOM (jsdom) including the XSS property specifically.
- **The load-balancer fix's CMocka regression test has still never
  executed anywhere** (`PHASE3_DATA_PLATFORM.md`, `UPSTREAM.md`) - blocked
  on unrelated build dependencies in this environment. The live
  load-balancer re-test (20/20) remains the only validation that has run.
- Everything else from Steps 1-7 and follow-ups 1-2 is verified for real
  against live infrastructure, as documented above.
