# Dev setup

## WSL2

Work inside WSL2, on the Linux filesystem — not under `/mnt/c`. Cross-filesystem
access from Windows to `/mnt/c` (and vice versa) is slow and can break file
permissions/line endings.

Repo location: `~/ShadowTracer` (e.g. `/home/<user>/ShadowTracer`).

## Line endings

`core.autocrlf` should be `input` or `false` — never `true` — since this repo
mixes LF (default), CRLF (`*.bat`), and binary files, and `.gitattributes`
already enforces normalization on checkout/commit:

```
git config core.autocrlf input
```

## Docker

Used for clean build verification and eventually for `deploy/`. Install
Docker Desktop with WSL2 integration, or Docker Engine directly inside WSL2.

## Lab memory budget (2026-11-05)

WSL froze from memory exhaustion during Phase 6.1a: ~10.6 GB anonymous memory in use,
swap full, vmbus page-allocation failures. The trigger was a `make -j10` test build
next to the running lab while managers and console backends had no memory limit.

**Host:** `.wslconfig` gives WSL 16 GB RAM and 8 GB swap. Container limits must total
less than 16 − 2.5 = **13.5 GiB**; the 2.5 GiB is for builds, Claude Code and the OS.

**Every compose service has `mem_limit` = `memswap_limit`** (no container swap) in
`deploy/lab/docker-compose.yml`. Values are the peak measured under the 4,000/s load
test plus ~30%. Two runs, 2026-11-05: 4,000/s syslog for 120 s into the test manager
with the shipper running, plus the backlog drain and a smoke run, sampled every 5 s.

| service | measured peak (MiB): docker stats / non-reclaimable* | limit |
|---|---|---|
| shadowtracer-master, -worker-test (-worker1, -worker2: **ha only**) | 454 / 365 (main); 3,743 / 814 (test manager under load) | 1216m each (was 1088m: hit `memory.max` 260k-810k times reclaiming `alerts.json` cache) |
| ch-clickhouse-1 (-2: **ha only**) | 1,420 / 1,052 | 2048m each (ClickHouse itself is capped at 1,800 MiB, `clickhouse/config.d/resources.xml`; 90 `max` events at 2304m) |
| kafka | 689 / 477 during the load test; **724** non-reclaimable hours later (heap grows to `-Xmx512m`) | 1152m (was 768m: 18,693 `max` events, ~70 MB page cache left, broker timeouts in the ingest tests) |
| postgres | 238 / 162 | 320m |
| ch-keeper | 182 / 108 | 256m |
| correlate-1, -2 | 219 / 165 | 288m each |
| writer-1, -2 | 146 / 143 (reload test); **228 anon draining a 1 M-message backlog** | 320m each (192m: OOM-killed every ~55 s while draining a backlog, 2026-11-06) |
| console-backend-1, -2 | 118 / 82 | 160m each |
| shipper-master (6.2), -worker-test (-worker1, -worker2: **ha only**) | 76 / 71 | 104m each (128m until 6.1c; cut to fund ti-matcher, still peak + 37%) |
| closer-1, -2 | 62 / 51 | 96m each |
| agent-ubuntu-1/2, agent-rocky-1/2 | 133 / 51 | 176m each |
| caddy | 61 / 15 | 80m (96m until 6.1c) |
| shadowtracer-lb | 13 / 9 | 32m |
| ti-sync (6.1b) | 74 steady; 6.2: OOM-killed at 256m importing CERT Polska's 126k domains until observations/rows were made compact, then 111 MiB for that import measured locally (lab peak below) | 256m (128m until 6.2) |
| ti-matcher (6.1c) | 77 draining a 300,000-message backlog at ~8,500/s (librdkafka prefetch capped at 16 MiB; with the 64 MiB default it OOM-killed at 128m); 6.2: one set per tenant now holds ~135k IOCs | 256m (128m until 6.2) |
| load generators (`deploy/load/syslog_fleet.sh` containers) | ~30 | 128m each |
| **total, default profile** (6.2) | | **9,472 MiB (9.25 GiB)**, 4,352 MiB under the cap |
| **total, `ha` profile** (6.2) | | **14,160 MiB**: 336 MiB **over** the 13,824 MiB cap (shipper-master +104, ti-sync and ti-matcher +128 each). Only for chaos/failover runs; backlog R7 |

**Compose profiles (6.2 housekeeping).** The default profile runs one ClickHouse replica,
the master as the main tenant's only manager (the LB sends agents to it as its backup
server, `shipper-master` ships its alerts) and the test tenant's manager. The `ha` profile
adds `ch-clickhouse-2`, `shadowtracer-worker1/2` and `shipper-worker1/2`; chaos and failover
scripts need it:

```
docker compose --env-file .env --env-file ha.env up -d && ./create-clickhouse-schema.sh
```
`ha.env` also switches ch-clickhouse-1 to the two-replica cluster definition
(`clickhouse/config.d/cluster.xml`; the default mounts `cluster-single.xml`, so ON CLUSTER
DDL never waits for a replica that is not deployed - `distributed_ddl_output_mode=
throw_only_active` does not cover a plain cluster, tested on 24.8) and the console's
replica and shipper lists. `smoke-test.sh` checks whichever profile is up (`HA=1` forces
`ha`); `recover-ch-after-crash.sh` and `repair-ch-lost-parts.sh` refuse to run without
replica 2. Back to default: `docker compose --profile ha rm -sf shadowtracer-worker1
shadowtracer-worker2 shipper-worker1 shipper-worker2 ch-clickhouse-2` (volumes kept), then
`docker compose up -d`. Recreating the master drops its agent registrations: re-enroll the
main tenant's agents with `./recreate-agent.sh agent-ubuntu-2 agent-rocky-1 agent-rocky-2`.

**Check `memory.events`, not only OOM kills.** A container can sit under its cap
and still be starved: every `max` event in
`/sys/fs/cgroup/system.slice/docker-<id>.scope/memory.events` is the kernel reclaiming
inside that cgroup. Kafka at 768m never OOM-killed but hit `max` 18,693 times with
~70 MB of page cache left, and the ingest test suite failed on broker timeouts. Size
JVM and Kafka-like services on heap + off-heap + page cache, re-measure hours into a
run (heaps grow), and keep `max` near zero for them.

\* non-reclaimable = cgroup `anon + shmem + kernel`. `docker stats` also counts active
page cache, which the kernel reclaims under a limit instead of OOM-killing. The test
manager's 3.7 GiB `docker stats` peak was mostly `alerts.json` page cache; it dropped
to ~300 MiB the moment the limit was applied. Managers are sized on non-reclaimable
memory for that reason.

Changing a limit means recreating the container (`docker compose up -d`). Recreating a
manager wipes its `client.keys`, so re-enroll its agents with `recreate-agent.sh`.
`docker update --memory X --memory-swap X <container>` applies a new limit live in the
meantime.

**Builds:** at most 4 compile jobs (`BUILD_JOBS`, default 4) in
`manager.Dockerfile`, `agent-*.Dockerfile` and `deploy/ci/run-ci.sh`, never
`-j$(nproc)`. The CI agent build container is capped at 6 GB. `.env` sets
`COMPOSE_PARALLEL_LIMIT=1` so compose builds one image at a time (manager and both
agent images each run a C/C++ build). Scratch build containers get `--memory` too.
A full `make TARGET=server TEST=1` does not fit in 6 GB even at `-j4`: `cc1plus` was
OOM-killed on the vulnerability scanner's C++ unit tests (2026-11-05). For C unit
tests, build only the daemon under test and its libraries, then just those tests:
`make TARGET=server DEBUG=1 TEST=1 -j2 wazuh-analysisd`, then in `unit_tests/build`
`cmake -DTARGET=server .. && make -j2 test_lists_list test_analysisd_hotreload`
(needs `libcmocka-dev` and `lcov`).

**Load tests:** `deploy/load/generate_load.py` refuses to start, and stops a running step
with exit code 3, when host `MemAvailable` drops below 1.5 GB
(`--min-mem-available-mb`). `e2e_step.sh` checks before each step and
`syslog_fleet.sh` reports generator exit codes. Revisit this budget whenever a
service is added (backlog R7).

## Build steps

```
cd src
make deps
make TARGET=server
# or
make TARGET=agent
```

The first build needs network access to fetch external dependencies.

### Build packages needed (Ubuntu 22.04)

Verified in a clean `ubuntu:22.04` container (2026-09-29):

```
apt-get install -y build-essential automake autoconf libtool cmake \
    curl wget git ca-certificates
```

(`policycoreutils`, `gawk`, `python3`, `sudo`, `lsb-release` were also
installed in the verification run but are not required for `TARGET=server`
or `TARGET=agent` — they matter for other targets like `TARGET=winagent`
or SELinux-enabled builds.)

`make deps` downloads prebuilt external-library tarballs from
`packages.wazuh.com` and the `http-request` submodule tarball from GitHub,
so the first build needs outbound HTTPS access.

### Build results (2026-09-29, clean `ubuntu:22.04` container, host: WSL2)

| Step | Time | Result |
|------|------|--------|
| `make deps` (TARGET=server) | 2m17s | OK, prebuilt binary deps fetched, no compilation needed |
| `make TARGET=server -j$(nproc)` | 3m40s | OK — `Done building server`, 35 compiler warnings (all pre-existing upstream code: `-Wstringop-overflow`, `-Wdiscarded-qualifiers`, one OpenSSL 3.0 deprecation, etc.), 0 errors |
| `make TARGET=agent -j$(nproc)` | 2s | OK — `Done building agent` (shares already-built objects with the server build), 4 warnings, 0 errors |

Both `src/wazuh-analysisd` and `src/wazuh-agentd` were produced.

That 2s `TARGET=agent` number is not a real agent build — it reused object
files already compiled for `TARGET=server` moments earlier. The real,
from-clean number is below.

### Real agent build (2026-09-29, fresh `ubuntu:22.04` container, host: WSL2)

`make deps`, then `make clean`, then `make TARGET=agent`, nothing else in
between:

| Step | Time | Result |
|------|------|--------|
| `make deps` | 1m18s | OK |
| `make clean` | 2s | OK |
| `make TARGET=agent -j$(nproc)` | 34s, then **Error 127** | `cd external/dbus/ && ./configure ...` → `./configure: not found` |

**`make clean` breaks a from-scratch build.** `make deps` fetches a
*prebuilt* dbus binary (only `external/dbus/lib/` and `external/dbus/include/`
— no source, no `configure` script). `make clean`'s dbus rule
(`rm -rf external/dbus/lib external/dbus/include`, `Makefile:2676`) assumes a
from-source build and deletes the only two directories that exist, leaving
`external/dbus/` completely empty. `make TARGET=agent` then tries to rebuild
`libdbus-1.a` from source (`Makefile:1290`) and there's nothing there to
configure.

The fix is simply to run `make deps` again before building — its dbus fetch
step is unconditional (unlike its source-fallback path, it isn't guarded by
`test -d external/dbus`), so it always re-populates the directory:

| Step | Time | Result |
|------|------|--------|
| `make deps` (recovers `external/dbus/`) | 1m0s | OK |
| `make TARGET=agent -j$(nproc)` | 1m18s | OK — `Done building agent`, 0 errors |

`src/wazuh-agentd` was produced. **Takeaway:** don't run `make clean` between
`make deps` and the first build in a fresh checkout; if you do, run
`make deps` once more before building.

## Local CI

GitHub Actions doesn't run on this account yet (every run fails before a
runner is even assigned — see `docs/DECISIONS.md`'s Phase 5.5 Item 2 entry).
Until that's fixed, run the same checks locally:

```
deploy/ci/run-ci.sh
```

Runs, in order, failing fast on the first error: `check-project.sh`,
`shellcheck` (on `shadowtracer/` and `deploy/` only — not the 93 inherited
Wazuh scripts this project doesn't maintain), the `ingest`/`correlate`/
`console/backend` pytest suites (sequentially — see the script's own
comment for why: a shared Postgres role races under concurrency), the
frontend (`oxlint`, `vitest`, `tsc`/`vite build`), and an agent build
inside a clean `ubuntu:22.04` container. Needs the lab stack up
(`docker compose -f deploy/lab/docker-compose.yml up -d`) for the pytest
suites, and Docker for the last step.

The exact same `check-project`/`shellcheck-syntax`/`build-agent` jobs still
run via `act` (`act -j check-project`, etc.) once GitHub Actions itself is
fixed — `run-ci.sh` is additive, not a replacement for
`.github/workflows/ci.yml`.

**Pre-push hook (opt-in):**

```
ln -sf ../../deploy/ci/pre-push-hook.sh .git/hooks/pre-push
```

Runs only the fast, lab-independent subset (`check-project.sh`, shellcheck,
frontend lint+test — ~6s measured) on every `git push`. Deliberately
excludes the pytest suites (lab-dependent, 2-4 minutes combined); those run
via `run-ci.sh` and CI. Bypass once with `git push --no-verify`.
