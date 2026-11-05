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
| shadowtracer-master, -worker1, -worker2, -worker-test | 454 / 365 (main); 3,743 / 814 (test manager under load) | 1088m each |
| ch-clickhouse-1, -2 | 1,420 / 1,052 | 2304m each (ClickHouse itself is capped at 1,800 MiB, `clickhouse/config.d/resources.xml`) |
| kafka | 689 / 477 (heap `-Xmx512m`) | 768m |
| postgres | 238 / 162 | 320m |
| ch-keeper | 182 / 108 | 256m |
| correlate-1, -2 | 219 / 165 | 288m each |
| writer-1, -2 | 146 / 143 (reload test, 2nd run) | 192m each |
| console-backend-1, -2 | 118 / 82 | 160m each |
| shipper-worker-test, -worker1, -worker2 | 76 / 71 | 128m each |
| closer-1, -2 | 62 / 51 | 96m each |
| agent-ubuntu-1/2, agent-rocky-1/2 | 133 / 51 | 192m each |
| caddy | 61 / 15 | 96m |
| shadowtracer-lb | 13 / 9 | 32m |
| load generators (`deploy/load/syslog_fleet.sh` containers) | ~30 | 128m each |
| **total of compose limits** | | **13,056 MiB (12.75 GiB)** |

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
