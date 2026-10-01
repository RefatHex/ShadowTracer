# Phase 1 findings — multi-node cluster proof

Lab: `deploy/lab/`. All images built from this fork's own source (no
published `wazuh/*` images used). Host: WSL2 (Ubuntu 22.04, 12 vCPU, 7.4GiB
RAM), Docker Desktop 4.91.0.

## Phase 1 complete

**Done:** Step 0, Step 1, Step 2, Step 3 items 1-18, Step 4 (smoke test
script), Step 5 (below). Items 14 (data volume), 15 (worker outage with
failover), and 17 (full-stack restart) were redone against a corrected
test plan after the first pass - see their rows for the final results; the
original item 17 (agent network-cut) is preserved as item 18. **Carried
forward to Phase 3 as a known, documented limitation, not an open bug to
keep chasing:** the agent/load-balancer issue (Step 2 - classic Wazuh TCP
secure mode can't disambiguate multiple agents behind one shared-IP LB).

A prior session paused mid-Phase-1 after losing a large amount of time to
two compounding problems: (a) Docker Desktop's WSL integration repeatedly
dropping, and (b) every config-only change (entrypoint scripts,
`preloaded-vars*.conf`) requiring a full image rebuild, because `COPY . .`
in the Dockerfiles happened before the compile step, so editing anything
under `deploy/lab/` invalidated the compile cache and forced a 13+ minute
recompile just to test a one-line shell script change. This session applied
the fixes that prior pause called for:

1. `deploy/lab/` entrypoint and healthcheck scripts are now bind-mounted by
   `docker-compose.yml` instead of `COPY`-ed into the image at build time
   (see each Dockerfile) - editing them takes effect without any rebuild.
   `preloaded-vars*.conf` still has to be baked in (it's consumed by
   `install.sh` *during* the image build, not at container runtime, so
   there's nothing to mount), but it and the other iteration-heavy configs
   (entrypoint/healthcheck/compose/haproxy files) are now excluded from the
   Docker build context via `.dockerignore`, so editing any of them no
   longer busts the `COPY . .` layer and forces a recompile.
2. The compile step already ran before the remaining `COPY`-time config in
   all three Dockerfiles; no further reordering was needed once (1) moved
   the frequently-edited files out of the build context entirely.
3. All three Dockerfiles now build with `-j4` instead of `-j$(nproc)`.
4. No build failed twice for environment reasons this session - the one
   image rebuild needed (to pick up rule 1-3 and the item-13 osquery fix)
   completed cleanly in the background.

**A caveat the mount approach surfaced, specific to this host's Docker
Desktop + WSL2 setup:** editing a bind-mounted file while its container is
already running does *not* take effect on that running container, and
`docker restart` will outright fail rather than pick up the change - see
the eighth finding under Step 4. Use `docker compose up -d
--force-recreate <service>` after editing a mounted config; still seconds,
not a 13-minute rebuild, so the fix still holds, just not via `restart`.

## Step 1 — images built from source

| Image | Size | Build time | Notes |
|---|---|---|---|
| `shadowtracer-lab/manager:local` | 4.67 GB | ~13 min (full recompile) | single stage, full toolchain kept through install (see below) |
| `shadowtracer-lab/agent-ubuntu:local` | 601 MB | not isolated — built concurrently with the Rocky image (~18 min wall clock shared between both) | multi-stage (slim runtime is fine for agents — no framework/API needed), osquery 5.23.1 pinned |
| `shadowtracer-lab/agent-rocky:local` | 649 MB | same caveat as above | same, RPM package of osquery 5.23.1 |

Verified in both agent images: `osqueryd --version` → `5.23.1` (pinned),
`wazuh-agentd` binary present, `sttest` throwaway user present, `sshd`
present.

### Three real bugs found and fixed while getting the manager to actually run

These weren't cosmetic — each one produced a manager image that *looked*
like it built successfully (exit 0, "Thanks for using Wazuh") but was
non-functional. Root-caused by comparing against Wazuh's own official
integration-test manager Dockerfile
(`api/test/integration/env/base/manager/manager.Dockerfile`), which is a
known-working from-source build.

**1. Missing `/var/ossec/framework` and `/var/ossec/api` (manager wouldn't
start — `wazuh-apid: Configuration error`).**
The original `manager.Dockerfile` used a builder+slim-runtime split, with
`preloaded-vars-server.conf` setting `USER_BINARYINSTALL="y"` on the
assumption that the builder stage's compile already did everything
`install.sh` needed, so re-running the build in `install.sh` would be
redundant. It isn't: `install.sh`'s `Install()` function only skips its own
`make ... build` step when `USER_BINARYINSTALL` is set, but that same `make
build` invocation is what stages the embedded Python framework and the API
(`src/Makefile`'s `WPYTHON_DIR := ${INSTALLDIR}/framework/python`, with a
`pip3 install` from a locally-bundled dependency index). Skipping it left
`/var/ossec/framework` and `/var/ossec/api` never created. The slim runtime
image also had no `make`, so even when this path *did* get exercised it
failed silently (`install.sh` has no `set -e`). Fixed by merging
`manager.Dockerfile` into a single stage that keeps the full build toolchain
through the install step, and removing `USER_BINARYINSTALL` from
`preloaded-vars-server.conf` so `install.sh` does its real install. Costs
~1.5 GB of image size; correctness over slimness for this image.
(An earlier theory blamed shebang-exec (`./install.sh`) vs explicit `sh
install.sh` invocation for this — that correlation was a coincidence from
inconsistent build caching, not the real cause.)

**2. `wazuh-apid` config validation error: "`max_request_per_minute` was
unexpected".**
`entrypoint-manager.sh` appended `max_request_per_minute: 99999` at the
top level of `api.yaml`. The real schema nests it under `access:`. Fixed the
entrypoint to write `access:\n  max_request_per_minute: 99999`.

**3. `wazuh-clusterd not running` — cluster never actually configured.**
`entrypoint-manager.sh` guarded its cluster-config injection on `if !
grep -q "<cluster>" ossec.conf`, intending to add a `<cluster>` block only
if one wasn't already there. But the installed `ossec.conf` *always* ships
a default `<cluster>` block with placeholder values (empty `<key>`,
`node_name=node01`, `<node>NODE_IP</node>`, `<disabled>yes</disabled>`), so
that guard was always false and our real cluster settings never got
applied — nodes ran with cluster disabled and no key. Fixed by patching the
existing placeholders in place (`sed` on `NODE_IP`, the empty `<key>`,
`node01`, and `disabled>yes`) instead of guarding on presence/absence of
the tag.

**4. `docker compose up` never brought the master past "unhealthy",
despite all required daemons genuinely running.**
`healthcheck-manager.sh` did `STATUS=$(/var/ossec/bin/wazuh-control status)`
under `set -e`. `wazuh-control status` returns a non-zero exit code whenever
*any* daemon it knows about isn't running — including `wazuh-maild`,
`wazuh-agentlessd`, `wazuh-integratord`, `wazuh-csyslogd`, which are
disabled by default and never meant to run in this lab. Under `set -e`, that
non-zero exit silently killed the healthcheck script before it reached its
own daemon-specific logic, so the healthcheck ran, produced no output, and
failed every single time — regardless of the manager's actual health. Fixed
by capturing the status with `|| true` and checking only the specific
daemons this lab needs (`wazuh-execd`, `wazuh-analysisd`, `wazuh-syscheckd`,
`wazuh-remoted`, `wazuh-logcollector`, `wazuh-monitord`, `wazuh-modulesd`,
`wazuh-db`, `wazuh-authd`, `wazuh-apid`, `wazuh-clusterd`).

All four confirmed fixed via a standalone container run and then a real
`docker compose up`: `wazuh-apid`, `wazuh-clusterd`, and all core daemons
report running via `wazuh-control status`, `ossec.conf`'s cluster block
shows real values (key, node name, master hostname) instead of
placeholders, and the master container reaches Docker's `healthy` state.

## Step 2 — cluster lab

**Cluster (master + 2 workers): WORKS.**
`docker compose up -d` brings up all three manager nodes; all three reach
Docker `healthy`. `cluster_control -l` on the master shows all three nodes:

```
NAME     TYPE    VERSION  ADDRESS
master   master  4.14.8   wazuh-master
worker2  worker  4.14.8   172.28.0.12
worker1  worker  4.14.8   172.28.0.11
```

`cluster.log` on both workers shows continuous, successful `[Integrity
check]` and `[Agent-info sync]` cycles against the master (10s interval,
"Sync not required" once converged) — this is genuine cluster sync, not
just three independent nodes that happen to be running.

**Agent traffic through the HAProxy load balancer: BROKEN.** Discovered via
packet capture, not assumption. With agents registered the "normal" way
(`agent-auth` with no explicit IP → client.keys entry `any`), every agent
got stuck permanently in "Never connected" / a connect-close-retry loop —
*even when pointed directly at a worker, bypassing HAProxy entirely.* A
`tcpdump` capture of the raw TCP payload showed the agent's message arriving
as `#AES:<encrypted-data>` with no identifying prefix. Wazuh's classic TCP
secure-mode `wazuh-remoted` (`src/remoted/secure.c`) recognizes an agent one
of two ways: a `!<id>!` prefix for dynamic-IP ("any") agents, or a raw
source-IP lookup (`OS_IsAllowedIP`) for agents registered with a fixed IP.
Tracing `src/os_crypto/shared/msgs.c`'s `CreateSecMSG`, the `!<id>!` prefix
*should* be added for "any" agents (`!isSingleHost(ip) && isAgent`), but
empirically it wasn't happening in this build, so every "any"-registered
agent's message fell through to the IP-based lookup — which can never
succeed for an agent with no fixed IP, and which additionally can never
disambiguate *multiple* agents sharing one address (as they all would
behind a plain-TCP-passthrough load balancer, which masks every agent
behind the LB's own source IP). The exact reason the dynamic-ID prefix
isn't triggering wasn't root-caused further (would require patching/
debugging inherited `src/` C code, which needs sign-off per project rules)
— decided with the user to route around it instead of patching upstream.

**Resolution:** agents are registered with their own static IP
(`agent-auth -I <ip>`, confirmed correctly wired via
`src/shared/enrollment_op.c`) instead of `any`, given a fixed IP via
`docker-compose.yml`'s `172.28.0.0/24` subnet, and pointed directly at one
specific worker for event data (`AGENT_MANAGER_DATA_HOST` env var, patched
into `ossec.conf`'s `<server><address>` at container start) instead of
through `shadowtracer-lb`. Agents still enroll against the master directly
(unchanged, matches the original design). `shadowtracer-lb` is kept running
in the compose file (Step 2 asked for it) but carries no real agent traffic
in this lab — that's an honest limitation, not a fix.

Split: `agent-ubuntu-1` + `agent-rocky-1` → `wazuh-worker1`;
`agent-ubuntu-2` + `agent-rocky-2` → `wazuh-worker2`. Still satisfies
"agents spread across both workers" (Step 3, item 2) even without the LB
doing the spreading.

**Agent connectivity result, per OS:**
- **Ubuntu agents: WORKS.** Both `agent-ubuntu-1` and `agent-ubuntu-2`
  show `Active` in `agent_control -l` with their real static IPs.
- **Rocky agents: BROKEN, unrelated bug.** `agent-auth` enrolls
  successfully (`client.keys` populated, `agent_control -l` shows
  `Never connected` only because the agent daemon itself never starts far
  enough to send data). `wazuh-syscheckd` fails immediately:
  `/lib64/libc.so.6: version 'GLIBC_2.35' not found (required by
  /var/ossec/lib/libgcc_s.so.1)`. Rocky 9 ships glibc 2.34
  (`glibc-2.34-83.el9.7`); the `libgcc_s.so.1` bundled into `/var/ossec/lib`
  during the build requires 2.35 (Ubuntu 22.04's version). `src/Makefile`
  (line ~36) asks the *local* `g++ --print-file-name=libgcc_s.so.1` to
  source this file, which should yield a Rocky-native, glibc-2.34-compatible
  copy when run inside the Rocky builder stage — why it doesn't wasn't
  root-caused further, decided with the user to document as broken and move
  forward with the two working Ubuntu agents rather than debug the build
  toolchain further.

## Step 3 — capability verdicts

| # | Item | Verdict | Evidence |
|---|---|---|---|
| 1 | All 3 nodes connected | **WORKS** | `cluster_control -l` on the master lists all 3 nodes (master, worker1, worker2), each `4.14.8`, workers showing their real cluster-network IPs. |
| 2 | Agents spread across both workers, all active | **PARTIAL** | 2 of 4 agents active (both Ubuntu, one per worker — `agent-ubuntu-1`→worker1, `agent-ubuntu-2`→worker2), spread as designed. Rocky agents broken on an unrelated glibc bug (below). |
| 3 | Every node writes its own alerts.json, with `cluster.node`/`manager.name` | **WORKS** | worker1's alert: `"cluster":{"name":"wazuh","node":"worker1"},"manager":{"name":"wazuh-worker1"}`. worker2's: `"cluster":{"name":"wazuh","node":"worker2"},"manager":{"name":"wazuh-worker2"}`. Both fields present and correctly distinct per node. |
| 4 | Can two workers produce the same alert "id"? | **YES, they can collide** | The `id` field is `<unix_timestamp>.<per-manager-counter>` — e.g. worker1 produced `1790808809.1702794`, worker2 produced `1790808851.1702462`. Both components are generated **independently per manager process** with no node/cluster discriminator embedded. In this run the timestamps happened to differ enough to keep them apart, but nothing prevents two workers from firing an alert in the same second with the same local counter value and producing an identical `id`. **Consequence for later phases:** `id` alone is not a safe dedup/primary key across a cluster — pair it with `cluster.node` or `manager.name`. |
| 5 | SSH brute force → sshd rules fire | **WORKS** | 8 failed logins against each of the 2 active agents fired real rules: `5760` "sshd: authentication failed" (level 5), `5551` "PAM: Multiple failed logins in a small period of time" (level 10), `5763` "sshd: brute force trying to get access to the system" (level 10) — all tagged MITRE ATT&CK T1110 (Brute Force). Fired on both workers, for both agents. |

### A fourth real bug, found getting item 5 to work: rsyslog silently drops auth-facility messages written to a `touch`-created file

`entrypoint-agent.sh` added `/var/log/auth.log` as a monitored `<localfile>` (the
default agent config doesn't monitor it at all — a gap in our own lab config,
not Wazuh's), and pre-created the file with a plain `touch` so Wazuh wouldn't
choke on a missing file at startup. The failed SSH logins landed in `sshd`'s
own log stream correctly, but **nothing ever reached `/var/log/auth.log`** —
confirmed with `logger -p auth.info "test"` landing nowhere, while
`logger -p mail.err "test"` (untouched, rsyslog-owned file) worked fine.
Root cause: `touch` (running as root) created the file `root:root` mode
`644`. `rsyslog.conf` has `$PrivDropToUser syslog` / `$PrivDropToGroup syslog`
— rsyslog drops root after starting and then can't *write* to a file it
doesn't own that isn't group-writable. It fails silently; no error surfaced
anywhere we were looking. `mail.err` worked because rsyslog created that file
itself (`syslog:adm`, `0640`, matching its own `$FileCreateMode`). Fixed by
`chown syslog:adm` + `chmod 640` immediately after the `touch`. (A detour:
first tried `sshd -E <file>` to bypass syslog entirely, which does capture
the events but *without* the standard syslog prefix — timestamp, hostname,
`sshd[pid]:` tag — that Wazuh's `sshd` decoder needs to identify the source
program. Reverted; the permission fix is the real one.)

| 6 | FIM: create/modify a file in a monitored directory → alert | **WORKS** | Created then appended to `/var/ossec/lab-fim-test/testfile.txt` (realtime-watched). Rule `554` "File added to the system" fired immediately, then rule `550` "Integrity checksum changed" (MITRE T1565.001) on the edit, with full before/after size, mtime, md5/sha1/sha256 in the alert's `syscheck` object. |
| 7 | SCA: a policy scan runs and results appear | **WORKS** | `sca: INFO: Security Configuration Assessment scan finished. Duration: 20 seconds.` in the agent log. Summary alert (rule `19003`) reached the manager: CIS Ubuntu Linux 22.04 LTS Benchmark, 90 passed / 83 failed / 34 invalid of 207 checks, score 52%. |
| 8 | Rootcheck runs | **WORKS** | Agent log: `rootcheck: INFO: Starting rootcheck scan.` → `rootcheck: INFO: Ending rootcheck scan.` |
| 9 | Syscollector: installed packages available via the API | **WORKS** | `GET /syscollector/002/packages` (after authenticating as `wazuh-wui`) returned 139 packages for `agent-ubuntu-1`, each with name/version/architecture/vendor/size — e.g. `dpkg 1.21.1ubuntu2.6`, `sudo 1.9.9-1ubuntu2.6`. |
| 10 | Active response: `ar.conf` present, `disable-account` works end to end on throwaway user `sttest` | **WORKS**, needed two real fixes | `ar.conf` ships with only `restart-ossec`/`restart-wazuh` entries; `disable-account`'s `<command>` block already exists in `ossec.conf` by default. Triggering it via the API's `PUT /active-response` initially failed twice: (1) referencing it by an `ar.conf` name (even after adding one) hit `WazuhError 1652 "command not defined"` — the fix is the `!<script-name>` syntax (`"command":"!disable-account"`), which bypasses the `ar.conf`-name lookup entirely; (2) the script (`src/active-response/disable-account.c`) reads the target username *only* from `alert.data.dstuser` — passing it via `arguments`/`extra_args` (the intuitive-looking approach) silently no-ops with "Cannot read 'dstuser' from data". Correct payload: `{"command":"!disable-account","alert":{"data":{"dstuser":"sttest"}}}`. Confirmed locked (`passwd -S sttest` → `L`) immediately after. The API's `PUT /active-response` only triggers the "add" action — reversal normally fires automatically when `ar.conf`'s timeout field expires (ours was `0` = never); there's no documented "run delete now" call on this endpoint, so re-enable + delete were done directly (`usermod -U sttest`, `userdel -r sttest`) to finish the throwaway-user cleanup. |
| 11 | VirusTotal integration | **SKIPPED** | `VT_API_KEY` in `deploy/lab/.env` is blank — per the task spec itself ("Leave blank to skip that test"), not attempted. Needs a real key from whoever runs this lab next. |
| 12 | Vulnerability detection without an indexer | **Runs, produces nothing** | `<vulnerability-detection><enabled>yes</enabled>` ships on by default. `wazuh-modulesd:vulnerability-scanner` starts and runs `Initiating update feed process` on schedule — no crash, no fatal error. But every one of its outputs (vulnerabilities, package/system/process/port/hardware inventory — 15 distinct `wazuh-states-*` indices) is designed to land in the Wazuh **indexer**, not classic `alerts.json`. With no indexer running, `indexer-connector` logs `IndexerConnector initialization failed for index '...', retrying until successful` for all 15 indices, forever, and **zero** vulnerability alerts ever appear in `alerts.json`. This directly answers the open question in `DECISIONS.md`: **classic alerts.json is not a viable path for vulnerability data under our indexer-less design — a custom consumer would need to either stand up a compatible indexer/OpenSearch endpoint, or hook `indexer-connector`'s output some other way.** |
| 13 | OSQuery on an agent: wodle runs, results arrive | **WORKS**, needed two real fixes | Two gaps, both in our own lab config, not upstream: (a) `<wodle name="osquery">` ships `<disabled>yes</disabled>` by default; (b) `/etc/osquery/osquery.conf` (the path our own entrypoint already pointed `osqueryd` at) never existed, so there was nothing to schedule. Fixed by flipping the wodle to enabled and writing a minimal schedule (`system_info`, `listening_ports`, 60s interval). Once fixed, a *third* issue surfaced: the wodle has `<run_daemon>yes</run_daemon>`, meaning Wazuh spawns and owns its own `osqueryd` — our entrypoint was *also* manually launching one, and the two collided over osquery's own sqlite lock file (`osqueryd` exiting with code 78). Removed the manual launch; the wodle exclusively owns `osqueryd` now. Verified live (before the config was moved to a mounted file per this session's new build-discipline rule): `osqueryd.results.log` filled with real `system_info` (hostname, CPU, RAM) and `listening_ports` rows. Re-verified after the rebuild below: the wodle shows `<disabled>no</disabled>`/`<run_daemon>yes</run_daemon>` and `/etc/osquery/osquery.conf` is written correctly via the now volume-mounted `entrypoint-agent.sh` — confirmed with no image rebuild needed for this config. |
| 14 | Data volume under real activity: `archives.json`-to-`alerts.json` ratio, line counts and sizes per worker | **Measured** | Redone with real activity, not idle: ~14.3 minutes of normal SSH logins + commands on both Ubuntu agents (passwordless key auth, `whoami; uptime; ls /tmp` every ~75s) plus 4 deliberate failed SSH logins (1 manual + 3 scripted) targeting `agent-ubuntu-1`/worker1. `<logall>`/`<logall_json>` enabled on both workers for the window. **Worker1** (received the deliberate failures): `archives.json` 2,376→2,532 lines (+156), 5,970,553→6,084,123 bytes (+113,570); `alerts.json` 934→984 lines (+50), 2,112,741→2,161,212 bytes (+48,471). Ratio archives:alerts ≈ **3.12:1 by lines**, **2.34:1 by bytes**. **Worker2** (successful logins only, no deliberate failures): `archives.json` 2,385→2,509 lines (+124), 5,988,995→6,065,482 bytes (+76,487); `alerts.json` 933→975 lines (+42), 2,112,629→2,153,020 bytes (+40,391). Ratio ≈ **2.95:1 by lines**, **1.89:1 by bytes**. Cross-checked against worker1's own alerts: rule `5715`/`5501`/`5502` (ssh/PAM login success) each fired exactly 14 times, and rule `5760`/`5503` (ssh/PAM auth failure) each fired on all 4 deliberate failures - a 1:1 match, and proof that "normal" successful logins generate real alert volume too (`5501`/`5502` PAM session open/close), not just failures. **`logall_json` then turned off** on all 3 managers (live `sed` + `wazuh-control restart`, confirmed via `grep` showing `<logall_json>no</logall_json>` on master/worker1/worker2) and the auto-enable removed from `entrypoint-manager.sh` so it stays off by default going forward (ossec.conf's own shipped default). |
| 15 | Worker outage with failover: both Ubuntu agents configured with both workers, one worker stopped for 5 minutes, 20 test events generated, recovery measured | **Failover WORKS automatically but is slow (~3m36s) for a reason worth knowing; 19/20 events survived; no automatic move-back** | Added a second `<server>` block to each Ubuntu agent via `entrypoint-agent.sh`/`AGENT_MANAGER_DATA_HOST_FALLBACK` (mounted, no rebuild): `agent-ubuntu-1` primary `wazuh-worker1` / fallback `wazuh-worker2`, `agent-ubuntu-2` the reverse. `docker stop` (not restart) on `wazuh-worker1` at 03:58:19 UTC while `agent-ubuntu-1` was Active on it, held down for 5.5 minutes. During the outage, 20 deliberate failed SSH logins were generated on `agent-ubuntu-1` (local sshd, ~every 15s). **Failover:** `agent-ubuntu-1` reconnected to `wazuh-worker2` at 04:01:54 UTC - **3 minutes 36 seconds** after the outage began. Traced the cause in our own fork's source (`src/client-agent/start_agent.c`, `src/os_net/os_net.c`): this is not a failover-logic bug - the agent correctly exhausts `max_retries`×`retry_interval` (defaults 5×10s) against the *current* server before advancing to the next `<server>` entry, and each attempt calls `OS_GetHost()`/`getaddrinfo()` to resolve it first; a **stopped Docker container's hostname fails DNS resolution slowly** (not an instant NXDOMAIN) rather than refusing the connection instantly, which compounds across 5 retries into minutes, not seconds. `getent hosts wazuh-worker2` resolved correctly throughout, confirming the delay was entirely in exhausting the dead primary, not in finding the fallback. **Event survival:** of the 20 failed logins, **19 arrived** at worker2's `alerts.json` as rule `5760` for `agent-ubuntu-1` (1 apparently lost) - 12 delivered in a single burst at 04:01:57 (logcollector buffers locally while "locked"/offline and flushes on reconnect - confirmed via `ossec.log`'s "Process locked due to agent is offline" → "Agent is now online" messages), the remaining 7 delivered live as they occurred after reconnect. **Move-back:** `wazuh-worker1` was restored (had to use `docker compose up -d --force-recreate` per Step 4's bind-mount-inode finding, since `docker start` failed outright on the orphaned mount) and reached healthy again at 04:04:xx. `agent-ubuntu-1` **did not move back** to its restored primary - confirmed still on `wazuh-worker2` both immediately after and 2 full minutes after worker1's recovery. This matches the source: the agent only re-evaluates its server list on connection loss, never proactively migrates back while its current connection is healthy - a worker outage is "sticky" to whichever server the agent fails over to until that connection itself drops. |
| 16 | Failure behavior: restart the master | **WORKS, workers/agents unaffected during outage** | Restarted `wazuh-master` live. While it was down, confirmed via `ss` on worker1 that `agent-ubuntu-1`'s TCP session to port 1514 stayed `ESTAB` the entire time, and `wazuh-remoted`/`wazuh-analysisd` kept running on both workers without interruption - event ingestion never touches the master in this design (see Step 2), so agent data flow was not affected at all. Worker1's `cluster.log` shows `[Main] The master closed the connection` at the moment of restart, one `Could not connect to master. Trying again in 10 seconds` cycle, then `Successfully connected to master` ~18s later (self-healed, no intervention). `cluster_control -l` and `agent_control -l` on the master showed the full cluster and both active agents back to normal immediately once the master was healthy again. |
| 17 | Full-stack restart: `docker compose down` (no `-v`, nothing to keep - no named volumes exist in this lab) then `up` | **WORKS, fully automatic, ~64 seconds** | Tore down all 8 containers and the network at 04:06:56 UTC, brought everything back with a plain `docker compose up -d` at 04:07:14 UTC. All 3 manager nodes reached Docker-healthy, the cluster re-formed (`cluster_control -l` showed master/worker1/worker2), and both Ubuntu agents freshly enrolled and reached `Active` by 04:08:08-04:08:18 - roughly a minute total, zero manual steps. Notably this did **not** hit the "Duplicate IP" re-enrollment conflict from Step 4's partial agent-only recreate: tearing down the *entire* stack also resets the master's own agent registry, so there was no stale registration left to collide with. That issue is specific to recreating an agent container while the master (and its registry) keeps running - confirmed here by its absence when both reset together. |
| 18 | Failure behavior: agent loses network connectivity | **WORKS, fully automatic** | Used `docker network disconnect` on `agent-ubuntu-1` (harder cut than a container restart - severs the interface entirely, no DNS, no route). Confirmed detection two ways: the agent's own log flipped to `Could not resolve hostname 'wazuh-worker1'` / `Unable to connect to any server`, retrying every ~13s; and on worker1's side, `ss` showed the `ESTAB` session to `172.28.0.21` was gone. After ~3.5 minutes disconnected, `docker network connect --ip 172.28.0.21` restored the same address; a fresh `ESTAB` session appeared on worker1 within 9 seconds with no manual agent restart, and `agent_control -i 004` showed a live `Last keep alive` timestamp matching the reconnect time. Note: `agent_control`'s own `Active`/`Disconnected` label never flipped during the ~3.5-minute cut - Wazuh's default `<disconnect_time>` threshold (10 minutes, unset/default in this lab) is longer than the window tested, so the TCP/log-level evidence above is what actually demonstrates the detection-and-recovery behavior, not the agent_control status label. |

### A fifth and sixth real bug, found getting items 10 and 13 to work

**Active response (item 10):** see the two fixes described in the table row above — `!command` syntax instead of an `ar.conf` name, and `alert.data.dstuser` instead of `arguments`.

**OSQuery (item 13):** the osquery wodle ships disabled with no query schedule file in place, and — once enabled — conflicts with a second, independently-started `osqueryd` process over its own lock file if both are allowed to run. See table row above for the full fix.

## Step 4 — smoke test

`deploy/lab/smoke-test.sh`: brings the lab up, waits for the 3 manager nodes
and the 2 working agents to report Docker-healthy (not the Rocky agents -
see below), then checks `cluster_control -l` shows all 3 nodes and
`agent_control -l` shows both Ubuntu agents Active. This is a structural
health check, not a re-run of every Step 3 capability - those were verified
manually and are one-time proofs.

### A seventh real bug, found writing the smoke test: agent healthcheck always failing, silently, since Step 1

`healthcheck-agent.sh` did `/var/ossec/bin/wazuh-control status | grep -q
"wazuh-agentd.*is running"` under `set -euo pipefail` - the exact same bug
class as bug #4 (manager healthcheck), just never caught because nobody had
checked the agent *containers'* Docker health status before (every prior
Step 3 check used `agent_control -l`'s "Active" field instead, which is a
different, independent signal). `grep -q` exits the instant it finds a
match, which SIGPIPEs `wazuh-control status` while it's still writing;
`pipefail` then fails the whole pipeline (exit 141) even though the grep
itself matched. Every agent container had been silently "unhealthy" in
Docker's eyes (`FailingStreak` over 100) the entire session despite
`wazuh-agentd` genuinely running and agents genuinely being Active. Fixed
the same way as bug #4: capture `wazuh-control status`'s output into a
variable first, then `grep` the variable - no live pipe, no SIGPIPE.

### An eighth finding: Docker Desktop's WSL2 cross-distro bind mounts snapshot by inode, not by path

Editing a file mounted into a running container (e.g. `healthcheck-agent.sh`
after the bug-7 fix) did not take effect in that already-running container,
even though the mount is a live bind per `docker compose config`. Root
cause, specific to this host's Docker Desktop + WSL2 setup: the project
lives in a non-Docker-Desktop WSL distro, so Docker Desktop proxies the bind
mount through `/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/...`,
which snapshots the specific inode present at container-start time. An edit
that replaces the file (write-new-content-then-rename, as most editors and
this session's own edit tool do) leaves that inode orphaned - the running
container keeps serving the old content, and `docker restart` on the same
container outright fails (`no such file or directory` on the vanished
snapshot path) rather than just serving stale content. **Fix/workaround:**
`docker compose up -d --force-recreate <service>` (not `restart`) after
editing a bind-mounted file - this is still a several-second operation, not
a rebuild, so rule 1's goal (avoid the 13-minute recompile for config
edits) still holds, but "restart" is not enough on this host and will error.

Recreating an agent container this way also orphans its registration on the
master (same static IP, now empty `client.keys` in the fresh container) -
master refused re-enrollment with `Duplicate IP` until the stale `agent_id`
was removed with `manage_agents -r <id>` first. Not a bug, just an
operational step worth remembering: **removing + re-adding an agent
registration is required after force-recreating an agent container**, since
nothing in this lab persists `client.keys` across container recreates.

## Resource usage

Host: WSL2, 12 vCPU, 7.355 GiB RAM available to Docker Desktop.

**Images** (sizes from Step 1): manager 4.67 GB, agent-ubuntu 601 MB,
agent-rocky 649 MB. Full from-source rebuild of all three (`docker compose
build`, `-j4`): completed in the background within this session's
30-minute window.

**Runtime, steady state** (full lab: 3 manager nodes + 4 agents + 1 LB, 2
agents genuinely active and running their full module set - FIM, SCA,
rootcheck, syscollector, osquery):

| Container | CPU % | Memory |
|---|---|---|
| wazuh-master | 88.8% | 928 MiB |
| wazuh-worker1 | 47.6% | 1.03 GiB |
| wazuh-worker2 | 65.5% | 890 MiB |
| agent-ubuntu-1 | 0.16% | 103 MiB |
| agent-ubuntu-2 | 0.20% | 93 MiB |
| agent-rocky-1/2 (agentd not running) | 0.02% | 12-22 MiB |
| shadowtracer-lb (idle, no traffic) | 0.00% | 12 MiB |

Totals: ~202% CPU (of 1200% available across 12 vCPUs, so ~17% of host
capacity) and ~3.04 GiB memory (~41% of the 7.355 GiB available to Docker).
The 3 manager nodes account for essentially all of it - cluster sync
(`Integrity check`/`Agent-info sync` every ~10s) and the always-on module
set (`wazuh-db`, `wazuh-apid`, `wazuh-clusterd`, `analysisd`) keep each
manager busy even with only 1-2 lightly-loaded agents attached. Agents
themselves are cheap: under 1% CPU and ~100 MiB RAM each with the full
capability set (FIM, SCA, rootcheck, syscollector, osquery wodle) running.

**Data volume** (item 14, redone under real activity): over ~14.3 minutes
of normal logins/commands plus a handful of deliberate failed logins,
`archives.json` grew 2-3x faster than `alerts.json` (ratio ≈ 2.3-3.1:1
depending on worker and whether measured by bytes or lines) - and
`alerts.json` is not just failure-driven: successful logins generate real
alert volume too (PAM session open/close, `sshd: authentication success`).
See item 14's row for the full per-worker breakdown.

## Surprises

- A from-source `install.sh` run can exit 0 and print "Configuration
  finished properly" while silently producing a non-functional manager
  (missing framework/API, cluster disabled, API rejecting its own config).
  None of these were caught by the build — only by actually starting the
  container and checking `wazuh-control status`. See the three bugs above.
- A Docker healthcheck can fail 100% of the time, silently, for an entire
  session, on a daemon that is genuinely healthy - `grep -q` SIGPIPEs a
  still-writing upstream command in a pipe, and `pipefail` turns that into
  a hard failure even though the grep itself matched. Hit this twice
  independently (manager healthcheck during Step 1, agent healthcheck
  while writing the Step 4 smoke test) - worth grep-ing any future
  `cmd | grep -q ...` under `set -o pipefail` for the same pattern.
- Mounting config files into containers to dodge rebuilds (this session's
  whole fix for the prior session's biggest time sink) introduces its own
  gotcha on Docker Desktop + WSL2: the mount is pinned to an inode, not a
  path, so an editor that replaces-via-rename orphans it silently, and
  `docker restart` fails loudly instead of serving stale content. Still
  far cheaper than a rebuild (`--force-recreate` takes seconds), but not
  the zero-friction "just edit and it's live" the mount setup implies.
- Manager CPU usage stays high (50-90%) even at idle with only 1-2 agents
  attached - cluster-sync chatter and the always-on daemon set are the
  floor, not something that scales down with agent count in this build.
- Agent failover to a second `<server>` works correctly, but "the primary
  is down" takes much longer to detect than expected (3m36s, not ~60-90s)
  because a *stopped Docker container's hostname* fails DNS resolution
  slowly rather than refusing the connection instantly - and the agent's
  default `max_retries`×`retry_interval` (5×10s) is spent entirely
  re-resolving and re-trying the dead primary before it ever looks at the
  fallback. The fallback itself connects instantly once tried. A real
  deployment wanting faster failover would tune `retry_interval`/
  `max_retries` down, not assume the defaults give sub-minute failover.
  See item 15.
