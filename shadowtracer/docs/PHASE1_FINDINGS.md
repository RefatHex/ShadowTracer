# Phase 1 findings — multi-node cluster proof

Lab: `deploy/lab/`. All images built from this fork's own source (no
published `wazuh/*` images used). Host: WSL2 (Ubuntu 22.04, 12 vCPU, 7.4GiB
RAM), Docker Desktop 4.91.0.

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

## Step 4 — smoke test

_(pending)_

## Resource usage

_(pending)_

## Surprises

- A from-source `install.sh` run can exit 0 and print "Configuration
  finished properly" while silently producing a non-functional manager
  (missing framework/API, cluster disabled, API rejecting its own config).
  None of these were caught by the build — only by actually starting the
  container and checking `wazuh-control status`. See the three bugs above.
