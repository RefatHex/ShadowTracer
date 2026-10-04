# Decisions

- **Base:** Wazuh 4.14.8 with the classic (non-indexer) rules engine.
- **No Wazuh indexer or dashboard**: replaced by our own storage and console.
- **Storage:** ClickHouse for events, PostgreSQL for application data.
- **Console:** our own, not the Wazuh dashboard.
- **File scanning:** YARA-X.

## Open decisions

- ML feature location
- Licensing model

## Phase 3: queue, tenancy, alert identity, capacity (decided)

- **Queue: Apache Kafka, KRaft mode (no ZooKeeper), Apache 2.0 licence.**
  Lab runs 1 broker (combined controller+broker). Production runs 3 brokers
  (quorum tolerates 1 node loss). Official `apache/kafka` image used, not a
  vendor repackaging, to stay inside the Apache 2.0 licence decision.
- **Tenancy: every event carries `tenant_id`.** The lab's only tenant is
  `"lab"`. `tenant_id` is the leading component of the Kafka message key
  (`tenant_id + agent_id`) and the first column in ClickHouse's sort key, so
  both partitioning and query pruning are tenant-aware from day one even
  with a single tenant in the lab.
- **Alert identity: `(cluster.node, alert id)`.** Phase 1 (item 4) proved
  Wazuh's own `id` field (`<unix_timestamp>.<counter>`) is generated
  per-manager-process with no cluster discriminator and can collide across
  nodes. `hide_cluster_info` is pinned to `no` on every manager (see
  `deploy/lab/entrypoint-manager.sh`) so `cluster.node` is always present in
  alert JSON. If `cluster.node` is ever missing (e.g. a non-clustered
  manager), the normaliser falls back to `manager.name` and logs a counted
  warning - see `shadowtracer/docs/PHASE3_DATA_PLATFORM.md`.
- **Capacity target (placeholder for sizing, not measured): 5,000
  endpoints, 90 days hot/searchable, 1 year archived.** Re-measured against
  real ingest rates in Phase 6; today it only shapes the ClickHouse TTL
  policy (see the data-platform doc).

## Operational findings carried from Phase 1

- **Raw events (`logall`/`logall_json`) should be optional per customer,
  with short retention.** Phase 1 item 14 measured `archives.json` growing
  2.3-3.1x faster than `alerts.json` under real activity - cheap to enable
  per-customer when raw-event search is wanted, expensive to leave on for
  everyone by default.
- **Agent-to-manager event delivery can lose events during a failover.**
  Phase 1 item 15: of 20 deliberate events generated while an agent's
  primary manager was down, 1 did not arrive at the fallback (19/20
  delivered, 12 of those as a buffered burst on reconnect). Action:
  investigate agent buffer settings (`<buffer>`, queue size/flush
  behavior) in Phase 3 to close that gap.
- **Observed failover time (3m36s) needs re-testing outside Docker in
  Phase 6.** Phase 1 item 15 traced the delay to a stopped Docker
  container's hostname failing DNS resolution slowly, compounded across
  the agent's default retry count - a Docker Desktop/bridge-network
  artifact, not necessarily representative of bare-metal/VM failover
  timing against a real down host.
- **Agents do not return to their primary manager once failed over.**
  Confirmed in Phase 1 item 15: an agent stays on whichever server it
  successfully reconnects to, even after its original primary recovers -
  it only re-evaluates the server list on its next connection loss. Any
  load-rebalancing design must account for this (manual or forced
  reconnect, not automatic rebalancing).

## Phase 3 Step 0: carry-over fixes from Phase 1/2

**Packaging (`.deb`/`.rpm`): still blocked, unchanged from Phase 2.**
`cat /proc/cmdline` on this host shows no `vsyscall=emulate` (kernel
6.18.40.1-microsoft-standard-WSL2 doesn't support the flag at all - it's not
missing from the boot config, the kernel has no vsyscall page). Re-ran the
Phase 2 reproduction directly: `docker run --rm debian:7 bash -c "apt-get
update"` segfaults immediately (exit 139 = SIGSEGV), identically to Phase 2.
Since the host is unchanged, this doesn't newly fix the Rocky glibc failure
either (that's a separate, already-diagnosed bug - see Phase 1 Step 2: the
Rocky image's bundled `libgcc_s.so.1` wants glibc 2.35, Rocky 9 ships 2.34).
**Recorded, not re-attempted further** - per the task's own instruction, needs
a host with real vsyscall support (older kernel, or a VM) or a from-scratch
non-`debian:7` packaging base, neither of which is in scope to improvise here.

**Agent event loss during failover: root cause is the transport, not a
buffer setting.** Traced through `src/client-agent/{buffer,sendmsg,receiver}.c`:
- `queue_size`/`events_per_second` (`client_buffer` block, defaults 5000 /
  500/s) only govern the agent's in-memory ring buffer. At 20 events over a
  5.5-minute outage, that buffer was never remotely close to full - this
  wasn't a capacity problem.
- `send_msg()` (`src/client-agent/sendmsg.c`) has **no requeue on failure**.
  `dispatch_buffer()` pops a message off the ring buffer *before* calling
  `send_msg()`; if the send fails, the message is logged and freed, never
  put back. There is no per-event application-level ACK in classic Wazuh's
  TCP secure mode - "sent" means "accepted into the OS socket buffer," not
  "received by the manager."
- Outage detection (`os_setwait()`, which pauses `dispatch_buffer` via
  `os_wait()`) only fires when `receive_msg()` returns an error in
  `receiver.c`'s 1-second `select()` loop - i.e. on the *read* side noticing
  the connection is dead. Between the manager process actually dying and
  that read-side error surfacing, a `send()` on a TCP socket can return
  success purely because the OS buffered it locally, even though the peer
  is already gone (no RST has arrived yet). A message sent in that narrow
  window is silently swallowed - accepted by the local kernel, never
  delivered, and (per the point above) never retried because `send_msg()`
  already reported success and freed it.
- **Conclusion:** this is an inherent gap in classic Wazuh's fire-and-forget
  TCP transport, not a misconfigured client.conf. No `client_buffer` setting
  closes it. This is exactly why Phase 3's shipper (Step 3) does not trust
  the agent-to-manager wire for durability - it tails the manager's own
  `alerts.json` after the fact and treats *that* as the durable source of
  truth, with its own Kafka-acked offset. Not fixed (fixing it would mean
  patching inherited `src/client-agent` C code, same class of change Phase 2
  explicitly deferred without sign-off); recorded as a known upstream
  limitation that Phase 3's design already routes around.

**Agent load balancer: real root cause found, not a config issue.** Phase 1
traced the symptom (no `!<id>!` dynamic-ID prefix on "any"-registered
agents' traffic) but didn't find the cause. Found it this session in
`src/shared/validate_op.c`'s `OS_IsValidIP()`: when the input IP string is
literally `"any"`, the function takes an early-return path that **never
allocates `final_ip->ipv4`** (it stays NULL from the initial `memset`) -
that branch is only populated when the regex-based IPv4/IPv6 matching runs,
which is skipped entirely for `"any"`. `isSingleHost()`
(`src/headers/validate_op.h`) then unconditionally dereferences
`x->ipv4->netmask` whenever `x->is_ipv6` is false - a NULL-pointer read for
every "any"-registered agent's key entry. `CreateSecMSG()`
(`src/os_crypto/shared/msgs.c`) uses `!isSingleHost(...) && isAgent` to
decide whether to prepend the dynamic-ID prefix; the undefined read makes
that check unreliable, matching the observed behavior (no prefix ever sent).
**This is a genuine bug in inherited, shared (non-agent-only) C code, not a
lab config problem** - no `ossec.conf` setting can route around a NULL
dereference inside shared validation code. Per the same sign-off rule as
Phase 2's daemon-rename decision, not patched here. Phase 1's workaround
(static IPs per agent, direct-to-worker, LB carries no real agent traffic)
stands as the documented resolution for this lab.

## Phase 3 follow-up: agent send-failure fix (requeue, not drop)

**Decision: patch `src/client-agent/buffer.c` to requeue a failed send
instead of dropping it, accepting the duplicate-event risk this creates.**

Root cause (see DECISIONS.md's Phase 3 Step 0 section above for the
original diagnosis): `dispatch_buffer()` popped a message off the agent's
ring buffer, called `send_msg()`, and freed the message **unconditionally**
regardless of whether the send actually succeeded. A send that failed in
the narrow window before `os_wait()`'s connection-loss lock engages was
silently discarded - the direct cause of Phase 1 item 15's 1-of-20 event
loss during a worker failover.

**Fix:** on a failed send, call `buffer_append()` (already-existing,
already-locked) to put the message back on the queue instead of freeing
it outright. Minimal diff - one `if` around the existing `send_msg()`
call, no change to buffer sizing, locking, or the dispatch loop's timing.

**The trade-off, stated explicitly as asked:** requeuing a message whose
send may have *actually* landed on the manager (e.g. the manager received
it but the agent's read of the response/ack failed, or the send genuinely
failed but a partial write reached a buffering layer) can produce a
duplicate event on the manager, with a **new, different alert id** from
`wazuh-analysisd` (ids are generated at analysis time, not by the agent,
so a resend is indistinguishable from a brand-new event at the point of
generation). Phase 3's dedup design identifies an alert by
`(tenant_id, cluster_node, alert_id)` - a duplicate with a genuinely
different `alert_id` is invisible to that dedup and lands as two real,
distinct rows in ClickHouse. **Accepted anyway:** for a security product,
a duplicate alert is a minor nuisance (noisier dashboards, one extra row);
a silently lost alert is a missed detection. Re-run of Phase 1 item 15
after this fix: **20 of 20** events delivered (previously 19 of 20) - see
`shadowtracer/docs/PHASE3_DATA_PLATFORM.md` for the full re-test output.

**Validation:** re-ran the exact Phase 1 item 15 scenario (20 deliberate
events during a real worker outage, failover to the second manager) rather
than adding new CMocka unit-test infrastructure for `send_msg()`/
`dispatch_buffer()` (none exists today - would have grown the diff beyond
"minimal" for a behavior that's fundamentally about real network timing,
which a mocked unit test can't exercise anyway). See UPSTREAM.md for the
change record and the drafted upstream issue/patch.

## Phase 3 follow-up: load-balancer NULL-pointer fix, static-IP workaround removed

**Decision: patch `src/shared/validate_op.c`/`src/headers/validate_op.h`,
and remove the static-IP-per-worker workaround now that the real bug is
fixed and re-verified.**

Root cause (first diagnosed in Phase 3 Step 0, not patched then pending
sign-off; sign-off given for this follow-up): `OS_IsValidIP()`'s `"any"`
branch allocated `final_ip->ipv6` but never set `final_ip->is_ipv6 = TRUE`
to match, leaving it at its `memset(0)` default of `FALSE` while
`final_ip->ipv4` was never allocated (stays `NULL`). `isSingleHost()`
(`src/headers/validate_op.h`) then read the NULL `ipv4` pointer for every
`"any"`-registered agent - undefined behavior that made
`CreateSecMSG()`'s dynamic-ID prefix decision unreliable, which is why
dynamic-IP agents behind a shared-IP load balancer could never be told
apart (Phase 1 Step 2's original finding).

**Fix:** set `final_ip->is_ipv6 = TRUE` in the `"any"` branch (the actual
root cause), plus a defensive NULL check in `isSingleHost()` itself
(`x->is_ipv6 || !x->ipv4`) as a second line of defense against the same
class of mismatch anywhere else in the codebase.

**No duplicate-vs-loss trade-off here** - unlike the send-failure fix
above, this one has no new failure mode to accept. It makes a previously
broken code path (dynamic-IP identification) work correctly; it doesn't
change what happens when something fails.

**Validation:** rebuilt the agent image with the fix, switched
`deploy/lab/docker-compose.yml`'s agents from a static IP per worker to
`AGENT_MANAGER_DATA_HOST: shadowtracer-lb` with dynamic (`"any"`)
enrollment, and re-ran Phase 1 item 15 through the load balancer: 20 of 20
events delivered, both agents reaching `Active` with `IP: any` behind the
shared LB address for the first time. The `AGENT_MANAGER_DATA_HOST_FALLBACK`
per-agent second `<server>` workaround is removed too - redundant now that
HAProxy's own backend health check does the same job in front of the agent
instead of behind it. See `shadowtracer/docs/PHASE3_DATA_PLATFORM.md` for
the full re-test output, including an unexpected bonus: failover through
the LB took 26 seconds instead of the original ~3m36s, because the agent's
one configured address (the LB, always up) never hits the slow-DNS-resolution
problem that a dead worker's own hostname did.

A unit regression test was written
(`src/unit_tests/shared/test_validate_op.c`) but **has NOT YET RUN -
status is not proven, not passing; it has produced no pass/fail result
anywhere.** It could not be executed in this sandboxed environment (see
the data-platform doc for the four distinct build failures hit trying) -
the live re-test above is the only validation that has actually run. The
CMocka test runs, and this note updates to its real result, once a Linux
build host with the full suite is available. See UPSTREAM.md for the
change record and the drafted upstream issue/patch.

## Phase 2 Pass C decision: daemon names and the system user are kept

**Decision:** do not rename the `wazuh-*` daemons or the `wazuh`/`wazuh`
system user and group. Everything else in the rebrand (text, systemd
units, the control binary, packages, deployment env vars - Pass A/B)
proceeds as already done.

**Reasons** (full data in `shadowtracer/docs/REBRAND_PLAN.md`'s Pass C
section):
- 166 inherited files touched, a much wider blast radius than Pass B's 45.
- Conflicts with cleanly applying upstream security patches - daemon
  names and the system user are exactly the kind of low-level identifier
  upstream patches are least likely to rename but most likely to
  reference by exact string (log parsing, privilege-drop code, cluster
  health checks), so keeping them matching upstream keeps `git
  cherry-pick`ing security fixes simple.
- A proven, not hypothetical, decoder dependency:
  `ruleset/decoders/0200-ossec_decoders.xml` pattern-matches the literal
  string `wazuh-logcollector` to recognize Wazuh's own internal log
  format, and already carries a legacy `ossec-logcollector` alternative
  from the original OSSEC->Wazuh rename - this exact class of breakage
  has happened before.
- Privilege-drop risk: the system user is a C macro
  (`src/headers/defs.h`'s `USER`/`GROUPGLOBAL`) used by ~15 daemons to
  drop root after binding privileged ports/files, and drives `chown`
  ownership of the entire `/var/ossec` tree at install time - renaming it
  is a filesystem migration with real failure modes, not a text edit.

**Revisit condition:** only before GA, and only if customers actually ask
for it - not proactively.

**If revisited, it will not be done by hand.** It will be a scripted,
repeatable rename applied to a pristine upstream checkout (not to
whatever hand-edited state the tree happens to be in), re-run after every
upstream update rather than maintained as a one-time diff, so it never
drifts out of sync with new daemons/files upstream adds. The script must
include, at minimum:
- Updating `ruleset/decoders/0200-ossec_decoders.xml`'s `prematch` to
  accept both the `wazuh-` and `shadowtracer-` daemon-name forms (the
  same dual-accept pattern the file already uses for the legacy
  `ossec-` names), not replace one with the other.
- Tests proving the ruleset's self-monitoring rules (anything matching
  on a daemon's own log output) still fire correctly post-rename.
- A clean-install test specifically for the renamed system user -
  confirming privilege drop, file ownership, and queue socket
  permissions all still work end to end, not just that the daemons
  start.

## Phase 4: platform core decisions

- **Shared state (rate limits, lockouts, token families) lives in
  PostgreSQL.** No Redis for now - the lab's load doesn't need a
  dedicated cache/state store yet, and adding one now would be state
  split across two systems for no present benefit. Revisit in Phase 9 if
  load demands it.
- **Console: FastAPI backend, React + Vite + TypeScript + Tailwind
  frontend, served behind Caddy with TLS.** Caddy terminates TLS and
  reverse-proxies to the backend (API) and the built frontend (static
  files); 2 replicas of the backend behind Caddy in the lab prove the
  console is stateless (no sticky sessions, no in-process state that
  would break under round-robin).
- **Every request is scoped to the tenant in the user's token.** No
  query against ClickHouse or PostgreSQL runs without a `tenant_id`
  filter - enforced by a single RBAC dependency every route goes
  through (Step 3), not left to each route handler to remember.

## Phase 4 follow-up 2: the shipper in production is a sidecar, not this lab's container

The lab runs `shipper-worker1`/`shipper-worker2` as their own compose
services (`deploy/lab/ingest.Dockerfile`), each reaching its manager
node's alert log over a shared Docker volume. That's a lab convenience,
not the production shape: a real deployment runs the shipper as a
**sidecar process installed alongside the manager on the same host** (or
in the same pod), reading `/var/ossec/logs/alerts/alerts.json` directly
off local disk under the manager's own `wazuh` user - not over a network
filesystem, and not depending on a separate container's lifecycle to stay
in sync with the manager it's shipping for. This also removes the
lab-only `chmod o+r` permission shim in `entrypoint-manager.sh`
(`shadowtracer/docs/PHASE3_DATA_PLATFORM.md`'s open items): a true sidecar
shares the manager's host/pod and can run as (or be granted read access
via) the same `wazuh` uid, so the cross-container uid mismatch this shim
works around doesn't exist in that topology. Packaging that sidecar
(install alongside the manager package, not a standalone container image)
is tracked as Phase 5+ work - out of scope for the lab's walking skeleton.

## Kafka partition count: 24, set once, not resized later

`shadowtracer.events.raw` is provisioned explicitly at 24 partitions
(`deploy/lab/create-kafka-topics.sh`), keyed by `tenant_key:agent_id`
(`shipper.py`) - not left to `auto.create.topics.enable`'s implicit
default of 1, which is what the topic had been silently running on.

**Why 24, and why this has to be decided up front rather than tuned
later:**

- **Partition count is a hard ceiling on parallelism**, for both the
  writer (Phase 3/4) and correlation workers (Phase 5+): a Kafka consumer
  group can never have more *active* consumers than partitions - the
  Nth+1 consumer in a group sits idle once every partition already has an
  owner. 2 writer replicas need at least 2 partitions to split work at
  all (3 happened to allow a 2/1 split by accident); 24 leaves headroom
  for both the writer and, later, parallel correlation workers to scale
  out independently without hitting that ceiling immediately.
- **Growing the partition count later reshuffles key-to-partition
  mapping for every existing key.** Kafka routes a keyed message to
  `hash(key) % partition_count` - changing the denominator changes the
  result for most keys, not just the new ones. Since the key is
  `tenant_key:agent_id`, that means most agents would land on a
  *different* partition than the one carrying their event history,
  breaking the per-agent ordering guarantee the partition scheme exists
  for in the first place (two events from the same agent can arrive out
  of order if they're suddenly split across two different partitions
  mid-stream). Partitions can only be grown, never shrunk, so
  under-provisioning is a one-way door too. Picking a number with real
  headroom now avoids ever needing to cross that door.
- **24 is deliberately generous for this lab's current load, not derived
  from a specific target throughput** - the cost of an oversized
  partition count (more files, more per-partition overhead) is far
  cheaper here than the cost of a resize-triggered reordering incident
  later. Revisit with real production throughput numbers before Phase 9;
  this is a lab-scale placeholder for "comfortably more than 2", not a
  capacity-planning result.

## Phase 5A Step 2/3: fingerprints are tenant-scoped, not a shared library

The fingerprint hash itself (Step 3) never includes tenant-identifying
data - sorted rule groups, MITRE technique order, actor/target class,
volume and duration buckets only - so the same attack shape in two
different tenants hashes to the literal same value. That does not mean
the two tenants share one fingerprint row: `fingerprints`' primary key is
`(tenant_key, fingerprint_key)`, and every occurrence, verdict and
suppression decision is scoped to the tenant that owns it.

**Why, given a cross-tenant library is the more obviously valuable
feature:** every other part of this project enforces hard tenant
isolation as a hard rule - RBAC on every route, `tenant_key`-filtered
ClickHouse queries, the audit log - and a shared occurrence count breaks
that rule the moment it's useful: if tenant B can see "this fingerprint
has occurred 50 times" and tenant A was 49 of those occurrences, tenant B
has just learned tenant A was attacked, without ever touching tenant A's
own data directly. A suppression decision is worse: one tenant's analysts
marking a pattern as a false positive would silently lower its visibility
for every other tenant too, including ones who've never seen it and have
no way to know their own view of a real attack was quietly deprioritized
by someone else's triage call.

The real cost of this choice: the library doesn't get smarter from
cross-customer volume the way a shared-fingerprint design would. Revisit
only with an explicit, opt-in, genuinely anonymized threat-intel-sharing
design - not as a side effect of how the hash happens to be computed.
