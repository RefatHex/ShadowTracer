# Decisions

- **Base:** Wazuh 4.14.8 with the classic (non-indexer) rules engine.
- **No Wazuh indexer or dashboard**: replaced by our own storage and console.
- **Storage:** ClickHouse for events, PostgreSQL for application data.
- **Console:** our own, not the Wazuh dashboard.
- **File scanning:** YARA-X.

## Open decisions

- ML feature location
- Licensing model
- `session.timeout.ms` tuning for the correlator's Kafka consumer group:
  left at librdkafka's default (45s), measured to produce a ~50s real
  failover on a hard `docker kill` (see PHASE5A_CORRELATION.md's chaos
  test). Not changed yet - revisit with a real slow-Postgres test (a
  worker that's alive but can't commit in time may behave differently
  than a cleanly-killed one) before deciding whether to lower it.
- **Production tenant-to-manager mapping** - see "Phase 5C Step 0b
  follow-up" below. Deferred to Phase 10.

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

## Phase 5A Step 1: correlation state lives only in PostgreSQL, never in a worker's memory

The correlator keeps zero incident state in process memory between
messages - every lookup, append, and aggregate update reads and writes
`incidents`/`incident_alerts` directly, inside one transaction per alert.
This is slower per-alert than an in-memory session cache would be, and
deliberate: the 24-partition topic's key (`tenant_key:agent_id`) only
guarantees a given agent's events stay *ordered* on one partition, not
that the same worker keeps owning that partition forever. A Kafka
rebalance (a worker joining, leaving, or crashing) can hand an agent's
partition to a different worker mid-attack at any moment, and an
in-memory design would lose that agent's in-flight incident state the
instant it did - silently splitting one real attack into two incidents,
unprovably, since nothing would ever report the handoff happened. Making
PostgreSQL the only source of truth means a rebalance is invisible to the
correlation result: whichever worker picks up the partition next reads
the exact same state the previous one left, mid-incident, and keeps
going. Verified for real in `test_killing_a_worker_mid_attack_...` by
killing a consumer thread outright (not a graceful stop) and starting a
replacement in the same consumer group.

The closer follows the same principle for a different hazard: closing is
a background sweep over ALL incidents (not partitioned), so running more
than one closer replica is a genuine concurrent-access problem, not just
a rebalance edge case. `pg_try_advisory_xact_lock` keyed on the
incident's id - the same mechanism `app/audit.py` already uses for
`append_entry`, just a per-incident key instead of one fixed key - makes
losing the race for a given incident a normal, silent no-op rather than
a double-close.

## Kafka retention: 7 days explicit on events.raw and events.dead-letter

Both topics' `retention.ms` are now set explicitly by
`deploy/lab/create-kafka-topics.sh` (7 days, `604800000`), re-applied on
every run even for a topic that already exists - the same
"explicit-not-implicit" reasoning as the partition count entry above, but
retention is a dynamic topic config (safe to change later), not a
structural property, so unlike partition count this script always
re-asserts it rather than create-once-leave-alone.

**Why this mattered**: both topics had been running on
`auto.create.topics.enable`'s implicit defaults - confirmed by querying
`events.raw`'s config before this change and finding `retention.ms`
reported with `source: DEFAULT_CONFIG, is_default: True` (604800000, the
*broker's* cluster-wide default, which only happens to already be 7 days
- nothing was pinning it there, and a future broker config change would
have silently changed it under us). `events.dead-letter` had never been
explicitly provisioned at all - like `events.raw` before Phase 4's
partition-count fix, it existed only because something had produced to
it once, at whatever partition count and retention the broker defaulted
to at that moment.

**Why 7 days, and why this is a placeholder, not a capacity-planning
result**: matches `dead_letter_events`' ClickHouse TTL (30 days;
dead-lettered diagnostic data is kept longer there than its originating
Kafka message, since replaying from Kafka is the point of the dead-letter
topic but ClickHouse is where someone actually goes looking for it) and
gives comfortable headroom over the writer/correlator's normal
consumption latency (seconds, not days) without committing to a specific
disk budget yet - revisit with real production retention/compliance
requirements before Phase 9, same caveat as the partition count decision.

**`events.dead-letter`'s partition count (6, not 24)**: no per-agent
ordering guarantee depends on this topic the way `events.raw`'s does -
dead-lettered records are inspected/replayed, never correlated by agent
- so under-provisioning it isn't the same one-way door `events.raw`'s
partition count is. 6 is "comfortably more than 1" for this topic's
expected volume (a small fraction of the main event stream), the same
placeholder spirit as 24 was for `events.raw`, not a derived number.
Note: this lab's `events.dead-letter` topic had already been
auto-created (by earlier dead-letter test runs, before this fix existed)
at the implicit 1-partition default before this script ever ran against
it - `create-kafka-topics.sh` intentionally leaves an existing topic's
partition count alone (same policy as `events.raw`), so this lab
instance is still running dead-letter on 1 partition; a from-scratch
deployment gets 6 from the start.

## /health/detail: lag measured as an AGE against retention, not just an offset count

`writer_consumer_lag` already reported lag in offsets (log end offset
minus committed offset, summed across partitions) - but an offset count
alone doesn't say how close a stalled consumer is to actually losing
data: whether 1,000,000 offsets behind means "five minutes of normal
traffic" or "about to fall off the retention window entirely" depends
entirely on produce rate, which isn't known at the health-check layer.
Converted to something that answers the real question directly: for
whichever lagging partition's oldest unconsumed message is OLDEST, how
old is it (fetched by assigning a throwaway consumer to that partition's
committed offset and reading just that one message's timestamp - it's
never committed back, so this doesn't disturb the real consumer group's
position), as a fraction of the topic's own `retention.ms` (read live via
`AdminClient.describe_configs`, not a duplicated Python constant, so it
can never drift from what's actually configured on the topic above).
Alerts past a configurable fraction (`LAG_RETENTION_ALERT_FRACTION`,
default 0.25) - a quarter of the retention window elapsed with a
consumer still behind is "this will start losing data if it doesn't
catch up soon", which is the actual operational question, not "is the
offset count non-zero".

## Phase 5C Step 0b follow-up: tenant-to-manager mapping for production (undecided, Phase 10)

`TENANT_ID` is a shipper environment variable (`x-shipper-env`/`x-shipper-test-env` in
`deploy/lab/docker-compose.yml`), and the shipper ships one manager node's entire
`alerts.json` under that one value - **tenant identity is effectively a per-manager
property, not a per-agent one.** Found concretely in Phase 5C Step 0's dedicated test
tenant work: there was no way to put just one agent (`agent-ubuntu-1`) in a different
tenant from its siblings without giving it an entirely separate manager
(`wazuh-worker-test`) and shipper (`shipper-worker-test`) - every agent that reports to
`wazuh-worker1`/`wazuh-worker2` is in the main lab tenant, unconditionally, by
construction, regardless of anything about the agent itself.

This is fine for the lab (one real tenant, one throwaway test tenant, each with its own
manager) but doesn't describe how a real multi-tenant production deployment should
work. Two options, **neither chosen yet**:

- **(a) A dedicated manager (or manager cluster) per tenant.** Simple, reuses exactly
  this lab's own mechanism unchanged - no new code, no new concept. Cost: one manager
  deployment per tenant, which stops scaling cleanly once the number of tenants is
  large relative to the traffic any one of them generates (a tenant with 3 agents still
  needs its own manager cluster, the same fixed overhead as a tenant with 300).
- **(b) Shared managers, tenant derived from the agent's own Wazuh group or a label.**
  Wazuh agents can carry a group assignment (`agent_control`/`agent_groups`) the shipper
  (or a new normalizer step) could read per-alert instead of taking tenant identity from
  its own static env var. **Correction (Phase 5.5 Item 1, see
  `docs/design/TENANCY.md` §3): the claim directly above this one - that
  `agent.group` is "already present on every real alert's JSON" - was wrong,**
  not just unverified. A real read of `src/analysisd/format/to_json.c` and
  `json_extended.c` found the alert's `agent` JSON object carries only `id`,
  `name`, `ip`, and `labels` - no group field at all; `wdb_get_agent_group()`
  (`src/wazuh_db/helpers/wdb_global_helpers.c:645`) exists but its only caller
  in the whole repo is `remoted` (`src/remoted/manager.c:1569`), never
  `analysisd`. Option (b) as originally stated cannot work unmodified. The
  investigation below (also now done) still stands on its own: group
  assignment is **agent-asserted at enrollment**, not purely manager-side -
  `src/os_auth/auth.c:158-184` parses a client-supplied `-G <group>` token
  with no existence/authorization check beyond enrollment auth, and
  `src/os_auth/main-server.c:1136-1143` writes it with
  `WDB_GROUP_MODE_OVERRIDE`. See TENANCY.md for the full citation trail and
  what this means for option (b)'s viability.

**Noted while this was found, not yet acted on:** the dedicated test tenant (Phase 5C
Step 0, item 3) bypasses `shadowtracer-lb` entirely - `agent-ubuntu-1`'s
`AGENT_MANAGER_DATA_HOST` points directly at `wazuh-worker-test`, which isn't in the
LB's backend pool. This means **no chaos/failover test run against the test tenant
exercises the LB's actual failover path** (Phase 1 item 15's capability, re-verified for
the main tenant's `worker1`/`worker2` pool in Phase 5C Step 0b's own VERIFY). Any future
LB-failover VERIFY must keep using a main-tenant-pooled agent (`agent-ubuntu-2`, as Step
0b's VERIFY did) and purge its resulting test rows afterward, same as that VERIFY did -
the test tenant's existence does not retire that obligation.

## Phase 5C: Sigma rule support - execution model, raw-event topic, identity keys, rule-selection policy (decided)

Full investigation and real-data verification in `shadowtracer/docs/design/PHASE5C_SIGMA.md`
(design doc, approved in direction); this entry records the decisions themselves, for
the same reason every other phase's design doc gets a terse DECISIONS.md summary -
this file is what the next phase reads, not the full design doc.

- **Execution model: (b), a custom streaming matcher**, not a Wazuh-XML transpiler and
  not the thin single-maintainer `pySigma-backend-clickhouse` package. pySigma used for
  rule parsing and field-mapping only (confirmed via a real spike, §8 of the design doc:
  no built-in evaluator exists in pySigma regardless of backend choice, so a custom
  matcher is required either way - this isn't a "build vs. buy" tradeoff, there is
  nothing to buy). **Rule dispatch is logsource-indexed from the start**, not a flat
  rule-by-rule scan - measured at a ~215x cost difference in the same spike, making this
  a correctness-of-architecture decision, not a later optimization.
- **New raw-event topic: `shadowtracer.events.archives`** (not `events.raw`, which
  already exists and - confusingly - carries Wazuh **alerts**, not raw pre-match
  events; the first design draft invented a different, wrong topic name and separately
  proposed `events.raw` as if it were free, which would have collided with the real
  topic of that name). Sourced from `archives.json` (`logall_json`), shipped by the
  same per-manager shipper mechanism as alerts, tagged by a `source_file` Kafka header
  distinguishing the two streams on one topic-per-manager-per-tenant model (not two
  separate topics) - see Phase 5C Step 0b follow-up's tenant-to-manager entry above for
  why that model is itself still undecided for multi-tenant production.
- **Archive event identity: `(cluster.node, file inode, byte offset)`** - not Wazuh's
  `id` field. Withdrawn after real paired-data testing (design doc §6a) found `id`
  disagreeing between an alert and its own archive copy of the *same real event* 47% of
  the time (not just colliding across different events, §11) - the shipper's existing
  `TailSource` already tracks `(inode, offset)` per file to survive rotation correctly;
  this reuses that, rather than inventing a new identity concept.
- **Alert-to-archive linking key: `(cluster.node, agent.name, timestamp, hash(full_log))`**
  - validated on real paired lab data (45 real alert/archive pairs, zero ambiguity); the
  hash-of-`full_log` half is marked an assumption in the design doc (not yet tested for
  an actual collision), everything else in this key is measured, not assumed.
- **Rule-selection policy:**
  - Default enabled: Sigma `status: stable` only. `test` is an explicit per-tenant
    opt-in; `experimental`/`deprecated` are never auto-enabled.
  - Default level: `medium` and above; `low`/`informational` are opt-in - matches the
    alert-fatigue reasoning Phase 5B's rarity/warm-up machinery already exists for.
  - Ruleset version is pinned to a reviewed commit hash (same `RULESET_VERSION`
    convention `fingerprint.py` already uses for its own shape version) - a ruleset
    bump is a reviewed, versioned change, never a silent `git pull`.
  - Per-tenant enable/disable reuses `tenant_alert_settings`, the same mechanism every
    other per-tenant knob in this project already uses - no new config table.
  - Suppression: a Sigma-sourced incident's fingerprint goes through the exact same
    `suppression_state` mechanism as a Wazuh-sourced one, by construction (both reach
    fingerprinting through the same alert shape) - no special-casing needed or added.
- **Fingerprints are unaffected by any of the above** - confirmed directly against
  `fingerprint.py`'s own code: no event id, Kafka offset, inode, byte offset, or hash
  of any kind reaches fingerprint computation from either the alert or the archive
  side. This was a real mistake in the first design draft (withdrawn, not just
  revised) and is checked explicitly in the design doc rather than assumed still true
  after the identity-key rework above.
- **Coverage, honestly, as of this decision: 0 of 3,152 Sigma rules are lab-backed
  today** (~3,152 convertible, ~14 of 210 linux rules mappable to real fields, 0 of
  2,418 windows rules - no Windows data source yet). Closing this runs through 5C-1's
  data-source work and Phase 5D's attack execution, not through this decision alone -
  recorded here so this entry doesn't imply more real coverage exists than does.

## Phase 5.5 Item 1: tenancy model for production (recommendation given, not decided)

Full design and citation trail in `docs/design/TENANCY.md`. Recommendation: option
(A), dedicated manager per tenant (today's lab mechanism, unchanged) - option (B)
(shared managers, tenant derived from agent group) needs a field that doesn't exist in
this codebase's alert JSON today, and would move tenant identity from
trusted-by-construction to agent-influenced-at-enrollment (`-G` is accepted with no
authorization check in `src/os_auth/auth.c:158-184`). Not decided yet - project owner
to weigh in.

## Phase 5.5 Item 2: local CI (done - run-ci.sh, pre-push hook, GitHub Actions diagnosis)

- **`deploy/ci/run-ci.sh`**: one command running check-project.sh, shellcheck (our own
  scripts only), the three real-database pytest suites, the frontend, and an agent
  build in a clean `ubuntu:22.04` container - sequentially, fails on first error. See
  `docs/DEV_SETUP.md`'s "Local CI" section for usage. Measured end-to-end: ~314s for
  everything through the frontend step (ingest 202s, correlate 67s, backend 31s,
  frontend 12s, check-project+shellcheck+lab-check ~2s), plus the agent build (see
  below for why its first real run took three attempts).
- **`deploy/ci/pre-push-hook.sh`** (opt-in, install command in DEV_SETUP.md): fast
  lab-independent subset only (check-project.sh, shellcheck, frontend lint+test),
  measured ~6s. The pytest suites are lab-dependent and too slow (2-4 min combined)
  for a push-time gate; no pure-unit tier exists to run instead - verified directly
  that even a test file touching no DB in its own body still pays conftest.py's full
  session-fixture cost, since every suite's autouse fixture is session-scoped.
- **Three real bugs found while building/verifying this, all fixed:**
  1. **Postgres test-DB name race, half-fixed, not fully**: the 2026-10-08 fix
     (MEMORY/project_test_suite_db_race.md) made `TEST_CLICKHOUSE_DB` session-unique
     in all three suites but left `TEST_POSTGRES_DB` as the fixed string
     `"shadowtracer_test"` in `correlate` and `console/backend` (their own comments
     *claimed* it was already session-unique - it wasn't). Fixed in both
     `tests/conftest.py` files to match `ingest`'s pattern. Verified by running all
     three suites concurrently before and after: before, `console/backend` failed
     with 94 errors; after, all three passed concurrently (and are now run
     sequentially in `run-ci.sh` anyway, for the next bug).
  2. **Postgres role race, a second, separate bug**: Postgres roles are
     cluster-global, not per-database. Every suite's Alembic migration does
     `ALTER ROLE shadowtracer_app WITH PASSWORD ...`
     (`shadowtracer/ingest/alembic/versions/5f408777ad31_*.py`) against that one
     shared role even though each suite targets its own isolated database -
     concurrent runs hit a real `psycopg2.errors.InternalError: tuple concurrently
     updated` on the shared `pg_authid` catalog row, reproduced directly by running 3
     concurrent `alembic upgrade head` processes. Not fixed in the migration itself
     (out of scope, production-affecting); `run-ci.sh` runs suites sequentially
     instead, which avoids it entirely.
  3. **Agent build fails from a clean container - two causes, both fixed**:
     (a) `cp -r` (not `-a`) resets copied files' mtimes to "now" in traversal order,
     which can make vendored `src/external/libyaml`'s pre-generated `aclocal.m4`
     look older than its own `Makefile.am` - triggering a regenerate-via-`ACLOCAL`
     rule in libyaml's shipped `Makefile` that hardcodes
     `/build_wazuh/rpmbuild/BUILD/wazuh-agent-4.8.0/...` (a leftover absolute path
     from whatever RPM buildroot produced this vendored tarball, for a far older
     4.8.0, never since regenerated) - fails with "No such file" since that path
     exists nowhere outside Wazuh's own build infra. Fixed: `cp -a` in
     `run-ci.sh` (preserves the host's already-correct mtime ordering).
     (b) `external/libbpf-bootstrap`'s CMake `ExternalProject_Add` needs `git` to
     clone its own dependency - missing from both `run-ci.sh`'s package list AND
     `.github/workflows/ci.yml`'s `build-agent` job (which only ever installed
     `build-essential automake autoconf libtool cmake`, matching `run-ci.sh`'s first
     draft exactly). `docs/DEV_SETUP.md`'s own prior verified clean-build record
     already listed `git curl wget ca-certificates` as needed - the GitHub Actions
     job just never matched it, and this was never caught because that job has never
     actually run on GitHub (every run fails before a runner is assigned - see
     below). Fixed in both files.
- **Known flaky test, found while verifying `run-ci.sh`, NOT fixed (out of this
  item's scope)**: `shadowtracer/ingest/tests/test_writer.py::
  test_replay_does_not_inflate_base_table_or_rollup` failed once in a full
  `run-ci.sh` run (asserted 10 rows after a replay, got 20 - ClickHouse's
  `insert_deduplication_token` did not dedupe that time) but passed 3/3 in
  isolation and 46/46 on an immediate full-suite rerun - consistent with the
  dedup token's window being time-bounded and occasionally exceeded under
  this test's own timing, not a regression from anything touched here. Left
  as a known flake, not chased further or fixed.
- **GitHub Actions diagnosis**: queried the public API directly
  (`api.github.com/repos/RefatHex/ShadowTracer/actions/runs`) rather than guessing.
  All 15 most recent CI runs show `status: completed`, `conclusion: failure`, each
  finishing in 1-3 seconds. Per-job detail: zero recorded `steps`, `runner_id: 0`,
  `runner_name: ""` - no runner was ever assigned to any job, for any run, so nothing
  in `.github/workflows/ci.yml` itself ever executed. `runs-on: ubuntu-22.04` is a
  valid, standard GitHub-hosted label, ruling out a bad label as the cause. This is
  consistent with an account-level block (billing/spending limit or a manual-review
  hold), not a workflow bug - `/repos/.../actions/permissions` requires auth (401), so
  this can't be confirmed further without `gh auth` or repo-admin access, and account/
  billing settings are explicitly out of scope here per instruction. Once Actions is
  unblocked, `act` (confirmed still runs `check-project` unchanged, see
  `docs/DEV_SETUP.md`) and the `build-agent` fix above mean the workflow should run
  for real, not just get scheduled, for the first time.

## Phase 5.5 Item 3: versioning and upgrades (scheme + inventory recommended, real upgrade/rollback test run)

Full writeup in `docs/design/VERSIONING.md`. Checked every place a version marker
could live today - found none wired up (`shadowtracer/VERSION` unused,
`package.json`'s version a placeholder, FastAPI's default, no Kafka envelope version
field at all). Recommends semantic versioning sourced from `shadowtracer/VERSION`,
surfaced via the API/console, plus a new `envelope_version` Kafka header - directly
motivated by the real, already-documented 46 unrecoverable pre-envelope dead letters
(`docs/PHASE3_DATA_PLATFORM.md`).

Schema inventory: Postgres/Alembic is real and versioned (13 migrations). ClickHouse
is **not** - `apply_schema()`'s `CREATE TABLE IF NOT EXISTS` silently no-ops a column
added to an existing table, demonstrated concretely (not just read from code) against
an isolated test table. Checked whether this has bitten anyone: every real schema
change in this project's git history so far added a whole new table, never altered an
existing one - the gap is real but has never actually been exercised. Proposed a
versioned migration mechanism (numbered SQL files + a tracking table) - not built yet.

Ran a real upgrade+rollback test in a genuinely separate stack
(`deploy/ci/upgrade-test/`, own network/ports/volumes, lab's 26 containers confirmed
untouched before and after): old version = commit `a233b161ce` (pre-Phase-5C) in a git
worktree, new version = HEAD, 3 real Alembic migrations apart. Generated real data
with the OLD code (tenant/admin/audit entry, 2 incidents closed into 1 real campaign
via the real `close_eligible_incidents`, a real dead letter via the real
`send_to_dead_letter`). Upgraded for real: all data and the audit hash chain verified
byte-identical before/after via the real `cli.py verify-audit-chain`. Resumption
tested by restarting the real `run_writer.py` mid-stream (3 then 4 events, same
consumer group): 7 events, 7 distinct ids, zero loss or duplication. Rollback tested
for real (`alembic downgrade`, all 3 down-migrations actually implemented, not
stubs) - data and audit chain stayed intact, but found a real caveat: one
down-migration does `DROP COLUMN`, a genuine one-way data-loss point on rollback for
any tenant with a real (non-default) value in that column - not hit by this test's
tenant, but real for production. Re-upgraded to HEAD and tore the stack down
afterward.

## Phase 5.5 Item 4: backup and restore (mechanism recommended, real restore test run)

Full writeup in `docs/design/BACKUP_RESTORE.md`. Mechanism: Postgres `pg_dump`/
`pg_restore` (logical - dataset doesn't justify `pg_basebackup` yet), ClickHouse native
`BACKUP`/`RESTORE` to a new `backups` disk, Kafka not backed up by design (7-day
retention is the replay buffer, not durable storage - bounds RPO instead).

Consistency: writer and correlator are independent Kafka consumer groups on the same
topic, so backup ordering alone cannot guarantee Postgres/ClickHouse consistency -
proposed recording both groups' offsets at backup time and replaying the behind one
on restore (same mechanism `replay_unknown_tenant_dead_letters.py` already uses for a
different gap). Verified this is actually safe to do: reset a consumer group backward
by 5 and reran it for real - raw `count()` briefly over-counted (5 duplicates,
unmerged) but `count() FINAL`/`uniqExact` were correct (7) immediately, same
`ReplicatedReplacingMergeTree` behavior already documented for `dead_letter_events`.

Ran a real restore test in a separate stack (`deploy/ci/backup-test/`, own network/
ports/volumes, lab's 26 containers confirmed untouched). Generated real data (tenant/
admin/audit entry, 5 real events through the real writer, 2 incidents into 1 real
campaign, 1 real dead letter). Backed up (BACKUP: 0.24s, pg_dump: 0.30s). Destructively
wiped both databases for real. `pg_restore` worked immediately (0.6s). **ClickHouse's
`RESTORE DATABASE` failed on the first attempt** - `REPLICA_ALREADY_EXISTS` - a real
Keeper-metadata snag: `DROP DATABASE` left `ReplicatedMergeTree` replica registrations
behind in Keeper. Fixed for real with `SYSTEM DROP REPLICA ... FROM ZKPATH ...` per
affected table (confirmed via `system.zookeeper`, not guessed), then `RESTORE`
succeeded (0.43s). All data and the audit hash chain verified byte-identical after
restore via the real `cli.py verify-audit-chain`. Console verified working against
the restored data (real login, real JWT issued). Pipeline resumption verified (7
events, 7 distinct ids, zero loss/duplication across the restore).

RPO: bounded by backup frequency, with Kafka's 7-day retention closing any
writer/correlator offset gap within that window. RTO: restore itself sub-second per
store at this dataset's size; the Keeper-cleanup step is real added time a written
runbook (not yet written) would make routine instead of a from-scratch diagnosis.

## Phase 5.5 Item 5: licence boundary inventory (not legal advice)

Full inventory in `docs/design/LICENSE_INVENTORY.md`, generated from this repo's real
dependency trees (no new SBOM tool added - Python via stdlib `importlib.metadata`,
npm via each package's own `package.json`, sidestepping the "verify the SBOM tool's
own licence" question entirely). Found: GPLv2 base (confirmed via `ruleset/`'s own
header), one copyleft Python dependency (`psycopg2-binary`, LGPL, statically bundles
`libpq` - flagged for a lawyer), 3 MPL-2.0 npm packages (`lightningcss` + 2 native
builds), no GPL/AGPL anywhere in either dependency tree. **pySigma and Sigma rules are
not yet real dependencies** - grepped every `requirements.txt` and the whole tree for
rule files, zero matches; Phase 5C's Sigma work is design-only per this file's own
"0 of 3,152 rules lab-backed" entry, so their licence obligations are future, not
current. Confirmed (by grepping, not assuming) that ShadowTracer's own ingest/
correlate/console-backend code never imports the GPL `framework` package or calls the
manager's API directly - the only GPL boundary is files (`alerts.json`/`archives.json`,
read-only) and Kafka (network), never linking.

## Phase 5.5 Item 6: threat model outline (report only, no fixes)

Full outline in `docs/design/THREAT_MODEL.md`. Every boundary's "what protects it
today" claim is evidence (a command run, a file/line cited), not a guess. Top findings,
all confirmed directly: **Kafka has zero authentication on every listener**
(`SASL`/`SSL`/`TLS` grepped across the whole compose file - zero matches) - the widest
-open boundary, and the one the tenant-isolation model depends on being closed, since
`TENANT_ID` is asserted by the shipper into that otherwise-unauthenticated bus.
**Postgres/ClickHouse traffic is cleartext** (`SHOW ssl` -> `off`, confirmed directly;
no `interface="https"` anywhere `clickhouse_connect.get_client()` is called). **One
shared `JWT_SECRET` signs every tenant's tokens** - compromise breaks cross-tenant
isolation for every tenant at once, the same single-shared-resource pattern
`docs/design/TENANCY.md` already flagged for fingerprints. **ClickHouse has no
per-service least privilege** (zero `GRANT`/`ROLE` statements in `events_schema.sql`)
where **Postgres does** (the restricted `shadowtracer_app` role, confirmed real -
`audit_log` has `UPDATE`/`DELETE` explicitly revoked from it). Real positive findings
stated too, not just gaps: secrets are gitignored and never hardcoded in compose files
(confirmed); browser-to-console already has real TLS (Caddy). Rule/feed updates and a
future SOAR don't exist yet (confirmed empty), so nothing to threat-model there today -
flagged for a real pass once either is built. No fixes made, per instruction - this is
the input to whatever gets prioritized next.
