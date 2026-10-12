# Tenancy model for production (design only, no product code)

Status: **draft, recommendation given, decision pending** — Phase 5.5 Item 1. This
compares two options for how a real multi-tenant production deployment maps tenants to
Wazuh managers. Nothing here changes the lab, which stays single-manager-per-tenant
regardless of which option is chosen (see §5, migration cost).

This doc corrects a factual error in `docs/DECISIONS.md`'s existing "Phase 5C Step 0b
follow-up" entry (recorded there in passing, not re-verified at the time): it claimed
`agent.group` is "already present on every real alert's JSON". A real read of the
4.14.8 alert-construction code (§3 below) found that's wrong, not just unverified — the
alert JSON carries no group field at all. `docs/DECISIONS.md` has been updated with a
correction note pointing back here.

## 0. Today's model, in one sentence

Tenant identity is a static environment variable (`TENANT_ID`) on the **shipper**
process, one shipper per manager node — every alert a given manager produces is
shipped under that one tenant, unconditionally, regardless of which agent produced it.
This is option (a) below, already in production use in the lab (main tenant: 3 manager
nodes behind `shadowtracer-lb`; test tenant: 1 dedicated manager, `wazuh-worker-test`).

## 1. Option (A): dedicated manager (or manager cluster) per tenant

**What it is:** exactly today's lab mechanism, unchanged. Each tenant gets its own
Wazuh manager cluster (1+ nodes) and its own shipper(s), each shipper's `TENANT_ID` set
once at deploy time. No per-event tenant logic anywhere in the Wazuh C code; tenant
identity is a property of *which process* produced the data, trusted by construction.

**Isolation strength:** the boundary sits at the **manager process/container**, the
widest boundary available. A bug that leaks data across tenants would have to cross a
process boundary (shared only if an operator misconfigures `TENANT_ID` on a shipper, or
points two tenants' agents at the same manager cluster) — there is no code path inside
a manager, shipper, writer, correlator, or console that reads one tenant's data while
believing it belongs to another, because the Kafka message key, ClickHouse row, and
Postgres row all inherit `tenant_id`/`tenant_key` from the shipper's own static config,
never from untrusted alert content. The console's query-time scoping (every query
filtered by the JWT's `tenant_id`, `app/rbac.py:37-57`) is a second, independent layer
on top of this, not the only thing standing between tenants.

**Cost per tenant (labelled estimates, not measured — no production deployment exists
yet to measure against):**

| Size | Agents | Manager topology | Rough monthly compute (estimate) |
|---|---|---|---|
| Small | 1–20 | 1 manager node (no cluster) | ~1 small VM (2 vCPU/4GB) per tenant — fixed cost regardless of agent count below cluster-worthy scale |
| Medium | 20–300 | 1 master + 1–2 workers | ~2–3 VMs per tenant |
| Large | 300+ | 1 master + N workers, load-balanced | scales with agent count, same per-tenant fixed floor plus workers |

The floor (one manager, however small the tenant) is the whole story of this option's
cost curve: a 3-agent tenant pays the same fixed manager overhead as a 300-agent
tenant pays per-worker-group. This is the number in the design brief's own framing —
cost per tenant does **not** shrink for small tenants relative to option (B), because
there is no shared infrastructure to amortize across them.

**Ops burden:**
- **Upgrades:** once per tenant, per manager cluster — N tenants means N independent
  upgrade operations (though scriptable, each is a real deploy with its own blast
  radius; see Item 3's upgrade-test work for what one such operation actually
  involves).
- **Failover:** per-tenant load balancer (today: `shadowtracer-lb`, one per tenant,
  per `docker-compose.yml`) — a tenant's failover domain is fully isolated from every
  other tenant's, which is simple to reason about but means N load balancers, N worker
  pools, N sets of the healthcheck/restart machinery already in
  `deploy/lab/docker-compose.yml`'s manager services.
- **Agent enrolment:** each tenant's agents enroll against that tenant's own
  `MANAGER_ENROLL_HOST` — operationally identical to today's lab, just repeated per
  tenant. No cross-tenant enrollment confusion is possible because there is no shared
  enrollment endpoint.

**What changes in shipper/writer/correlator/console:** nothing. This is the entire
point of the option — it is the zero-new-code path. The only "change" moving from lab
to production is operational: a deploy pipeline that stands up N manager clusters
instead of 1, not a code change to any of the four services.

**Migration cost from today's design:** zero. Today's design already **is** this
option.

## 2. Option (B): shared managers, tenant derived from the agent's group or a label

**What it is:** one (or a few, for scale) shared manager cluster serves many tenants.
Tenant identity is derived per-agent (or per-alert) from something the agent itself
carries — its Wazuh group assignment, or a label — rather than from which manager
process shipped the data. The shipper (or a new normalizer step between shipper and
Kafka) would read this field per-alert and set the Kafka message key / `tenant_id`
column from it instead of its own static `TENANT_ID` env var.

**Isolation strength: this is where option (B) runs into a real, confirmed problem,**
not a hypothetical one — see §3 for the full citation trail. Two findings:

1. **The field this option depends on doesn't exist today.** Alert JSON produced by
   `analysisd` (and `wazuh-logtest`, which shares the same code path) carries an
   `agent` object with only `id`, `name`, `ip`, and `labels` — no group field
   (`src/analysisd/format/to_json.c:50,299`; `src/analysisd/format/json_extended.c:412,
   484-500,702`). `wdb_get_agent_group()` (`src/wazuh_db/helpers/wdb_global_helpers.c:645`)
   is the only function in the codebase that reads an agent's assigned group from
   `global.db`, and its **only caller anywhere in the repo** is `remoted`
   (`src/remoted/manager.c:1569`, used for shared-config distribution) — `analysisd`
   never calls it. Making option (B) work would require **new code**: either analysisd
   gains a new field (a real upstream-adjacent change, invasive) or a new
   normalizer/enrichment step queries `global.db`/the API for each agent's current
   group out-of-band and joins it onto each alert before it reaches Kafka (less
   invasive, but adds a stateful lookup — and a new failure mode — to the hot path of
   every single event).
2. **Even with that field added, the isolation boundary would be weak by
   construction.** Group assignment is **not** purely manager-side, trusted state the
   way `TENANT_ID` is today. At enrollment, `os_auth`/`authd` accepts a client-supplied
   `-G <group>` token (`src/os_auth/auth.c:158-184`, `w_auth_parse_data()`) with only
   syntactic validation (`w_validate_group_name()`, `src/shared/agent_op.c:276` —
   character set and length only, **no check that the group exists or that this
   enrolling client is authorized to claim it**) and writes it with
   **`WDB_GROUP_MODE_OVERRIDE`** semantics (`src/os_auth/main-server.c:1136-1143`) —
   i.e. the agent's own self-declared value wins outright. The only thing standing
   between an enrolling agent and claiming any other tenant's group name is whatever
   the operator's enrollment workflow enforces *outside* this code (e.g. a
   provisioning script that only ever calls `agent-auth -G <tenant>` with a value it
   controls) — there is no in-manager authorization check tying an enrolling client's
   identity to which group names it may request. A second, narrower vector
   (`remoted`'s `guess_agent_group`, `src/remoted/manager.c:614-647`) lets an agent's
   self-reported `merged.mg` checksum auto-assign it into a group matching that
   checksum, but only when the operator has opted in (`remoted.guess_agent_group=1`,
   default `0` per `etc/internal_options.conf:216`) and only while the agent's group is
   still unset. Once an admin has explicitly assigned a group via the API
   (`framework/wazuh/core/agent.py:916`, `agent_groups -a`), ordinary agent traffic
   cannot change it (`lookfor_agent_group()` short-circuits once a DB value exists,
   `src/remoted/manager.c:1569-1574`) — so the live risk window is specifically
   **enrollment time**, not steady state.
   
   Net effect: moving tenant identity from "a property of which process shipped this
   line" (option A — trusted by construction, no agent input anywhere in the chain) to
   "a property of agent-reachable enrollment input" (option B) is a real downgrade in
   isolation strength unless enrollment itself is locked down so that an enrolling
   client cannot request an arbitrary group — e.g. per-tenant enrollment credentials
   (separate `authpass` per tenant, each only able to mint agents already scoped to
   that tenant) rather than one shared enrollment endpoint accepting any `-G` value.
   That lockdown is itself new design work, not yet specified.

**Cost per tenant (labelled estimates):** the appeal of option (B) is that it should
amortize the fixed manager floor across many tenants on shared infrastructure —
small/medium tenants no longer each pay a dedicated manager's worth of compute. At
small scale this is a real win (many tiny tenants sharing one cluster's fixed
overhead). The crossover point where a tenant's own traffic volume justifies dedicating
it a manager anyway is not estimated here — it depends on real per-event cost figures
this project doesn't have yet (Item 3/Phase 6's measurement work).

**Ops burden:**
- **Upgrades:** one shared manager cluster to upgrade regardless of tenant count — a
  single upgrade operation, but its blast radius is now every tenant sharing that
  cluster at once, where option (A)'s blast radius was always one tenant.
- **Failover:** one shared load-balanced pool; tenants no longer need their own.
- **Agent enrolment:** this is the crux — enrollment must now authoritatively bind an
  enrolling agent to exactly one tenant's group, which (per the finding above) the
  current `authd`/`os_auth` code does not do on its own. This is new operational
  surface, not a simplification.

**What changes in shipper/writer/correlator/console:**
- **Shipper:** loses its per-process `TENANT_ID` static identity; either gains a
  per-alert tenant lookup (new code, new failure mode: what happens to an alert whose
  agent has no resolvable tenant yet?) or a new normalizer step absorbs that lookup
  upstream of it.
- **Writer:** unaffected in shape — it already reads `tenant_id`/`tenant_key` off the
  Kafka message, whatever derived it. The *trust* of that field changes (previously
  shipper-asserted and trusted; now agent-influenced, per the finding above), which is
  a correctness/security concern for the writer's tenant-existence check
  (`tenants.py`'s `TenantCache`, already a real Postgres dependency per
  `docs/DECISIONS.md`'s Phase 5C Step 0 entry) even though no writer code needs to
  change to keep working.
- **Correlator:** same as writer — consumes the same Kafka key, same trust-boundary
  shift, no shape change.
- **Console:** unaffected — it already scopes every query by the JWT's `tenant_id`
  (`app/rbac.py:37-57`), independent of how that `tenant_id` got assigned to data
  upstream.

**Migration cost from today's design:** non-trivial. Requires: (a) deciding how tenant
identity reaches an alert (new analysisd field vs. new normalizer — both real
engineering, not configuration), (b) locking down enrollment so agents can't claim
arbitrary tenants (new design, not specified here), (c) a data-migration story for
existing lab/production tenants already running under option (A)'s per-manager model,
and (d) re-verifying every per-tenant isolation guarantee this project already relies
on (`docs/DECISIONS.md`'s fingerprint-isolation entry, RBAC scoping, etc.) against a
model where tenant identity is no longer trusted-by-construction.

## 3. Verification detail: is `agent.group` on every alert, and can an agent spoof it?

Full citation trail (condensed into §2 above; kept here as the dedicated answer to the
two specific questions this item asked):

- **Is agent group present on every alert's JSON?** No. Verified by reading the full
  alert-JSON construction path: `src/analysisd/format/to_json.c` (creates the `agent`
  object at line 50, writes only `id` at line 299) and
  `src/analysisd/format/json_extended.c` (adds `name` line 412, `ip` line 500 sourced
  from a synthetic `_agent_ip` label, `labels` line 702). No `group`/`agent.group` key
  is written anywhere in either file. The two `"group"` cJSON writes that do exist in
  `src/analysisd/` are unrelated: `config_json.c:255` is a **rule** classification
  group (e.g. `authentication_success`), and `to_json.c:570` is Linux audit-subsystem
  group info — neither is the agent's Wazuh group. `wazuh-logtest` shares the same
  `Eventinfo_to_jsonstr()` output path, so the same conclusion applies there too.
  (Whether some *downstream* enrichment outside `src/`/`framework/` — e.g. a
  console-side join against the agents API — ever adds a group field to what an
  operator sees is not verified either way here; not found in this repo.)
- **Is group assignment agent-asserted or manager-assigned?** Both, depending on when.
  Steady-state, admin-driven assignment (`agent_groups -a` /
  `framework/wazuh/core/agent.py:916`) is purely manager-side, and once set,
  `lookfor_agent_group()` (`src/remoted/manager.c:1562-1574`) uses the stored value
  unconditionally — ordinary agent traffic cannot change it after the fact. But at
  **enrollment**, `src/os_auth/auth.c:158-184` accepts a client-supplied `-G <group>`
  token with only syntactic validation, and `src/os_auth/main-server.c:1136-1143`
  writes it with override semantics. **An agent can claim any group name it likes at
  enrollment time**, gated only by whatever credential/network control the operator
  puts in front of the enrollment endpoint itself — there is no in-code check binding
  an enrolling client's identity to an allowed set of group names.

## 4. Recommendation

**Option (A) for now; keep (B) as a flagged future option, not a commitment.**

Reasoning: ShadowTracer has zero production tenants today, so there is no existing
cost pain from option (A)'s per-tenant fixed floor to justify option (B)'s real new
engineering (a tenant-identity field that doesn't exist yet, plus an enrollment
lockdown that doesn't exist yet) and its real isolation downgrade (agent-influenced
tenant identity vs. today's trusted-by-construction model) before any of that is
needed. Option (A) is also what the lab already proves end-to-end today, including
under the chaos/failover testing this project has already invested in
(`docs/DECISIONS.md`'s Phase 1/Phase 5C entries) — choosing it for production is zero
migration cost, not a deferred decision.

Revisit option (B) specifically when: (a) a real sales/cost pressure from many small
tenants materializes (the thing option (B) actually solves), and (b) the enrollment
lockdown problem in §2/§3 has its own design pass, not bundled into a tenancy decision
that otherwise has nothing to do with enrollment security.

I'll decide — flagged for the project owner, per Item 1's instruction, before this
moves from "recommendation" to "decided" in `docs/DECISIONS.md`.
