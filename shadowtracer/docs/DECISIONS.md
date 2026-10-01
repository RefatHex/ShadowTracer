# Decisions

- **Base:** Wazuh 4.14.8 with the classic (non-indexer) rules engine.
- **No Wazuh indexer or dashboard**: replaced by our own storage and console.
- **Storage:** ClickHouse for events, PostgreSQL for application data.
- **Console:** our own, not the Wazuh dashboard.
- **File scanning:** YARA-X.

## Open decisions

- Capacity target
- Queue technology
- ML feature location
- Tenancy model
- Licensing model

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
