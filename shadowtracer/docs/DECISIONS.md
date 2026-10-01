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
