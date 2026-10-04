# Phase 5A - Correlation, incidents and the attack fingerprint library

Standing rules apply: commit and push per verified step, check-project.sh
before every commit, stop after two environment failures, tests on real
Kafka/PostgreSQL/ClickHouse only, tests use the isolated test databases
and never touch the lab's data.

## STEP 0 - HOUSEKEEPING

- Save this full spec as `shadowtracer/docs/specs/PHASE5A.md` and commit
  it first, so future sessions can resume from it.
- The ClickHouse schema now exists twice: the lab schema and
  `schema/test_only_clickhouse_schema.sql`. Two copies will drift. Make
  ONE schema source, with only the database name and Keeper path as
  parameters, used by both the lab and the tests. Add a check that fails
  if they ever diverge.

## STEP 1 - CORRELATION ENGINE (shadowtracer/correlate/)

- A second Kafka consumer group on the events topic. It never reads
  events back out of ClickHouse.
- The topic's 24 partitions are keyed by tenant_key + agent, so one
  worker owns an agent's events in order. Workers can move between
  partitions during a rebalance, so all incident state lives in
  PostgreSQL, never in memory.
- Grouping: alerts join an incident when they share a correlation key
  and arrive within the session gap (default 600s), up to a maximum span
  (default 4h). Key priority: (agent, source IP), then (agent, user),
  then (agent, primary rule group). Record which basis was used.
- Handle out-of-order alerts explicitly, never by crashing.
- Idempotent: an alert's membership is unique on (tenant_key, node, alert
  id). Replaying Kafka must never add an alert twice or change counts.
  Commit Kafka offsets only after the database write.
- A closer marks incidents closed after the session gap. It must be safe
  with several replicas (advisory lock), never closing twice.
- Cap stored distinct values per incident (source IPs, users) at a fixed
  number plus a total count, so one scan of 10,000 IPs can't create a
  giant row.

## STEP 2 - INCIDENTS (PostgreSQL)

- incidents: tenant_key, correlation key and basis, agent, first and
  last seen, alert count, max level, rule ids, MITRE ids, capped source
  IPs and users, state (open/closed), triage status (new/acknowledged/
  escalated/false_positive/closed), fingerprint_key.
- incident_alerts link table, unique on (tenant_key, node, alert id).
- Incidents never delete or hide alerts. Every alert stays queryable.
- Every query is filtered by the caller's tenant_key.

## STEP 3 - FINGERPRINTS

- Computed when an incident closes. The hash covers the attack's SHAPE:
  sorted rule groups, MITRE techniques in order of first appearance,
  actor class (internal/external/local, from configured internal
  ranges), target class (OS family plus optional role tag), volume
  bucket floor(log2(alert count)), and duration bucket.
- The hash NEVER includes IP addresses, usernames, ports, timestamps or
  agent ids. Hashing those turns every new source into a new
  fingerprint, and the library learns nothing.
- sha256 over canonical JSON (sorted keys, no whitespace). Store the
  ruleset version alongside it.
- Mutable state in PostgreSQL: label, notes, verdict counts, suppression
  state. Occurrence history in ClickHouse: one row per closed incident.
  Occurrence counts come from ClickHouse, not a counter incremented in
  PostgreSQL.
- Changing an agent's role tag changes its fingerprints. Every role tag
  change writes an audit row.

## STEP 4 - VERDICTS AND SUPPRESSION

- Triage on an incident updates its fingerprint's verdict counts.
- Suppression guards, all mandatory:
  - 5+ false-positive verdicts from 2+ DIFFERENT analysts only makes a
    fingerprint "proposed" for suppression
  - only an admin can make it "active"
  - active suppression expires (default 90 days) back to "proposed"
  - every state change is audited
  - suppression NEVER deletes or hides data: it only stops notifications
    and lowers placement in the default list
- Never automatic. An attacker who can trigger benign-looking alerts
  must not be able to train the system to ignore their pattern.

## STEP 5 - API AND CONSOLE

- Incident list and detail (with its alerts), and triage actions:
  acknowledge, comment, escalate, false positive. Each writes an audit
  row. Viewers cannot triage.
- Attack Library: fingerprint list and detail, with occurrence history,
  verdicts, and admin-only label, notes and suppression controls.
- All text rendered as text, never HTML. New routes are covered by the
  route-enumeration test automatically.
- Run the browser check on the new screens too.

## VERIFY (paste real output)

- SSH brute force for 2 minutes on one agent -> exactly ONE incident.
- Same attack from two different source IPs -> two incidents, ONE
  fingerprint, occurrence count 2.
- A different attack (create a local user) -> a different fingerprint.
- Hash tests: same shape with different IPs, users and times -> same
  key; different technique order -> different key.
- Replay a Kafka range -> no duplicate incident membership, counts
  unchanged.
- Kill a correlation worker mid-attack -> the open incident survives and
  keeps growing; it doesn't split in two.
- Two correlation workers -> the 24 partitions split between them,
  nothing processed twice.
- Suppression: 5 false-positive verdicts from ONE analyst -> not
  proposed; from two analysts -> proposed, not active; admin approves ->
  active; expiry returns it to proposed; all audited.
- Started-and-draining tests for the correlation consumer and the
  closer, enforced by check-project.sh.
- Report the alerts-to-incidents ratio from the lab, labelled as lab
  data, not a product claim.
