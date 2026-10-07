# Phase 5B — Rare-pattern alerting, ATT&CK coverage map, sequence detection, campaign linking

Phase 5B: rare-pattern alerting, ATT&CK coverage map, sequence detection, campaign
linking. Spec is at shadowtracer/docs/specs/PHASE5B.md. Read it first. Where this prompt
and the spec disagree, stop and tell me instead of picking one.

Rules for the whole phase: real lab only, nothing mocked in VERIFY. No ML. Everything is
deterministic and explainable. Report failures honestly and don't adjust a test to get
green. Mutable state goes in PostgreSQL, history in ClickHouse. Nothing may ever hide or
drop data.

Step 0: 5A doc fixes (small, do first)
- In PHASE5A_CORRELATION.md, state plainly that the chaos script proves failover and
  continuity, NOT redelivery de-duplication. alerts_duplicate was 0 in all 6 cycles, so
  no uncommitted message was redelivered. De-dup is proven by the Kafka replay test.
- Record the known correlator failover time: about 50s (47.8-50.3s, 6 runs), driven by
  the default session.timeout.ms of 45s.
- Do NOT change session.timeout.ms yet. Add it as an open item for a later phase, to be
  tested with a slow-Postgres run.

Step 1: Verify against the real ruleset BEFORE writing code
- Extract from the real 4.14.8 ruleset (shadowtracer/ruleset or wherever it lives; find
  it, don't guess):
  a. every rule that carries MITRE ids, giving the rule id, groups, and technique ids
  b. the set of rule groups that actually exist
- Every rule group named in any sequence YAML must exist in (b). Write a test that loads
  every sequence file and fails if a group doesn't exist. Do not invent group names.
- Print the counts: rules with MITRE ids, distinct techniques, distinct groups.

Step 2: ATT&CK static coverage map
- Build it from the inherited rules only: technique -> rule ids -> tactic.
- Expose it via the API (read-only, RBAC-protected, covered by the route-enumeration
  test) and a simple console view.
- Label it clearly as "rules that exist for a technique", NOT "attacks we detect".
  Coverage testing comes later in 5D with Atomic Red Team. Don't imply tested coverage.

Step 3: Rare-pattern alerting with warm-up guard
- Rarity is a count: how many times this fingerprint has occurred for this tenant before
  (from fingerprint_occurrences). No model.
- Warm-up guard: a tenant produces NO rare-pattern alerts until BOTH are true: at least
  7 days of data AND at least N incidents (take N from the spec; if the spec has no
  number, propose one and tell me why). Until then, show "warming up (day X of 7, Y of N
  incidents)" in the API and UI.
- A rare-pattern alert is a flag on the incident (with the occurrence count and the
  reason), never a replacement for it. The incident always exists regardless.
- A suppressed fingerprint (state "active") must not raise a rare flag, but the incident
  and its data stay visible.
- Rarity must be per tenant, never across tenants. Write a test that proves tenant A's
  history can't affect tenant B.

Step 4: Sequence detection
- YAML-defined, curated set (start small: 3 to 5 sequences). Each has an id, steps
  (rule groups in order), a time window, and the key it must match on (same agent plus
  same source IP or user).
- Evaluated by the correlator against incident and alert state in Postgres, never in
  memory (a worker restart mid-sequence must not lose progress).
- Idempotent: replaying a Kafka range must not fire a sequence twice.
- Each fired sequence records which alerts matched which step, so the analyst can see why.
- Out-of-order or partial sequences must not fire. Test both.

Step 5: Campaign linking
- A campaign links incidents with the same fingerprint AND the same actor within a 24h
  window. Define "actor" explicitly (source IP first, then user) and document it.
- Different actor, same fingerprint -> NOT the same campaign.
- Same actor, same fingerprint, 25h apart -> NOT linked. Test the window edges.
- Campaign state in Postgres, with membership idempotent on replay.

VERIFY (real lab, same standard as 5A):
- Brute force from one IP, repeated twice inside 24h -> ONE campaign, 2 incidents.
- Same attack from a second IP -> same fingerprint but a separate campaign.
- A fresh tenant -> no rare flags during warm-up. A tenant past warm-up with a never-seen
  fingerprint -> a rare flag with the correct count.
- A real sequence (for example, a failed-login burst followed by a success from the same
  IP) -> fires once. Replay the Kafka range -> still once. Kill a correlator mid-sequence
  (docker kill, as in 5A) -> it completes correctly on the survivor.
- Show the real SQL and API output for each.
- Run the VERIFY script twice from clean; both runs exit 0.

Rules for finishing:
- check-project.sh passes, all existing tests stay green, new tests added for every
  behaviour above.
- Update PHASE5B doc with the real outputs. Record any limitation honestly (for example,
  the sequence set is small by design).
- Commit and push, then paste the final real outputs.
- If any step shows a real bug (duplicate firing, lost sequence state, cross-tenant
  leak), stop and send me the output before fixing.

Do NOT start Phase 5C (Sigma) until I confirm. 5C needs a raw-event stream and a
field-mapping design first, so it begins with a design doc, not code.

## Addendum (resolved before Step 1, per follow-up instruction)

- There is no separate Phase 5B spec document - this task prompt IS the spec.
  The "where this prompt and the spec disagree, stop and tell me" line above is
  explicitly waived; there is nothing else to disagree with.
- Step 3's open number (N incidents for the warm-up guard) is resolved as:
  - Warm-up: at least 7 days of data AND at least **30 incidents** for that tenant.
  - Both values (7 days, 30 incidents) are **per-tenant configuration with these
    as defaults**, not hardcoded constants.
  - **30 is a starting guess to be checked against real tenant volume, not a
    measured value** - record this honestly wherever the warm-up guard is
    documented or surfaced.
