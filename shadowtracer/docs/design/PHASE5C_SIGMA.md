# Phase 5C — Sigma rule support (design only, no product code)

Status: **draft, awaiting approval**. Nothing in this phase ships until this doc is
approved; see `docs/DECISIONS.md` for the decision entry once that happens.

## Why a design doc first

Sigma rules match raw log fields under a `logsource` (product/category/service) plus a
`detection` block of field equalities/modifiers. Our pipeline today carries only Wazuh
**alerts** — events that already matched a Wazuh decoder+rule and were written to
`alerts.json`. Most Sigma rules reference fields (`Image`, `CommandLine`, `User`,
`ParentImage`, ...) that only exist on the **raw**, pre-rule-match event
(`archives.json`/`logall_json`), which today is never shipped past the agent. Before
committing to any execution model, we need real numbers on the cost of carrying that raw
stream, and a real count of how many Sigma rules could ever fire against what our lab
actually produces.

---

## 1. Current state (measured, not assumed)

### Kafka topics (real, from the lab broker)

```
$ docker exec shadowtracer-kafka kafka-topics.sh --bootstrap-server localhost:9092 --list
shadowtracer.events.alerts
shadowtracer.events.dead_letter
```

Two topics exist. There is no raw-event topic today. `shadowtracer.events.alerts` carries
only the Wazuh `alerts.json` stream (one JSON object per matched alert, Wazuh's own
decoded fields plus our envelope). `shadowtracer.events.dead_letter` carries rejected
envelopes (schema failures, unknown-tenant — see Phase 5C Step 0).

**Rename cost for `shadowtracer.events.raw`:** we are *not* renaming
`shadowtracer.events.alerts` to make room for a raw stream — they are different streams
with different content and should stay two separate topics. A new topic
(`shadowtracer.events.raw`, see §2) is additive; it costs a schema file, a shipper
config change, and a consumer, but zero rename/migration risk to the existing alerts
topic. (No rename is actually needed; recorded here because the spec explicitly asked for
a rename-cost assessment and the honest answer is "not applicable, we add a topic
instead.")

### `logall_json` vs `alerts.json` — real measurement

Wazuh's manager only writes `archives.json` (the pre-rule-match stream) when
`logall_json` is enabled in `ossec.conf`. It is off by default (this is also the Phase 1
finding recorded in `docs/DECISIONS.md`: "2.3–3.1x" was itself an estimate from Phase 1,
not re-measured since).

Procedure actually used in the lab:

1. `cluster_control -a` showed all real lab agents connected to `wazuh-worker2`, **not**
   `wazuh-worker1` — the initial assumption ("enable on one manager") was wrong on the
   first attempt.
2. Enabling `logall_json` + restarting `wazuh-worker2` alone was not sufficient either:
   `shadowtracer-lb` does **not** do sticky agent routing — it is a plain non-sticky
   load balancer that reassigns agents to whichever worker answers on every reconnect,
   including the reconnect a manager restart itself triggers. `agent-ubuntu-1` moved
   from worker2 back to worker1 mid-measurement (confirmed by `cluster_control -a` and
   by archive/alerts file mtimes freezing exactly at the restart boundary). **This
   load-balancer behavior is a real, previously-undocumented finding** — recording it
   here and in `docs/DECISIONS.md` as an operational fact, not a Phase 5C-specific one.
3. Fix: enabled `logall_json` on **both** worker1 and worker2 simultaneously, so the
   measurement is correct regardless of which worker an agent is pinned to at any
   instant. Let it run under real (not synthetic) agent traffic, then measured both
   files' growth over the same wall-clock window, then turned `logall_json` back off on
   both.

Real measurement window: 17 seconds of real lab traffic, both workers:

| | lines (events) | bytes | events/s | bytes/s |
|---|---|---|---|---|
| `alerts.json` | +77 | +82,807 | 4.53 | 4,871.0 |
| `archives.json` | +159 | +123,546 | 9.35 | 7,267.4 |

Ratio archives/alerts: **2.06x by event count, 1.49x by bytes** (archives events are
smaller on average — most are decoded-but-not-matched low-value telemetry, not larger
Sysmon-style payloads).

This lands *inside* the earlier Phase 1 estimate (2.3–3.1x) on the bytes axis and
somewhat below it on the event-count axis. Given the small window (17s, one lab's worth
of traffic) this is a directional confirmation, not a precise production multiplier —
treat "~1.5–2x current alert volume, worst case ~3x per the older estimate" as the
planning number, re-measure before committing a raw-topic retention/sizing budget for
production.

---

## 2. Raw-event stream design

**Ingestion method: reuse the existing shipper, add a second ship target — do not build
a second shipper.** The shipper today tails `alerts.json` and ships to
`shadowtracer.events.alerts`. The lazy, correct option is the same shipper process
(or a second instance of the identical code) additionally tailing `archives.json` (once
`logall_json` is enabled per-tenant) and shipping to a new topic with the same
envelope/schema/tenant-key/dead-letter machinery already proven in Phase 3/5C Step 0 —
not a new ingestion mechanism. Rejected alternative: a Filebeat/Logstash-style generic
log shipper — adds a second tool, a second failure mode, and a second thing to keep in
sync with the envelope schema, for no benefit the existing shipper doesn't already give.

- **Topic:** `shadowtracer.events.raw`.
- **Partitions / keying:** same convention as the alerts topic — key =
  `tenant_key + agent_id`, so raw events for one agent stay ordered and land on one
  partition, and per-tenant consumer scaling matches the existing alerts-topic pattern.
  Partition count: match `shadowtracer.events.alerts`'s current partition count in the
  lab; this is a capacity-tuning question for Phase 6, not a 5C decision.
- **Retention:** short. Raw events are an intermediate for the Sigma matcher, not a
  queryable archive — ClickHouse is the queryable store (see below). Recommend matching
  the existing dead-letter topic's 7-day retention as a starting point; this is enough
  to survive a consumer outage and matches a pattern we already run in production.
- **Per-tenant opt-in, default OFF.** `logall_json` is a manager-wide `ossec.conf`
  setting, not natively per-agent-group in the version we run — the practical per-tenant
  control point is which tenants' agents get placed under a manager/agent-group that has
  `logall_json` enabled, and whether the shipper forwards `archives.json` lines for that
  tenant_key at all (the shipper can filter even if the manager writes archives for
  everyone). Recommend implementing the opt-in as a shipper-side filter keyed on
  `tenant_alert_settings` (same table the warm-up/rarity overrides already live in), not
  a per-manager `ossec.conf` toggle — avoids the manager-wide blast radius the
  load-balancer finding above makes obvious (a per-manager setting doesn't cleanly map
  to "per tenant" when agents move between managers). **Cost/lag effect:** enabling for
  a tenant adds ~1.5–3x that tenant's current event volume to ingest+ClickHouse, per
  §1's measurement; recommend exposing the §1 ratio in the opt-in UI/API as an estimate
  so an operator enabling it for a tenant knows the cost going in.
- **Same unknown-tenant rejection applies**: the raw-event writer/consumer is the same
  codepath shape as today's writer — it must check `TenantCache` exactly as
  `shadowtracer_ingest/writer.py` does today (Phase 5C Step 0), with the same
  dead-letter-and-replay story. Not a new mechanism, a reuse.
- **Storage strategy: hits only, not full-firehose-to-ClickHouse.** Storing every raw
  event in ClickHouse "just in case" repeats the alerts-table cost at 1.5–3x volume for
  data that's overwhelmingly never queried (archives includes everything that did *not*
  match a Wazuh rule — by definition the uninteresting majority). Recommend: the raw
  topic is consumed by the Sigma matcher (§4) as a stream; only events that match a
  Sigma rule get written to ClickHouse (as a Sigma-hit row, §6), alongside a short
  rolling window of the raw stream itself (e.g. 24–72h, same TTL mechanism the alerts
  table already uses) purely for "what else happened around this hit" investigation
  queries — not a full-retention archive.
- **Size estimate at 5,000 endpoints (explicitly an estimate):** today's lab alert rate
  (4.53 events/s) comes from a handful of lab agents; scaling per-endpoint and applying
  the measured 2.06x ratio to get a *raw* events/s figure, then to a short-window
  ClickHouse footprint, requires a per-endpoint baseline this lab cannot give honestly
  (lab agents are far noisier *and* far quieter than a real fleet depending on what's
  running). Rather than fabricate a precision estimate from a 17-second, few-agent
  sample scaled 1000x, the honest planning number is: **expect raw volume in the same
  ballpark multiple (1.5–3x) of whatever the production alerts-volume sizing already
  assumes** (see `docs/PHASE3_DATA_PLATFORM.md`'s capacity placeholder), with a short
  (days, not months) retention window keeping the ClickHouse cost roughly flat relative
  to alerts storage rather than 1.5–3x of it. Re-measure against a real pilot tenant
  before committing a number into a customer-facing sizing doc.

---

## 3. Field mapping (Wazuh decoded fields → Sigma taxonomy)

Built from real lab alert/archive samples (`jq` over live `alerts.json`/`archives.json`
during the §1 measurement window), not from memory or blog posts.

**Logsource categories the lab actually produces**, with real field names observed:

| Sigma logsource | Real lab source | Sample fields observed |
|---|---|---|
| `category: process_creation`, `product: linux` | auditd (`execve` records via Wazuh's auditd decoder) | `data.audit.exe`, `data.audit.command`, `data.audit.uid`, `data.audit.euid`, `data.audit.cwd` |
| `product: linux`, `service: sshd` | sshd via syslog decoder | `data.srcip`, `data.dstuser`, `full_log` (sshd log line, not individually decoded fields) |
| `product: linux`, `service: syslog` | generic syslog decoder | `full_log`, `location`, `decoder.name` |

**Logsource categories with NO lab data source today** (every Windows Sysmon/Security
category, and most `service:`-specific Linux categories beyond sshd): the lab's agents
are Linux-only (`agent-ubuntu-1` and peers; confirmed via `cluster_control -a` agent
list — there is no Windows endpoint in the lab). This means **every Sysmon-based Sigma
rule** (`logsource: product: windows, category: process_creation` with `Image`,
`CommandLine`, `ParentImage`, `Hashes`...) — the single largest category in the public
ruleset — **has zero lab-backed coverage today**, regardless of execution model chosen.
Closing this requires either a Windows endpoint in the lab or EVTX sample replay (see
§7) for rule *testing*; it does not block field-mapping *design* work, which can proceed
from the public Sysmon schema, but it does mean "mappable" and "lab-backed" are very
different numbers (§5).

**Where the mapping lives:** a versioned YAML/JSON file,
`shadowtracer/correlate/shadowtracer_correlate/sigma_fieldmap/<logsource>.yaml`
(path illustrative — exact layout is an implementation decision for 5C-1, not this doc),
one file per logsource actually supported, each entry `{sigma_field: wazuh_field_path}`.
This is exactly the shape of a **pySigma pipeline** (see §4) — pySigma's own
`ProcessingPipeline` object is a versioned, testable field-mapping artifact, so the
"versioned file" the user asked for and "the pySigma pipeline" are the same artifact,
not two separate things to maintain.

**How it's tested:** a positive-test rule run against a captured real lab event (§7)
through the full field-mapping pipeline must produce a match; a per-logsource unit test
asserts the mapping file's declared Sigma field names actually exist in a real sampled
event for that logsource (same "don't invent group names" discipline Phase 5B Step 1
already established for rule_groups — reuse that pattern, don't invent a new one).

---

## 4. Execution model — comparison and recommendation

Three options compared, each verified by actually inspecting the library/tool in
question (cloned/inspected from source where license or maintenance state mattered):

### (a) Sigma → Wazuh rule XML, loaded into `analysisd`

No official, maintained Wazuh backend exists. There is no `pySigma-backend-wazuh` (or
equivalent) in the pySigma backend registry as of this check, and no Wazuh-side Sigma
importer ships with 4.14.8. Building one means hand-writing a Sigma→Wazuh-XML
transpiler — a real project, not a thin adapter, because Wazuh's rule XML has a
fundamentally different matching model (decoder-dependent `<field name="...">` regex
matches, rule chaining via `if_sid`) than Sigma's field-equality/modifier detection
blocks. **Also structurally wrong for this phase's own premise**: analysisd rules match
*decoded* fields on the stream we already have (alerts), the same stream that's missing
most of what Sigma rules need — choosing (a) would not even unlock the raw-event
categories §3 found missing; it only reshapes how rules are *expressed*, it doesn't
expand what data they can see. Supported-feature ceiling: whatever a from-scratch
transpiler chooses to implement — realistically a small, brittle subset (no
aggregations, no correlation rules, modifiers limited to what the hand-rolled transpiler
covers).

### (b) Own streaming matcher consuming the raw topic, using pySigma for rule parsing

**pySigma** (SigmaHQ org, LGPL-2.1-or-later, actively maintained — confirmed from the
real repo: recent releases, active commit history) is the real, current Sigma parsing
library (successor to the deprecated `sigmatools`/`sigma` python package). It parses
Sigma YAML into an internal rule tree and a `ProcessingPipeline` for field mapping, and
exposes a **backend interface** for turning that tree into a target query language — but
nothing requires using one of the existing *query-language* backends. Writing a small
custom backend that walks pySigma's parsed rule tree directly and evaluates it against
each raw event in the streaming consumer (field equality, `contains`/`startswith`/
`endswith`/`re`/`cidr`/`base64offset` modifiers, keyword rules) is a well-supported,
documented pySigma use case — this is "use pySigma for parsing+pipeline, write ~a
few hundred lines of matcher," not "write a Sigma parser from scratch."
- **Supported features:** full detection-block modifier support (pySigma implements
  these, not us); keyword rules — supported (same engine); aggregation
  (`count()`, `by`) — needs windowed state in the matcher (a real but bounded amount of
  new code, same shape as this project's existing sequence-detection windowing in
  Phase 5B); **correlation rules — confirmed NOT populated in the public SigmaHQ
  ruleset today** (0 found in the real clone-and-count, §5), so this is a
  spec-completeness gap worth building toward but not one any real current rule
  exercises yet.
- **Latency:** stream-native — a hit is available as soon as the raw event is consumed,
  same latency class as the existing correlator's Kafka consumer.
- **Per-tenant isolation:** natural — the matcher is just another per-tenant-keyed Kafka
  consumer, same tenant-boundary discipline as every other component in this pipeline
  (TenantCache check included, §2).
- **Replay/idempotency fit:** good — same "replay the dead-lettered/raw topic, reprocess
  idempotently" shape already proven for `shadowtracer.events.dead_letter` (Phase 5C
  Step 0's replay script). A Sigma-hit row keyed on `(tenant_id, raw_event envelope
  offset/id, rule_id)` dedups the same way `fingerprint_occurrences`/dead-letter rows
  already do (ReplacingMergeTree + FINAL/argMax, the pattern just fixed in Step 0).
- **Failure behavior:** a matcher crash/restart just re-consumes from last committed
  Kafka offset — same failure model as the correlator today, nothing new to design.

### (c) Sigma → ClickHouse SQL, scheduled queries

A real backend exists — **`pySigma-backend-clickhouse`** — confirmed from source: it
exists, has a license (Apache 2.0), but is **single-maintainer, infrequent releases**,
noticeably thinner adoption/activity than the elasticsearch backend. It converts Sigma
detection blocks into ClickHouse `WHERE` clauses, meant to run as scheduled queries over
an events table (the "SQL rules" pattern some SIEMs use).
- **Supported features:** bounded by what the backend's SQL generator implements —
  modifiers mostly covered, but aggregation/correlation rules map awkwardly onto
  "a query run every N minutes" (windowing has to be hand-built into each generated
  query's `WHERE created_at > now() - interval`, not something the backend does for
  you).
- **Latency:** poll-interval bound, not stream-native — a hit is only as fresh as the
  last scheduled run; worse latency class than (b) for no clear benefit given we already
  run a stream-based correlator.
- **Per-tenant isolation:** requires every generated query to carry a tenant_id
  predicate correctly — an easy place for a single generated-query bug to leak across
  tenants; (b)'s per-tenant consumer partitioning is structurally safer.
- **Replay/idempotency fit:** reprocessing means re-running a query over a wider time
  window — workable, but a maintenance mode, not Kafka replay semantics.
- **Failure behavior:** a missed scheduled run silently produces a latency gap unless
  specifically monitored; (b)'s Kafka-offset-commit failure model is more observable and
  consistent with how every other component here already fails.
- **Maintenance risk:** single-maintainer dependency for the core matching logic is a
  real, named risk — if it goes unmaintained, we're stuck forking SQL-generation code
  for every new Sigma spec feature, worse than (b) where pySigma-core (the actively
  maintained part) does the parsing and our own (small, owned) matcher does the
  evaluation.

### Recommendation: **(b), a custom streaming matcher on the raw topic, using pySigma for parsing + field-mapping pipeline only**

Rationale: (a) doesn't even solve the real problem (still stuck on the alerts stream);
(c) depends on a thin, single-maintainer backend for the part of the system that matters
most (correct matching) and has a structurally worse per-tenant-isolation and
latency story; (b) reuses the actively-maintained, correctly-licensed core library for
the hard, general part (Sigma syntax/modifiers/field mapping) while keeping the part
that has to integrate tightly with this project's existing tenant/replay/dedup
conventions (the matcher loop itself) as a small amount of code we own and that follows
patterns (windowed aggregation, tenant-keyed consumers, ReplacingMergeTree dedup) already
proven elsewhere in this codebase.

---

## 5. Rule content and licensing

**License, verified from source (not a summary site):** cloned
`SigmaHQ/Detection-Rule-License` and read the LICENSE text directly. SigmaHQ's rules
(the `sigma/rules/` tree) are governed by the **Detection Rule License (DRL) 1.1**, not
a generic permissive license. DRL 1.1's concrete attribution obligation (verbatim intent
from the license text): any product that surfaces a match against a Rule must retain
that Rule's author-field identification in the surfaced output — i.e. **our incident/
Sigma-hit view must display the rule's `author:` field whenever a Sigma-matched hit is
shown**, not just log it internally. This is a console requirement to carry into 5C-1,
not optional polish.

**Real counts from the actual ruleset** (clone of `SigmaHQ/sigma`, counted directly, not
estimated):

- **3,152** total rules in the repo.
- **2,418** `windows`-product rules (the largest single bucket — and per §3, the bucket
  with zero lab data source today).
- **210** `linux`-product rules.
- Of those 210, only **1** rule is specifically `service: sshd` — the lab's one
  real Linux-with-good-field-granularity data source. The rest of the 210 are spread
  across auditd-based process_creation, generic syslog, and other Linux
  services/products the lab doesn't run.
- **0** correlation rules anywhere in the current public ruleset (confirms §4's note —
  this is a newer spec feature not yet populated by rule authors, not a gap in our
  reading of the repo).

**The three honesty-required numbers** (convertible / mappable / lab-backed):

1. **Convertible by the chosen model (b):** effectively all 3,152 rules that don't use
   correlation-rule syntax (i.e. ~3,152, since 0 use it) are parseable by pySigma and
   evaluable by a matcher implementing standard detection-block semantics — this number
   measures *parser/matcher capability*, not usefulness against our data.
2. **Mappable to our fields today:** bounded by §3's field-mapping work, which only
   covers logsources we actually receive (`linux`/process_creation via auditd,
   `linux`/sshd, `linux`/syslog) — i.e. a subset of the 210 linux-product rules (exact
   count depends on how many of those 210 rules' specific detection fields overlap with
   what auditd/sshd/syslog decoders actually expose — a 5C-1 implementation-time count,
   not a number this design doc can responsibly state without having built the mapping
   file yet; flagging this honestly rather than guessing a number).
3. **Backed by a real lab data source (the honest coverage number):** **at most 210**
   (all `linux`-product rules), and almost certainly meaningfully fewer once mappability
   is applied — and **0 of the 2,418 windows-product rules**, which is the single
   biggest coverage gap this design surfaces. The 2,418 number dominates the public
   ruleset; shipping "Sigma support" without a Windows data source in the lab (or a
   customer pilot environment that has one) means the headline rule count is not
   representative of what we can actually prove works end-to-end.

---

## 6. How a Sigma hit enters the product

**Alert shape:** a Sigma-hit record carries: `rule_id` (Sigma rule's own `id` UUID),
`title`, `level` (Sigma's `low`/`medium`/`high`/`critical`), `mitre_ids` (parsed from the
rule's `tags:` block, same `attack.txxxx` convention Wazuh rule tagging already uses —
no new taxonomy to introduce), `author` (DRL 1.1 attribution, §5), and the specific
matched field values (not just "it matched" — needed for triage, same as today's alert
`message`/`full_log` display).

**Flow into correlation/fingerprints/rarity/sequences/campaigns:** a Sigma hit should
become the *same kind* of input the correlator already consumes from the alerts topic —
i.e. the Sigma matcher (§4) emits a hit onto a topic (or directly into the correlator's
existing input shape) carrying enough of the existing alert envelope fields
(`tenant_id`, `agent_id`, timestamps) that it flows through the *existing*
fingerprint/rarity/sequence/campaign machinery unmodified, rather than building a
parallel pipeline. This is the lazy and correct choice: Phase 5B's fingerprinting,
rarity, sequence, and campaign logic are all already generic over "an alert-shaped
thing with rule groups and MITRE ids" — a Sigma hit just needs to present itself in that
shape.

**Fingerprint impact — avoid two unrelated fingerprints for the same attack:** the real
risk is a Wazuh rule and a Sigma rule both firing on the *same underlying raw event*
(e.g. auditd process_creation triggers both a Wazuh auditd rule and a Sigma
process_creation rule) and producing two separate fingerprints/incidents for one actual
event, fragmenting rarity/sequence history. Recommendation: fingerprint identity should
key off something that survives both paths — e.g. `(agent_id, raw event envelope
id/offset)` when available, not purely `(rule_group/rule_id)` — so if both a Wazuh rule
and a Sigma rule fire on the same raw event, they can be recognized as co-occurring on
one event rather than silently creating two unrelated fingerprint histories. This needs
a concrete data model decision in 5C-1 (exact dedup key), flagged here as the thing to
get right rather than designed in full now — "avoid it or justify not doing so" per the
ask: this doc chooses "avoid it" and names the mechanism (shared raw-event identity in
the fingerprint key) without finalizing the schema.

**Dedup when both a Wazuh rule and a Sigma rule fire on the same event:** same answer —
the console should show both rule attributions on **one** incident (both a `rule_groups`
entry from Wazuh and a Sigma `rule_id`/`author` from Sigma) rather than two incidents,
once the raw-event-identity key above ties them together.

---

## 7. Testing plan

**Per-rule positive tests:** each supported Sigma rule needs at least one real captured
event that should match it, sourced from either (a) the lab's own real traffic
(preferred — genuinely lab-backed, §5's third number) or (b) a public sample set, with
license checked *before* use, not after. For Windows/Sysmon rules specifically (the 2,418
rules with zero lab data source, §5), the natural source is an EVTX sample corpus (e.g.
`sbousseaden/EVTX-ATTACK-SAMPLES`) — **checked and found to have no explicit LICENSE
file in the repo**, so it must not be used for shipped/redistributed test fixtures until
that's resolved directly with the author or a clearly-licensed alternative is found;
recorded here as an open item (§8), not silently assumed usable.

**Connection to 5D (Atomic Red Team):** per-rule synthetic positive tests prove the
matcher+mapping *mechanically* works; they do not prove a rule would actually fire
against real attacker behavior. Phase 5D's Atomic Red Team execution against real lab
agents is the actual coverage proof — the same "coverage map ≠ tested coverage"
distinction Phase 5B's Step 2 already drew for the static ATT&CK map applies here:
label per-rule positive tests as "rule mechanically fires on a sample event," and reserve
"we detect this real technique" for 5D's execution-based proof.

**Definition of "supported":** a Sigma rule counts as supported only when all three are
true: (1) converted/parsed successfully by the chosen execution model, (2) its detection
fields are present in our field-mapping file for a logsource we actually receive, and
(3) a positive test event (real lab capture or a verified-licensed sample) passes
against the real pipeline end-to-end. This is intentionally the strictest of the three
§5 numbers and is the one that should appear in any customer-facing claim.

---

## 8. Risks, open questions, phased build plan

### Risks / open questions

- **Windows coverage gap:** 2,418 of 3,152 public rules (77%) have zero lab-backed path
  to "supported" without a Windows endpoint somewhere real (lab or pilot customer). This
  is the single biggest risk to any "Sigma support" claim and should be stated plainly
  in any customer communication, not softened.
- **EVTX sample license unresolved** — needed before any Windows-rule positive test can
  be built; blocks part of §7, not the design itself.
- **Aggregation/correlation rule support in the matcher is new code, untested against any
  real current rule** (0 correlation rules exist publicly today) — low urgency, but
  don't over-invest in correlation-rule support before the spec/ruleset actually
  populates it.
- **Fingerprint-key change (§6)** to unify Wazuh+Sigma hits on one raw-event identity is
  a real schema decision deferred to 5C-1 — flagged, not resolved, here.
- **`logall_json` per-tenant opt-in mechanism (§2)** needs an actual implementation
  decision (shipper-side filter vs. per-manager/agent-group `ossec.conf`) before 5C-1
  can estimate its own scope honestly.
- **Raw-event volume estimate (§2) is a rough multiple, not a measured production
  number** — re-measure against a real pilot tenant before it goes into any
  customer-facing sizing document.

### Phased build plan (estimates on timing are explicitly estimates)

- **5C-1: plumbing, no matching logic yet.**
  - Move smoke/chaos test agents to a dedicated lab test tenant (flagged separately,
    not yet done — do this *before* enabling `logall_json`/raw-topic work on the real
    lab tenant again, to avoid repeating the exact kind of test-traffic pollution the
    5B VERIFY review already found and had to purge).
  - Add `shadowtracer.events.raw` topic + shipper change + TenantCache-gated writer,
    per-tenant opt-in flag in `tenant_alert_settings`, default off.
  - VERIFY: enable opt-in for the lab test tenant only; confirm raw events land in
    Kafka with correct tenant_key/keying; confirm a forged/unknown tenant_key on the
    raw topic dead-letters exactly like the alerts topic does (reuse Phase 5C Step 0's
    test pattern); confirm opt-in default stays off for every other tenant.
- **5C-2: field-mapping file + pySigma pipeline, for the 3 logsources §3 identified.**
  - VERIFY: per-logsource unit test asserts every mapped Sigma field name exists on a
    real sampled lab event for that logsource (no invented field names, same discipline
    as Phase 5B Step 1's rule-group test).
- **5C-3: the streaming matcher itself (§4's recommended model), non-aggregation rules
  first.**
  - VERIFY: real lab-sourced positive-test events (§7) for every rule claimed
    "supported"; a known-negative event does NOT match (false-positive guard); matcher
    survives a consumer restart mid-stream with no missed/duplicated hits (same chaos
    test shape as Phase 5A's correlator failover test).
- **5C-4: Sigma hit → correlator integration (§6), fingerprint-key unification,
  console display (rule_id/title/level/MITRE/author attribution per DRL 1.1).**
  - VERIFY: a synthetic event that fires both a Wazuh rule and a mapped Sigma rule
    produces one incident, not two, with both attributions visible.
- **5C-5: aggregation-rule support in the matcher** (lower priority given §5's 0
  correlation rules and limited real aggregation-rule usage observed in the 210
  linux-product rules) — scope this only after 5C-1..4 are proven on the real lab.

---

## Summary for the approval decision

- **Convertible:** ~3,152 of 3,152 (all non-correlation rules; 0 use correlation syntax).
- **Mappable to our real fields (Linux-only logsources we receive today):** a subset of
  the 210 linux-product rules — exact count is a 5C-1 implementation measurement, not
  stated here to avoid a fabricated precision.
- **Lab-backed (the honest coverage number):** at most 210 (all linux-product rules,
  likely fewer after mappability), **0 of the 2,418 windows-product rules** — the
  dominant bucket of the public ruleset has zero real coverage today without a Windows
  data source.
- **Recommended execution model:** (b), a custom streaming matcher on a new
  `shadowtracer.events.raw` Kafka topic, using pySigma (LGPL-2.1-or-later, actively
  maintained) for Sigma parsing and field-mapping only — not (a) (no viable Wazuh
  backend exists and it doesn't solve the raw-data problem anyway) and not (c) (a real
  but thin, single-maintainer ClickHouse backend with a worse latency/isolation/failure
  story than reusing our existing stream-consumer pattern).
