# Phase 5C — Sigma rule support (design only, no product code)

Status: **draft, awaiting approval**. Nothing in this phase ships until this doc is
approved; see `docs/DECISIONS.md` for the decision entry once that happens.

## Revision note (this pass)

This is a correction pass on the first draft, requested after review. Real
investigation turned up several places where the first draft was simply wrong, not
just imprecise - recorded here plainly instead of quietly smoothed over:

- **Topic names were wrong.** The real topics are `shadowtracer.events.raw` (an
  existing, already-provisioned, 24-partition topic that carries Wazuh **alerts**,
  not raw pre-match events - a confusing name, explained in §1) and
  `shadowtracer.events.dead-letter` (hyphenated, 6 partitions). The first draft invented
  `shadowtracer.events.alerts` / `shadowtracer.events.dead_letter` (neither exists) and
  then proposed `shadowtracer.events.raw` for a *new* topic - which would have collided
  with the real, already-in-use topic of that name. Fixed in §1.
- **§6 put event identity inside the fingerprint.** The actual fingerprint code
  (`shadowtracer/correlate/shadowtracer_correlate/fingerprint.py`) hashes attack
  **shape** only, by design, and its own docstring already says never to put identity
  in it. The first draft's "key fingerprints off `(agent_id, raw event envelope
  offset/id)`" was exactly the mistake that docstring warns against. Rewritten in §6 to
  keep event-linking (how a Wazuh alert and a Sigma hit on the same raw event find each
  other) completely separate from fingerprinting (what attack shape gets hashed).
- **§3 assumed auditd was configured on the lab agents. It is not** - checked directly
  (no `auditd` binary, no rules, nothing under `/etc/audit/` on any of the 4 lab
  agents). The `data.audit.*` field names the first draft cited do not exist anywhere
  in this lab's real data; that was an error, not a measurement. Section 3 is rewritten
  from real sampled events only.
- **The logall_json/alerts.json ratio was only measured over 17 seconds** with no
  deliberate attack traffic. Re-measured over a real ~35-minute window including a real
  attack-traffic burst - and the fuller measurement overturns the "archives is a multiple
  of alerts" premise entirely, not just refines its number. See §4.
- A real, previously-unknown bug was found while investigating the load-balancer's
  non-sticky agent reassignment (§1's finding from the first draft). See §9 - reported,
  **not fixed**, per instruction.

---

## 1. Current state (measured, not assumed)

### Kafka topics (real, from the live lab broker) - corrected

```
$ docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 --list
shadowtracer.events.raw            (24 partitions)
shadowtracer.events.dead-letter    (6 partitions)
```

(Plus a large number of leftover `shadowtracer.test.*`/`shadowtracer.test.lag.*` topics
from the test suite's per-session-unique Kafka topic naming - noted here only so no one
mistakes them for product topics; harmless, outside this doc's scope.)

**`shadowtracer.events.raw` is a confusing name: it carries Wazuh ALERTS, not raw
pre-rule-match events.** Verified from source, not from the name alone:
`deploy/lab/docker-compose.yml`'s shipper env block sets
`ALERTS_PATH: /var/ossec/logs/alerts/alerts.json` and `KAFKA_TOPIC:
shadowtracer.events.raw`; `shadowtracer/ingest/shadowtracer_ingest/shipper.py` tails
`alerts_path` unconditionally and ships every line to `topic`. `PHASE3_DATA_PLATFORM.md`
line 541's `source_location=shadowtracer.events.raw:17:74` reference (the VERIFY
offset-tracing incident) is this same topic - consistent, and explains why the earlier
summary of this investigation referenced "`events.raw` partition 17 offset 74" even
though the first draft of this doc claimed no raw topic existed: the topic is real, it's
just not what its name implies.

**The raw-event (pre-rule-match, `archives.json`-sourced) path is partially plumbed
already, unused today.** `shipper.run()` already accepts an optional `archives_path` and,
if set, tails `archives.json` **onto the same topic** as `alerts.json`, distinguished
only by a Kafka header `source_file: "alerts.json"|"archives.json"` (shipper.py,
`run()`'s `sources` dict and the `headers=[...]` list in the produce loop).
`run_shipper.py`'s docstring documents this as `ARCHIVES_PATH` (optional - only set for
tenants with raw events enabled) - the plumbing anticipates per-tenant raw-event opt-in,
but **`ARCHIVES_PATH` is never set in `docker-compose.yml` today**, so no archives line
has ever actually been shipped in the lab.

**This also means the existing path is not safe to turn on as-is.** The writer
(`shadowtracer_ingest/writer.py`) does not look at the `source_file` header at all - it
calls `normalize_alert()` on every line unconditionally. `archives.json` contains every
decoded event whether or not a Wazuh rule matched it; an unmatched line does not have
the same shape `normalize_alert()` expects (no `rule` block), so turning on
`ARCHIVES_PATH` today would either crash-and-dead-letter most archive lines, or (for the
subset of archive lines that *are* rule-matches, since matched events are written to
*both* files) silently double-insert the same alert into the `shadowtracer.events`
ClickHouse table once from each file. **Nobody should flip `ARCHIVES_PATH` on before
5C-1 gives the writer (or a dedicated new consumer) a way to tell the two apart.**

### Topic design decision for Sigma's raw stream

Given the above, two real options, decided here:

1. **Reuse `shadowtracer.events.raw` via the existing header mechanism.** Rejected:
   mixing archives traffic onto the same 24-partition topic as alerts means the
   *existing* writer and correlator consumer groups receive and must skip every
   archives-sourced message too - extra CPU and consumer lag on the alerts path for
   every tenant, not just ones that opt into raw events (and per §4, archives volume is
   driven by a steady background rate independent of alert volume - real, continuous
   load, not an occasional spike). Opt-in per tenant was the whole point; a shared topic
   defeats it.
2. **A new, separate topic for archives-sourced raw events.** Chosen. Name:
   **`shadowtracer.events.archives`** - mirrors the real source file name
   (`archives.json`), avoids the word "raw" entirely (that word is already spoken for,
   confusingly, by the existing alerts topic), and does not collide with anything
   current (`events.raw`, `events.dead-letter`) or historical (`git log -S` over
   `deploy/lab/create-kafka-topics.sh` shows only those two topic names have ever been
   provisioned). Partition count: match `events.raw`'s 24 as a starting placeholder (same
   reasoning `DECISIONS.md` already gives for why `events.raw` is 24 - not a derived
   number, a sizing placeholder); retention: 7 days, matching `events.dead-letter`'s
   policy.

**Rename cost assessment for `shadowtracer.events.raw` itself (asked for explicitly):**
considered and **rejected**. Renaming it to something less confusing (e.g.
`shadowtracer.events.alerts`) is, in Kafka, not a rename at all - it's a new topic plus a
live migration of every producer (shipper-worker1, shipper-worker2) and consumer group
(`shadowtracer-writer`, `shadowtracer-correlate`) off the old name, with the attendant
risk of lost or reprocessed messages around the cutover, for a cosmetic improvement with
zero functional benefit. Not worth it. The confusing name is recorded here and should be
called out once in a code comment near `KAFKA_TOPIC`'s default in `run_writer.py`/
`run_correlator.py`/`run_shipper.py` at 5C-1 time (a comment, not a schema change) so the
next person doesn't make the first draft's mistake of assuming the name describes the
content.

### `logall_json` vs `alerts.json` - see §4 for the real re-measurement

---

## 2. Raw-event stream design

- **Ingestion: reuse the shipper's existing (unused) `ARCHIVES_PATH` mechanism**, but
  point it at the new `shadowtracer.events.archives` topic instead of the alerts topic.
  This needs one small shipper.py change (not made now - design only): accept a second,
  independent topic parameter for the archives source instead of shipping both sources
  to the same `topic` argument. Everything else (offset persistence by inode, dead-letter
  on malformed lines, tenant keying) is already correct and already tested for this
  exact file-tailing shape - reuse, don't rebuild.
- **Keying:** same convention as `events.raw` - `tenant_key:agent_id`, so ordering and
  per-tenant consumer scaling match the existing pattern.
- **Retention:** 7 days (matches `events.dead-letter`).
- **Per-tenant opt-in, default OFF**, implemented as whether a given shipper instance is
  launched with `ARCHIVES_PATH` set at all - driven by `tenant_alert_settings` (the same
  table `rare_alert_warmup_days`/`rare_alert_prior_occurrence_threshold` already live
  in), not a manager-wide `ossec.conf` toggle. This matters more than it sounds: Wazuh's
  `logall_json` is manager-wide, but the LB's non-sticky agent reassignment (§9) means
  "manager-wide" never cleanly maps to "tenant-wide" anyway once a manager serves more
  than one tenant's agents - the shipper-side per-source-file-per-process gate is the
  only control point that's actually per-tenant today.
- **Cost/lag effect:** per §4, model this as a roughly fixed per-agent background rate
  (driven by whatever scheduled/housekeeping telemetry - osquery, `monitord`-equivalent -
  a real fleet runs), not a multiplier on that tenant's alert volume; an attack burst adds
  to alert volume more than to archives volume, the opposite of what a multiplier model
  would predict. Surface the measured per-agent background rate in the opt-in UI/API so
  an operator knows the cost before flipping it on, and re-measure per-agent rather than
  assuming a single global constant, since it depends on what's scheduled on that fleet.
- **Same unknown-tenant rejection applies** - whatever consumes `events.archives` (the
  Sigma matcher, §6) must check `TenantCache` exactly as `writer.py` does today, with the
  same dead-letter-and-replay story (`replay_unknown_tenant_dead_letters.py` already
  generalizes over topic name).
- **Storage: hits only, not a full raw-event archive in ClickHouse** - same reasoning as
  the first draft: archives is overwhelmingly events that did *not* match anything, and a
  short (days) rolling raw window for investigation context is enough; only Sigma hits
  get durable, long-retention ClickHouse rows (§6).
- **Size estimate at 5,000 endpoints: still an estimate**, and now anchored to a
  fixed-per-agent-background-rate model rather than a ratio-of-alerts model (§4) -
  4 lab agents' idle rate (~0.07-0.1 archive-events/s/worker, i.e. roughly per-agent in
  this lab's case) scaled to 5,000 is a different, and more defensible, extrapolation
  than scaling a ratio that depends on how much attack traffic happens to be occurring.
  Still just a 4-agent, 35-minute lab sample scaled 1000x+ - re-measure against a real
  pilot tenant with realistic per-endpoint scheduled telemetry before this goes into a
  customer-facing sizing document.

---

## 3. Field mapping (Wazuh decoded fields → Sigma taxonomy) - rebuilt from real data

**Confirmed: no auditd anywhere in the lab.** Checked directly on all 4 lab agents
(`agent-ubuntu-1`, `agent-ubuntu-2`, `agent-rocky-1`, `agent-rocky-2`): no `auditd`
binary, no `/etc/audit/rules.d/*.rules`, `auditctl -l` not applicable (binary absent).
This removes the single largest assumption the first draft made. There is **no
process_creation-equivalent data source in this lab at all.**

**What the lab actually produces, by real decoder name** (counted directly from live
`alerts.json` on both managers):

| decoder | count (sample window) | what it actually is |
|---|---|---|
| `json` | 182 | osquery scheduled-query results (see below - **not** a Sigma `category: process_creation` source) |
| `sshd` | 136 | real sshd auth-failure lines from `/var/log/auth.log` |
| `ossec` | 12 | Wazuh's own internal agent/manager lifecycle messages (agent started, manager started) |

**Real sampled events** (captured 2026-10-09 from the live lab; `srcuser` value redacted
to `REDACTED`, everything else verbatim):

```jsonc
// decoder=sshd - rule 5710, groups=[syslog, sshd, authentication_failed, invalid_login]
{
  "full_log": "Oct  9 09:00:15 agent-ubuntu-1 sshd[8233]: Invalid user REDACTED from ::1 port 33330",
  "predecoder": {"program_name": "sshd", "timestamp": "Oct  9 09:00:15", "hostname": "agent-ubuntu-1"},
  "decoder": {"parent": "sshd", "name": "sshd"},
  "data": {"srcip": "::1", "srcport": "33330", "srcuser": "REDACTED"},
  "location": "/var/log/auth.log"
}

// decoder=json - osquery listening_ports (this lab's only network-adjacent data)
{
  "rule": {"level": 3, "description": "osquery: listening_ports query result", "groups": ["osquery"]},
  "decoder": {"name": "json"},
  "data": {"osquery": {
    "name": "listening_ports", "hostIdentifier": "agent-rocky-1",
    "columns": {"pid": "-1", "port": "36119", "protocol": "6"}, "action": "removed"
  }},
  "location": "osquery"
}

// decoder=ossec - internal lifecycle, not security telemetry
{
  "rule": {"level": 3, "description": "ShadowTracer agent started.", "groups": ["ossec"]},
  "full_log": "ossec: Agent started: 'agent-rocky-1->any'.",
  "decoder": {"parent": "ossec", "name": "ossec"},
  "location": "wazuh-agent"
}
```

**Correction from the first draft: the real decoded field is `data.srcuser`, not
`data.dstuser`** - checked against the actual event above, not assumed.

**Sigma logsource categories with a real lab data source, honestly assessed:**

| Sigma logsource | Lab source | Real fields available | Fit |
|---|---|---|---|
| `product: linux, service: sshd` | real sshd decoder | `full_log` (raw auth.log line), `data.srcip/srcport/srcuser` | genuine fit - this is exactly what the one real `service: sshd` Sigma rule needs (§5) |
| `product: linux` (generic, keyword-style rules with no service/category) | sshd `full_log` and, in principle, any syslog-sourced `full_log` | `full_log` only | fit for **keyword-condition** rules only (plain substring match against raw text) - no structured fields beyond `full_log` exist for this bucket |
| anything requiring `Image`/`CommandLine`/process-tree fields (`process_creation`, `auditd` service) | **none** | - | **no fit** - confirmed, no auditd |
| `network_connection` (Sysmon/auditd-style outbound-connection fields `Image`, `DestinationHostname`, `Initiated`) | **none** | osquery's `listening_ports` is a *local listening-socket snapshot*, not an outbound-connection event - different semantics, no Sigma logsource in the mainline taxonomy corresponds to osquery scheduled-query output at all | **no fit**, and not just a mapping gap - the data shape itself doesn't correspond to any Sigma network logsource |
| every Windows/Sysmon category | **none** | - | lab has zero Windows endpoints (confirmed: all 4 agents are `agent-ubuntu-*`/`agent-rocky-*`, via `cluster_control -a`) |

**Where the mapping lives:** a pySigma `ProcessingPipeline` (pySigma's own versioned,
testable field-mapping object - see §5's note that this *is* the "versioned file" asked
for, not a separate artifact), one per logsource actually supported. **How it's tested:**
a unit test asserts every field name the pipeline declares actually exists on a real
sampled event for that logsource (same discipline Phase 5B Step 1 already established
for rule_groups - don't invent field names any more than that test allows inventing
group names).

---

## 4. `logall_json` vs `alerts.json` - real re-measurement (quiet vs. active)

Procedure: both `wazuh-worker1` and `wazuh-worker2` restarted with `logall_json: yes`
(using the real control binary, `/var/ossec/bin/shadowtracer-control restart` - this
fork renames `wazuh-control`; the first attempt at this re-measurement used the upstream
name, silently failed, and nearly produced a measurement against a manager that was
never actually restarted - caught by checking `ps -eo etime` before trusting the
numbers, not before running the script). Real window: baseline (T0) →
20 min quiet → `deploy/lab/smoke-test.sh` run as the attack/traffic burst → settle →
`logall_json` disabled again.

**Real counts** (both managers, `wc -l`/byte size at each checkpoint):

| checkpoint | time | worker1 alerts (lines/bytes) | worker1 archives | worker2 alerts | worker2 archives |
|---|---|---|---|---|---|
| T0 (baseline) | 17:54:39 | 287 / 92,790,625 | 126 / 81,304 | 125 / 106,187 | 121 / 76,304 |
| T1 (quiet end, +1173s) | 18:14:12 | 287 / 92,790,625 | 210 / 111,055 | 125 / 106,187 | 163 / 90,917 |
| T2 (post smoke-test, +37s) | 18:14:49 | 298 / 104,369,432 | 212 / 112,630 | 125 / 106,187 | 163 / 90,917 |
| T3 (settled, +294s) | 18:19:43 | 298 / 104,369,432 | 240 / 122,547 | 125 / 106,187 | 177 / 95,788 |

**The real finding here overturns the premise the first draft (and Phase 1's original
estimate) both assumed: the archives/alerts ratio is not a stable constant - it flips
sign depending on whether real attack/rule-matching traffic is happening.**

- **Quiet window (20 min, both workers, zero deliberate traffic):** alerts grew by
  **zero lines on either worker** - no rule fired at all for 20 real minutes. Archives
  still grew steadily: +84 lines/+29,751 bytes (worker1), +42 lines/+14,613 bytes
  (worker2) - purely Wazuh's own internal housekeeping (`monitord`'s periodic `df -P`/
  `last -n 20`/rootcheck checks, osquery's scheduled queries) continuing regardless of
  whether anything attack-relevant is happening. Rate: ~0.07-0.1 archive-events/s per
  worker, **0 alert-events/s** - the ratio is literally undefined (divide by zero), not
  "small."
- **Active window (37s, smoke-test's real attack/hostile-traffic burst, worker1 only -
  worker2 saw none of it, consistent with the LB routing the test's target agent to
  worker1):** alerts jumped **+11 lines** (a real SSH brute-force alert plus smoke-test's
  2 good + 8 deliberately-hostile/oversized dead-letter-test payloads) while archives grew
  by only **+2 lines** - slower, in absolute terms, than its own idle-window rate. The
  byte delta (+11.58MB on alerts) is **not representative of normal attack traffic size** -
  it's dominated by smoke-test's deliberately oversized hostile payloads (built to test
  the dead-letter path on oversized events), not organic attack bytes; flagging this
  plainly rather than presenting a misleading bytes-based ratio.
- **Settle window (294s after the burst):** archives +28 lines/+9,917 bytes
  (≈0.095 events/s) - back to essentially the same idle rate as the quiet window
  (≈0.072 events/s), confirming the housekeeping rate is a steady background hum,
  independent of whether an attack just happened.

**Honest conclusion, replacing the "2.3-3.1x" / "2.06x" framing:** in this lab, archives
volume during idle periods is driven almost entirely by non-security internal
housekeeping (osquery scheduled queries, `monitord` checks) that **does not scale with
attack activity** - while alert volume is, by definition, only the subset of traffic that
actually matched a rule. A real attack burst grows alerts faster than archives, not the
reverse. This means **raw-event cost should be modeled as a roughly fixed per-agent
background rate (driven by whatever scheduled/housekeeping telemetry a real fleet runs),
not as a multiplier on alert/attack volume** - a materially different, and better, sizing
model than the first draft's (and Phase 1's) ratio framing. The first draft's own
17-second measurement (4.53 alert-events/s) sampled a moment with real alert activity this
20-minute idle window didn't have at all - underscoring how sensitive a short measurement
window is to exactly when it's taken, and why neither 17 seconds nor this one ~35-minute
lab run should be treated as a production sizing input (§2 already says this; this
measurement makes the reason concrete rather than hypothetical).

### Archives.json disk/rotation on managers (real, from the live containers)

Checked `internal_options.conf` directly:

```
monitord.rotate_log=1       # rotate plain+JSON logs daily
monitord.size_rotate=512    # also rotate at 512MB
monitord.daily_rotations=12 # up to 12 rotations/day if size-triggered
monitord.compress=1         # gzip rotated logs
```

Rotated files land at `/var/ossec/logs/archives/YYYY/Mon/ossec-archives-DD.json.gz`
(confirmed this exact pattern already exists for `alerts/` - e.g.
`ossec-alerts-07.json.gz` - and `monitord`'s rotation code is shared between the two log
streams, so the same daily+512MB+12-rotations+gzip policy applies to `archives.json`
automatically once `logall_json` is on; no separate rotation config exists to tune for
archives specifically). Disk headroom in the lab: 838GB free of 1007GB on the manager
hosting the busiest agent - not a lab constraint today, but the daily-rotation default
means a manager that's down for over a day during a `logall_json`-enabled outage could
lose more than one day of raw events to rotation before the shipper catches up; worth a
retention-vs-outage-tolerance note in 5C-1, not a blocker for the design.

---

## 5. Rule content and licensing

**Verified directly from the cloned repos** (not from memory, not from a summary site -
every hash/date below is from `git log -1` against a real `git clone --depth 1` done
during this investigation):

| Project | Repo | Commit | Date | License (verified) |
|---|---|---|---|---|
| Sigma ruleset | github.com/SigmaHQ/sigma | `8a4813404ea3074890e0cda9272d4d1a8b2941d6` | 2026-10-06 | Rules: **DRL 1.1** (the repo's own `LICENSE` file states this explicitly - quoted below); spec+logo: public domain |
| pySigma | github.com/SigmaHQ/pySigma | `50708bae1fd24c75a5342187e34c126c13c69a18` | 2026-10-04 | **LGPL-2.1-only** (correction from the first draft, which said "-or-later" - `pyproject.toml`'s `license = "LGPL-2.1-only"` is explicit; PyPI release 2.0.0 uploaded 2026-10-04) |
| sigma-cli | github.com/SigmaHQ/sigma-cli | `863c714109c2001050dc99f7d54b97e72bf8463e` | 2026-10-04 | LGPL-2.1-or-later (PyPI metadata explicit); release 3.1.0, uploaded 2026-07-07 |
| pySigma-pipeline-sysmon | github.com/SigmaHQ/pySigma-pipeline-sysmon | `965d57c2324292f66bec3da41b223838b3b7251b` | 2026-09-30 | LGPL-2.1-only (PyPI metadata explicit); release 2.0.0, uploaded 2025-11-30 |
| pySigma-backend-elasticsearch | github.com/SigmaHQ/pySigma-backend-elasticsearch | `1c49eb1b0a796f885e7f3c6b69201f5762b7969c` | 2026-09-20 | not explicit in PyPI metadata (`license: None`); release 2.1.1, uploaded 2026-08-10 |
| pySigma-backend-clickhouse | **repo not conclusively located** - PyPI page (`pypi.org/project/pysigma-backend-clickhouse/1.0.1/`) lists maintainer `souzo` (`github.com/souzomain`) but `home_page`/`project_urls`/`license` are all `null` in PyPI's own JSON metadata; a `LICENSE.md` ships inside the sdist per `license_files`, but its content could not be verified without the repo | - | - | **correction from the first draft, which asserted "Apache 2.0" with no real evidence - withdrawn.** Release 1.0.1, uploaded 2026-07-16. Single-maintainer either way (confirmed by the PyPI author field and absence of any visible co-maintainer), which was the operative point for §6's execution-model comparison - the license correction doesn't change that recommendation, but the first draft should not have stated a license it hadn't actually checked. |

**DRL 1.1, verbatim attribution clause** (from `LICENSE.Detection.Rules.md` in
`SigmaHQ/Detection-Rule-License` at `bcbdc605172d00390572cd774ba395ec9e975dfc`,
2024-12-27):

> If you use the Rules (including in modified form) on data, messages based on matches
> with the Rules must retain the following if it is supplied within the Rules: 1.
> identification of the authors(s) ("author" field) of the Rule and any others
> designated to receive attribution...

Concrete product obligation: **any view that surfaces a Sigma-rule match must display
that rule's `author` field.** The ruleset repo's own `LICENSE` file confirms this is what
governs `rules/`: "The rules contained in the SigmaHQ repository ... are released under
the Detection Rule License (DRL) 1.1."

**Real counts from the actual ruleset** (`git clone --depth 1`, counted directly with a
script that parses every rule YAML - not estimated):

- **3,152** total rules. **2,418** windows-product. **210** linux-product. **0**
  correlation rules.
- **210 linux-product rules, broken down by (category, service)** - this is the honest
  breakdown the first draft didn't do:

  | category | service | count | lab fit |
  |---|---|---|---|
  | `process_creation` | - | 122 | 0 - no auditd/process data source |
  | - | `auditd` | 53 | 0 - no auditd |
  | - | (none) | 15 | ~13 of 15 are keyword/plain-string-list rules (inspected each: `lnx_shellshock`, `lnx_shell_clear_cmd_history`, `lnx_susp_jexboss`, `lnx_shell_susp_commands`, `lnx_susp_dev_tcp`, `lnx_shell_susp_rev_shells`, `lnx_apt_equationgroup_lnx`, `lnx_symlink_etc_passwd`, `lnx_shell_susp_log_entries`, `lnx_buffer_overflows`, `lnx_ldso_preload_injection`, plus `lnx_privileged_user_creation` which is a plain-string-list rule against `/var/log/auth.log` text) - all match against `full_log`, **field-compatible in principle**, zero real lab traffic ever produces their trigger content (reverse shells, shellshock, privilege escalation, log tampering - none have occurred) |
  | `file_event` | - | 8 | 0 - no FIM/auditd-shaped file-event source (Wazuh's own syscheck FIM, if enabled, has a different event shape entirely and wasn't checked in depth - low value regardless, since matching it to Sigma's `file_event` taxonomy would need its own mapping effort even if enabled) |
  | `network_connection` | - | 5 | 0 - inspected all 5: all require `Image`/`DestinationHostname`/`Initiated`/`DestinationPort` (Sysmon/auditd-shaped), none of which exist; osquery's listening-port snapshots are a structurally different thing (see §3) |
  | - | `syslog` | 2 | 0 lab-backed - one is `full_log`-keyword-compatible in principle (`lnx_syslog_security_tools_disabling_syslog`), but the lab never disables security tools or produces named(8) errors |
  | - | `sshd` | **1** | **yes - the one genuine, directly-verified fit.** `lnx_sshd_susp_ssh.yml` (`Suspicious OpenSSH Daemon Error`) is a `condition: keywords` rule matching strings like `'unexpected internal error'`, `'incorrect signature'` against the raw sshd log line - exactly `full_log`'s shape. **Not lab-backed today though**: our real sshd traffic is ordinary auth failures, never an OpenSSH internal/crypto error - the field is real, a real trigger event has never occurred. |
  | - | `clamav`/`vsftpd`/`cron`/`guacamole` | 1 each (4) | 0 - none of these services run in the lab |

**The three honesty-required numbers, revised and much more conservative than the first
draft:**

1. **Convertible by the chosen execution model:** ~3,152 of 3,152 (all non-correlation
   rules - pySigma parses them regardless of whether our data can ever satisfy them;
   this number measures parser capability, not usefulness).
2. **Mappable to our real fields today:** **~14 of 210** linux rules (1 sshd + ~13
   generic keyword/plain-string rules whose only required field, `full_log`, we have) -
   **0 of 2,418** windows rules (no Windows data source to build or test a mapping
   against, even though the *fields themselves* are well documented upstream).
3. **Lab-backed (an actual real captured event that would fire it) - the honest coverage
   number: 0 of 210, 0 of 3,152.** This is the sobering, real finding this revision
   surfaces: even the one rule with a perfect field match (`lnx_sshd_susp_ssh`) has never
   seen its trigger condition in real lab traffic, and none of the ~13 generic keyword
   rules' attacker behaviors (reverse shells, shellshock, log tampering, privilege
   escalation) have ever been run against a lab agent. "Mappable" and "lab-backed" are
   very different numbers, and today the honest lab-backed number is zero - closing that
   gap is what the Phase 5D Atomic Red Team connection (§7) and the phased build plan's
   early VERIFY steps (§9) are for, not something this design doc can claim in advance of
   actually running those attacks.

---

## 6. How a Sigma hit enters the product (corrected)

**Fingerprints never contain identity, offsets, or event IDs - full stop.** Confirmed by
reading the real code: `shadowtracer/correlate/shadowtracer_correlate/fingerprint.py`'s
own docstring states the hash covers attack **shape** only - "never anything that
identifies who was involved: no IP addresses, usernames, ports, timestamps, or agent
ids." `fingerprint_shape()` takes `rule_groups`, `mitre_ids`, a bucketed `actor_class`
(internal/external/local, never a raw IP), a bucketed `target_class`, a log2 volume
bucket, and a duration bucket - nothing resembling an event ID, Kafka offset, or
per-message identifier appears anywhere in it, and nothing proposed here adds any. The
first draft's "key the fingerprint off `(agent_id, raw event envelope offset/id)`" is
withdrawn - that was a real mistake, not a simplification.

**(a) Event linking - how a Wazuh alert and a Sigma hit on the same raw event find each
other.** This is a *correlation/ingestion-time* concern, strictly separate from
fingerprinting, and it reuses an existing mechanism rather than inventing one.

Checked on real paired lab events (now that `logall_json` is live for the
re-measurement, §4): a matched event's Wazuh-internal `id` field
(`<unix_timestamp>.<counter>`, the same field Phase 3's `(cluster.node, id)` alert
identity decision in `DECISIONS.md` already keys off) is **identical** between its
`alerts.json` line and its `archives.json` line - confirmed directly:

```
# same underlying sshd auth-failure event, both files, same id:
alerts.json:   "id":"1791554012.107653"  rule.id=5710 groups=[syslog,sshd,...]
archives.json: "id":"1791554012.107653"  (same event, same timestamp)
```

**Recommendation: reuse `(cluster.node, id)` - the project's existing alert identity -
as the event-linking key, carried through on both the `events.raw` and the new
`events.archives` envelopes.** No new mechanism, no new schema field category - this is
exactly the kind of reuse the first draft should have reached for instead of inventing a
raw-event-offset concept.

**A real caveat found while verifying this on live data - bigger than expected, and
reported in full rather than minimized:** `id` is **not** reliably unique, and not only
for internal housekeeping noise. Checked exhaustively against a real archives.json
snapshot (parsed with Python, not grep, after the first attempt at this check silently
miscounted due to a `grep -o` first-match bug): **22 distinct `id` values each cover more
than one archive line**, and this is not limited to `monitord` batches like `df -P`/
`last -n 20` (which do show the same pattern, e.g. 7 different filesystem lines all
carrying `"id":"1791568437.0"`). It also happens for genuine, real **sshd** events: one
real synthetic-load burst produced a group of **13 distinct real sshd log lines**
(`Invalid user ...` / `Connection closed by invalid user ...`, different ports, different
PIDs) **all sharing the single id `1791554012.106602`.** This matters more than a
monitord-only caveat would, because a burst of related events sharing one `id` is
*exactly* the shape a real attack (e.g. a brute-force burst) produces - precisely the
case where Sigma/Wazuh event-linking needs to be correct.

**`(cluster.node, id)` alone is therefore a candidate-narrowing filter, not a unique join
key, whenever events arrive in a burst.** The real data does offer a clean fix at no
extra schema cost, though: across all 22 real collision groups found, **`full_log` was
unique within every group - zero exact duplicates**. Recommendation: event-linking uses
`(cluster.node, id)` to narrow to a candidate set, then an exact `full_log` string match
to pick the specific archives-side line that corresponds to a given alerts-side line.
Both fields already exist on both envelopes today - no new field, no offset, no identity
added to anything that reaches `fingerprint.py`. This is real, tested-on-real-data
behavior, not a theoretical fallback; the first pass at this caveat (an earlier version
of this sentence) understated it as a monitord-only rare case before the fuller sshd-burst
check above was run - correcting that here rather than quietly fixing it upstream.

**(b) Fingerprint compatibility - one vocabulary from either source.** The real gap is
narrower than the first draft implied:

- `mitre_ids` is **already** a shared vocabulary: Wazuh alerts carry `rule.mitre.id`
  (e.g. `T1110.001`), Sigma rules carry `tags: [attack.t1110.001, ...]` - a trivial
  string normalization (`attack.t1110.001` → `T1110.001`), not a new taxonomy.
- `rule_groups` has no Sigma equivalent as a concept, but Wazuh's `rule_groups` is
  already just a free-form string list with no closed enum (Phase 5B Step 1 only checked
  that referenced groups *exist* in the real ruleset, never required a fixed vocabulary).
  **Recommendation: a Sigma hit contributes its `logsource.service` or
  `logsource.category` string as its `rule_groups` entry.** This isn't a new shared
  taxonomy file - it's reusing the existing free-form convention. It is **directly
  verified to work for the one case we can test today**: the real sshd Wazuh alerts'
  `rule.groups` already literally include the string `"sshd"`, and the one real Sigma
  sshd rule's `logsource.service` is also literally `sshd` - the vocabulary already lines
  up without any translation table, for this one case. Untested beyond sshd, honestly,
  since no other logsource has real lab data to verify against (§3/§5).
- **Dedup when both fire on the same event**: falls out of the existing incident-assembly
  code for free, once (a)'s event-linking merges the Sigma hit and the Wazuh alert into
  one alert record before it reaches the correlator. `correlator.py`'s existing
  accumulation (`for g in event.rule_groups: if g not in rule_groups: append`) already
  dedups `rule_groups` as alerts join an incident - a merged alert record carrying both
  sources' groups gets the same treatment, no special-casing needed. One real integration
  detail to flag for 5C-4, not resolved here: `correlator.py:59-60` uses
  `event.rule_groups[0]` as part of the *correlation basis* that decides which incident a
  new alert joins in the first place - if a Sigma hit's synthesized `rule_groups[0]`
  doesn't match a co-occurring Wazuh alert's, they could end up correlated into
  *different* incidents before the event-linking merge ever gets a chance to combine
  them. 5C-4 needs to either merge at a point that happens before correlation-basis
  assignment, or treat a confirmed `(cluster.node, id)` link as an override to the normal
  correlation basis. Flagged as a real design decision for that step, not pre-resolved
  here.

**Alert shape (unchanged from the first draft, still correct):** `rule_id` (Sigma UUID),
`title`, `level`, `mitre_ids` (normalized per above), `author` (DRL 1.1 attribution,
§5), and the specific matched field values. Flows into the existing correlator/
fingerprint/rarity/sequence/campaign pipeline by presenting itself in the same
alert-shape the correlator already consumes - no parallel pipeline.

---

## 7. Testing plan

**Per-rule positive tests**, sourced from real lab traffic where possible (today: none,
see §5's honest lab-backed count) or a verified-licensed external sample set for
Windows/Sysmon rules. **EVTX-ATTACK-SAMPLES (`sbousseaden/EVTX-ATTACK-SAMPLES`) license -
corrected from the first draft**, which reported it as unconfirmed. Checked directly via
the GitHub API this time (`repos/sbousseaden/EVTX-ATTACK-SAMPLES`): the repo carries a
`LICENSE.GPL` file (GitHub's own license detector: **GPL-3.0**, last repo push
2023-01-24T12:02:51Z). Usable as a private internal test fixture; **GPL-3.0 on what is
fundamentally a *data* repository is unusual and its copyleft/redistribution obligations
should get real legal review before any EVTX sample is bundled into or redistributed
with our own repo or product** - using them privately to generate positive-test events
during development is a materially different situation from shipping them, and this
design doc does not resolve that distinction, just flags it honestly.

**Connection to 5D (Atomic Red Team):** unchanged from the first draft - per-rule
synthetic positive tests prove the matcher+mapping mechanically works; Phase 5D's real
attack execution against real lab agents is the actual coverage proof, same
"coverage map ≠ tested coverage" distinction Phase 5B Step 2 already drew for the static
ATT&CK map.

**Definition of "supported":** unchanged - converted + mapped + a positive test passes
on the real pipeline, all three. Given §5's revised numbers, expect this list to start
very small (realistically: the sshd rule, once someone deliberately produces an OpenSSH
internal-error condition on a lab agent to prove it) and grow only as real attack
behavior is actually run in the lab.

---

## 8. Spike: 20 real SigmaHQ rules via pySigma, evaluated against real lab events

Scratch spike, not committed (per the allowed-work list). pySigma 2.0.0 installed
isolated (no system/venv changes - `pip install --target=<scratch>/pylibs`, no sudo, no
apt). **Confirmed by inspecting the public API directly: pySigma has no built-in
event-evaluator.** `SigmaRule`/`SigmaDetections` only expose `from_dict`/`to_dict`/
`from_yaml`/etc. - pySigma is a parser + query-*generation* framework (for backends that
target Elastic/Splunk/etc.), not something that evaluates a parsed rule against a Python
event dict out of the box. This directly validates §6's "execution model (b)" choice
from the first draft: a from-scratch matcher really is needed regardless of which
backend ecosystem is used, and the spike below **is** a tiny prototype of exactly that
matcher, walking pySigma's parsed `SigmaDetection`/`SigmaDetectionItem` tree.

20 rules chosen: the 1 real sshd rule, 13 of the keyword/plain-string "no
category/service" linux rules, the 2 syslog-service rules, 2 network_connection linux
rules (expected-negative control), and 3 windows process_creation rules evaluated
against **synthetic, explicitly-labeled-as-not-real** Windows-shaped events (the lab has
none - this is a matcher-correctness/cost check only, not a lab-backed test).

Matcher: ~100 lines, handles field equality + `contains`/`endswith`/`startswith`
modifiers (stripping the wildcard token pySigma's modifiers add), keyword items
(`field: None`, matched against `full_log` + a JSON dump of the event), recursive
OR-grouped nested `SigmaDetection` objects (needed for rules like
`selection_img: [{Image|endswith: ...}, {OriginalFileName: ...}]`), and a small
condition-string evaluator (`all of X*`, `1 of X*`, `and`/`or`/`and not`) - enough for
these 20 rules, not Sigma's full condition grammar.

**Results:**

```
rule                                                    avg us/event   matched
lnx_sshd_susp_ssh (sshd)                                    17.2 us    (none - real sshd/osquery/ossec events)
lnx_privileged_user_creation                                10.3 us    (none)
lnx_shellshock                                                5.5 us    (none)
lnx_shell_clear_cmd_history                                  12.3 us    (none)
lnx_susp_jexboss                                              6.2 us    (none)
lnx_shell_susp_commands                                      22.3 us    (none)
lnx_susp_dev_tcp                                              8.1 us    (none)
lnx_shell_susp_rev_shells                                    12.4 us    (none)
lnx_apt_equationgroup_lnx                                    25.5 us    (none)
lnx_symlink_etc_passwd                                        5.9 us    (none)
lnx_shell_susp_log_entries                                    6.1 us    (none)
lnx_buffer_overflows                                          6.6 us    (none)
lnx_ldso_preload_injection                                    5.3 us    (none)
lnx_syslog_security_tools_disabling_syslog                   10.9 us    (none)
lnx_syslog_susp_named                                         5.3 us    (none)
net_connection_lnx_back_connect_shell_dev                     6.6 us    (none - expected, no network_connection fields)
net_connection_lnx_susp_malware_callback_port                 8.7 us    (none - expected)
proc_creation_win_whoami_priv_discovery                       6.4 us    MATCHED synthetic_windows_whoami (validates matcher correctness)
proc_creation_win_certutil_download                           7.9 us    MATCHED synthetic_windows_certutil (validates matcher correctness)
proc_creation_win_net_user_add                                7.1 us    (none - no synthetic positive event built for this one)

average: 9.8 us/rule/event (naive, no logsource indexing, no regex pre-compilation, single-threaded CPython)
```

**Zero matches against any real lab event** - consistent with, and independent
confirmation of, §5's honest "0 lab-backed" finding. The two synthetic Windows events
did match their intended rules, which validates the matcher logic itself (nested
OR-groups, `endswith`/`contains` modifiers, `all of selection_*` conditions all work
correctly) - the zero-match result against real data is a real finding about our data,
not a matcher bug.

**Cost projection to 3,000 rules (labelled estimate):**

- **Naive, unindexed** (every event checked against every rule): `3,000 × 9.8us ≈ 29.5ms`
  per event, single-threaded. At even a modest sustained rate this is a real bottleneck -
  not viable as-is for a raw-event stream running at the §4-measured rate.
- **Indexed by logsource** (an event only gets checked against rules whose logsource it
  could plausibly satisfy): a real sshd event would face ~14 candidate rules (the 1 real
  sshd rule + the ~13 generic `full_log`-keyword rules from §5's table) instead of 3,000
  - `14 × 9.8us ≈ 137us` per event, a **~215x reduction** from logsource indexing alone,
  before any further optimization (compiled regex, Aho-Corasick for keyword lists, etc.).
  This is the strongest concrete argument for why 5C-1/5C-3 must build the
  logsource-indexed dispatch from the start rather than a flat rule list - confirmed by
  this spike's real numbers, not assumed.
- Both numbers are from a 20-rule sample on unoptimized Python with no JIT/compilation -
  treat as an order-of-magnitude estimate, not a capacity-planning number.

---

## 9. A real bug found during this investigation, reported (not fixed)

While investigating the load-balancer's non-sticky agent reassignment (discovered in the
first draft's §1 measurement work), this revision checked whether it has any
consequence beyond `logall_json` measurement inconvenience. It does.

**Confirmed setup:** two independent shipper processes exist
(`shipper-worker1`/`shipper-worker2`, `deploy/lab/docker-compose.yml`), each tailing a
*different* manager's `alerts.json`, each with its own `Producer()`, its own offset file,
batching independently (`BATCH_MAX_LINES=500`, `BATCH_MAX_SECONDS=1.0`,
`shipper.py:36-37`) with no cross-shipper coordination of production order. The Kafka
key is `tenant_id:agent_id` (same partition per agent), which guarantees **production
order** is preserved per partition - not **event-content order**. If `shipper-worker1`
is slower to flush an older batch for agent X than `shipper-worker2` is for a newer batch
of the same agent (plausible right after the LB reassigns X from worker1 to worker2
mid-stream, e.g. during a worker restart), the newer event can be produced to Kafka
first.

**Confirmed consequence for Phase 5B sequence detection** (`sequences.py`): sequence
matching advances on **consumption order**, not event timestamp. `event.alert_time` is
used only for window-expiry math (`> seq["window_seconds"]`), never to verify or reorder
steps - a step is checked only against the one next-expected rule group
(`sequences.py:92-99`, "never scanned ahead" per its own docstring), and a non-matching
alert is a silent, un-retried no-op. `sequence_progress` state itself survives a
correlator restart fine (Postgres-committed in the same transaction as the alert,
`correlator.py:124-185`) - the exposure is purely ordering, not lost state.

**Concrete failure scenario:** agent X mid-sequence (step 1 fired, waiting for step 2).
Worker1 (serving X) restarts; the LB reassigns X to worker2 before worker1's shipper has
flushed the still-pending step-1 alert. Worker2's shipper, on its own 1-second batch
timer, ships X's step-2 alert first. Both land on the same Kafka partition in that order
(same `tenant:agent` key). The correlator consumes step 2 while still expecting step 1 →
silent no-op, that message is gone. Step 1 then arrives, advances the sequence to
"waiting for step 2" - which already came and went - and the sequence now waits until
`window_seconds` expiry for an event that will never arrive again: a **missed sequence
fire, with no error, log, or metric indicating it happened.** The reverse ordering can
also, in principle, let unrelated alerts complete a sequence whose true per-event
timestamps were never in the YAML's intended order, since nothing checks inter-step
chronology - a **false-positive fire risk**, though harder to trigger reliably than the
missed-fire case.

This is real and exploitable specifically because of the LB's non-sticky reassignment
combined with per-worker shippers and a consumption-order-only sequence engine - not a
theoretical concern. **It predates Phase 5C and is not part of this design; it is
reported here because this investigation is what surfaced it, and because the phased
build plan below deliberately avoids building anything in 5C that would compound it
(the Sigma matcher itself is per-event, stateless, and order-independent - it does not
inherit this exposure; a future Sigma *correlation rule* feature, once the spec actually
populates one, would need to reckon with it directly).** Per instruction, this is
reported, not fixed, and no commit in this revision touches `sequences.py`,
`shipper.py`, or the load balancer.

---

## 10. Risks, open questions, phased build plan

### Risks / open questions (consolidated)

- **Windows coverage gap unchanged and now sharper:** 2,418 of 3,152 rules (77%) have no
  lab-backed path without a Windows endpoint, lab or pilot.
- **Lab-backed coverage today is 0, not "small"** - stated plainly per §5; the realistic
  path to a non-zero number runs through Phase 5D attack execution, not rule-mapping work
  alone.
- **EVTX sample license is GPL-3.0, confirmed** - fine for private internal test-fixture
  use; needs real legal review before any redistribution/bundling.
- **The `correlator.py:59-60` correlation-basis-vs-event-linking interaction (§6b)** is a
  real open design question for 5C-4, not resolved in this doc.
- **The LB/sequence-detection bug (§9)** is real, reported, unfixed, and pre-existing -
  track it separately from 5C.
- **`events.archives`'s per-tenant opt-in mechanism** still needs an actual
  implementation decision (shipper.py's two-source-two-topic change) before 5C-1 can
  scope itself honestly.
- **Raw-event volume is now modeled as a per-agent background rate, not an alert-volume
  multiplier** (§4's real finding) - better grounded than the first draft's ratio, still
  only a 4-agent, 35-minute lab sample, not a production sizing study.
- **pySigma-backend-clickhouse's actual license is unverified** (§5) - a corrected
  "don't know" is better than the first draft's wrong "Apache 2.0", but it's still not
  resolved; irrelevant to the chosen execution model either way.

### Phased build plan (estimates on timing are explicitly estimates)

- **5C-0: move smoke/chaos test agents to a dedicated lab test tenant.** Pulled forward
  to its own first step (was folded into 5C-1 in the first draft) - this is the same
  kind of test-traffic-into-the-real-tenant pollution the 5B VERIFY review already found
  and had to purge once; do it before any `events.archives` work touches the real lab
  tenant again.
  - VERIFY: smoke-test.sh and verify-correlator-chaos.sh run entirely against the
    dedicated test tenant; the real lab tenant's incident/fingerprint history shows zero
    new rows from a full smoke-test run.
- **5C-1: a Windows VM + Sysmon lab endpoint, and the `events.archives` plumbing.**
  Bundled because both are prerequisites everything else depends on, and neither is
  useful alone: a Windows endpoint with no raw-event pipeline can't prove Sigma
  Windows-rule mapping against real data, and a raw-event pipeline with no Windows data
  still leaves the 77%-of-ruleset gap untouched.
  - Stand up one Windows VM (or container, if a viable Windows-container-with-Sysmon lab
    image exists - unverified, check before assuming) running Sysmon with a real
    config, enrolled as a lab agent.
  - shipper.py's two-topic change; `events.archives` topic provisioned (24 partitions, 7
    day retention); per-tenant opt-in via `tenant_alert_settings`.
  - VERIFY: opt-in for the dedicated test tenant only; archives-sourced events land in
    `events.archives` with correct tenant_key/keying; a forged/unknown tenant_key
    dead-letters exactly like `events.raw` does (reuse the Phase 5C Step 0 test
    pattern); opt-in default stays off for every other tenant; real Sysmon events are
    visible end-to-end for the first time, with real field names sampled the same way
    §3 did for Linux.
- **5C-2: field-mapping pipelines** for the logsources §3 identified as real (sshd,
  generic-linux-keyword) plus the new Windows/Sysmon ones 5C-1 unlocks.
  - VERIFY: per-logsource unit test asserts every mapped field name exists on a real
    sampled event for that logsource (same discipline as Phase 5B Step 1's rule-group
    test) - no invented field names.
- **5C-3: the streaming matcher**, logsource-indexed dispatch from the start (§8's
  ~215x finding makes an unindexed flat-list matcher a non-starter), non-aggregation
  rules first.
  - VERIFY: real lab-sourced positive-test events (§7) for every rule claimed
    "supported"; a known-negative event does not match; matcher survives a consumer
    restart mid-stream with no missed/duplicated hits (same chaos-test shape as Phase
    5A's correlator failover test).
- **5C-4: Sigma hit → correlator integration** (§6), including the
  correlation-basis-vs-event-linking decision flagged there, fingerprint-group-vocabulary
  reuse, console display with DRL 1.1 author attribution.
  - VERIFY: a synthetic event firing both a Wazuh rule and a mapped Sigma rule produces
    one incident, not two, with both attributions visible.
- **5C-5: rule-selection policy** (new in this revision - the first draft didn't address
  this at all):
  - **Status default:** only Sigma `status: stable` rules enabled by default; `test`
    available as an explicit per-tenant opt-in, `experimental`/`deprecated` never
    auto-enabled.
  - **Level default:** `medium` and above enabled by default, to avoid the alert-fatigue
    failure mode the warm-up/rarity machinery (Phase 5B) was built to manage in the first
    place; `low`/`informational` available as opt-in.
  - **Update/versioning:** pin the SigmaHQ ruleset to a reviewed commit hash (same
    convention `RULESET_VERSION` already establishes for the fingerprint shape version in
    `fingerprint.py`) - a ruleset bump is a reviewed, versioned change, never a silent
    `git pull`.
  - **Per-tenant enable/disable:** reuses `tenant_alert_settings`, same pattern as every
    other per-tenant knob this project already has.
  - **Interaction with suppression:** a Sigma-sourced incident's fingerprint participates
    in the exact same `suppression_state` mechanism as a Wazuh-sourced one (§6) - no
    special-casing, by construction, since both reach fingerprinting through the same
    alert-shape and the same `fingerprint.py` code path.
  - VERIFY: a rule below the default status/level thresholds never fires even if its
    fields and data are otherwise a perfect match; a per-tenant disable takes effect
    without a restart (or, if it requires one, that's stated as a known limitation, not
    silently assumed instant).
- **5C-6: aggregation-rule support** in the matcher - still lower priority given 0
  correlation rules exist publicly and limited real aggregation-rule usage observed in
  the 210 linux-product rules; scope only after 5C-0..5C-5 are proven on the real lab.

---

## Summary for the approval decision

- **Convertible:** ~3,152 of 3,152 (all non-correlation rules).
- **Mappable to our real fields today:** ~14 of 210 linux rules (1 sshd + ~13 generic
  `full_log`-keyword rules); 0 of 2,418 windows rules (no Windows data source yet - see
  5C-1).
- **Lab-backed (the honest coverage number): 0 of 3,152, today.** Closing this runs
  through Phase 5D attack execution and the Windows-VM build step, not rule-mapping work
  alone - stated plainly rather than inflated.
- **Recommended execution model:** unchanged from the first draft and now independently
  validated by the §8 spike - (b), a custom streaming matcher on the new
  `shadowtracer.events.archives` topic, using pySigma (confirmed LGPL-2.1-only, actively
  maintained, confirmed to have no built-in evaluator so a custom matcher is required
  regardless of chosen backend ecosystem) for parsing and field-mapping only, with
  logsource-indexed rule dispatch from the start (a ~215x cost difference, not a
  nice-to-have).
- **One item outside 5C's scope needs separate attention:** §9's real, pre-existing
  sequence-detection ordering bug, found while investigating the load balancer. Reported
  here, not fixed.

---

## 11. Step 0a (approval condition): does the `id` collision reach back into 5A? (real evidence, no product changes made)

**Scope, verbatim from the approval:** are any of the 22 collision groups found in §6
present in `alerts.json` (not just `archives.json`) on the same node with different
content; if so, quantify whether `incident_alerts`' `UNIQUE(tenant_key, node, alert_id)`
and ClickHouse's `uniqExact(cluster_node, alert_id)` have dropped or undercounted real
alerts, on real lab data; read what Wazuh's `id` is actually made of in 4.14.8 and cite
file/line; propose a collision-safe identity and its migration impact. **Investigate
only, report before changing anything** - nothing in this section changes product code,
schema, or config beyond the lab stack itself (restarted to reproduce the condition;
left running at the end, see "lab-tenant pollution" below).

### Finding 1 — the 22 collision groups were never checked against `alerts.json`; a fresh real reproduction shows zero collisions there

§6's 22 groups were found by scanning a one-off `archives.json` snapshot during the
earlier `logall_json` re-measurement; that pass never checked whether the same `id`
values also appear more than once in `alerts.json`. Re-tested directly:

```
$ cd deploy/lab && docker compose up -d        # stack had exited 18 min earlier, see below
$ # enabled logall_json on both workers, restarted analysisd:
$ docker exec shadowtracer-lab-wazuh-worker1-1 sed -i \
    's#<logall_json>no</logall_json>#<logall_json>yes</logall_json>#' /var/ossec/etc/ossec.conf
$ docker exec shadowtracer-lab-wazuh-worker1-1 /var/ossec/bin/shadowtracer-control restart
$ # (same for worker2)
$ # fired 2 real 20-connection parallel SSH invalid-user bursts against agent-ubuntu-1:
$ docker exec shadowtracer-lab-agent-ubuntu-1-1 sh -c '
    for i in $(seq 1 20); do
      ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=2 "burstuser${i}@localhost" true &
    done; wait'
$ docker cp shadowtracer-lab-wazuh-worker2-1:/var/ossec/logs/alerts/alerts.json w2-alerts.json
$ docker cp shadowtracer-lab-wazuh-worker2-1:/var/ossec/logs/archives/archives.json w2-archives.json
$ # (same for worker1) - then grouped every line by its "id" field with a real Python
$ # script (json.loads per line, not grep - the design doc's own §6 caveat about a
$ # grep -o false-negative applies here too)
```

Result, both workers, parsed with Python (`json.loads` per line, `collections.defaultdict`
grouping by `id`):

| file | lines | distinct ids | collision groups |
|---|---|---|---|
| worker1 `alerts.json` (full file, includes pre-existing + new) | 86 | 86 | **0** |
| worker2 `alerts.json` (full file, includes pre-existing + new) | 79 | 79 | **0** |
| worker1 `archives.json` (this test window only) | 16 | 7 | 3 |
| worker2 `archives.json` (this test window only) | 46 | 12 | 8 |

Zero `alerts.json` collisions, on either node, across the full lifetime of both files in
this lab run (165 real alert lines total) - including the exact burst shape (20 parallel
SSH connections, same second, same agent) that produced §6's 13-line sshd collision
group **in `archives.json`**. The corresponding `alerts.json` entries for that same burst
(rule 5710/5712, 16 real alerts) each got a distinct `id`. Every `archives.json`
collision group in this reproduction reflects the same two patterns §6 already
described: manager housekeeping (`df -P`, `last -n 20`, CIS benchmark summaries) and
non-alerting lines inside a real sshd burst (`Connection closed by invalid user ...`,
`drop connection ... past MaxStartups` - these never individually satisfy an alert rule,
so they only ever reach `archives.json`). **Answer to the first question: no, none of
the collision groups appear in `alerts.json` with different content, because none of
them appear in `alerts.json` at all.**

### Finding 2 — what `id` is actually made of in 4.14.8, and why that split is not a coincidence

Read directly from source (this repo vendors Wazuh 4.14.8 under `src/`, confirmed via
`shadowtracer/docs/ALLOWLIST_WAZUH_TEXT.txt:561-567`):

- The `id` field is `"<tv_sec>.<counter>"`, built by `snprintf(alert_id, 22, "%ld.%ld",
  (long int)lf->time.tv_sec, get_global_alert_second_id())` -
  **`src/analysisd/format/to_json.c:58`** (`alert_id` added to the JSON root at line 62).
  This one function, `Eventinfo_to_jsonstr()` (`to_json.c:26`), formats **both**
  alert-output and archive-output JSON - there is no separate archive formatter.
- `counter` is a single process-wide `long` (`g_ftell_alerts`) behind an rwlock:
  `get_global_alert_second_id()` / `set_global_alert_second_id()` -
  **`src/analysisd/config.c:341-353`**.
- The counter is **only ever set** in `w_writer_log_thread` (the alert-output path,
  created exactly once: `w_create_thread(w_writer_log_thread, NULL)` at
  **`src/analysisd/analysisd.c:1037`**), which sets it to `ftell()` of whichever real
  alert-log stream is active - `ftell(_aflog)` if `Config.alerts_log` or
  `Config.custom_alert_output` is on, else `ftell(_jflog)` - **immediately before**
  writing that alert, all inside one `writer_threads_mutex` critical section
  (**`analysisd.c:1496-1507`**). This lab's `ossec.conf` has both `alerts_log: yes` and
  `jsonout_output: yes` (confirmed: `docker exec ... grep -n jsonout_output -A2
  /var/ossec/etc/ossec.conf` → both `yes`), so the `ftell(_aflog)` branch is the one
  actually exercised. Because this thread is single-instance and every real alert
  appends a non-empty, variable-length record to that stream, `ftell()` strictly
  increases between any two real alerts - that is the entire reason `alerts.json` ids
  cannot collide with each other under this code path, not an incidental property of
  the test data.
- The archive-output path, `w_writer_thread` (created exactly once:
  **`analysisd.c:1034`**, calling `jsonout_output_archive()` at **`analysisd.c:1480`**
  when `Config.logall_json` is on), **never calls `set_global_alert_second_id`** -
  confirmed by grep (`grep -n set_global_alert_second_id src/analysisd/*.c` → only
  `analysisd.c:1500/1503/1506` inside `w_writer_log_thread`, and `testrule.c`'s unit-test
  harness; zero hits in the archive path). Every archive-only event - anything that
  reaches `archives.json` without itself clearing an alert rule - is formatted through
  the same `Eventinfo_to_jsonstr()` but reads whatever counter value the **alert**
  thread last wrote, however long ago. That stale, shared value is §6's and this
  section's entire collision mechanism, and it is structural, not rare: `writer_queue`
  (archives) and `writer_queue_log` (alerts) are two independent queues feeding two
  independent single-instance threads, and only one of the two ever advances the shared
  counter.

### Finding 3 — quantified real impact on 5A's own tables: zero, today, and architecturally zero regardless of volume

`shipper.py`'s `ALERTS_PATH` reads `/var/ossec/logs/alerts/alerts.json` only -
`archives.json` is not ingested anywhere yet (that is precisely the new
`events.archives` topic §2/§6a propose for 5C-1). Combined with Finding 1/2,
`incident_alerts` and `events` have never had a real `(node, alert_id)` collision to
drop, and structurally cannot while the ingestion source stays `alerts.json`-only.
Verified on real data, same lab session, after restarting `correlate-1/2` and
`closer-1/2` (both had crashed on a ClickHouse-not-yet-ready race from the earlier
`docker compose up -d` - an environment startup race, unrelated to this investigation,
fixed by `docker compose restart correlate-1 correlate-2 closer-1 closer-2`):

```
$ docker exec shadowtracer-lab-ch-clickhouse-1-1 clickhouse-client -u shadowtracer \
    --password '***' --query \
    "SELECT cluster_node, count(), uniqExact(alert_id) FROM shadowtracer.events \
     WHERE time >= now() - INTERVAL 2 MINUTE GROUP BY cluster_node"
worker2	15	15

$ docker exec shadowtracer-lab-postgres-1 psql -U shadowtracer -d shadowtracer -t -c \
    "SELECT node, count(*), count(DISTINCT alert_id) FROM incident_alerts \
     WHERE created_at >= now() - interval '2 minutes' GROUP BY node;"
 worker1 |    56 |    56
 worker2 |    79 |    79

$ docker exec shadowtracer-lab-ch-clickhouse-1-1 clickhouse-client -u shadowtracer \
    --password '***' --query \
    "SELECT component, count() FROM shadowtracer.dead_letter_events \
     WHERE failed_at >= now() - INTERVAL 2 MINUTE GROUP BY component"
(empty - zero dead-letters)
```

`count()` equals `uniqExact(alert_id)`/`count(DISTINCT alert_id)` in every row, for both
ClickHouse (post-ReplacingMergeTree, checked both with and without `FINAL` - identical)
and Postgres's unique constraint: nothing has ever collapsed, and nothing has been
rejected by the constraint. This matches the full `alerts.json` scan in Finding 1
(165/165 distinct across the whole lab lifetime, including the test bursts above).

### Collision-safe identity — recommendation

**No migration needed for 5A's existing identity.** `(cluster_node, alert_id)` /
`(tenant_key, node, alert_id)` is safe today, and will stay safe for as long as the
ingestion source is `alerts.json` only, because the *source* field is proven unique by
Finding 2's mechanism, not by luck. The risk §6 already found and designed around
(`(cluster.node, id)` as a candidate-narrowing filter, exact `full_log` match to
disambiguate, §6a) is real but **scoped entirely to the new `events.archives` path**
5C-1 proposes - it does not reach back into anything 5A built or anything already in
`incident_alerts`/`events` today. Concretely: **do not change `incident_alerts` or
`events`'s identity columns or constraints as part of 5C-1** - keep §6a's
`full_log`-narrowing design for the archives side exactly as written, and apply it only
to the new archive-sourced rows when 5C-1 builds `events.archives`.

Two residual, unretested edge cases, flagged as theoretical (not reproduced, marked
honestly rather than silently assumed away):
- If `ossec.conf` ever ran with `alerts_log: no` and `jsonout_output: yes` alone, the
  same single-thread/`ftell(_jflog)` argument applies (same code, same mutex) - not
  separately tested live, since this lab's config exercises the `_aflog` branch.
- After a manager restart, `_aflog`/`_jflog` reopen in append mode at the existing
  file's end-of-file offset, not zero - a same-second collision would need that
  reopened `ftell()` to exactly match a completely unrelated alert's offset from a
  different moment. Not observed in this or the original investigation; astronomically
  unlikely given `ftell` values are real byte offsets into a growing file, not noted as
  a real risk.

### Lab-tenant pollution (disclosed, not cleaned up here per "report before changing anything")

The two 20-connection SSH bursts used to reproduce Finding 1 ran against the same shared
lab tenant (`TENANT_KEY` in `deploy/lab/.env`) - there is no dedicated test tenant yet
(that is §10's proposed 5C-0, not built). This is the same test-traffic-into-the-real-tenant
pattern `deploy/lab/purge-2026-10-09-lab-tenant-test-incidents/` was already created to
clean up once. New test incidents from this investigation are in the real lab tenant's
`incidents`/`incident_alerts`/`fingerprint_occurrences` tables now; **left as-is**,
since purging is a change and this section's instructions were to report findings, not
act on them. A purge pass (same shape as the existing `purge-2026-10-09-...` backup) is
one more argument for pulling 5C-0 forward, as §10 already proposes.
