# SOAR — incident-level automated response (Phase 9)

Status: **research + design (report before coding)**. Host isolation and Windows
actions are plan-only until the VMs exist. This document records what our tree
already gives us, proves the one hard dependency (a timed Wazuh active-response
block driven from the manager API), and sets the design against the industry
references before any SOAR code is written.

---

## 1. Wazuh active response (AR) in our 4.14.8 tree

### Shipped scripts
Built from `src/active-response/` (`src/Makefile`, `active_response_programs`),
installed on every agent under `/var/ossec/active-response/bin/`. Confirmed
present on `agent-ubuntu-1`:

| script | action | timeout_allowed | notes |
|---|---|---|---|
| `firewall-drop` (built from `default-firewall-drop`) | iptables/nft `INPUT -s <ip> -j DROP` | yes | Linux. Our primary block. |
| `firewalld-drop` | firewalld rich-rule drop | yes | Linux (firewalld hosts). |
| `host-deny` | append `<ip>` to `/etc/hosts.deny` | yes | Linux, no NET_ADMIN needed. |
| `route-null` | null-route the IP | yes | Linux. |
| `ip-customblock` | user-supplied block command | yes | Linux. |
| `disable-account` | lock a local account | yes | Linux. |
| `netsh.exe`, `route-null.exe` | Windows firewall / null route | yes | **plan-only** until the Windows VM exists. |
| `restart-wazuh`, `kaspersky`, `wazuh-slack` | (not used by SOAR) | — | — |

### Stateful timeout + reverse action
Commands declared `<timeout_allowed>yes</timeout_allowed>` support an
`add` → (timeout) → `delete` lifecycle. The script is **stateful**: on `add` it
first emits a `check_keys` request (its active key = the srcip) and waits for
execd to answer `continue` (apply) or `abort` (key is in the ignore list / already
acted). `delete` reverses the same key. This `delete` path is exactly what our
**undo** and **timed expiry** will invoke.

### `repeated_offenders`
Configured on the `<active-response>` block (`src/os_execd/`); escalates the block
duration for an IP that re-offends within a window. **Linux agents only** — Windows
execd does not honour it. Where unsupported (Windows, later) SOAR owns its own
escalation schedule (design §E).

### Custom AR JSON input / `check_keys`
AR scripts read a JSON message on stdin:
`{"version":1,"origin":{…},"command":"add|delete|continue","parameters":{"extra_args":[…],"alert":{"data":{"srcip":"…"}},"program":"…"}}`.
`check_keys` lets the script refuse keys execd marks ignored — a second, agent-side
allowlist beneath our own (design §F).

### Manager API active-response call (incl. `!script`)
`PUT /active-response?agents_list=<id>` → `framework/wazuh/core/active_response.py`
`create_message()`. The `command` is validated against `ar.conf` (only commands
wired to an `<active-response>` rule block appear there) **unless it starts with
`!`**, which runs the named script directly and bypasses that check. Our tree's
`ar.conf` only lists `restart-wazuh0` and `shadowtracer-yara-scan0`, so SOAR calls
the **`!firewall-drop`** custom form — the same form we'll use for every
containment script.

### Proof — timed firewall-drop on a lab Linux victim via the API
Manager API `https://127.0.0.1:55000` (wazuh-wui). Target IP `203.0.113.50`
(RFC5737 documentation range — never a real host).

**(a) API dispatch path** — `PUT /active-response?agents_list=001` with
`{"command":"!firewall-drop","arguments":[],"alert":{"data":{"srcip":"203.0.113.50"}}}`:
```
{"data": {"affected_items": ["001"], "total_affected_items": 1, ...}, "error": 0}
```
Agent `active-responses.log`:
```
firewall-drop: {…"command":"check_keys","parameters":{"keys":["203.0.113.50"]}}
firewall-drop: {…"command":"continue"…"program":"active-response/bin/firewall-drop"}
firewall-drop: Ended
```
So manager API → execd → agent → script ran with the correct srcip and honoured
the `check_keys` handshake.

**(b) Block + reverse on real netfilter** — driving the binary as root inside the
NET_ADMIN-capable agent, feeding the exact manager JSON (`add`+`continue`, then
`delete`+`continue`):
```
=== ADD + continue ===  → iptables: -A INPUT -s 203.0.113.50/32 -j DROP
=== DELETE + continue === → iptables: (no rule)
```
Block applied, reverse removed it. **The full timed firewall-drop is proven**:
API dispatch ✓, stateful check_keys ✓, iptables DROP ✓, reverse ✓.

**Lab gap for a single-command end-to-end (VERIFY phase, not a Phase 9 blocker):**
the only agent with `NET_ADMIN` + working iptables is `agent-ubuntu-1`, which
carries a **stale key (060)** the manager never registered (pre-existing lab drift
from a reset); the registered+active agents `001/002/003` lack `NET_ADMIN`. A
one-line compose fix (grant `NET_ADMIN` to a registered agent and reprovision its
key) gives a registered+capable victim for the live VERIFY run. Chosen not to do it
now to avoid disrupting the owner's running lab during the research phase.

**"Timed":** our SOAR layer owns expiry regardless (safety rail §F: every block
timed, automatic expiry), scheduling the `delete` we proved above; Wazuh's own
`<timeout>` is a belt-and-braces second timer where a rule-wired block is used.

---

## 2. Wazuh integrator — shippable integrations and reuse

`integrations/` ships `slack.py`, `pagerduty.py`, `shuffle.py`, `virustotal.py`,
`maltiverse.py` (the `wazuh-integratord` scripts). For SOAR notifications:

- **Slack** — reuse `integrations/slack.py`'s webhook POST shape; we drive it from
  the SOAR notifier (not integratord) so delivery, retry, throttling and redaction
  are under our control and audited.
- **Shuffle** — reuse as an **optional outbound webhook only** (design: no embedded
  Shuffle/Tracecat/n8n code).
- **PagerDuty** — available; not in the Phase 9 channel set (email/webhook/Slack/
  Discord/Telegram), left as future.
- **Discord, Telegram** — no shipped integrator; implemented in the SOAR notifier
  (Discord channel webhook; Telegram Bot API `sendMessage` to a chat id).

Integratord runs on the manager off alerts — wrong layer for incident-level,
tenant-scoped, audited SOAR notifications. We reuse the **payload shapes**, not the
integratord runtime.

---

## 3. Incident open/update events for a worker

**No incident Kafka topic exists.** Kafka carries per-tenant *alert* topics only
(`shadowtracer.t.<key>.alerts`, `ingest/shadowtracer_ingest/topics.py`); the
correlator consumes those and writes **incident state to Postgres**
(`correlate/shadowtracer_correlate/models.py` → `incidents`). Incidents carry
`state` (`open`/`closed`), `triage_status`, `updated_at`, `created_at`, plus every
signal SOAR needs: `rule_ids`, `rule_groups`, `mitre_ids`, `source_ips`,
`source_ip_total`, `users`, `agent_id`, `fingerprint_key`, `ti_confidence`,
`ml_score`/`ml_anomaly_score`, `priority`.

**SOAR worker source of truth = Postgres, polled** on `updated_at > watermark`
(cheap, indexed, no new infra, no hot-path coupling). This is its own worker
process; nothing runs on the alert hot path (constraint: "Nothing on the hot path").

---

## 4. Reusable pieces (build on, don't rebuild)

| need | reuse | where |
|---|---|---|
| audit log | hash-chained append-only `audit_log` + `append_entry()` / `verify_chain()` | `console/backend/app/audit.py` |
| roles | `RequireRole` deps: `ADMIN_ONLY`, `ANALYST_OR_ABOVE`, `ALL_ROLES` | `console/backend/app/rbac.py` |
| tenant registry | `tenants` table + per-tenant `tenant_key` scoping everywhere | `models.py`, `ingest/.../tenants.py` |
| TI facts | incident `ti_confidence` (ti-matcher) + per-source IOC confidence | `intel/shadowtracer_intel/{store,feeds,matcher}.py` |
| campaigns / fingerprints | `campaigns`, `campaign_incidents`, `fingerprints`, `fingerprint_verdicts` | `correlate/.../models.py` |
| asset data from agents | `agent_role_tags` (`role_tag`, `os_family`) — asset grouping + OS capability | `models.py` |
| secrets | envelope-sealed secrets (AES-256-GCM, KEK) — pattern for notifier secrets, **but Phase 9 keeps notifier secrets in `.env` only** | `console/backend/app/secrets_crypto.py` |
| Wazuh API client | token cache + `_request` + `endpoints()` (tenant→manager URL) | `console/backend/app/wazuh_api.py` (extend with `run_command`) |

`agent_role_tags.os_family` already tells SOAR which block script an agent supports
(firewall-drop vs firewalld-drop vs host-deny); `role_tag` is the handle for the
`full|approval|none` automation groups (design §B).

---

## 5. Design — approach and why native

Mapped to the industry references, then why we build on Wazuh AR rather than adopt a
SOAR platform.

- **Microsoft Defender automation levels** (full / semi-automated with
  approval variants / no-automation) → our **per-asset-group `full | approval | none`**
  (§B), default `approval`. Defender's *attack disruption* keeps the containment
  decision with the system or a person and excludes break-glass accounts → our
  **allowlist + kill switch + confidence gate** (§F). Defender's "full automation
  removes more malware" is a vendor claim; we don't take it on faith — autonomy is
  **earned per playbook on measured shadow precision** (§D), not switched on by policy.
- **Google SecOps action classes** (enrichment / notification / containment) → our
  **enrichment (always auto) / escalation (notify) / containment (gated)** split (§A).
- **Tines guardrails** (change control: peer review before live, requester ≠ approver,
  audit every change, tier approval by risk to avoid fatigue) → our **four-eyes
  approvals** (approver ≠ playbook owner, §G), **mode-per-step** `shadow|approval|auto`
  so only consequential steps gate (§E), and **every request/approve/execute/undo/
  expire in the hash-chained audit log** (§F).
- **Shuffle / Tracecat / Cortex** (open SOAR engines) → not adopted; Shuffle is an
  **optional outbound webhook only**. We don't embed a workflow engine.

**Why native.** Containment here *is* Wazuh active response — the agents, the
manager API, the stateful timeout/reverse, `repeated_offenders` and `check_keys`
already exist and are proven above. A bolt-on SOAR platform would duplicate the
agent fleet's capability map, re-auth to the same manager API, and add a second
audit trail and secret store next to the ones we already run hash-chained and
tenant-scoped. The incremental SOAR logic we actually need — confidence gate,
earned autonomy, safety rails, approvals, playbooks — is **policy around a
dispatch primitive we already have**, so it lives as one tenant-scoped worker +
console pages on our existing Postgres/RBAC/audit spine.

**Memory headroom.** The SOAR worker is a single poller (no model, no PyTorch); it
reads Postgres and POSTs to the manager API / webhooks. Budget it like the other
light workers (`ml-drift`, `closer`) at a ~128–176 MB mem_limit. Headroom to be
reported with real figures once the worker runs.

---

## 6. Build log — commit (a): worker + block_ip + gate + rails + audit

Backend, no console/live-VERIFY yet (those are a follow-up). Lives in the console-backend
package (reuses the hash-chained `audit`, `wazuh_api`, `db`, `models` — one audit chain,
one AR client) and runs as its own process.

- **Schema** (`ingest/alembic/…b3d5f7a9c1e2`): `soar_actions` (idempotent on
  tenant+incident+playbook+action+target), `soar_tenant_settings` (kill switch, circuit
  breaker, block default/max seconds, rate + scope limits), `soar_global_settings` (global
  kill switch), `soar_allowlist`, `soar_worker_state` (poll cursor). Applied to the lab.
- **Worker** (`app/soar/worker.py`, run `python -m app.soar.worker`): polls open incidents
  from Postgres with an **overlap window** behind the `(updated_at, id)` cursor, so an
  incident committing with an `updated_at` earlier than the cursor is still seen; the
  idempotency constraint makes the re-read a no-op (test:
  `test_overlap_window_processes_late_incident_exactly_once`). Off the hot path.
- **Confidence gate** (`gate.py`): ≥2 independent non-model signals (rule match / TI hit /
  known repeat / KEV); model scores are recorded but never counted and never sole trigger.
- **Safety rails** (`rails.py`): kill switch (global + per-tenant), allowlist
  (RFC1918/loopback/link-local/multicast/reserved + agent-and-manager IPs + admin CIDRs),
  anti-spoof (refuse an IP corroborated by a single alert — a forged log line — unless
  TI-confirmed; real activity like a brute force has many), timed blocks
  (default 1 h, capped at the admin max), per-tenant hourly rate limit and per-run scope
  limit (both trip the circuit breaker), idempotency (DB constraint). Every
  request/refuse/breaker-trip is in the hash-chained audit log.
- **Containment dispatch** (`actions.py` + AR script
  `intel/active_response/shadowtracer-fw-drop`): `apply_block`/`reverse_block` call the
  ShadowTracer AR script with `add`/`delete`, giving SOAR API-driven block **and** reverse
  (the basis for timed expiry + undo). In (a) the worker records actions only (status
  `requested`/`refused`); execution lands with approvals in (c).
- **Deploy**: opt-in `soar-worker` compose service under the `soar` profile (won't auto-start
  in a running lab). Tests: `test_soar_worker.py` (9), `test_soar_actions.py` (2), module
  self-checks in gate/rails/triggers. Console suite 197 green.

## 7. Build log — commit (b): shadow mode + earned autonomy

- **Schema** (`…c4e6a8b0d2f4`): `soar_playbooks` (per-playbook `mode` shadow|approval|auto +
  promotion audit — (c) extends it with the versioned YAML); `soar_tenant_settings` gains
  `promotion_min_precision` (0.95) + `promotion_min_incidents` (20).
- **Shadow is the default** (`earned_autonomy.playbook_mode`): a never-promoted playbook runs
  in shadow, so the worker records a **would-have** action (`status='shadow'`) and executes
  nothing. The rails still apply — a shadow action on an allowlisted/spoofed IP is still
  `refused`, recording what we'd actually have done.
- **The confidence gate now bites**: in `auto`, an action is auto-approved
  (`status='approved'`, `approved_by='auto'`, no human) only when the gate passes (≥2
  independent signals) and the rails didn't downgrade; a 1-signal or model-only incident
  falls back to an approval request. (`worker._resolve`.)
- **Shadow precision** (`earned_autonomy.compute_precision`): per playbook, over incidents
  that later got an analyst verdict — `triage_status='escalated'` = TP, `'false_positive'` =
  FP, counted per distinct incident. **Promotion gate** (`can_promote_to_auto` / `set_mode`):
  an admin may switch shadow→auto only at precision ≥ threshold over ≥ N verdicted incidents;
  below either, the switch is refused and audited (`soar.promotion_refused`); a successful
  switch is audited (`soar.playbook_mode_changed`). Demotion/approval need no gate.
- **Tests**: `test_soar_earned_autonomy.py` (6) + 2 worker auto-mode tests. Console suite 205
  green; CI floor 197→205.

## 8. Build log — commit (c): playbooks + approvals (four-eyes, expiry) + undo

- **Schema** (`…d2f4a6c8e0b1`): `soar_playbooks` gains `definition` (JSONB), `version`,
  `block_seconds` override, `updated_by`; `soar_playbook_versions` keeps every version
  (append-only); `soar_tenant_settings` gains `approval_ttl_seconds` (3600).
- **Playbooks** (`playbooks.py`): the 3 shipped definitions (SSH brute → block; TI IP →
  block; malware/YARA → collect_evidence + quarantine (approval) + notify). `upsert_playbook`
  bumps the version, appends to history, audits. The worker reads each playbook's block
  duration (`block_seconds_for`).
- **Approvals** (`approvals.py` + `routers/soar.py`, `/api/soar/*`, analyst+): `GET
  /approvals` queue, `GET /actions` history, `POST /approvals/{id}/approve|deny`, `POST
  /actions/{id}/undo`. Approve requires a reason, enforces **four-eyes** (approver ≠ playbook
  owner) and RBAC (block_ip = analyst+; disable_account/quarantine = admin, for (d)), then
  dispatches the block via Wazuh AR and sets a timed expiry; deny → refused; a cross-tenant
  action id is invisible (404). Every approve/deny/execute/undo is audited.
- **Undo + timed expiry** (`approvals.undo`, `worker.expire_stale`): undo reverses an
  executed block (one call). The worker sweep expires an unanswered request as **no-action**
  (escalation notification in (e)) and reverses an executed block past its expiry.
- **Tests**: `test_soar_approvals.py` (8), `test_soar_expiry_playbooks.py` (4). Console suite
  217 green; CI floor 205→217.

## 9. Build log — commit (d): disable_account / quarantine_file / collect_evidence

Three new containment action types, each a ShadowTracer AR script keyed on an apply/reverse
verb in `extra_args` (so the API drives both directions), wired through the same approval/undo
pipeline.

- **AR scripts** (`intel/active_response/`): `shadowtracer-disable-account`
  (`usermod -L/-U` + expiry; POSIX-name validated; refuses root/service accounts),
  `shadowtracer-quarantine` (move into a 0600 quarantine store with a sha256+path manifest /
  restore; refuses a path outside a FIM-monitored root), `shadowtracer-collect-evidence`
  (read-only snapshot of processes/connections/recent logins → a log the agent ships back,
  attached to the incident; no reverse). All no-shell, args-as-list.
- **Dispatch** (`actions.py`): `ACTION_SCRIPTS` maps each type → (script, apply verb, reverse
  verb); `apply_action`/`reverse_action` dispatch by type; `REVERSIBLE =
  {block_ip, disable_account, quarantine_file}` (collect_evidence is read-only).
- **Approvals** (`approvals.py`): approve/undo dispatch by action type; RBAC already requires
  **admin** for disable_account/quarantine_file, analyst+ for block_ip and the read-only
  collect_evidence; undo on an irreversible action is refused (409). Only `block_ip` gets a
  timed auto-expiry — account-disable/quarantine persist until undone.
- **Tests**: +4 approval tests (admin-gated approve/undo for disable_account & quarantine,
  read-only collect_evidence) +2 dispatch-map tests. Console suite 223 green; CI floor
  217→223.

The three scripts deploy onto agents (like `shadowtracer-fw-drop`) at live-VERIFY time.

## 10. Build log — commit (e): notifiers (email / webhook / Slack / Discord / Telegram)

Notification-only escalation; messages link to the console, no inbound buttons/callbacks.

- **Schema** (`…e1a3c5b7d9f2`): `soar_channels` (per-tenant per-channel config — off by default,
  detail level, severity threshold, throttle + batch window); `soar_notifications` (the delivery
  queue: queued→sent|failed, attempts, backoff, 429 retry-after).
- **Notifier** (`notify.py`): five senders (email via SMTP; webhook/slack/discord/telegram/shuffle
  via httpx). **Secrets are env-only** (`SOAR_CHANNEL_SECRETS` JSON) — never in the DB/logs/API;
  the API reports configured/not. **Redaction by construction**: the context is whitelisted to
  `SAFE_KEYS` at enqueue, so raw logs, log usernames, secrets and IOC lists can never reach a
  payload. **Detail level**: minimal (severity, title, status, console link) vs standard (+ host,
  ATT&CK, action). **Delivery** (`deliver_pending`): queued, exponential backoff, honours HTTP 429
  `Retry-After`, per-channel throttle, and **burst batching** (many due on a channel → one summary).
  A send failure stays in the queue and never blocks the action (`notify_safe`).
- **Events wired**: approval_needed (worker request), action_executed/undone (approvals),
  circuit_breaker_tripped + approval_expired (worker). The worker runs `deliver_pending` each poll.
- **API** (`routers/soar.py`, admin): `GET /channels` (config + configured flag, no secrets),
  `PUT /channels/{channel}` (enable/detail/etc., audited), `POST /channels/{channel}/test`.
- **Tests** (`test_soar_notify.py`, 11 + 1 opt-in): each channel to a local mock server, mock SMTP,
  minimal vs standard, redaction, 429 retry-after, 50-event burst → one summary, disabled/
  unconfigured send nothing. Opt-in `SOAR_MANUAL_NOTIFY_TEST` hits real Discord/Telegram. Console
  suite 235 green; CI floor 223→235.

## 11. Build log — commit (f): metrics

- **`metrics.py`** (+ `GET /api/soar/metrics`, analyst+, tenant-scoped): computed from
  `soar_actions` + `incidents` with no new storage. Per-incident timeline (first alert →
  incident → requested → executed) gives **MTTD** (first alert → incident) and **MTTC** (first
  alert → contained), plus the mean request and approve→execute latencies. Rates: **automation
  rate** (auto executions / all executions), **undo rate**, and **false-positive action rate**
  (actions on incidents an analyst later verdicted `false_positive`, over verdicted incidents).
  Division-by-zero yields `null`, not an error.
- **Tests**: `test_soar_metrics.py` (3) — timings + rates on seeded data, empty tenant, endpoint
  auth. Console suite 238 green; CI floor 235→238.

## Backend complete — what's left (follow-up)

Commits (a)–(f) are the backend-complete milestone agreed with the owner.

## 12. Build log — follow-up Part A: backend gaps

- **A1 asset automation levels** (`assets.py`, migration `f3b5d7a9c1e4` → `soar_asset_levels`):
  admin tags an agent or a whole role_tag as full | approval | none (default approval; resolution
  agent → role_tag → default). Enforced in the worker: `none` → containment refused
  (`asset_level_none`, audited; incident notification still fires); `approval` → never auto even
  under an auto playbook; `full` → the playbook mode applies. API `GET/PUT /api/soar/asset-levels`
  (admin, audited).
- **A2 repeat-offender escalation** (`repeat_offender.py`): Wazuh's `repeated_offenders` doesn't
  apply to API-dispatched custom scripts, so SOAR owns it — per tenant+IP, count prior blocks in
  the look-back window and pick the escalating schedule step (default 1h→6h→24h, capped at the
  admin max). Recorded on the action (a `repeat_offender` signal). Config on
  `soar_tenant_settings` (`repeat_window_seconds`, `escalation_schedule`).
- **A3 agent-side expiry** (`shadowtracer-fw-drop`): each timed block is recorded on the agent with
  its absolute expiry; the script removes due blocks ITSELF on every call and on a periodic Wazuh
  `command` wodle (`sweep`), so a block still lifts on time even if the SOAR worker is dead. The
  worker's `expire_stale` stays as the second, independent timer. The block TTL is passed as the
  third AR arg (`actions.apply_action`).
- **A4 anti-spoof by provenance** (`provenance.py`): an IP is blockable only if it reached us as the
  `src_endpoint_ip` of a **trusted network decoder** (`TRUSTED_DECODERS`), never because it was
  parsed out of user-controllable text — so a log-injection line that puts an IP in a username field
  is never blockable, regardless of count/TI. The count check stays as an extra condition
  (`rails.guard` now takes `trusted_field`). The live lookup joins the incident's alerts to
  ClickHouse; injectable for tests.
- **A5 least-privilege API user** (`provision-soar-api-user.sh`, `wazuh_api._soar_token`): a
  dedicated Wazuh user with a policy allowing only `active-response:command` on the test-tenant
  agents; SOAR authenticates as it (`SOAR_WAZUH_API_*`, env only) instead of wazuh-wui, so a leaked
  SOAR credential can't manage agents or read logs. (Wazuh RBAC has no per-script resource; the
  shadowtracer-* restriction is enforced on our side.)
- **A6 notifications wired**: `incident_opened` (once per incident, severity-gated, deduped) and
  `kill_switch_toggled` (on the kill-switch API) added to the notifier events.
- **Tests**: A1/A2/A4 at the worker level + asset-level/kill-switch API tests (console suite 246
  green); A3 verified offline (sweep logic) with the live 2-minute-expiry timer in Part C.
- **A5 verified live** against the lab manager: the `soar` user fires `PUT /active-response` (**200**)
  but is denied `DELETE /agents` (**403**) and `GET /manager/logs` (**403**); agent:read stays
  allowed (a responder needs agent IDs). Provisioned with `rbac_mode: white` (deny-by-default). The
  SOAR worker now authenticates as `soar` (creds in the gitignored `.env`, never committed).

> **Note:** this followed a lab recovery — a host reset had left a native Windows PostgreSQL squatting
> host port 5432, blocking the lab's Docker Postgres; cleared by stopping the Windows service, after
> which Postgres reattached to the lab network and the suite ran clean.

## 13. Build log — follow-up Part B: console pages

One **SOAR** nav tab (`SoarPage.tsx`) with five sub-tabs, analyst/admin-gated to match the API, plus a
metrics strip (MTTD / MTTC / automation / undo / FP-action rate):

- **Approvals** — pending queue; approve/deny with a required reason; four-eyes / RBAC errors shown
  inline (the API's 403/409 detail).
- **Action history** — status filters, expiry countdown on executed blocks, one-click undo (hidden for
  read-only collect_evidence).
- **Playbooks** — mode badge, version, **shadow precision + verdict count** against the threshold, and a
  Promote-to-auto button that is disabled with the reason when below the gate.
- **Asset levels** (admin) — set full/approval/none per agent or role_tag.
- **Settings** (admin) — kill switch + circuit-breaker reset, limits/escalation schedule (read), allowlist
  add/remove, and the notification channels with configured/not-configured badges, enable toggle, detail
  level, and a **Send test** button.

Supporting API added to `routers/soar.py`: `GET /playbooks`, `POST /playbooks/{key}/mode` (admin, gated),
`GET/PUT /settings`, `POST/DELETE /allowlist` (+ a `DELETE` grant migration `a7c9e1f3b5d8`). Tests:
`test_soar_console_api.py` (6). Console suite 252 green; frontend `tsc`/build/lint clean. Screenshot
`docs/report/9-soar.png`.

**Not yet done:** the console pages (Part B) and the live-lab VERIFY matrix (Part C) — which first
needs **re-enrolling agent-ubuntu-1 (NET_ADMIN) into the test tenant**. **Windows netsh/route-null
stay plan-only** until the VMs exist. No containment is driven by the LLM agent or a model score
alone; nothing runs on the hot path; the SOAR worker is a single light poller (~160 MB).
