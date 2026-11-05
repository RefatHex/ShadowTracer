# ShadowTracer — Optimisation & Hardening Backlog

Last updated: 2026-11-05

ShadowTracer is in a **features-first** period. Anything that is not needed for a
feature to work correctly goes here instead of blocking feature work. Nothing in
this file is forgotten. It is the queue for the optimisation and hardening phases
that follow the feature phases.

## How to use this file

- Add an item the moment it is found (bug that isn't blocking, slow path, missing
  hardening, measurement gap). Include the evidence or the commit where it was found.
- Never delete an item. When it's done, set its status to `DONE <commit>`.
- Two rules still apply during feature work and are **not** deferred:
  1. **Correctness:** no data loss, no duplicate incidents, no cross-tenant leak.
  2. **Throughput gate:** no feature may slow the ingestion hot path (see
     `FEATURE_PLAN.md`, "Throughput rule").

**Trigger legend**

| Trigger | Meaning |
|---|---|
| BFC | Must be done before the first customer install |
| B5C | Must be done before the Sigma raw-event stream (5C) ships |
| NEXT-OPT | First thing to do in the next optimisation phase |
| LATER | Do when scale or customers require it |

---

## 1. Throughput and performance

Current measured state (lab, WSL2, 12 GB, 2026-11-05, `THROUGHPUT_BASELINE.md`):
end-to-end ~500 events/s (~43 M/day); writer ~3,300/s; analysisd ~4,000/s per
manager; shipper ~10,000/s; correlator ~530–550/s and Postgres-bound.

| ID | Item | Evidence / current state | Proposed fix | Trigger | Effort |
|---|---|---|---|---|---|
| T1 | Correlator is the end-to-end ceiling | ~530–550/s at 1k–5k/s offered; correlators at 2–51% CPU, Postgres at 123–171% (commit 1401d6dc38, c66d52808e) | Apply the item-4 profiling proposal; reduce Postgres round trips further; skip correlation for low-level/SCA alerts | NEXT-OPT | M |
| T2 | Partition skew from few syslog devices | 12 device keys give 2.5–17% per partition | Fine with real device counts; size partitions per tenant by endpoint/device count | LATER | S |
| T3 | analysisd ceiling per manager | ~4,000/s on lab hardware | Big tenants need a manager cluster; document sizing per manager | LATER | S |
| T4 | Shipper blocking flush after every batch | Ceiling ~10,000/s | Async delivery with bounded in-flight, offset advanced on ack | LATER | S |
| T5 | Correlator failover ~50 s | Default 45 s session timeout (5A chaos runs) | Lower session timeout / heartbeat; test with slow Postgres | LATER | S |
| T6 | Scale design not written | 10k / 100k / 1M events/s path unknown | `SCALE.md`: streaming state engine for correlation, ClickHouse sharding by tenant, tiered storage, ClickHouse Kafka ingestion instead of Python writer | LATER | M |
| T7 | TLS/SASL overhead unmeasured | No plaintext listener left to compare | One comparison run on a throwaway broker | LATER | S |
| T8 | fsync cost on writes | Turned on after power-cut corruption | Measure write ceiling with/without; production relies on replicas on separate hosts | LATER | S |
| T9 | Throughput of new feature consumers | TI matcher, ML scorer, embedder not measured yet | Measure each consumer's ceiling when it is built (feature phases record it here) | Per feature | S |
| T10 | analysisd collapses on many-source brute force | Moved to **S9** (security) on 2026-11-05: attacker-triggered event loss | — | MOVED S9 | — |
| T11 | integratord is serial fork/exec per alert | `src/os_integrator/integrator.c:278-460`: one process per matching alert, waits for it. Estimated 3–20 alerts/s with an HTTPS call (not measured) | Measure in 6.3 with the VT script; if FIM bursts lag, run the script as a long-lived worker fed by a queue | LATER | S |

## 2. Reliability and operations

| ID | Item | Evidence / current state | Proposed fix | Trigger | Effort |
|---|---|---|---|---|---|
| R1 | 577 empty closed incidents in the lab | Replica race, now fixed (e7c3847296); query in `THROUGHPUT_BASELINE.md` §13.6 | Export, then delete | NEXT-OPT | S |
| R2 | ClickHouse replicas share one host | One power cut corrupted both replicas | Production: replicas on separate hosts and power | BFC | M |
| R3 | Postgres `ALTER ROLE` race in migrations | Suites must run sequentially in CI | Move grants to a separate provisioning step | LATER | S |
| R4 | Post-crash ClickHouse recovery is manual | `recover-ch-after-crash.sh` needed a human approval | Runbook plus automated detection of broken parts in `/health/detail` | LATER | S |
| R5 | Lab power cuts | Three cuts in one round | UPS for the dev machine | Now (non-code) | — |
| R6 | Warm-up threshold (30 incidents) is a guess | Lab data only | Recheck against a pilot tenant | LATER | S |

## 3. Security (before first customer)

From `THREAT_MODEL.md` §11–12. Kafka TLS/SASL + per-tenant topics are DONE.

| ID | Item | Proposed fix | Trigger | Effort |
|---|---|---|---|---|
| S1 | Single shared JWT secret | One EdDSA/RS256 key pair, `kid` rotation, algorithm pinned, key outside repo | BFC | M |
| S2 | ClickHouse shared admin credential | Per-service users with scoped grants | BFC | M |
| S3 | Flat network | Split data plane / manager tiers | BFC | M |
| S4 | Agent enrollment | Enrollment password + agent-side manager certificate verification | BFC | S |
| S5 | Postgres/ClickHouse cleartext | TLS on both | Before multi-host | M |
| S6 | Secrets rotation | Runbook written; implement automation | LATER | M |
| S7 | Agent↔manager channel never re-audited | Review or explicit out-of-scope decision | BFC | S |
| S8 | VM ports open on all interfaces | `docker-compose.vm.yml` override only, enrollment password on | While VMs are used | S |
| S9 | **Attacker-triggered event loss in analysisd** (was T10). An invalid-user SSH spray from many source IPs at 3,000/s held analysisd to 1,485–2,301 processed/s with drops from ~30 s and 553% CPU after the sender stopped (`design/THREAT_INTEL.md` §9.1). An attacker who can reach sshd on monitored hosts can blind the manager to everything else. Likely rule 5712 (`if_matched_sid 5710`, `same_source_ip`, 120 s) scanning a history that never reaches 8 matches. Not caused by TI | Confirm with perf; then index the per-rule prev-matched list by source IP or bound the scan; drop alarm in `/health/detail` (events_dropped rate); per-agent EPS limits as a stopgap | BFC | M |

## 4. Rebrand

| ID | Item | State | Trigger | Effort |
|---|---|---|---|---|
| B1 | Stage 2: Windows NSIS installer + service | 100% Wazuh-branded; needs Windows VM | BFC | M |
| B2 | Stage 3: daemon names + system user | Scripted, dual-accept decoders (~20 self-log matches) | BFC | L |
| B3 | Stage 4: install path `/var/ossec` → `/opt/shadowtracer` | After B2; our side already uses one setting | BFC (hard gate) | M |

## 5. Detection coverage

| ID | Item | State | Trigger | Effort |
|---|---|---|---|---|
| D1 | Windows VM + Sysmon, Ubuntu VM + auditd | Blocked on Hyper-V access | Needed for 5C and B1 | S (setup) |
| D2 | 5C Sigma (design approved, model b) | Lab-backed coverage is 0 until D1 | After D1 | L |
| D3 | 5D Atomic Red Team coverage on Windows | Linux part is pulled into AI phase 7.0 | After D1 | M |
| D4 | SCA scans dominate alert volume | Noise in incidents/fingerprints | Policy: exclude or down-weight from correlation | NEXT-OPT | S |

## 6. Tooling, packaging and upstream

| ID | Item | State | Trigger | Effort |
|---|---|---|---|---|
| U1 | GitHub Actions blocked at account level | `runner_id: 0` on every run; local `run-ci.sh` in use | Contact GitHub Support | — |
| U2 | `.deb`/`.rpm` packaging | Needs a Linux build VM (WSL2 lacks vsyscall) | BFC | M |
| U3 | CMocka load-balancer regression test | Never run | LATER | S |
| U4 | Upstream bug reports to Wazuh | Buffer requeue, LB NULL pointer, `wazuh_apid.py` shebang; from 6.0 (`design/THREAT_INTEL.md` §1.5, §9.4-9.5, §9.2): **hot reload frees queued events and unwritten alerts** (29/240,000 lost over 5 reloads; fix itself in 6.1a), **CDB fd/mmap leak per reload**, **`address_match_key_value` inverted**; also `PUT /lists/files` not atomic and rejects URL keys, reload reports success while dropping rules, `Lists_OP_MakeCDB` ignores `cdb_make_add` errors and leaks the temp FILE on a failed open (`lists_make.c:52-59,140`) | LATER | S |
| U5 | Tenancy model revisit | Dedicated managers chosen; shared model documented | When tenant count grows | — |
| U6 | Upstream reports from the 6.0 TI audit | Merged into U4 on 2026-11-05 | MERGED U4 | — |
