# ShadowTracer — Feature Plan: Threat Intelligence and AI

Last updated: 2026-11-05
Companion file: `OPTIMIZATION_BACKLOG.md` (everything deferred goes there).

## 0. Ground rules for the features-first period

1. **Features first.** Build each feature end to end (backend, storage, console view,
   tests, VERIFY), then move on. Optimisation and hardening that a feature doesn't
   need go to `OPTIMIZATION_BACKLOG.md`.
2. **Correctness is not deferred.** No data loss, no duplicates, no cross-tenant
   leak, in any feature.
3. **Throughput rule (see §2).** No feature may slow the ingestion hot path.
4. **Honest evaluation.** Every model is compared against a simple baseline on held-out
   data, with the result reported even if the model loses. A model that doesn't beat
   its baseline is shipped as "experimental" or not shipped, and the report says so.
   Lesson from earlier ML work: unsupervised scoring fails when attacks have benign
   look-alikes, and a triage model ranked at chance. Expect some null results.
5. **Every phase produces report material:** a results table, a screenshot of the
   console view, the VERIFY output, and a short "limits" paragraph.
6. **One feature per prompt, in three steps:**
   a. **Build standalone** and verify it in isolation (correct output on known inputs,
      failure behaviour, licence/terms checked).
   b. **Integrate** into the running program (pipeline, incidents, console).
   c. **Verify the integration** (end-to-end on the lab, tenant isolation, replay,
      throughput gate).
7. **Use Wazuh's own mechanisms first.** Before building a ShadowTracer service,
   check what Wazuh 4.14.8 already provides (CDB lists, rules, `wazuh-integratord`
   integrations, active response). Extend or modify the Wazuh tree when that is
   faster or simpler; record every change to inherited files in `UPSTREAM.md`.
   New files added to the Wazuh tree use ShadowTracer names. Renaming existing Wazuh
   names is done only through the rebrand script (Stage 3), never by hand mid-feature.

---

## 1. Architecture: where the new parts sit

```
agents -> managers (analysisd: rules + CDB IOC lists = Wazuh-native TI matching,
                    integratord: VirusTotal on FIM events)
       -> shipper -> Kafka (per-tenant topics)
                                   |
        HOT PATH (unchanged) ------+--> writer      -> ClickHouse events
                                   +--> correlator  -> Postgres incidents
                                   |
        SIDE CONSUMERS (new, own consumer groups, never block the hot path)
                                   +--> ti-matcher  -> only if CDB lists can't
                                   |                   cover a case (decided in 6.0)
                                   +--> ml-scorer   -> ClickHouse ml_scores   (HST)

        INCIDENT-CLOSE PIPELINE (rate ~ incidents, roughly 50x lower than alerts)
        closer -> incident_closed event -> enrichment worker:
                    features -> ARF / XGBoost -> SHAP -> embedding -> Qdrant
                    VirusTotal lookups (budgeted, cached)

        PERIODIC JOBS
        ti-sync (OTX, MISP) -> IOC store       drift-monitor (ADWIN on rollups)
        trainer (XGBoost / ARF checkpoints) -> MLflow registry

        ON DEMAND (analyst clicks)
        graph API (NetworkX)   investigation agent (LangGraph + LLM, read-only tools)
```

New services: `ti-sync`, `ti-matcher` (only if 6.0 shows it is needed), `ml-scorer`, `enrichment-worker`,
`drift-monitor`, `trainer`, `qdrant`, `mlflow` (+ its own Postgres database),
optional `misp` stack, `agent-api`.

---

## 2. Throughput rule

**Baseline to protect** (`THROUGHPUT_BASELINE.md`, 2026-11-05): end to end ~500
events/s; writer ~3,300/s; correlator ~530–550/s.

Rules:
- **No network calls on the hot path.** No VirusTotal, OTX, MISP, LLM or Qdrant
  call ever runs inside the shipper, writer or correlator.
- **Side consumers use their own consumer groups.** If one lags or crashes, ingestion
  and correlation continue unaffected. Their lag is reported in `/health/detail`
  but does not fail `/health/ready`.
- **Per-alert work must be O(1) and in-process:** IOC set lookup, River `score_one`.
  Each per-alert consumer must reach at least the writer's ceiling (~3,300/s) on
  its own, or scale by partition.
- **Heavy work runs per incident, not per alert:** features, ARF, XGBoost, SHAP,
  embeddings.
- **Expensive work runs on demand only:** graph building, the LLM agent.
- **Gate for every phase:** rerun the throughput baseline. The hot path (writer,
  correlator, end to end) must stay within 5% of the numbers above. Each new consumer's
  own ceiling is measured and recorded in `OPTIMIZATION_BACKLOG.md` (T9).
- **Idempotent outputs:** every new ClickHouse table is a ReplacingMergeTree keyed on
  the source identity (alert identity, or incident id + model version), so replay
  never duplicates.

---

## 3. Phase order

| Phase | Feature | Depends on | Lab resources |
|---|---|---|---|
| 6.0 | TI alignment audit with Wazuh (CDB lists, integratord) and design | — | small |
| 6.1 | IOC store, CDB list generation/distribution, OTX feed | 6.0 | small |
| 6.2 | MISP (feed-only or server mode) | 6.1 | MISP stack ~2–3 GB RAM, or feed-only |
| 6.3 | VirusTotal (Wazuh integration + on-demand) | 6.0 | small |
| 6.4 | TI in console and incidents, retro-hunt | 6.1–6.3 | small |
| 7.0 | ML foundation: features, labels, ground truth, MLflow, eval harness | — | MLflow small |
| 7.1 | River HalfSpaceTrees: real-time anomaly score | 7.0 | small |
| 7.2 | River ADWIN: behavioural drift | 7.0 | small |
| 7.3 | River Adaptive Random Forest: online classification | 7.0 | small |
| 7.4 | XGBoost + SHAP: historical classifier with explanations | 7.0 | small |
| 7.5 | Sentence Transformers + Qdrant: similar incidents | 7.0 | Qdrant ~300 MB, model ~100 MB |
| 7.6 | NetworkX: event relationship graph | — | small |
| 7.7 | LangGraph + LLM: investigation agent | 6.x, 7.5, 7.6 | LLM via API (local LLM too heavy for the lab) |

MLflow (component 9) is set up in 7.0 so every model from 7.1 onward is tracked and
registered from the start.

If time runs short, the minimum demonstrable set is: 6.0–6.4 (MISP feed-only), 7.0, 7.1,
7.4, 7.5, 7.6. 7.2, 7.3 and 7.7 can then be reported as designed but partial.

---

## 4. Phase 6 — Threat intelligence (Wazuh-native first)

Wazuh 4.14.8 already has the building blocks; we extend them instead of rebuilding:
- **CDB lists + rules** (`<list field=... lookup=...>` in rule XML): constant-time
  IOC lookups inside analysisd, at decode time, in C. A match becomes a normal alert
  with a threat-intel rule group, so it flows through our pipeline, incidents,
  fingerprints and console with no new hot-path code.
- **`wazuh-integratord` integrations:** the built-in VirusTotal integration (FIM hash
  lookups, rate-limited) and custom integration scripts.
- **Active response:** later, for SOAR.

What ShadowTracer adds: pulling feeds (OTX, MISP) into CDB lists, distributing them to
every manager, hot reload, per-tenant private lists, expiry, retro-hunting new IOCs
against stored events in ClickHouse, and the console views.

Each step below is one prompt: build standalone, verify, integrate, verify again.

### 6.0 Alignment audit and design (no feature code)
Read the 4.14.8 source and docs (cite file and line) for: CDB list format, size
limits and lookup types; how lists are loaded and whether 4.14's ruleset hot reload
covers lists without a restart; how the cluster syncs lists from master to workers;
which decoded fields rules can match lists against; how a TI rule can match events
that no other rule matched; integratord's VirusTotal integration (trigger, rate
limits, output alert shape, rule ids); the custom integration interface; Wazuh's
documented OTX/MISP integration approaches and why per-event API calls would break the
throughput rule. Spike: a 100,000-entry CDB list, measure analysisd's ceiling with and
without it. Output: `docs/design/THREAT_INTEL.md` with the chosen design and where any
side consumer is still needed.

### 6.1 IOC store, list generation and distribution (+ OTX as first feed)
`ti-sync` service: pulls OTX pulses (incremental, key from a secret), normalises into
an IOC store in Postgres (type, value, source, confidence, tags, first/last seen,
expiry, tenant or global), generates CDB lists per type, plus the ShadowTracer TI rule
file (new files, ShadowTracer names), distributes to managers (cluster sync or Wazuh
API) and triggers reload. Atomic list swaps; never a half-written list.

### 6.2 MISP
Feed-only mode (public MISP-format feeds, no server) by default; server mode (MISP
container in a separate compose profile, PyMISP, `to_ids=true` attributes) when RAM
allows; tenant-private MISP instances produce tenant-private lists on that tenant's
dedicated manager only.

### 6.3 VirusTotal
Enable and adapt Wazuh's built-in integratord VirusTotal integration for FIM hashes
(per-tenant key, rate limit respected, output alert mapped into incidents). Add an
on-demand "check on VirusTotal" from the console with a cache and daily budget.
Hashes only, never file uploads.

### 6.4 Console and incidents
TI hits on incident detail with source and pulse/event reference; IOC browser; TI
source settings per tenant (admin only, audited); retro-hunt of newly added IOCs over
the last N days in ClickHouse (scheduled, bounded).

VERIFY for every step: known test IOC produces exactly one TI alert end to end; replay
adds no duplicate; expiry stops matches; tenant-private IOCs never match another
tenant; reload without losing events; hot-path throughput within 5%; analysisd ceiling
with real list sizes recorded; licence/terms of each source recorded with links.

---

## 5. Phase 7 — AI system

### 7.0 ML foundation (needed by everything else)

1. **Labels and ground truth.**
   - Analyst verdicts (true positive, false positive, benign) from the console,
     stored in Postgres with analyst and time; audited.
   - **Atomic Red Team on the Linux lab agents now** (the Linux part of 5D; the
     Windows part waits for the VM). Each run records technique id, agent, and time
     window. Alerts and incidents in that window become labelled positives.
   - Benign background traffic, including benign look-alikes (SSH typos, internal
     scans, admin cron jobs), so models aren't evaluated on an easy problem.
   - Labelled replay corpus, generated with a fixed seed and checksummed.
2. **Feature definitions** shared by training and serving (one module, causal
   features only: nothing from after an incident closes). Per-alert features for
   HST; per-incident features for ARF/XGBoost.
3. **Feature tables** in ClickHouse: `incident_features` (incident id, feature
   version, vector, label if known).
4. **MLflow:** tracking server + model registry in the lab (own Postgres database,
   local artifact volume, internal network only). Every trained model logs data
   version, feature version, metrics, and git commit. Serving loads models by
   registry stage ("Production"), never by file path.
5. **Evaluation harness:** time-based train / validation / test split, test set
   frozen and evaluated once per model version; thresholds chosen on validation only;
   baselines: rules only (rule level threshold) and frequency/rarity (from 5B).
   Metrics: recall, precision, false alerts per day, PR-AUC, time to detect.
6. **Model serving contract:** a model's output is a score with a reason, never a
   silent action. Scores are visible on alerts/incidents; nothing is suppressed or
   blocked automatically in this phase.

VERIFY: ART runs produce labelled incidents (counts per technique pasted); the corpus
regenerates with identical checksums; a dummy model registers in MLflow and the
serving code loads it by stage; the harness refuses to evaluate on an unfrozen test set.

### 7.1 River HalfSpaceTrees — real-time anomaly score

- `ml-scorer` side consumer, per-alert. One model per tenant, keyed internally by
  entity group (agent, user, source IP class) where data volume allows; warm-up period
  before scores are shown (same idea as the 5B rarity warm-up).
- Output: `ml_scores` (alert identity, model version, score, top contributing
  features). Incident score = max/mean of member alert scores.
- Checkpoints: periodic, explicit serialisation with a schema version (no bare
  pickle), restored on restart; replay-safe.
- Position honestly: an anomaly **score** that helps prioritise, not a detector.

VERIFY: scores appear within the latency budget; restart restores state; replay is
idempotent; evaluation vs rarity baseline on the 7.0 harness (report even if it
loses); consumer ceiling measured.

### 7.2 River ADWIN — behavioural drift

- `drift-monitor` periodic job (every minute) over ClickHouse hourly/minute rollups:
  per tenant and per agent: alert rate, distinct rules, distinct users, rule-level mix.
- ADWIN detects a change; output is a drift event with before/after values and the
  affected entity, shown in the console as "behaviour changed". Also used to flag when
  a model's input distribution drifts (triggers retraining review).
- No per-alert work at all.

VERIFY: a deliberate rate change on a lab agent produces exactly one drift event with
correct before/after values; a stable period produces none over a fixed window
(report the false-drift rate).

### 7.3 River Adaptive Random Forest — online threat classification

- Runs in the enrichment worker at incident close. Predicts a threat class (for
  example brute force, persistence, discovery, benign) from incident features.
- Learns online from new labels (analyst verdicts, ART runs) as they arrive;
  `learn_one` only on labelled incidents.
- Checkpointed and versioned in MLflow (explicit serialisation; if River state cannot
  round-trip safely, signed checkpoint with a key from a secret, verified before load).
- Compared against XGBoost (7.4) and the rules-only baseline.

VERIFY: prequential evaluation (predict then learn) on the harness, per-class
precision/recall; learning from a new verdict changes the next prediction; restart
restores state.

### 7.4 XGBoost + SHAP — historical classifier with explanations

- `trainer` job trains XGBoost offline on labelled incident features (7.0), with
  class weighting for imbalance, hyperparameters chosen on validation only.
  Registered in MLflow with metrics.
- Served in the enrichment worker at incident close: class + probability.
- **SHAP (TreeExplainer)** for each prediction: top features with direction, turned
  into plain-language reasons in the console ("score raised by: 47 failed logins in
  2 minutes; external source").
- Optional role: **false-positive triage** (score that an incident is benign) shown
  as a hint only, never auto-suppressing; must hold a recall floor chosen on
  validation if ever used to filter.

VERIFY: test-set metrics vs baselines with bootstrap confidence intervals; SHAP values
sum to the model output (additivity check); explanation latency per incident measured;
the console shows reasons for a real lab incident.

### 7.5 Sentence Transformers + Qdrant — similar incident retrieval

- At incident close, build a text summary from structured fields (rules, MITRE,
  actor class, target, counts, timing; no raw secrets) and embed it with a small
  open model (for example `all-MiniLM-L6-v2`; verify licence) on CPU, batched.
- Store vectors in Qdrant with payload: tenant_key, incident id, fingerprint,
  verdict, time. **Every query goes through one wrapper that always adds the
  tenant_key filter**; a test proves another tenant's incidents never return.
- Console: "Similar past incidents" on incident detail, with their verdicts and how
  they were resolved.
- Licences: Sentence Transformers (Apache 2.0) and Qdrant (Apache 2.0); verify the
  model's licence separately.

VERIFY: an incident from a repeated ART technique retrieves the earlier run's incident
in the top 5; cross-tenant query returns nothing; embedding throughput per incident
measured; Qdrant restart keeps data.

### 7.6 NetworkX — event relationship graph

- On-demand API: build a graph for an incident or campaign from ClickHouse/Postgres:
  nodes = hosts, users, IPs, processes, files, rules, IOCs; edges = observed
  relations with time. Bounded size (cap nodes and time window).
- Graph analytics: connected components, central nodes, shortest path between an
  external IP and a sensitive host, campaign links.
- Console: interactive graph view on incident and campaign detail.

VERIFY: graph for a known lab attack shows the expected chain; caps respected on a
large incident; response time measured; tenant isolation tested.

### 7.7 LangGraph + LLM — investigation agent

- Analyst-triggered, read-only. LangGraph workflow: plan -> call tools -> summarise.
  Tools: query alerts for an incident, get similar incidents (7.5), get the graph
  (7.6), TI lookup (6.x), get model scores and SHAP reasons (7.1–7.4), ATT&CK info.
- **Output:** an investigation summary with every claim linked to the tool result it
  came from, suggested next steps, and a confidence statement. No actions: SOAR comes
  later and will never be triggered directly by the agent.
- **Security:**
  - Log content is attacker-controlled. Everything returned by tools is data, never
    instructions; the agent has no tool that changes state, so injection cannot cause
    an action.
  - Tools run with the analyst's own tenant and role; no cross-tenant access.
  - Sending customer data to an external LLM is per-tenant opt-in, shown in the UI,
    and recorded in the audit log. Provider configurable (API or self-hosted).
  - Token and cost budget per tenant per day.
- Licence: LangGraph (MIT); LLM provider terms recorded.

VERIFY: on 5 lab incidents, the summary's facts all trace to tool outputs (manual
check, report the error count honestly); a prompt-injection string inside a log line
does not change the agent's behaviour or tool use; cross-tenant attempt refused; cost
and latency per investigation measured.

---

## 6. MLflow — model lifecycle (component 9)

Set up in 7.0, used by 7.1–7.5:
- Experiments per model; runs log data version, feature version, git commit,
  parameters, metrics and the evaluation report.
- Registry stages: Staging -> Production -> Archived. Promotion is a manual,
  audited admin action, only when the model beats its baseline on the frozen test.
- Serving reads the Production version; rollback = promote the previous version.
- MLflow runs on the internal network only (no host port in production) and is
  backed up with the other databases.

---

## 7. Report outline (what each phase contributes)

| Report section | Source |
|---|---|
| Threat intelligence integration | 6.0–6.3 VERIFY, TI hit screenshots, sync counts |
| ML methodology | 7.0 labels, corpus, harness, baselines |
| Real-time anomaly scoring | 7.1 results vs baseline |
| Drift detection | 7.2 detection and false-drift results |
| Classification and explainability | 7.3 vs 7.4 metrics, SHAP examples |
| Similar incident retrieval | 7.5 top-k results |
| Investigation graph | 7.6 graph screenshots |
| AI investigation agent | 7.7 traced summaries, injection test |
| Model lifecycle | MLflow registry screenshots |
| Throughput impact | per-phase gate results |
| Limitations and future work | null results, `OPTIMIZATION_BACKLOG.md` |
