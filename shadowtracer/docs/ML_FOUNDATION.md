# ML foundation (Phase 7.0)

What 7.0 builds, and the rules every model obeys. Code: `shadowtracer/ml/shadowtracer_ml/`,
tests: `shadowtracer/ml/tests/` (CI step "ml tests"). Everything runs in the **TEST tenant**
only, and every run, event, incident and label carries its source: `atomic_linux`,
`caldera`, `normal_activity`, `replay:<dataset>`, `analyst` or `ti_fp`.

ShadowTracer builds no tooling that runs attack activity. The owner runs Atomic Red Team and
Caldera and wraps each run with the recorder (section 2).

## 1. Services (`deploy/lab/docker-compose.yml`)

| service | what | memory |
|---|---|---|
| `mlflow` | MLflow 3.18 tracking + registry. Backend: its own Postgres database `mlflow` (role `mlflow`, PUBLIC revoked). Artifacts: volume `mlflow-artifacts`, served by the server (`--serve-artifacts`). Internal network only, no published port. `MLFLOW_SERVER_ENABLE_JOB_EXECUTION=false`: MLflow 3's job runner was OOM-killed at 512m | 512m |
| `ml-enricher` | Scores closed incidents (section 6) and runs the labeler every 5 min | 512m |
| `ml-activity` | Normal-activity schedule (section 3), every 20 min ±30 % | 128m |

`./ha.sh up` stops all three, as it does ti-sync and ti-matcher, so the "ha" profile stays
under the cap (DEV_SETUP.md memory table).

## 2. Recorder: `attack_runs` / `attack_run_steps`

`deploy/lab/st-record` (needs `shadowtracer/ml/.venv`, see section 10) writes the run window. It
never executes anything.

    ./st-record start --technique T1136.001 --agent agent-ubuntu-1 --tool atomic [--test "<atomic test name>"]
    ./st-record stop <run_id> [--aborted]
    ./st-record caldera --operation <id> --url http://<caldera>:8888   # API key: CALDERA_API_KEY
    ./st-record list

A row holds run id, tool (`atomic|caldera|normal|replay`), source, label (`attack`, or `benign`
for normal activity), technique, agent, start/end and status. A Caldera import creates one run per
operation and one `attack_run_steps` row per executed link (technique, ability name, agent, start
and finish). Commands are never stored. A run that executed nothing is set to `aborted` and is
never labelled.

## 3. Normal activity with look-alikes

`shadowtracer_ml/normal_activity.py` runs ordinary administration on `agent-ubuntu-1` that looks like
an ATT&CK technique. Each action is recorded as a `normal` run (label benign; the technique is the
one it resembles) and undone afterwards.

| action | resembles | what |
|---|---|---|
| service-account | T1136.001 | `useradd -r` a service account, then remove it |
| cron-maintenance | T1053.003 | add/remove a logrotate cron file |
| sudo-admin | T1548.003 | an admin runs `apt-cache` through a scoped sudo rule |
| ssh-typo | T1110.001 | two mistyped SSH logins |
| package-install | T1105 | install/purge a small package |
| bashrc-alias | T1546.004 | add/remove a shell alias |
| key-rotation | T1098.004 | an admin regenerates their own SSH key |
| sudoers-dropin | T1548.003 | delegate `apt-cache` to an ops group |

Realtime FIM on that agent (`entrypoint-agent.sh`, marker `shadowtracer-ml-fim`) covers the
account, sudoers, cron, systemd, profile and home paths these techniques touch.

## 4. Recorded public datasets

Never committed: they are downloaded to `/home/refat/st-data/datasets` by
`python -m shadowtracer_ml.datasets download splunk|evtx|otrf`.

| dataset | OS | log types | ATT&CK labels | size | licence | usable |
|---|---|---|---|---|---|---|
| Splunk attack_data | Windows, Linux | Windows Security/Sysmon/PowerShell/System as XmlWinEventLog, Linux auditd, Sysmon for Linux | per technique folder + YAML | >9 GB (Git LFS) | Apache-2.0 | yes. Windows XML is replayed. The Linux auditd samples decode but reach only level-0 rules (no Wazuh audit keys), so they are unused |
| OTRF Security-Datasets | Windows (mostly) | Security, Sysmon, PowerShell as NXLog JSON | metadata YAML `attack_mappings` | several GB | MIT | yes. JSON is rebuilt into event XML |
| EVTX-ATTACK-SAMPLES | Windows | EVTX | tactic folder only | ~280 files, 50 MB | GPL-3.0 | yes. **Internal training only, never redistributed** (owner decision) |
| AIT Log Data Set V2.0 | Linux | auth, syslog, apache, audit, ... | attack-step labels | 130.6 GB | CC BY-NC-SA 4.0 | **no** (non-commercial) |

**Injection point** (`shadowtracer_ml/replay.py`). Each event is sent to analysisd's queue socket
`queue/sockets/queue` (DEFAULTQUEUE, `src/headers/defs.h:120`), the same socket remoted forwards
agent events to, inside the test manager. remoted builds the agent header `[id] (name) ip`
(`src/remoted/secure.c`). A Windows agent's EventChannel event has queue char `f` (WIN_EVT_MQ,
`src/headers/mq_op.h`), location `EventChannel`, and the log
`{"Message": ..., "Event": "<Event ...>"}`, formatted by `win_format_event_string`
(`src/logcollector/logcollector.c:1139`, called from `read_win_event_channel.c:519`).
analysisd sends `f` to its EventChannel decoder (`src/analysisd/analysisd.c:1377`), and the
inherited Windows rules match as they would for a live agent.

- **Dedicated agents.** Each dataset gets its own registered agent `replay-<dataset>` (table
  `replay_agents`), so no incident mixes two datasets or a real host.
- **Timestamps.** Events are re-timed to now. The original timestamp stays in the event XML and,
  with the dataset id, ATT&CK label and line hash, in ClickHouse `ml_replay_events`.
- **Rate and memory.** ≤ 200 events/s. The replay aborts if host MemAvailable drops below 1.5 GB.
- **Serialized like the agent.** Every reader passes events through `agent_quotes`: attributes in
  single quotes, no raw `"`, as Windows' EvtRender writes them. analysisd parses the
  *JSON-printed* Event string (`decoders/winevtchannel.c:152-155`), so a `"` arrives as `\"` and the
  event is dropped. Only the first such failure is a warning; later ones are debug-only.
  - EVTX via python-evtx (double quotes) decoded 0 events until this was fixed. Those 10 runs are
    marked `aborted` and were replayed again.
  - 3,588 of 112,912 Splunk events (3.2 %) have a raw `"` in their text. They were dropped in the
    first pass, before this fix; the Splunk datasets were not replayed again (backlog D13).

    python -m shadowtracer_ml.replay --plan
    python -m shadowtracer_ml.replay --all [--only splunk:|otrf:|evtx:]

The datasets replayed and the alerts each produced are in section 11. Each training run also logs
the datasets it used, with their licences, as `datasets_used.json` in MLflow.

## 5. Labels (`ml_labels`, `shadowtracer_ml/labels.py`)

`ml_labels` holds one row per (incident, origin) with label, technique, source, run or dataset id,
origin and **confidence**.

- **attack_window / normal_window.** The incident must be on the run's agent and overlap
  `[start, end + 120 s]`. It must also show **activity from the run**: an alert inside the window
  that either matches the run's technique (parent id, or any Caldera step's technique) or comes
  from a rule that did not fire on that agent in the 24 h before the run.
  - Confidence is 0.9 for a technique match and 0.6 for a new rule only, multiplied by the share of
    the incident's alerts inside the window (floor 0.5 of that).
  - Background incidents in the window stay **unlabelled**.
- **dataset_label.** Incidents on a dataset's replay agent during its run get the dataset's label,
  with confidence 0.8, because recordings contain some unrelated host noise.
- **analyst_verdict.** Escalate → attack, false positive → benign, from these steps in order:
  1. Read from the audit log (`incident_triage:<action>`), and only from users with the analyst or
     admin role.
  2. Queued in `ml_verdict_reviews`.
  3. Used only after a second person approves (`labels review --approve ID --by NAME`; the
     reviewer cannot be the analyst).
  - Conflicting approved verdicts give no label.
  - Counts per analyst: `labels verdict-counts`.
- **ti_false_positive.** An incident whose TI match an analyst marked false positive → benign, 0.7.

Training uses one label per incident. Priority is analyst > run window > dataset > TI. Incidents
with conflicting labels are dropped, as are labels under 0.5 confidence.

## 6. Features (`shadowtracer_ml/features.py`, version `f1`)

One module serves both training and serving.

- **Time cut.** `compute(incident, alerts)` uses only alerts up to the incident's `closed_at`.
- **Storage.** ml-enricher stores each incident's features in ClickHouse `ml_incident_features`.
  Training reads those stored rows back (`from_row`) and never re-derives them.
  `model_input()` builds the DataFrame for both paths.
- **Content.** Counts and level mix, rule and group counts, duration and rate, distinct IPs and
  users, rarity, prior occurrences, TI confidence, correlation basis, and shares of 30 rule groups
  and 12 ATT&CK tactics.
- **No source-revealing features.** There is no agent id or name, tenant, node, location,
  dataset or run id, decoder, and no absolute time (hour, weekday, date): replays are re-timed and
  lab activity is scheduled. Three checks enforce this:
  - the module refuses to import if a feature name contains a forbidden word;
  - `test_feature_names_reveal_no_source` checks the names;
  - `test_features_do_not_change_with_source_fields_or_retiming` changes every source field and
    shifts all times by 1,234 days, and the features must stay identical.
- **Train/serve parity.** `tests/test_parity.py` checks that the serving path
  (`enrich.incident_features` → stored row) and the training path (`from_row`) give the model the
  same input. `evaluate.py parity` runs the same check on live stored rows.
- **Versioning.** Change `FEATURE_VERSION` whenever a feature's meaning changes.

## 7. Training, evaluation and promotion (`shadowtracer_ml/evaluate.py`)

| rule | where it is enforced |
|---|---|
| Split by **time** and by **group** (an attack/normal run or a replayed dataset). Groups are ordered by first close; the last 20 % go to test and the 15 % before them to validation. No run spans train and test | `group_time_split`; `test_split_is_by_time_and_no_group_spans_splits` |
| Test set fixed per evaluation and logged (`test_set.json`); it can be pinned with `--test-set` | `run`; `test_pinned_test_set_takes_whole_groups` |
| Cross-source evaluation: each source family is held out in turn | `cross_source`; `test_cross_source_holds_out_each_family` |
| Class imbalance: `class_weight="balanced"` | `make_estimator`; `test_evaluate_split_uses_class_weights...` |
| Metrics are recall, precision, PR-AUC and false alerts/day, never accuracy | `metrics`; `test_metrics_never_report_accuracy...` |
| Rule-level baseline (max rule level) for every model, on the same test set | `baseline_scores`, `evaluate_split` |
| Thresholds for model and baseline chosen on validation only | `choose_threshold` (validation arrays only) |
| Promotion only if the model beats the baseline (higher PR-AUC, recall not lower) on a test set with ≥ 5 of each class | `should_promote`; `test_promotion_requires_beating_baseline...` |
| Logged per run: seed, label snapshot hash, feature version, git commit, datasets used, test set, cross-source results, model card | `run` |
| Model card per model (purpose, data and sources, metrics, limits) | `model_card` → `model_card.md` artifact |

Models are logged as **models-from-code** (`serving_model.py`, no pickled classes). An
estimator, if present, is a joblib artifact.

## 8. Serving (`shadowtracer_ml/enrich.py`)

ml-enricher picks closed, unscored incidents (index `incidents_ml_unscored`). Only TEST-tenant
incidents closed since 2026-11-06 11:25 UTC (`ML_SINCE`, the 7.0 data start) are scored; older
ones are load-test traffic. For each incident
it:

1. computes features;
2. stores them, plus hourly per-feature n/sum/sum² in `ml_feature_stats`;
3. scores the incident with every model in `ML_SERVED_MODELS` at stage **Production**, reloaded
   every 5 min;
4. writes `ml_score`, `ml_reasons` (per model: score and top features), `ml_model` and
   `ml_scored_at`.

If no Production model exists, it leaves incidents for later. The dummy model
`incident-risk-dummy` (score = max level / 15) proves the path; it is the baseline itself and is
never "promoted" through the gate.

**Models never trigger actions.** Nothing reads `ml_score` to act. It is shown to analysts only.

## 9. Monitoring

- `/health/detail` → `ml` reports, per served model, the score distribution (deciles) over 24 h,
  the number scored, and incidents closed in the last hour still unscored.
- Input drift: `ml_feature_stats` (hourly n, sum, sum² per feature and version) is the hook the
  ADWIN detector reads in 7.2.

## 10. How to run

    cd shadowtracer/ml && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    .venv/bin/python -m pytest -q tests
    cd deploy/lab
    docker compose run --rm ml-enricher python -m shadowtracer_ml.evaluate register-dummy
    docker compose run --rm -e GIT_COMMIT=$(git rev-parse HEAD) ml-enricher python -m shadowtracer_ml.evaluate run
    ../../shadowtracer/ml/.venv/bin/python -m shadowtracer_ml.labels coverage   # from shadowtracer/ml, with .env sourced

## 11. Datasets used and coverage (2026-11-06)

Replayed through the test manager at ≤ 200 events/s. Each dataset has its own replay agent and
one run (EVTX: the second run, after the quoting fix). analysisd `events_dropped` stayed 0.
"incidents" counts the incidents on the dataset's agent since its run started; all are labelled
`dataset_label`. Licences: `splunk:` Apache-2.0, `otrf:` MIT, `evtx:` GPL-3.0 (internal
training only, never redistributed). Each MLflow training run also lists the datasets it used
(`datasets_used.json`) and its model card.

| dataset | technique | events | alerts | rules | level>=12 | incidents | labelled | top rules |
|---|---|---|---|---|---|---|---|---|
| splunk:T1136.001/atomic_red_team | T1136.001 | 6,391 | 347 | 18 | 123 | 2 | 2 | 92213×100, 92203×90, 92052×62, 92032×43 |
| splunk:T1003.001/atomic_red_team | T1003.001 | 7,960 | 601 | 15 | 233 | 1 | 1 | 92213×122, 92217×121, 92203×93, 92052×62 |
| splunk:T1021.002/atomic_red_team | T1021.002 | 65 | 10 | 3 | 0 | 1 | 1 | 92027×6, 92004×2, 92032×2 |
| splunk:T1027/atomic_red_team | T1027 | 6,235 | 355 | 12 | 133 | 1 | 1 | 92213×110, 92203×91, 92052×62, 92032×45 |
| splunk:T1053.005/atomic_red_team | T1053.005 | 6,277 | 358 | 12 | 129 | 1 | 1 | 92213×108, 92203×93, 92052×62, 92032×51 |
| splunk:T1059.001/atomic_red_team | T1059.001 | 21,926 | 6,705 | 17 | 6,544 | 2 | 2 | 92910×6363, 92213×152, 92070×36, 92106×32 |
| splunk:T1070.001/atomic_red_team | T1070.001 | 6,226 | 332 | 11 | 123 | 1 | 1 | 92213×102, 92203×90, 92052×62, 92032×44 |
| splunk:T1105/atomic_red_team | T1105 | 2,290 | 74 | 8 | 53 | 2 | 2 | 92910×50, 92106×8, 92004×5, 92032×5 |
| splunk:T1112/atomic_red_team | T1112 | 6,461 | 347 | 12 | 127 | 1 | 1 | 92213×106, 92203×90, 92052×62, 92032×43 |
| splunk:T1218.011/atomic_red_team | T1218.011 | 13,363 | 617 | 16 | 188 | 1 | 1 | 92217×181, 92213×103, 92203×93, 92910×63 |
| splunk:T1482/atomic_red_team | T1482 | 515 | 41 | 4 | 31 | 1 | 1 | 92910×30, 92004×5, 92032×5, 92213×1 |
| splunk:T1543.003/atomic_red_team | T1543.003 | 6,218 | 359 | 12 | 130 | 1 | 1 | 92213×109, 92203×93, 92052×62, 92032×50 |
| splunk:T1547.001/atomic_red_team | T1547.001 | 6,287 | 356 | 14 | 130 | 1 | 1 | 92213×106, 92203×93, 92052×62, 92032×43 |
| splunk:T1548.002/atomic_red_team | T1548.002 | 6,715 | 373 | 18 | 139 | 1 | 1 | 92213×106, 92203×91, 92052×62, 92032×45 |
| splunk:T1562.001/atomic_red_team | T1562.001 | 7,745 | 359 | 12 | 235 | 2 | 2 | 92910×202, 92052×53, 92032×41, 92213×26 |
| splunk:T1569.002/atomic_red_team | T1569.002 | 8,236 | 512 | 14 | 144 | 1 | 1 | 92213×123, 92217×120, 92203×94, 92052×63 |
| otrf:SDWIN-190301125905 | T1222.001 | 9,002 | 6,091 | 7 | 0 | 1 | 1 | 60011×2372, 61602×1997, 60102×955, 60014×341 |
| otrf:SDWIN-190301174830 | T1003.006 | 8,465 | 4,822 | 6 | 0 | 1 | 1 | 60011×3377, 61602×512, 60014×482, 60102×330 |
| otrf:SDWIN-190319020147 | T1069.001 | 884 | 724 | 6 | 0 | 1 | 1 | 61602×419, 60102×161, 61643×63, 60011×49 |
| otrf:SDWIN-190319020729 | T1087.001 | 1,907 | 1,763 | 6 | 0 | 1 | 1 | 61602×1106, 60102×348, 61643×160, 60011×87 |
| otrf:SDWIN-190319021158 | T1087.002 | 633 | 556 | 7 | 0 | 1 | 1 | 61602×350, 60102×79, 60011×56, 61643×49 |
| otrf:SDWIN-190319023812 | T1547.001 | 40,569 | 39,576 | 15 | 0 | 1 | 1 | 61602×17634, 60102×16463, 61643×2520, 60206×2352 |
| otrf:SDWIN-190319024742 | T1053.005 | 1,297 | 1,093 | 7 | 0 | 1 | 1 | 61602×605, 60102×203, 60011×149, 61643×86 |
| otrf:SDWIN-190319131123 | T1550.002 | 10,271 | 6,227 | 7 | 0 | 1 | 1 | 60011×3238, 60102×1647, 61602×564, 60014×462 |
| otrf:SDWIN-190319145126 | T1003.003 | 1,179 | 1,014 | 7 | 0 | 1 | 1 | 61602×494, 60102×269, 60011×124, 61643×70 |
| otrf:SDWIN-190403133337 | T1574.001 | 6,349 | 5,623 | 8 | 0 | 1 | 1 | 60102×2612, 61602×1784, 60011×522, 60206×373 |
| otrf:SDWIN-190518182022 | T1059.005 | 2,067 | 1,957 | 7 | 0 | 1 | 1 | 61602×1042, 60102×565, 61643×148, 60011×106 |
| otrf:SDWIN-190518184306 | T1546.003 | 79,896 | 79,233 | 13 | 0 | 1 | 1 | 61602×56502, 60102×12488, 61643×8070, 60206×1785 |
| otrf:SDWIN-190518200432 | T1055.003 | 5,898 | 3,887 | 7 | 0 | 1 | 1 | 60011×1819, 61602×1020, 60102×563, 60014×259 |
| otrf:SDWIN-190518201207 | T1069.002 | 1,749 | 1,582 | 6 | 0 | 1 | 1 | 61602×1037, 60102×240, 61643×148, 60011×108 |
| otrf:SDWIN-190518202151 | T1003.001 | 6,026 | 4,324 | 6 | 0 | 1 | 1 | 60011×2581, 60102×610, 61602×595, 60014×368 |
| otrf:SDWIN-190518210125 | T1021.002 | 7,504 | 6,955 | 8 | 0 | 1 | 1 | 61602×5182, 61643×739, 60102×489, 60011×410 |
| otrf:SDWIN-190518210652 | T1021 | 4,348 | 3,940 | 9 | 0 | 1 | 1 | 61602×2575, 60102×524, 61643×366, 60011×343 |
| otrf:SDWIN-190518211052 | T1021.003 | 32,706 | 32,347 | 8 | 0 | 1 | 1 | 61602×27198, 61643×3884, 60102×854, 60011×252 |
| otrf:SDWIN-190518211456 | T1021.006 | 2,744 | 2,544 | 8 | 0 | 1 | 1 | 61602×1445, 60102×606, 61643×206, 60011×170 |
| otrf:SDWIN-190518213907 | T1047 | 4,559 | 4,224 | 8 | 0 | 1 | 1 | 61602×2415, 60102×992, 61643×344, 60011×285 |
| otrf:SDWIN-190518221344 | T1055.001 | 12,200 | 11,301 | 7 | 0 | 1 | 1 | 61602×4655, 60102×4528, 60011×706, 61643×665 |
| otrf:SDWIN-190518224039 | T1069.001 | 4,570 | 3,784 | 7 | 0 | 1 | 1 | 61602×2254, 60011×681, 60102×374, 61643×321 |
| otrf:SDWIN-190518230752 | T1003.004 | 13,199 | 9,677 | 6 | 0 | 1 | 1 | 61602×4381, 60011×3203, 60102×885, 61643×625 |
| otrf:SDWIN-190518235535 | T1003 | 7,887 | 4,375 | 6 | 0 | 1 | 1 | 60011×3457, 60014×495, 61602×243, 60102×128 |
| otrf:SDWIN-190519005224 | T1049 | 5,047 | 4,442 | 8 | 0 | 1 | 1 | 60102×2684, 61602×713, 60011×488, 60206×383 |
| otrf:SDWIN-190625103712 | T1003.002 | 12,349 | 8,924 | 6 | 0 | 1 | 1 | 61602×4543, 60011×3111, 61643×648, 60014×444 |
| otrf:SDWIN-190625133822 | T1003.002 | 738 | 629 | 6 | 0 | 1 | 1 | 61602×407, 60011×82, 60102×63, 61643×57 |
| otrf:SDWIN-191027055035 | T1003.001 | 5,489 | 5,476 | 6 | 0 | 1 | 1 | 61602×4103, 60102×683, 61643×585, 60206×97 |
| otrf:SDWIN-191027223020 | T1218.004 | 1,730 | 1,725 | 5 | 0 | 1 | 1 | 61602×978, 60102×532, 61643×138, 60206×76 |
| otrf:SDWIN-191225045202 | T1112 | 1,635 | 1,508 | 6 | 0 | 1 | 1 | 61602×955, 60102×236, 61643×135, 60011×131 |
| evtx:AutomatedTestingTools | - | 698 | 592 | 16 | 11 | 2 | 2 | 92032×417, 92004×148, 62123×6, 62124×5 |
| evtx:Command and Control | - | 1,969 | 38 | 11 | 4 | 3 | 3 | 67027×17, 60106×3, 67022×3, 67028×3 |
| evtx:Credential Access | - | 29,853 | 116 | 30 | 6 | 3 | 3 | 60229×22, 60106×11, 61071×10, 60112×8 |
| evtx:Defense Evasion | - | 431 | 27 | 15 | 3 | 3 | 3 | 92200×4, 92106×4, 92052×2, 92154×2 |
| evtx:Discovery | - | 172 | 18 | 6 | 1 | 2 | 2 | 92106×7, 60106×3, 63103×3, 67017×2 |
| evtx:Execution | - | 541 | 203 | 11 | 7 | 2 | 2 | 60610×173, 92032×12, 61640×4, 92052×4 |
| evtx:Lateral Movement | - | 1,288 | 95 | 26 | 7 | 3 | 3 | 92106×12, 67027×10, 60106×9, 92032×9 |
| evtx:Other | - | 744 | 42 | 4 | 1 | 2 | 2 | 60011×36, 60014×4, 92052×1, 61618×1 |
| evtx:Persistence | - | 411 | 37 | 12 | 6 | 2 | 2 | 60229×18, 60121×3, 92032×3, 92217×2 |
| evtx:Privilege Escalation | - | 1,142 | 117 | 32 | 32 | 3 | 3 | 92213×18, 92052×18, 67027×9, 92206×6 |
| **total (56 datasets)** | | **443,056** | **273,354** | | | **75** | **75** | |

**Coverage per source** (`python -m shadowtracer_ml.labels coverage`). normal_activity counts the
look-alike techniques; the owner's Atomic Red Team and Caldera runs will add `atomic_linux` and
`caldera` rows.

| source | techniques run/replayed | produced alerts | labelled incidents | rules (count: first 12) |
|---|---|---|---|---|
| normal_activity | 7 (T1053.003, T1098.004, T1105, T1110.001, T1136.001, T1546.004, T1548.003) | 6 | 9 | 10: 5403, 550, 5501, 5502, 553, 554, 5710, 5901, 5902, 5903 |
| replay:evtx | 10 () | 10 | 25 | 52: 60011, 60014, 60104, 60106, 60109, 60110, 60112, 60118, 60121, 60154, 60229, 60610 |
| replay:otrf | 27 (T1003, T1003.001, T1003.002, T1003.003, T1003.004, T1003.006, T1021, T1021.002, T1021.003, T1021.006, T1047, T1049, T1053.005, T1055.001, T1055.003, T1059.005, T1069.001, T1069.002, T1087.001, T1087.002, T1112, T1218.004, T1222.001, T1546.003, T1547.001, T1550.002, T1574.001) | 27 | 30 | 13: 60011, 60014, 60102, 60206, 61102, 61110, 61602, 61643, 63102, 67003, 67010, 91809 |
| replay:splunk | 16 (T1003.001, T1021.002, T1027, T1053.005, T1059.001, T1070.001, T1105, T1112, T1136.001, T1218.011, T1482, T1543.003, T1547.001, T1548.002, T1562.001, T1569.002) | 16 | 20 | 26: 60144, 61618, 61627, 67027, 92004, 92027, 92032, 92036, 92041, 92052, 92057, 92070 |

**First evaluation (MLflow run `ee1ab872b01945b0bdb0bf4a1cb41e60`).**
- Data: 84 labelled incidents (9 benign normal activity, 1 TI false positive, 74 attack replays).
- Model on the test set: PR-AUC 0.992. Baseline: 0.981.
- **Not promoted.** The test set has 4 benign incidents, below the 5 the gate requires.
- **Known confound.** Every attack label is a Windows replay and every benign label is Linux
  activity, so OS-specific rule groups currently stand in for the source. The cross-source run
  shows it: holding out normal_activity leaves training with 1 benign incident. Data that breaks
  the confound is needed before any model can be trusted:
  - the owner's Linux Atomic Red Team and Caldera runs (attack on Linux);
  - Windows normal activity once the Windows VM exists (backlog D1).

**Agent ids are reused.** `agent-ubuntu-1` had ids 001-005 over a week of re-creations, and replay
agents took 002-005. The labeler therefore maps an agent name to the ids it had *during the run*
(±1 h), never a wider span. Verified: all run-window labels are on agent 001, and no incident has
conflicting labels. A temporary agent `st-xmltest` (058) was used to find the quoting issue and
removed again; its 3 test alerts are unlabelled.

---

# Phase 7.1

## 12. Task reframe: multi-class tactic classifier (`evaluate.py classify`)

The 7.0 binary "attack vs benign" incident model had an OS confound (every attack label was a
Windows replay, every benign label was Linux activity), so it could separate the classes on
OS-specific rule groups instead of on the attack. The task is reframed:

- **Primary (`evaluate.py classify`).** Multi-class: given an incident already judged an attack,
  predict its **ATT&CK tactic** (the tactic its alerts carry, from ClickHouse `events.mitre_tactics`).
  Trained on labelled attack incidents across OSes.
- **Secondary (`evaluate.py run`).** The binary attack-vs-benign logistic model is kept as a
  secondary experiment only. In production, attack-vs-benign stays with rules + HalfSpaceTrees
  (section 13) + rarity (5B), not a supervised binary model.
- **Sample size is distinct sources.** Class counts are counted by **distinct source windows /
  datasets**, never alerts or incidents (one dataset replayed once can emit thousands of alerts
  but is a single sample). A tactic with fewer than `MIN_SOURCES` (2) distinct sources is dropped.
- **OS-shortcut report** (`os_shortcut`): the OS × label contingency, with a verdict on whether a
  model could shortcut on OS. The 7.0 incident source-leak test is unchanged and still passes.
- **Promotion** of the tactic model requires ≥ 2 surviving classes, beating the majority-class
  baseline, no held-out source collapsing to chance, **and** the OS shortcut being absent.

## 13. Live anomaly scorer: `ml-scorer` (River HalfSpaceTrees)

A side consumer in its own group (`shadowtracer-ml-scorer`) on every tenant's alerts topic
(`ALERTS_TOPIC_PATTERN`) - **never the hot path**: read-only on alerts (its own Kafka credential,
mirroring ti-matcher), writes only its own ClickHouse table. One HalfSpaceTrees model per tenant,
warmed online.

- **Features** (`alert_features.py`, version `a1`, shared by scorer and offline eval). All in
  [0, 1], no source-revealing field (no agent id/name, tenant, node, manager, location, decoder,
  dataset, raw IP): rule level, rule groups feature-hashed to 12 buckets, time-of-day and
  day-of-week as cyclical sin/cos (a live stream's clock is real behaviour - the 7.0 ban on
  absolute time is about re-timed replays, a different module), the host's recent alert rate
  (EWMA), source-IP class (none/private/public), and first-seen flags for the (agent, user) and
  (agent, source-IP) pairs. State is **bounded**: per-agent LRU seen-sets (cap 512 each) and an
  LRU of at most 4096 agents, so memory has a hard ceiling. `local_rate` is the host's rate, not
  its identity.
- **Scoring.** Score (0-1, higher = more anomalous) then learn, so a point is judged against the
  stream so far. Below the per-tenant warm-up (`WARMUP` = 300 alerts) the score is withheld
  (`warm = 0`). Rows go to ClickHouse `ml_scores`, a ReplacingMergeTree on
  (tenant, cluster_node, alert_id, model_version): replaying the group after a restart overwrites,
  never duplicates. Offsets commit only after the batch is written (at-least-once + dedup).
- **Reasons.** Top features by deviation from the running per-feature mean - an approximation of
  "what was unusual", **not** an exact HST attribution (stated on the model card).
- **Checkpoint.** `hst.AnomalyModel.save_bytes` writes a versioned, validated envelope (a JSON
  header - format, River version, feature version, model version, n_seen - then the payload); it
  is **not a bare pickle**. On restart each tenant's model is restored; a header that disagrees
  (feature/algorithm/River-version change) is discarded and the model warms up again. Written
  atomically to the `ml-scorer-state` volume every 5 min.
- **Incident anomaly.** At incident close the enricher sets `incidents.ml_anomaly_score` = the MAX
  of the incident's alerts' warm scores, with that alert's reasons (`ml_anomaly_reasons`,
  `ml_anomaly_model`). Separate from the 7.0 `ml_score`. Both are advisory; **no model triggers an
  action.**
- **MLflow.** The model is registered once per start (`incident-anomaly-hst`) with its params and
  card. It runs live, not served by stage.
- `/health/detail` → `ml` → `anomaly`: scored count, mean and max per model over 24 h.

## 14. Data to break the OS shortcut (part B) - RESOLVED

Status 2026-11-07: the owner's Atomic Red Team runs landed (59 `done` atomic runs → 18
`atomic_linux` attack-window labels), so **attack data now spans both OSes** (Windows replays +
Linux ART). The remaining single-OS class is **benign, which is still Linux-only** (scheduled
normal activity on the one Linux agent). So the gap to fully close the shortcut is **Windows
benign** - exactly what BOTSv3's Windows Sysmon/WinEventLog provides. Breaking it needs benign
data on Windows. The two sources the plan named for cross-OS data both hit a wall:

- **Splunk attack_data Linux** (auditd, Sysmon-for-Linux). These decode but reach only generic
  rules in our ruleset - auditd → rule 3782 (level 0), `sysmon_linux` → rule 1002 - so they
  produce **no meaningful attack incidents** without extra decoders/audit-key rules (backlog D9,
  D15). Not usable as-is for Linux attack labels.
- **Splunk BOTSv3 Windows benign (done).** BOTSv3 (CC0, 320 MB, md5 `d7ccca99...`) ships as a
  pre-indexed Splunk app, but its Sysmon events are `XmlWinEventLog` stored as `<Event>` XML inside
  the buckets' `rawdata/journal.gz` - so **no Splunk was needed** (Option 1 simplified):
  `replay.iter_botsv3_sysmon` gunzips each journal and extracts the XML directly. 9,212 Sysmon
  events replayed on a dedicated agent (`replay-botsv3-sysmon`, OS Windows), 2,091 alerted
  (`windows_eventchannel`; rules 92032/92200/92213/...), labelled **benign background**
  (`dataset_label`, confidence 0.6). This gives the missing **Windows benign** class, so benign now
  spans Linux + Windows and the OS shortcut is broken on both sides (attack: Windows replays + Linux
  ART; benign: Linux normal activity + Windows BOTSv3). The classic `WinEventLog:*` text streams are
  not decodable by Wazuh and are skipped; `linux_secure` (sshd) is available for more Linux benign
  (not yet replayed).
- **Label ceiling (backlog D17).** BOTSv3 is a CTF capture, so a little real attack activity sits in
  the "benign" Sysmon (≈23 level-15 events of 2,091). They are labelled benign at low confidence
  (0.6); precise attack-window exclusion using the BOTSv3 answer key is deferred.
- **Splunk attack_data Linux / Sysmon-for-Linux decoder coverage** stays as backlog D15 (would let
  attack_data's Linux samples alert; also helps real Linux agents).

A model is still promoted only through its gate (section 7/12): more data lowers the confound but
the gates (beat the baseline, generalise across sources, no OS shortcut) are what decide promotion.

## 15. Future work

- **DARPA OpTC** (github.com/FiveDirections/OpTC-data): large (~1 TB), richly labelled Windows+Linux
  host telemetry (eCAR). Attractive for cross-OS attack labels, but the licence is unclear and the
  size is impractical for the lab. **Not downloaded.** Revisit only with a licence check and a
  selective-window extraction plan.
- Re-replay the 15 Splunk Windows datasets with the D13 quoting fix (3.2 % of their events were
  dropped before it); pending, low value until the corpus matters.

## 16. Phase 7.1 results (2026-11-07)

Data after the owner's Atomic Red Team runs (Linux attacks), the Windows replays, scheduled Linux
normal activity, and the BOTSv3 Windows-Sysmon benign replay:

- **OS shortcut: gone.** `evaluate classify` os_shortcut contingency - windows {attack 81,
  benign 1}, linux {attack 14, benign 12}, unknown {benign 1}: attack and benign now share both
  OSes, so a model can no longer separate them on OS. (ART supplied Linux attacks; BOTSv3 supplied
  Windows benign.) The 7.0 incident source-leak test still passes.
- **Tactic classifier (primary): not promoted.** 7 tactic classes kept (>= 2 distinct sources
  each); macro-recall 0.485, micro-accuracy 0.429. The gate blocks promotion because the held-out
  `atomic_linux` source scores 0 - it does not yet generalise across sources (too few distinct
  sources per class). Honest "thin data" outcome; the model card and class counts are logged.
- **Anomaly scorer (HalfSpaceTrees):** on the warm-scored labelled incidents, incident anomaly
  (max of alert scores) separates attack from benign about as well as, and on Windows better than,
  the 5B rarity and rule-level baselines - PR-AUC overall 0.817 vs 0.814 (rarity) / 0.804 (rule
  level); Windows subset 0.915 vs 0.794 / 0.771. Small sample (n=13 warm-scored labelled; most
  attack incidents predate per-tenant warm-up), reported as-is.
- **Scorer health:** 1 model (test tenant) warm (>300 alerts), ~14k scores, 0 restarts; dedup
  verified (rows == distinct identities after a restart); checkpoint restore confirmed.

## 17. Phase 7.2 — behavioural + model-input drift (River ADWIN)

`drift-monitor` (own service, every 60 s, off the hot path, **ClickHouse rollups only - 0 Kafka env
vars, cannot read an alert topic**) runs one River ADWIN per (entity, metric), LRU-capped, with a
**versioned/validated state envelope** (same shape as the HST checkpoint: a JSON header gates the
pickle, a format/River/drift-version mismatch discards the state and re-warms - never a bare pickle
load). Behaviour drift per (tenant, agent) from `events_hourly_rollup`; model-input drift per served
model from `ml_feature_stats`. Advisory only -> `drift_events`.

**ADWIN tuning.** `delta=0.2, clock=1, grace_period=5, min_window_length=3` - catches a 2-3 bucket
behaviour change with **0 false drifts** on a stable/noisy stream (the defaults, delta 0.002, need
~30 buckets). Measured: on a clean baseline ADWIN confirms a change on the **2nd elevated bucket**
(index 1), i.e. it waits for the change to persist one more bucket before firing.

**Real burst through the full pipeline.** A live SSH brute force on a lab agent (60 distinct
usernames) produced **62 `Invalid user` (rule 5710) alerts** that flowed agent -> manager -> shipper
-> Kafka -> writer -> ClickHouse in ~55 s and landed in the rollup as **`distinct_users = 64` for
that agent's current hour** (vs a single-digit recent baseline). Because the rollup dedups rows per
(rule, level) per hour, a same-rule brute force surfaces in `distinct_users`, not `alert_volume`. The
drift-monitor then found real drift events across the tenant's agents on real data (1,841 events,
e.g. agent 001 `distinct_users 64.5 -> 904`, load agents `~14 -> 156`).

**Detection delay (given hourly rollups).** change start -> drift event =
  (time for the change's hour bucket to close: 0-60 min, since only completed hours are processed)
  + (1 confirming elevated bucket for ADWIN: ~1 h)
  ≈ **1-2 h**. A single-hour transient burst is therefore an *anomaly* (caught per-alert by the 7.1
HST scorer), not a *drift*: the drift-monitor flags a behaviour change only once it persists past the
confirming bucket. This is deliberate - a drift event means "this agent's normal has shifted and
stayed shifted", and it never triggers any action or retrain.
