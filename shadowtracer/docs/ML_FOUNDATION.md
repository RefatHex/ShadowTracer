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

## 18. Phase 7.5 — similar past incidents (Sentence Transformers + Qdrant)

At incident close the ml-enricher builds a short text from the incident's **structured fields only**
(rule descriptions/groups, MITRE techniques+tactics, actor class internal/external, target class,
alert-count bucket, duration bucket, TI sources, YARA rule names, FIM path *classes*, analyst
verdict) - never raw full_log, usernames, IPs or hostnames: similarity is about attack **shape**,
and campaigns (7.6) already link the same attackers. The text builder is versioned (`TEXT_VERSION`)
and shared by the live path and the backfill. It is embedded once with **all-MiniLM-L6-v2** (CPU,
Apache-2.0; loaded once, batched, off the hot path - only closed incidents) and the 384-dim vector is
upserted to **Qdrant** (Apache-2.0; internal network, persistent volume, 384 MiB). `similar.py`.

Payload: tenant_key, incident_id, fingerprint, verdict, closed_at, model + text version. Every query
goes through `QdrantIndex`/`qdrant_similar`, which **always** adds the tenant filter; the console API
also tenant-scopes the Postgres detail join, so a cross-tenant id is 404 and a foreign vector never
surfaces (tested). Re-index on a model/text-version change (`ml_sim_text_version`); hourly
consistency purge deletes vectors whose incident was removed. model/version logged to MLflow.

API (analyst+): `GET /api/incidents/{id}/similar` → top-k with similarity, verdict and how each was
resolved. Console: a **Similar past incidents** section on the incident page.

Evaluation (`evaluate_similar.py`, precision@5 on ml_labels technique over the ART + replay pool,
K=5): embed **0.282** vs rule-group-Jaccard baseline **0.241** for technique (tactic 0.353 vs 0.315);
per source embed wins on splunk (0.192 vs 0.067), ties on atomic_linux (0.889), both fail on otrf
(diverse techniques). Per-OS collapses to "unknown" (replay agents have no os_family role tag). Lab
checks: a repeated SSH brute force retrieves 5/5 earlier brute-force incidents at 1.000; cross-tenant
query → 404; embedding ~33-82 ms/incident; Qdrant survives a restart (830 vectors kept); running
mem_limit 12,256 MiB (headroom 1,568 under the 13,824 cap). Screenshot:
`docs/report/7.5-similar-incidents.png`.

## 19. Phase 7.4 — XGBoost + SHAP historical classifier with explanations

A supervised classifier that labels a **closed** incident attack-vs-benign with a probability and
plain-language reasons, shown to analysts as an **advisory hint** at incident close.
`shadowtracer_ml/classifier.py` trains it; `xgb_serving_model.py` serves it; `reasons.py` turns SHAP
values into sentences. **It never triggers an action** — no suppression, auto-close or filtering.

**Training.** Same data discipline as the 7.0 logreg (`evaluate.py`, reused wholesale): split by
**time and group**, a **frozen/pinnable test set**, thresholds **and hyperparameters chosen on the
validation split only**, class imbalance via `scale_pos_weight`. On top of that, 7.4 adds:
- **fingerprint dedup across the split** — a replay re-run produces the same feature vector; those
  near-duplicates are collapsed to one (earliest-closed kept) so the same shape can't sit in both
  train and test. The count removed is reported and logged.
- **two baselines** beaten on PR-AUC: **rules-only** (max rule level) and **rarity** (rare_pattern).
- **bootstrap 95 % CIs** on every test metric (per-class precision/recall, macro-F1, PR-AUC).
- a **SHAP TreeExplainer additivity check** (`sum(shap) + base == model margin`), max abs error
  logged.

The model is persisted as **XGBoost native JSON/UBJ** — never a pickle, so loading an untrusted model
file cannot execute code. Registered in MLflow (`incident-classifier`) with the data/label snapshot
hash, feature version, git commit, hyperparameters, metrics and a model card; promoted to the
Production **stage** only if it clears the baseline+test-size gate (otherwise it is tagged
`experimental` and only served for the hint when explicitly promoted with `--promote-experimental`).

**Serving.** The ml-enricher loads it **by MLflow stage** (never a file path), refreshed every 5 min,
and scores each incident **at close**, off the alert hot path. It stores model version + class +
probability + SHAP reasons + the version's `experimental` flag into
`incidents.ml_reasons.models["incident-classifier:<v>"]` — the same per-incident, tenant-scoped
Postgres row the 7.0 score uses. **SHAP reasons carry no raw username, IP or hostname**: they can't,
because no identifier is a model feature (features are counts / rates / flags only), so `reasons.py`
is a closed vocabulary of phrases.

**Scoring window + backfill.** The daemon's enrich window start is **config, not a hardcoded date**:
`ML_SINCE` if set, else the **served model's MLflow registration time** (a model never auto-scores
incidents that closed before it existed), else the 7.0-data fallback. Older incidents are picked up
with a documented, idempotent backfill:

```
python -m shadowtracer_ml.enrich backfill --since 2026-11-06T00:00:00Z [--until <ISO>]
```

It re-scores every closed incident in the window with the current served models, paging by a
`(closed_at, id)` keyset cursor, and **overwrites each incident by id + model version** — safe to
re-run, no duplicate rows. (This is exactly how incident 394326, closed before the classifier's
registration, was scored for the report.)

API (analyst+): `GET /api/incidents/{id}/model-assessment` → class, probability, reasons, model
version, **`experimental`**; cross-tenant id → 404. Console: a **Model assessment** section on the
incident page carrying an **`experimental`** badge (from the served version's tag) next to *advisory
hint*, with the likely class, P(attack) and the top reasons.

**Results (TEST tenant, test set; thresholds + hyperparameters from validation only).**

212 labelled incidents → **71 near-duplicate fingerprints removed** → 141 kept (39 benign, 102
attack). SHAP additivity max abs error **1.2e-07**.

**Headline — cross-source generalization COLLAPSES.** Train on two source families, test on the
held-out third (`classifier.leave_one_source_out`): the model does **not** transfer. Every held-out
source collapses (`collapsed: [atomic_linux, normal_activity, replay, ti_fp]`):

| held-out source | test (benign/attack) | PR-AUC | macro-F1 | note |
|---|---|---|---|---|
| atomic_linux | 0 / 14 | — | 0.00 | held-out set single-class (all attack) |
| normal_activity | 39 / 0 | — | 0.00 | held-out set single-class (all benign) |
| replay | 1 / 88 | 0.982 | **0.011** | predicts ~everything benign — attack recall 0.0 |
| ti_fp | 1 / 0 | — | 0.50 | n=1 |

The root cause is **source/label collinearity**: each source family is almost single-class
(atomic_linux≈attack, normal_activity≈benign, replay≈attack), so holding one out leaves a
single-class test and strips the model of the only signal it had. Confirmed by SHAP — the top feature
by mean |SHAP| is **`alerts_per_min` (1.25, a source proxy)**, 2× the next, with `duration_log`
(another proxy) third:

| rank | feature | mean \|SHAP\| | source proxy? |
|---|---|---|---|
| 1 | `alerts_per_min` | 1.25 | **yes (volume)** |
| 2 | `g_windows` | 0.63 | no (attack shape) |
| 3 | `duration_log` | 0.15 | **yes (duration)** |
| 4 | `lvl_mid` | 0.13 | no |
| 5 | `t_privilege-escalation` | 0.03 | no |

So the model leans heavily on **how much/how long** (which tracks the recording harness) more than on
attack shape. **The group-stratified CV below (PR-AUC 0.994) is therefore IN-DISTRIBUTION and
OPTIMISTIC** — within the labelled set source and label are nearly collinear, so a high CV score
mostly measures "can it separate the sources by volume," not "can it separate attack from benign in
general." Treat 0.994 as an upper bound, not expected field performance. The model stays
**experimental** and the promotion gate now also blocks on a cross-source collapse.

The frozen **time-split test set is single-class** (23 benign, **0 attack**) — benign `normal_activity`
incidents all close most recently, so the last groups in time are all benign. Attack-side metrics,
PR-AUC and the baselines are therefore **undefined on the time-split**, and the model **cannot clear
the promotion gate** (it is registered `experimental` and served only as a hint). Defined there:
benign precision 1.00, benign recall 0.52 [0.35, 0.74], macro-F1 0.34 [0.26, 0.43].

Because the time-split is degenerate on this data, a **group-stratified CV** (StratifiedGroupKFold,
k=5 — groups are `source-family | run/dataset`, so both classes are in every fold's test slice and no
run/replay near-duplicate spans folds) gives a leakage-controlled two-class read. **In-distribution,
and optimistic (see the headline above) — indicative only, not the promotion gate.** 95 % bootstrap
CIs:

| metric (group-stratified CV) | model | 95 % CI | rules-only | rarity |
|---|---|---|---|---|
| PR-AUC | **0.994** | [0.981, 1.000] | 0.905 | 0.835 |
| attack precision | 0.980 | [0.948, 1.000] | — | — |
| attack recall | 0.971 | [0.935, 1.000] | — | — |
| benign precision | 0.925 | [0.833, 1.000] | — | — |
| benign recall | 0.949 | [0.868, 1.000] | — | — |
| macro-F1 | 0.956 | [0.915, 0.990] | — | — |

So within the labelled distribution the model beats both baselines (PR-AUC 0.994 > rules 0.905 >
rarity 0.835), but that number is optimistic (headline above) and it **cannot be validated on the
strict frozen time-split** — hence experimental.

**Why incident 394326 scores only ~0.73 when in-distribution attacks score near 1.0 — it is out of
distribution.** 394326 is a real SSH brute force with **128,532 alerts** (P(attack) 0.73 under the
served v4; 0.56 under v3 — either way well short of the ~0.97 confidence the grouped CV gives
in-distribution attacks). On the two features the model leans on most, it sits **beyond the entire
training range** (`classifier.SOURCE_PROXY_FEATURES` check):

| feature (model's #1 and #3) | 394326 | train min | train p95 | train max | in range? |
|---|---|---|---|---|---|
| `n_alerts_log` (volume) | **11.76** | 0.69 | 8.81 | 11.28 | **no — above max** |
| `duration_log` | **6.80** | 0.00 | 5.06 | 6.09 | **no — above max** |
| `alerts_per_min` (proxy) | 8 630 | 1.0 | 6 213 | 11 905 | at the top (p95–max) |

Because the model's dominant signal is volume/duration and 394326 is larger and longer than anything
it trained on, it is **extrapolating**, so it lands well below the near-1.0 scores it gives
in-distribution attacks. This is the predicted behaviour of a model whose top features are source
proxies — and the reason it is a hint, not a detector.

**Limits.** The labelled set is dominated by one Linux agent and a handful of recorded Windows
datasets; benign examples come from very few distinct fingerprints, so after dedup the **test set is
small and the confidence intervals are wide** — the model is **experimental** and is shown only as a
hint. Labels come from run windows and dataset agents (background noise in a window can be
mislabelled). Not calibrated across tenants; trained on the TEST tenant only. Because it does not
reliably clear the baselines on this thin data, it must never be used to filter, suppress or
auto-close — it is an explanation aid, not a detector. Screenshot:
`docs/report/7.4-model-assessment.png`.


## 20. Phase 7.3 — River Adaptive Random Forest online classifier

An **online** counterpart to the 7.4 XGBoost model (`shadowtracer_ml/online.py`). Same features
(`features.py`, shared), scored at incident close in the ml-enricher, **off the hot path**. Stored and
shown exactly like 7.4 — class, probability, model version, `experimental` — as a **second "Online
model (River ARF)" row** in the console's Model assessment panel. **Advisory only**: never suppresses,
auto-closes or blocks.

**What it learns from.** `learn_one` is called **only on LABELLED incidents** — analyst verdicts
(`origin=analyst_verdict`) and ART attack runs (`origin=attack_window`). It **never** learns from an
unlabelled incident or from its own predictions. Guard-rails, all enforced:
- **Audit.** Every learn is recorded in `online_learn_log` (analyst, time, incident, label, checkpoint
  version) before the offset of truth moves.
- **Four-eyes on verdicts.** A triage verdict becomes a label only after a *different* account approves
  the review. `labels review --approve … --by <reviewer>` refuses unless `<reviewer>` resolves to a real
  **`analyst`/`admin` user in that tenant** *and* is **not** the account that created the verdict
  (`labels.check_reviewer` → `four_eyes_ok` + role check; a bogus email, a `viewer`, or the creator is
  refused). See **Limits** for what `--by` does and does not authenticate.
- **Per-analyst rate cap.** At most `ONLINE_LEARN_CAP_PER_ANALYST_PER_HOUR` (default 20) analyst-verdict
  incidents learned per analyst per rolling hour, so one analyst can't flood the model. ART runs are not
  capped.
- **Signed checkpoints, never an unsigned pickle load.** River state is a pickle, so each checkpoint is
  **HMAC-SHA256 signed** with `ONLINE_MODEL_SECRET` and the signature is **verified before
  `pickle.loads` ever runs** — a tampered blob or signature, or a wrong/absent key, is **refused**
  (`load_checkpoint_bytes`). No secret → the online model is simply not served. Checkpoints are versioned
  in MLflow (`incident-online`, Production stage, always tagged `experimental`); the last
  `KEEP_CHECKPOINTS` (5) are kept.
- **One-command rollback.** `online rollback` promotes the previous checkpoint to Production and flags
  the rolled-back batch in `online_learn_log` so the reverted model never re-learns a bad verdict batch.

**The benign labels used here are TEST labels, not real analyst verdicts.** ART gives 18 attack labels
(all one class). To exercise the two-class learning loop, up to **14 ground-truth-benign test labels**
were created: `false_positive` verdicts raised by **test-admin** on 14 incidents that sit inside
recorded **normal-activity run windows** (routine `adduser`/`sudo`/`syscheck`/`dpkg` activity, agent
001, no attack-run overlap), then **reviewed and approved by a separate operator account**
(`report-analyst@test.lab`, four-eyes). They are recorded as *ground-truth-benign test labels (created
by test-admin, reviewed by report-analyst@test.lab)* — **not** real production analyst decisions.

**Results — a demonstration of the learning loop, NOT an accuracy claim** (2026-11-21). The 2-class
prequential evaluation (predict-then-learn, time order) runs over **32 labels (18 ART attack + 14 benign
test)**. With so few labels and a near-perfect source/label split it shows the *mechanics* of online
learning beating the rules baseline, not field accuracy. **In this 32-label stream label source and
class coincide — every attack comes from ART, every benign from normal runs — so the 2-class result
demonstrates the learning loop, not attack detection; the leave-one-source-out collapse below confirms
it.**

| metric (prequential, predict-then-learn, n=32) | online ARF | rules-only (max level ≥ 10) |
|---|---|---|
| attack precision / recall | 0.75 / 0.50 | — / 0.00 |
| benign precision / recall | 0.55 / 0.79 | 0.44 / 1.00 |
| macro-F1 | **0.624** | 0.304 |

The rules-only baseline (flag attack iff an alert reached level ≥ 10) calls *everything* benign here and
scores 0 on attack — the ARF's 0.624 macro-F1 is the learning loop earning its keep on this stream. (The
7.4 XGBoost model is a batch classifier, not an online predict-then-learn one, so it has no comparable
prequential number — see §19 for its leave-one-source-out results.)

**Leave-one-source-out collapses, as expected and reported.** The two source families are each
single-class on this data (`analyst` = 14 benign, `atomic_linux` = 18 attack), so holding one out leaves
a single-class training stream — `leave_one_source_out` reports both folds `skipped` / `collapsed`
rather than a misleading score. Honest limitation of the tiny label set, not a bug.

**The verdicts measurably reshaped the model (learning-loop demonstration).** Before the benign verdicts,
the attack-only checkpoint (v1) predicted `P(attack)=1.0` for *every* incident. After folding in the 14
approved benign verdicts (v2, Production), on the same incidents:

| incident | v1 (attack-only) P(attack) | v2 (after verdicts) P(attack) |
|---|---|---|
| benign 482815 (normal-activity window) | 1.00 | **0.39** → *likely benign* |
| attack 482932 (ART run) | 1.00 | 0.80 → *still attack* |

**Restart parity (signed-checkpoint reload).** Reloading v2 from its HMAC-verified MLflow checkpoint (a
cold restart) reproduces distinct, non-degenerate probabilities — attack 482932 → `P(attack)=0.80`,
benign 482815 → `P(attack)=0.39` (differ, neither pinned at 1.0). **Rollback** was exercised end to end:
`online rollback` moved Production v2 → v1 in one command and flagged the 14 learn rows so the reverted
model won't re-learn them; v2 was then restored as the live checkpoint.

**Memory headroom.** The online ARF adds a single small River forest to ml-enricher; steady-state
≈ 475 MiB / 1280 MiB limit (37 %, ~800 MiB headroom) with the online model served.

**Limits.**
- Tiny, source-segregated label set; benign examples are hand-made test labels on the TEST tenant only;
  not calibrated across tenants. Experimental, advisory, a hint — never a detector.
- **`--by` names the reviewer but does not *authenticate* them.** The `labels review --approve --by
  <email>` CLI trusts whoever has shell access: it checks `<email>` is a real analyst/admin ≠ the verdict
  creator (four-eyes on *identity*), but anyone on the host can pass any analyst's email. Real
  four-eyes **authentication** needs approval from the console with the reviewer's own logged-in session
  (the triage/review API already authenticates the caller). Tracked in `OPTIMIZATION_BACKLOG.md`.

Screenshot: `docs/report/7.3-online-model.png`.
