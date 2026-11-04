# ShadowTracer throughput baseline (Phase 5.6)

> **Every number in this document is for ONE machine — the lab described in
> §1 — measured 2026-11-04.** It is a baseline of the current code, not a
> capacity promise. Nothing in the product was changed to produce it
> (measure only). Anything outside the measured range is labelled
> **estimate**.

**On this lab, ShadowTracer sustains ~100 events/s end to end (~8.6 million/day); the first bottleneck is per-event database round trips in the Kafka consumers on a single partition — the correlator (one Postgres transaction per alert) and the writer (mostly 1-row ClickHouse inserts at ~60–100 ms each) both saturate between 100 and 150 events/s.**

| Component (tested alone) | Sustained ceiling (events/s) | First symptom | Resource that ran out |
|---|---|---|---|
| Wazuh analysisd (test manager) | **~4,000** (4,000 held 120 s; 5,000 not) | `event_queue_usage` → 1.00, then `events_dropped` climbs (`/var/ossec/var/run/wazuh-analysisd.state`) | analysisd processing: ~3,800–4,300 processed/s flat, ~450–530% CPU for the manager container. Host CPU **not** exhausted (top: 37–87% idle) |
| Shipper (worker-test) | **~10,000** (10,000 held 180 s; 15,000 not) | shipper byte lag (alerts.json size − committed offset) grows | shipper's synchronous `producer.flush()` per ≤500-line batch (latency-bound; shipper ~82% of one core at 10k; Kafka 48% CPU) |
| Writer (2 replicas, 3 partitions) | **~100** (lag levels off at 3–4k); flat with lag <1.5k at **50**; saturated max ~110–120 | writer consumer-group lag grows (200/s: +75/s) | ClickHouse insert round trips: 94–99% of insert calls are **1-row** inserts at 67–99 ms avg; ClickHouse 140–214% CPU/node and Keeper 56–87% (idle baseline 12–52% / 5–9%). Parts stayed 36–67 (not a parts problem) |
| Correlator (2 replicas, 3 partitions) | **~200** (lag levels off at ~1.7k); saturated max ~210 | correlator consumer-group lag grows (400/s: +~190/s) | Postgres round trips: one transaction per alert, 458–506 tx/s, Postgres up to 90% CPU, **0 lock waits** |
| **End to end** (raw syslog → … → ClickHouse + Postgres) | **~100** (100 held 10 min, all lags flat; 150 and 500 not) | correlator and writer lag both grow at 150/s (correlator faster: +~64/s vs +~50/s) | the single partition one manager's syslog lands on (§7.3): correlator ~81–86/s and writer ~100/s once backlogged — Postgres and ClickHouse round-trip latency; no CPU, memory, disk or parts limit was hit |

Contents: 1 Lab · 2 Tooling · 3 Stage 1 analysisd · 4 Stage 2 shipper ·
5 Stages 3–4 writer and correlator · 6 End to end · 7 Findings (measured,
not fixed) · 8 Settings asked about · 9 Estimates · 10 Reproduce / cleanup ·
11 ClickHouse replication stall: investigation and repair.

---

## 1. The lab (this machine only)

```
$ nproc; grep -m1 "model name" /proc/cpuinfo; free -h; df -h /
12
model name	: AMD Ryzen 5 7600 6-Core Processor
               total        used        free      shared  buff/cache   available
Mem:            11Gi       5.8Gi       437Mi        97Mi       5.4Gi       5.5Gi
Swap:          3.0Gi       2.1Gi       944Mi
/dev/sdd       1007G  182G  774G  20% /
$ cat /proc/version
Linux version 6.18.54.1-microsoft-standard-WSL2 ...
$ find /mnt/c/Users -maxdepth 2 -iname .wslconfig     # → nothing: WSL2 defaults
$ docker info --format 'CPUs={{.NCPU}} Mem={{.MemTotal}}'
CPUs=12 Mem=12111888384
```

- **No `.wslconfig`** — WSL2 defaults: all 12 logical CPUs, ~11 GiB RAM.
  The host was already **2.1 GiB into swap with 5.5 GiB available before
  any load**; the whole 26-container lab (4 agents, 4 managers, 1 Kafka
  broker, 2 ClickHouse replicas + Keeper, Postgres, 2 writers, 2
  correlators, 3 shippers, 2 closers, 2 console backends, LB, Caddy) shares
  these 12 CPUs, so each "stage alone" number still competes with the idle
  rest of the stack.
- Per-container limits (`deploy/lab/docker-compose.yml`, `grep -n mem_limit`):
  kafka 768m (line 432), ch-keeper 256m (541), ch-clickhouse-1 2304m (563),
  ch-clickhouse-2 2304m (600), postgres 256m (634). **No CPU limits
  anywhere**; managers, shippers, writers, correlators have no memory limit
  (`docker inspect … NanoCpus=0 Memory=0`).
- Versions: Wazuh 4.14.8 fork (analysisd `event_threads=0`,
  `rule_matching_threads=0` = auto), ClickHouse 24.8.14.39, Kafka 3.9.0
  (single broker, SASL_SSL/SCRAM-SHA-256 on every client listener),
  PostgreSQL 16.15, confluent-kafka/librdkafka 2.15.1. Tenant topics have 3
  partitions; Kafka key = `agent.id`.
- Test tenant only: `6da85d3ba8d9b0974ea6d3e712575eca`
  (topic `shadowtracer.t.6da85d3b….alerts`, manager `shadowtracer-worker-test`).

## 2. Tooling (committed under `deploy/load/`)

| File | What it does |
|---|---|
| `fixtures/alerts_sample.anon.jsonl` | The committed corpus: 3,000 real `raw_event` rows sampled (read-only) from the lab tenant's ClickHouse history (`SELECT raw_event FROM shadowtracer.events WHERE tenant_id='eec7…bb72' ORDER BY rand() LIMIT 3000` → `fixtures/real_alerts_sample.jsonl`, **gitignored, never committed**), anonymised by `anonymize.py`. 3000/3000 valid JSON, 6 `location`s, 73 distinct `full_log` prefixes, 19 rule ids, ~2.1 KB avg. The baseline runs in §3–§6 used the raw export; §2.1 shows the anonymised one gives the same results. |
| `anonymize.py` | Replaces IPv4 with RFC 5737 addresses (same string length where possible), IPv6 with 2001:db8::/32, and hostnames, usernames and agent ids with same-length, same-shape pseudonyms, consistently across every field and inside `full_log`/`previous_output`. Policy prose under `rule.*`/`data.sca.*` is left alone (CIS numbers look like IPs). A built-in check fails if any original value survives (plain substring search), a field path changes, or the total size drifts ≥1%. |
| `generate_load.py` | Fixed-rate load at `--rate` events/s, `--run-id` tag in every event. `--target syslog` (raw sshd `full_log` over UDP to the manager), `shipper` (append to alerts.json), `kafka` (produce to the tenant topic). Events are paced evenly (`t0 + seq/rate`), not bursted — see §3.1 for why. JSON targets rotate 50 agent ids `load-<run>-<n>` (the Kafka key) so load spreads across partitions like real agents. Prints achieved rate every 10 s. |
| `sample_pipeline.py` | Read-only sampler, one line per interval: analysisd `.state` deltas, shipper byte lag, writer/correlator group lag on the test topic, topic ingress, ClickHouse InsertQuery/InsertedRows and active parts, Postgres tx/s and lock-waiters. |
| `skip_test_backlog.sh` | Between stages: stops writers+correlators, moves **only the test topic's** committed offsets for both groups to the high watermark, restarts them (approved by the owner for this run). Prints old → new offset per partition. |
| `e2e_step.sh` | One end-to-end step: syslog load + sampler + `docker stats` ×3 + latency percentiles + disk + dead letters + error log lines + restart counts. |

### 2.1 Anonymised fixture gives the same results (A/B, 2026-11-04)

Same step twice, back to back, with only the fixture changed:
`generate_load.py --target kafka --rate 100 --duration 120 --seed 42` (same
sample sequence), writers and correlators running, measured after both lags
drained.

| | raw export (`ab2-raw`) | anonymised (`ab2-anon`) |
|---|---|---|
| delivered | 12,000 / 0 failed | 12,000 / 0 failed |
| writer / correlator lag (every 15 s) | 224/124 342/158 361/344 339/143 159/190 184/122 281/111 → 0/0 | 237/151 129/126 287/93 153/100 116/109 267/224 160/132 → 0/0 |
| ClickHouse alerts (`uniqExact`) | 12,000 | 12,000 |
| distinct rules / agents | 19 / 50 | 19 / 50 |
| per-rule counts | 24010:3602 19008:3268 19007:3045 19009:1362 5710:301 502:70 503:66 … 5712:3 | identical, every rule |
| alerts with a source IP / distinct IPs / distinct users | 304 / 6 / 31 | 304 / 6 / 31 |
| `raw_event` bytes | 22,634,660 | 22,671,098 (+0.16%) |
| Postgres memberships / Σ alert_count / distinct correlation keys | 12,000 / 12,000 / 322 | 12,000 / 12,000 / 322 |
| incidents (open + closed) | 3,446 (1,402 + 2,044) | 3,157 (3,038 + 119) |

The incident totals differ because of the closer, not the fixture. The
corpus carries its original (October) timestamps, so the closer's
inactivity cutoff applies to these incidents while the run is still going.
It closed 2,044 of the first run's incidents and 119 of the second's, and an
alert whose incident was just closed starts a new one. The memberships,
counts and the 322 correlation keys are identical.

Test-only lab change (not committed, lost on recreate): a syslog listener
on the test manager so analysisd can be fed raw lines —
`<remote><connection>syslog</connection><port>5514</port><protocol>udp</protocol><allowed-ips>172.28.0.0/16</allowed-ips></remote>`
appended to `shadowtracer-worker-test`'s `/var/ossec/etc/ossec.conf`, then
`shadowtracer-control restart`.

## 3. Stage 1 — analysisd

Input: `generate_load.py --target syslog --host 172.28.0.14 --port 5514`.
Stats file cited: **`/var/ossec/var/run/wazuh-analysisd.state`** (fields
`events_received`, `events_processed`, `events_dropped`,
`event_queue_usage`, `event_queue_size='16384'`), plus
`/var/ossec/var/run/wazuh-remoted.state` (`discarded_count`, `queue_size`)
and the container's `/proc/net/snmp` UDP counters.

### 3.1 First attempt was a tooling artefact (kept for the record)

The first generator sent each second's events in one burst. At "500/s"
only 16,828 of 30,000 sent arrived; at "5,000/s" 46,998 of 300,000 — yet
analysisd showed `events_dropped='0'` and `event_queue_usage='0.00'`
throughout. The loss was in the kernel, before remoted:

```
$ docker exec shadowtracer-lab-shadowtracer-worker-test-1 cat /proc/net/snmp | grep -A1 ^Udp:
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors ...
Udp: 146611 0 423061 5932 423061 ...
$ docker exec … cat /proc/sys/net/core/rmem_default /proc/sys/net/core/rmem_max
212992
4194304
```

Fixed in the generator (even pacing). After the fix `RcvbufErrors` never
moved again (463860 before and after every run below). See §7.5 for what
this means for real bursty syslog senders.

### 3.2 Ramp under contention (writer/correlator running, 45 s steps)

| rate | events_received Δ | events_dropped | event_queue_usage at end |
|---|---|---|---|
| 500 | 22,509 | 0 → 0 | 0.00 |
| 1,000 | 44,999 | 0 → 0 | 0.00 |
| 2,500 | 112,499 | 0 → 0 | **0.51** |
| 5,000 | 219,424 | 0 → **141,070** | 0.54 |
| 10,000 | 448,073 | 145,990 → 531,617 | 0.82 |
| 20,000 | 861,129 | 531,617 → 1,322,376 | 0.80 |

Here analysisd queued from 2,500/s — but the writer/correlator (and the
ClickHouse/Postgres they drive) were working through the backlog this very
ramp created, on the same CPUs. So 3.3 is the isolated number.

### 3.3 Isolated (writer + correlator stopped, shipper running), `sample_pipeline.py --interval 15`

```
time     ad_recv/s ad_proc/s ad_drop/s ad_q
-- 4,000/s for 120 s
11:33:31 4002 3990 0 0.00
11:34:00 4001 4043 0 0.00
11:34:29 3929 3929 0 0.00
11:34:58 3692 3692 0 0.00
-- 5,000/s for 120 s
11:36:33 5001 4076 0    0.14
11:36:47 5427 4333 80   1.00
11:37:16 5002 3860 1142 1.00
11:38:02 4606 3800 806  1.00
-- 6,000/s
11:39:28 6316 4241 2005 0.91
11:40:43 6003 3973 2030 1.00
-- 8,000/s
11:42:12 8007 3773 4234 1.00
11:42:55 8003 3581 4423 1.00
```

2,000, 2,500 and 3,000/s (120–180 s each) were likewise `ad_proc = ad_recv`,
`ad_drop 0`, `ad_q 0.00`. UDP `RcvbufErrors` stayed 463860 throughout.
`top` inside the manager: `wazuh-analysisd` 160% at 2,000/s, 100% at
3,000/s, **480% at 4,000/s**, 450–473% at 5,000–6,000/s; host
`%Cpu(s) … 50.6 id` at 4,000/s.

**Ceiling: ~4,000 events/s.** Processing flattens at ~3,800–4,300/s
whatever the input; above that the 16,384-slot event queue fills in
~45 s and drops start. Nearly every sshd sample fires a rule, so alerts ≈
events (`alerts_written='532764'` vs `events_processed='532810'` after the
first ramp).

## 4. Stage 2 — shipper

Input: `generate_load.py --target shipper --path /alerts/alerts.json`, run in
a throw-away container from the shipper image as uid 999 with the test
manager's alerts dir mounted (the shipper's own mount is read-only).
Writers and correlators stopped. Lag = `stat -c %s alerts.json` −
`offsets.json["alerts.json"].offset` (bytes; ~2.1 KB per event:
20 events = 41,782 B).

```
rate    duration  shipper lag (bytes, every ~10–15 s)                         after stop
1,000   60 s      921769 1254303 462859 783567 1201727 567805                  0
2,500   60 s      1533254 2084969 2788747 967461 1940652 2806506               0
5,000   60 s      6267122 4937144 3036676 4913924 3089014 1762838              0
10,000  180 s     22032889 0 36751394 4248581 28712118 3516463 10470835
                  26752115 46995993 22288525 4035943 21247335                  0 (≤14 s)
15,000  120 s     9582604 5561942 100825551 88186200 192054251 193882492
                  246692098 277284016 151977420                                0 (after stop)
20,000  60 s      73035257 58406342 151139665 145336428 401402751 509600515     0 (after stop)
```

Topic ingress matched the input at ≤10,000/s (`topic_in/s` 9,041–11,331 at
10,000). `docker stats` at 10,000/s: shipper **82.25%**, Kafka 48.21%;
at 20,000/s Kafka 268.72%, 652 MiB / 768 MiB.

**Ceiling: ~10,000 events/s** (oscillating, no trend, for 3 min); at 15,000
the lag grows ~2 MB/s and keeps growing. The shipper produces a batch of
≤500 lines and then blocks on `producer.flush(30)` before reading the next
(`shipper.py:280`, flagged in its own `ponytail:` comment), so it is
latency-bound per batch rather than out of CPU or Kafka.

## 5. Stages 3–4 — writer and correlator (Kafka-direct)

Input: `generate_load.py --target kafka --tenant-key 6da85d3b…`, 50 rotating
agent keys (all 3 partitions used), 180 s per step. Stage 3: correlators
stopped. Stage 4: writers stopped. Offsets skipped to the end before each
stage.

### 5.1 Writer (Stage 3)

`sample_pipeline.py` writer lag (messages), every ~15 s:

```
25/s   207 356 490 468 402 352 617 588 847 712 485 379            → 0 after stop
50/s   396 650 1195 1152 763 627 1036 1222 1167 899 990 1437      → 245
100/s  1312 1937 2981 3621 2437 3342 3316 3199 3148 3760 3378 4413
200/s  2992 6017 6984 6962 8749 9747 10534 12527 12352 13300 15077 16127 16214
400/s  15680 21211 24375 28919 32852 38448 42425 45025 50100 53513 58646 61607 67226
```

Insert shape per step (ClickHouse node 1's `system.query_log`; node 2 got 0
inserts — both writers list `ch-clickhouse-1:8123` first):

```
SELECT countIf(written_rows<=2), countIf(written_rows>2), round(avg(query_duration_ms)), round(quantile(0.95)(query_duration_ms))
FROM system.query_log WHERE type='QueryFinish' AND query_kind='Insert' AND has(tables,'shadowtracer.events') AND event_time BETWEEN <step>
```

| input/s | 1-row inserts | 100-row inserts | % of calls that are 1-row | rows written ≈ (1-row + 100×batch) / 180 s | avg / p95 ms |
|---|---|---|---|---|---|
| 25 | 3,353 | 8 | 99.8% | 23/s | 70 / 105 |
| 50 | 3,411 | 44 | 98.7% | 43/s | 67 / 106 |
| 100 | 3,110 | 116 | 96.4% | 82/s | 83 / 139 |
| 200 | 3,029 | 179 | 94.4% | 116/s | 88 / 154 |
| 400 | 2,704 | 166 | 94.2% | 107/s | 99 / 185 |

(`written_rows` counts the events row plus the `events_hourly_rollup_mv`
row, so a 1-row insert shows `written_rows=2`.) The 1-row path runs at
~15–19 inserts/s however much traffic arrives — that is the cap.

`docker stats` mid-step: writer-1 10–23%, writer-2 8–18% CPU (the writers
wait); ch-clickhouse-1 172–214%, ch-clickhouse-2 142–210%, ch-keeper
56–87%, Postgres 2–7%. Idle baseline with writers and correlators stopped:
ch-clickhouse-1 15–52%, ch-clickhouse-2 12–17%, ch-keeper 5–9%. Active parts
of `shadowtracer.events`: 36–67 throughout (`system.parts … active`) — no
"too many parts" pressure.

Single-partition drain (the Stage 1 backlog, all `agent.id=000` → partition
2, one writer replica): 532,702 rows landed between `21:51:52` and
`23:23:14` UTC → **~97 rows/s**; in a 5-minute window of it, 2,949 1-row
inserts (avg 66 ms) vs 261 100-row inserts (avg 63 ms).

**Ceiling: ~100 events/s** (lag levels off at 3–4k ≈ 30–40 s of data);
**~50/s** with lag under 1.5k; saturated throughput ~110–120/s; 200/s
grows without bound.

### 5.2 Correlator (Stage 4)

Correlator lag (messages):

```
25/s   0 0 0 1 1 0 0 0 0 0 0 0
50/s   5 0 21 0 0 40 1 0 1 0 0 0
100/s  1 111 13 1 0 1 1 2 0 1 56 34 1
200/s  106 4 46 196 150 243 1177 1883 1563 1717 1750 1703           → 0 at once after stop
400/s  1484 4634 7406 9822 12749 15361 18621 21632 24908 27238 29890 32480 33509
       (after stop: 33509 → 30546 in 14 s ≈ 211/s drain)
```

Postgres (`pg_stat_database xact_commit+xact_rollback` delta, and
`pg_stat_activity WHERE wait_event_type='Lock'`):

| input/s | Postgres tx/s avg (max) | lock waiters | Postgres CPU | correlator-1 / -2 CPU |
|---|---|---|---|---|
| 25 | 117 (250) | 0 | 18.7% | 3.7% / 7.3% |
| 50 | 170 (260) | 0 | 34.4% | 4.0% / 26.4% |
| 100 | 296 (445) | 0 | 71.1% | 25.0% / 46.9% |
| 200 | 458 (583) | 0 | 89.8% | 50.2% / 50.7% |
| 400 | 506 (631) | 0 | 63.1% | 34.6% / 40.3% |

(idle `pg_tx/s` with nothing flowing: 1.) Each alert is one transaction
(`SELECT … FOR UPDATE` on the open incident, insert/update incident, insert
`incident_alerts`; `correlator.py:126`) plus an async Kafka commit per
message.

**Ceiling: ~200 events/s** (lag flat at ~1.7k); saturated ~210/s. Bound by
per-alert Postgres round trips, not locks.

## 6. End to end

Raw sshd syslog → test manager analysisd → alerts.json → shipper → Kafka →
writer (ClickHouse) and correlator (Postgres), everything running.
`../load/e2e_step.sh <rate> 600 e2e-r<rate>`; backlog skipped before each
step. Latency:

- **writer**: `dateDiff('millisecond', time, ingested_at)` over the test
  tenant's `agent_id='000'` rows whose alert `time` falls inside the step
  (`time` = analysisd's alert timestamp, `ingested_at DEFAULT now64(3)`
  on the ClickHouse server).
- **correlator**: `incident_alerts.created_at − alert_time`
  (`created_at server_default now()` in Postgres).

All containers share the host clock.

Steps run: **25, 50, 100, 150, 500** events/s, 10 min each. 100 was the
first requested step; it held, so 500 was run (clearly saturated → ramp
stopped there, 1,000+ not run), then 150 to bracket, and 25/50 to show
the flat region.

### 6.1 Lag trend per consumer group (`sample_pipeline.py --interval 30`, messages)

```
step  writer lag (every 30 s)                                          correlator lag
25    274 292 460 339 105 384 150 161 187 495 213 159 136 230 505 211   0 0 180 0 0 0 0 4 0 7 0 0 0 0 11 0
      471 252 353 525                → 0                                0 8 4 0 10    → 0
50    453 276 467 449 1007 1057 400 653 486 930 503 578 787 250 508    0 0 0 0 20 116 0 15 0 0 0 9 2 14 32
      685 281 566 635 426            → 0                                0 0 49 0 11   → 0
100   910 1186 1743 302 2024 986 1966 1167 1157 2480 1437 602 903      196 57 430 23 1340 1272 1039 1804 1314
      1358 1412 1375 1346 1275 1392 1420  → 0 within 30 s               2627 2191 1543 1284 724 356 1019 1378
                                                                        1166 1499 1598  → 37 → 0
150   2397 3763 5077 7594 8064 10614 11932 13193 14515 16881 18183     1327 3875 5739 7830 9682 12076 14121
      20506 21816 23111 24401 25757 27015 28397 28756 30196             16061 17731 20404 22046 24491 26449
                                                                        27952 29587 32037 33586 35292 36644 38353
500   11876 23374 34877 47374 59804 71410 83521 95628 107642 119003    11750 23889 35675 48584 61017 73219
      130445 142047 153375 164917 176106 187644 199074 212400          86224 98684 111300 123769 135435 147625
      224017 235178 241218                                              159762 172190 183651 196069 207829
                                                                        220906 233222 244860 251350
```

Analysisd (`ad_drop/s` 0, `ad_q` 0.00) and shipper (byte lag ≤ 424 KB,
back to 0 after every step) stayed flat at every step.

### 6.2 Per step

| step (ev/s) | lags | writer latency p50 / p95 / p99 (ms) | correlator latency p50 / p95 / p99 (ms) | writer inserts: 1-row / 100-row (% calls 1-row) | dead letters | error log lines | restarts |
|---|---|---|---|---|---|---|---|
| 25 | flat | 9,218 / 16,487 / 18,361 (15,000 rows) | 437 / 2,010 / 5,126 (15,000) | 5,814 / 87 (98.5%) | 0 | 0 | 0 |
| 50 | flat | 9,390 / 16,924 / 19,892 (30,000) | 448 / 2,364 / 5,395 (30,000) | 5,883 / 237 (96.1%) | 0 | 0 | 0 |
| **100** | **flat** (w ≤2.5k, c ≤2.6k) | **10,594 / 19,317 / 22,521** (60,000) | **13,062 / 25,256 / 27,714** (60,000) | 6,270 / 525 (92.3%) | 0 | 0 | 0 |
| 150 | **both grow** (w +~50/s, c +~64/s) | 140,190 / 219,765 / 223,194 (67,016 landed) | 169,693 / 282,135 / 287,982 (57,331) | 6,057 / 539 (91.8%) | 0 | 0 | 0 |
| 500 | **both grow** (w +~400/s, c +~420/s) | 266,903 / 510,843 / 538,400 (64,831 of 300,000 landed) | 281,983 / 536,795 / 562,159 (53,844) | 5,810 / 520 (91.8%) | 0 | 0 | 0 |

Latency counts are the rows that had landed when the step's query ran (one
minute after the step); for 150/500 the rest were still queued, so their
real latency is worse than shown. Insert counts: test-tenant inserts only
(`Settings['insert_deduplication_token'] LIKE '%6da85d3b…%'`), both
ClickHouse nodes summed. Restarts: `docker inspect --format
'{{.RestartCount}}'` unchanged for every pipeline container (worker-test
shows 7 from before this run; all others 0). Dead letters:
`shadowtracer.dead_letter_events` for the test tenant since step start.
Error lines: `docker logs --since <step start> | grep -ciE
'error|exception|traceback'` for shipper, both writers, both correlators.

Saturated throughput on the single partition (lag growth subtracted from
input): writer ~100/s (≈58–60k rows per 10 min at 150 and 500),
correlator ~86/s at 150 and ~81/s at 500. Writer rows at 150/500: 59,957 /
57,810 in 600 s.

### 6.3 CPU / RAM per container (`docker stats --no-stream` at 25/50/75% of each step; ranges)

| container | 25/s | 50/s | 100/s | 150/s | 500/s | memory (limit) |
|---|---|---|---|---|---|---|
| shadowtracer-worker-test (analysisd) | 2–3% | 4–7% | 11–13% | 19–26% | 55–68% | 404–509 MiB (none) |
| shipper-worker-test | 0.3–6% | 0.3–0.4% | 0.6–3.6% | 0.6–0.7% | 2–5% | 47 MiB (none) |
| writer (busy replica) | ≤6.6% | ≤18% | 5–18% | 7–17% | 12–18% | 50–90 MiB; 142–162 MiB at 500 (none) |
| correlator (busy replica) | 0.4–10% | 13–38% | 25–47% | 24–45% | 45–53% | 53–95 MiB; 150–177 MiB at 500 (none) |
| kafka | 2–9% | 3–9% | 5–54% | 9–34% | 10–94% | 547–638 MiB (768 MiB) |
| ch-clickhouse-1 | 12–103% | 20–142% | 74–128% | 96–162% | 133–160% | 1.27–1.72 GiB (2.25 GiB) |
| ch-clickhouse-2 | 6–111% | 12–180% | 78–102% | 88–141% | 151–176% | 1.17–1.81 GiB (2.25 GiB) |
| ch-keeper | 4–71% | 44–64% | 28–57% | 29–61% | 47–59% | 188–222 MiB (256 MiB) |
| postgres | 0.2–9% | 11–56% | 16–27% | 14–29% | 28–56% | 194–222 MiB (256 MiB) |

The second writer and correlator replica sat at ~0.1% throughout: every
syslog alert is `agent.id=000` → one partition (§7.3).

### 6.4 Disk growth per step (`e2e_step.sh` `disk()` before/after)

| step | alerts generated | manager alerts dir (alerts.json + alerts.log) | Kafka data dir | ClickHouse `events` active parts | Postgres DB |
|---|---|---|---|---|---|
| 25 | 15,000 | +23,795,667 B (1,586 B/alert) | +20,796,353 B | +873,766 B | +4,964,352 B (331 B/alert) |
| 50 | 30,000 | +47,591,479 B (1,586 B/alert) | +41,419,684 B | +1,754,082 B | +9,912,320 B (330 B/alert) |
| 100 | 60,000 | +95,427,919 B (1,590 B/alert) | −22,004,849 B (retention deleted old segments during the step) | +3,073,138 B | +19,881,984 B (331 B/alert) |
| 150 | 90,000 | +143,035,412 B | +118,188,417 B | +3,649,131 B (67k rows landed) | +18,980,864 B |
| 500 | 300,000 | +476,684,403 B (1,589 B/alert) | +369,070,539 B (1,230 B/msg) | +3,342,542 B (65k rows landed) | +17,850,368 B |

`du` could not read the manager's rotated-archive subdirectory
(`alerts-worker-test/2026`, owned by uid 999), so the alerts-dir figure is
the live files only. ClickHouse bytes are before background merges and
include the small background inserts of other tenants.

### 6.5 Result

**End-to-end sustained rate: ~100 events/s** — 100/s held for 10 min with
every lag flat (writer ≤2.5k, correlator ≤2.6k, analysisd and shipper ~0),
0 dead letters, 0 errors, 0 restarts. **Latency at 100/s: writer (alert →
ClickHouse row) p50 10.6 s / p95 19.3 s / p99 22.5 s; correlator (alert →
incident updated in Postgres) p50 13.1 s / p95 25.3 s / p99 27.7 s.** At
150/s both consumer lags grow without bound, so the ceiling is between 100
and 150/s; the correlator on one partition (~81–86/s once backlogged)
saturates slightly before the writer (~100/s).

## 7. Findings (measured; nothing changed — measure only)

1. **Writer: 1-row inserts dominate.** `writer.py` inserts complete
   offset-aligned 100-row buckets in one call and every row of an
   incomplete bucket on its own (`DEDUP_CHUNK_SIZE = 100`,
   `writer.py:434–468`). Its comment expects "a sustained burst … still
   gets full batch efficiency"; measured, even while draining a 400k
   backlog 92% of insert calls were 1-row, because consume batches
   (≤1,000 msgs / 2 s) are cut at arbitrary offsets and each cut leaves
   up to two partial buckets. Each insert into the replicated table
   costs ~70–100 ms (Keeper dedup + part commit), so the writer
   saturates at ~15–19 inserts/s ≈ 100–120 rows/s.
2. **Writer: a Postgres write per ClickHouse insert.** `clear_stuck()`
   (`retry_state.py`) runs `DELETE FROM component_retry_state` in its own
   transaction after every successful insert, including every 1-row
   insert — one extra Postgres round trip per insert on the hot path.
3. **One manager's syslog = one partition.** The Kafka key is
   `agent.id`; everything a manager ingests via syslog has
   `agent.id='000'`, so it all lands on one partition and is served by one
   writer and one correlator replica (Stage 1 backlog: partition 2 lag
   424,761, partitions 0/1 lag 0; writer-2 and correlate-2 idle). Adding
   replicas does not raise the end-to-end ceiling for a syslog-heavy
   manager.
4. **ClickHouse CPU follows insert count, not rows.** 25 events/s already
   drives ClickHouse to 140–200% CPU/node and Keeper to ~56% — the
   per-insert cost, not data volume.
5. **Syslog over UDP drops bursts in the kernel.** `net.core.rmem_default`
   is 212,992 bytes in the manager container; a burst of a few thousand
   datagrams overflows it (`RcvbufErrors` 423,061) before remoted reads
   anything, and neither remoted nor analysisd counts it.
6. **Writer latency floor ~9 s at any rate.** Median alert → ClickHouse
   row was 9.2 s at 25/s and 9.4 s at 50/s (§6): the writer only batches
   once enough rows are waiting, so a steady state with a few hundred
   messages of lag is where it settles.
7. **Memory headroom is thin even at low rates.** During the end-to-end
   steps Postgres reached 222 MiB of its 256 MiB limit, ch-keeper 222 /
   256 MiB, Kafka 638 / 768 MiB (§6.3), and the host itself was 2.1 GiB
   into swap before any load (§1). None of them hit the limit in these
   runs.
8. **Correlator slows once backlogged.** It kept up with 100/s on one
   partition, but processed only ~86/s at 150 and ~81/s at 500 once a
   backlog built (§6.2); Stage 1's single-partition drain was ~75/s.
9. **Pre-existing ClickHouse replication damage blocks every mutation.**
   Found during cleanup, not caused by this run: both replicas have had 7
   `GET_PART` entries in `system.replication_queue` since
   **2026-11-02 08:00 UTC** that can never succeed ("No active replica has
   part … or covering part"), retried 85k–276k times each, across
   `events`, `events_hourly_rollup`, `fingerprint_occurrences` and
   `dead_letter_events`. Every `ALTER … DELETE` on `events` since then
   (mutations 114–118 from 2026-11-03, and this cleanup's 119) sits at
   `parts_to_do=3`. Inserts and reads were unaffected, so none of the
   numbers above are. **Investigated and repaired afterwards — see §11.**

## 8. Settings asked about

**Shipper producer** (`shipper.py:181-192`; librdkafka `debug=conf` lists only
the non-defaults):

```
$ python -c "Producer({'bootstrap.servers':..., 'debug':'conf', 'acks':'all', 'message.timeout.ms':1200000}, logger=...)"
CONF ... request.required.acks = -1
CONF ... message.timeout.ms = 1200000
```

| setting | value |
|---|---|
| acks | all (-1) |
| message.timeout.ms | 1,200,000 |
| compression | not set → librdkafka 2.15.1 default `none` |
| linger.ms | not set → librdkafka default (5 ms per librdkafka docs) |
| batch.size / batch.num.messages | not set → librdkafka defaults (1,000,000 B / 10,000 per librdkafka docs) |
| application batching | ≤500 lines or 1 s (`BATCH_MAX_LINES`, `BATCH_MAX_SECONDS`), then a blocking `flush(30)` per batch |

The librdkafka default values are as documented, not printed by the
library; the `debug=conf` output only proves they are not overridden.

**Writer batch sizes actually achieved:** consume batches of up to 1,000
messages / 2 s (`BATCH_MAX_MESSAGES`, `BATCH_MAX_SECONDS`), but ClickHouse
inserts of **1 row (94–99.8% of calls)** or **exactly 100 rows** — see the
table in §5.1 and the end-to-end breakdown in §6.

**TLS/SASL effect on the writer ceiling: unmeasured.** Every Kafka client
listener is SASL_SSL (`KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=BROKER:SASL_SSL,CONTROLLER:PLAINTEXT,EXTERNAL:SASL_SSL`),
so a comparison run needs a new plaintext listener and a broker recreate —
not cheap, and a security change to the shared lab broker. Indirect
evidence that it would not move the writer number: writers sit at 8–23%
CPU while saturated, and 94%+ of their insert calls wait 67–99 ms on
ClickHouse; the shipper pushed 10,000/s through the same SASL_SSL broker.

## 9. Estimates (outside the measured range — not measured)

- **Days:** ~100 events/s ≈ 8.6 M events/day end to end on this lab; the
  measured stage ceilings would be ~345 M/day analysisd, ~864 M/day
  shipper — **estimate**, by multiplication only.
- **Varied-agent end to end** (traffic from many agents instead of one
  manager's syslog): bounded by the writer's 3-partition number, ~100–120/s,
  not much above the single-partition figure — **estimate**.
- **Disk per day at 100 events/s** (8.64 M alerts), from §6.4's per-alert
  growth: manager alerts files ~13.7 GB/day before rotation, Kafka
  ~10.6–12 GB/day before retention, Postgres ~2.9 GB/day before any
  closer/vacuum effect, ClickHouse ~0.45–0.5 GB/day before merges —
  **estimate**, linear extrapolation of 10-minute steps.
- **Different hardware / more replicas:** not measured. Because the writer
  limit is per-insert latency against a replicated table, more CPU alone
  is not expected to scale it linearly — **estimate**.

## 10. Reproduce / cleanup

```
cd deploy/lab
# one stage step
../load/generate_load.py --target kafka --tenant-key <test key> --run-id <id> --rate 100 --duration 180
../load/sample_pipeline.py --tenant-key <test key> --interval 15     # in parallel (env: see its docstring)
# between stages
../load/skip_test_backlog.sh
# end to end
../load/e2e_step.sh 100 600 e2e-r100
```

Every event carries its run id: `agent_id LIKE 'load-<run>-%'` for
Kafka/shipper-target events; for syslog-target events `agent_id='000'` on the
test tenant with the sshd user rewritten to `load-<run>-<n>`.

### Cleanup done after this run (owner-approved scope: benchmark rows only + Kafka test-topic records)

Scope: test tenant, created after `2026-11-03 21:40 UTC`. Verified
beforehand that every test-tenant event after that point is load-tagged
(81,693 `agent_id LIKE 'load-%'`, 771,444 `agent_id='000'` with the sshd
user rewritten to `load-<run>-<n>`, 1 "ossec: Manager started" from the
listener restart); test-tenant data from before it (verification
scripts, since 2026-10-10) was kept.

**Postgres — done** (one transaction, `ON_ERROR_STOP=1`):

```
=== before (test tenant, all time) ===      === after ===
 incidents          |  28022                  incidents          |   894
 incident_alerts    | 872389                  incident_alerts    |  6843
 campaigns          |    774                  campaigns          |    14
 campaign_incidents |   2328                  campaign_incidents |   242
 fingerprints       |    116                  fingerprints       |    31
 sequence_progress  |   1318                  sequence_progress  |   204
DELETE 2086 (campaign_incidents) · DELETE 760 (campaigns) · DELETE 865546 (incident_alerts)
DELETE 27128 (incidents) · DELETE 85 (fingerprints) · DELETE 1114 (sequence_progress updated since)
```

No pre-existing campaign or fingerprint had been updated by the run
(`created_at < T AND updated_at >= T` → 0 for both).

**Kafka — done.** All consumer groups were checked to be at the high
watermark first, then `AdminClient.delete_records` up to it:

```
shadowtracer.t.6da85d3b….alerts[0] low 0 -> 1823215 (deleted 1823215)
shadowtracer.t.6da85d3b….alerts[1] low 0 -> 2302212 (deleted 2302212)
shadowtracer.t.6da85d3b….alerts[2] low 0 -> 6238348 (deleted 6238348)
```

`du -sbc /var/lib/kafka/data/shadowtracer.t.6da85d3b….alerts-{0,1,2}`:
17,774,705,316 B before → 1,664,041,093 B after the broker's next
retention check (18:32:32). The remainder is each partition's active
segment, which Kafka never deletes; it goes once the segment rolls.

**ClickHouse — done (after the §11 repair).** Mutation `0000000119`
(`DELETE WHERE tenant_id='6da85d3b…' AND ingested_at >= '2026-11-03
21:40:00'`) had in fact been applied to every real part; it only showed
unfinished because of the phantom lost parts (§11). The repair finished
it and ran the rest (`deploy/lab/repair-ch-lost-parts.sh` step 7):

```
ok: benchmark events rows on shadowtracer-lab-ch-clickhouse-1-1 = 0
ok: benchmark events rows on shadowtracer-lab-ch-clickhouse-2-1 = 0
ok: benchmark fingerprint rows on …-1-1 = 0      (27,124 deleted)
ok: benchmark fingerprint rows on …-2-1 = 0
ok: load-* rollup rows on …-1-1 = 0              (19,944 deleted)
ok: load-* rollup rows on …-2-1 = 0
ok: test-tenant rollup identities == base identities = 6655
```

The test tenant's 2026-11 rollup partition was rebuilt from the restored
events by `events_hourly_rollup_mv` during the repair, so the planned
agent-000 rollup rebuild was not needed.

**Left in place by the owner's choice:** the test manager's
`alerts.json` (15.1 GB) and `alerts.log` (1.9 GB) — they rotate nightly —
and the test-only syslog listener on `shadowtracer-worker-test:5514/udp`
(§2; lost on the next container recreate).

## 11. ClickHouse replication stall: investigation and repair (2026-11-04)

### 11.1 What was stuck

`system.replication_queue`, both replicas, identical 7 entries, all
`type=GET_PART`, all `last_exception: Code: 234 … No active replica has
part X or covering part (NO_REPLICA_HAS_PART)`:

| table | part | create_time (UTC) | num_tries node1 / node2 |
|---|---|---|---|
| events | `24a53b97…_0_371_90_304` | 2026-11-02 08:00:44 | 265,710 / 279,261 |
| events | `24a53b97…_372_377_1` | 2026-11-02 08:00:44 | 265,778 / 279,297 |
| events | `a9b80bea…_0_251_44_147` | 2026-11-02 08:00:47 | 265,712 / 279,287 |
| events_hourly_rollup | `a9b80bea…_0_339_68` | 2026-11-02 08:00:46 | 262,149 / 276,278 |
| fingerprint_occurrences | `202611_0_205_31` | 2026-11-02 08:00:43 | 86,478 / 88,255 |
| fingerprint_occurrences | `202611_191_201_2` | 2026-11-02 08:00:43 | 86,477 / 88,254 |
| dead_letter_events | `202611_427452_439335_611` | 2026-11-02 08:00:47 | 260,955 / 270,867 |

`system.replicas`: both `is_readonly=0`, `active_replicas=2`, log
pointers equal; `lost_part_count` already 6 (events) / 10 (rollup) / 4
(fingerprints) / 37 (dead letters); node 2's
`last_queue_update_exception: Session expired`. `system.detached_parts`:
empty on both. Open mutations 114–119 on `events` all `parts_to_do=3`
(114–118 are verify-script tenant deletes from 2026-11-03).

### 11.2 Had the replicas diverged?

Per partition `count()` and `sum(cityHash64(toString(tuple(*))))` on both
nodes (the `toString` form because `events.envelope_version` is Nullable,
which makes a plain `cityHash64(*)` NULL):

- `events` (14 partitions), `dead_letter_events`, `sequence_firings`:
  identical.
- `events_hourly_rollup`: same row counts; raw aggregate-state bytes
  differ (merge order), finalized `uniqExactMerge` values identical
  (20,487 groups, same checksum).
- `fingerprint_occurrences`: **diverged** — node 1 had 4 rows node 2
  lacked (`closed_at` 2026-11-02 07:55:02 and 08:00:36; 2 real-tenant, 2
  test-tenant), i.e. written seconds before the crash below.

### 11.3 Root cause

1. **Unclean stop of the whole lab host** between 08:00:39 and
   08:06:09 UTC on 2026-11-02. ClickHouse (both nodes): last `text_log`
   line 08:00:37 / 08:00:39, next `Starting ClickHouse` 08:06:09, no
   `Received termination signal` in between. Postgres at the same moment:
   `database system was interrupted; last known up at 2026-11-02
   07:59:38 UTC` → `not properly shut down; automatic recovery in
   progress`. What killed the WSL VM / Docker engine is not recorded
   inside the VM (it has rebooted since).
2. **No fsync for parts.** `system.merge_tree_settings`:
   `fsync_after_insert=0`, `fsync_part_directory=0`,
   `min_rows_to_fsync_after_merge=0`,
   `min_compressed_bytes_to_fsync_after_merge=0`,
   `min_compressed_bytes_to_fsync_after_fetch=0` (ClickHouse defaults).
   Parts both replicas had just produced by merges came back as 0-byte
   files: `Part …/24a53b97…_0_371_90_304/ is broken … Cannot parse input:
   expected 'columns … Detaching broken part … (size: 0.00 B)`, plus
   `Detached 4 parts covered by broken part …`.
3. **ClickHouse's lost-part handling deadlocks on this shape.** Each
   replica queued a fetch for the merged part. The part-check thread then
   declines to declare it lost: `Found parts with the same min block and
   with the same max block as the missing part … on replica 02. Hoping
   that it will eventually appear as a result of a merge.` That merge can
   never be scheduled while the queued fetch claims the range — looped for
   two days. Every later mutation on these tables was applied to all real
   parts but stayed "unfinished" on the three phantom ones.
4. Contributing load: 31 leftover test databases
   (`shadowtracer_test_*`, `shadowtracer_dedupwindow_*`, ~210 replicated
   tables) on a 256 MiB Keeper; Keeper sessions expired at 07:49, before
   the crash.

### 11.4 Repair (supported SQL only, no Keeper edits)

No supported command drops a queue entry for a part no replica has
(`DROP PART` needs it locally; `RESTORE REPLICA` re-attaches data under
new block numbers). `ALTER TABLE … DROP PARTITION` removes the queue
entries covering its range, and the affected partitions were small, so
`deploy/lab/repair-ch-lost-parts.sh` did: pause the 11 services that write
to ClickHouse → copy each affected partition to scratch MergeTree tables
on node 1 (node 1 holds the 4 extra fingerprint rows) → verify → `DROP
PARTITION` (`replication_alter_partitions_sync=2`) → wait for queue and
mutations to clear → re-insert (`insert_deduplicate=0`; the MV rebuilt the
rollup) → verify both replicas → benchmark cleanup → restart services.

```
== 2. copy affected partitions to scratch
ok: copy of events (rows, checksum) = 8185 …
ok: copy of fingerprint_occurrences (rows, checksum) = 28027 17185028841659186104
ok: copy of dead_letter_events (rows, checksum) = 942692 1316478450179294041
== 4. queue and mutations must clear
ok: replication_queue entries (both nodes) = 0
ok: unfinished mutations = 0
== 5./6. restored and both replicas agree
ok: fingerprint_occurrences restored on node1 / node2 = 28027 17185028841659186104
ok: dead_letter_events restored on node1 / node2 = 942692 1316478450179294041
ok: fingerprint_occurrences node1 == node2 = [('202610',450,…),('202611',28027,17185028841659186104)]
ok: dead_letter_events node1 == node2 = [('202610',536,…),('202611',942692,1316478450179294041)]
ok: events_hourly_rollup finalized node1 == node2 = 15779 15762254842941809635
== 8. after
node1 queue 0 · node2 queue 0 · unfinished mutations 0
```

The script's `events` checksum was the NULL-producing form, so `events`
was re-verified afterwards with the NULL-safe one: node 1 == node 2 in
all 14 partitions, and the restored rows on node 1 equal the scratch copy
exactly (`8185  9428343029296360943` both). All 11 paused services came
back healthy; queue 0 on both nodes.

The scratch copy is still in `shadowtracer_repair` on node 1.

### 11.5 Not done (proposals)

- **Durability:** with fsync off, any host crash can lose the last
  minutes of merged parts on every replica at once (they run on the same
  disk). `fsync_part_directory=1` plus non-zero
  `min_compressed_bytes_to_fsync_after_merge`/`…_after_fetch` would close
  that; it costs write throughput, so it should be measured with the
  item-4 rerun, not switched blind.
- **Leftover test databases:** the 31 `shadowtracer_test_*` /
  `shadowtracer_dedupwindow_*` databases should be dropped and the suites
  that leave them behind should clean up.
