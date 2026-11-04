#!/usr/bin/env python3
"""Throughput-baseline sampler: prints one line every --interval seconds with
every lag/pressure signal docs/THROUGHPUT_BASELINE.md cites. Read-only.

Run from deploy/lab with the correlate venv and the lab .env loaded (needs
Kafka admin creds - same setup as verify-phase5b.sh):
  set -a; source .env; set +a
  KAFKA_SECURITY_PROTOCOL=SASL_SSL KAFKA_SASL_USERNAME=admin \
  KAFKA_SASL_PASSWORD="$KAFKA_ADMIN_PASSWORD" KAFKA_SSL_CA_LOCATION=$PWD/kafka-certs/ca.crt \
  ../../shadowtracer/correlate/.venv/bin/python3 ../load/sample_pipeline.py --tenant-key <key>

Columns (cumulative counters are printed as per-second deltas):
  ad_recv/s ad_proc/s ad_drop/s ad_q   analysisd .state (events_received/processed/dropped, event_queue_usage)
  ship_lag_b                          alerts.json size - shipper's committed byte offset
  w_lag c_lag                         writer / correlator group lag on the tenant's alerts topic (sum of partitions)
  topic_in/s                          tenant alerts topic high-watermark growth
  ch_ins_q/s ch_rows/s ch_parts       ClickHouse InsertQuery/InsertedRows (both replicas) and active parts of shadowtracer.events
  pg_tx/s pg_lockwait                 Postgres commits+rollbacks/s and backends waiting on a Lock
"""

import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shadowtracer", "ingest"))
from confluent_kafka import Consumer, ConsumerGroupTopicPartitions, TopicPartition  # noqa: E402
from confluent_kafka.admin import AdminClient  # noqa: E402
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env  # noqa: E402
from shadowtracer_ingest.topics import alerts_topic_for_tenant  # noqa: E402

MANAGER = "shadowtracer-lab-shadowtracer-worker-test-1"
SHIPPER = "shadowtracer-lab-shipper-worker-test-1"
CH_NODES = ["shadowtracer-lab-ch-clickhouse-1-1", "shadowtracer-lab-ch-clickhouse-2-1"]
PG = "shadowtracer-lab-postgres-1"
GROUPS = {"w_lag": "shadowtracer-writer", "c_lag": "shadowtracer-correlate"}


def sh(*cmd) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout


def analysisd():
    out = sh("docker", "exec", MANAGER, "cat", "/var/ossec/var/run/wazuh-analysisd.state")
    kv = dict(line.split("=", 1) for line in out.splitlines() if "=" in line and not line.startswith("#"))
    g = lambda k: float(kv.get(k, "'0'").strip("'"))  # noqa: E731
    return g("events_received"), g("events_processed"), g("events_dropped"), g("event_queue_usage")


def shipper_lag():
    off = json.loads(sh("docker", "exec", SHIPPER, "cat", "/offsets/offsets.json") or "{}")
    size = int(sh("docker", "exec", SHIPPER, "stat", "-c", "%s", "/var/ossec/logs/alerts/alerts.json").strip() or 0)
    return size - off.get("alerts.json", {}).get("offset", 0)


def clickhouse():
    q = ("SELECT sumIf(value, event='InsertQuery'), sumIf(value, event='InsertedRows') FROM system.events "
         "FORMAT TSV")
    ins = rows = 0
    for node in CH_NODES:
        a, b = sh("docker", "exec", node, "clickhouse-client", "--query", q).split()
        ins += int(a)
        rows += int(b)
    parts = int(sh("docker", "exec", CH_NODES[0], "clickhouse-client", "--query",
                   "SELECT count() FROM system.parts WHERE database='shadowtracer' AND table='events' AND active").strip())
    return ins, rows, parts


def postgres():
    env = ["env", f"PGPASSWORD={os.environ['POSTGRES_PASSWORD']}", "psql", "-U", os.environ["POSTGRES_USER"],
           "-d", os.environ["POSTGRES_DB"], "-tAF", " ", "-c"]
    q = ("SELECT (SELECT xact_commit + xact_rollback FROM pg_stat_database WHERE datname = current_database()), "
         "(SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock')")
    tx, lw = sh("docker", "exec", PG, *env, q).split()
    return int(tx), int(lw)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--tenant-key", required=True)
    p.add_argument("--bootstrap", default="127.0.0.1:9094")
    p.add_argument("--interval", type=float, default=10)
    p.add_argument("--duration", type=float, default=0, help="0 = until killed")
    args = p.parse_args()

    cfg = kafka_client_config_from_env()
    admin = AdminClient({"bootstrap.servers": args.bootstrap, **cfg})
    wm = Consumer({"bootstrap.servers": args.bootstrap, "group.id": "throughput-sampler", "enable.auto.commit": False, **cfg})
    topic = alerts_topic_for_tenant(args.tenant_key)
    parts = sorted(admin.list_topics(topic, timeout=10).topics[topic].partitions)
    tps = [TopicPartition(topic, p_) for p_ in parts]

    def kafka():
        high = {tp.partition: wm.get_watermark_offsets(tp, timeout=5, cached=False)[1] for tp in tps}
        lags = {}
        for col, group in GROUPS.items():
            res = admin.list_consumer_group_offsets([ConsumerGroupTopicPartitions(group, tps)])[group].result(timeout=10)
            lags[col] = sum(max(0, high[tp.partition] - tp.offset) if tp.offset >= 0 else high[tp.partition]
                            for tp in res.topic_partitions)
        return sum(high.values()), lags

    def snap():
        return time.time(), analysisd(), shipper_lag(), kafka(), clickhouse(), postgres()

    print("time ad_recv/s ad_proc/s ad_drop/s ad_q ship_lag_b w_lag c_lag topic_in/s ch_ins_q/s ch_rows/s ch_parts pg_tx/s pg_lockwait", flush=True)
    prev = snap()
    t_end = time.time() + args.duration if args.duration else float("inf")
    while time.time() < t_end:
        time.sleep(max(0, args.interval - (time.time() - prev[0])))
        cur = snap()
        dt = cur[0] - prev[0]
        r = lambda a, b: (a - b) / dt  # noqa: E731
        (_, ad, ship, (hw, lags), ch, pg), (_, ad0, _, (hw0, _), ch0, pg0) = cur, prev
        print(time.strftime("%H:%M:%S"),
              f"{r(ad[0], ad0[0]):.0f} {r(ad[1], ad0[1]):.0f} {r(ad[2], ad0[2]):.0f} {ad[3]:.2f}",
              ship, lags["w_lag"], lags["c_lag"], f"{r(hw, hw0):.0f}",
              f"{r(ch[0], ch0[0]):.1f} {r(ch[1], ch0[1]):.0f} {ch[2]}",
              f"{r(pg[0], pg0[0]):.0f} {pg[1]}", flush=True)
        prev = cur


if __name__ == "__main__":
    main()
