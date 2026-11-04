#!/usr/bin/env python3
"""Phase 5.6 throughput baseline: a load generator for measuring current
capacity, not for changing any product behavior - see docs/THROUGHPUT_BASELINE.md
for what it was used to measure and how.

Draws realistic events from fixtures/alerts_sample.anon.jsonl: 3000 real
raw_event JSON lines sampled from the lab tenant's ClickHouse history
(varied agents/rules/IPs/users/sizes, not synthetic), anonymised by
anonymize.py - the raw export itself is gitignored. Every event
this script emits is tagged with --run-id (embedded in agent.id/agent.name
for JSON-mode targets, in the simulated username for syslog-mode targets)
so it can be found and cleaned up afterward without guessing.

Modes (--target):
  shipper   append JSON lines directly to an alerts.json file (shipper's
            own input - bypasses analysisd/the manager entirely).
  kafka     produce directly to a tenant's alerts Kafka topic (writer's
            and correlator's shared input - bypasses shipper entirely).
  syslog    send raw full_log text over UDP syslog to a Wazuh remote
            syslog listener (analysisd's input when there's no agent
            forwarding it - see docs/THROUGHPUT_BASELINE.md for the
            one-time <remote> block this needs on the target manager).

Rate control: a fixed target events/s, held by sleeping the remainder of
each 1-second tick after sending that tick's share - never a tight loop,
so the actual achieved rate (printed every 10s) is the real evidence for
"did we actually hit the target rate", not an assumption.
"""

import argparse
import json
import os
import random
import socket
import sys
import time

FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "alerts_sample.anon.jsonl")


def load_corpus(path=FIXTURES_PATH):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def tag_json_event(event: dict, run_id: str, seq: int) -> dict:
    """Returns a copy with agent identity rewritten to carry run_id - the
    one thing every cleanup query below keys on. Everything else (rule,
    data, decoder, full_log) stays as sampled, for realistic variety."""
    event = dict(event)
    event["agent"] = dict(event.get("agent") or {})
    # 50 distinct agents, not one: the Kafka key is agent.id, so a single id
    # would pin every event to one partition and one consumer replica.
    event["agent"]["id"] = f"load-{run_id}-{seq % 50}"
    event["agent"]["name"] = event["agent"]["id"]
    event["id"] = f"load-{run_id}.{seq}"
    return event


def tag_syslog_line(raw: dict, run_id: str, seq: int) -> str:
    """full_log for an sshd-shaped sample already looks like
    'Failed password for invalid user X from Y port Z ssh2' - splice the
    run_id into the username so Postgres/ClickHouse rows this produces
    are findable by actor_user LIKE 'load-<run_id>-%' afterward."""
    full_log = raw.get("full_log", "")
    user_tag = f"load-{run_id}-{seq % 50}"
    if " user " in full_log:
        prefix, _, rest = full_log.partition(" user ")
        _, _, after_user = rest.partition(" ")
        full_log = f"{prefix} user {user_tag} {after_user}"
    else:
        full_log = f"{full_log} load_tag={user_tag}"
    return full_log


def run_shipper(args, corpus):
    path = args.path
    seq = 0
    t0 = time.time()
    next_report = t0 + 10
    sent_since_report = 0
    interval = 1.0 / args.rate
    with open(path, "a") as f:
        while time.time() - t0 < args.duration:
            event = tag_json_event(random.choice(corpus), args.run_id, seq)
            f.write(json.dumps(event) + "\n")
            seq += 1
            sent_since_report += 1
            if seq % 50 == 0:
                f.flush()
            now = time.time()
            if now >= next_report:
                elapsed = now - t0
                print(f"[{elapsed:.0f}s] sent={seq} achieved_rate={sent_since_report/10:.0f}/s", flush=True)
                sent_since_report = 0
                next_report = now + 10
            next_send = t0 + seq * interval
            remaining = next_send - time.time()
            if remaining > 0:
                time.sleep(remaining)
        f.flush()
    print(f"DONE seq={seq} elapsed={time.time()-t0:.1f}s", flush=True)


def run_kafka(args, corpus):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shadowtracer", "ingest"))
    from confluent_kafka import Producer
    from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
    from shadowtracer_ingest.topics import alerts_topic_for_tenant

    topic = alerts_topic_for_tenant(args.tenant_key)
    producer = Producer({"bootstrap.servers": args.bootstrap, **kafka_client_config_from_env()})
    seq = 0
    delivered = 0
    failed = 0

    def on_delivery(err, _msg):
        nonlocal delivered, failed
        if err is not None:
            failed += 1
        else:
            delivered += 1

    t0 = time.time()
    next_report = t0 + 10
    sent_since_report = 0
    interval = 1.0 / args.rate
    while time.time() - t0 < args.duration:
        event = tag_json_event(random.choice(corpus), args.run_id, seq)
        key = event["agent"]["id"].encode()
        producer.produce(
            topic, key=key, value=json.dumps(event).encode(),
            headers=[("tenant_id", args.tenant_key.encode())],
            on_delivery=on_delivery,
        )
        seq += 1
        sent_since_report += 1
        producer.poll(0)
        now = time.time()
        if now >= next_report:
            elapsed = now - t0
            print(f"[{elapsed:.0f}s] sent={seq} delivered={delivered} failed={failed} "
                  f"achieved_rate={sent_since_report/10:.0f}/s", flush=True)
            sent_since_report = 0
            next_report = now + 10
        next_send = t0 + seq * interval
        remaining = next_send - time.time()
        if remaining > 0:
            time.sleep(remaining)
    producer.flush(30)
    print(f"DONE seq={seq} delivered={delivered} failed={failed} elapsed={time.time()-t0:.1f}s", flush=True)


def run_syslog(args, corpus):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    t0 = time.time()
    next_report = t0 + 10
    sent_since_report = 0
    # Only sshd-shaped samples (location == /var/log/auth.log) make sense
    # as raw syslog lines for this - everything else in the corpus is
    # JSON-shaped already-decoded data, not a plausible raw syslog input.
    sshd_corpus = [e for e in corpus if e.get("location") == "/var/log/auth.log" and e.get("full_log")]
    if not sshd_corpus:
        print("ERROR: no /var/log/auth.log samples in corpus", file=sys.stderr)
        sys.exit(1)
    interval = 1.0 / args.rate
    while time.time() - t0 < args.duration:
        line = tag_syslog_line(random.choice(sshd_corpus), args.run_id, seq)
        # Minimal RFC3164-shaped syslog: priority + timestamp + host + tag + message.
        ts = time.strftime("%b %d %H:%M:%S")
        packet = f"<86>{ts} load-test-host sshd[1]: {line}"
        sock.sendto(packet.encode(), (args.host, args.port))
        seq += 1
        sent_since_report += 1
        now = time.time()
        if now >= next_report:
            elapsed = now - t0
            print(f"[{elapsed:.0f}s] sent={seq} achieved_rate={sent_since_report/10:.0f}/s", flush=True)
            sent_since_report = 0
            next_report = now + 10
        next_send = t0 + seq * interval
        remaining = next_send - time.time()
        if remaining > 0:
            time.sleep(remaining)
    print(f"DONE seq={seq} elapsed={time.time()-t0:.1f}s", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", required=True, choices=["shipper", "kafka", "syslog"])
    p.add_argument("--rate", type=int, required=True, help="events/s")
    p.add_argument("--duration", type=int, required=True, help="seconds")
    p.add_argument("--run-id", required=True, help="tag embedded in every event, for later cleanup")
    p.add_argument("--path", help="shipper target: alerts.json path to append to")
    p.add_argument("--bootstrap", default="127.0.0.1:9094", help="kafka target: bootstrap servers")
    p.add_argument("--tenant-key", help="kafka target: tenant key (topic derived from it)")
    p.add_argument("--host", default="127.0.0.1", help="syslog target: destination host")
    p.add_argument("--port", type=int, default=5514, help="syslog target: destination UDP port")
    p.add_argument("--fixture", default=FIXTURES_PATH, help="corpus file (default: the anonymised fixture)")
    p.add_argument("--seed", type=int, help="fix the sample sequence, e.g. to A/B two fixtures")
    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    corpus = load_corpus(args.fixture)
    print(f"loaded {len(corpus)} corpus samples, run_id={args.run_id}, target={args.target}, rate={args.rate}/s, duration={args.duration}s", flush=True)

    if args.target == "shipper":
        if not args.path:
            p.error("--target shipper requires --path")
        run_shipper(args, corpus)
    elif args.target == "kafka":
        if not args.tenant_key:
            p.error("--target kafka requires --tenant-key")
        run_kafka(args, corpus)
    elif args.target == "syslog":
        run_syslog(args, corpus)


if __name__ == "__main__":
    main()
