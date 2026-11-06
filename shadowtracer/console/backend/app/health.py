"""Dependency health checks (Step 5). Each check is a small, independently
callable function so the readiness endpoint's logic (call every check,
report per-dependency status) is trivial and each check is unit-testable
without going through HTTP.
"""

import datetime
import os
import sys

import clickhouse_connect
import httpx
from confluent_kafka import Consumer, ConsumerGroupTopicPartitions, TopicPartition
from confluent_kafka.admin import AdminClient, ConfigResource
from sqlalchemy import text
from sqlalchemy.orm import Session

# Phase 5.6 Item 1: same cross-package sys.path pattern
# attack_coverage.py already uses for shadowtracer_ingest.ruleset - one
# shared implementation of the TLS/SASL config block, never duplicated.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "ingest"))
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env  # noqa: E402

from .config import Settings


def check_postgres(db: Session) -> tuple[bool, str]:
    try:
        db.execute(text("SELECT 1"))
        return True, "ok"
    except Exception as exc:  # noqa: BLE001 - any failure means "not ready", report it
        return False, str(exc)


def check_clickhouse(settings: Settings) -> tuple[bool, str]:
    try:
        client = clickhouse_connect.get_client(
            host=settings.clickhouse_host, port=settings.clickhouse_port,
            username=settings.clickhouse_user, password=settings.clickhouse_password,
            database=settings.clickhouse_database, connect_timeout=3,
        )
        client.query("SELECT 1")
        client.close()
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def check_kafka(settings: Settings) -> tuple[bool, str]:
    try:
        admin = AdminClient({"bootstrap.servers": settings.kafka_bootstrap_servers, **kafka_client_config_from_env()})
        metadata = admin.list_topics(timeout=3)
        if not metadata.brokers:
            return False, "no brokers in cluster metadata"
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def clickhouse_replica_health(settings: Settings) -> dict:
    """Dead-letter-ClickHouse incident (2026-10-08): a replica stuck
    read-only or with an expired Keeper session (system.replicas'
    is_readonly/is_session_expired) silently degrades a table's
    durability - or a specific query's correctness, since a stale read
    replica is still reachable - with nothing in check_clickhouse (which
    only proves ONE host answers SELECT 1) ever noticing. Queries EVERY
    configured host individually (clusterAllReplicas needs the `default`
    user for inter-server auth, which the lab's user isn't - see the
    incident's own notes) for EVERY replicated table, not just
    dead_letter_events - the same table-by-table scope Step 1 of that
    incident's response used, since any replicated table can suffer this
    independently."""
    hosts = settings.clickhouse_hosts or [(settings.clickhouse_host, settings.clickhouse_port)]
    unhealthy = []
    per_host = {}
    for host, port in hosts:
        host_key = f"{host}:{port}"
        try:
            client = clickhouse_connect.get_client(
                host=host, port=port, username=settings.clickhouse_user,
                password=settings.clickhouse_password, connect_timeout=3,
            )
            rows = client.query(
                "SELECT database, table, is_readonly, is_session_expired, zookeeper_exception FROM system.replicas"
            ).result_rows
            client.close()
            tables = []
            for database, table, is_readonly, is_session_expired, zookeeper_exception in rows:
                entry = {
                    "database": database, "table": table,
                    "is_readonly": bool(is_readonly), "is_session_expired": bool(is_session_expired),
                    "zookeeper_exception": zookeeper_exception or None,
                }
                tables.append(entry)
                if is_readonly or is_session_expired:
                    unhealthy.append({"host": host_key, **entry})
            per_host[host_key] = {"ok": True, "tables": tables}
        except Exception as exc:  # noqa: BLE001 - an unreachable host is itself reported, not a crash
            per_host[host_key] = {"ok": False, "error": str(exc)}
            unhealthy.append({"host": host_key, "error": str(exc)})
    return {"healthy": not unhealthy, "unhealthy": unhealthy, "per_host": per_host}


def check_clickhouse_replicas(settings: Settings) -> tuple[bool, str]:
    report = clickhouse_replica_health(settings)
    if report["healthy"]:
        return True, "ok"
    return False, f"{len(report['unhealthy'])} unhealthy replica/table pair(s): {report['unhealthy']}"


def stuck_components(db: Session, threshold_seconds: int) -> dict:
    """Phase 5.6 closeout item 3: a writer/correlator consumer paused in
    its dead-letter retry-forever loop looks, from Kafka's own consumer-
    group APIs, exactly like one that's just processing slowly - lag
    goes up either way. component_retry_state (written directly by the
    stuck component itself - retry_state.py's mark_stuck/clear_stuck,
    called from writer.py's/consumer.py's on_retry callbacks) is the
    one place that actually distinguishes them: a row only exists while
    a retry is unresolved, and disappears the moment it succeeds.

    over_threshold, not just non-empty: a retry that resolves in a few
    seconds (a genuine transient blip) is normal and expected - this
    only alerts once something's been stuck long enough that it's
    unlikely to be anything but a real, persistent problem (a deleted
    topic, a revoked ACL)."""
    try:
        rows = db.execute(text(
            "SELECT component, group_id, partitions_paused, stuck_since, updated_at, last_error, "
            "EXTRACT(EPOCH FROM (now() - stuck_since)) AS stuck_seconds "
            "FROM component_retry_state ORDER BY stuck_since"
        )).mappings().all()
    except Exception as exc:  # noqa: BLE001 - a missing table (pre-migration) or DB hiccup must not crash /health
        return {"error": str(exc), "components": [], "over_threshold": [], "alert": False}

    components = [
        {
            "component": r["component"], "group_id": r["group_id"],
            "partitions_paused": r["partitions_paused"],
            "stuck_since": r["stuck_since"].isoformat(), "updated_at": r["updated_at"].isoformat(),
            "last_error": r["last_error"], "stuck_seconds": r["stuck_seconds"],
        }
        for r in rows
    ]
    over_threshold = [c["component"] for c in components if c["stuck_seconds"] >= threshold_seconds]
    return {
        "threshold_seconds": threshold_seconds,
        "components": components,
        "over_threshold": over_threshold,
        "alert": bool(over_threshold),
    }


def check_stuck_components(db: Session, threshold_seconds: int) -> tuple[bool, str]:
    report = stuck_components(db, threshold_seconds)
    if report.get("error"):
        return True, f"check skipped: {report['error']}"
    if report["alert"]:
        return False, f"{len(report['over_threshold'])} component(s) stuck >{threshold_seconds}s: {report['over_threshold']}"
    return True, "ok"


def readiness_report(db: Session, settings: Settings) -> dict:
    checks = {
        "postgres": check_postgres(db),
        "clickhouse": check_clickhouse(settings),
        "clickhouse_replicas": check_clickhouse_replicas(settings),
        "kafka": check_kafka(settings),
        "consumers_stuck": check_stuck_components(db, settings.stuck_retry_alert_seconds),
    }
    all_ok = all(ok for ok, _ in checks.values())
    return {
        "ready": all_ok,
        "checks": {name: {"ok": ok, "detail": detail} for name, (ok, detail) in checks.items()},
    }


def shipper_lag_per_node(settings: Settings) -> dict:
    """Polls each configured shipper's metrics HTTP endpoint (see
    shadowtracer/ingest/shadowtracer_ingest/metrics.py). Best-effort - an
    unreachable shipper is reported as unreachable, not a crash."""
    result = {}
    for url in settings.shipper_metrics_urls:
        try:
            resp = httpx.get(url, timeout=2)
            resp.raise_for_status()
            result[url] = resp.json()
        except Exception as exc:  # noqa: BLE001
            result[url] = {"error": str(exc)}
    return result


def _topic_retention_ms(admin: AdminClient, topic: str) -> int | None:
    futures = admin.describe_configs([ConfigResource(ConfigResource.Type.TOPIC, topic)])
    for _, future in futures.items():
        config = future.result(timeout=5)
        entry = config.get("retention.ms")
        return int(entry.value) if entry is not None else None
    return None


def writer_consumer_lag(settings: Settings) -> dict:
    return consumer_lag(settings, settings.writer_consumer_group)


def consumer_lag(settings: Settings, group: str) -> dict:
    """Total lag (log end offset - committed offset) for the writer's
    consumer group, summed across partitions, plus per-partition detail -
    and, for whichever lagging partition's oldest unconsumed message is
    OLDEST, how old it is as a fraction of the topic's own retention.
    Offset lag alone doesn't say how close a stalled consumer is to
    falling off the retention window and losing data outright - this
    does, which is what actually matters operationally."""
    try:
        admin = AdminClient({"bootstrap.servers": settings.kafka_bootstrap_servers, **kafka_client_config_from_env()})
        group_futures = admin.list_consumer_group_offsets(
            [ConsumerGroupTopicPartitions(group)]
        )

        results = {}
        for group_id, future in group_futures.items():
            try:
                group_result = future.result(timeout=5)
                consumer = Consumer({
                    "bootstrap.servers": settings.kafka_bootstrap_servers,
                    "group.id": "shadowtracer-console-lag-check",
                    # Read-only diagnostic snapshot - never commits
                    # anything, so it never needs Group Read permission
                    # on top of the Describe grant this group already has.
                    "enable.auto.commit": False,
                    **kafka_client_config_from_env(),
                })
                total_lag = 0
                partitions = []
                lagging = []  # (topic, partition, committed) for partitions with lag > 0
                for tp in group_result.topic_partitions:
                    low, high = consumer.get_watermark_offsets(TopicPartition(tp.topic, tp.partition), timeout=5)
                    committed = tp.offset if tp.offset >= 0 else low
                    lag = max(0, high - committed)
                    total_lag += lag
                    partitions.append({"topic": tp.topic, "partition": tp.partition, "committed": committed, "high_watermark": high, "lag": lag})
                    if lag > 0:
                        lagging.append((tp.topic, tp.partition, committed))

                # Separate pass (not interleaved with the watermark
                # queries above): assigns the consumer to each lagging
                # partition's committed offset and reads just that one
                # message to get its timestamp - the AGE of the oldest
                # thing not yet consumed. Needs real Read permission on
                # the topic (Describe alone can't fetch message content) -
                # caught on its own, separately from the lag/partitions
                # above, so a permission gap (or any other transient
                # failure) here degrades just this one group's age/
                # retention fields instead of losing every group's
                # total_lag too.
                oldest_age_seconds = 0.0
                lagging_topic = None
                age_error = None
                try:
                    for topic, partition, committed in lagging:
                        consumer.assign([TopicPartition(topic, partition, committed)])
                        msg = consumer.poll(5)
                        if msg is not None and msg.error() is None:
                            _, ts_ms = msg.timestamp()
                            age_seconds = max(0.0, datetime.datetime.now(datetime.timezone.utc).timestamp() - ts_ms / 1000)
                            if age_seconds > oldest_age_seconds:
                                oldest_age_seconds = age_seconds
                                lagging_topic = topic
                except Exception as exc:  # noqa: BLE001 - see comment above: degrade this group's age fields only
                    age_error = str(exc)
                consumer.close()

                retention_ms = _topic_retention_ms(admin, lagging_topic) if lagging_topic else None
                retention_seconds = (retention_ms / 1000) if retention_ms else None
                fraction = (oldest_age_seconds / retention_seconds) if retention_seconds else 0.0
                results[group_id] = {
                    "status": "ok", "total_lag": total_lag, "partitions": partitions,
                    "oldest_unconsumed_age_seconds": oldest_age_seconds if age_error is None else None,
                    "retention_seconds": retention_seconds,
                    "fraction_of_retention": fraction if age_error is None else None,
                    "alert": (fraction >= settings.lag_retention_alert_fraction) if age_error is None else False,
                    **({"age_error": age_error} if age_error is not None else {}),
                }
            except Exception as exc:  # noqa: BLE001 - one group's failure must not lose every other group's report
                results[group_id] = {"status": "error", "error": str(exc)}
        return results
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def dead_letter_counts_per_tenant(settings: Settings, window_hours: int = 24) -> dict:
    """No single event may stop the pipeline: counts dead_letter_events
    rows (shipper/writer/correlator - shadowtracer_ingest/dead_letter.py)
    in the last window_hours, per tenant. A ClickHouse-side count, not a
    component's in-process counter, since those don't survive a restart
    or aggregate across replicas - this is the one place that can
    actually answer "how many for tenant X".

    Alerts on VOLUME (total over settings.dead_letter_alert_threshold),
    not merely non-zero - a handful of dead-lettered events is expected
    background noise (a hostile scanner, a misconfigured one-off agent),
    not something worth paging anyone over; a tenant producing hundreds
    of them is a real signal something's actually broken upstream.

    uniqExact(source_location), not count(): dead_letter_events is a
    ReplicatedReplacingMergeTree keyed on (tenant_id, component,
    source_location) - see events_schema.sql's own comment - so a replay
    that re-dead-letters the same message inserts a real duplicate row
    that only disappears once a background merge collapses it. count()
    would inflate on every such replay until that merge happens;
    uniqExact over the identity is correct immediately, the same fix
    events_hourly_rollup already needed for the same reason (Phase 3
    follow-up 1).

    This function only ever COUNTS - nothing in this codebase lists
    individual dead_letter_events rows today. If one is ever added (an
    admin view of actual dead-letter envelopes, not just counts), it must
    use FINAL or argMax, never a plain SELECT - the same merge-timing gap
    applies to individual rows, not just counts:

        -- FINAL: simplest, forces the merge at query time.
        SELECT * FROM dead_letter_events FINAL
        WHERE tenant_id = {tenant:String} ORDER BY failed_at DESC LIMIT 50

        -- argMax: no FINAL, scales better on a large table - picks each
        -- identity's latest version explicitly instead.
        SELECT tenant_id, component, source_location,
               argMax(error, failed_at) AS error,
               argMax(raw_event_preview, failed_at) AS raw_event_preview,
               argMax(raw_event_size, failed_at) AS raw_event_size,
               argMax(raw_event_sha256, failed_at) AS raw_event_sha256,
               max(failed_at) AS failed_at
        FROM dead_letter_events
        WHERE tenant_id = {tenant:String}
        GROUP BY tenant_id, component, source_location
        ORDER BY failed_at DESC LIMIT 50
    """
    try:
        client = clickhouse_connect.get_client(
            host=settings.clickhouse_host, port=settings.clickhouse_port,
            username=settings.clickhouse_user, password=settings.clickhouse_password,
            database=settings.clickhouse_database, connect_timeout=3,
        )
        rows = client.query(
            "SELECT tenant_id, component, uniqExact(source_location) AS n FROM dead_letter_events "
            "WHERE failed_at >= now() - INTERVAL {window_hours:UInt32} HOUR "
            "GROUP BY tenant_id, component ORDER BY tenant_id, component",
            parameters={"window_hours": window_hours},
        ).result_rows
        client.close()
        by_tenant: dict = {}
        for tenant_id, component, n in rows:
            by_tenant.setdefault(tenant_id, {"total": 0, "by_component": {}})
            by_tenant[tenant_id]["total"] += n
            by_tenant[tenant_id]["by_component"][component] = n
        for tenant in by_tenant.values():
            tenant["over_threshold"] = tenant["total"] > settings.dead_letter_alert_threshold
        return {
            "window_hours": window_hours,
            "threshold": settings.dead_letter_alert_threshold,
            "alert": any(t["over_threshold"] for t in by_tenant.values()),
            "by_tenant": by_tenant,
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def last_event_time_per_tenant(settings: Settings) -> dict:
    try:
        client = clickhouse_connect.get_client(
            host=settings.clickhouse_host, port=settings.clickhouse_port,
            username=settings.clickhouse_user, password=settings.clickhouse_password,
            database=settings.clickhouse_database, connect_timeout=3,
        )
        rows = client.query("SELECT tenant_id, max(time) AS last_event FROM events GROUP BY tenant_id").result_rows
        client.close()
        return {tenant_id: last_event.isoformat() if isinstance(last_event, datetime.datetime) else str(last_event)
                for tenant_id, last_event in rows}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def clock_skew_per_node(settings: Settings, window_minutes: int = 60) -> dict:
    """Phase 5C Step 0b / 5C-1 follow-up: chrony now runs on every manager
    (`entrypoint-manager.sh`), but with `-x` - it cannot actually set the
    clock inside these containers (`adjtimex` needs CAP_SYS_TIME, not
    granted, confirmed directly) and every manager shares the one WSL2
    host kernel clock anyway (no per-container clock namespace), so
    inter-manager skew is ~0 here BY CONSTRUCTION regardless of what
    chrony measures - there is only one clock to measure, several times.
    This check exists for a real multi-host deployment, where neither of
    those things is true: each manager has its own clock, its own
    chrony/NTP client actually correcting it (no `-x` there), and nothing
    else today verifies they still agree.

    Reuses data every event already carries instead of adding a new
    manager-API client: `ingested_at - time` (writer-insert wall-clock
    minus the alert's own reported event time) is mostly real pipeline
    latency (shipper/Kafka/writer hops), NOT skew - reported as
    `median_latency_seconds` per node, informational only. The one
    unambiguous skew signal is a NEGATIVE value: ingestion happening
    BEFORE the event's own reported time is impossible unless that
    node's clock is ahead of the writer's - `clock_ahead_suspected` is
    only ever set from that, never from a large positive latency, which
    this check cannot distinguish from ordinary backlog.

    Directly relevant to the sequence-lateness-window default
    (sequences.py's SEQUENCE_LATENESS_SECONDS): that window is sized to
    absorb exactly this kind of cross-node timing slop, so an operator
    seeing `clock_ahead_suspected` here has the right place to look
    before assuming the window itself needs widening.
    """
    try:
        client = clickhouse_connect.get_client(
            host=settings.clickhouse_host, port=settings.clickhouse_port,
            username=settings.clickhouse_user, password=settings.clickhouse_password,
            database=settings.clickhouse_database, connect_timeout=3,
        )
        rows = client.query(
            "SELECT cluster_node, "
            "median(dateDiff('millisecond', time, ingested_at)) / 1000.0 AS median_latency_seconds "
            "FROM events WHERE ingested_at >= now() - INTERVAL {window:UInt32} MINUTE "
            "GROUP BY cluster_node",
            parameters={"window": window_minutes},
        ).result_rows
        client.close()
        return {
            node: {
                "median_latency_seconds": latency,
                "clock_ahead_suspected": latency < 0,
            }
            for node, latency in rows
        }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}


def ti_list_versions(db: Session) -> dict:
    """Phase 6.1a (THREAT_INTEL.md §4.16): which version of every ShadowTracer
    threat-intel file each manager node holds, written by the safe reload
    wrapper (shadowtracer/intel/shadowtracer_intel/safe_reload.py) after every
    distribution. Per tenant: each node's last result and the short checksum of
    each file. A tenant alerts when any node's last result is not ok/unchanged
    (warnings, errors, sync_timeout, rolled_back, rejected) or a worker holds a
    file whose checksum differs from its master's - that worker is matching
    against different intel than the rest of its cluster."""
    try:
        rows = db.execute(text(
            "SELECT tenant_key, node, role, path, sha256, entries, result, detail, checked_at "
            "FROM ti_list_versions ORDER BY tenant_key, role DESC, node, path"
        )).mappings().all()
    except Exception as exc:  # noqa: BLE001 - missing table (pre-migration) or DB hiccup must not crash /health
        db.rollback()
        return {"error": str(exc), "tenants": {}, "alert": False}

    tenants: dict = {}
    for r in rows:
        t = tenants.setdefault(r["tenant_key"], {"nodes": {}, "mismatched": [], "failed": [], "alert": False})
        n = t["nodes"].setdefault(r["node"], {
            "role": r["role"], "result": r["result"], "detail": r["detail"],
            "checked_at": r["checked_at"].isoformat(), "files": {},
        })
        if r["path"] != "*":
            n["files"][r["path"]] = {"sha256": (r["sha256"] or "")[:16] or None, "entries": r["entries"]}
    for t in tenants.values():
        masters = [n for n in t["nodes"].values() if n["role"] == "master"]
        master_files = masters[0]["files"] if masters else {}
        for name, n in t["nodes"].items():
            if n["result"] not in ("ok", "unchanged"):
                t["failed"].append(name)
            shas = {p: f["sha256"] for p, f in n["files"].items()}
            if n["role"] != "master" and shas != {p: f["sha256"] for p, f in master_files.items()}:
                t["mismatched"].append(name)
        t["alert"] = bool(t["failed"] or t["mismatched"])
    return {"tenants": tenants, "alert": any(t["alert"] for t in tenants.values())}


# Phase 6.2: the slowest a source of each kind refreshes on purpose (ti-sync FEEDS min_interval).
SOURCE_REFRESH_SECONDS = {"warninglist": 86400, "spamhaus_drop": 86400, "misp_feed": 3600, "certpl": 3600, "ip_list": 3600}


def ti_sources(db: Session, sync_interval_seconds: int = 900) -> dict:
    """Phase 6.1b (THREAT_INTEL.md §4.12): threat-intel feed staleness. A failed sync
    keeps the source's last good data, so the lists keep working - but the intel ages.
    A source alerts when its last attempt failed or its last success is older than
    three sync intervals (two days for the daily MISP warninglists), or it never
    succeeded. Disabled sources and manual (analyst-entered) sources never alert."""
    try:
        rows = db.execute(text(
            "SELECT name, kind, tenant_key, enabled, last_attempt_at, last_success_at, last_error, last_counts, "
            "EXTRACT(EPOCH FROM (now() - last_success_at)) AS age_seconds, "
            "(SELECT count(*) FROM ioc_sightings s WHERE s.source_id = ti_sources.id AND s.revoked_at IS NULL) AS live_iocs "
            "FROM ti_sources ORDER BY name"
        )).mappings().all()
    except Exception as exc:  # noqa: BLE001 - missing table (pre-migration) or DB hiccup must not crash /health
        db.rollback()
        return {"error": str(exc), "sources": [], "stale": [], "alert": False}
    sources, stale = [], []
    for r in rows:
        failing = r["last_error"] is not None
        # warninglists and Spamhaus DROP refresh daily by design (DROP's terms: at most once a
        # day), hourly feeds hourly; manual (analyst-entered) sources are not feeds
        limit = max(3 * sync_interval_seconds, SOURCE_REFRESH_SECONDS.get(r["kind"], 0) * 2)
        too_old = r["age_seconds"] is None or r["age_seconds"] > limit
        is_stale = r["enabled"] and r["kind"] != "manual" and (failing or too_old)
        if is_stale:
            stale.append(r["name"])
        sources.append({
            "name": r["name"], "kind": r["kind"], "tenant_key": r["tenant_key"], "enabled": r["enabled"],
            "last_attempt_at": r["last_attempt_at"].isoformat() if r["last_attempt_at"] else None,
            "last_success_at": r["last_success_at"].isoformat() if r["last_success_at"] else None,
            "age_seconds": r["age_seconds"], "last_error": r["last_error"], "live_iocs": r["live_iocs"],
            "last_counts": r["last_counts"], "stale": is_stale,
        })
    return {"sync_interval_seconds": sync_interval_seconds, "sources": sources, "stale": stale, "alert": bool(stale)}


TI_MATCHER_GROUP = "shadowtracer-ti-matcher"


def ti_matcher(db: Session, settings: Settings, behind_alert_seconds: int = 300) -> dict:
    """Phase 6.1c (THREAT_INTEL.md §3.1): ti-matcher's consumer lag and the IOC store
    version each instance has loaded per tenant. Detail only, never readiness: the
    matcher is off the hot path. A tenant alerts when its loaded version is behind the
    store for longer than behind_alert_seconds (a stuck reload)."""
    out = {"consumer_lag": consumer_lag(settings, TI_MATCHER_GROUP)}
    try:
        current = db.execute(text("SELECT version, changed_at, EXTRACT(EPOCH FROM now() - changed_at) AS age "
                                  "FROM ti_store_version")).mappings().first()
        rows = db.execute(text("SELECT instance, tenant_key, store_version, iocs, by_type, loaded_at "
                               "FROM ti_matcher_state ORDER BY tenant_key, instance")).mappings().all()
    except Exception as exc:  # noqa: BLE001 - missing table (pre-migration) or DB hiccup must not crash /health
        db.rollback()
        return {**out, "error": str(exc), "alert": False}
    behind = [f"{r['instance']}/{r['tenant_key']}" for r in rows
              if r["store_version"] < current["version"] and current["age"] > behind_alert_seconds]
    out.update({
        "store_version": current["version"], "store_changed_at": current["changed_at"].isoformat(),
        "loaded": [{**dict(r), "loaded_at": r["loaded_at"].isoformat()} for r in rows],
        "behind": behind, "alert": bool(behind),
    })
    return out
