"""Core correlation logic (Phase 5A Step 1): groups alerts into
incidents, purely by the PostgreSQL state in `incidents`/`incident_alerts`
- no in-memory session state, since the Kafka partition a worker owns can
move to another worker at any rebalance (see module docstring in
run_correlator.py).

Session-window grouping: an alert joins an existing OPEN incident if it
shares that incident's (tenant_key, agent_id, correlation_key, basis) and
its timestamp falls within `session_gap_seconds` of the incident's
current [first_seen, last_seen] span - checked on both sides, not just
forward, so an alert that arrives late (out of order) but whose own
timestamp is still within the gap of the window still joins correctly.
Joining must also not stretch the incident's span past
`max_span_seconds` from whichever end is now furthest out - if it would,
a new incident is started instead, even though the key matches.
"""

import datetime
from dataclasses import dataclass

from sqlalchemy import select, text, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from .models import incident_alerts, incidents
from .sequences import DEFAULT_LATENESS_SECONDS, evaluate_sequences

DEFAULT_SESSION_GAP_SECONDS = 600
DEFAULT_MAX_SPAN_SECONDS = 4 * 3600
CAPPED_VALUES_LIMIT = 20


class UnparseableEvent(Exception):
    """A permanently malformed field (so far: a timestamp that isn't real
    ISO8601) - never worth retrying, since nothing about redelivering the
    same bytes makes them parse differently next time. Found the hard way
    (Phase 5A VERIFY): consumer.py originally treated every exception from
    process_event as transient and never committed the offset, so one bad
    timestamp wedged a partition in an infinite retry loop instead of
    being skipped and counted like any other malformed alert."""


@dataclass
class CorrelationResult:
    status: str  # "created" | "joined" | "duplicate" | "unkeyable"
    incident_id: int | None


def correlation_key_and_basis(event) -> tuple[str, str] | None:
    """Priority order: (agent, source IP), then (agent, user), then
    (agent, primary rule group - the first one, a deterministic choice
    since rule_groups preserves the order Wazuh's rule definition gives
    it). None if the alert has none of these fields - it genuinely can't
    be correlated into anything, by any basis."""
    if event.src_endpoint_ip:
        return f"{event.agent_id}|srcip:{event.src_endpoint_ip}", "source_ip"
    if event.actor_user:
        return f"{event.agent_id}|user:{event.actor_user}", "user"
    if event.rule_groups:
        return f"{event.agent_id}|rulegroup:{event.rule_groups[0]}", "rule_group"
    return None


def _parse_time(value: str) -> datetime.datetime:
    try:
        dt = datetime.datetime.fromisoformat(value)
    except ValueError as exc:
        raise UnparseableEvent(f"not a valid ISO8601 timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _cap_append(current: list[str], total: int, new_value: str, cap: int) -> tuple[list[str], int]:
    """Appends new_value to the capped sample array if it isn't already
    there and there's room, and bumps the total. The total counts every
    alert that carried a non-empty value for this field, so once the
    array is full (cap reached) it can keep climbing past `cap` while the
    array itself stops growing - the row's size has a fixed ceiling
    regardless of how many distinct values (10,000 source IPs in a scan,
    say) actually occurred."""
    if not new_value:
        return current, total
    if new_value in current:
        return current, total
    if len(current) < cap:
        return current + [new_value], total + 1
    return current, total + 1


def parse_alert_time(event) -> datetime.datetime:
    """Raises UnparseableEvent - consumers call this per message before a
    batch, so one bad timestamp is dead-lettered alone instead of failing
    the whole batch's transaction."""
    return _parse_time(event.time)


def _fresh_incident_state(incident_id, alert_time):
    return {
        "id": incident_id, "first_seen": alert_time, "last_seen": alert_time,
        "alert_count": 0, "max_level": 0, "rule_ids": [], "rule_groups": [], "mitre_ids": [],
        "source_ips": [], "source_ip_total": 0, "users": [], "user_total": 0,
    }


def process_batch(
    db: Session,
    events: list,
    session_gap_seconds: int = DEFAULT_SESSION_GAP_SECONDS,
    max_span_seconds: int = DEFAULT_MAX_SPAN_SECONDS,
    cap: int = CAPPED_VALUES_LIMIT,
    sequences: list | None = None,
    ch_client=None,
    clickhouse_database: str | None = None,
    sequence_lateness_seconds: float = DEFAULT_LATENESS_SECONDS,
    metrics=None,
) -> list[CorrelationResult]:
    """A poll batch of alerts, one transaction (docs/design/THROUGHPUT_FIXES.md
    4b); results in the same order as `events`. Same outcome as calling
    process_event once per alert in order, with one lock per correlation key,
    one bulk membership insert and one UPDATE per touched incident instead of
    a transaction per alert:

    - Replays (already in incident_alerts, or repeated within the batch) are
      "duplicate" with the original incident id and change nothing.
    - Groups are locked in sorted key order, so two replicas overlapping
      during a rebalance can't deadlock on each other.
    - Each group's alerts are assigned in arrival order with process_event's
      exact window rules; incidents created earlier in the batch are
      candidates for later alerts.
    - Only memberships the bulk insert actually wrote (ON CONFLICT DO
      NOTHING RETURNING) are counted, so a concurrent replica inserting the
      same alert still can't double-count it.
    - Sequence detection runs per newly inserted alert, in arrival order,
      inside the same transaction - as before.
    Raises UnparseableEvent for a bad timestamp before touching the database.
    """
    results: list = [None] * len(events)
    gap = datetime.timedelta(seconds=session_gap_seconds)
    max_span = datetime.timedelta(seconds=max_span_seconds)

    keyed = []
    for i, ev in enumerate(events):
        key_and_basis = correlation_key_and_basis(ev)
        if key_and_basis is None:
            results[i] = CorrelationResult(status="unkeyable", incident_id=None)
            continue
        keyed.append((i, ev, key_and_basis[0], key_and_basis[1], _parse_time(ev.time)))
    if not keyed:
        return results

    with db.begin():
        idents = sorted({(ev.tenant_id, ev.cluster_node, ev.alert_id) for _, ev, _, _, _ in keyed})
        existing = {}
        for n in range(0, len(idents), 1000):
            rows = db.execute(
                select(incident_alerts.c.tenant_key, incident_alerts.c.node, incident_alerts.c.alert_id,
                       incident_alerts.c.incident_id)
                .where(tuple_(incident_alerts.c.tenant_key, incident_alerts.c.node, incident_alerts.c.alert_id)
                       .in_(idents[n:n + 1000]))
            ).all()
            existing.update({(r[0], r[1], r[2]): r[3] for r in rows})

        first_index = {}
        repeats = []
        groups: dict[tuple, list] = {}
        for item in keyed:
            i, ev, key, basis, _ = item
            ident = (ev.tenant_id, ev.cluster_node, ev.alert_id)
            if ident in existing:
                results[i] = CorrelationResult(status="duplicate", incident_id=existing[ident])
            elif ident in first_index:
                repeats.append((i, first_index[ident]))
            else:
                first_index[ident] = i
                groups.setdefault((ev.tenant_id, ev.agent_id, key, basis), []).append(item)

        assignments = []  # (item, incident state) in arrival order within each group
        for group_key in sorted(groups):
            tenant, agent, key, basis = group_key
            candidates = [dict(r) for r in db.execute(
                select(incidents)
                .where(
                    incidents.c.tenant_key == tenant,
                    incidents.c.agent_id == agent,
                    incidents.c.correlation_key == key,
                    incidents.c.correlation_basis == basis,
                    incidents.c.state == "open",
                )
                .order_by(incidents.c.id)
                .with_for_update()
            ).mappings().all()]
            for item in groups[group_key]:
                i, ev, _, _, alert_time = item
                inc = next((c for c in candidates
                            if c["first_seen"] - gap <= alert_time <= c["last_seen"] + gap), None)
                if inc is not None and max(inc["last_seen"], alert_time) - min(inc["first_seen"], alert_time) > max_span:
                    inc = None
                if inc is None:
                    new_id = db.execute(
                        incidents.insert().values(
                            tenant_key=tenant, correlation_key=key, correlation_basis=basis, agent_id=agent,
                            first_seen=alert_time, last_seen=alert_time, alert_count=0, max_level=0,
                            rule_ids=[], rule_groups=[], mitre_ids=[], source_ips=[], users=[],
                        ).returning(incidents.c.id)
                    ).scalar_one()
                    inc = _fresh_incident_state(new_id, alert_time)
                    inc["_base"] = dict(inc)
                    candidates.append(inc)
                    status = "created"
                else:
                    inc.setdefault("_base", dict(inc))
                    status = "joined"
                inc["first_seen"] = min(inc["first_seen"], alert_time)
                inc["last_seen"] = max(inc["last_seen"], alert_time)
                assignments.append((item, inc, status))

        inserted = set()
        if assignments:
            rows = db.execute(
                pg_insert(incident_alerts)
                .values([
                    dict(incident_id=inc["id"], tenant_key=ev.tenant_id, node=ev.cluster_node,
                         alert_id=ev.alert_id, alert_time=alert_time)
                    for (i, ev, _, _, alert_time), inc, _ in assignments
                ])
                .on_conflict_do_nothing(constraint="incident_alerts_identity_unique")
                .returning(incident_alerts.c.tenant_key, incident_alerts.c.node, incident_alerts.c.alert_id)
            ).all()
            inserted = {tuple(r) for r in rows}

        new_alerts = []
        folded: dict[int, dict] = {}
        for (i, ev, _, _, alert_time), inc, status in assignments:
            if (ev.tenant_id, ev.cluster_node, ev.alert_id) not in inserted:
                # Lost a race with a concurrent replica - already counted there.
                results[i] = CorrelationResult(status="duplicate", incident_id=inc["id"])
                continue
            results[i] = CorrelationResult(status=status, incident_id=inc["id"])
            new_alerts.append((i, ev, alert_time))
            agg = folded.setdefault(inc["id"], {k: (list(v) if isinstance(v, list) else v)
                                                for k, v in inc["_base"].items() if not k.startswith("_")})
            agg["first_seen"] = min(agg["first_seen"], alert_time)
            agg["last_seen"] = max(agg["last_seen"], alert_time)
            agg["alert_count"] += 1
            agg["max_level"] = max(agg["max_level"], ev.rule_level)
            if ev.rule_id and ev.rule_id not in agg["rule_ids"]:
                agg["rule_ids"].append(ev.rule_id)
            for g in ev.rule_groups:
                if g not in agg["rule_groups"]:
                    agg["rule_groups"].append(g)
            for m in ev.mitre_ids:
                if m not in agg["mitre_ids"]:
                    agg["mitre_ids"].append(m)
            agg["source_ips"], agg["source_ip_total"] = _cap_append(agg["source_ips"], agg["source_ip_total"], ev.src_endpoint_ip, cap)
            agg["users"], agg["user_total"] = _cap_append(agg["users"], agg["user_total"], ev.actor_user, cap)

        if sequences and ch_client is not None:
            for i, ev, alert_time in sorted(new_alerts, key=lambda a: a[0]):
                evaluate_sequences(
                    db, ch_client, clickhouse_database, sequences, ev.tenant_id, ev, alert_time,
                    lateness_seconds=sequence_lateness_seconds, metrics=metrics,
                )

        for incident_id, agg in sorted(folded.items()):
            db.execute(
                incidents.update().where(incidents.c.id == incident_id).values(
                    first_seen=agg["first_seen"], last_seen=agg["last_seen"],
                    alert_count=agg["alert_count"], max_level=agg["max_level"],
                    rule_ids=agg["rule_ids"], rule_groups=agg["rule_groups"], mitre_ids=agg["mitre_ids"],
                    source_ips=agg["source_ips"], source_ip_total=agg["source_ip_total"],
                    users=agg["users"], user_total=agg["user_total"],
                    updated_at=text("now()"),
                )
            )

        for i, first in repeats:
            results[i] = CorrelationResult(status="duplicate", incident_id=results[first].incident_id)

    return results


def process_event(
    db: Session,
    event,
    session_gap_seconds: int = DEFAULT_SESSION_GAP_SECONDS,
    max_span_seconds: int = DEFAULT_MAX_SPAN_SECONDS,
    cap: int = CAPPED_VALUES_LIMIT,
    sequences: list | None = None,
    ch_client=None,
    clickhouse_database: str | None = None,
    sequence_lateness_seconds: float = DEFAULT_LATENESS_SECONDS,
    metrics=None,
) -> CorrelationResult:
    """One alert: process_batch with a batch of one, so tests of
    single-alert behaviour exercise the same code path the consumer runs."""
    return process_batch(
        db, [event], session_gap_seconds, max_span_seconds, cap,
        sequences=sequences, ch_client=ch_client, clickhouse_database=clickhouse_database,
        sequence_lateness_seconds=sequence_lateness_seconds, metrics=metrics,
    )[0]
