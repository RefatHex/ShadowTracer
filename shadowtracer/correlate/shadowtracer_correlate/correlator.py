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

from sqlalchemy import select, text
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
) -> CorrelationResult:
    """One alert, one transaction. Safe to call twice for the same alert
    (a Kafka replay): the second call is a no-op past the idempotency
    check (incident_alerts' unique constraint), never a duplicate
    membership row or a double-counted incident. Caller commits Kafka
    offsets only after this returns without raising - see
    run_correlator.py.

    Phase 5B Step 4: sequences/ch_client/clickhouse_database are optional
    - omitted (None), sequence detection is simply not evaluated for this
    call (existing tests that don't care about it need no changes).
    Passed, shadowtracer_correlate.sequences.evaluate_sequences runs
    INSIDE this same transaction, right after the idempotency check below
    - so sequence progress commits or rolls back atomically with the
    incident/membership write it's based on, same "never in memory"
    reasoning as everything else here."""
    key_and_basis = correlation_key_and_basis(event)
    if key_and_basis is None:
        return CorrelationResult(status="unkeyable", incident_id=None)
    correlation_key, basis = key_and_basis
    alert_time = _parse_time(event.time)
    gap = datetime.timedelta(seconds=session_gap_seconds)
    max_span = datetime.timedelta(seconds=max_span_seconds)

    with db.begin():
        # FOR UPDATE: this worker owns this agent's partition exclusively
        # under normal operation (see module docstring), so this never
        # contends except for the brief overlap a rebalance can cause -
        # exactly what it's here to make safe.
        row = db.execute(
            select(incidents)
            .where(
                incidents.c.tenant_key == event.tenant_id,
                incidents.c.agent_id == event.agent_id,
                incidents.c.correlation_key == correlation_key,
                incidents.c.correlation_basis == basis,
                incidents.c.state == "open",
                incidents.c.first_seen - gap <= alert_time,
                incidents.c.last_seen + gap >= alert_time,
            )
            .with_for_update()
        ).mappings().first()

        incident_id = None
        if row is not None:
            new_first = min(row["first_seen"], alert_time)
            new_last = max(row["last_seen"], alert_time)
            if new_last - new_first <= max_span:
                incident_id = row["id"]

        if incident_id is None:
            result = db.execute(
                incidents.insert().values(
                    tenant_key=event.tenant_id,
                    correlation_key=correlation_key,
                    correlation_basis=basis,
                    agent_id=event.agent_id,
                    first_seen=alert_time,
                    last_seen=alert_time,
                    alert_count=0,
                    max_level=0,
                    rule_ids=[], rule_groups=[], mitre_ids=[], source_ips=[], users=[],
                ).returning(incidents.c.id)
            )
            incident_id = result.scalar_one()
            status = "created"
        else:
            status = "joined"

        inserted = db.execute(
            pg_insert(incident_alerts)
            .values(
                incident_id=incident_id, tenant_key=event.tenant_id,
                node=event.cluster_node, alert_id=event.alert_id, alert_time=alert_time,
            )
            .on_conflict_do_nothing(constraint="incident_alerts_identity_unique")
            .returning(incident_alerts.c.id)
        ).first()

        if inserted is None:
            # Replay of an alert already counted in this incident - the
            # whole point of the idempotency key. Nothing else to do.
            return CorrelationResult(status="duplicate", incident_id=incident_id)

        if sequences and ch_client is not None:
            evaluate_sequences(
                db, ch_client, clickhouse_database, sequences, event.tenant_id, event, alert_time,
                lateness_seconds=sequence_lateness_seconds,
            )

        current = db.execute(
            select(incidents).where(incidents.c.id == incident_id).with_for_update()
        ).mappings().one()

        new_source_ips, new_source_ip_total = _cap_append(
            list(current["source_ips"]), current["source_ip_total"], event.src_endpoint_ip, cap
        )
        new_users, new_user_total = _cap_append(
            list(current["users"]), current["user_total"], event.actor_user, cap
        )
        rule_ids = list(current["rule_ids"])
        if event.rule_id and event.rule_id not in rule_ids:
            rule_ids.append(event.rule_id)
        rule_groups = list(current["rule_groups"])
        for g in event.rule_groups:
            if g not in rule_groups:
                rule_groups.append(g)
        mitre_ids = list(current["mitre_ids"])
        for m in event.mitre_ids:
            if m not in mitre_ids:
                mitre_ids.append(m)

        db.execute(
            incidents.update().where(incidents.c.id == incident_id).values(
                first_seen=min(current["first_seen"], alert_time),
                last_seen=max(current["last_seen"], alert_time),
                alert_count=current["alert_count"] + 1,
                max_level=max(current["max_level"], event.rule_level),
                rule_ids=rule_ids,
                rule_groups=rule_groups,
                mitre_ids=mitre_ids,
                source_ips=new_source_ips,
                source_ip_total=new_source_ip_total,
                users=new_users,
                user_total=new_user_total,
                updated_at=text("now()"),
            )
        )

        return CorrelationResult(status=status, incident_id=incident_id)
