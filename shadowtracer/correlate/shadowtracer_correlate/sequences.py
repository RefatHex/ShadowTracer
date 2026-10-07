"""Phase 5B Step 4: sequence detection - curated, YAML-defined multi-step
attack patterns (sequences/*.yaml), evaluated against Postgres state only
(sequence_progress) - never in memory, so a worker restart mid-sequence
never loses progress (same reasoning as every other piece of correlator
state - see correlator.py's own module docstring).

Idempotent by construction, not by a separate mechanism: evaluate_sequences
is only ever called (from correlator.py's process_event) for an alert
whose CorrelationResult status is "created" or "joined" - a genuinely
NEW alert. A Kafka replay of an alert already recorded short-circuits
earlier, at incident_alerts' own unique constraint (status "duplicate"),
and never reaches here at all - so the same alert can never advance or
complete a sequence twice.

Matching is always against step_groups[current_step] - the ONE next
expected step, never scanned ahead. This is what makes an out-of-order
alert a no-op rather than a bug: an alert matching a LATER step while an
EARLIER one hasn't matched yet simply doesn't match
step_groups[current_step] (still 0), so nothing happens. A stale,
uncompleted attempt (window_seconds elapsed since first_step_at) is
treated as expired - only a fresh step-0 match restarts it, so an
expired partial sequence can never complete just because its next alert
happens to arrive late.

A completed sequence's firing is recorded in ClickHouse
(sequence_firings - history, read via uniqExact(completing_alert_id),
never count() - see that table's own header in schema/events_schema.sql)
and the Postgres progress row is reset to current_step=0 so the same
(tenant, sequence, agent, key) combination can be tracked fresh for a
future occurrence - sequence_progress holds only the CURRENT in-flight
attempt, never a history of past ones.

Known limitation, documented rather than silently left: expired
sequence_progress rows are never actively reaped - they're harmless
(re-evaluated as expired, correctly, forever) but accumulate. A periodic
cleanup is a reasonable follow-up, not required for this phase's
"start small" scope.
"""

import datetime
import json
import os

import yaml
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .models import sequence_progress


def load_sequences(sequences_dir: str) -> list:
    """One dict per sequences/*.yaml file: {"id", "description",
    "window_seconds", "key" ("source_ip" | "user"), "steps" (ordered list
    of rule group names)}."""
    defs = []
    for name in sorted(os.listdir(sequences_dir)):
        if not name.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(sequences_dir, name)) as f:
            defs.append(yaml.safe_load(f))
    return defs


def _key_value(event, key_type: str):
    if key_type == "source_ip":
        return event.src_endpoint_ip or None
    if key_type == "user":
        return event.actor_user or None
    return None


def evaluate_sequences(db, ch_client, clickhouse_database: str, sequences: list, tenant_key: str, event, alert_time: datetime.datetime) -> list:
    """Returns the list of sequence ids that fired as a direct result of
    this one alert (usually empty - most alerts don't complete anything)."""
    fired_ids = []

    for seq in sequences:
        key_value = _key_value(event, seq["key"])
        if not key_value:
            continue  # this alert has no value for this sequence's key field - can't participate

        row = db.execute(
            select(sequence_progress).where(
                sequence_progress.c.tenant_key == tenant_key,
                sequence_progress.c.sequence_id == seq["id"],
                sequence_progress.c.agent_id == event.agent_id,
                sequence_progress.c.key_type == seq["key"],
                sequence_progress.c.key_value == key_value,
            ).with_for_update()
        ).mappings().first()

        step_groups = seq["steps"]
        expired = row is not None and (alert_time - row["first_step_at"]).total_seconds() > seq["window_seconds"]
        current_step = 0 if (row is None or expired) else row["current_step"]

        if current_step >= len(step_groups):
            continue  # defensive - should never happen, a completed row is always reset to 0
        if step_groups[current_step] not in event.rule_groups:
            continue  # doesn't match the next expected step - out-of-order and irrelevant alerts both land here, as a no-op

        step_match = {
            "step_index": current_step, "node": event.cluster_node,
            "alert_id": event.alert_id, "matched_at": alert_time.isoformat(),
        }
        prior_matches = [] if current_step == 0 else list(row["step_matches"])
        new_matches = prior_matches + [step_match]
        new_step = current_step + 1
        first_step_at = alert_time if current_step == 0 else row["first_step_at"]

        if new_step == len(step_groups):
            completing_alert_id = f"{event.cluster_node}:{event.alert_id}"
            ch_client.insert(
                "sequence_firings",
                [[
                    tenant_key, seq["id"], event.agent_id, seq["key"], key_value,
                    alert_time, json.dumps(new_matches), completing_alert_id,
                ]],
                column_names=[
                    "tenant_id", "sequence_id", "agent_id", "key_type", "key_value",
                    "fired_at", "step_matches", "completing_alert_id",
                ],
                database=clickhouse_database,
            )
            fired_ids.append(seq["id"])
            # Reset - ready to track a future occurrence of this same
            # sequence for this same (agent, key) fresh, from scratch.
            new_step, new_matches, first_step_at = 0, [], alert_time

        db.execute(
            pg_insert(sequence_progress)
            .values(
                tenant_key=tenant_key, sequence_id=seq["id"], agent_id=event.agent_id,
                key_type=seq["key"], key_value=key_value,
                current_step=new_step, first_step_at=first_step_at, last_step_at=alert_time,
                step_matches=new_matches,
            )
            .on_conflict_do_update(
                index_elements=["tenant_key", "sequence_id", "agent_id", "key_type", "key_value"],
                set_={
                    "current_step": new_step, "first_step_at": first_step_at,
                    "last_step_at": alert_time, "step_matches": new_matches,
                },
            )
        )

    return fired_ids
