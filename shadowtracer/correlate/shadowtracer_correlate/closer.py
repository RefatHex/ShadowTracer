"""Phase 5A Step 1 (closer) / Step 3 (fingerprint computation at close
time). Marks incidents closed once they've gone quiet past the session
gap, computes their fingerprint, and records one occurrence row in
ClickHouse.

Safe with several replicas: each candidate incident is closed inside its
own transaction, guarded by a Postgres advisory transaction lock keyed on
the incident's id (pg_try_advisory_xact_lock - released automatically on
commit or rollback, same mechanism app/audit.py already uses for
append_entry, just per-incident instead of one fixed key). A replica that
loses the race for a given incident just skips it - the one that won
already closed it.

Write order inside the transaction matters: ClickHouse (the occurrence
row) before the PostgreSQL commit. If the process dies between the two,
the incident is still 'open' and gets reconsidered next run - which
would insert a second ClickHouse row for the same incident_id. That's
harmless by design: fingerprint_occurrences is read with
uniqExact(incident_id), not count(), so a duplicate from a retried close
can't inflate the occurrence count (see schema/events_schema.sql's
header for that table). The reverse order (PostgreSQL first) would risk
the opposite: an incident permanently marked closed with no matching
ClickHouse row at all, since a closed incident is never reconsidered.
"""

import datetime

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from .fingerprint import RULESET_VERSION, compute_fingerprint
from .models import agent_role_tags, fingerprints, incidents


def close_eligible_incidents(
    db: Session,
    ch_client,
    clickhouse_database: str,
    session_gap_seconds: int,
    internal_ranges: list[str],
) -> list[int]:
    """Returns the ids this call actually closed (not ones another
    replica got to first, and not ones a fresh alert kept open)."""
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=session_gap_seconds)

    candidate_ids = db.execute(
        select(incidents.c.id).where(incidents.c.state == "open", incidents.c.last_seen < cutoff)
    ).scalars().all()
    # The SELECT above auto-begins a transaction on this Session (SQLAlchemy
    # 2.0 default) - close it out before the per-incident loop below opens
    # its own with db.begin(), which would otherwise raise "a transaction
    # is already begun on this Session".
    db.commit()

    closed_ids = []
    for incident_id in candidate_ids:
        with db.begin():
            acquired = db.execute(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": incident_id}).scalar_one()
            if not acquired:
                continue  # another replica already owns this one

            row = db.execute(
                select(incidents).where(incidents.c.id == incident_id).with_for_update()
            ).mappings().first()
            if row is None or row["state"] != "open" or row["last_seen"] >= cutoff:
                continue  # closed already, or a fresh alert extended it since the scan

            role_row = db.execute(
                select(agent_role_tags).where(
                    agent_role_tags.c.tenant_key == row["tenant_key"],
                    agent_role_tags.c.agent_id == row["agent_id"],
                )
            ).mappings().first()
            os_family = role_row["os_family"] if role_row else None
            role_tag = role_row["role_tag"] if role_row else None

            fingerprint_key = compute_fingerprint(
                row["rule_groups"], row["mitre_ids"], row["source_ips"], row["alert_count"],
                row["first_seen"], row["last_seen"], os_family, role_tag, internal_ranges,
            )
            closed_at = datetime.datetime.now(datetime.timezone.utc)

            # ClickHouse before the PostgreSQL commit - see module docstring.
            ch_client.insert(
                "fingerprint_occurrences",
                [[row["tenant_key"], fingerprint_key, incident_id, closed_at, row["alert_count"]]],
                column_names=["tenant_id", "fingerprint_key", "incident_id", "closed_at", "alert_count"],
                database=clickhouse_database,
            )

            db.execute(
                incidents.update().where(incidents.c.id == incident_id).values(
                    state="closed", closed_at=closed_at,
                    fingerprint_key=fingerprint_key, ruleset_version=RULESET_VERSION,
                )
            )
            db.execute(
                pg_insert(fingerprints)
                .values(tenant_key=row["tenant_key"], fingerprint_key=fingerprint_key)
                .on_conflict_do_nothing(index_elements=["tenant_key", "fingerprint_key"])
            )
            closed_ids.append(incident_id)

    return closed_ids
