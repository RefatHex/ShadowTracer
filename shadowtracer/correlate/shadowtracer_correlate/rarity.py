"""Phase 5B Step 3: rare-pattern alerting with a warm-up guard.

Rarity is a COUNT - how many times this exact fingerprint has occurred
for this tenant before (fingerprint_occurrences, ClickHouse,
uniqExact(incident_id) - never a stored counter, same reasoning as every
other occurrence count in this project) - never a model, never an ML
feature. A tenant produces no rare-pattern flags at all until it's past
warm-up (see warmup_status): at least warmup_days of data AND at least
warmup_min_incidents incidents, both per-tenant configurable
(tenant_alert_settings), defaulting to 7 and 30 - 30 is a starting guess
to be checked against real tenant volume, not a measured value (see
docs/specs/PHASE5B.md's addendum).

A rare-pattern alert is a FLAG on the incident, with the occurrence count
and the reason - never a replacement for the incident, which exists and
stays fully visible regardless. A suppressed fingerprint (suppression_state
'active') never raises a flag, but its incidents and their data stay
visible exactly as before - suppression deprioritizes, it never hides.

Rarity is evaluated strictly per tenant: the ClickHouse query below is
always scoped by tenant_id, and the warm-up status is always scoped by
tenant_key - one tenant's history can never make another tenant's
first-ever fingerprint anything but rare.
"""

import datetime

from sqlalchemy import func, select

from .models import fingerprints, incidents, tenant_alert_settings

DEFAULT_WARMUP_DAYS = 7
DEFAULT_WARMUP_MIN_INCIDENTS = 30


def get_tenant_warmup_config(db, tenant_key: str) -> tuple:
    row = db.execute(
        select(
            tenant_alert_settings.c.rare_alert_warmup_days,
            tenant_alert_settings.c.rare_alert_warmup_min_incidents,
        ).where(tenant_alert_settings.c.tenant_key == tenant_key)
    ).first()
    if row is None:
        return DEFAULT_WARMUP_DAYS, DEFAULT_WARMUP_MIN_INCIDENTS
    return row[0], row[1]


def warmup_status(db, tenant_key: str) -> dict:
    """Always scoped to tenant_key - never reads or is influenced by any
    other tenant's incidents. Returns the exact fields the API/console
    need to show "warming up (day X of 7, Y of N incidents)"."""
    warmup_days, warmup_min_incidents = get_tenant_warmup_config(db, tenant_key)
    earliest, count = db.execute(
        select(func.min(incidents.c.created_at), func.count())
        .where(incidents.c.tenant_key == tenant_key)
    ).one()
    if earliest is None:
        days_elapsed = 0
    else:
        if earliest.tzinfo is None:
            earliest = earliest.replace(tzinfo=datetime.timezone.utc)
        days_elapsed = (datetime.datetime.now(datetime.timezone.utc) - earliest).days
    return {
        "complete": days_elapsed >= warmup_days and count >= warmup_min_incidents,
        "days_elapsed": days_elapsed,
        "warmup_days": warmup_days,
        "incident_count": count,
        "warmup_min_incidents": warmup_min_incidents,
    }


def evaluate_rare_pattern(db, ch_client, clickhouse_database: str, tenant_key: str, fingerprint_key: str):
    """Returns a dict {"flag": True, "occurrence_count": 0, "reason": ...}
    if this incident should be flagged rare, else None. MUST be called
    before the caller inserts this incident's own occurrence row into
    ClickHouse (see closer.py) - the count here is "how many times before
    this one", which only holds if this incident's own row isn't counted
    yet."""
    status = warmup_status(db, tenant_key)
    if not status["complete"]:
        return None

    suppression_row = db.execute(
        select(fingerprints.c.suppression_state).where(
            fingerprints.c.tenant_key == tenant_key,
            fingerprints.c.fingerprint_key == fingerprint_key,
        )
    ).first()
    if suppression_row is not None and suppression_row[0] == "active":
        return None  # suppressed - never raises a rare flag; the incident/data stay visible regardless, handled entirely by the caller not calling this differently

    prior_count = ch_client.query(
        f"SELECT uniqExact(incident_id) FROM {clickhouse_database}.fingerprint_occurrences "
        "WHERE tenant_id = {tenant_id:String} AND fingerprint_key = {fingerprint_key:String}",
        parameters={"tenant_id": tenant_key, "fingerprint_key": fingerprint_key},
    ).result_rows[0][0]

    if prior_count != 0:
        return None  # seen before for this tenant - not rare by this definition

    return {
        "flag": True,
        "occurrence_count": prior_count,
        "reason": "Never seen before for this tenant - this is the first occurrence of this fingerprint.",
    }
