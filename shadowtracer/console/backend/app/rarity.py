"""Phase 5B Step 3: read-only mirror of shadowtracer_correlate/rarity.py's
warm-up status computation, for the API/console to display "warming up
(day X of 7, Y of N incidents)" - the correlator's closer.py is the only
thing that actually EVALUATES and writes a rare-pattern flag; this module
only reads the same two inputs (tenant_alert_settings, incidents) to show
the same status, never writes anything."""

import datetime

from sqlalchemy import func, select

from .models import incidents, tenant_alert_settings

DEFAULT_WARMUP_DAYS = 7
DEFAULT_WARMUP_MIN_INCIDENTS = 30


def warmup_status(db, tenant_key: str) -> dict:
    row = db.execute(
        select(
            tenant_alert_settings.c.rare_alert_warmup_days,
            tenant_alert_settings.c.rare_alert_warmup_min_incidents,
        ).where(tenant_alert_settings.c.tenant_key == tenant_key)
    ).first()
    warmup_days, warmup_min_incidents = (row[0], row[1]) if row is not None else (DEFAULT_WARMUP_DAYS, DEFAULT_WARMUP_MIN_INCIDENTS)

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
