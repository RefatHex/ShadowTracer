"""Phase 7.8: attack recurrence forecasting from occurrence timestamps.

Pure stdlib (no numpy/scipy/statsmodels/Prophet): model the inter-arrival GAP distribution and the
HOUR-OF-WEEK profile, then predict the next window. Advisory/experimental - a hint, never an alert.

The same pure function is duplicated in the console backend (app/forecast.py) so the API can recompute
on view without the console depending on this ML package - KEEP THE TWO `forecast_from_times` IN SYNC.
"""
from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime, timedelta

MODEL_VERSION = "7.8-gap-how-v2"
MIN_HISTORY = 4                      # fewer EVENTS -> "not enough history"
BURST_SECONDS = 3600                 # occurrences within 1h are one "event" (collapse batch bursts)


def collapse_bursts(times: list[datetime], burst_seconds: int = BURST_SECONDS) -> list[datetime]:
    """Collapse a run of occurrences closer than burst_seconds into a single event (keep the first).

    Lab (and real) attacks fire MANY incidents at once (an ART batch, a brute-force spray). For
    *recurrence* the unit is the attack RUN, not each incident - otherwise the inter-arrival gaps are
    full of zeros and the forecast window degenerates to a point. We forecast inter-EVENT gaps.
    """
    times = sorted(times)
    if not times:
        return []
    events = [times[0]]
    for t in times[1:]:
        if (t - events[-1]).total_seconds() > burst_seconds:
            events.append(t)
    return events


def forecast_from_times(times: list[datetime]) -> dict | None:
    """Occurrence timestamps (any order) -> forecast dict, or None if < MIN_HISTORY distinct EVENTS.

    Bursts are collapsed to events first. Window = inter-quartile band of the inter-event gap
    distribution added to the last event (a ~50% central band for when the next run lands). Confidence
    from event count + gap dispersion (CV). Also reports the hour-of-week profile of the events."""
    raw_n = len(times)
    events = collapse_bursts(times)
    n = len(events)
    if n < MIN_HISTORY:
        return None
    times = events
    gaps = [(times[i] - times[i - 1]).total_seconds() for i in range(1, n)]
    positive = [g for g in gaps if g > 0]
    gaps = positive or gaps                      # (after collapsing, all should be > 0)

    med = statistics.median(gaps)
    if len(gaps) >= 4:
        q = statistics.quantiles(gaps, n=4, method="inclusive")
        q_lo, q_hi = q[0], q[2]                  # 25th / 75th percentile gap
    else:
        q_lo = q_hi = med
    mean = statistics.fmean(gaps)
    sd = statistics.pstdev(gaps)
    cv = sd / mean if mean else 99.0             # coefficient of variation (gap regularity)

    last = times[-1]
    start = last + timedelta(seconds=q_lo)
    end = last + timedelta(seconds=max(q_hi, q_lo + 1))

    how = [t.weekday() * 24 + t.hour for t in times]
    modal_bin, modal_n = Counter(how).most_common(1)[0]
    concentration = modal_n / n

    if n >= 8 and cv < 0.75:
        conf = "high"
    elif n >= 5 and cv < 1.5:
        conf = "medium"
    else:
        conf = "low"

    return {
        "occurrences": n,                        # distinct EVENTS (recurrence unit)
        "raw_occurrences": raw_n,                 # underlying incident count (pre-collapse)
        "predicted_start": start,
        "predicted_end": end,
        "probability": 0.5,                      # IQR of gaps ~ 50% central band
        "confidence": conf,
        "median_gap_seconds": round(med),
        "gap_cv": round(cv, 3),
        "modal_hour_of_week": modal_bin,
        "hour_of_week_concentration": round(concentration, 3),
        "last_occurrence": last,
        "model_version": MODEL_VERSION,
    }


# --- storage / recompute (enricher side; console reads the table) -------------------------------
# Uses a SQLAlchemy Connection (the enricher already holds an `engine`).

_UPSERT = """
INSERT INTO recurrence_forecasts (tenant_key, subject_type, subject_key, occurrences, raw_occurrences,
  predicted_start, predicted_end, probability, confidence, median_gap_seconds, gap_cv, modal_hour_of_week,
  hour_of_week_concentration, last_occurrence, model_version, computed_at)
VALUES (:tenant_key,:subject_type,:subject_key,:occurrences,:raw_occurrences,:predicted_start,
  :predicted_end,:probability,:confidence,:median_gap_seconds,:gap_cv,:modal_hour_of_week,
  :hour_of_week_concentration,:last_occurrence,:model_version, now())
ON CONFLICT (tenant_key, subject_type, subject_key) DO UPDATE SET
  occurrences=EXCLUDED.occurrences, raw_occurrences=EXCLUDED.raw_occurrences,
  predicted_start=EXCLUDED.predicted_start,
  predicted_end=EXCLUDED.predicted_end, probability=EXCLUDED.probability, confidence=EXCLUDED.confidence,
  median_gap_seconds=EXCLUDED.median_gap_seconds, gap_cv=EXCLUDED.gap_cv,
  modal_hour_of_week=EXCLUDED.modal_hour_of_week,
  hour_of_week_concentration=EXCLUDED.hour_of_week_concentration,
  last_occurrence=EXCLUDED.last_occurrence, model_version=EXCLUDED.model_version, computed_at=now()
"""


def _series(conn, sql: str, tenant_key: str) -> dict[str, list[datetime]]:
    from sqlalchemy import text
    out: dict[str, list[datetime]] = {}
    for key, ts in conn.execute(text(sql), {"t": tenant_key}).fetchall():
        out.setdefault(str(key), []).append(ts)
    return {k: v for k, v in out.items() if len(v) >= MIN_HISTORY}


def recompute_tenant(conn, tenant_key: str) -> int:
    """Recompute every eligible fingerprint + campaign forecast for one tenant and upsert. `conn` is a
    SQLAlchemy Connection inside a transaction. Returns the number of rows written."""
    from sqlalchemy import text
    fps = _series(conn, "SELECT fingerprint_key, first_seen FROM incidents WHERE tenant_key=:t "
                        "AND fingerprint_key IS NOT NULL AND first_seen IS NOT NULL", tenant_key)
    camps = _series(conn, "SELECT c.id, i.first_seen FROM campaigns c "
                         "JOIN campaign_incidents ci ON ci.campaign_id=c.id "
                         "JOIN incidents i ON i.id=ci.incident_id "
                         "WHERE c.tenant_key=:t AND i.first_seen IS NOT NULL", tenant_key)
    subjects = [("fingerprint", k, v) for k, v in fps.items()] + [("campaign", k, v) for k, v in camps.items()]
    written = 0
    for subject_type, subject_key, times in subjects:
        f = forecast_from_times(times)
        if not f:
            continue
        conn.execute(text(_UPSERT), {"tenant_key": tenant_key, "subject_type": subject_type,
                                     "subject_key": subject_key, **f})
        written += 1
    return written


def recompute_all(engine) -> dict:
    """Recompute forecasts for every tenant (one transaction). Returns {tenant_key: rows_written}."""
    from sqlalchemy import text
    with engine.begin() as conn:
        tenants = [r[0] for r in conn.execute(text("SELECT tenant_key FROM tenants")).fetchall()]
        return {t: recompute_tenant(conn, t) for t in tenants}
