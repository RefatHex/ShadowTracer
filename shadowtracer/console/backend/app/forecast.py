"""Phase 7.8: recurrence-forecast read + recompute-on-view for the console.

The pure forecast math is DUPLICATED from shadowtracer_ml/forecast.py because the console and the
ml-enricher are separate deployables with no shared package - KEEP forecast_from_times / collapse_bursts
IN SYNC between the two files. Everything here is tenant-scoped and read-only w.r.t. incident data (it
only writes the derived recurrence_forecasts cache). Advisory/experimental - a hint, never an alert.
"""
from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

MODEL_VERSION = "7.8-gap-how-v2"
MIN_HISTORY = 4
BURST_SECONDS = 3600


def collapse_bursts(times: list[datetime], burst_seconds: int = BURST_SECONDS) -> list[datetime]:
    """Collapse occurrences closer than burst_seconds into one event (the attack RUN is the unit)."""
    times = sorted(times)
    if not times:
        return []
    events = [times[0]]
    for t in times[1:]:
        if (t - events[-1]).total_seconds() > burst_seconds:
            events.append(t)
    return events


def forecast_from_times(times: list[datetime]) -> dict | None:
    """Occurrence timestamps -> forecast dict, or None if < MIN_HISTORY distinct events. See
    shadowtracer_ml/forecast.py for the canonical copy and docstring."""
    raw_n = len(times)
    events = collapse_bursts(times)
    n = len(events)
    if n < MIN_HISTORY:
        return None
    gaps = [(events[i] - events[i - 1]).total_seconds() for i in range(1, n)]
    gaps = [g for g in gaps if g > 0] or gaps
    med = statistics.median(gaps)
    if len(gaps) >= 4:
        q = statistics.quantiles(gaps, n=4, method="inclusive")
        q_lo, q_hi = q[0], q[2]
    else:
        q_lo = q_hi = med
    mean = statistics.fmean(gaps)
    cv = statistics.pstdev(gaps) / mean if mean else 99.0
    last = events[-1]
    start = last + timedelta(seconds=q_lo)
    end = last + timedelta(seconds=max(q_hi, q_lo + 1))
    modal_bin, modal_n = Counter(e.weekday() * 24 + e.hour for e in events).most_common(1)[0]
    if n >= 8 and cv < 0.75:
        conf = "high"
    elif n >= 5 and cv < 1.5:
        conf = "medium"
    else:
        conf = "low"
    return {"occurrences": n, "raw_occurrences": raw_n, "predicted_start": start, "predicted_end": end,
            "probability": 0.5, "confidence": conf, "median_gap_seconds": round(med),
            "gap_cv": round(cv, 3), "modal_hour_of_week": modal_bin,
            "hour_of_week_concentration": round(modal_n / n, 3), "last_occurrence": last,
            "model_version": MODEL_VERSION, "events": events}


_UPSERT = text("""
INSERT INTO recurrence_forecasts (tenant_key, subject_type, subject_key, occurrences, raw_occurrences,
  predicted_start, predicted_end, probability, confidence, median_gap_seconds, gap_cv, modal_hour_of_week,
  hour_of_week_concentration, last_occurrence, model_version, computed_at)
VALUES (:tenant_key,:subject_type,:subject_key,:occurrences,:raw_occurrences,:predicted_start,
  :predicted_end,:probability,:confidence,:median_gap_seconds,:gap_cv,:modal_hour_of_week,
  :hour_of_week_concentration,:last_occurrence,:model_version, now())
ON CONFLICT (tenant_key, subject_type, subject_key) DO UPDATE SET
  occurrences=EXCLUDED.occurrences, raw_occurrences=EXCLUDED.raw_occurrences,
  predicted_start=EXCLUDED.predicted_start, predicted_end=EXCLUDED.predicted_end,
  probability=EXCLUDED.probability, confidence=EXCLUDED.confidence,
  median_gap_seconds=EXCLUDED.median_gap_seconds, gap_cv=EXCLUDED.gap_cv,
  modal_hour_of_week=EXCLUDED.modal_hour_of_week,
  hour_of_week_concentration=EXCLUDED.hour_of_week_concentration,
  last_occurrence=EXCLUDED.last_occurrence, model_version=EXCLUDED.model_version, computed_at=now()
""")


def _occurrence_times(db: Session, tenant_key: str, subject_type: str, subject_key: str) -> list[datetime]:
    if subject_type == "fingerprint":
        rows = db.execute(text("SELECT first_seen FROM incidents WHERE tenant_key=:t "
                               "AND fingerprint_key=:k AND first_seen IS NOT NULL"),
                          {"t": tenant_key, "k": subject_key}).fetchall()
    else:
        try:
            cid = int(subject_key)
        except ValueError:
            return []
        rows = db.execute(text("SELECT i.first_seen FROM campaign_incidents ci "
                               "JOIN incidents i ON i.id=ci.incident_id JOIN campaigns c ON c.id=ci.campaign_id "
                               "WHERE c.tenant_key=:t AND c.id=:k AND i.first_seen IS NOT NULL"),
                          {"t": tenant_key, "k": cid}).fetchall()
    return [r[0] for r in rows]


def get_forecast(db: Session, tenant_key: str, subject_type: str, subject_key: str) -> dict:
    """Return the forecast for one subject, recomputing on view if a new occurrence has arrived since
    the stored row (keeps 'new occurrence -> forecast updates' immediate, independent of the hourly job).
    {status: 'ok', ...} or {status: 'not_enough_history', raw_occurrences}."""
    times = _occurrence_times(db, tenant_key, subject_type, subject_key)
    row = db.execute(text("SELECT * FROM recurrence_forecasts WHERE tenant_key=:t AND subject_type=:st "
                          "AND subject_key=:k"),
                     {"t": tenant_key, "st": subject_type, "k": subject_key}).mappings().first()
    newest = max(times) if times else None
    stale = row is None or (newest is not None and row["last_occurrence"] is not None
                            and newest > row["last_occurrence"])
    f = forecast_from_times(times) if stale else None
    if f:
        db.execute(_UPSERT, {"tenant_key": tenant_key, "subject_type": subject_type,
                             "subject_key": subject_key, **{k: v for k, v in f.items() if k != "events"}})
        db.commit()
        row = db.execute(text("SELECT * FROM recurrence_forecasts WHERE tenant_key=:t AND subject_type=:st "
                              "AND subject_key=:k"),
                         {"t": tenant_key, "st": subject_type, "k": subject_key}).mappings().first()

    if row is None:
        return {"status": "not_enough_history", "subject_type": subject_type, "subject_key": subject_key,
                "raw_occurrences": len(times)}
    events = collapse_bursts(times)
    out = dict(row)
    out.pop("id", None)
    out.pop("tenant_key", None)
    out["status"] = "ok"
    out["events"] = [e.isoformat() for e in events[-60:]]        # recent events for the timeline
    for k in ("predicted_start", "predicted_end", "last_occurrence", "computed_at"):
        if out.get(k) is not None:
            out[k] = out[k].isoformat()
    return out
