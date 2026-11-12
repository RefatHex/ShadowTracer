"""Phase 7.2: River ADWIN behavioural + model-input drift detection (advisory only).

drift-monitor is its own periodic service (default every 60 s). It is OFF the hot path and reads
**ClickHouse rollups only** - never a Kafka alert topic. It runs one River ADWIN per (entity,
metric) over completed hourly buckets and records a drift_events row when a metric's distribution
shifts. It takes no action and never retrains anything - a drift event is a signal for a human.

Two kinds of drift:
  1. behaviour, per (tenant, agent), from events_hourly_rollup: alert_volume (distinct rule×level
     signatures/hour), distinct_rule_ids, distinct_users, mean_rule_level;
  2. model-input, per served model, from ml_feature_stats: a feature's hourly mean.

Bounded state: one ADWIN per (entity, metric), with an LRU cap on entities; the whole detector set
+ the last-processed hour are pickled to a state dir between runs. Params/run are logged to MLflow.
"""
import argparse
import datetime as dt
import json
import logging
import os
import pickle
import time
from collections import OrderedDict, deque

from river.drift import ADWIN

from . import db

log = logging.getLogger("ml-drift")

DRIFT_VERSION = "drift-v2"
STATE_FORMAT = "shadowtracer-drift/1"


class StateIncompatible(Exception):
    """The saved drift state cannot be trusted with this code/library - discard and re-warm."""


def _river_version() -> str:
    import river
    return river.__version__
INTERVAL = float(os.environ.get("DRIFT_INTERVAL_SECONDS", "60"))
MAX_ENTITIES = int(os.environ.get("DRIFT_MAX_ENTITIES", "5000"))
# ADWIN tuned for responsiveness to a short behaviour burst over hourly buckets (a 2-3 bucket change
# is caught, not only a 30-bucket slow drift) while holding zero false drifts on a stable/noisy
# stream: delta 0.2, check every bucket (clock=1), grace 5, min sub-window 3.
ADWIN_DELTA = float(os.environ.get("DRIFT_ADWIN_DELTA", "0.2"))
ADWIN_CLOCK = int(os.environ.get("DRIFT_ADWIN_CLOCK", "1"))
ADWIN_GRACE = int(os.environ.get("DRIFT_ADWIN_GRACE", "5"))
ADWIN_MIN_WINDOW = int(os.environ.get("DRIFT_ADWIN_MIN_WINDOW", "3"))
# how far back to catch up the first time there is no state (completed hours)
BACKFILL_HOURS = int(os.environ.get("DRIFT_BACKFILL_HOURS", "168"))
STATE_DIR = os.environ.get("DRIFT_STATE_DIR", "/state")
STATE_PATH = os.path.join(STATE_DIR, "drift_state.pkl")

BEHAVIOUR_METRICS = ("alert_volume", "distinct_rule_ids", "distinct_users", "mean_rule_level")


class Detectors:
    """One ADWIN per (entity, metric). LRU cap on ENTITIES (each entity holds its metrics).
    update() returns (before, after, magnitude) when ADWIN flags a change, else None."""

    def __init__(self, max_entities: int = MAX_ENTITIES, delta: float = ADWIN_DELTA):
        self.max_entities = max_entities
        self.delta = delta
        self.entities: "OrderedDict[str, dict]" = OrderedDict()

    def update(self, entity: str, metric: str, value: float):
        slot = self.entities.get(entity)
        if slot is None:
            slot = {}
            self.entities[entity] = slot
        self.entities.move_to_end(entity)
        while len(self.entities) > self.max_entities:
            self.entities.popitem(last=False)          # evict least-recently-updated entity
        st = slot.get(metric)
        if st is None:
            # keep a short window of recent values so before/after read the OLD vs NEW regime
            # cleanly (ADWIN's own estimation at detection is a partial blend across the change).
            st = {"adwin": ADWIN(delta=self.delta, clock=ADWIN_CLOCK, grace_period=ADWIN_GRACE,
                                 min_window_length=ADWIN_MIN_WINDOW), "hist": deque(maxlen=160)}
            slot[metric] = st
        a, hist = st["adwin"], st["hist"]
        hist.append(float(value))
        a.update(float(value))
        if a.drift_detected and len(hist) >= 2:
            # 'after' is the value of the bucket that tripped the detector (unambiguously the new
            # regime - ADWIN can fire with as few as 3 new samples, so any window averaged over the
            # deque is diluted by old values); 'before' is the stable baseline (oldest buckets).
            vals = list(hist)
            k = max(1, min(10, len(vals) // 2))
            before = sum(vals[:k]) / k
            after = float(value)
            hist.clear()                                    # start the new regime's window fresh
            return (before, after, abs(after - before))
        return None

    def entity_count(self) -> int:
        return len(self.entities)


# --- ClickHouse metric queries (rollups only) -------------------------------------------------
def _utc(h: dt.datetime) -> dt.datetime:
    return h.replace(tzinfo=dt.timezone.utc) if h.tzinfo is None else h


def behaviour_rows(ch, last_hour: dt.datetime, until: dt.datetime):
    """(tenant, agent, hour, {metric: value}) per completed hour in (last_hour, until]."""
    rows = ch.query(
        "SELECT tenant_id, agent_id, hour, count() AS alert_volume, uniqExact(rule_id) AS distinct_rule_ids, "
        "uniqExactMerge(identity_state) AS distinct_users, avg(rule_level) AS mean_rule_level "
        "FROM events_hourly_rollup WHERE hour > {last:DateTime} AND hour <= {until:DateTime} "
        "GROUP BY tenant_id, agent_id, hour ORDER BY hour",
        parameters={"last": last_hour, "until": until}).result_rows
    for tenant, agent, hour, vol, rules, users, lvl in rows:
        yield tenant, agent, _utc(hour), {"alert_volume": float(vol), "distinct_rule_ids": float(rules),
                                          "distinct_users": float(users), "mean_rule_level": float(lvl)}


def model_rows(ch, last_hour: dt.datetime, until: dt.datetime):
    """(feature_version, feature, hour, mean) per completed hour in (last_hour, until]."""
    rows = ch.query(
        "SELECT feature_version, feature, hour, sum(sum) / sum(n) AS mean FROM ml_feature_stats "
        "WHERE hour > {last:DateTime} AND hour <= {until:DateTime} "
        "GROUP BY feature_version, feature, hour HAVING sum(n) > 0 ORDER BY hour",
        parameters={"last": last_hour, "until": until}).result_rows
    for fv, feature, hour, mean in rows:
        yield fv, feature, _utc(hour), float(mean)


def _record(conn, tenant_key, entity_type, entity, metric, window_start, before, after, magnitude):
    from sqlalchemy import text
    conn.execute(text(
        "INSERT INTO drift_events (tenant_key, entity_type, entity, metric, window_start, before_value, "
        "after_value, magnitude) VALUES (:t,:et,:e,:m,:w,:b,:a,:g) "
        "ON CONFLICT (tenant_key, entity_type, entity, metric, window_start) DO NOTHING"),
        {"t": tenant_key, "et": entity_type, "e": entity, "m": metric, "w": window_start,
         "b": before, "a": after, "g": magnitude})


def process(engine, ch, det: Detectors, last_hour: dt.datetime, until: dt.datetime) -> tuple:
    """Feed every completed bucket in (last_hour, until] to the detectors; record drift events.
    Returns (drift_count, new_last_hour)."""
    from sqlalchemy import text
    drifts, newest = 0, last_hour
    with engine.begin() as conn:
        for tenant, agent, hour, metrics in behaviour_rows(ch, last_hour, until):
            newest = max(newest, hour)
            for metric, value in metrics.items():
                r = det.update(f"agent|{tenant}|{agent}", metric, value)
                if r:
                    _record(conn, tenant, "agent", agent, metric, hour, *r)
                    drifts += 1
        for fv, feature, hour, mean in model_rows(ch, last_hour, until):
            newest = max(newest, hour)
            r = det.update(f"model|{fv}|{feature}", "feature_mean", mean)
            if r:
                _record(conn, "global", "model", fv, feature, hour, *r)
                drifts += 1
    return drifts, newest


# --- state ------------------------------------------------------------------------------------
def _encode_state(det: Detectors, last_hour: dt.datetime) -> bytes:
    """Versioned, validated envelope (same shape as the HST checkpoint): a JSON header gates the
    pickle payload, so a format/library/version change forces a clean rebuild - never a bare pickle."""
    header = json.dumps({
        "format": STATE_FORMAT, "river": _river_version(), "drift_version": DRIFT_VERSION,
        "entities": det.entity_count(), "last_hour": last_hour.isoformat() if last_hour else None,
        "saved_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }).encode()
    payload = pickle.dumps({"detectors": det, "last_hour": last_hour}, protocol=pickle.HIGHEST_PROTOCOL)
    return header + b"\n" + payload


def _decode_state(data: bytes):
    nl = data.find(b"\n")
    if nl < 0:
        raise StateIncompatible("no header")
    try:
        head = json.loads(data[:nl])
    except ValueError as exc:
        raise StateIncompatible(f"bad header: {exc}") from exc
    if head.get("format") != STATE_FORMAT:
        raise StateIncompatible(f"format {head.get('format')} != {STATE_FORMAT}")
    if head.get("drift_version") != DRIFT_VERSION:
        raise StateIncompatible(f"drift version {head.get('drift_version')} != {DRIFT_VERSION}")
    if head.get("river") != _river_version():
        raise StateIncompatible(f"river {head.get('river')} != {_river_version()} (pickle not portable across versions)")
    body = pickle.loads(data[nl + 1:])      # only after the header validates
    if not isinstance(body.get("detectors"), Detectors):
        raise StateIncompatible("payload is not a Detectors")
    return body["detectors"], body["last_hour"]


def load_state():
    """Load the validated state, or re-warm from scratch on any mismatch/corruption."""
    try:
        with open(STATE_PATH, "rb") as f:
            return _decode_state(f.read())
    except FileNotFoundError:
        return Detectors(), None
    except (StateIncompatible, OSError, pickle.UnpicklingError, KeyError) as exc:
        log.warning("discarding drift state, re-warming: %s", exc)
        return Detectors(), None


def save_state(det: Detectors, last_hour: dt.datetime):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(_encode_state(det, last_hour))
    os.replace(tmp, STATE_PATH)


def _floor_hour(now: dt.datetime) -> dt.datetime:
    return now.replace(minute=0, second=0, microsecond=0)


def run_once(engine, ch, det: Detectors, last_hour, now=None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    until = _floor_hour(now)                                  # only COMPLETED hours
    if last_hour is None:
        last_hour = until - dt.timedelta(hours=BACKFILL_HOURS)
    if until <= last_hour:
        return {"drifts": 0, "last_hour": last_hour, "entities": det.entity_count()}
    drifts, new_last = process(engine, ch, det, last_hour, until)
    save_state(det, max(new_last, last_hour))
    return {"drifts": drifts, "last_hour": max(new_last, last_hour), "entities": det.entity_count()}


def _mlflow_log(result):
    try:
        import mlflow
        mlflow.set_experiment("behaviour-drift")
        with mlflow.start_run(run_name=f"{DRIFT_VERSION}-run"):
            mlflow.log_params({"drift_version": DRIFT_VERSION, "adwin_delta": ADWIN_DELTA,
                               "max_entities": MAX_ENTITIES, "interval_s": INTERVAL})
            mlflow.log_metrics({"drifts": result["drifts"], "entities": result["entities"]})
    except Exception as exc:  # noqa: BLE001 - MLflow trouble never stops drift detection
        log.warning("MLflow log skipped: %s", exc)


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser()
    p.add_argument("mode", nargs="?", default="loop", choices=["loop", "once"])
    a = p.parse_args(argv)
    engine, ch = db.engine(), db.clickhouse()
    det, last_hour = load_state()
    while True:
        try:
            r = run_once(engine, ch, det, last_hour)
            last_hour = r["last_hour"]
            if r["drifts"]:
                log.info("drift: %d events, %d entities, through %s", r["drifts"], r["entities"], r["last_hour"])
            _mlflow_log(r)
        except Exception:  # noqa: BLE001 - one bad cycle never stops the service
            log.exception("drift cycle failed")
        if a.mode == "once":
            return 0
        time.sleep(INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
