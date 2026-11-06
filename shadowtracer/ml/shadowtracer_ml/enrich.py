"""ml-enricher (Phase 7.0): at incident close, compute features (features.py, the same module
training uses), store them in ClickHouse ml_incident_features (+ hourly ml_feature_stats for
drift), score with each served model loaded from MLflow by stage "Production", and write
ml_score / ml_reasons / ml_model / ml_scored_at to the incident. Scores are advisory: nothing
reads them to act. Runs the labeler every LABEL_INTERVAL_SECONDS.

  python -m shadowtracer_ml.enrich            # loop
  python -m shadowtracer_ml.enrich once       # one batch, prints what it did
"""
import collections
import datetime as dt
import json
import logging
import os
import sys
import time

from sqlalchemy import text

from . import db, features, labels

log = logging.getLogger("ml-enricher")
BATCH = 200
STAGE = "Production"


# Only incidents closed after this are enriched: older test-tenant incidents are load-test traffic.
SINCE = os.environ.get("ML_SINCE", "2026-11-06T11:25:00Z")   # 7.0 data start (first recorded run 11:28)


def tenants(env=os.environ) -> list:
    return [t for t in env.get("ML_TENANTS", db.test_tenant(env)).split(",") if t]


def incident_alerts(conn, ch, inc) -> list:
    """The incident's earliest MAX_ALERTS alerts up to its close (ClickHouse events)."""
    rows = conn.execute(text(
        "SELECT node, alert_id FROM incident_alerts WHERE incident_id = :i AND alert_time <= :c ORDER BY alert_time, id LIMIT :n"),
        {"i": inc["id"], "c": inc["closed_at"], "n": features.MAX_ALERTS}).all()
    if not rows:
        return []
    return [dict(zip(("time", "rule_level", "rule_groups", "mitre_tactics"), r)) for r in ch.query(
        "SELECT time, rule_level, rule_groups, mitre_tactics FROM events WHERE tenant_id = {t:String} "
        "AND time BETWEEN {a:DateTime64(3)} - INTERVAL 5 MINUTE AND {b:DateTime64(3)} + INTERVAL 5 MINUTE "
        "AND (cluster_node, alert_id) IN {ids:Array(Tuple(String, String))}",
        parameters={"t": inc["tenant_key"], "a": inc["first_seen"], "b": inc["closed_at"],
                    "ids": [(r[0], r[1]) for r in rows]}).result_rows]


def incident_features(conn, ch, inc) -> dict:
    """The serving-side feature path; tests/test_parity.py checks it equals the stored row."""
    alerts = [dict(a, time=a["time"].replace(tzinfo=dt.timezone.utc) if a["time"].tzinfo is None else a["time"])
              for a in incident_alerts(conn, ch, inc)]
    return features.compute(dict(inc), alerts)


def store_features(ch, rows: list) -> None:
    if not rows:
        return
    ch.insert("ml_incident_features", rows,
              column_names=["tenant_id", "incident_id", "feature_version", "closed_at", "computed_at", "features"])
    stats = collections.defaultdict(lambda: [0, 0.0, 0.0])
    for r in rows:
        hour = r[3].replace(minute=0, second=0, microsecond=0)
        for k, v in r[5].items():
            s = stats[(hour, k)]
            s[0] += 1
            s[1] += v
            s[2] += v * v
    ch.insert("ml_feature_stats", [[h, features.FEATURE_VERSION, k, n, s, s2] for (h, k), (n, s, s2) in stats.items()],
              column_names=["hour", "feature_version", "feature", "n", "sum", "sum_sq"])


class Models:
    """Served models by stage; reloaded every refresh so a stage change takes effect without a restart."""

    def __init__(self, names: list, refresh: float = 300.0):
        self.names, self.refresh, self.loaded, self.at = names, refresh, {}, 0.0

    def get(self) -> dict:
        if time.monotonic() - self.at > (self.refresh if self.loaded else 60.0):
            import mlflow
            client = mlflow.MlflowClient()
            loaded = {}
            for name in self.names:
                try:
                    versions = client.get_latest_versions(name, stages=[STAGE])
                    if versions:
                        v = versions[0].version
                        key = f"{name}:{v}"
                        loaded[key] = self.loaded.get(key) or mlflow.pyfunc.load_model(f"models:/{name}/{STAGE}")
                except Exception:  # noqa: BLE001 - a missing/broken model leaves incidents unscored, never stops the worker
                    log.exception("loading %s/%s failed", name, STAGE)
            self.loaded, self.at = loaded, time.monotonic()
        return self.loaded


def enrich_batch(engine, ch, models: Models, tenant_list: list, limit: int = BATCH) -> dict:
    served = models.get()
    if not served:
        return {"incidents": 0, "models": []}             # no Production model yet: leave incidents for later
    with engine.begin() as conn:
        incs = [dict(r._mapping) for r in conn.execute(text(
            "SELECT id, tenant_key, first_seen, last_seen, closed_at, alert_count, max_level, rule_ids, rule_groups, "
            "source_ip_total, user_total, correlation_basis, rare_pattern_flag, prior_occurrences, ti_confidence "
            "FROM incidents WHERE state = 'closed' AND ml_scored_at IS NULL AND tenant_key = ANY(:t) "
            "AND closed_at >= CAST(:since AS timestamptz) ORDER BY closed_at LIMIT :n FOR UPDATE SKIP LOCKED"),
            {"t": tenant_list, "n": limit, "since": SINCE})]
        if not incs:
            return {"incidents": 0}
        feats = [incident_features(conn, ch, i) for i in incs]
        now = dt.datetime.now(dt.timezone.utc)
        store_features(ch, [features.to_row(i["tenant_key"], i["id"], i["closed_at"], f, now) for i, f in zip(incs, feats)])
        X = features.model_input(feats)
        outputs = {}
        for key, model in served.items():
            outputs[key] = model.predict(X)
        primary = next(iter(outputs))
        for n, inc in enumerate(incs):
            per_model = {k: {"score": round(float(o["score"].iloc[n]), 4), "reasons": json.loads(o["reasons"].iloc[n])}
                         for k, o in outputs.items()}
            conn.execute(text(
                "UPDATE incidents SET ml_score = :s, ml_reasons = CAST(:r AS jsonb), ml_model = :m, ml_scored_at = now() "
                "WHERE id = :i"),
                {"s": per_model[primary]["score"], "m": primary, "i": inc["id"],
                 "r": json.dumps({"feature_version": features.FEATURE_VERSION, "models": per_model})})
    return {"incidents": len(incs), "models": list(outputs), "first_id": incs[0]["id"]}


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    argv = argv if argv is not None else sys.argv[1:]
    engine, ch = db.engine(), db.clickhouse()
    models = Models([m for m in os.environ.get("ML_SERVED_MODELS", "incident-risk-dummy").split(",") if m])
    tl = tenants()
    if argv[:1] == ["once"]:
        print(json.dumps(enrich_batch(engine, ch, models, tl), default=str))
        return 0
    poll = float(os.environ.get("ML_POLL_SECONDS", "15"))
    label_every = float(os.environ.get("LABEL_INTERVAL_SECONDS", "300"))
    last_label = 0.0
    while True:
        try:
            r = enrich_batch(engine, ch, models, tl)
            if r["incidents"]:
                log.info("enriched %s", r)
            if time.monotonic() - last_label > label_every:
                for t in tl:
                    log.info("labels %s", json.dumps(labels.run_all(engine, ch, t), default=str))
                last_label = time.monotonic()
            if r["incidents"] >= BATCH:
                continue
        except Exception:  # noqa: BLE001 - keep the worker alive; the batch is retried
            log.exception("enrich batch failed")
        time.sleep(poll)


if __name__ == "__main__":
    sys.exit(main())
