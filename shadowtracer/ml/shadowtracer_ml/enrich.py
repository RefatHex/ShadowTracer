"""ml-enricher (Phase 7.0): at incident close, compute features (features.py, the same module
training uses), store them in ClickHouse ml_incident_features (+ hourly ml_feature_stats for
drift), score with each served model loaded from MLflow by stage "Production", and write
ml_score / ml_reasons / ml_model / ml_scored_at to the incident. Scores are advisory: nothing
reads them to act. Runs the labeler every LABEL_INTERVAL_SECONDS.

  python -m shadowtracer_ml.enrich            # loop
  python -m shadowtracer_ml.enrich once       # one batch, prints what it did
  python -m shadowtracer_ml.enrich backfill --since 2026-11-06T00:00:00Z [--until ...]
                                              # re-score a closed window with the current served
                                              # models (idempotent: overwrites each incident by id +
                                              # model version, no duplicates - safe to re-run)
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


# The default enrich window start (Phase 7.4 item 6): config, not a hardcoded date. ML_SINCE wins if
# set; otherwise enrich_batch uses the SERVED MODEL's registration time (Models.since()) - a model
# never scores incidents that closed before it existed; older ones are a deliberate `backfill`. This
# fallback (7.0 data start) is used only before any model has loaded, and by anomaly/similar below,
# which have no model-registration time of their own.
SINCE_FALLBACK = "2026-11-06T11:25:00Z"   # 7.0 data start (first recorded run 11:28)
SINCE = os.environ.get("ML_SINCE", SINCE_FALLBACK)


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
        self.experimental: dict = {}   # key -> bool, from the model version's `experimental` tag (7.4 item 5)
        self.registered_at = None      # earliest served-version creation time, ms epoch (7.4 item 6)

    def get(self) -> dict:
        if time.monotonic() - self.at > (self.refresh if self.loaded else 60.0):
            import mlflow
            client = mlflow.MlflowClient()
            loaded, experimental, registered = {}, {}, None
            for name in self.names:
                try:
                    versions = client.get_latest_versions(name, stages=[STAGE])
                    if versions:
                        mv = versions[0]
                        key = f"{name}:{mv.version}"
                        loaded[key] = self.loaded.get(key) or mlflow.pyfunc.load_model(f"models:/{name}/{STAGE}")
                        experimental[key] = (mv.tags or {}).get("experimental") == "true"
                        if mv.creation_timestamp:
                            registered = mv.creation_timestamp if registered is None else min(registered, mv.creation_timestamp)
                except Exception:  # noqa: BLE001 - a missing/broken model leaves incidents unscored, never stops the worker
                    log.exception("loading %s/%s failed", name, STAGE)
            self.loaded, self.experimental, self.registered_at, self.at = loaded, experimental, registered, time.monotonic()
        return self.loaded

    def since(self) -> str:
        """Default enrich window start (7.4 item 6): explicit ML_SINCE wins; else the earliest served
        model's registration time (a model never auto-scores incidents that closed before it existed);
        else the 7.0-data fallback before anything has loaded."""
        if os.environ.get("ML_SINCE"):
            return os.environ["ML_SINCE"]
        if self.registered_at:
            return dt.datetime.fromtimestamp(self.registered_at / 1000, dt.timezone.utc).isoformat()
        return SINCE_FALLBACK


_INCIDENT_COLS = (
    "id, tenant_key, first_seen, last_seen, closed_at, alert_count, max_level, rule_ids, rule_groups, "
    "source_ip_total, user_total, correlation_basis, rare_pattern_flag, prior_occurrences, ti_confidence")


def _score_and_store(conn, ch, models: Models, served: dict, incs: list) -> list:
    """Compute+store features, predict with every served model, and write one ml_reasons row per
    incident. Shared by the daemon (enrich_batch) and the backfill tool. The UPDATE is keyed by
    incident id and the models dict is keyed by name:version, so re-scoring the same incident with
    the same model versions overwrites in place - idempotent, never duplicated (7.4 item 6)."""
    feats = [incident_features(conn, ch, i) for i in incs]
    now = dt.datetime.now(dt.timezone.utc)
    store_features(ch, [features.to_row(i["tenant_key"], i["id"], i["closed_at"], f, now) for i, f in zip(incs, feats)])
    X = features.model_input(feats)
    outputs = {key: model.predict(X) for key, model in served.items()}
    primary = next(iter(outputs))
    for n, inc in enumerate(incs):
        per_model = {}
        for k, o in outputs.items():
            entry = {"score": round(float(o["score"].iloc[n]), 4), "reasons": json.loads(o["reasons"].iloc[n])}
            if "label" in o.columns:  # Phase 7.4 classifier: class + probability + experimental flag
                entry["class"] = o["label"].iloc[n]
                entry["prob"] = round(float(o["prob"].iloc[n]), 4)
                entry["experimental"] = bool(models.experimental.get(k, False))   # 7.4 item 5: shown in the panel
            per_model[k] = entry
        conn.execute(text(
            "UPDATE incidents SET ml_score = :s, ml_reasons = CAST(:r AS jsonb), ml_model = :m, ml_scored_at = now() "
            "WHERE id = :i"),
            {"s": per_model[primary]["score"], "m": primary, "i": inc["id"],
             "r": json.dumps({"feature_version": features.FEATURE_VERSION, "models": per_model})})
    return list(outputs)


def enrich_batch(engine, ch, models: Models, tenant_list: list, limit: int = BATCH,
                 since: str = None, until: str = None, rescore: bool = False, after=None) -> dict:
    served = models.get()
    if not served:
        return {"incidents": 0, "models": []}             # no Production model yet: leave incidents for later
    conds = ["state = 'closed'", "tenant_key = ANY(:t)", "closed_at >= CAST(:since AS timestamptz)"]
    params = {"t": tenant_list, "n": limit, "since": since or models.since()}
    if not rescore:                                       # daemon: only unscored incidents
        conds.append("ml_scored_at IS NULL")
    if until:                                             # backfill: bounded window
        conds.append("closed_at < CAST(:until AS timestamptz)"); params["until"] = until
    if after:                                             # backfill: (closed_at, id) keyset cursor
        conds.append("(closed_at, id) > (CAST(:acat AS timestamptz), :aid)")
        params["acat"], params["aid"] = after
    sql = (f"SELECT {_INCIDENT_COLS} FROM incidents WHERE " + " AND ".join(conds)
           + " ORDER BY closed_at, id LIMIT :n FOR UPDATE SKIP LOCKED")
    with engine.begin() as conn:
        incs = [dict(r._mapping) for r in conn.execute(text(sql), params)]
        if not incs:
            return {"incidents": 0}
        model_list = _score_and_store(conn, ch, models, served, incs)
    return {"incidents": len(incs), "models": model_list, "first_id": incs[0]["id"],
            "cursor": (incs[-1]["closed_at"], incs[-1]["id"])}


def backfill(engine, ch, models: Models, tenant_list: list, since: str, until: str = None) -> dict:
    """Re-score every closed incident in [since, until) with the current served models, paging by a
    (closed_at, id) keyset cursor. Idempotent (overwrites by incident id + model version); a one-shot
    operator tool for picking up a newly added/retrained model on older incidents the daemon window
    skips. 7.4 item 6."""
    if not models.get():
        return {"backfilled": 0, "error": "no served model"}
    total, cursor, batches = 0, None, 0
    while True:
        r = enrich_batch(engine, ch, models, tenant_list, since=since, until=until, rescore=True, after=cursor)
        if not r["incidents"]:
            break
        total += r["incidents"]; cursor = r["cursor"]; batches += 1
        log.info("backfill %s", {"scored_so_far": total, "through_closed_at": str(cursor[0]), "models": r["models"]})
    return {"backfilled": total, "batches": batches, "since": since, "until": until}


def anomaly_batch(engine, ch, tenant_list: list, limit: int = BATCH) -> dict:
    """7.1: set each newly closed incident's anomaly = MAX of its alerts' warm HST scores
    (ClickHouse ml_scores), with that alert's reasons. Independent of the supervised model, so it
    runs even when no model is served. An incident whose alerts were never warm-scored (warm-up or
    scorer down at the time) is marked done with a NULL score - late scores are not backfilled."""
    from .hst import MODEL_VERSION
    with engine.begin() as conn:
        incs = conn.execute(text(
            "SELECT id, tenant_key FROM incidents WHERE state = 'closed' AND ml_anomaly_model IS NULL "
            "AND tenant_key = ANY(:t) AND closed_at >= CAST(:since AS timestamptz) "
            "ORDER BY closed_at LIMIT :n FOR UPDATE SKIP LOCKED"), {"t": tenant_list, "n": limit, "since": SINCE}).all()
        if not incs:
            return {"incidents": 0}
        scored = 0
        for inc in incs:
            pairs = [(r[0], r[1]) for r in conn.execute(text(
                "SELECT node, alert_id FROM incident_alerts WHERE incident_id = :i"), {"i": inc.id})]
            best = (None, None)
            # chunk the identity list: a big replay incident has tens of thousands of alerts, more
            # than one ClickHouse HTTP query (its IN list) can carry. Max over chunks is exact.
            for i in range(0, len(pairs), 2000):
                # count() gates the aggregate: ClickHouse max() over an EMPTY match returns 0.0 (score
                # is non-nullable), not NULL - so an incident with no warm-scored alert must be told
                # apart from one that genuinely scored 0, or every un-scored incident looks like 0.
                n, mx, rsn = ch.query(
                    "SELECT count(), max(score), argMax(reasons, score) FROM ml_scores WHERE tenant_id = {t:String} "
                    "AND model_version = {v:String} AND warm = 1 AND (cluster_node, alert_id) IN {p:Array(Tuple(String,String))}",
                    parameters={"t": inc.tenant_key, "v": MODEL_VERSION, "p": pairs[i:i + 2000]}).result_rows[0]
                if n and (best[0] is None or float(mx) > best[0]):
                    best = (round(float(mx), 4), rsn or "[]")
            conn.execute(text("UPDATE incidents SET ml_anomaly_score = :s, ml_anomaly_reasons = CAST(:r AS jsonb), "
                              "ml_anomaly_model = :m WHERE id = :i"),
                         {"s": best[0], "r": best[1], "m": MODEL_VERSION, "i": inc.id})
            scored += best[0] is not None
    return {"incidents": len(incs), "with_score": scored}


def _load_similar():
    """Phase 7.5: load the embedding model + Qdrant index once. Returns (embedder, index,
    internal_ranges) or None if 7.5 is disabled/unavailable - the enricher runs fine without it."""
    if os.environ.get("ML_SIMILAR", "1") == "0" or not os.environ.get("QDRANT_URL"):
        return None
    try:
        from . import similar
        ir = [r.strip() for r in os.environ.get("INTERNAL_IP_RANGES", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",") if r.strip()]
        emb, idx = similar.Embedder(), similar.QdrantIndex()
        log.info("similar-incidents: model %s loaded, qdrant has %d vectors", emb.model_name, idx.count())
        return emb, idx, ir
    except Exception:  # noqa: BLE001 - never let 7.5 setup stop the core enricher
        log.exception("similar-incidents setup failed; continuing without it")
        return None


def similar_batch(engine, ch, sim, tenant_list, limit=BATCH) -> dict:
    from . import similar
    emb, idx, ir = sim
    r = similar.embed_batch(engine, ch, emb, idx, tenant_list, ir, limit=limit)
    if r["indexed"]:
        similar._mlflow_log(r)
    return r


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    argv = argv if argv is not None else sys.argv[1:]
    engine, ch = db.engine(), db.clickhouse()
    models = Models([m for m in os.environ.get("ML_SERVED_MODELS", "incident-risk-dummy").split(",") if m])
    tl = tenants()
    sim = _load_similar()
    if argv[:1] == ["once"]:
        out = {"supervised": enrich_batch(engine, ch, models, tl), "anomaly": anomaly_batch(engine, ch, tl)}
        if sim:
            out["similar"] = similar_batch(engine, ch, sim, tl)
        print(json.dumps(out, default=str))
        return 0
    if argv[:1] == ["backfill"]:
        import argparse
        ap = argparse.ArgumentParser(prog="enrich backfill")
        ap.add_argument("--since", required=True, help="ISO-8601, inclusive")
        ap.add_argument("--until", help="ISO-8601, exclusive (default: now)")
        a = ap.parse_args(argv[1:])
        print(json.dumps(backfill(engine, ch, models, tl, a.since, a.until), default=str))
        return 0
    poll = float(os.environ.get("ML_POLL_SECONDS", "15"))
    label_every = float(os.environ.get("LABEL_INTERVAL_SECONDS", "300"))
    consistency_every = float(os.environ.get("ML_SIM_CONSISTENCY_SECONDS", "3600"))
    last_label = last_consistency = 0.0
    while True:
        try:
            r = enrich_batch(engine, ch, models, tl)
            if r["incidents"]:
                log.info("enriched %s", r)
            a = anomaly_batch(engine, ch, tl)
            if a["incidents"]:
                log.info("anomaly %s", a)
            s = {"indexed": 0}
            if sim:
                s = similar_batch(engine, ch, sim, tl)
                if s["indexed"]:
                    log.info("similar %s", s)
                if time.monotonic() - last_consistency > consistency_every:
                    from . import similar
                    log.info("similar consistency %s", json.dumps(similar.purge_consistency(engine, sim[1], tl)))
                    last_consistency = time.monotonic()
            if time.monotonic() - last_label > label_every:
                for t in tl:
                    log.info("labels %s", json.dumps(labels.run_all(engine, ch, t), default=str))
                last_label = time.monotonic()
            if r["incidents"] >= BATCH or a["incidents"] >= BATCH or s["indexed"] >= BATCH:
                continue
        except Exception:  # noqa: BLE001 - keep the worker alive; the batch is retried
            log.exception("enrich batch failed")
        time.sleep(poll)


if __name__ == "__main__":
    sys.exit(main())
