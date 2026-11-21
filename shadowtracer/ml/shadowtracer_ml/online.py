"""Phase 7.3: River Adaptive Random Forest ONLINE classifier (incident-online).

An online counterpart to the 7.4 XGBoost model. Same features (features.py, shared), scored at incident
close in the enrichment worker, OFF the hot path. ADVISORY ONLY - stored class/probability/version and
shown in the console as a second "Online model" row, never used to suppress, auto-close or block.

It learns continuously with `learn_one`, but ONLY from LABELLED incidents - analyst verdicts
(origin=analyst_verdict) and ART attack runs (origin=attack_window). It NEVER learns from an
unlabelled incident or from its own predictions. Guard-rails:
  - Every learn is AUDITED (online_learn_log: analyst, time, incident, label, checkpoint version).
  - Learning is RATE-CAPPED per analyst per hour, so one analyst's bad batch of verdicts can't flood it.
  - River state is a pickle, so checkpoints are HMAC-SIGNED with a secret and VERIFIED before load -
    a tampered or unsigned checkpoint is REFUSED (never unpickled). Checkpoints are versioned in MLflow.
  - `rollback` restores an earlier checkpoint with one command and flags the bad batch so it isn't
    re-learned.

CLI:
  python -m shadowtracer_ml.online train        # learn new labelled incidents, checkpoint
  python -m shadowtracer_ml.online rollback      # restore the previous checkpoint (bad verdict batch)
  python -m shadowtracer_ml.online eval          # prequential + leave-one-source-out (no learning kept)
"""
import argparse
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import pickle
import sys
import tempfile

import numpy as np

from . import db, features
from .enrich import _INCIDENT_COLS, incident_features
from .evaluate import git_commit, source_family

MODEL_NAME = "incident-online"
EXPERIMENT = "incident-online"
STAGE = "Production"
SEED = 7
N_MODELS = 10
KEEP_CHECKPOINTS = 5
# Learn at most this many analyst-verdict incidents per analyst per rolling hour. ART runs
# (attack_window, source 'art') are automated and not rate-capped.
LEARN_CAP_PER_ANALYST_PER_HOUR = int(os.environ.get("ONLINE_LEARN_CAP_PER_ANALYST_PER_HOUR", "20"))
LEARN_ORIGINS = ("analyst_verdict", "attack_window")


# ---------------------------------------------------------------- the model
def new_model():
    from river.forest import ARFClassifier
    return ARFClassifier(n_models=N_MODELS, seed=SEED)


def _x(feats: dict) -> dict:
    # River wants a flat {feature: number} dict; our feature vector already is one.
    return {k: float(v) for k, v in feats.items()}


def predict(model, feats: dict) -> tuple:
    """-> (label, prob_attack). Threshold 0.5 (online model: no tuned threshold)."""
    proba = model.predict_proba_one(_x(feats)) or {}
    p = float(proba.get(1, 0.0))
    return ("attack" if p >= 0.5 else "benign"), round(p, 4)


def learn_one(model, feats: dict, label: str) -> None:
    model.learn_one(_x(feats), 1 if label == "attack" else 0)


# ---------------------------------------------------------------- signed checkpoints (never an unsigned pickle load)
def _secret() -> bytes:
    s = os.environ.get("ONLINE_MODEL_SECRET", "")
    if not s:
        raise SystemExit("ONLINE_MODEL_SECRET is not set - refusing to sign/verify checkpoints without a key")
    return s.encode()


def sign(blob: bytes) -> str:
    return hmac.new(_secret(), blob, hashlib.sha256).hexdigest()


def verify(blob: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(blob), signature or "")


def _dump(model) -> bytes:
    buf = io.BytesIO()
    pickle.dump(model, buf, protocol=pickle.HIGHEST_PROTOCOL)
    return buf.getvalue()


def load_checkpoint_bytes(blob: bytes, signature: str):
    """Verify the HMAC, THEN unpickle. A bad/absent signature raises before pickle.loads ever runs."""
    if not verify(blob, signature):
        raise ValueError("online checkpoint HMAC mismatch - refusing to load (tampered or wrong key)")
    return pickle.loads(blob)   # safe: only reached after the signature verified


# ---------------------------------------------------------------- MLflow versioning
def save_checkpoint(model, meta: dict) -> str:
    """Sign + log the checkpoint as MLflow artifacts, register a new incident-online version from those
    artifacts, promote it to Production (always experimental), and prune old versions. Returns the new
    version string. The checkpoint is a signed pickle (not an MLflow model flavor), so the version is
    created with create_model_version pointing at the artifact URI, not register_model."""
    import mlflow
    blob = _dump(model)
    meta = {**meta, "signed": True, "hmac_sha256": sign(blob)[:12] + "...", "git_commit": git_commit(),
            "feature_version": features.FEATURE_VERSION, "saved_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    client = mlflow.MlflowClient()
    try:
        client.create_registered_model(MODEL_NAME)
    except Exception:  # noqa: BLE001 - already exists
        pass
    mlflow.set_experiment(EXPERIMENT)
    with mlflow.start_run(run_name=f"arf-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%S}") as run:
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "checkpoint.pkl"), "wb").write(blob)
            open(os.path.join(d, "checkpoint.sig"), "w").write(sign(blob))
            json.dump(meta, open(os.path.join(d, "meta.json"), "w"), indent=1)
            mlflow.log_artifacts(d, artifact_path="checkpoint")
        mlflow.log_metrics({k: v for k, v in meta.items() if isinstance(v, (int, float))})
        source = mlflow.get_artifact_uri("checkpoint")
    mv = client.create_model_version(MODEL_NAME, source=source, run_id=run.info.run_id)
    client.set_model_version_tag(MODEL_NAME, mv.version, "experimental", "true")
    client.set_model_version_tag(MODEL_NAME, mv.version, "signed", "true")
    client.transition_model_version_stage(MODEL_NAME, mv.version, STAGE, archive_existing_versions=True)
    _prune(client)
    return str(mv.version)


def _prune(client) -> None:
    versions = sorted(client.search_model_versions(f"name='{MODEL_NAME}'"), key=lambda v: int(v.version), reverse=True)
    for v in versions[KEEP_CHECKPOINTS:]:
        try:
            client.delete_model_version(MODEL_NAME, v.version)
        except Exception:  # noqa: BLE001 - pruning is best-effort
            pass


def load_production():
    """-> (model, version) from the Production checkpoint (HMAC-verified), or (fresh model, None) when
    no checkpoint exists yet (first run: the registered model is absent, so bootstrap a fresh ARF)."""
    import mlflow
    from mlflow.exceptions import RestException
    client = mlflow.MlflowClient()
    try:
        versions = client.get_latest_versions(MODEL_NAME, stages=[STAGE])
    except RestException:
        versions = []   # model not registered yet -> fresh model, first checkpoint will create it
    if not versions:
        return new_model(), None
    v = versions[0]
    local = mlflow.artifacts.download_artifacts(run_id=v.run_id, artifact_path="checkpoint")
    blob = open(os.path.join(local, "checkpoint.pkl"), "rb").read()
    sig = open(os.path.join(local, "checkpoint.sig")).read().strip()
    return load_checkpoint_bytes(blob, sig), str(v.version)


def versions_desc(client=None) -> list:
    import mlflow
    client = client or mlflow.MlflowClient()
    return sorted(client.search_model_versions(f"name='{MODEL_NAME}'"), key=lambda v: int(v.version), reverse=True)


# ---------------------------------------------------------------- the labelled learning stream
def _learn_candidates(engine, tenant: str) -> list:
    """Labelled incidents (analyst verdicts + ART runs) NOT yet learned, oldest first. Each carries the
    approving analyst (for the per-analyst cap) - 'art' for an automated attack_window run."""
    from sqlalchemy import text
    with engine.begin() as conn:
        rows = conn.execute(text(
            "SELECT l.incident_id, l.label, l.origin, i.closed_at, "
            "  COALESCE((SELECT min(r.analyst) FROM ml_verdict_reviews r "
            "            WHERE r.incident_id = l.incident_id AND r.tenant_key = l.tenant_key AND r.approved), 'art') AS analyst "
            "FROM ml_labels l JOIN incidents i ON i.id = l.incident_id "
            "WHERE l.tenant_key = :t AND l.origin = ANY(:origins) AND i.state = 'closed' "
            "  AND NOT EXISTS (SELECT 1 FROM online_learn_log o WHERE o.incident_id = l.incident_id AND o.tenant_key = :t) "
            "ORDER BY i.closed_at, l.incident_id"),
            {"t": tenant, "origins": list(LEARN_ORIGINS)}).mappings().all()
    return [dict(r) for r in rows]


def _fetch_features(engine, ch, tenant: str, incident_id: int) -> dict | None:
    from sqlalchemy import text
    with engine.begin() as conn:
        inc = conn.execute(text(f"SELECT {_INCIDENT_COLS} FROM incidents WHERE id = :i AND tenant_key = :t"),
                           {"i": incident_id, "t": tenant}).mappings().first()
        if inc is None:
            return None
        return incident_features(conn, ch, dict(inc))


def _analyst_hour_count(engine, tenant: str, analyst: str) -> int:
    from sqlalchemy import text
    with engine.begin() as conn:
        return conn.execute(text(
            "SELECT count(*) FROM online_learn_log WHERE tenant_key = :t AND analyst = :a "
            "AND learned_at > now() - interval '1 hour'"), {"t": tenant, "a": analyst}).scalar_one()


def learn_new(engine, ch, tenant: str, model, log=None) -> dict:
    """Predict-then-learn each new labelled incident (oldest first) IN MEMORY, enforcing the per-analyst
    hourly cap. Returns the learned batch; the caller saves the checkpoint and ONLY THEN records the
    audit log (record_learned) - so a failed checkpoint never marks an incident as learned."""
    cands = _learn_candidates(engine, tenant)
    learned, capped, skipped = [], 0, 0
    per_analyst_added: dict = {}
    for c in cands:
        analyst = c["analyst"]
        if analyst != "art":   # human verdicts are rate-capped; ART runs are not
            used = _analyst_hour_count(engine, tenant, analyst) + per_analyst_added.get(analyst, 0)
            if used >= LEARN_CAP_PER_ANALYST_PER_HOUR:
                capped += 1
                continue
        feats = _fetch_features(engine, ch, tenant, c["incident_id"])
        if feats is None:
            skipped += 1
            continue
        learn_one(model, feats, c["label"])           # only labelled data, never a prediction
        per_analyst_added[analyst] = per_analyst_added.get(analyst, 0) + 1
        learned.append({"incident_id": c["incident_id"], "label": c["label"], "origin": c["origin"], "analyst": analyst})
    out = {"learned": len(learned), "capped": capped, "skipped_no_features": skipped, "candidates": len(cands),
           "batch": learned}
    if log:
        log.info("online learn %s", {k: v for k, v in out.items() if k != "batch"})
    return out


def record_learned(engine, tenant: str, batch: list, version: str) -> None:
    """Audit the learned batch AFTER its checkpoint saved, tagged with that checkpoint's version."""
    from sqlalchemy import text
    with engine.begin() as conn:
        for it in batch:
            conn.execute(text(
                "INSERT INTO online_learn_log (tenant_key, incident_id, label, origin, analyst, checkpoint_version) "
                "VALUES (:t, :i, :l, :o, :a, :v) ON CONFLICT (tenant_key, incident_id) DO NOTHING"),
                {"t": tenant, "i": it["incident_id"], "l": it["label"], "o": it["origin"], "a": it["analyst"], "v": version})


# ---------------------------------------------------------------- rollback
def rollback(to_version: str = None) -> dict:
    """Restore an earlier checkpoint to Production (default: the one before the current), and flag the
    rolled-back batch in online_learn_log so the reverted model never re-learns it. One command."""
    import mlflow
    client = mlflow.MlflowClient()
    vs = versions_desc(client)
    if len(vs) < 2:
        return {"error": "need at least two checkpoints to roll back", "have": len(vs)}
    current = max(int(v.version) for v in vs if v.current_stage == STAGE) if any(v.current_stage == STAGE for v in vs) else int(vs[0].version)
    target = int(to_version) if to_version else max((int(v.version) for v in vs if int(v.version) < current), default=None)
    if target is None:
        return {"error": "no earlier checkpoint to roll back to", "current": current}
    client.transition_model_version_stage(MODEL_NAME, str(target), STAGE, archive_existing_versions=True)
    # Flag every learn folded into a checkpoint newer than the target, so it is not re-learned.
    engine = db.engine()
    from sqlalchemy import text
    with engine.begin() as conn:
        flagged = conn.execute(text(
            "UPDATE online_learn_log SET rolled_back = true "
            "WHERE checkpoint_version IS NOT NULL AND checkpoint_version::int > :target AND NOT rolled_back"),
            {"target": target}).rowcount
    return {"rolled_back_to": target, "from": current, "learn_rows_flagged": flagged}


# ---------------------------------------------------------------- offline evaluation (no state kept)
def _metrics(y: np.ndarray, pred: np.ndarray) -> dict:
    out, f1s = {}, []
    for cls, name in ((1, "attack"), (0, "benign")):
        yc, pc = (y == cls), (pred == cls)
        tp = int((yc & pc).sum())
        prec = tp / int(pc.sum()) if pc.sum() else None
        rec = tp / int(yc.sum()) if yc.sum() else None
        f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else 0.0
        out[f"{name}_precision"], out[f"{name}_recall"] = _r(prec), _r(rec)
        f1s.append(f1)
    out["macro_f1"] = round(float(np.mean(f1s)), 3)
    return out


def _r(v):
    return round(float(v), 3) if v is not None else None


def _labelled_stream(engine, ch, tenant: str) -> list:
    """All analyst+ART labelled incidents with features, oldest first - the offline eval stream."""
    cands = _learn_candidates_all(engine, tenant)
    items = []
    for c in cands:
        feats = _fetch_features(engine, ch, tenant, c["incident_id"])
        if feats is not None:
            items.append({**c, "features": feats, "y": 1 if c["label"] == "attack" else 0})
    return items


def _learn_candidates_all(engine, tenant: str) -> list:
    """Like _learn_candidates but ignoring online_learn_log (for offline eval over the whole stream)."""
    from sqlalchemy import text
    with engine.begin() as conn:
        rows = conn.execute(text(
            "SELECT l.incident_id, l.label, l.origin, l.source, i.closed_at "
            "FROM ml_labels l JOIN incidents i ON i.id = l.incident_id "
            "WHERE l.tenant_key = :t AND l.origin = ANY(:origins) AND i.state = 'closed' "
            "ORDER BY i.closed_at, l.incident_id"),
            {"t": tenant, "origins": list(LEARN_ORIGINS)}).mappings().all()
    return [dict(r) for r in rows]


def prequential_eval(items: list) -> dict:
    """Predict-then-learn over the stream in time order (interleaved test-then-train). Reports the
    model's online metrics plus a rules-only baseline (max rule level) on the same predictions."""
    if len({i["y"] for i in items}) < 2:
        return {"skipped": "stream is single-class", "n": len(items),
                "classes": [sum(1 for i in items if i["y"] == 0), sum(1 for i in items if i["y"] == 1)]}
    model = new_model()
    y, pred, base = [], [], []
    for it in items:
        p = model.predict_proba_one(_x(it["features"])) or {}
        pred.append(1 if float(p.get(1, 0.0)) >= 0.5 else 0)
        base.append(1 if float(it["features"].get("max_level", 0)) >= 10 else 0)   # rules-only: level>=10 -> attack
        y.append(it["y"])
        learn_one(model, it["features"], it["label"])
    y = np.array(y)
    return {"n": len(items), "classes": [int((y == 0).sum()), int((y == 1).sum())],
            "model": _metrics(y, np.array(pred)), "rules_only": _metrics(y, np.array(base))}


def leave_one_source_out(items: list) -> dict:
    """Train on two source families, test on the third held-out one (as in 7.4). Online: learn the
    train stream in time order, then predict the held-out set without learning it."""
    fams = sorted({source_family(i["source"]) for i in items})
    out = {}
    for fam in fams:
        test = [i for i in items if source_family(i["source"]) == fam]
        train = [i for i in items if source_family(i["source"]) != fam]
        yte = np.array([i["y"] for i in test])
        if len(test) == 0 or len({i["y"] for i in train}) < 2:
            out[fam] = {"skipped": "empty held-out or single-class train", "test_n": len(test),
                        "test_classes": [int((yte == 0).sum()), int((yte == 1).sum())]}
            continue
        model = new_model()
        for it in train:
            learn_one(model, it["features"], it["label"])
        pred = np.array([1 if float((model.predict_proba_one(_x(i["features"])) or {}).get(1, 0.0)) >= 0.5 else 0 for i in test])
        m = _metrics(yte, pred)
        out[fam] = {"test_n": len(test), "test_classes": [int((yte == 0).sum()), int((yte == 1).sum())], **m}
    collapsed = [f for f, r in out.items() if "skipped" in r or (r.get("macro_f1") or 0) < 0.6]
    return {"by_source": out, "collapsed": collapsed}


# ---------------------------------------------------------------- run / CLI
def run_train(engine, ch, tenant: str, log=None) -> dict:
    model, version = load_production()
    res = learn_new(engine, ch, tenant, model, log=log)
    batch = res.pop("batch")
    if batch:
        saved = save_checkpoint(model, {"n_learned_batch": len(batch), "base_version": version or "none"})
        record_learned(engine, tenant, batch, saved)   # audit ONLY after the checkpoint persisted
        res["checkpoint_version"] = saved
    else:
        res["checkpoint_version"] = version   # nothing new; keep the current checkpoint
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="shadowtracer_ml.online")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("train")
    rb = sub.add_parser("rollback")
    rb.add_argument("--to-version")
    sub.add_parser("eval")
    args = ap.parse_args(argv)
    tenant = db.test_tenant()   # TEST tenant only - never main tenant data
    if args.cmd == "train":
        print(json.dumps(run_train(db.engine(), db.clickhouse(), tenant), default=str, indent=1))
    elif args.cmd == "rollback":
        print(json.dumps(rollback(args.to_version), default=str, indent=1))
    elif args.cmd == "eval":
        items = _labelled_stream(db.engine(), db.clickhouse(), tenant)
        print(json.dumps({"n": len(items), "prequential": prequential_eval(items),
                          "leave_one_source_out": leave_one_source_out(items)}, default=str, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
