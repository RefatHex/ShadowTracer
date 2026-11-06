"""Training / evaluation / promotion (Phase 7.0, docs/ML_FOUNDATION.md). Runs where MLflow is
reachable (inside the lab network):

  docker compose run --rm -e GIT_COMMIT=$(git rev-parse HEAD) ml-enricher python -m shadowtracer_ml.evaluate run [--test-set FILE]
  docker compose run --rm ml-enricher python -m shadowtracer_ml.evaluate register-dummy

Rules enforced here (tests/test_evaluate.py):
  * split by TIME and GROUP: a group is an attack/normal run or a replayed dataset (analyst and TI
    labels are their own group); groups are ordered by first close time, the last TEST_FRAC go to
    test, the VAL_FRAC before them to validation. No group spans two splits.
  * the test set is fixed per evaluation, logged (test_set.json) and can be pinned (--test-set).
  * class imbalance: class_weight="balanced".
  * metrics: recall, precision, PR-AUC, false alerts/day - never accuracy.
  * every model is compared with the rule-level baseline (max rule level) on the same test set;
    thresholds for both are chosen on VALIDATION only; promotion only if the model beats the
    baseline (higher PR-AUC and recall not lower) and the test set has both classes.
  * cross-source evaluation: each source family held out in turn.
  * logged: seed, label snapshot hash, feature version, git commit, datasets used, model card.
Models never trigger actions; Production only means "scores shown to analysts".
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile

import numpy as np

from . import db, features

SEED = 7
VAL_FRAC, TEST_FRAC = 0.15, 0.2
MIN_PER_CLASS = 5
MIN_CONFIDENCE = 0.5
EXPERIMENT = "incident-risk"
MODEL_NAME = "incident-risk"
DUMMY_NAME = "incident-risk-dummy"
ORIGIN_PRIORITY = ("analyst_verdict", "attack_window", "normal_window", "dataset_label", "ti_false_positive")


# ---------------------------------------------------------------- data
def resolve_labels(rows: list) -> list:
    """rows: dicts incident_id, label, origin, confidence, source, run_id, dataset_id, closed_at.
    One label per incident by ORIGIN_PRIORITY; an incident with conflicting labels is dropped;
    labels under MIN_CONFIDENCE are dropped."""
    by_inc = {}
    for r in rows:
        if r["confidence"] >= MIN_CONFIDENCE:
            by_inc.setdefault(r["incident_id"], []).append(r)
    out = []
    for inc, rs in by_inc.items():
        if len({r["label"] for r in rs}) > 1:
            continue
        best = min(rs, key=lambda r: ORIGIN_PRIORITY.index(r["origin"]))
        # a dataset is one group across all its runs; otherwise the run; analyst/TI labels stand alone
        group = (f"dataset:{best['dataset_id']}" if best["dataset_id"] else None) or best["run_id"] or f"{best['origin']}:{inc}"
        out.append({**best, "group": group, "y": 1 if best["label"] == "attack" else 0})
    return out


def source_family(source: str) -> str:
    return "replay" if source.startswith("replay:") else source


def load(engine, ch, tenant: str) -> list:
    from sqlalchemy import text
    with engine.connect() as conn:
        rows = [dict(r._mapping) for r in conn.execute(text(
            "SELECT l.incident_id, l.label, l.origin, l.confidence, l.source, l.run_id, l.dataset_id, i.closed_at "
            "FROM ml_labels l JOIN incidents i ON i.id = l.incident_id WHERE l.tenant_key = :t"), {"t": tenant})]
    labelled = resolve_labels(rows)
    stored = {r[0]: r[1] for r in ch.query(
        "SELECT incident_id, argMax(features, computed_at) FROM ml_incident_features WHERE tenant_id = {t:String} "
        "AND feature_version = {v:String} GROUP BY incident_id", parameters={"t": tenant, "v": features.FEATURE_VERSION}).result_rows}
    return [dict(r, features=features.from_row(stored[r["incident_id"]])) for r in labelled if r["incident_id"] in stored]


# ---------------------------------------------------------------- split
def group_time_split(items: list, val_frac: float = VAL_FRAC, test_frac: float = TEST_FRAC, test_ids=None) -> dict:
    """-> {"train": [...], "val": [...], "test": [...]}. Pinned test_ids: their groups are test."""
    groups = {}
    for it in items:
        g = groups.setdefault(it["group"], {"start": it["closed_at"], "items": []})
        g["start"] = min(g["start"], it["closed_at"])
        g["items"].append(it)
    order = sorted(groups, key=lambda k: (groups[k]["start"], k))
    if test_ids is not None:
        test_ids = set(test_ids)
        test_g = [g for g in order if any(i["incident_id"] in test_ids for i in groups[g]["items"])]
        rest = [g for g in order if g not in test_g]
    else:
        n_test = max(1, round(len(order) * test_frac)) if len(order) >= 3 else 0
        test_g, rest = order[len(order) - n_test:], order[:len(order) - n_test]
    n_val = max(1, round(len(order) * val_frac)) if len(rest) >= 2 else 0
    val_g, train_g = rest[len(rest) - n_val:], rest[:len(rest) - n_val]
    pick = lambda gs: [i for g in gs for i in groups[g]["items"]]  # noqa: E731
    out = {"train": pick(train_g), "val": pick(val_g), "test": pick(test_g)}
    assert not ({i["group"] for i in out["train"]} & {i["group"] for i in out["test"]})
    assert not ({i["group"] for i in out["val"]} & {i["group"] for i in out["test"]})
    return out


# ---------------------------------------------------------------- metrics
def baseline_scores(items: list) -> np.ndarray:
    """Rule-level baseline: the incident's max rule level, scaled to 0..1."""
    return np.array([min(i["features"]["max_level"] / 15.0, 1.0) for i in items])


def choose_threshold(y_val, s_val) -> float:
    """Max F1 on VALIDATION. (Never called with test data - see evaluate_split.)"""
    y_val, s_val = np.asarray(y_val), np.asarray(s_val)
    best, best_f1 = 0.5, -1.0
    for t in sorted(set(np.round(s_val, 6))):
        p = s_val >= t
        tp = int((p & (y_val == 1)).sum())
        f1 = 2 * tp / max(int(p.sum()) + int((y_val == 1).sum()), 1)
        if f1 > best_f1:
            best, best_f1 = float(t), f1
    return best


def metrics(y, s, threshold: float, days: float) -> dict:
    from sklearn.metrics import average_precision_score
    y, s = np.asarray(y), np.asarray(s)
    p = s >= threshold
    tp, fp = int((p & (y == 1)).sum()), int((p & (y == 0)).sum())
    pos = int((y == 1).sum())
    return {"recall": tp / pos if pos else None, "precision": tp / int(p.sum()) if p.sum() else None,
            "pr_auc": float(average_precision_score(y, s)) if pos and pos < len(y) else None,
            "false_alerts_per_day": fp / max(days, 1 / 24), "threshold": threshold, "n": len(y), "positives": pos}


def span_days(items: list) -> float:
    ts = [i["closed_at"] for i in items]
    return max((max(ts) - min(ts)).total_seconds() / 86400.0, 1 / 24) if ts else 1 / 24


def has_both(items: list, k: int = MIN_PER_CLASS) -> bool:
    ys = [i["y"] for i in items]
    return sum(ys) >= k and len(ys) - sum(ys) >= k


def should_promote(model_m: dict, base_m: dict, test_ok: bool) -> tuple:
    if not test_ok:
        return False, f"test set lacks {MIN_PER_CLASS}+ incidents of each class"
    if model_m["pr_auc"] is None or base_m["pr_auc"] is None:
        return False, "PR-AUC undefined on the test set"
    if model_m["pr_auc"] <= base_m["pr_auc"]:
        return False, f"PR-AUC {model_m['pr_auc']:.3f} does not beat baseline {base_m['pr_auc']:.3f}"
    if (model_m["recall"] or 0) < (base_m["recall"] or 0):
        return False, f"recall {model_m['recall']:.3f} below baseline {base_m['recall']:.3f}"
    return True, f"PR-AUC {model_m['pr_auc']:.3f} > baseline {base_m['pr_auc']:.3f}, recall not lower"


def make_estimator(seed: int = SEED):
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    return make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=2000, random_state=seed))


def evaluate_split(split: dict, seed: int = SEED) -> dict:
    """Fit on train, thresholds on val, metrics on test. -> results (and the fitted estimator)."""
    tr, va, te = split["train"], split["val"], split["test"]
    res = {"sizes": {k: len(v) for k, v in split.items()},
           "classes": {k: [len(v) - sum(i["y"] for i in v), sum(i["y"] for i in v)] for k, v in split.items()}}
    if not (tr and va and te) or len({i["y"] for i in tr}) < 2:
        res["skipped"] = "train needs both classes and val/test must be non-empty"
        return res
    est = make_estimator(seed).fit(features.model_input([i["features"] for i in tr]), [i["y"] for i in tr])
    score = lambda items: est.predict_proba(features.model_input([i["features"] for i in items]))[:, 1]  # noqa: E731
    yv, yt = [i["y"] for i in va], [i["y"] for i in te]
    t_model, t_base = choose_threshold(yv, score(va)), choose_threshold(yv, baseline_scores(va))
    days = span_days(te)
    res["model"] = metrics(yt, score(te), t_model, days)
    res["baseline"] = metrics(yt, baseline_scores(te), t_base, days)
    res["estimator"] = est
    return res


def cross_source(items: list, seed: int = SEED) -> dict:
    """Hold out each source family: train/val on the others (group-time split), test on it."""
    out = {}
    for fam in sorted({source_family(i["source"]) for i in items}):
        held = [i for i in items if source_family(i["source"]) == fam]
        rest = group_time_split([i for i in items if source_family(i["source"]) != fam], val_frac=0.2, test_frac=0.0)
        r = evaluate_split({"train": rest["train"], "val": rest["val"], "test": held}, seed)
        r.pop("estimator", None)
        out[fam] = r
    return out


# ---------------------------------------------------------------- MLflow
def git_commit() -> str:
    if os.environ.get("GIT_COMMIT"):
        return os.environ["GIT_COMMIT"]
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def label_snapshot(items: list) -> str:
    h = hashlib.sha256()
    for i in sorted(items, key=lambda i: i["incident_id"]):
        h.update(f"{i['incident_id']}|{i['y']}|{i['origin']}|{i['group']}\n".encode())
    return h.hexdigest()


def datasets_used(items: list) -> list:
    from .datasets import INVENTORY
    lic = {d["dataset"].split()[0].lower(): d["licence"] for d in INVENTORY}
    out = {}
    for i in items:
        if i.get("dataset_id"):
            prefix = i["dataset_id"].split(":")[0]
            out[i["dataset_id"]] = {"splunk": lic.get("splunk"), "otrf": lic.get("otrf"), "evtx": lic.get("evtx-attack-samples")}.get(prefix)
    return [{"dataset_id": k, "licence": v} for k, v in sorted(out.items())]


def model_card(name: str, purpose: str, items: list, res: dict, xs: dict, decision: tuple, limits: list) -> str:
    srcs = {}
    for i in items:
        srcs.setdefault(i["source"], [0, 0])[i["y"]] += 1
    lines = [f"# Model card: {name}", "", f"**Purpose.** {purpose}", "",
             "**Never triggers actions**; scores are shown to analysts only.", "",
             f"**Feature version** {features.FEATURE_VERSION}; git {git_commit()}; seed {SEED}.", "",
             "## Data and sources", "", "| source | benign | attack |", "|---|---|---|"]
    lines += [f"| {s} | {b} | {a} |" for s, (b, a) in sorted(srcs.items())]
    lines += ["", "Datasets: " + (", ".join(f"{d['dataset_id']} ({d['licence']})" for d in datasets_used(items)) or "none"), "",
              "## Metrics (test set, thresholds from validation)", "", "```", json.dumps(
                  {k: res.get(k) for k in ("sizes", "classes", "model", "baseline", "skipped")}, indent=1, default=str), "```",
              "", "## Cross-source (held-out source family)", "", "```",
              json.dumps(xs, indent=1, default=str), "```", "", f"## Promotion: {'yes' if decision[0] else 'no'} - {decision[1]}",
              "", "## Limits", ""] + [f"- {x}" for x in limits]
    return "\n".join(lines) + "\n"


LIMITS = ["Lab data only: one Linux agent, recorded Windows datasets, small number of runs.",
          "Labels come from run windows and dataset agents; background noise in a window can be mislabelled (confidence < 1).",
          "Not calibrated across tenants; trained on the TEST tenant only."]


def run(engine, ch, tenant: str, test_set_file=None) -> dict:
    import mlflow
    items = load(engine, ch, tenant)
    pinned = json.load(open(test_set_file)) if test_set_file else None
    split = group_time_split(items, test_ids=pinned)
    res = evaluate_split(split)
    xs = cross_source(items)
    test_ok = has_both(split["test"])
    decision = should_promote(res["model"], res["baseline"], test_ok) if "model" in res else (False, res.get("skipped", ""))
    mlflow.set_experiment(EXPERIMENT)
    with mlflow.start_run(run_name=f"logreg-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M}") as r:
        mlflow.log_params({"seed": SEED, "feature_version": features.FEATURE_VERSION, "git_commit": git_commit(),
                           "label_snapshot": label_snapshot(items), "n_labelled": len(items), "val_frac": VAL_FRAC,
                           "test_frac": TEST_FRAC, "class_weight": "balanced", "min_confidence": MIN_CONFIDENCE,
                           "test_set_pinned": bool(pinned)})
        mlflow.log_dict(datasets_used(items), "datasets_used.json")
        mlflow.log_dict(sorted(i["incident_id"] for i in split["test"]), "test_set.json")
        for side in ("model", "baseline"):
            for k, v in (res.get(side) or {}).items():
                if isinstance(v, (int, float)) and v is not None:
                    mlflow.log_metric(f"{side}_{k}", v)
        mlflow.log_dict({k: v for k, v in xs.items()}, "cross_source.json")
        card = model_card(MODEL_NAME, "Rank closed incidents by how likely they are real attack activity.", items, res, xs,
                          decision, LIMITS)
        mlflow.log_text(card, "model_card.md")
        mlflow.set_tag("promoted", str(decision[0]).lower())
        mlflow.set_tag("promotion_reason", decision[1])
        if "estimator" in res:
            import joblib
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "estimator.joblib")
                joblib.dump(res["estimator"], path)
                info = mlflow.pyfunc.log_model(name="model", python_model=_code_path(), artifacts={"estimator": path},
                                               registered_model_name=MODEL_NAME if decision[0] else None)
            if decision[0]:
                _to_production(MODEL_NAME, info.registered_model_version)
        return {"mlflow_run": r.info.run_id, "labelled": len(items), "split": res.get("sizes"), "classes": res.get("classes"),
                "model": res.get("model"), "baseline": res.get("baseline"), "promoted": decision,
                "cross_source": {k: {kk: v.get(kk) for kk in ("sizes", "model", "baseline", "skipped")} for k, v in xs.items()}}


def _code_path() -> str:
    return os.path.join(os.path.dirname(__file__), "serving_model.py")


def _to_production(name: str, version) -> None:
    import mlflow
    mlflow.MlflowClient().transition_model_version_stage(name, str(version), "Production", archive_existing_versions=True)


def register_dummy() -> dict:
    """The dummy (score = max_level/15) registered and moved to Production to prove serving by stage.
    It is a serving check, not a promoted model: it never went through `run`'s baseline gate."""
    import mlflow
    mlflow.set_experiment(EXPERIMENT)
    with mlflow.start_run(run_name="dummy-serving-check") as r:
        mlflow.log_params({"feature_version": features.FEATURE_VERSION, "git_commit": git_commit(), "seed": SEED})
        mlflow.set_tag("dummy", "true")
        mlflow.log_text(f"# Model card: {DUMMY_NAME}\n\n**Purpose.** Prove the serving path (MLflow stage -> ml-enricher -> "
                        "incident). Score = max rule level / 15, i.e. the rule-level baseline itself.\n\n**Data.** None (no "
                        "training).\n\n**Metrics.** Equal to the baseline by construction.\n\n**Limits.** Not a detector; "
                        "never triggers actions.\n", "model_card.md")
        info = mlflow.pyfunc.log_model(name="model", python_model=_code_path(), registered_model_name=DUMMY_NAME)
    _to_production(DUMMY_NAME, info.registered_model_version)
    return {"mlflow_run": r.info.run_id, "model": DUMMY_NAME, "version": info.registered_model_version, "stage": "Production"}


def live_parity(engine, ch, tenant: str, n: int = 50) -> dict:
    """Recompute n stored incidents' features through the serving path; they must equal the stored rows."""
    from sqlalchemy import text
    from . import enrich
    stored = ch.query("SELECT incident_id, argMax(features, computed_at) FROM ml_incident_features WHERE tenant_id = {t:String} "
                      "AND feature_version = {v:String} GROUP BY incident_id ORDER BY incident_id DESC LIMIT {n:UInt32}",
                      parameters={"t": tenant, "v": features.FEATURE_VERSION, "n": n}).result_rows
    mismatched = []
    with engine.connect() as conn:
        for inc_id, fmap in stored:
            inc = dict(conn.execute(text(
                "SELECT id, tenant_key, first_seen, last_seen, closed_at, alert_count, max_level, rule_ids, rule_groups, "
                "source_ip_total, user_total, correlation_basis, rare_pattern_flag, prior_occurrences, ti_confidence "
                "FROM incidents WHERE id = :i"), {"i": inc_id}).one()._mapping)
            served = enrich.incident_features(conn, ch, inc)
            if not features.model_input([served]).equals(features.model_input([features.from_row(fmap)])):
                mismatched.append(inc_id)
    return {"checked": len(stored), "mismatched": mismatched}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=["run", "register-dummy", "parity"])
    p.add_argument("--test-set", help="JSON list of incident ids to pin as the test set")
    a = p.parse_args(argv)
    if a.cmd == "register-dummy":
        out = register_dummy()
    elif a.cmd == "parity":
        out = live_parity(db.engine(), db.clickhouse(), db.test_tenant())
    else:
        out = run(db.engine(), db.clickhouse(), db.test_tenant(), a.test_set)
    print(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
