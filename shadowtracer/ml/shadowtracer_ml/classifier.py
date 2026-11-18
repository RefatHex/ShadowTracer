"""Phase 7.4: XGBoost + SHAP historical incident classifier (docs/ML_FOUNDATION.md §7.4).

Trains OFFLINE on the labelled incident features from 7.0, with the SAME data discipline as the 7.0
logreg (shadowtracer_ml.evaluate): split by TIME and GROUP, a frozen/pinnable test set, thresholds
and hyperparameters chosen on VALIDATION only, class imbalance handled (scale_pos_weight). Adds, on
top of 7.0:
  * fingerprint dedup across the split - near-duplicate replays (identical feature vectors) are
    collapsed to one, so the same shape can't sit in both train and test (count removed is reported);
  * two baselines - rules-only (max rule level) and rarity (rare_pattern flag) - beaten on PR-AUC;
  * bootstrap 95% CIs on every test metric (per-class precision/recall, macro-F1, PR-AUC);
  * a SHAP TreeExplainer additivity check (sum(shap)+base == model margin);
  * the model persisted as XGBoost native JSON/UBJ (never pickle) and served via SHAP reasons.

Run where MLflow is reachable (inside the lab network):
  docker compose run --rm -e GIT_COMMIT=$(git rev-parse HEAD) ml-enricher \
      python -m shadowtracer_ml.classifier run [--test-set FILE] [--promote-experimental]

Models never trigger actions; Production only means "shown to analysts as a hint".
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import tempfile

import numpy as np

from . import db, features
from .evaluate import (LIMITS, MIN_PER_CLASS, SEED, TEST_FRAC, VAL_FRAC, _to_production, baseline_scores,
                       choose_threshold, datasets_used, git_commit, group_time_split, has_both, label_snapshot,
                       load, source_family, span_days)

MODEL_NAME = "incident-classifier"
EXPERIMENT = "incident-classifier"

# Features whose magnitude tracks the DATA SOURCE / collection regime (volume, duration) more than
# the attack itself - a load-test replay dumps ~100k alerts in a short burst, an ART run far fewer.
# Flagged if they dominate SHAP, because then the model may be learning "which harness produced this"
# rather than "is this an attack" (7.4 item 4c).
SOURCE_PROXY_FEATURES = frozenset({
    "n_alerts_log", "alerts_per_min", "duration_log", "n_src_ips_log", "n_users_log",
    "n_rules_log", "n_groups_log", "max_level", "mean_level"})
# Small grid searched on VALIDATION only (never the test set). Kept tiny on purpose: the labelled
# set is small, so a large grid would just overfit the validation split.
GRID = [{"max_depth": d, "eta": e, "num_boost_round": n}
        for d in (2, 3, 4) for e in (0.1, 0.3) for n in (50, 150)]


# ---------------------------------------------------------------- fingerprint dedup
def fingerprint(item: dict) -> str:
    """A replay re-run produces the same incident shape -> the same feature vector. Hash the rounded
    vector so near-identical duplicates collapse to one fingerprint."""
    vec = features.vector(item["features"])
    return hashlib.sha1(",".join(f"{v:.4f}" for v in vec).encode()).hexdigest()


def dedup_by_fingerprint(items: list) -> tuple:
    """Keep the EARLIEST-closed incident per fingerprint (deterministic), so the same shape never
    straddles the train/test boundary. -> (deduped_items, removed_count)."""
    seen = {}
    for it in sorted(items, key=lambda i: (i["closed_at"], i["incident_id"])):
        seen.setdefault(fingerprint(it), it)
    deduped = list(seen.values())
    return deduped, len(items) - len(deduped)


# ---------------------------------------------------------------- model
def _dmatrix(items: list):
    import xgboost as xgb
    X = features.model_input([i["features"] for i in items])
    y = [i["y"] for i in items]
    return xgb.DMatrix(X, label=y, feature_names=list(features.FEATURE_NAMES)), X, np.asarray(y)


def _train_one(dtrain, params: dict, spw: float, seed: int):
    import xgboost as xgb
    p = {"objective": "binary:logistic", "eval_metric": "aucpr", "max_depth": params["max_depth"],
         "eta": params["eta"], "scale_pos_weight": spw, "seed": seed, "tree_method": "hist",
         "subsample": 0.9, "colsample_bytree": 0.9}
    return xgb.train(p, dtrain, num_boost_round=params["num_boost_round"])


def tune_and_fit(train: list, val: list, seed: int = SEED) -> tuple:
    """Grid over GRID, scored by PR-AUC on VALIDATION; refit the winner on train. Class imbalance via
    scale_pos_weight = n_benign/n_attack (computed on train only). -> (booster, best_params, val_prauc)."""
    from sklearn.metrics import average_precision_score
    import xgboost as xgb
    dtrain, _, ytr = _dmatrix(train)
    n_pos = max(int(ytr.sum()), 1)
    spw = (len(ytr) - int(ytr.sum())) / n_pos
    dval, _, yval = _dmatrix(val)
    best, best_auc = None, -1.0
    for params in GRID:
        bst = _train_one(dtrain, params, spw, seed)
        s = bst.predict(dval)
        auc = average_precision_score(yval, s) if 0 < yval.sum() < len(yval) else -1.0
        if auc > best_auc:
            best, best_auc, best_params = bst, auc, params
    return best, best_params, float(best_auc)


# ---------------------------------------------------------------- metrics + CIs
def _classification_metrics(y: np.ndarray, prob: np.ndarray, threshold: float) -> dict:
    """Per-class precision/recall, macro-F1, PR-AUC. Attack = positive class (1)."""
    from sklearn.metrics import average_precision_score
    y = np.asarray(y); pred = (np.asarray(prob) >= threshold).astype(int)
    out = {}
    f1s = []
    for cls, name in ((1, "attack"), (0, "benign")):
        yc, pc = (y == cls), (pred == cls)
        tp = int((yc & pc).sum())
        prec = tp / int(pc.sum()) if pc.sum() else None
        rec = tp / int(yc.sum()) if yc.sum() else None
        f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else 0.0
        out[f"{name}_precision"], out[f"{name}_recall"] = prec, rec
        f1s.append(f1)
    out["macro_f1"] = float(np.mean(f1s))
    out["pr_auc"] = float(average_precision_score(y, prob)) if 0 < y.sum() < len(y) else None
    return out


def bootstrap_cis(y: np.ndarray, prob: np.ndarray, threshold: float, b: int = 1000, seed: int = SEED) -> dict:
    """95% bootstrap CIs for each metric: resample the test set with replacement, recompute, take the
    2.5/97.5 percentiles. Returns {metric: [lo, hi]} (None where undefined on too many resamples)."""
    rng = np.random.default_rng(seed)
    y = np.asarray(y); prob = np.asarray(prob); n = len(y)
    acc = {}
    for _ in range(b):
        idx = rng.integers(0, n, n)
        m = _classification_metrics(y[idx], prob[idx], threshold)
        for k, v in m.items():
            if v is not None:
                acc.setdefault(k, []).append(v)
    return {k: [round(float(np.percentile(v, 2.5)), 3), round(float(np.percentile(v, 97.5)), 3)]
            for k, v in acc.items() if v}


def shap_additivity(booster, X) -> float:
    """sum(shap) + base == model margin, per row. Returns the max abs error over X."""
    import shap, xgboost as xgb
    expl = shap.TreeExplainer(booster)
    sv = np.asarray(expl.shap_values(X))
    margin = booster.predict(xgb.DMatrix(X, feature_names=list(features.FEATURE_NAMES)), output_margin=True)
    return float(np.abs(sv.sum(1) + expl.expected_value - margin).max())


# ---------------------------------------------------------------- baselines
def rarity_scores(items: list) -> np.ndarray:
    return np.array([1.0 if i["features"].get("rare_pattern") else 0.0 for i in items])


def _pr_auc(y, s):
    from sklearn.metrics import average_precision_score
    y = np.asarray(y)
    return float(average_precision_score(y, s)) if 0 < y.sum() < len(y) else None


def beats_baselines(model_prauc, rules_prauc, rarity_prauc) -> tuple:
    if model_prauc is None:
        return False, "model PR-AUC undefined on the test set"
    worse = [b for b in ((rules_prauc, "rules-only"), (rarity_prauc, "rarity")) if b[0] is not None and model_prauc <= b[0]]
    if worse:
        return False, "does not beat " + ", ".join(f"{n} ({v:.3f})" for v, n in worse) + f" (model {model_prauc:.3f})"
    return True, f"model PR-AUC {model_prauc:.3f} beats rules-only and rarity baselines"


# ---------------------------------------------------------------- orchestration
def evaluate_classifier(items: list, test_set_file=None) -> dict:
    """Dedup -> split -> tune on val -> metrics + CIs on test vs baselines -> SHAP additivity."""
    deduped, removed = dedup_by_fingerprint(items)
    pinned = json.load(open(test_set_file)) if test_set_file else None
    split = group_time_split(deduped, test_ids=pinned)
    tr, va, te = split["train"], split["val"], split["test"]
    res = {"n_labelled": len(items), "duplicates_removed": removed, "n_after_dedup": len(deduped),
           "sizes": {k: len(v) for k, v in split.items()},
           "classes": {k: [len(v) - sum(i["y"] for i in v), sum(i["y"] for i in v)] for k, v in split.items()}}
    if not (tr and va and te) or len({i["y"] for i in tr}) < 2:
        res["skipped"] = "train needs both classes and val/test must be non-empty"
        return res, None, None
    booster, best_params, val_prauc = tune_and_fit(tr, va)
    res["hyperparameters"] = best_params
    res["val_pr_auc"] = round(val_prauc, 3)
    dval, Xval, yval = _dmatrix(va)
    dtest, Xtest, ytest = _dmatrix(te)
    prob_test = booster.predict(dtest)
    # threshold chosen on VALIDATION, never test
    threshold = choose_threshold(yval, booster.predict(dval))
    res["threshold"] = round(float(threshold), 4)
    res["test"] = {k: (round(v, 3) if isinstance(v, float) else v)
                   for k, v in _classification_metrics(ytest, prob_test, threshold).items()}
    res["test_cis"] = bootstrap_cis(ytest, prob_test, threshold)
    # baselines on the SAME test set
    rules = baseline_scores(te)
    res["baselines"] = {"rules_only_pr_auc": round(_pr_auc(ytest, rules), 3) if _pr_auc(ytest, rules) is not None else None,
                        "rarity_pr_auc": round(_pr_auc(ytest, rarity_scores(te)), 3) if _pr_auc(ytest, rarity_scores(te)) is not None else None}
    res["shap_additivity_max_abs_err"] = shap_additivity(booster, Xtest)
    res["beats_baselines"] = beats_baselines(res["test"]["pr_auc"], res["baselines"]["rules_only_pr_auc"],
                                             res["baselines"]["rarity_pr_auc"])
    res["test_has_both_classes"] = has_both(te)
    return res, booster, (split, threshold)


def grouped_cv_eval(items: list, n_splits: int = 5, seed: int = SEED) -> dict:
    """Group-stratified cross-validation, reported ALONGSIDE the frozen time-split. On this thin,
    time-segregated lab data the time-split test set is single-class (all benign incidents close most
    recently), so PR-AUC / attack metrics / baselines are undefined there. StratifiedGroupKFold keeps
    BOTH classes in every fold's test slice while still never letting a group (a run/dataset, and
    therefore a replay near-duplicate) span folds, so this is a leakage-controlled two-class
    evaluation - INDICATIVE ONLY, never the promotion gate. Out-of-fold predictions are pooled; the
    threshold is a fixed 0.5 (no tuning on the evaluated rows)."""
    from sklearn.model_selection import StratifiedGroupKFold
    deduped, _ = dedup_by_fingerprint(items)
    y = np.array([i["y"] for i in deduped])
    # 7.4 item 4a: the CV group is (source family | run/dataset). Dedup already dropped identical
    # fingerprints; grouping by run/dataset keeps a run's near-duplicate replays together, and the
    # source-family prefix guarantees no two folds share a source's near-dupes. A run belongs to one
    # source, so this prefix is a relabel, not a coarsening - the fold count is unchanged.
    groups = [f"{source_family(i['source'])}|{i['group']}" for i in deduped]
    n_groups = len(set(groups))
    k = max(2, min(n_splits, int(y.sum()), int(len(y) - y.sum()), n_groups))
    if y.sum() < 2 or (len(y) - y.sum()) < 2 or n_groups < k:
        return {"skipped": "need >=2 of each class across >=k groups"}
    oof = np.full(len(deduped), np.nan)
    params = {"max_depth": 3, "eta": 0.1, "num_boost_round": 150}   # fixed (not tuned on evaluated rows)
    sgkf = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=seed)
    for tr_idx, te_idx in sgkf.split(np.zeros(len(y)), y, groups):
        tr = [deduped[i] for i in tr_idx]; te = [deduped[i] for i in te_idx]
        dtr, _, ytr = _dmatrix(tr)
        spw = (len(ytr) - int(ytr.sum())) / max(int(ytr.sum()), 1)
        bst = _train_one(dtr, params, spw, seed)
        dte, _, _ = _dmatrix(te)
        oof[te_idx] = bst.predict(dte)
    m = {kk: (round(v, 3) if isinstance(v, float) else v) for kk, v in _classification_metrics(y, oof, 0.5).items()}
    rules = baseline_scores(deduped); rarity = rarity_scores(deduped)
    base = {"rules_only_pr_auc": _pr_auc(y, rules), "rarity_pr_auc": _pr_auc(y, rarity)}
    base = {kk: (round(v, 3) if v is not None else None) for kk, v in base.items()}
    return {"folds": k, "n": len(deduped), "classes": [int(len(y) - y.sum()), int(y.sum())],
            "metrics": m, "cis": bootstrap_cis(y, oof, 0.5), "baselines": base,
            "beats_baselines": beats_baselines(m["pr_auc"], base["rules_only_pr_auc"], base["rarity_pr_auc"])}


def _r(v, n=3):
    return round(float(v), n) if v is not None else None


def top_shap_features(booster, items: list, k: int = 10) -> list:
    """Top-k features by mean |SHAP| over the deduped set, each flagged if it is a source proxy
    (volume/duration) rather than attack shape (7.4 item 4c)."""
    import shap
    deduped, _ = dedup_by_fingerprint(items)
    X = features.model_input([i["features"] for i in deduped])
    sv = np.asarray(shap.TreeExplainer(booster).shap_values(X))
    mean_abs = np.abs(sv).mean(axis=0)
    names = list(features.FEATURE_NAMES)
    order = np.argsort(mean_abs)[::-1][:k]
    return [{"feature": names[j], "mean_abs_shap": _r(mean_abs[j], 4),
             "source_proxy": names[j] in SOURCE_PROXY_FEATURES} for j in order]


def leave_one_source_out(items: list, seed: int = SEED) -> dict:
    """Train on two source families, test on the third held-out one, for each (7.4 item 4b). The
    honesty check: if the model only works because train and test share a source, holding a source
    out collapses it. Fixed params (no tuning on the held-out source), threshold 0.5."""
    deduped, _ = dedup_by_fingerprint(items)
    fams = sorted({source_family(i["source"]) for i in deduped})
    params = {"max_depth": 3, "eta": 0.1, "num_boost_round": 150}
    out = {}
    for fam in fams:
        test = [i for i in deduped if source_family(i["source"]) == fam]
        train = [i for i in deduped if source_family(i["source"]) != fam]
        yte = np.array([i["y"] for i in test]); ytr = np.array([i["y"] for i in train])
        classes = [int((yte == 0).sum()), int((yte == 1).sum())]
        if len(set(ytr.tolist())) < 2 or len(test) == 0:
            out[fam] = {"skipped": "train single-class or empty held-out set", "test_n": len(test), "test_classes": classes}
            continue
        dtr, _, _ = _dmatrix(train)
        spw = (len(ytr) - int(ytr.sum())) / max(int(ytr.sum()), 1)
        bst = _train_one(dtr, params, spw, seed)
        dte, _, _ = _dmatrix(test)
        m = _classification_metrics(yte, bst.predict(dte), 0.5)
        out[fam] = {"test_n": len(test), "test_classes": classes,
                    "pr_auc": _r(m["pr_auc"]), "macro_f1": _r(m["macro_f1"]),
                    "attack_precision": _r(m["attack_precision"]), "attack_recall": _r(m["attack_recall"]),
                    "benign_precision": _r(m["benign_precision"]), "benign_recall": _r(m["benign_recall"])}
    # collapsed = any held-out source with undefined PR-AUC (single-class test) or macro-F1 < 0.6
    collapsed = [f for f, r in out.items()
                 if "skipped" in r or r.get("pr_auc") is None or (r.get("macro_f1") or 0) < 0.6]
    return {"by_source": out, "collapsed": collapsed}


def _model_card(res: dict, items: list, experimental: bool) -> str:
    lines = [f"# Model card: {MODEL_NAME}", "", "**Purpose.** Classify a CLOSED incident as attack vs "
             "benign with a probability and plain-language SHAP reasons, shown to analysts as a hint at "
             "incident close. **Never triggers actions.**", "",
             f"**Feature version** {features.FEATURE_VERSION}; git {git_commit()}; seed {SEED}.",
             f"**Labels** {res['n_labelled']} ({res['duplicates_removed']} near-duplicate fingerprints removed; "
             f"{res['n_after_dedup']} kept).", ""]
    if experimental:
        lines += ["> **EXPERIMENTAL** - does not clear the baseline/test-size gate on the current lab data; "
                  "shown only as a hint, never used to filter, suppress or auto-close.", ""]
    lines += ["## Metrics (frozen time-split test set; thresholds + hyperparameters from validation only)", "", "```",
              json.dumps({k: res.get(k) for k in ("sizes", "classes", "hyperparameters", "threshold", "test",
                          "test_cis", "baselines", "beats_baselines", "shap_additivity_max_abs_err")},
                         indent=1, default=str), "```", "",
              "## Group-stratified CV (indicative two-class eval; leakage controlled by group, NOT the promotion gate)",
              "", "```", json.dumps(res.get("grouped_cv"), indent=1, default=str), "```", ""]
    loso = res.get("leave_one_source_out") or {}
    lines += ["## Leave-one-source-out (train on 2 source families, test on the 3rd)", ""]
    if loso.get("collapsed"):
        lines += [f"> **CROSS-SOURCE COLLAPSE on {', '.join(loso['collapsed'])}** - held-out-source PR-AUC is "
                  "undefined or macro-F1 < 0.6, so the in-distribution CV (above) is OPTIMISTIC; treat it as an "
                  "upper bound, not expected field performance.", ""]
    lines += ["```", json.dumps(loso, indent=1, default=str), "```", ""]
    if res.get("top_shap_features"):
        lines += ["## Top features by mean |SHAP| (source_proxy = volume/duration, may encode the harness not the attack)",
                  "", "```", json.dumps(res["top_shap_features"], indent=1, default=str), "```", ""]
    lines += ["## Limits", ""]
    lines += [f"- {x}" for x in LIMITS] + [
              "- Thin benign data: few distinct benign fingerprints, so the test set is small and the CIs are wide.", ""]
    return "\n".join(lines) + "\n"


def run(engine, ch, tenant: str, test_set_file=None, promote_experimental: bool = False) -> dict:
    import mlflow
    items = load(engine, ch, tenant)
    res, booster, extra = evaluate_classifier(items, test_set_file)
    res["grouped_cv"] = grouped_cv_eval(items)             # indicative two-class eval; NOT the promotion gate
    res["leave_one_source_out"] = leave_one_source_out(items)   # 7.4 item 4b: cross-source honesty check
    if booster is not None:
        res["top_shap_features"] = top_shap_features(booster, items)   # 7.4 item 4c
    # Promotion gate: a frozen two-class test set that beats baselines AND cross-source does not collapse.
    passed = bool(res.get("test_has_both_classes") and res.get("beats_baselines", (False,))[0]
                  and not res["leave_one_source_out"]["collapsed"])
    experimental = booster is not None and not passed
    mlflow.set_experiment(EXPERIMENT)
    with mlflow.start_run(run_name=f"xgb-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M}") as r:
        mlflow.log_params({"seed": SEED, "feature_version": features.FEATURE_VERSION, "git_commit": git_commit(),
                           "label_snapshot": label_snapshot(items), "n_labelled": len(items),
                           "duplicates_removed": res["duplicates_removed"], "val_frac": VAL_FRAC, "test_frac": TEST_FRAC,
                           "test_set_pinned": bool(test_set_file), **({f"hp_{k}": v for k, v in res["hyperparameters"].items()}
                                                                      if "hyperparameters" in res else {})})
        for section in ("sizes", "classes", "test", "test_cis", "baselines"):
            if section in res and isinstance(res[section], dict):
                for k, v in res[section].items():
                    if isinstance(v, (int, float)) and v is not None:
                        mlflow.log_metric(f"{section}_{k}", v)
        if "shap_additivity_max_abs_err" in res:
            mlflow.log_metric("shap_additivity_max_abs_err", res["shap_additivity_max_abs_err"])
        if isinstance(res.get("grouped_cv"), dict) and "metrics" in res["grouped_cv"]:
            for k, v in res["grouped_cv"]["metrics"].items():
                if isinstance(v, (int, float)) and v is not None:
                    mlflow.log_metric(f"cv_{k}", v)
        mlflow.log_dict(res, "results.json")
        mlflow.log_dict(datasets_used(items), "datasets_used.json")
        if extra:
            mlflow.log_dict(sorted(i["incident_id"] for i in extra[0]["test"]), "test_set.json")
        mlflow.set_tag("experimental", str(experimental).lower())
        mlflow.set_tag("promoted", str(passed or (experimental and promote_experimental)).lower())
        if booster is not None:
            mlflow.log_text(_model_card(res, items, experimental), "model_card.md")
            with tempfile.TemporaryDirectory() as d:
                ubj = os.path.join(d, "model.ubj"); booster.save_model(ubj)   # native JSON/UBJ, never pickle
                thr = os.path.join(d, "threshold.json")
                json.dump({"threshold": extra[1]}, open(thr, "w"))
                register = passed or (experimental and promote_experimental)
                info = mlflow.pyfunc.log_model(
                    name="model", python_model=os.path.join(os.path.dirname(__file__), "xgb_serving_model.py"),
                    artifacts={"model_ubj": ubj, "threshold": thr},
                    code_paths=[os.path.dirname(os.path.dirname(__file__)) + "/shadowtracer_ml"],
                    registered_model_name=MODEL_NAME if register else None)
            if register:
                # 7.4 item 5: tag the MODEL VERSION (not just the run) so the serving worker can read
                # `experimental` at load time and the console panel can surface it.
                mlflow.MlflowClient().set_model_version_tag(
                    MODEL_NAME, str(info.registered_model_version), "experimental", str(experimental).lower())
                _to_production(MODEL_NAME, info.registered_model_version)
        return {"mlflow_run": r.info.run_id, "model": MODEL_NAME, "passed_gate": passed,
                "experimental": experimental, "promoted": passed or (experimental and promote_experimental),
                "results": res}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("run")
    rp.add_argument("--test-set")
    rp.add_argument("--promote-experimental", action="store_true",
                    help="serve the model (Production stage) even if it doesn't clear the baseline gate - "
                         "for demonstrating the serving path on thin lab data; always tagged experimental.")
    args = ap.parse_args(argv)
    engine, ch = db.engine(), db.clickhouse()
    tenant = db.test_tenant()   # trained on the TEST tenant only - never touches main tenant data
    out = run(engine, ch, tenant, args.test_set, args.promote_experimental)
    print(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
