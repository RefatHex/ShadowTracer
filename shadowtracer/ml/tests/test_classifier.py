"""Phase 7.4 trainer logic, with synthetic items (no DB/MLflow): dedup, split discipline, metrics +
bootstrap CIs, SHAP additivity, baselines. The real end-to-end training is run on the lab."""
import datetime as dt

import numpy as np
import pytest

from conftest import T0, make_alerts, make_incident
from shadowtracer_ml import classifier as C
from shadowtracer_ml import features, reasons


def _items(n_groups=16, per=6, dup_each=0):
    rng = np.random.default_rng(7)
    out, k = [], 0
    for g in range(n_groups):
        for j in range(per):
            y = (g + j) % 2
            # attack: high level + credential-access signal; benign: low level. Per-item variation on
            # count/ips/users/priors so distinct incidents get distinct feature vectors (fingerprints).
            inc = make_incident(max_level=int(rng.integers(12, 15)) if y else int(rng.integers(2, 5)),
                                alert_count=int(rng.integers(3, 40)), source_ip_total=int(rng.integers(1, 9)),
                                user_total=int(rng.integers(1, 6)), prior_occurrences=int(rng.integers(0, 10)))
            f = features.compute(inc, make_alerts(shift=dt.timedelta(seconds=int(rng.integers(0, 120)))))
            base = {"incident_id": k, "group": f"run-{g}", "y": y,
                    "source": "replay:x" if g % 2 else "normal_activity", "origin": "dataset_label",
                    "closed_at": T0 + dt.timedelta(hours=g, minutes=j), "features": f}
            out.append(base); k += 1
            for _ in range(dup_each):  # exact duplicates: same feature vector -> same fingerprint
                out.append({**base, "incident_id": k, "closed_at": base["closed_at"] + dt.timedelta(seconds=1)}); k += 1
    return out


def test_fingerprint_dedup_collapses_identical_vectors_and_reports_count():
    items = _items(n_groups=4, per=4, dup_each=2)   # each item has 2 exact dups
    deduped, removed = C.dedup_by_fingerprint(items)
    assert removed == len(items) - len(deduped) > 0
    # every surviving fingerprint is unique
    assert len({C.fingerprint(i) for i in deduped}) == len(deduped)


def test_reasons_are_closed_vocabulary_no_identifiers():
    reasons.demo()   # asserts no identifier tokens, direction follows sign, k-capped


def test_evaluate_runs_end_to_end_with_cis_and_additivity():
    res, booster, extra = C.evaluate_classifier(_items())
    assert booster is not None, res
    # dedup + split reported
    assert "duplicates_removed" in res and res["sizes"]["test"] > 0
    # thresholds/hyperparameters chosen on validation, not test
    assert "hyperparameters" in res and "val_pr_auc" in res
    # per-class precision/recall, macro-F1, PR-AUC present
    for k in ("attack_precision", "attack_recall", "benign_precision", "benign_recall", "macro_f1", "pr_auc"):
        assert k in res["test"], k
    # bootstrap CIs are [lo, hi] with lo <= hi
    for k, (lo, hi) in res["test_cis"].items():
        assert lo <= hi, (k, lo, hi)
    # baselines computed on the same test set
    assert "rules_only_pr_auc" in res["baselines"] and "rarity_pr_auc" in res["baselines"]
    # SHAP additivity holds tightly
    assert res["shap_additivity_max_abs_err"] < 1e-3, res["shap_additivity_max_abs_err"]


def test_serving_model_predict_matches_booster_and_emits_reasons():
    res, booster, extra = C.evaluate_classifier(_items())
    split, threshold = extra
    te = split["test"]
    X = features.model_input([i["features"] for i in te])
    # exercise the serving pyfunc directly (same artifacts the MLflow model would hold)
    import tempfile, os, json
    from shadowtracer_ml.xgb_serving_model import IncidentClassifierModel
    with tempfile.TemporaryDirectory() as d:
        ubj = os.path.join(d, "m.ubj"); booster.save_model(ubj)
        thr = os.path.join(d, "t.json"); json.dump({"threshold": threshold}, open(thr, "w"))
        class Ctx:  # minimal mlflow context stand-in
            artifacts = {"model_ubj": ubj, "threshold": thr}
        m = IncidentClassifierModel(); m.load_context(Ctx())
        out = m.predict(None, X)
    import xgboost as xgb
    direct = booster.predict(xgb.DMatrix(X, feature_names=list(features.FEATURE_NAMES)))
    assert np.allclose(out["prob"].to_numpy(), direct, atol=1e-6)
    assert set(out["label"]) <= {"attack", "benign"}
    # reasons are JSON lists of plain-language strings
    for r in out["reasons"]:
        rs = json.loads(r)
        assert isinstance(rs, list) and all(isinstance(x, str) and ":" in x for x in rs)
