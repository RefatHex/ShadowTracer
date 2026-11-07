import datetime as dt

import numpy as np
import pytest

from conftest import T0, make_alerts, make_incident
from shadowtracer_ml import evaluate as ev
from shadowtracer_ml import features


def items(n_groups=10, per=6):
    out, k = [], 0
    for g in range(n_groups):
        for j in range(per):
            y = (g + j) % 2
            f = features.compute(make_incident(max_level=12 if y else 4), make_alerts())
            out.append({"incident_id": k, "group": f"run-{g}", "y": y, "source": "replay:x" if g % 2 else "normal_activity",
                        "origin": "dataset_label", "closed_at": T0 + dt.timedelta(hours=g, minutes=j), "features": f})
            k += 1
    return out


def test_split_is_by_time_and_no_group_spans_splits():
    s = ev.group_time_split(items())
    groups = {k: {i["group"] for i in v} for k, v in s.items()}
    assert not (groups["train"] & groups["val"]) and not (groups["train"] & groups["test"]) and not (groups["val"] & groups["test"])
    assert max(i["closed_at"] for i in s["train"]) < min(i["closed_at"] for i in s["val"]) < min(i["closed_at"] for i in s["test"])
    assert groups["test"] == {"run-8", "run-9"}


def test_pinned_test_set_takes_whole_groups():
    s = ev.group_time_split(items(), test_ids=[0])
    assert {i["group"] for i in s["test"]} == {"run-0"} and len(s["test"]) == 6


def test_threshold_comes_from_validation_only():
    t = ev.choose_threshold([0, 0, 1, 1], [0.1, 0.2, 0.7, 0.9])
    assert t == 0.7


def test_metrics_never_report_accuracy_and_count_false_alerts_per_day():
    m = ev.metrics([0, 0, 1, 1], [0.9, 0.1, 0.8, 0.2], 0.5, days=2.0)
    assert "accuracy" not in m and m["recall"] == 0.5 and m["precision"] == 0.5 and m["false_alerts_per_day"] == 0.5
    assert m["pr_auc"] is not None


def test_promotion_requires_beating_baseline_on_a_two_class_test_set():
    good = {"pr_auc": 0.9, "recall": 0.8}
    base = {"pr_auc": 0.7, "recall": 0.8}
    assert ev.should_promote(good, base, True)[0]
    assert not ev.should_promote(base, base, True)[0]
    assert not ev.should_promote({"pr_auc": 0.95, "recall": 0.5}, base, True)[0]
    assert not ev.should_promote(good, base, False)[0]


def test_resolve_labels_drops_conflicts_and_low_confidence():
    r = lambda i, label, origin, c=0.9: {"incident_id": i, "label": label, "origin": origin, "confidence": c,  # noqa: E731
                                        "source": "s", "run_id": f"run-{i}", "dataset_id": None, "closed_at": T0}
    out = ev.resolve_labels([r(1, "attack", "attack_window"), r(1, "benign", "analyst_verdict"),
                             r(2, "attack", "dataset_label"), r(2, "attack", "analyst_verdict"),
                             r(3, "benign", "normal_window", 0.3)])
    assert [(o["incident_id"], o["origin"], o["y"]) for o in out] == [(2, "analyst_verdict", 1)]


def test_evaluate_split_uses_class_weights_and_reports_baseline():
    res = ev.evaluate_split(ev.group_time_split(items()))
    assert res["estimator"][-1].class_weight == "balanced"
    assert {"recall", "precision", "pr_auc", "false_alerts_per_day"} <= set(res["model"]) and "baseline" in res


def test_cross_source_holds_out_each_family():
    xs = ev.cross_source(items())
    assert set(xs) == {"replay", "normal_activity"}
    assert xs["replay"]["sizes"]["test"] == 30


def _mc_items(tactics, per=4, sources_per=2):
    import datetime as dt
    from conftest import T0, make_alerts, make_incident
    from shadowtracer_ml import features
    out, k = [], 0
    for ti, tac in enumerate(tactics):
        for sidx in range(sources_per):
            for j in range(per):
                f = features.compute(make_incident(max_level=10 + ti), make_alerts())
                out.append({"incident_id": k, "y": 1, "tactic": tac, "os": "windows",
                            "source": f"replay:{tac}-{sidx}", "group": f"{tac}-src{sidx}", "cls": tac,
                            "closed_at": T0 + dt.timedelta(hours=ti, minutes=sidx * 10 + j), "features": f})
                k += 1
    return out


def test_class_counts_measures_distinct_sources_not_incidents():
    items = _mc_items(["persistence", "execution"], per=5, sources_per=2)
    c = ev.class_counts(items)
    assert c["by_tactic"]["persistence"]["sources"] == 2 and c["by_tactic"]["persistence"]["incidents"] == 10


def test_multiclass_drops_classes_with_too_few_sources():
    items = _mc_items(["persistence", "execution"], per=4, sources_per=2)
    items += _mc_items(["rare"], per=4, sources_per=1)       # only 1 source -> dropped
    for n, it in enumerate(items):
        it["incident_id"] = n
    res = ev.multiclass_eval(items, min_sources=2)
    assert "rare" in res["dropped_classes"] and set(res["kept_classes"]) == {"persistence", "execution"}


def test_os_shortcut_detected_when_attack_and_benign_differ_by_os():
    items = [{"y": 1, "os": "windows", "source": "replay:x", "group": "g", "tactic": "execution"},
             {"y": 0, "os": "linux", "source": "normal_activity", "group": "n", "tactic": "unknown"}]
    r = ev.os_shortcut(items)
    assert r["shortcut_present"] and r["attack_os"] == ["windows"] and r["benign_os"] == ["linux"]


def test_promotion_blocked_by_os_shortcut():
    mc = {"macro_recall": 0.9, "micro_accuracy": 0.9, "majority_baseline_accuracy": 0.5, "cross_source": {}}
    assert not ev._promote_tactic(mc, {"shortcut_present": True})[0]
    assert ev._promote_tactic(mc, {"shortcut_present": False})[0]
