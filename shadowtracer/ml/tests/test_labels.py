from shadowtracer_ml import labels


def test_technique_match_gives_high_confidence():
    c = labels.activity_confidence({"T1136.001"}, [("5902", ["T1136"]), ("550", [])], {"550"}, 2)
    assert c == 0.9


def test_new_rule_without_technique_is_medium():
    assert labels.activity_confidence({"T1053.003"}, [("554", [])], {"550"}, 1) == 0.6


def test_background_only_stays_unlabelled():
    assert labels.activity_confidence({"T1053.003"}, [("550", [])], {"550"}, 1) is None
    assert labels.activity_confidence({"T1053.003"}, [], set(), 5) is None


def test_mostly_outside_window_lowers_confidence():
    assert labels.activity_confidence({"T1110"}, [("5710", ["T1110.001"])], set(), 100) == 0.45


def test_parent_technique():
    assert labels.parent("t1059.001") == "T1059" and labels.parent(None) == ""


def test_coverage_table():
    rows = [{"source": "normal_activity", "technique": "T1136.001", "run_id": "a", "label": "benign", "alerts": 6,
             "rules": ["550", "5902"], "labelled_incidents": 1},
            {"source": "normal_activity", "technique": "T1105", "run_id": "b", "label": "benign", "alerts": 0, "rules": [],
             "labelled_incidents": 0}]
    t = labels.coverage_table(rows)
    assert "| normal_activity | 2 (T1105, T1136.001) | 1 | 1 | 2: 550, 5902 |" in t
