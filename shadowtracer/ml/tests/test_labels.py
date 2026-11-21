from shadowtracer_ml import labels


def test_four_eyes_refuses_self_review():
    # a verdict feeds the online model, so its creator can't also approve it (four-eyes).
    assert labels.four_eyes_ok("alice@x", "bob@x") is True        # different reviewer: allowed
    assert labels.four_eyes_ok("alice@x", "alice@x") is False     # same account: refused
    assert labels.four_eyes_ok("alice@x", "") is False            # no reviewer named: refused
    assert labels.four_eyes_ok("alice@x", None) is False


def test_check_reviewer_requires_a_different_real_analyst():
    import pytest
    # ok: a different account that is a real analyst/admin
    labels.check_reviewer("alice@x", "bob@x", "analyst")
    labels.check_reviewer("alice@x", "carol@x", "admin")
    # refused: the creator approving their own verdict (four-eyes), even as admin
    with pytest.raises(ValueError, match="four-eyes"):
        labels.check_reviewer("alice@x", "alice@x", "admin")
    # refused: a real user but not analyst+ (viewer)
    with pytest.raises(ValueError, match="not an analyst"):
        labels.check_reviewer("alice@x", "bob@x", "viewer")
    # refused: not a real user at all (role resolved to None)
    with pytest.raises(ValueError, match="not an analyst"):
        labels.check_reviewer("alice@x", "ghost@x", None)


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
