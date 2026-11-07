import random

import pytest

from conftest import FakeAlert
from shadowtracer_ml import hst
from shadowtracer_ml.hst import AnomalyModel, CheckpointIncompatible


def _warm(m, n=hst.WARMUP):
    random.seed(1)
    for i in range(n):
        m.observe(FakeAlert(agent_id="001", rule_level=random.choice([3, 5]), rule_groups=("sshd",),
                            time=f"2026-11-07T09:{(i // 60) % 60:02d}:{i % 60:02d}+00:00",
                            actor_user="svc", src_endpoint_ip="10.0.0.2"))


def test_no_score_before_warmup_then_scores():
    m = AnomalyModel()
    s, r, _ = m.observe(FakeAlert())
    assert s is None and not m.warm
    _warm(m)
    assert m.warm
    s, r, _ = m.observe(FakeAlert(agent_id="001", rule_level=5, actor_user="svc", src_endpoint_ip="10.0.0.2"))
    assert 0.0 <= s <= 1.0


def test_outlier_scores_higher_than_inlier():
    m = AnomalyModel()
    _warm(m)
    inlier, _, _ = m.observe(FakeAlert(agent_id="001", rule_level=5, rule_groups=("sshd",), actor_user="svc", src_endpoint_ip="10.0.0.2"))
    outlier, reasons, _ = m.observe(FakeAlert(agent_id="001", rule_level=15, rule_groups=("rootcheck", "attack"),
                                              actor_user="attacker", src_endpoint_ip="203.0.113.9"))
    assert outlier > inlier and reasons and "feature" in reasons[0]


def test_checkpoint_round_trip_preserves_state_and_scores():
    m = AnomalyModel()
    _warm(m)
    probe = FakeAlert(agent_id="001", rule_level=9, actor_user="svc", src_endpoint_ip="10.0.0.2")
    blob = m.save_bytes()
    m2 = AnomalyModel.load_bytes(blob)
    assert m2.n_seen == m.n_seen
    # identical model -> identical score for the same next point
    assert m.hst.score_one(__import__("shadowtracer_ml.alert_features", fromlist=["compute"]).compute(probe, m.state)) == \
           m2.hst.score_one(__import__("shadowtracer_ml.alert_features", fromlist=["compute"]).compute(probe, m2.state))


def test_checkpoint_rejects_incompatible_versions():
    m = AnomalyModel()
    _warm(m, n=hst.WARMUP)
    blob = m.save_bytes()
    nl = blob.find(b"\n")
    import json
    head = json.loads(blob[:nl]); head["alert_feature_version"] = "zzz"
    with pytest.raises(CheckpointIncompatible):
        AnomalyModel.load_bytes(json.dumps(head).encode() + blob[nl:])
    with pytest.raises(CheckpointIncompatible):
        AnomalyModel.load_bytes(b"not-json\n" + blob[nl + 1:])


def test_model_version_tracks_feature_version():
    assert hst.MODEL_VERSION.endswith(__import__("shadowtracer_ml.alert_features", fromlist=["x"]).ALERT_FEATURE_VERSION)
