"""Phase 7.2: River ADWIN drift detector - burst -> one event, stable -> zero, model-input shift,
bounded LRU state. Pure (no DB/ClickHouse); the service wiring is smoke-tested separately."""
import random

from shadowtracer_ml.drift import Detectors


def _feed(det, entity, metric, values):
    drifts = []
    for v in values:
        r = det.update(entity, metric, v)
        if r:
            drifts.append(r)
    return drifts


def test_burst_gives_exactly_one_drift_with_correct_before_after():
    det = Detectors()
    rng = random.Random(1)
    before = [2.0 + rng.gauss(0, 0.05) for _ in range(200)]      # stable baseline ~2
    after = [12.0 + rng.gauss(0, 0.05) for _ in range(80)]       # a burst to ~12
    drifts = _feed(det, "agent|t|a1", "alert_volume", before + after)
    assert len(drifts) == 1, f"expected exactly one drift, got {len(drifts)}"
    b, a, mag = drifts[0]
    assert 1.5 < b < 2.5 and 11.5 < a < 12.5          # before ~2, after ~12
    assert abs(mag - abs(a - b)) < 1e-9 and mag > 8


def test_stable_window_gives_zero_false_drifts():
    det = Detectors()
    rng = random.Random(2)
    total, false = 0, 0
    for agent in range(20):                                       # 20 agents, 300 stable buckets each
        drifts = _feed(det, f"agent|t|{agent}", "distinct_rule_ids", [5.0 + rng.gauss(0, 0.1) for _ in range(300)])
        false += len(drifts); total += 300
    assert false == 0, f"false-drift rate {false}/{total}"


def test_model_input_mean_shift_fires():
    det = Detectors()
    rng = random.Random(3)
    stable = [0.30 + rng.gauss(0, 0.01) for _ in range(200)]      # feature mean ~0.30
    shifted = [0.75 + rng.gauss(0, 0.01) for _ in range(80)]      # mean shifts to ~0.75
    drifts = _feed(det, "model|fv1|login_rate", "feature_mean", stable + shifted)
    assert len(drifts) == 1
    b, a, _ = drifts[0]
    assert b < 0.4 and a > 0.65


def test_lru_cap_bounds_entities():
    det = Detectors(max_entities=50)
    for i in range(500):
        det.update(f"agent|t|{i}", "alert_volume", 1.0)
    assert det.entity_count() == 50                               # bounded, newest kept


def test_each_metric_is_independent():
    det = Detectors()
    # a shift in one metric does not create a drift on another metric of the same entity
    _feed(det, "agent|t|a", "distinct_users", [1.0] * 200)
    drifts = _feed(det, "agent|t|a", "alert_volume", [1.0] * 200 + [20.0] * 60)
    assert len(drifts) == 1                                        # only alert_volume drifts


def test_state_envelope_roundtrip_and_version_guard():
    from shadowtracer_ml import drift as D
    det = Detectors()
    _feed(det, "agent|t|a", "alert_volume", [1.0] * 50)
    last = __import__("datetime").datetime(2026, 10, 1, tzinfo=__import__("datetime").timezone.utc)
    blob = D._encode_state(det, last)
    # header is JSON and gates the payload
    assert blob.split(b"\n", 1)[0].startswith(b'{') and D.STATE_FORMAT.encode() in blob
    det2, last2 = D._decode_state(blob)
    assert det2.entity_count() == 1 and last2 == last
    # a version/format/river mismatch is rejected (-> caller re-warms), never a bare pickle load
    import json
    for bad in ({"format": "other"}, {"format": D.STATE_FORMAT, "drift_version": "nope"},
                {"format": D.STATE_FORMAT, "drift_version": D.DRIFT_VERSION, "river": "0.0.0"}):
        tampered = json.dumps(bad).encode() + b"\n" + blob.split(b"\n", 1)[1]
        try:
            D._decode_state(tampered)
            assert False, f"accepted {bad}"
        except D.StateIncompatible:
            pass
    # no header at all -> rejected
    try:
        D._decode_state(b"not-an-envelope")
        assert False
    except D.StateIncompatible:
        pass


def test_load_state_rewarms_on_bad_file(tmp_path, monkeypatch):
    from shadowtracer_ml import drift as D
    p = tmp_path / "drift_state.pkl"
    p.write_bytes(b"garbage without header")
    monkeypatch.setattr(D, "STATE_PATH", str(p))
    det, last = D.load_state()                      # must not raise; re-warms fresh
    assert isinstance(det, Detectors) and det.entity_count() == 0 and last is None
