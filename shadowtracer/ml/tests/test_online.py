"""Phase 7.3 unit checks for the online ARF model (no MLflow/DB):
  - HMAC-signed checkpoints: a good checkpoint loads; a tampered blob or signature is REFUSED before
    any pickle.loads; a missing secret refuses outright.
  - predict/learn basics and a two-class prequential run (predict-then-learn).
"""
import os

import numpy as np
import pytest

os.environ.setdefault("ONLINE_MODEL_SECRET", "unit-test-secret")

from shadowtracer_ml import features, online  # noqa: E402

FEATS = {n: 0.0 for n in features.FEATURE_NAMES}


def _attackish(i):
    f = dict(FEATS); f.update(max_level=15, mean_level=12, alerts_per_min=500, n_alerts_log=8, lvl_high=0.8); return f


def _benignish(i):
    f = dict(FEATS); f.update(max_level=3, mean_level=3, alerts_per_min=1, n_alerts_log=1, lvl_low=0.9); return f


def test_signed_checkpoint_roundtrips():
    m = online.new_model()
    online.learn_one(m, _attackish(0), "attack")
    blob = online._dump(m)
    assert online.verify(blob, online.sign(blob))
    assert type(online.load_checkpoint_bytes(blob, online.sign(blob))).__name__ == "ARFClassifier"


def test_tampered_blob_is_refused():
    blob = online._dump(online.new_model())
    sig = online.sign(blob)
    with pytest.raises(ValueError):
        online.load_checkpoint_bytes(blob[:-1] + b"\x00", sig)   # one byte changed


def test_bad_signature_is_refused():
    blob = online._dump(online.new_model())
    with pytest.raises(ValueError):
        online.load_checkpoint_bytes(blob, "deadbeef")


def test_missing_secret_refuses(monkeypatch):
    monkeypatch.delenv("ONLINE_MODEL_SECRET", raising=False)
    with pytest.raises(SystemExit):
        online.sign(b"x")


def test_prequential_learns_two_classes():
    # a clean separable stream; after seeing both classes the online model should not be trivial
    items = []
    for i in range(40):
        a = i % 2 == 0
        items.append({"features": _attackish(i) if a else _benignish(i), "y": 1 if a else 0,
                      "source": "replay:x" if a else "normal_activity", "label": "attack" if a else "benign"})
    res = online.prequential_eval(items)
    assert res["classes"] == [20, 20]
    assert res["model"]["macro_f1"] >= 0.5          # beats nothing-learned on a separable stream
    assert "rules_only" in res


if __name__ == "__main__":
    test_signed_checkpoint_roundtrips()
    test_tampered_blob_is_refused()
    test_bad_signature_is_refused()
    test_prequential_learns_two_classes()
    print("ok")
