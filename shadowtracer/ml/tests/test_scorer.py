import json

from conftest import FakeAlert
from shadowtracer_ml import hst, scorer


class FakeCH:
    def __init__(self):
        self.inserted = []

    def insert(self, table, rows, column_names=None):
        self.inserted.append((table, [dict(zip(column_names, r)) for r in rows]))


def test_score_row_shape_and_identity_is_stable_for_replay():
    ev = FakeAlert(cluster_node="worker-test", alert_id="1793970000.1")
    r1 = scorer.score_row(ev, "ten", 0.8, [{"feature": "level", "value": 1.0, "mean": 0.3}])
    r2 = scorer.score_row(ev, "ten", 0.4, [])        # same alert re-scored (restart replay)
    # identity (tenant, node, alert_id, model_version) is identical -> ReplacingMergeTree dedups
    assert r1[:4] == r2[:4] == ["ten", "worker-test", "1793970000.1", hst.MODEL_VERSION]
    assert r1[5] == 1 and json.loads(r1[6])[0]["feature"] == "level"
    warm_none = scorer.score_row(ev, "ten", None, [])
    assert warm_none[4] == 0.0 and warm_none[5] == 0      # warm flag 0 before warm-up


def test_flush_inserts_then_clears():
    ch = FakeCH(); rows = [scorer.score_row(FakeAlert(), "t", 0.5, [])]
    scorer.flush(ch, rows)
    assert ch.inserted[0][0] == "ml_scores" and rows == []
    scorer.flush(ch, rows)                                # empty -> no-op
    assert len(ch.inserted) == 1


def test_models_restore_and_reject_incompatible(tmp_path):
    m = scorer.Models(state_dir=str(tmp_path))
    model = m.get("ten"); model.n_seen = 123
    m.dirty.add("ten"); assert m.checkpoint() == 1
    m2 = scorer.Models(state_dir=str(tmp_path))
    assert m2.get("ten").n_seen == 123                   # restored from disk
    # corrupt the header -> discarded, warms fresh (n_seen 0), no crash
    path = m2._path("ten"); data = open(path, "rb").read()
    open(path, "wb").write(b'{"format":"wrong"}\n' + data[data.find(b"\n") + 1:])
    m3 = scorer.Models(state_dir=str(tmp_path))
    assert m3.get("ten").n_seen == 0
