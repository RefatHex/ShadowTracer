"""HalfSpaceTrees anomaly model (7.1): one per tenant, scored live by ml-scorer. Wraps
river.anomaly.HalfSpaceTrees over alert_features (already [0,1]), tracks a running per-feature
mean for human-readable reasons, and serialises to an explicitly versioned, validated checkpoint
(never a bare pickle: a header gates the payload and a version change forces a clean rebuild).

score_one is in [0,1], higher = more anomalous. The model scores a point BEFORE learning it, so
a point is judged against the stream so far. Below the warm-up count the score is None (the model
has seen too little to judge). Reasons are the top features by |value - running mean| - a cheap
approximation of "what made this unusual", NOT an exact HST attribution (documented as such).
"""
import datetime as dt
import json
import pickle

from river import anomaly

from . import alert_features as af

N_TREES = 10
HEIGHT = 8
WINDOW = 250
SEED = 7
WARMUP = 300                 # alerts a tenant's model must see before it scores
MEAN_ALPHA = 1.0 / 250       # EWMA weight for the per-feature running mean (reasons only)
MODEL_VERSION = f"hst-{af.ALERT_FEATURE_VERSION}"
CHECKPOINT_FORMAT = "shadowtracer-hst/1"


class CheckpointIncompatible(Exception):
    """The saved checkpoint cannot be trusted with this code/library - rebuild from scratch."""


class AnomalyModel:
    def __init__(self):
        self.hst = anomaly.HalfSpaceTrees(n_trees=N_TREES, height=HEIGHT, window_size=WINDOW, seed=SEED)
        self.state = af.StreamState()
        self.mean = {k: 0.0 for k in af.FEATURE_NAMES}
        self.n_seen = 0

    def _reasons(self, features: dict, k: int = 3) -> list:
        dev = sorted(af.FEATURE_NAMES, key=lambda n: abs(features[n] - self.mean[n]), reverse=True)
        return [{"feature": n, "value": round(features[n], 3), "mean": round(self.mean[n], 3)}
                for n in dev[:k] if abs(features[n] - self.mean[n]) > 1e-6]

    def observe(self, event):
        """Score then learn one alert. -> (score|None, reasons, features). score is None until warm."""
        features = af.compute(event, self.state)
        score = self.hst.score_one(features) if self.n_seen >= WARMUP else None
        reasons = self._reasons(features) if score is not None else []
        self.hst.learn_one(features)
        for n in af.FEATURE_NAMES:
            self.mean[n] += MEAN_ALPHA * (features[n] - self.mean[n])
        self.n_seen += 1
        return score, reasons, features

    @property
    def warm(self) -> bool:
        return self.n_seen >= WARMUP

    def save_bytes(self) -> bytes:
        header = json.dumps({
            "format": CHECKPOINT_FORMAT, "river": _river_version(),
            "alert_feature_version": af.ALERT_FEATURE_VERSION, "model_version": MODEL_VERSION,
            "n_seen": self.n_seen, "saved_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }).encode()
        payload = pickle.dumps({"hst": self.hst, "state": self.state, "mean": self.mean, "n_seen": self.n_seen},
                               protocol=pickle.HIGHEST_PROTOCOL)
        return header + b"\n" + payload

    @classmethod
    def load_bytes(cls, data: bytes) -> "AnomalyModel":
        nl = data.find(b"\n")
        if nl < 0:
            raise CheckpointIncompatible("no header")
        try:
            head = json.loads(data[:nl])
        except ValueError as exc:
            raise CheckpointIncompatible(f"bad header: {exc}") from exc
        if head.get("format") != CHECKPOINT_FORMAT:
            raise CheckpointIncompatible(f"format {head.get('format')} != {CHECKPOINT_FORMAT}")
        if head.get("alert_feature_version") != af.ALERT_FEATURE_VERSION:
            raise CheckpointIncompatible(f"feature version {head.get('alert_feature_version')} != {af.ALERT_FEATURE_VERSION}")
        if head.get("river") != _river_version():
            raise CheckpointIncompatible(f"river {head.get('river')} != {_river_version()} (pickle not portable across versions)")
        body = pickle.loads(data[nl + 1:])
        m = cls()
        m.hst, m.state, m.mean, m.n_seen = body["hst"], body["state"], body["mean"], body["n_seen"]
        return m


def _river_version() -> str:
    import river
    return river.__version__
