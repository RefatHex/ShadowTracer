"""Train/serve parity: serving computes features through enrich.incident_features and feeds
features.model_input; training reads the STORED row back through features.from_row and feeds the
same model_input. Both must give the model identical input."""
import datetime as dt

from conftest import FakeConn, make_alerts, make_incident
from shadowtracer_ml import enrich, features


class FakeCH:
    def __init__(self, alerts):
        self.alerts, self.inserted = alerts, {}

    def query(self, sql, parameters=None):
        rows = [(a["time"].replace(tzinfo=None), a["rule_level"], a["rule_groups"], a["mitre_tactics"]) for a in self.alerts]

        class R:
            result_rows = rows
        return R()

    def insert(self, table, rows, column_names=None):
        self.inserted.setdefault(table, []).extend(rows)


def test_serving_features_equal_stored_training_features():
    inc, alerts = make_incident(), make_alerts()
    conn = FakeConn(rows=[("worker-test", str(i)) for i in range(len(alerts))])
    ch = FakeCH(alerts)
    served = enrich.incident_features(conn, ch, inc)
    assert served == features.compute(inc, alerts)
    enrich.store_features(ch, [features.to_row("t", inc["id"], inc["closed_at"], served)])
    stored = ch.inserted["ml_incident_features"][0]
    trained = features.from_row(stored[5])
    assert features.model_input([served]).equals(features.model_input([trained]))
    stats = {r[2]: r for r in ch.inserted["ml_feature_stats"]}
    assert set(stats) == set(features.FEATURE_NAMES) and stats["max_level"][3] == 1 and stats["max_level"][4] == 10.0


def test_serving_model_dummy_and_estimator_take_the_same_input():
    from shadowtracer_ml.evaluate import make_estimator
    from shadowtracer_ml.serving_model import IncidentRiskModel
    f = [features.compute(make_incident(max_level=lvl), make_alerts()) for lvl in (3, 12, 5, 15)]
    X = features.model_input(f)
    m = IncidentRiskModel()
    m.load_context(None)
    out = m.predict(None, X)
    assert list(out["score"].round(3)) == [0.2, 0.8, 0.333, 1.0]
    m.estimator = make_estimator().fit(X, [0, 1, 0, 1])
    out = m.predict(None, X)
    assert out["score"].between(0, 1).all() and len(out) == 4
