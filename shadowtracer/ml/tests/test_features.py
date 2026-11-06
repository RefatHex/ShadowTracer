import datetime as dt

from conftest import T0, make_alerts, make_incident
from shadowtracer_ml import features


def test_feature_names_reveal_no_source():
    leaks = [n for n in features.FEATURE_NAMES if any(s in n for s in features.FORBIDDEN_SUBSTRINGS)]
    assert leaks == []


def test_forbidden_list_covers_known_source_fields():
    for field in ("agent_id", "agent_name", "dataset_id", "tenant_key", "location", "node", "replay", "hour_of_day",
                  "weekday", "time_shift", "manager_name", "decoder_name", "run_id"):
        assert any(s in field for s in features.FORBIDDEN_SUBSTRINGS), field


def test_compute_returns_exactly_the_feature_names():
    f = features.compute(make_incident(), make_alerts())
    assert tuple(sorted(f)) == features.FEATURE_NAMES
    assert f["max_level"] == 10 and abs(f["lvl_crit"] - 0.25) < 1e-9 and f["t_credential-access"] == 0.5


def test_features_do_not_change_with_source_fields_or_retiming():
    base = features.compute(make_incident(), make_alerts())
    shift = dt.timedelta(days=1234, hours=7, minutes=13)
    moved = make_incident(agent_id="001", agent_name="agent-ubuntu-1", location="/var/log/auth.log", dataset_id=None,
                          node="worker1", tenant_key="other", first_seen=T0 + shift,
                          last_seen=T0 + shift + dt.timedelta(minutes=3), closed_at=T0 + shift + dt.timedelta(minutes=10))
    alerts = [dict(a, agent_id="001", agent_name="agent-ubuntu-1", location="/var/log/auth.log") for a in make_alerts(shift)]
    assert features.compute(moved, alerts) == base


def test_alerts_after_close_are_ignored():
    inc = make_incident(closed_at=T0 + dt.timedelta(seconds=45))
    late = features.compute(inc, make_alerts())
    assert late == features.compute(inc, make_alerts()[:2])


def test_vector_order_and_round_trip():
    f = features.compute(make_incident(), make_alerts())
    row = features.to_row("t", 1, T0, f)
    assert features.from_row(row[5]) == f
    assert features.vector(f) == list(features.model_input([f]).iloc[0])
