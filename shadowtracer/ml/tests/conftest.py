import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..', 'ingest'))
import datetime as dt

import pytest

T0 = dt.datetime(2026, 11, 6, 12, 0, tzinfo=dt.timezone.utc)


class FakeConn:
    """Records execute() calls; returns canned rows for SELECTs."""

    def __init__(self, rows=None):
        self.calls, self.rows = [], rows or []

    def execute(self, stmt, params=None):
        self.calls.append((str(stmt), params or {}))
        conn = self

        class R:
            rowcount = 1

            def all(self_):
                return conn.rows

            def first(self_):
                return conn.rows[0] if conn.rows else None
        return R()


@pytest.fixture
def fake_conn():
    return FakeConn()


def make_incident(**kw):
    inc = {"id": 1, "tenant_key": "t", "first_seen": T0, "last_seen": T0 + dt.timedelta(minutes=3),
           "closed_at": T0 + dt.timedelta(minutes=10), "alert_count": 4, "max_level": 10, "rule_ids": ["5710", "5503"],
           "rule_groups": ["sshd", "authentication_failed"], "source_ip_total": 1, "user_total": 2,
           "correlation_basis": "source_ip", "rare_pattern_flag": False, "prior_occurrences": 3, "ti_confidence": None,
           # source-revealing fields an incident/alert may carry - must never change features
           "agent_id": "002", "agent_name": "replay-x", "location": "EventChannel", "dataset_id": "splunk:x", "node": "worker-test"}
    inc.update(kw)
    return inc


def make_alerts(shift=dt.timedelta(0)):
    return [{"time": T0 + shift + dt.timedelta(seconds=30 * i), "rule_level": lvl, "rule_groups": g, "mitre_tactics": t,
             "agent_id": "002", "agent_name": "replay-x", "location": "EventChannel"}
            for i, (lvl, g, t) in enumerate([(5, ["sshd", "authentication_failed"], ["Credential Access"]),
                                             (10, ["sshd", "authentication_failures"], ["Credential Access"]),
                                             (3, ["pam"], []), (12, ["sysmon", "sysmon_eid1_detections"], ["Execution"])])]


class FakeAlert:
    """Duck-typed NormalizedEvent for the 7.1 streaming feature/model tests."""
    def __init__(self, agent_id="001", rule_level=5, rule_groups=("sshd",), time=None,
                 src_endpoint_ip="", actor_user="", target_user="", agent_name="a", location="/var/log/auth.log",
                 cluster_node="worker-test", alert_id="1793970000.1"):
        self.agent_id, self.rule_level, self.rule_groups = agent_id, rule_level, list(rule_groups)
        self.time = time or "2026-11-07T09:30:00+00:00"
        self.src_endpoint_ip, self.actor_user, self.target_user = src_endpoint_ip, actor_user, target_user
        self.agent_name, self.location, self.cluster_node, self.alert_id = agent_name, location, cluster_node, alert_id
