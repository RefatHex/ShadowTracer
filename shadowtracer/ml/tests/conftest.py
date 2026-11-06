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
