"""Phase 9 (f): SOAR metrics — MTTD/MTTC, automation rate, undo rate, false-positive action rate."""
import datetime

from sqlalchemy import text

import uuid

from app.soar import metrics
from conftest import insert_tenant
from test_incidents_api import _token_for, app_settings, client, tenant  # noqa: F401

TK = "soar-metrics-tenant"
T0 = datetime.datetime(2026, 11, 22, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _incident(db, *, triage, created_off, first_off=0):
    return db.execute(text("""
        INSERT INTO incidents (tenant_key, correlation_key, correlation_basis, agent_id,
            first_seen, last_seen, state, triage_status, source_ips, created_at)
        VALUES (:t, :ck, 'source_ip', '001', :fs, :fs, 'closed', :v, '{8.8.8.8}', :cr) RETURNING id"""),
        {"t": TK, "ck": f"ck-{created_off}", "v": triage,
         "fs": T0 + datetime.timedelta(seconds=first_off),
         "cr": T0 + datetime.timedelta(seconds=created_off)}).scalar()


def _action(db, iid, *, status, approved_by, created_off, exec_off):
    db.execute(text("""INSERT INTO soar_actions (tenant_key, incident_id, playbook_key, action_type,
        target, mode, status, approved_by, created_at, executed_at)
        VALUES (:t, :i, 'builtin-ssh-brute-force', 'block_ip', '8.8.8.8', 'approval', :s, :by, :cr, :ex)"""),
        {"t": TK, "i": iid, "s": status, "by": approved_by,
         "cr": T0 + datetime.timedelta(seconds=created_off),
         "ex": T0 + datetime.timedelta(seconds=exec_off)})
    db.commit()


def test_metrics_timings_and_rates(db):
    insert_tenant(db, TK)
    # i1: human-approved executed, verdicted escalated (TP). detect 10s, contain at +40s.
    i1 = _incident(db, triage="escalated", created_off=10)
    _action(db, i1, status="executed", approved_by="5", created_off=20, exec_off=40)
    # i2: AUTO executed, verdicted false_positive. detect 10s, contain at +25s.
    i2 = _incident(db, triage="false_positive", created_off=10)
    _action(db, i2, status="executed", approved_by="auto", created_off=15, exec_off=25)
    # i3: undone, no verdict yet.
    i3 = _incident(db, triage="new", created_off=10)
    _action(db, i3, status="undone", approved_by="7", created_off=10, exec_off=30)

    m = metrics.compute(db, TK, since=T0 - datetime.timedelta(days=1))
    assert m["executions"] == 3                                  # all three have executed_at
    assert m["mttd_seconds"] == 10.0                             # created - first_seen
    assert round(m["automation_rate"], 2) == 0.33               # 1 auto of 3
    assert round(m["undo_rate"], 2) == 0.33                      # 1 undone of 3 executed
    assert m["false_positive_action_rate"] == 0.5                # 1 fp of 2 verdicted (i3 'new' excluded)
    assert m["mttc_seconds"] is not None and m["mttc_seconds"] > 0


def test_metrics_empty_tenant_has_no_divide_by_zero(db):
    insert_tenant(db, TK)
    m = metrics.compute(db, TK)
    assert m["executions"] == 0 and m["automation_rate"] is None and m["undo_rate"] is None


def test_metrics_endpoint_analyst(client, db, tenant):
    tid, tk = tenant
    tok = _token_for(client, db, tid, f"a-{uuid.uuid4().hex[:8]}@x.io", role="analyst")
    r = client.get("/api/soar/metrics", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and "automation_rate" in r.json() and "mttc_seconds" in r.json()
