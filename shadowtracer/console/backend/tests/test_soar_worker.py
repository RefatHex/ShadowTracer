"""Phase 9 (a): SOAR worker — confidence gate, safety rails, idempotent overlap-window polling,
audited action records. Hits the real isolated test Postgres (conftest), never a mock DB.
"""
import datetime

import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from app.soar import worker
from app.soar.models import soar_actions, soar_global_settings, soar_tenant_settings, soar_worker_state
from conftest import insert_tenant

TK = "soar-test-tenant"
NOW = datetime.datetime(2026, 11, 22, 12, 0, 0, tzinfo=datetime.timezone.utc)


@pytest.fixture
def sf(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture(autouse=True)
def _reset_singletons(db):
    # worker_state cursor and global kill switch are singletons the fixture TRUNCATE doesn't touch.
    db.execute(text("UPDATE soar_worker_state SET cursor_updated_at='epoch', cursor_id=0 WHERE id=1"))
    db.execute(text("UPDATE soar_global_settings SET kill_switch=false WHERE id=1"))
    db.commit()
    worker._TENANT_ID.clear()


def _mk_incident(db, *, tenant_key=TK, source_ips, updated_at=NOW, sources=2, ti=None,
                 rule_groups=("authentication_failures",), mitre=()):
    """Insert one open incident plus `sources` distinct incident_alerts rows (for anti-spoof)."""
    row = db.execute(text("""
        INSERT INTO incidents (tenant_key, correlation_key, correlation_basis, agent_id,
            first_seen, last_seen, state, source_ips, rule_ids, rule_groups, mitre_ids,
            ti_confidence, updated_at)
        VALUES (:t, :ck, 'source_ip', '001', :now, :now, 'open', :ips, '{5710}', :rg, :mitre, :ti, :upd)
        RETURNING id"""), {
        "t": tenant_key, "ck": f"ck-{source_ips[0]}", "now": NOW, "ips": list(source_ips),
        "rg": list(rule_groups), "mitre": list(mitre), "ti": ti, "upd": updated_at}).scalar()
    for i in range(sources):
        db.execute(text("""INSERT INTO incident_alerts (incident_id, tenant_key, node, alert_id, alert_time)
            VALUES (:iid, :t, :node, :aid, :now)"""),
            {"iid": row, "t": tenant_key, "node": f"node-{i}", "aid": f"{row}-{i}", "now": NOW})
    db.commit()
    return row


def _actions(db, incident_id):
    return db.execute(soar_actions.select().where(soar_actions.c.incident_id == incident_id)
                      ).mappings().all()


def test_brute_force_public_ip_requests_block_and_audits(db, sf):
    insert_tenant(db, TK)
    iid = _mk_incident(db, source_ips=["8.8.8.8"])
    worker.poll_once(sf, protected_ips_fn=lambda t: set(), now=NOW)
    acts = _actions(db, iid)
    assert len(acts) == 1
    a = acts[0]
    assert a["status"] == "requested" and a["action_type"] == "block_ip" and a["target"] == "8.8.8.8"
    assert a["mode"] == "approval" and a["block_seconds"] == 3600          # timed, tenant default
    assert any(s["type"] == "rule_match" for s in a["signals"])
    audit = db.execute(text("SELECT action, outcome FROM audit_log WHERE actor='soar-worker'")).mappings().all()
    assert ("soar.requested", "requested") in {(r["action"], r["outcome"]) for r in audit}


def test_internal_ip_is_refused_by_allowlist(db, sf):
    insert_tenant(db, TK)
    iid = _mk_incident(db, source_ips=["10.0.0.5"])
    worker.poll_once(sf, protected_ips_fn=lambda t: set(), now=NOW)
    acts = _actions(db, iid)
    assert len(acts) == 1 and acts[0]["status"] == "refused"
    assert acts[0]["refuse_reason"] == "allowlist:rfc1918_internal"


def test_agent_own_ip_is_refused(db, sf):
    insert_tenant(db, TK)
    iid = _mk_incident(db, source_ips=["8.8.8.8"])
    worker.poll_once(sf, protected_ips_fn=lambda t: {"8.8.8.8"}, now=NOW)   # 8.8.8.8 is an agent IP here
    assert _actions(db, iid)[0]["refuse_reason"] == "allowlist:manager_or_agent_ip"


def test_anti_spoof_single_source_no_ti_refused(db, sf):
    insert_tenant(db, TK)
    iid = _mk_incident(db, source_ips=["8.8.8.8"], sources=1)               # one corroborating alert, no TI
    worker.poll_once(sf, protected_ips_fn=lambda t: set(), now=NOW)
    assert _actions(db, iid)[0]["refuse_reason"] == "anti_spoof:single_observation_no_ti"


def test_anti_spoof_single_source_with_ti_allowed(db, sf):
    insert_tenant(db, TK)
    iid = _mk_incident(db, source_ips=["8.8.8.8"], sources=1, ti=90)        # TI overrides single source
    worker.poll_once(sf, protected_ips_fn=lambda t: set(), now=NOW)
    assert _actions(db, iid)[0]["status"] == "requested"


def test_global_kill_switch_refuses(db, sf):
    insert_tenant(db, TK)
    db.execute(text("UPDATE soar_global_settings SET kill_switch=true WHERE id=1"))
    db.commit()
    iid = _mk_incident(db, source_ips=["8.8.8.8"])
    worker.poll_once(sf, protected_ips_fn=lambda t: set(), now=NOW)
    assert _actions(db, iid)[0]["refuse_reason"] == "kill_switch"


def test_overlap_window_processes_late_incident_exactly_once(db, sf):
    # Condition 2: an incident whose updated_at is EARLIER than the stored cursor must still be
    # processed, and re-reads (overlap) must not duplicate it — the idempotency key is the guard.
    insert_tenant(db, TK)
    db.execute(text("UPDATE soar_worker_state SET cursor_updated_at=:c, cursor_id=999 WHERE id=1"),
               {"c": NOW})                                                  # cursor ahead of the incident
    db.commit()
    iid = _mk_incident(db, source_ips=["8.8.8.8"], updated_at=NOW - datetime.timedelta(seconds=30))
    worker.poll_once(sf, protected_ips_fn=lambda t: set(), now=NOW)         # within the 120s overlap
    assert len(_actions(db, iid)) == 1
    worker.poll_once(sf, protected_ips_fn=lambda t: set(), now=NOW)         # re-read: idempotent no-op
    assert len(_actions(db, iid)) == 1
    # cursor never regressed below the late row
    cur = db.execute(text("SELECT cursor_updated_at FROM soar_worker_state WHERE id=1")).scalar()
    assert cur == NOW


def test_scope_limit_trips_breaker_and_caps_targets(db, sf):
    insert_tenant(db, TK)
    db.execute(text("INSERT INTO soar_tenant_settings (tenant_key, scope_limit_per_run) VALUES (:t, 2)"),
               {"t": TK})
    db.commit()
    ips = ["8.8.8.8", "9.9.9.9", "1.1.1.1", "208.67.222.222"]
    iid = _mk_incident(db, source_ips=ips, ti=90)                           # ti so anti-spoof passes
    worker.poll_once(sf, protected_ips_fn=lambda t: set(), now=NOW)
    assert len(_actions(db, iid)) == 2                                      # capped to scope_limit
    tripped = db.execute(text("SELECT circuit_breaker_tripped, circuit_breaker_reason "
                              "FROM soar_tenant_settings WHERE tenant_key=:t"), {"t": TK}).mappings().first()
    assert tripped["circuit_breaker_tripped"] and tripped["circuit_breaker_reason"] == "scope_limit"


def test_rate_limit_trips_breaker(db, sf):
    insert_tenant(db, TK)
    db.execute(text("INSERT INTO soar_tenant_settings (tenant_key, rate_limit_per_hour) VALUES (:t, 1)"),
               {"t": TK})
    db.commit()
    _mk_incident(db, source_ips=["8.8.8.8"], ti=90)
    _mk_incident(db, source_ips=["9.9.9.9"], ti=90)
    # rate limit counts rows created in the last real hour, so the poll's logical `now` must be real
    # time here (not the fixed future NOW used for cursor math elsewhere).
    worker.poll_once(sf, protected_ips_fn=lambda t: set(), now=datetime.datetime.now(datetime.timezone.utc))
    tripped = db.execute(text("SELECT circuit_breaker_tripped, circuit_breaker_reason "
                              "FROM soar_tenant_settings WHERE tenant_key=:t"), {"t": TK}).mappings().first()
    assert tripped["circuit_breaker_tripped"] and tripped["circuit_breaker_reason"] == "rate_limit"
