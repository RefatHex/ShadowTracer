"""SOAR worker (Phase 9 (a)): off the hot path, polls open incidents from Postgres, runs the
confidence gate and safety rails, and records every intended/taken containment action in
soar_actions, audited. It executes nothing yet — an allowed action is recorded status='requested'
(mode='approval'); approval/execution (c) and shadow/auto (b) layer on top. A refused action
(kill switch / allowlist / anti-spoof) is recorded status='refused' with the reason.

Polling cannot miss a row: each poll re-reads an OVERLAP window behind the stored (updated_at, id)
cursor, so an incident whose transaction commits with an updated_at earlier than the cursor is still
seen on the next poll; the soar_actions idempotency constraint makes the re-read a no-op. The cursor
only ever advances (never regresses below a late row).
"""

import datetime
import logging
import os
import time

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .. import audit, wazuh_api
from ..config import load_settings
from ..db import make_session_factory
from ..models import incident_alerts, incidents, tenants
from . import (actions, assets, earned_autonomy, gate, notify, playbooks, provenance,
               rails, repeat_offender, triggers)
from .models import (soar_actions, soar_allowlist, soar_global_settings,
                     soar_tenant_settings, soar_worker_state)

log = logging.getLogger("soar.worker")

OVERLAP = datetime.timedelta(seconds=int(os.environ.get("SOAR_POLL_OVERLAP_SECONDS", "120")))
POLL_INTERVAL = int(os.environ.get("SOAR_POLL_INTERVAL_SECONDS", "30"))
TI_MIN = gate.TI_MIN_CONFIDENCE

_TENANT_ID: dict[str, int] = {}


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _tenant_id(db, tenant_key: str) -> int | None:
    if tenant_key not in _TENANT_ID:
        row = db.execute(select(tenants.c.id).where(tenants.c.tenant_key == tenant_key)).first()
        if not row:
            return None
        _TENANT_ID[tenant_key] = row[0]
    return _TENANT_ID[tenant_key]


def _audit(db, tenant_key: str, action: str, target: str, outcome: str) -> None:
    audit.append_entry(db, "soar-worker", _tenant_id(db, tenant_key), action, target, outcome)


def _tenant_settings(db, tenant_key: str) -> dict:
    """Fetch (and lazily create) the tenant's SOAR settings row."""
    row = db.execute(select(soar_tenant_settings).where(
        soar_tenant_settings.c.tenant_key == tenant_key)).mappings().first()
    if row:
        return dict(row)
    db.execute(soar_tenant_settings.insert().values(tenant_key=tenant_key))
    db.commit()
    return db.execute(select(soar_tenant_settings).where(
        soar_tenant_settings.c.tenant_key == tenant_key)).mappings().first()


def _global_kill(db) -> bool:
    return bool(db.execute(select(soar_global_settings.c.kill_switch)
                           .where(soar_global_settings.c.id == 1)).scalar())


def _allow_cidrs(db, tenant_key: str) -> list[str]:
    return [r[0] for r in db.execute(select(soar_allowlist.c.cidr)
            .where(soar_allowlist.c.tenant_key == tenant_key)).all()]


def _observation_count(db, incident_id: int) -> int:
    """Number of alert records evidencing this incident — anti-spoof corroboration (a forged single
    log line yields 1; real activity yields many, even from one agent)."""
    return db.execute(select(func.count()).select_from(incident_alerts)
                      .where(incident_alerts.c.incident_id == incident_id)).scalar() or 0


def _actions_last_hour(db, tenant_key: str, now: datetime.datetime) -> int:
    return db.execute(select(func.count()).select_from(soar_actions).where(
        soar_actions.c.tenant_key == tenant_key,
        soar_actions.c.created_at >= now - datetime.timedelta(hours=1),
        soar_actions.c.status.in_(("requested", "approved", "executed")))).scalar() or 0


def _trip_breaker(db, tenant_key: str, reason: str, now: datetime.datetime) -> None:
    db.execute(soar_tenant_settings.update()
               .where(soar_tenant_settings.c.tenant_key == tenant_key)
               .values(circuit_breaker_tripped=True, circuit_breaker_reason=reason,
                       circuit_breaker_tripped_at=now, updated_at=now))
    _audit(db, tenant_key, "soar.circuit_breaker_tripped", reason, "tripped")
    notify.notify_safe(db, tenant_key, "circuit_breaker_tripped",
                       {"incident_title": "circuit breaker", "action_status": reason, "severity": 0}, 0)


def default_protected_ips(tenant_key: str) -> set[str]:
    """Agent + manager IPs for a tenant, from its Wazuh manager API. Best-effort: an empty set on
    any failure (the RFC1918 rail still refuses internal targets)."""
    base = wazuh_api.endpoints().get(tenant_key)
    if not base:
        return set()
    try:
        return {a["ip"] for a in wazuh_api.list_agents(base) if a.get("ip")}
    except wazuh_api.WazuhApiError:
        return set()


def _resolve(pb_mode: str, asset_level: str, gate_passed: bool, decision) -> tuple[str, str, str | None, str]:
    """Map playbook mode + asset level + confidence gate + rails into
    (status, effective_mode, approved_by, event). shadow -> record a would-have action, execute
    nothing. auto -> no human, but only on a 'full' asset with a passing gate and no rail downgrade;
    otherwise an approval request. The gate keeps a 1-signal or model-only incident out of auto."""
    if pb_mode == "shadow":
        return "shadow", "shadow", None, "soar.shadow"
    # Auto executes with no human ONLY when the asset is 'full' AND the gate passes AND the rails did
    # not downgrade. An 'approval' asset never auto-executes even under an auto playbook.
    if pb_mode == "auto" and asset_level == "full" and gate_passed and not decision.force_approval:
        return "approved", "auto", "auto", "soar.auto_approved"
    return "requested", "approval", None, "soar.requested"


def _record_action(db, *, tenant_key, incident_id, playbook_key, action_type, target, agent_id,
                   mode, status, signals, refuse_reason, block_seconds, approved_by=None) -> bool:
    """Idempotent insert. Returns True if a new row was created (so the caller audits once)."""
    stmt = pg_insert(soar_actions).values(
        tenant_key=tenant_key, incident_id=incident_id, playbook_key=playbook_key,
        action_type=action_type, target=target, agent_id=agent_id, mode=mode, status=status,
        signals=signals, refuse_reason=refuse_reason, block_seconds=block_seconds,
        approved_by=approved_by,
    ).on_conflict_do_nothing(constraint="soar_actions_idempotent").returning(soar_actions.c.id)
    return db.execute(stmt).first() is not None


def process_incident(db, inc: dict, now: datetime.datetime, protected_ips: set[str],
                     trusted_ips: set[str]) -> None:
    tenant_key = inc["tenant_key"]
    plays = triggers.match(inc)
    if not plays:
        return

    st = _tenant_settings(db, tenant_key)
    gkill = _global_kill(db)
    allow_cidrs = _allow_cidrs(db, tenant_key)
    observations = _observation_count(db, inc["id"])
    ti_confirmed = (inc.get("ti_confidence") or 0) >= TI_MIN
    gate_passed, signals = gate.evaluate(inc)
    level = assets.asset_level(db, tenant_key, inc.get("agent_id"))      # A1: full | approval | none

    for playbook_key, action_type, targets in plays:
        pb_mode = earned_autonomy.playbook_mode(db, tenant_key, playbook_key)   # default 'shadow'

        # A1: a 'none' asset is never contained — refuse every target (audited); notify already ran.
        if level == "none":
            for ip in targets:
                if _record_action(db, tenant_key=tenant_key, incident_id=inc["id"],
                                  playbook_key=playbook_key, action_type=action_type, target=ip,
                                  agent_id=inc.get("agent_id"), mode=pb_mode, status="refused",
                                  signals=signals, refuse_reason="asset_level_none",
                                  block_seconds=None, approved_by=None):
                    _audit(db, tenant_key, "soar.refused", f"{action_type}:{ip} (asset_level_none)", "refused")
            continue

        # Scope limit: one run may act on at most scope_limit targets; overflow trips the breaker.
        scope = st["scope_limit_per_run"]
        if len(targets) > scope:
            _trip_breaker(db, tenant_key, "scope_limit", now)
            st["circuit_breaker_tripped"] = True
            targets = targets[:scope]

        for ip in targets:
            actions_last_hour = _actions_last_hour(db, tenant_key, now)
            decision = rails.guard(
                ip, global_kill=gkill, tenant_kill=st["kill_switch"],
                breaker_tripped=st["circuit_breaker_tripped"], allow_cidrs=allow_cidrs,
                protected_ips=protected_ips, trusted_field=(ip in trusted_ips),
                observations=observations, ti_confirmed=ti_confirmed,
                actions_last_hour=actions_last_hour, rate_limit=st["rate_limit_per_hour"])

            if not decision.allowed:
                if _record_action(db, tenant_key=tenant_key, incident_id=inc["id"],
                                  playbook_key=playbook_key, action_type=action_type, target=ip,
                                  agent_id=inc.get("agent_id"), mode=pb_mode, status="refused",
                                  signals=signals, refuse_reason=decision.refuse_reason,
                                  block_seconds=None, approved_by=None):
                    _audit(db, tenant_key, "soar.refused",
                           f"{action_type}:{ip} ({decision.refuse_reason})", "refused")
                continue

            if decision.breaker_trip_reason and not st["circuit_breaker_tripped"]:
                _trip_breaker(db, tenant_key, decision.breaker_trip_reason, now)
                st["circuit_breaker_tripped"] = True

            # A2: repeat-offender escalation owns the block duration for block_ip.
            action_signals = list(signals)
            if action_type == "block_ip":
                block_seconds, prior = repeat_offender.duration_for(
                    db, tenant_key, ip, schedule=st["escalation_schedule"],
                    window_seconds=st["repeat_window_seconds"], cap=st["block_max_seconds"], now=now)
                if prior:
                    action_signals.append({"type": "repeat_offender",
                                           "detail": f"offense #{prior + 1} → {block_seconds}s", "counts": False})
            else:
                pb_block = playbooks.block_seconds_for(db, tenant_key, playbook_key, st["block_default_seconds"])
                block_seconds = rails.clamp_block_seconds(
                    pb_block, st["block_default_seconds"], st["block_max_seconds"])
            signals_for_row = action_signals
            status, mode_rec, approved_by, event = _resolve(pb_mode, level, gate_passed, decision)
            if _record_action(db, tenant_key=tenant_key, incident_id=inc["id"],
                              playbook_key=playbook_key, action_type=action_type, target=ip,
                              agent_id=inc.get("agent_id"), mode=mode_rec, status=status,
                              signals=signals_for_row, refuse_reason=None, block_seconds=block_seconds,
                              approved_by=approved_by):
                _audit(db, tenant_key, event, f"{action_type}:{ip}", status)
                if status == "requested":                    # escalate: an approval is needed
                    ctx = notify.incident_ctx(db, tenant_key, inc["id"])
                    ctx.update({"action": action_type, "action_status": "requested"})
                    notify.notify_safe(db, tenant_key, "approval_needed", ctx, ctx.get("severity") or 0)


def expire_stale(db, now: datetime.datetime, *, reverse_fn=actions.reverse_block,
                 base_url_fn=lambda t: wazuh_api.endpoints().get(t)) -> None:
    """Two time-based transitions (Phase 9 c): an unanswered approval request past its tenant TTL
    expires as no-action (and should escalate a notification — Phase 9 e); an executed block past its
    expiry is reversed and marked expired. A reverse that can't reach the manager is left to retry."""
    # unanswered approvals -> expired (no action)
    stale = db.execute(text("""
        SELECT a.id, a.tenant_key, a.action_type, a.target
        FROM soar_actions a LEFT JOIN soar_tenant_settings s ON s.tenant_key = a.tenant_key
        WHERE a.status = 'requested'
          AND a.created_at < :now - make_interval(secs => COALESCE(s.approval_ttl_seconds, 3600))
    """), {"now": now}).mappings().all()
    for a in stale:
        db.execute(soar_actions.update().where(soar_actions.c.id == a["id"])
                   .values(status="expired", expired_at=now, updated_at=now))
        _audit(db, a["tenant_key"], "soar.approval_expired",
               f"{a['action_type']}:{a['target']}", "expired")
        notify.notify_safe(db, a["tenant_key"], "approval_expired",
                           {"incident_title": f"{a['action_type']}:{a['target']}",
                            "action_status": "expired (no action)", "severity": 0}, 0)

    # executed blocks past expiry -> reverse + expired
    due = db.execute(text("""
        SELECT id, tenant_key, agent_id, action_type, target FROM soar_actions
        WHERE status = 'executed' AND block_expires_at IS NOT NULL AND block_expires_at < :now
    """), {"now": now}).mappings().all()
    for a in due:
        if a["action_type"] not in actions.REVERSIBLE:   # only timed, reversible actions are swept
            continue
        base = base_url_fn(a["tenant_key"])
        if not base:
            continue
        try:
            reverse_fn(base, a["agent_id"], a["target"])
        except wazuh_api.WazuhApiError:
            log.warning("soar: expiry reverse failed for action %s; will retry", a["id"])
            continue
        db.execute(soar_actions.update().where(soar_actions.c.id == a["id"])
                   .values(status="expired", expired_at=now, updated_at=now))
        _audit(db, a["tenant_key"], "soar.block_expired",
               f"{a['action_type']}:{a['target']}", "expired")


def _alert_ids(db, incident_id: int) -> list[str]:
    return [r[0] for r in db.execute(select(incident_alerts.c.alert_id)
            .where(incident_alerts.c.incident_id == incident_id)).all()]


def _notify_incident_opened(db, inc: dict) -> None:
    """A6: incident_opened (once per incident, severity gated at the channel). Deduped on the incident."""
    tk = inc["tenant_key"]
    seen = db.execute(text("SELECT 1 FROM soar_notifications WHERE tenant_key=:t AND event='incident_opened' "
                           "AND context->>'incident_id' = :i LIMIT 1"),
                      {"t": tk, "i": str(inc["id"])}).first()
    if seen:
        return
    ctx = notify.incident_ctx(db, tk, inc["id"])
    ctx["action_status"] = "opened"
    notify.notify_safe(db, tk, "incident_opened", ctx, ctx.get("severity") or 0)


def poll_once(session_factory, *, protected_ips_fn=default_protected_ips,
              blockable_ips_fn=None, now=None) -> int:
    """One poll cycle. Returns the number of incidents examined. Exactly-once processing is the
    idempotency constraint's job, not the cursor's — the overlap re-read is deliberately at-least-once.
    blockable_ips_fn(tenant_key, alert_ids) -> set of IPs that reached us through a trusted network
    decoder field (A4); None uses the live ClickHouse lookup."""
    now = now or _utcnow()
    if blockable_ips_fn is None:
        blockable_ips_fn = provenance.make_default_fn(load_settings())
    examined = 0
    with session_factory() as db:
        expire_stale(db, now)
        cur = db.execute(select(soar_worker_state.c.cursor_updated_at, soar_worker_state.c.cursor_id)
                         .where(soar_worker_state.c.id == 1)).first()
        since = (cur[0] - OVERLAP) if cur else datetime.datetime.min
        rows = db.execute(select(incidents).where(
            incidents.c.updated_at >= since, incidents.c.state == "open"
        ).order_by(incidents.c.updated_at, incidents.c.id)).mappings().all()

        max_updated, max_id = (cur[0], cur[1]) if cur else (datetime.datetime.min, 0)
        ip_cache: dict[str, set[str]] = {}
        for inc in rows:
            examined += 1
            tk = inc["tenant_key"]
            if tk not in ip_cache:
                ip_cache[tk] = protected_ips_fn(tk)
            try:
                _notify_incident_opened(db, dict(inc))
                trusted = blockable_ips_fn(tk, _alert_ids(db, inc["id"]))
                process_incident(db, dict(inc), now, ip_cache[tk], trusted)
            except Exception:                       # one bad incident never stalls the poll
                log.exception("soar: failed to process incident %s", inc["id"])
                db.rollback()
            # advance the high-water mark (monotonic; a late row below it won't regress it)
            if (inc["updated_at"], inc["id"]) > (max_updated, max_id):
                max_updated, max_id = inc["updated_at"], inc["id"]

        db.execute(soar_worker_state.update().where(soar_worker_state.c.id == 1)
                   .values(cursor_updated_at=max_updated, cursor_id=max_id, updated_at=now))
        db.commit()
        try:
            notify.deliver_pending(db, now)
        except Exception:                           # delivery never breaks the poll cycle
            log.exception("soar notify delivery failed")
    return examined


def run() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = load_settings()
    sf = make_session_factory(settings)
    blockable = provenance.make_default_fn(settings)         # built once, reused each poll
    log.info("soar worker started (poll %ss, overlap %ss)", POLL_INTERVAL, OVERLAP.total_seconds())
    while True:
        try:
            n = poll_once(sf, blockable_ips_fn=blockable)
            log.debug("soar poll examined %d incidents", n)
        except Exception:
            log.exception("soar poll cycle failed")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
