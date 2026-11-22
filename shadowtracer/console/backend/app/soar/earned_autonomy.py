"""Earned autonomy (Phase 9 D). Every playbook starts in shadow (dry-run): the worker records a
"would have acted" action, executes nothing. As analysts later give incidents a verdict, we compute
each playbook's shadow precision; an admin may promote it to auto only once precision clears the
tenant's threshold over enough verdicted incidents (defaults 95% / 20). Promotion is audited.

Verdict signal = the incident's triage_status: 'escalated' is a true positive (the block would have
been right), 'false_positive' a false positive (it would have been wrong). Other statuses aren't a
definitive verdict yet and don't count. Precision is per distinct incident, not per action.
"""

import datetime

from sqlalchemy import select, text

from .. import audit
from .models import soar_playbooks, soar_tenant_settings

VALID_MODES = ("shadow", "approval", "auto")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def playbook_mode(db, tenant_key: str, playbook_key: str) -> str:
    """Current mode, defaulting to 'shadow' (and persisting that default) for a playbook never seen."""
    row = db.execute(select(soar_playbooks.c.mode).where(
        soar_playbooks.c.tenant_key == tenant_key,
        soar_playbooks.c.playbook_key == playbook_key)).first()
    if row:
        return row[0]
    db.execute(soar_playbooks.insert().values(tenant_key=tenant_key, playbook_key=playbook_key))
    db.commit()
    return "shadow"


def compute_precision(db, tenant_key: str, playbook_key: str) -> dict:
    """Shadow precision over verdicted incidents. -> {tp, fp, count, precision|None}."""
    rows = db.execute(text("""
        SELECT i.triage_status AS verdict, count(DISTINCT a.incident_id) AS n
        FROM soar_actions a JOIN incidents i ON i.id = a.incident_id
        WHERE a.tenant_key = :t AND a.playbook_key = :p AND a.status = 'shadow'
          AND i.triage_status IN ('escalated', 'false_positive')
        GROUP BY i.triage_status"""), {"t": tenant_key, "p": playbook_key}).mappings().all()
    tp = next((r["n"] for r in rows if r["verdict"] == "escalated"), 0)
    fp = next((r["n"] for r in rows if r["verdict"] == "false_positive"), 0)
    count = tp + fp
    return {"tp": tp, "fp": fp, "count": count, "precision": (tp / count) if count else None}


def can_promote_to_auto(db, tenant_key: str, playbook_key: str) -> tuple[bool, str | None, dict]:
    """Whether the playbook's shadow record clears the promotion gate. -> (ok, reason_if_not, stats)."""
    st = db.execute(select(soar_tenant_settings.c.promotion_min_precision,
                           soar_tenant_settings.c.promotion_min_incidents).where(
        soar_tenant_settings.c.tenant_key == tenant_key)).first()
    min_prec, min_n = (st[0], st[1]) if st else (0.95, 20)
    stats = compute_precision(db, tenant_key, playbook_key)
    stats["min_precision"] = min_prec
    stats["min_incidents"] = min_n
    if stats["count"] < min_n:
        return False, f"only {stats['count']} verdicted incidents (need {min_n})", stats
    if stats["precision"] < min_prec:
        return False, f"precision {stats['precision']:.2f} below {min_prec:.2f}", stats
    return True, None, stats


def set_mode(db, tenant_key: str, tenant_id: int | None, playbook_key: str, to_mode: str,
             actor: str) -> dict:
    """Switch a playbook's mode. Promotion to 'auto' is refused below the gate. Audited either way.
    -> {ok, mode, reason, stats}."""
    if to_mode not in VALID_MODES:
        raise ValueError(f"invalid mode {to_mode!r}")
    current = playbook_mode(db, tenant_key, playbook_key)
    stats = compute_precision(db, tenant_key, playbook_key)

    if to_mode == "auto":
        ok, reason, stats = can_promote_to_auto(db, tenant_key, playbook_key)
        if not ok:
            audit.append_entry(db, actor, tenant_id, "soar.promotion_refused",
                               f"{playbook_key}:{current}->auto ({reason})", "refused")
            return {"ok": False, "mode": current, "reason": reason, "stats": stats}

    now = _now()
    db.execute(soar_playbooks.update()
               .where(soar_playbooks.c.tenant_key == tenant_key,
                      soar_playbooks.c.playbook_key == playbook_key)
               .values(mode=to_mode, promoted_at=now, promoted_by=actor,
                       promoted_from=current, updated_at=now))
    audit.append_entry(db, actor, tenant_id, "soar.playbook_mode_changed",
                       f"{playbook_key}:{current}->{to_mode}", to_mode)
    return {"ok": True, "mode": to_mode, "reason": None, "stats": stats}
