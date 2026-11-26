"""SOAR console API (Phase 9 G/H): approvals queue, approve/deny, undo, action history.
Tenant-scoped, analyst+ (admin for disable_account/quarantine approvals — enforced in approvals.py).
Four-eyes and reason-required are enforced in the logic layer. A cross-tenant action id -> 404.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..audit import append_entry
from ..rbac import ADMIN_ONLY, ANALYST_OR_ABOVE, CurrentUser
from ..deps import get_db
from ..soar import approvals, assets, earned_autonomy, metrics as metrics_logic, notify, playbooks
from ..soar.models import (soar_allowlist, soar_channels, soar_playbooks, soar_tenant_settings)

router = APIRouter(prefix="/api/soar", tags=["soar"])


class Decision(BaseModel):
    reason: str


class ChannelConfig(BaseModel):
    enabled: bool | None = None
    detail_level: str | None = None
    min_severity: int | None = None
    throttle_seconds: int | None = None
    batch_window_seconds: int | None = None


class AssetLevel(BaseModel):
    scope_type: str
    scope_value: str
    level: str


class KillSwitch(BaseModel):
    enabled: bool


def _load(db, user: CurrentUser, action_id: int) -> dict:
    action = approvals.get_action(db, user.tenant_key, action_id)
    if action is None:
        raise HTTPException(status_code=404, detail="action not found")
    return action


@router.get("/approvals")
def pending(db: Session = Depends(get_db), user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    return {"pending": approvals.list_pending(db, user.tenant_key)}


@router.get("/metrics")
def metrics(db: Session = Depends(get_db), user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    """MTTD / MTTC, automation rate, undo rate, false-positive action rate (last 30 days)."""
    return metrics_logic.compute(db, user.tenant_key)


@router.get("/actions")
def history(limit: int = 100, db: Session = Depends(get_db),
            user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    from sqlalchemy import select
    from ..soar.models import soar_actions
    rows = db.execute(select(soar_actions).where(soar_actions.c.tenant_key == user.tenant_key)
                      .order_by(soar_actions.c.created_at.desc()).limit(min(limit, 500))).mappings().all()
    return {"actions": [dict(r) for r in rows]}


@router.post("/approvals/{action_id}/approve")
def approve(action_id: int, body: Decision, db: Session = Depends(get_db),
            user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    action = _load(db, user, action_id)
    try:
        return approvals.approve(db, user.tenant_key, user.tenant_id, action,
                                 str(user.user_id), user.role, body.reason)
    except approvals.ApprovalError as e:
        raise HTTPException(status_code=e.code, detail=e.message)


@router.post("/approvals/{action_id}/deny")
def deny(action_id: int, body: Decision, db: Session = Depends(get_db),
         user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    action = _load(db, user, action_id)
    try:
        return approvals.deny(db, user.tenant_key, user.tenant_id, action,
                              str(user.user_id), user.role, body.reason)
    except approvals.ApprovalError as e:
        raise HTTPException(status_code=e.code, detail=e.message)


@router.post("/actions/{action_id}/undo")
def undo(action_id: int, db: Session = Depends(get_db),
         user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    action = _load(db, user, action_id)
    try:
        return approvals.undo(db, user.tenant_key, user.tenant_id, action, str(user.user_id), user.role)
    except approvals.ApprovalError as e:
        raise HTTPException(status_code=e.code, detail=e.message)


# --- notification channels (admin): secrets are env-only; the API only reports configured/not ---

@router.get("/channels")
def channels(db: Session = Depends(get_db), user: CurrentUser = Depends(ADMIN_ONLY)):
    cfg = {r["channel"]: dict(r) for r in db.execute(select(soar_channels).where(
        soar_channels.c.tenant_key == user.tenant_key)).mappings().all()}
    out = []
    for ch in notify.CHANNELS:
        c = cfg.get(ch, {})
        out.append({
            "channel": ch,
            "enabled": c.get("enabled", False),
            "detail_level": c.get("detail_level", "minimal"),
            "min_severity": c.get("min_severity", 0),
            "throttle_seconds": c.get("throttle_seconds", 0),
            "batch_window_seconds": c.get("batch_window_seconds", 60),
            "configured": notify.is_configured(user.tenant_key, ch),   # presence of an env secret; never the secret
        })
    return {"channels": out}


@router.put("/channels/{channel}")
def set_channel(channel: str, body: ChannelConfig, db: Session = Depends(get_db),
                user: CurrentUser = Depends(ADMIN_ONLY)):
    if channel not in notify.CHANNELS:
        raise HTTPException(status_code=404, detail="unknown channel")
    if body.detail_level and body.detail_level not in ("minimal", "standard"):
        raise HTTPException(status_code=400, detail="detail_level must be minimal or standard")
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    fields["updated_by"] = str(user.user_id)
    db.execute(pg_insert(soar_channels).values(
        tenant_key=user.tenant_key, channel=channel, **fields
    ).on_conflict_do_update(index_elements=["tenant_key", "channel"], set_=fields))
    append_entry(db, str(user.user_id), user.tenant_id, "soar.channel_configured",
                 f"{channel}:{'on' if fields.get('enabled') else 'off'}", "updated")
    return {"ok": True, "channel": channel, **fields}


@router.get("/asset-levels")
def asset_levels(db: Session = Depends(get_db), user: CurrentUser = Depends(ADMIN_ONLY)):
    return {"levels": assets.list_levels(db, user.tenant_key), "default": assets.DEFAULT_LEVEL}


@router.put("/asset-levels")
def set_asset_level(body: AssetLevel, db: Session = Depends(get_db),
                    user: CurrentUser = Depends(ADMIN_ONLY)):
    try:
        return assets.set_level(db, user.tenant_key, user.tenant_id, body.scope_type,
                                body.scope_value, body.level, str(user.user_id))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/settings/kill-switch")
def kill_switch(body: KillSwitch, db: Session = Depends(get_db),
                user: CurrentUser = Depends(ADMIN_ONLY)):
    """Toggle the tenant kill switch (stops all containment). Audited; notifies the channels."""
    db.execute(pg_insert(soar_tenant_settings).values(tenant_key=user.tenant_key, kill_switch=body.enabled)
               .on_conflict_do_update(index_elements=["tenant_key"], set_={"kill_switch": body.enabled}))
    append_entry(db, str(user.user_id), user.tenant_id, "soar.kill_switch_toggled",
                 f"tenant={'on' if body.enabled else 'off'}", "on" if body.enabled else "off")
    notify.notify_safe(db, user.tenant_key, "kill_switch_toggled",
                       {"incident_title": "kill switch", "action_status": "on" if body.enabled else "off",
                        "severity": 0}, 0)
    return {"ok": True, "kill_switch": body.enabled}


@router.post("/channels/{channel}/test")
def test_channel(channel: str, db: Session = Depends(get_db), user: CurrentUser = Depends(ADMIN_ONLY)):
    if channel not in notify.CHANNELS:
        raise HTTPException(status_code=404, detail="unknown channel")
    if not notify.is_configured(user.tenant_key, channel):
        raise HTTPException(status_code=409, detail="channel is not configured (set its secret in the env)")
    queued = notify.enqueue(db, user.tenant_key, "test",
                            {"incident_title": "test message", "action_status": "ok"}, 0,
                            only_channel=channel)
    append_entry(db, str(user.user_id), user.tenant_id, "soar.channel_test", channel, "queued")
    return {"queued": queued}


# --- playbooks (list + promote) ---

class ModeChange(BaseModel):
    mode: str


@router.get("/playbooks")
def list_playbooks(db: Session = Depends(get_db), user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    """Each shipped/edited playbook with its mode, version, and shadow precision + verdict count."""
    stored = {r["playbook_key"]: dict(r) for r in db.execute(select(soar_playbooks).where(
        soar_playbooks.c.tenant_key == user.tenant_key)).mappings().all()}
    keys = sorted(set(playbooks.DEFAULT_PLAYBOOKS) | set(stored))
    out = []
    for key in keys:
        pb = stored.get(key, {})
        ok, reason, stats = earned_autonomy.can_promote_to_auto(db, user.tenant_key, key)
        default = playbooks.DEFAULT_PLAYBOOKS.get(key, {})
        out.append({
            "playbook_key": key,
            "title": (pb.get("definition") or default).get("title", key),
            "mode": pb.get("mode", "shadow"),
            "version": pb.get("version", 1),
            "block_seconds": playbooks.block_seconds_for(db, user.tenant_key, key, 3600),
            "precision": stats["precision"], "verdict_count": stats["count"],
            "can_promote_to_auto": ok, "promote_blocked_reason": reason,
            "min_precision": stats.get("min_precision"), "min_incidents": stats.get("min_incidents"),
            "promoted_by": pb.get("promoted_by"), "updated_by": pb.get("updated_by"),
        })
    return {"playbooks": out}


@router.post("/playbooks/{playbook_key}/mode")
def set_playbook_mode(playbook_key: str, body: ModeChange, db: Session = Depends(get_db),
                      user: CurrentUser = Depends(ADMIN_ONLY)):
    try:
        res = earned_autonomy.set_mode(db, user.tenant_key, user.tenant_id, playbook_key,
                                       body.mode, str(user.user_id))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not res["ok"]:
        raise HTTPException(status_code=409, detail=res["reason"] or "promotion refused")
    return res


# --- settings (tenant limits/thresholds + allowlist + kill switches) ---

class SettingsUpdate(BaseModel):
    block_default_seconds: int | None = None
    block_max_seconds: int | None = None
    rate_limit_per_hour: int | None = None
    scope_limit_per_run: int | None = None
    approval_ttl_seconds: int | None = None
    promotion_min_precision: float | None = None
    promotion_min_incidents: int | None = None
    repeat_window_seconds: int | None = None
    escalation_schedule: list[int] | None = None
    circuit_breaker_tripped: bool | None = None       # admin reset of the breaker


class AllowlistEntry(BaseModel):
    cidr: str
    note: str | None = None


@router.get("/settings")
def get_settings(db: Session = Depends(get_db), user: CurrentUser = Depends(ANALYST_OR_ABOVE)):
    row = db.execute(select(soar_tenant_settings).where(
        soar_tenant_settings.c.tenant_key == user.tenant_key)).mappings().first()
    allow = [dict(r) for r in db.execute(select(soar_allowlist).where(
        soar_allowlist.c.tenant_key == user.tenant_key).order_by(soar_allowlist.c.cidr)).mappings().all()]
    gkill = db.execute(text("SELECT kill_switch FROM soar_global_settings WHERE id=1")).scalar()
    return {"settings": dict(row) if row else None, "allowlist": allow, "global_kill_switch": gkill}


@router.put("/settings")
def update_settings(body: SettingsUpdate, db: Session = Depends(get_db),
                    user: CurrentUser = Depends(ADMIN_ONLY)):
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="no fields to update")
    db.execute(pg_insert(soar_tenant_settings).values(tenant_key=user.tenant_key, **fields)
               .on_conflict_do_update(index_elements=["tenant_key"], set_=fields))
    append_entry(db, str(user.user_id), user.tenant_id, "soar.settings_updated",
                 ",".join(sorted(fields)), "updated")
    db.commit()
    return {"ok": True, **fields}


@router.post("/allowlist")
def add_allowlist(body: AllowlistEntry, db: Session = Depends(get_db),
                  user: CurrentUser = Depends(ADMIN_ONLY)):
    db.execute(pg_insert(soar_allowlist).values(tenant_key=user.tenant_key, cidr=body.cidr, note=body.note)
               .on_conflict_do_nothing(constraint="soar_allowlist_identity"))
    append_entry(db, str(user.user_id), user.tenant_id, "soar.allowlist_add", body.cidr, "added")
    db.commit()
    return {"ok": True, "cidr": body.cidr}


@router.delete("/allowlist/{entry_id}")
def del_allowlist(entry_id: int, db: Session = Depends(get_db), user: CurrentUser = Depends(ADMIN_ONLY)):
    row = db.execute(select(soar_allowlist).where(
        soar_allowlist.c.id == entry_id, soar_allowlist.c.tenant_key == user.tenant_key)).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    db.execute(soar_allowlist.delete().where(soar_allowlist.c.id == entry_id))
    append_entry(db, str(user.user_id), user.tenant_id, "soar.allowlist_del", row["cidr"], "removed")
    db.commit()
    return {"ok": True}
