"""Approvals, execution and undo (Phase 9 G/H). An approver acts on a tenant's pending containment
requests. Rules:
  - four-eyes: the approver must differ from the playbook owner (who configured/edited it).
  - RBAC: analyst+ may approve block_ip; disable_account / quarantine_file need admin (Phase 9 d).
  - a reason is required to approve or deny.
On approve the block is dispatched (Wazuh AR) and timed; undo (or timed expiry) reverses it. Every
request/approve/deny/execute/undo/expire is already in the hash-chained audit log.

Dispatch goes through actions.apply_block / reverse_block; the manager base URL per tenant comes from
WAZUH_API_ENDPOINTS. Cross-tenant action ids are invisible (404), never actionable.
"""

import datetime

from sqlalchemy import select, text

from .. import audit, wazuh_api
from . import actions
from .models import soar_actions, soar_playbooks

# action types that require admin to approve (the rest: analyst+). quarantine/disable land in (d).
ADMIN_ACTIONS = {"disable_account", "quarantine_file"}


class ApprovalError(Exception):
    def __init__(self, code: int, message: str):
        self.code, self.message = code, message
        super().__init__(message)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def get_action(db, tenant_key: str, action_id: int) -> dict | None:
    """Tenant-scoped fetch — another tenant's action id is invisible (the router returns 404)."""
    row = db.execute(select(soar_actions).where(
        soar_actions.c.id == action_id, soar_actions.c.tenant_key == tenant_key)).mappings().first()
    return dict(row) if row else None


def list_pending(db, tenant_key: str) -> list[dict]:
    rows = db.execute(select(soar_actions).where(
        soar_actions.c.tenant_key == tenant_key, soar_actions.c.status == "requested"
    ).order_by(soar_actions.c.created_at)).mappings().all()
    return [dict(r) for r in rows]


def _owner(db, tenant_key: str, playbook_key: str) -> str | None:
    row = db.execute(select(soar_playbooks.c.updated_by, soar_playbooks.c.promoted_by).where(
        soar_playbooks.c.tenant_key == tenant_key,
        soar_playbooks.c.playbook_key == playbook_key)).first()
    return (row[0] or row[1]) if row else None


def _require_approvable(action: dict, role: str, approver: str, reason: str, db, tenant_key: str):
    if not reason or not reason.strip():
        raise ApprovalError(400, "a reason is required")
    if action["status"] != "requested":
        raise ApprovalError(409, f"action is {action['status']}, not awaiting approval")
    if action["action_type"] in ADMIN_ACTIONS and role != "admin":
        raise ApprovalError(403, f"{action['action_type']} needs admin approval")
    owner = _owner(db, tenant_key, action["playbook_key"])
    if owner and owner == approver:
        raise ApprovalError(403, "four-eyes: the approver cannot be the playbook owner")


def approve(db, tenant_key: str, tenant_id: int | None, action: dict, approver: str, role: str,
            reason: str) -> dict:
    """Approve and execute. Raises ApprovalError on a failed check. Returns the updated action."""
    _require_approvable(action, role, approver, reason, db, tenant_key)
    base = wazuh_api.endpoints().get(tenant_key)
    if not base:
        raise ApprovalError(503, "no manager API endpoint configured for this tenant")

    now = _now()
    try:
        actions.apply_block(base, action["agent_id"], action["target"])
    except wazuh_api.WazuhApiError as e:
        db.execute(soar_actions.update().where(soar_actions.c.id == action["id"]).values(
            status="failed", error=str(e), approved_by=approver, reason=reason, updated_at=now))
        audit.append_entry(db, approver, tenant_id, "soar.execute_failed",
                           f"{action['action_type']}:{action['target']}", "failed")
        raise ApprovalError(502, f"dispatch failed: {e}")

    expires = now + datetime.timedelta(seconds=action["block_seconds"] or 3600)
    db.execute(soar_actions.update().where(soar_actions.c.id == action["id"]).values(
        status="executed", approved_by=approver, reason=reason, executed_by=approver,
        executed_at=now, block_expires_at=expires, updated_at=now))
    audit.append_entry(db, approver, tenant_id, "soar.executed",
                       f"{action['action_type']}:{action['target']}", "executed")
    return get_action(db, tenant_key, action["id"])


def deny(db, tenant_key: str, tenant_id: int | None, action: dict, approver: str, role: str,
         reason: str) -> dict:
    _require_approvable(action, role, approver, reason, db, tenant_key)
    now = _now()
    db.execute(soar_actions.update().where(soar_actions.c.id == action["id"]).values(
        status="refused", refuse_reason=f"denied: {reason}", approved_by=approver, reason=reason,
        updated_at=now))
    audit.append_entry(db, approver, tenant_id, "soar.denied",
                       f"{action['action_type']}:{action['target']}", "denied")
    return get_action(db, tenant_key, action["id"])


def undo(db, tenant_key: str, tenant_id: int | None, action: dict, actor: str, role: str) -> dict:
    """Reverse an executed block (one click). admin-approved action types also need admin to undo."""
    if action["status"] != "executed":
        raise ApprovalError(409, f"action is {action['status']}, nothing to undo")
    if action["action_type"] in ADMIN_ACTIONS and role != "admin":
        raise ApprovalError(403, f"undoing {action['action_type']} needs admin")
    base = wazuh_api.endpoints().get(tenant_key)
    if not base:
        raise ApprovalError(503, "no manager API endpoint configured for this tenant")
    now = _now()
    actions.reverse_block(base, action["agent_id"], action["target"])
    db.execute(soar_actions.update().where(soar_actions.c.id == action["id"]).values(
        status="undone", undone_at=now, updated_at=now))
    audit.append_entry(db, actor, tenant_id, "soar.undone",
                       f"{action['action_type']}:{action['target']}", "undone")
    return get_action(db, tenant_key, action["id"])
