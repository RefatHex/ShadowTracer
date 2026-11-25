"""Asset automation levels (Phase 9 follow-up A1). An admin tags agents (or whole role_tags) as
full | approval | none; the default for every agent is approval. Resolution for an incident's agent:
agent-specific level, else its role_tag's level (from agent_role_tags), else 'approval'.

Enforcement (worker): 'none' -> containment refused (notify still runs); 'approval' -> never auto even
if the playbook is auto; 'full' -> the playbook's own mode applies.
"""

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .. import audit
from .models import soar_asset_levels

DEFAULT_LEVEL = "approval"
LEVELS = ("full", "approval", "none")


def asset_level(db, tenant_key: str, agent_id: str | None) -> str:
    """Resolve the automation level for an agent: agent override -> its role_tag -> default."""
    if agent_id:
        lvl = db.execute(select(soar_asset_levels.c.level).where(
            soar_asset_levels.c.tenant_key == tenant_key,
            soar_asset_levels.c.scope_type == "agent",
            soar_asset_levels.c.scope_value == agent_id)).scalar()
        if lvl:
            return lvl
        role = db.execute(text("SELECT role_tag FROM agent_role_tags WHERE tenant_key=:t AND agent_id=:a"),
                          {"t": tenant_key, "a": agent_id}).scalar()
        if role:
            lvl = db.execute(select(soar_asset_levels.c.level).where(
                soar_asset_levels.c.tenant_key == tenant_key,
                soar_asset_levels.c.scope_type == "role_tag",
                soar_asset_levels.c.scope_value == role)).scalar()
            if lvl:
                return lvl
    return DEFAULT_LEVEL


def set_level(db, tenant_key: str, tenant_id: int | None, scope_type: str, scope_value: str,
              level: str, actor: str) -> dict:
    if scope_type not in ("agent", "role_tag") or level not in LEVELS:
        raise ValueError("invalid scope_type or level")
    db.execute(pg_insert(soar_asset_levels).values(
        tenant_key=tenant_key, scope_type=scope_type, scope_value=scope_value,
        level=level, updated_by=actor
    ).on_conflict_do_update(
        index_elements=["tenant_key", "scope_type", "scope_value"],
        set_={"level": level, "updated_by": actor}))
    audit.append_entry(db, actor, tenant_id, "soar.asset_level_set",
                       f"{scope_type}:{scope_value}={level}", level)
    db.commit()
    return {"scope_type": scope_type, "scope_value": scope_value, "level": level}


def list_levels(db, tenant_key: str) -> list[dict]:
    rows = db.execute(select(soar_asset_levels).where(
        soar_asset_levels.c.tenant_key == tenant_key)).mappings().all()
    return [dict(r) for r in rows]
