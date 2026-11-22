"""Playbooks (Phase 9 E): admin-edited, versioned per tenant in Postgres. A definition names the
trigger, required signals, steps (each with its own mode), and block duration. The worker's built-in
triggers (triggers.py) are the shipped defaults; a stored definition overrides a playbook's block
duration and is the source the console edits. Editing bumps the version and appends to history.

Three ship (design E). The malware playbook's actions (collect_evidence, quarantine_file) are wired
in Phase 9 (d); its definition exists here now so the console can show and edit it.
"""

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .. import audit
from .models import soar_playbook_versions, soar_playbooks

DEFAULT_PLAYBOOKS: dict[str, dict] = {
    "builtin-ssh-brute-force": {
        "title": "SSH brute force → block IP",
        "trigger": "rule_groups in {authentication_failures, sshd} or MITRE T1110",
        "required_signals": ["rule_match"],
        "steps": [{"action": "block_ip", "mode": "shadow"}],
        "block_seconds": 3600,
    },
    "builtin-ti-malicious-ip": {
        "title": "TI-confirmed malicious IP → block",
        "trigger": "ti_confidence >= 75",
        "required_signals": ["rule_match", "ti_hit"],
        "steps": [{"action": "block_ip", "mode": "shadow"}],
        "block_seconds": 7200,
    },
    "builtin-malware-yara": {
        "title": "Malware / YARA hit → collect evidence + quarantine (approval) + notify",
        "trigger": "YARA/malware rule hit with file hash",
        "required_signals": ["rule_match", "ti_hit"],
        "steps": [
            {"action": "collect_evidence", "mode": "auto"},
            {"action": "quarantine_file", "mode": "approval"},
            {"action": "notify", "mode": "auto"},
        ],
        "block_seconds": None,
    },
}


def get_playbook(db, tenant_key: str, playbook_key: str) -> dict | None:
    row = db.execute(select(soar_playbooks).where(
        soar_playbooks.c.tenant_key == tenant_key,
        soar_playbooks.c.playbook_key == playbook_key)).mappings().first()
    return dict(row) if row else None


def effective_definition(db, tenant_key: str, playbook_key: str) -> dict | None:
    """The stored definition if edited, else the shipped default."""
    pb = get_playbook(db, tenant_key, playbook_key)
    if pb and pb.get("definition"):
        return pb["definition"]
    return DEFAULT_PLAYBOOKS.get(playbook_key)


def block_seconds_for(db, tenant_key: str, playbook_key: str, default: int) -> int | None:
    """Per-playbook block duration override (stored col, else default definition), else tenant default."""
    pb = get_playbook(db, tenant_key, playbook_key)
    if pb and pb.get("block_seconds") is not None:
        return pb["block_seconds"]
    d = DEFAULT_PLAYBOOKS.get(playbook_key)
    if d and "block_seconds" in d:
        return d["block_seconds"] if d["block_seconds"] is not None else default
    return default


def upsert_playbook(db, tenant_key: str, tenant_id: int | None, playbook_key: str,
                    definition: dict, actor: str, block_seconds: int | None = None) -> dict:
    """Create or edit a playbook definition: bump version, append to history, audit. The mode is NOT
    changed here (earned_autonomy.set_mode owns that). -> the new row."""
    existing = get_playbook(db, tenant_key, playbook_key)
    version = (existing["version"] + 1) if existing else 1
    db.execute(pg_insert(soar_playbooks).values(
        tenant_key=tenant_key, playbook_key=playbook_key, definition=definition,
        version=version, block_seconds=block_seconds, updated_by=actor,
    ).on_conflict_do_update(
        index_elements=["tenant_key", "playbook_key"],
        set_={"definition": definition, "version": version, "block_seconds": block_seconds,
              "updated_by": actor, "updated_at": func.now()}))
    db.execute(soar_playbook_versions.insert().values(
        tenant_key=tenant_key, playbook_key=playbook_key, version=version,
        definition=definition, created_by=actor))
    audit.append_entry(db, actor, tenant_id, "soar.playbook_edited",
                       f"{playbook_key} v{version}", "edited")
    return get_playbook(db, tenant_key, playbook_key)
