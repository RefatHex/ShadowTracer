"""Containment dispatch primitives (Phase 9 A/H). Each action type maps to a ShadowTracer AR script
and an apply/reverse verb, dispatched via the manager API (the !script custom form). The verb is the
first extra_arg and the subject (ip / account / path) the second, so the one script both applies and
reverses through the API — the basis for timed expiry and undo. collect_evidence is read-only (no
reverse). block_ip keeps its dedicated helpers (the worker's timed-expiry sweep calls them).
"""

from .. import wazuh_api

# action_type -> (script, apply_verb, reverse_verb | None). reverse_verb None => not reversible.
ACTION_SCRIPTS: dict[str, tuple[str, str, str | None]] = {
    "block_ip":         ("shadowtracer-fw-drop",          "add",        "delete"),
    "disable_account":  ("shadowtracer-disable-account",  "disable",    "enable"),
    "quarantine_file":  ("shadowtracer-quarantine",       "quarantine", "restore"),
    "collect_evidence": ("shadowtracer-collect-evidence", "collect",    None),
}
REVERSIBLE = {a for a, (_, _, rev) in ACTION_SCRIPTS.items() if rev}


def pick_script(os_family: str | None) -> str:
    """Which AR block script a Linux agent uses for block_ip. ponytail: firewalld-drop/host-deny
    variants by os_family when a non-iptables agent appears; the dispatch shape is identical."""
    return ACTION_SCRIPTS["block_ip"][0]


def apply_action(action_type: str, base_url: str, agent_id: str, target: str) -> None:
    """Apply a containment action on one agent. Subject goes in both srcip (block_ip reads it) and the
    second extra_arg (the account/file scripts read it). Raises wazuh_api.WazuhApiError on failure."""
    script, verb, _ = ACTION_SCRIPTS[action_type]
    wazuh_api.run_command(base_url, agent_id, script, [verb, target], target)


def reverse_action(action_type: str, base_url: str, agent_id: str, target: str) -> None:
    """Reverse a reversible action (undo / timed expiry)."""
    script, _, rev = ACTION_SCRIPTS[action_type]
    if rev is None:
        raise ValueError(f"{action_type} is not reversible")
    wazuh_api.run_command(base_url, agent_id, script, [rev, target], target)


# block_ip-specific helpers (worker timed-expiry sweep + the AR dispatch contract test).
def apply_block(base_url: str, agent_id: str, ip: str) -> None:
    apply_action("block_ip", base_url, agent_id, ip)


def reverse_block(base_url: str, agent_id: str, ip: str) -> None:
    reverse_action("block_ip", base_url, agent_id, ip)
