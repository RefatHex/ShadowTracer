"""Containment dispatch primitives (Phase 9 A/H). block_ip applies and reverses an IP block via
Wazuh AR (the ShadowTracer shadowtracer-fw-drop script, add/delete) through the manager API. The
worker and the approvals/undo paths call apply_block / reverse_block; both are a no-op-safe single
rule per srcip (the agent script is idempotent). Other action classes (disable_account,
quarantine_file, collect_evidence) land in Phase 9 (d).
"""

from .. import wazuh_api

FW_SCRIPT = "shadowtracer-fw-drop"


def pick_script(os_family: str | None) -> str:
    """Which AR block script an agent supports. For now every Linux agent uses the ShadowTracer
    iptables add/delete script. ponytail: firewalld-drop/host-deny variants by os_family when a
    non-iptables agent appears; the dispatch shape is identical."""
    return FW_SCRIPT


def apply_block(base_url: str, agent_id: str, ip: str, script: str = FW_SCRIPT) -> None:
    """Apply an IP block on one agent. Raises wazuh_api.WazuhApiError if the manager won't dispatch."""
    wazuh_api.run_command(base_url, agent_id, script, ["add"], ip)


def reverse_block(base_url: str, agent_id: str, ip: str, script: str = FW_SCRIPT) -> None:
    """Reverse an IP block (undo / timed expiry). Same script, delete action."""
    wazuh_api.run_command(base_url, agent_id, script, ["delete"], ip)
