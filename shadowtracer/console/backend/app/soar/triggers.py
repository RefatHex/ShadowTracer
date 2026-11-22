"""Built-in containment triggers (Phase 9 (a)): which playbook an incident fires and the targets.
These are the hardcoded form of the three shipped playbooks' triggers; Phase 9 (e) replaces them
with admin-edited versioned YAML, same shape. block_ip targets are the incident's source IPs — the
safety rails (allowlist/anti-spoof) then decide which are actually blockable, not these triggers.
"""

# Wazuh rule groups / MITRE ids that mark an SSH/credential brute force.
_BRUTE_GROUPS = {"authentication_failures", "authentication_failed", "ssh", "sshd", "win_authentication_failed"}
_BRUTE_MITRE = {"T1110"}


def _is_brute_force(inc: dict) -> bool:
    groups = {g.lower() for g in (inc.get("rule_groups") or [])}
    mitre = set(inc.get("mitre_ids") or [])
    return bool(groups & _BRUTE_GROUPS) or bool(mitre & _BRUTE_MITRE)


def match(inc: dict) -> list[tuple[str, str, list[str]]]:
    """-> [(playbook_key, action_type, targets)]. Empty if no containment playbook applies."""
    out: list[tuple[str, str, list[str]]] = []
    ips = list(inc.get("source_ips") or [])

    # TI-confirmed malicious source IP -> block (strongest; highest priority).
    if ips and (inc.get("ti_confidence") or 0) >= 75:
        out.append(("builtin-ti-malicious-ip", "block_ip", ips))
    # SSH / credential brute force -> block the source IP(s).
    elif ips and _is_brute_force(inc):
        out.append(("builtin-ssh-brute-force", "block_ip", ips))

    return out


if __name__ == "__main__":  # self-check
    assert match({"source_ips": ["8.8.8.8"], "rule_groups": ["authentication_failures"]}) == \
        [("builtin-ssh-brute-force", "block_ip", ["8.8.8.8"])]
    assert match({"source_ips": ["8.8.8.8"], "ti_confidence": 90})[0][0] == "builtin-ti-malicious-ip"
    assert match({"source_ips": ["8.8.8.8"], "rule_groups": ["syscheck"]}) == []
    assert match({"rule_groups": ["authentication_failures"]}) == []     # no source ip, nothing to block
    print("triggers self-check ok")
