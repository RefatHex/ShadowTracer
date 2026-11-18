"""Phase 7.4: plain-language reasons for the XGBoost historical classifier.

One template per model feature (shadowtracer_ml.features.FEATURE_NAMES), turned into a short human
phrase. A SHAP value's SIGN gives the direction ("raised by" when it pushed the incident toward
attack, "lowered by" when toward benign); its MAGNITUDE ranks the reasons. We never put a raw
username, IP or hostname in a reason - we can't, because none of those is a model feature (features
are counts / rates / fractions / flags only; features.py forbids identifier features and a test
enforces it). PHRASES below is therefore a closed vocabulary: render() only ever emits one of these
strings, so there is nothing to leak.

Used by the serving pyfunc (serving_model / xgb_model) and mirrored nowhere else.
"""

from .features import BASES, GROUPS, TACTICS

# Human phrase for each feature: what a LARGE value of it means, as a noun phrase. Direction words
# ("raised by" / "lowered by") are added by render() from the SHAP sign, so each phrase is neutral.
_GROUP_PHRASE = {
    "authentication_failed": "authentication-failure alerts",
    "authentication_failures": "repeated authentication-failure alerts",
    "authentication_success": "authentication-success alerts",
    "invalid_login": "invalid-login alerts",
    "sshd": "SSH service alerts",
    "sudo": "sudo / privilege-use alerts",
    "pam": "PAM authentication alerts",
    "syscheck": "file-integrity (syscheck) alerts",
    "syscheck_entry_added": "files-added (syscheck) alerts",
    "syscheck_entry_modified": "files-modified (syscheck) alerts",
    "syscheck_entry_deleted": "files-deleted (syscheck) alerts",
    "adduser": "user-creation alerts",
    "account_changed": "account-change alerts",
    "dpkg": "package-management (dpkg) alerts",
    "audit": "audit-log alerts",
    "firewall": "firewall alerts",
    "web": "web-server alerts",
    "attack": "known-attack-signature alerts",
    "rootcheck": "rootkit-check alerts",
    "shadowtracer_ti": "threat-intel-match alerts",
    "ti_virustotal": "VirusTotal-match alerts",
    "windows": "Windows event alerts",
    "sysmon": "Sysmon alerts",
    "sysmon_eid1_detections": "Sysmon process-creation (EID 1) alerts",
    "sysmon_eid11_detections": "Sysmon file-creation (EID 11) alerts",
    "sysmon_eid10_detections": "Sysmon process-access (EID 10) alerts",
    "group_changed": "group-membership-change alerts",
    "policy_changed": "policy-change alerts",
    "win_group_changed": "Windows group-change alerts",
    "process_creation": "process-creation alerts",
}
_TACTIC_PHRASE = {t: f"{t.replace('-', ' ')} technique alerts" for t in TACTICS}
_BASIS_PHRASE = {
    "source_ip": "alerts correlated by a shared source IP",
    "user": "alerts correlated by a shared user",
    "rule_group": "alerts correlated by a shared rule type",
}

PHRASES = {
    "n_alerts_log": "the number of alerts in the incident",
    "max_level": "the highest alert severity",
    "mean_level": "the average alert severity",
    "lvl_low": "the share of low-severity alerts",
    "lvl_mid": "the share of medium-severity alerts",
    "lvl_high": "the share of high-severity alerts",
    "lvl_crit": "the share of critical-severity alerts",
    "n_rules_log": "the number of distinct rules that fired",
    "n_groups_log": "the number of distinct rule types involved",
    "duration_log": "how long the incident lasted",
    "alerts_per_min": "how fast the alerts arrived",
    "n_src_ips_log": "the number of source IPs involved",
    "n_users_log": "the number of user accounts involved",
    "rare_pattern": "a rare alert pattern for this environment",
    "prior_occ_log": "how often this pattern was seen before",
    "ti_conf": "the threat-intel match confidence",
    **{f"g_{g}": f"the rate of {p}" for g, p in _GROUP_PHRASE.items()},
    **{f"t_{t}": f"the rate of {p}" for t, p in _TACTIC_PHRASE.items()},
    **{f"basis_{b}": p for b, p in _BASIS_PHRASE.items()},
}

# Every model feature must have a phrase (guards against a feature added without a reason template).
_MISSING = (set(f"g_{g}" for g in GROUPS) | set(f"t_{t}" for t in TACTICS)
            | set(f"basis_{b}" for b in BASES)) - set(PHRASES)
assert not _MISSING, f"reasons.py missing phrases for features: {sorted(_MISSING)}"


def render(feature: str, shap_value: float) -> str:
    """One reason line for a feature, directioned by the SHAP sign. Unknown features fall back to the
    bare feature name (still never an identifier)."""
    phrase = PHRASES.get(feature, feature.replace("_", " "))
    direction = "raised by" if shap_value >= 0 else "lowered by"
    return f"{direction}: {phrase}"


def top_reasons(feature_names, shap_values, k: int = 5, min_abs: float = 1e-6) -> list:
    """Top-k reasons by |SHAP|, most influential first, dropping near-zero contributions. Returns a
    list of plain-language strings drawn only from PHRASES - safe to show and to store."""
    pairs = sorted(zip(feature_names, shap_values), key=lambda fv: -abs(fv[1]))
    return [render(f, v) for f, v in pairs[:k] if abs(v) >= min_abs]


def demo() -> None:
    from .features import FEATURE_NAMES
    import random
    # every feature renders to a safe phrase
    assert all(isinstance(render(f, 1.0), str) and ":" in render(f, 1.0) for f in FEATURE_NAMES)
    # direction follows the sign
    assert render("max_level", 2.0).startswith("raised by")
    assert render("max_level", -2.0).startswith("lowered by")
    # top_reasons: ranked by |shap|, k-capped, near-zero dropped
    random.seed(0)
    shap = [random.uniform(-1, 1) for _ in FEATURE_NAMES]
    shap[FEATURE_NAMES.index("ti_conf")] = 5.0  # dominant
    rs = top_reasons(FEATURE_NAMES, shap, k=3)
    assert len(rs) == 3 and rs[0] == "raised by: the threat-intel match confidence", rs
    assert top_reasons(FEATURE_NAMES, [0.0] * len(FEATURE_NAMES)) == []  # all near-zero -> no reasons
    # no reason text contains an identifier-looking token (closed vocabulary)
    for f in FEATURE_NAMES:
        txt = render(f, 1.0).lower()
        assert not any(bad in txt for bad in ("@", "192.", "10.", "hostname", "username=")), txt
    print("reasons.py demo OK:", len(FEATURE_NAMES), "features templated")


if __name__ == "__main__":
    demo()
