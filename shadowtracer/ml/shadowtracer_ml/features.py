"""Incident features - ONE module for training and serving (docs/ML_FOUNDATION.md).

compute(incident, alerts) uses only data up to the incident's close: alerts later than
closed_at are ignored. Nothing that reveals where the data came from is a feature: no agent
id/name, tenant, node, location, dataset or run id, and no absolute time (hour, weekday,
dates) - replays are re-timed and lab activity runs on a schedule, so those would teach a
model the source, not the attack. tests/test_features.py fails if such a feature appears or if
features change when only those fields change.

Bump FEATURE_VERSION whenever a feature's meaning changes; stored rows keep their version.
"""
import datetime as dt
import math

FEATURE_VERSION = "f1"
MAX_ALERTS = 500            # alerts sampled per incident (earliest first); counts use the incident's totals

# Rule groups and ATT&CK tactics that carry signal, as fractions of the sampled alerts.
GROUPS = ("authentication_failed", "authentication_success", "authentication_failures", "invalid_login", "sshd", "sudo",
          "pam", "syscheck", "syscheck_entry_added", "syscheck_entry_modified", "syscheck_entry_deleted", "adduser",
          "account_changed", "dpkg", "audit", "firewall", "web", "attack", "rootcheck", "shadowtracer_ti", "ti_virustotal",
          "windows", "sysmon", "sysmon_eid1_detections", "sysmon_eid11_detections", "sysmon_eid10_detections",
          "group_changed", "policy_changed", "win_group_changed", "process_creation")
TACTICS = ("initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access",
           "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact")
BASES = ("source_ip", "user", "rule_group")

FEATURE_NAMES = tuple(sorted(
    ["n_alerts_log", "max_level", "mean_level", "lvl_low", "lvl_mid", "lvl_high", "lvl_crit", "n_rules_log",
     "n_groups_log", "duration_log", "alerts_per_min", "n_src_ips_log", "n_users_log", "rare_pattern",
     "prior_occ_log", "ti_conf"]
    + [f"basis_{b}" for b in BASES] + [f"g_{g}" for g in GROUPS] + [f"t_{t}" for t in TACTICS]))

# A feature name containing any of these is a leak (checked by tests and at import below).
FORBIDDEN_SUBSTRINGS = ("agent", "tenant", "dataset", "replay", "run_id", "node", "location", "host", "hour", "weekday",
                        "date", "time", "epoch", "shift", "name", "manager", "cluster", "decoder")


def _tactic(t: str) -> str:
    return t.strip().lower().replace(" ", "-")


def _as_dt(v):
    if v is None or isinstance(v, dt.datetime):
        return v if (v is None or v.tzinfo) else v.replace(tzinfo=dt.timezone.utc)
    return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))


def compute(incident: dict, alerts: list) -> dict:
    """incident: first_seen, last_seen, closed_at, alert_count, max_level, rule_ids, rule_groups,
    source_ip_total, user_total, correlation_basis, rare_pattern_flag, prior_occurrences,
    ti_confidence. alerts: dicts with time, rule_level, rule_groups, mitre_tactics (any order).
    -> {feature name: float} with exactly FEATURE_NAMES."""
    closed = _as_dt(incident.get("closed_at"))
    sample = sorted((a for a in alerts if closed is None or _as_dt(a["time"]) <= closed), key=lambda a: _as_dt(a["time"]))
    sample = sample[:MAX_ALERTS]
    n = max(len(sample), 1)
    levels = [int(a.get("rule_level") or 0) for a in sample]
    first, last = _as_dt(incident["first_seen"]), _as_dt(incident["last_seen"])
    if closed is not None:
        last = min(last, closed)
    duration = max((last - first).total_seconds(), 0.0)
    count = int(incident.get("alert_count") or len(sample))
    f = {
        "n_alerts_log": math.log1p(count),
        "max_level": float(incident.get("max_level") or (max(levels) if levels else 0)),
        "mean_level": sum(levels) / n if levels else 0.0,
        "lvl_low": sum(1 for x in levels if x <= 3) / n,
        "lvl_mid": sum(1 for x in levels if 4 <= x <= 7) / n,
        "lvl_high": sum(1 for x in levels if 8 <= x <= 11) / n,
        "lvl_crit": sum(1 for x in levels if x >= 12) / n,
        "n_rules_log": math.log1p(len(incident.get("rule_ids") or [])),
        "n_groups_log": math.log1p(len(incident.get("rule_groups") or [])),
        "duration_log": math.log1p(duration),
        "alerts_per_min": count / max(duration / 60.0, 1.0),
        "n_src_ips_log": math.log1p(int(incident.get("source_ip_total") or 0)),
        "n_users_log": math.log1p(int(incident.get("user_total") or 0)),
        "rare_pattern": 1.0 if incident.get("rare_pattern_flag") else 0.0,
        "prior_occ_log": -1.0 if incident.get("prior_occurrences") is None else math.log1p(int(incident["prior_occurrences"])),
        "ti_conf": float(incident.get("ti_confidence") or 0) / 100.0,
    }
    for b in BASES:
        f[f"basis_{b}"] = 1.0 if incident.get("correlation_basis") == b else 0.0
    for g in GROUPS:
        f[f"g_{g}"] = sum(1 for a in sample if g in (a.get("rule_groups") or [])) / n
    for t in TACTICS:
        f[f"t_{t}"] = sum(1 for a in sample if t in {_tactic(x) for x in (a.get("mitre_tactics") or [])}) / n
    assert set(f) == set(FEATURE_NAMES)
    return f


def vector(features: dict) -> list:
    """Model input order, the same for training and serving."""
    return [float(features[k]) for k in FEATURE_NAMES]


def model_input(feature_dicts: list):
    """The DataFrame every model gets, at training and at serving (parity: one function)."""
    import pandas as pd
    return pd.DataFrame([vector(f) for f in feature_dicts], columns=list(FEATURE_NAMES))


def to_row(tenant: str, incident_id: int, closed_at, features: dict, now: dt.datetime = None) -> list:
    """ClickHouse ml_incident_features row."""
    return [tenant, int(incident_id), FEATURE_VERSION, _as_dt(closed_at), now or dt.datetime.now(dt.timezone.utc),
            {k: float(v) for k, v in features.items()}]


def from_row(features_map: dict) -> dict:
    """The training side reads stored rows back through this, never a re-derivation."""
    return {k: float(features_map[k]) for k in FEATURE_NAMES}


_leaks = [n for n in FEATURE_NAMES if any(s in n for s in FORBIDDEN_SUBSTRINGS)]
if _leaks:
    raise ImportError(f"source-revealing feature names: {_leaks}")
