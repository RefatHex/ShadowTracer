"""Normalises a real Wazuh 4.14.8 alert JSON line into a ClickHouse
`shadowtracer.events` row.

Shape notes (confirmed against real alerts captured from the lab - see
shadowtracer/ingest/fixtures/real_alerts_4.14.8.jsonl, not guessed):
- rule.id is a string ("5710"), not a number.
- timestamp/id/full_log/location live at the alert's root.
- `data.*` is conditional and holds decoder-specific payloads (sca,
  osquery, srcip/srcuser, ...).
- `syscheck` is ALSO a conditional top-level object (FIM events put their
  payload there, not under `data`) - this is not mentioned in the task
  spec's own description of the shape and was only found by inspecting
  real captured alerts.
"""

import datetime
import json
from dataclasses import dataclass, field


class MissingClusterNode(Warning):
    """Raised (as a warning, not an error) when an alert has no
    cluster.node and the normaliser had to fall back to manager.name -
    see DECISIONS.md's alert-identity decision."""


@dataclass
class NormalizedEvent:
    tenant_id: str
    time: str  # ISO8601, ClickHouse parses this directly
    cluster_node: str
    manager_name: str
    alert_id: str
    agent_id: str
    agent_name: str
    agent_ip: str
    rule_id: str
    rule_level: int
    rule_description: str
    rule_groups: list
    mitre_ids: list
    mitre_tactics: list
    mitre_techniques: list
    src_endpoint_ip: str
    src_endpoint_port: int
    dst_endpoint_ip: str
    dst_endpoint_port: int
    actor_user: str
    target_user: str
    decoder_name: str
    location: str
    message: str
    extra_fields: dict
    raw_event: str
    cluster_node_fell_back: bool = field(default=False, repr=False)


def _flatten(prefix: str, value, out: dict) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten(f"{prefix}.{k}", v, out)
    elif isinstance(value, list):
        out[prefix] = json.dumps(value)
    elif value is not None:
        out[prefix] = str(value)


def _int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_alert(raw_line: str, tenant_id: str) -> NormalizedEvent:
    """Raises ValueError/KeyError on a genuinely malformed line - callers
    (the writer) are responsible for catching that, counting it, and
    moving on without crashing, per the Step 3/5 spec."""

    alert = json.loads(raw_line)

    # Validated here, once, for every caller - found the hard way (Phase
    # 5A VERIFY) that a malformed timestamp survived normalization
    # unexamined and only failed later, inside ClickHouse's own client
    # library mid-batch-insert, crashing the writer process outright
    # instead of being counted and skipped like any other malformed
    # alert. datetime.fromisoformat is used only to validate - the
    # original string (not the parsed object) is still what ClickHouse's
    # own parser receives, unchanged.
    datetime.datetime.fromisoformat(alert["timestamp"])

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    manager = alert.get("manager", {})
    cluster = alert.get("cluster", {})
    mitre = rule.get("mitre", {})
    data = alert.get("data", {})

    cluster_node = cluster.get("node")
    fell_back = False
    if not cluster_node:
        cluster_node = manager.get("name", "")
        fell_back = True

    extra_fields: dict = {}
    if isinstance(data, dict):
        _flatten("data", data, extra_fields)
    syscheck = alert.get("syscheck")
    if isinstance(syscheck, dict):
        _flatten("syscheck", syscheck, extra_fields)

    return NormalizedEvent(
        tenant_id=tenant_id,
        time=alert["timestamp"],
        cluster_node=cluster_node,
        manager_name=manager.get("name", ""),
        alert_id=alert["id"],
        agent_id=agent.get("id", ""),
        agent_name=agent.get("name", ""),
        agent_ip=agent.get("ip", ""),
        rule_id=str(rule.get("id", "")),
        rule_level=_int(rule.get("level"), 0),
        rule_description=rule.get("description", ""),
        rule_groups=list(rule.get("groups", []) or []),
        mitre_ids=list(mitre.get("id", []) or []),
        mitre_tactics=list(mitre.get("tactic", []) or []),
        mitre_techniques=list(mitre.get("technique", []) or []),
        src_endpoint_ip=str(data.get("srcip", "")) if isinstance(data, dict) else "",
        src_endpoint_port=_int(data.get("srcport")) if isinstance(data, dict) else 0,
        dst_endpoint_ip=str(data.get("dstip", "")) if isinstance(data, dict) else "",
        dst_endpoint_port=_int(data.get("dstport")) if isinstance(data, dict) else 0,
        actor_user=str(data.get("srcuser", "")) if isinstance(data, dict) else "",
        target_user=str(data.get("dstuser", "")) if isinstance(data, dict) else "",
        decoder_name=alert.get("decoder", {}).get("name", ""),
        location=alert.get("location", ""),
        message=alert.get("full_log", ""),
        extra_fields=extra_fields,
        raw_event=raw_line,
        cluster_node_fell_back=fell_back,
    )
