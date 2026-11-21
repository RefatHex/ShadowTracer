"""Gather the evidence pack IN CODE, by calling the same tenant-scoped, authz-checked read handlers
the analyst already has (no service-account shortcut). Each item gets an evidence id (E1, E2 ...).
Everything is summarised and bounded (top-N, truncated) so the whole pack fits the model's context.

A handler that 404s (cross-tenant / missing incident) is allowed to propagate; one that merely fails
(e.g. Qdrant down) is skipped with a note, so a partial evidence pack still renders.
"""
from __future__ import annotations

import re
from collections import Counter

from ..routers.incidents import ALERT_PAGE_SIZE, get_incident, get_incident_alerts
from ..routers.model_assessment import model_assessment
from ..routers.similar import similar_incidents
from ..routers.graph import incident_graph
from .attack import technique_info

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAX_BODY = 1400          # chars per evidence item
_MAX_TOTAL = 9000         # chars across the whole pack (~2.3k tokens; leaves room for 900 output in a 4096 ctx)


def _ips(text: str) -> list[str]:
    return [ip for ip in _IPV4.findall(text or "") if not ip.startswith(("10.", "127.", "172.", "192.168."))]


def _clip(s: str) -> str:
    return s if len(s) <= _MAX_BODY else s[:_MAX_BODY] + " …(truncated)"


def _alerts_summary(alerts: list, total: int) -> str:
    rules = Counter((a.rule_id, a.rule_description) for a in alerts)
    ips = Counter(ip for a in alerts for ip in _ips(a.message))
    levels = Counter(a.rule_level for a in alerts)
    lines = [f"Summary of the most recent {len(alerts)} of {total} alerts:"]
    lines.append("top rules: " + "; ".join(f"rule {rid} \"{desc[:40]}\" x{n}" for (rid, desc), n in rules.most_common(8)))
    lines.append("rule levels: " + ", ".join(f"level {lvl} x{n}" for lvl, n in sorted(levels.items(), reverse=True)[:6]))
    lines.append("top external source IPs: " + (", ".join(f"{ip} x{n}" for ip, n in ips.most_common(6)) or "none"))
    return "\n".join(lines)


def gather_core(db, user, settings, incident_id: int) -> tuple[list[dict], dict]:
    """-> (evidence[list of {id,title,body}], meta). Raises HTTPException(404) for cross-tenant."""
    detail = get_incident(incident_id, settings=settings, db=db, current_user=user)   # 404 propagates
    ev: list[dict] = []
    meta: dict = {"incident_id": incident_id, "techniques": list(getattr(detail, "mitre_ids", []) or []),
                  "alert_count": detail.alert_count}

    def add(title: str, body: str):
        ev.append({"id": f"E{len(ev) + 1}", "title": title, "body": _clip(body)})

    add("Incident overview",
        f"incident {detail.id}, agent {detail.agent_id}, state {detail.state}, triage {detail.triage_status}, "
        f"priority {detail.priority}, max rule level {detail.max_level}, alert_count {detail.alert_count}, "
        f"correlation basis: {detail.correlation_basis}, rule groups: {', '.join(detail.rule_groups or []) or 'none'}, "
        f"techniques: {', '.join(detail.mitre_ids or []) or 'none'}, "
        f"first_seen {detail.first_seen}, last_seen {detail.last_seen}, "
        f"CVEs: {', '.join(detail.cve_ids or []) or 'none'} (KEV: {', '.join(detail.kev_cve_ids or []) or 'none'}).")

    try:
        page = get_incident_alerts(incident_id, settings=settings, db=db, current_user=user,
                                   limit=ALERT_PAGE_SIZE)   # explicit int: the handler default is a Query()
        meta["alert_cursor"] = page.next
        add("Alerts summary", _alerts_summary(page.alerts, detail.alert_count))
    except Exception as e:                       # noqa: BLE001 - advisory, degrade
        add("Alerts summary", f"unavailable ({type(e).__name__})")

    try:
        ma = model_assessment(incident_id, db=db, current_user=user)
        if ma is None:
            add("Model assessment", "not scored by the ML models.")
        else:
            body = (f"historical classifier {ma.model_version}: {ma.predicted_class} "
                    f"(P={ma.probability:.2f}, experimental={ma.experimental}).")
            if ma.online:
                body += (f" online model {ma.online.model_version}: {ma.online.predicted_class} "
                         f"(P(attack)={ma.online.probability:.2f}, experimental).")
            add("Model assessment", body)
    except Exception as e:                       # noqa: BLE001
        add("Model assessment", f"unavailable ({type(e).__name__})")

    if detail.ti_matches:
        hits = "; ".join(f"{m.ioc_type} {m.ioc_value} (sources {', '.join(m.sources)}, conf {m.confidence}, {m.origin})"
                         for m in detail.ti_matches[:8])
        add("Threat-intel hits", hits)

    try:
        sims = similar_incidents(incident_id, k=5, db=db, current_user=user)
        if sims:
            add("Similar past incidents",
                "; ".join(f"incident {s.incident_id} (score {s.score:.2f}, basis {s.correlation_basis}, "
                          f"state {s.state}, triage {s.triage_status})" for s in sims))
    except Exception as e:                       # noqa: BLE001
        add("Similar past incidents", f"unavailable ({type(e).__name__})")

    try:
        g = incident_graph(incident_id, db=db, settings=settings, current_user=user)
        s = g.get("summary", {})
        add("Relationship graph",
            f"nodes {s.get('node_count', '?')}, edges {s.get('edge_count', '?')}, "
            f"alerts considered {s.get('alerts_considered', '?')}; node kinds: "
            + ", ".join(f"{k}:{v}" for k, v in (s.get("node_kind_counts", {}) or {}).items()))
    except Exception as e:                       # noqa: BLE001
        add("Relationship graph", f"unavailable ({type(e).__name__})")

    for tid in (detail.mitre_ids or [])[:4]:
        info = technique_info(tid)
        if info:
            add(f"ATT&CK {tid}", f"{info['id']} {info['name']} (tactics: {', '.join(info['tactics']) or 'n/a'})")

    # enforce the total budget
    total = 0
    bounded = []
    for item in ev:
        total += len(item["body"]) + len(item["title"])
        if total > _MAX_TOTAL:
            break
        bounded.append(item)
    return bounded, meta
