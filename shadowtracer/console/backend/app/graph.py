"""Phase 7.6: NetworkX event-relationship graph for an incident or a campaign (on-demand, analyst+).

Built from the tenant's own Postgres/ClickHouse data (the caller passes already-tenant-scoped rows).
Nodes are the entities an alert mentions (host, user, IP, rule+MITRE, file, IOC/TI match, CVE); edges
are the observed relations, each with first/last time and a count. Bounded: node/edge caps and a time
window, with a summary of what was dropped. NetworkX runs the analytics (components, centrality,
shortest path, shared nodes). Advisory, read-only, never on the hot path; the router caches it.
"""
import ipaddress
from collections import defaultdict

import networkx as nx

NODE_CAP = 150
EDGE_CAP = 300
# rule groups that mean an authentication attempt failed vs succeeded
FAIL_GROUPS = {"authentication_failed", "authentication_failures", "invalid_login", "win_authentication_failed"}
OK_GROUPS = {"authentication_success", "win_authentication_success"}

# node type -> colour (Cytoscape); text-only labels, no raw log rendering beyond the entity value
NODE_COLOURS = {"host": "#2563eb", "user": "#7c3aed", "ip": "#dc2626", "rule": "#64748b",
                "file": "#ea580c", "ioc": "#be123c", "cve": "#b45309", "yara": "#c026d3"}


def _is_external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local)
    except ValueError:
        return False


class GraphBuilder:
    def __init__(self, node_cap=NODE_CAP, edge_cap=EDGE_CAP):
        self.g = nx.MultiDiGraph()          # multiple relation types between the same pair
        self.node_cap, self.edge_cap = node_cap, edge_cap
        self.dropped = defaultdict(int)     # type -> count of nodes summarised away
        self.edge_overflow = 0

    def _node(self, ntype, value, label=None, **attrs):
        nid = f"{ntype}:{value}"
        if nid not in self.g:
            if self.g.number_of_nodes() >= self.node_cap:
                self.dropped[ntype] += 1
                return None
            self.g.add_node(nid, ntype=ntype, value=value, label=label or value, **attrs)
        elif attrs:
            self.g.nodes[nid].update({k: v for k, v in attrs.items() if v})
        return nid

    def _edge(self, src, dst, relation, when):
        if src is None or dst is None or src == dst:
            return
        key = (src, dst, relation)
        data = self.g.get_edge_data(src, dst, key=relation)
        if data is None:
            if self.g.number_of_edges() >= self.edge_cap:
                self.edge_overflow += 1
                return
            self.g.add_edge(src, dst, key=relation, relation=relation, count=1,
                            first_seen=when, last_seen=when)
        else:
            data["count"] += 1
            if when:
                data["first_seen"] = min(data["first_seen"], when) if data["first_seen"] else when
                data["last_seen"] = max(data["last_seen"], when) if data["last_seen"] else when

    def add_alert(self, a: dict):
        when = a.get("time")
        host = self._node("host", a.get("agent_id") or "?", label=a.get("agent_name") or a.get("agent_id"))
        groups = set(a.get("rule_groups") or [])
        rule = self._node("rule", a.get("rule_id") or "?", label=f"{a.get('rule_id')} {a.get('rule_description') or ''}".strip(),
                          mitre=a.get("mitre_techniques") or [], level=a.get("rule_level"))
        self._edge(host, rule, "triggered", when)
        src_ip, dst_ip = a.get("src_ip"), a.get("dst_ip")
        tgt_user, act_user = a.get("target_user"), a.get("actor_user")
        user = tgt_user or act_user
        un = self._node("user", user) if user else None
        if src_ip:
            sn = self._node("ip", src_ip, external=_is_external(src_ip))
            if un:
                rel = "failed login" if groups & FAIL_GROUPS else "logged in" if groups & OK_GROUPS else "authenticated as"
                self._edge(sn, un, rel, when)
                self._edge(un, host, "on host", when)
            else:
                self._edge(sn, host, "connected to", when)
        elif un:
            self._edge(un, host, "active on", when)
        if dst_ip:
            self._edge(host, self._node("ip", dst_ip, external=_is_external(dst_ip)), "connected to", when)
        f = a.get("file")
        if f:
            fn = self._node("file", f)
            self._edge(host, fn, "changed", when)
            if a.get("yara_rule"):
                self._edge(fn, self._node("yara", a["yara_rule"], label=f"YARA: {a['yara_rule']}"), "matched", when)

    def add_ti_match(self, m: dict):
        """m: observable_type, observable, sources (list). The observable's node -> an IOC node."""
        obs, otype = m.get("observable"), m.get("observable_type")
        nt = "ip" if otype in ("ipv4", "ipv6") else "file" if otype in ("sha256", "md5", "sha1") else "ioc"
        on = self._node(nt, obs) if obs else None
        ioc = self._node("ioc", obs, label=f"IOC: {obs} ({', '.join(m.get('sources') or [])})") if obs else None
        if on and ioc and on != ioc:
            self._edge(on, ioc, "listed in TI", None)

    def add_cves(self, host_agent, cve_ids, kev_ids):
        host = self._node("host", host_agent or "?")
        kev = set(kev_ids or [])
        for cve in cve_ids or []:
            self._edge(host, self._node("cve", cve, kev=(cve in kev)), "affected by", None)

    def result(self) -> dict:
        return {"nodes": self._nodes(), "edges": self._edges(), "analytics": self._analytics(),
                "summary": self._summary()}

    def _nodes(self):
        return [{"id": n, "type": d["ntype"], "label": d.get("label", d["value"]),
                 "external": d.get("external"), "mitre": d.get("mitre"), "kev": d.get("kev"),
                 "colour": NODE_COLOURS.get(d["ntype"], "#999")} for n, d in self.g.nodes(data=True)]

    def _edges(self):
        return [{"source": u, "target": v, "relation": k, "count": d["count"],
                 "first_seen": d.get("first_seen"), "last_seen": d.get("last_seen")}
                for u, v, k, d in self.g.edges(keys=True, data=True)]

    def _analytics(self):
        ug = self.g.to_undirected()
        comps = sorted((len(c) for c in nx.connected_components(ug)), reverse=True)
        deg = nx.degree_centrality(self.g)
        top_degree = sorted(deg, key=deg.get, reverse=True)[:5]
        # betweenness on the (small, bounded) graph
        btw = nx.betweenness_centrality(ug) if ug.number_of_nodes() > 2 else {}
        top_between = sorted(btw, key=btw.get, reverse=True)[:5]
        # shortest path from an external IP to any host
        ext = [n for n, d in self.g.nodes(data=True) if d["ntype"] == "ip" and d.get("external")]
        hosts = [n for n, d in self.g.nodes(data=True) if d["ntype"] == "host"]
        path = None
        for e in ext:
            for h in hosts:
                try:
                    path = nx.shortest_path(ug, e, h)
                    break
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
            if path:
                break
        return {"components": comps, "most_central_degree": top_degree,
                "most_central_betweenness": top_between, "external_ip_to_host_path": path}

    def _summary(self):
        parts = [f"+{n} more {t} nodes (capped)" for t, n in self.dropped.items()]
        if self.edge_overflow:
            parts.append(f"+{self.edge_overflow} more relations (capped)")
        return {"capped": bool(parts), "notes": parts,
                "node_count": self.g.number_of_nodes(), "edge_count": self.g.number_of_edges()}


def build_incident_graph(alerts, ti_matches, cve_ids, kev_ids, host_agent, node_cap=NODE_CAP, edge_cap=EDGE_CAP):
    b = GraphBuilder(node_cap, edge_cap)
    for a in alerts:
        b.add_alert(a)
    for m in ti_matches:
        b.add_ti_match(m)
    b.add_cves(host_agent, cve_ids, kev_ids)
    return b.result()


def shared_nodes_across_incidents(per_incident: dict) -> list:
    """per_incident: {incident_id: set(node_ids)}. -> nodes present in >1 incident (campaign pivots)."""
    seen = defaultdict(list)
    for inc, nodes in per_incident.items():
        for n in nodes:
            seen[n].append(inc)
    return sorted(([n, incs] for n, incs in seen.items() if len(incs) > 1), key=lambda x: -len(x[1]))
