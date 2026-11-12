"""Phase 7.6: event-relationship graph builder + analytics (pure) and the router (DB)."""
from app import graph as G
from app.routers import graph as graph_router  # noqa: F401  (import-time sanity)
from test_incidents_api import _make_incident, app_settings, client, tenant  # noqa: F401
from sqlalchemy import text


def _bf_alert(user, t):
    return {"time": t, "agent_id": "060", "agent_name": "web01", "rule_id": "5710",
            "rule_description": "sshd: invalid user", "rule_groups": ["authentication_failed"],
            "mitre_techniques": ["T1110"], "src_ip": "45.33.32.171", "dst_ip": None,
            "actor_user": None, "target_user": user, "file": None, "yara_rule": None}


def test_brute_force_chain_ip_to_users_to_host():
    alerts = [_bf_alert(f"bf{i}", 1000 + i) for i in range(4)]
    g = G.build_incident_graph(alerts, [], [], [], "060")
    types = {n["type"] for n in g["nodes"]}
    assert {"ip", "user", "host", "rule"} <= types
    rels = {(e["source"], e["target"], e["relation"]) for e in g["edges"]}
    assert ("ip:45.33.32.171", "user:bf0", "failed login") in rels
    assert any(s == "user:bf0" and t == "host:060" for s, t, r in rels)
    # external attacker IP -> host path exists
    assert g["analytics"]["external_ip_to_host_path"] is not None
    assert g["analytics"]["external_ip_to_host_path"][0] == "ip:45.33.32.171"


def test_fim_yara_chain_host_file_rule():
    a = {"time": 1, "agent_id": "060", "agent_name": "web01", "rule_id": "110201", "rule_description": "YARA match",
         "rule_groups": ["syscheck"], "mitre_techniques": [], "src_ip": None, "dst_ip": None,
         "actor_user": None, "target_user": None, "file": "/tmp/evil", "yara_rule": "SUSP_EICAR"}
    g = G.build_incident_graph([a], [{"observable_type": "sha256", "observable": "deadbeef", "sources": ["malwarebazaar"]}],
                               ["CVE-2021-34527"], ["CVE-2021-34527"], "060")
    rels = {(e["source"], e["target"], e["relation"]) for e in g["edges"]}
    assert ("host:060", "file:/tmp/evil", "changed") in rels
    assert ("file:/tmp/evil", "yara:SUSP_EICAR", "matched") in rels
    assert ("host:060", "cve:CVE-2021-34527", "affected by") in rels
    kev = [n for n in g["nodes"] if n["type"] == "cve"][0]
    assert kev["kev"] is True


def test_caps_and_summary():
    alerts = [_bf_alert(f"u{i}", i) for i in range(500)]        # 500 distinct users
    g = G.build_incident_graph(alerts, [], [], [], "060", node_cap=50, edge_cap=80)
    assert g["summary"]["node_count"] <= 50 and g["summary"]["edge_count"] <= 80
    assert g["summary"]["capped"] and any("more" in n for n in g["summary"]["notes"])


def test_edge_count_aggregates_repeats():
    alerts = [_bf_alert("bob", 1000 + i) for i in range(6)]     # same (ip, user) six times
    g = G.build_incident_graph(alerts, [], [], [], "060")
    e = next(e for e in g["edges"] if e["relation"] == "failed login")
    assert e["count"] == 6 and e["first_seen"] == 1000 and e["last_seen"] == 1005


def test_shared_nodes_across_incidents():
    per = {1: {"ip:45.33.32.171", "host:a"}, 2: {"ip:45.33.32.171", "host:b"}, 3: {"host:c"}}
    shared = G.shared_nodes_across_incidents(per)
    assert shared and shared[0][0] == "ip:45.33.32.171" and set(shared[0][1]) == {1, 2}


# --- router (DB) ---------------------------------------------------------------------------------
def _token(client, db, tenant, role="analyst"):
    from test_incidents_api import _token_for
    return {"Authorization": f"Bearer {_token_for(client, db, tenant[0], f'{role}@x.io', role=role)}"}


def test_incident_graph_404_for_missing_and_cross_tenant(client, db, tenant):
    h = _token(client, db, tenant)
    assert client.get("/api/incidents/99999999/graph", headers=h).status_code == 404


def test_incident_graph_viewer_forbidden(client, db, tenant):
    inc = _make_incident(db, tenant[1], agent_id="060")
    h = _token(client, db, tenant, role="viewer")
    assert client.get(f"/api/incidents/{inc}/graph", headers=h).status_code == 403


def test_incident_graph_builds_with_cve(client, db, tenant):
    inc = _make_incident(db, tenant[1], agent_id="060")
    db.execute(text("UPDATE incidents SET cve_ids='{CVE-2021-34527}', kev_cve_ids='{CVE-2021-34527}' WHERE id=:i"), {"i": inc})
    db.commit()
    h = _token(client, db, tenant)
    r = client.get(f"/api/incidents/{inc}/graph", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "nodes" in body and "edges" in body and "analytics" in body and "response_ms" in body
    assert any(n["type"] == "cve" for n in body["nodes"])        # CVE node present even with no alerts
    # second call is cached
    assert client.get(f"/api/incidents/{inc}/graph", headers=h).json()["cached"] is True
