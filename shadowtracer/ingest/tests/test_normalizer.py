import json

from shadowtracer_ingest.normalizer import normalize_alert


def test_all_real_fixtures_normalize_without_error(real_alert_lines):
    for line in real_alert_lines:
        ev = normalize_alert(line, tenant_id="lab")
        assert ev.tenant_id == "lab"
        assert ev.alert_id
        assert ev.cluster_node  # every lab fixture has cluster.node
        assert not ev.cluster_node_fell_back
        assert isinstance(ev.rule_id, str)  # confirmed string in 4.14.8, not int


def test_fim_alert_flattens_syscheck_not_data(real_alert_lines):
    fim = next(json.loads(l) for l in real_alert_lines if json.loads(l)["rule"]["id"] == "554")
    ev = normalize_alert(json.dumps(fim), tenant_id="lab")
    assert any(k.startswith("syscheck.") for k in ev.extra_fields)
    assert ev.extra_fields["syscheck.sha256_after"] == fim["syscheck"]["sha256_after"]
    assert ev.rule_description == "File added to the system."


def test_sshd_alert_extracts_src_endpoint_and_actor_user(real_alert_lines):
    sshd = next(l for l in real_alert_lines if json.loads(l)["rule"]["id"] == "5710")
    ev = normalize_alert(sshd, tenant_id="lab")
    assert ev.src_endpoint_ip == "::1"
    assert ev.actor_user == "nouser"
    assert "T1110.001" in ev.mitre_ids
    assert "Credential Access" in ev.mitre_tactics


def test_sca_alert_flattens_nested_data_dict(real_alert_lines):
    sca = next(l for l in real_alert_lines if json.loads(l)["rule"]["id"] == "19003")
    ev = normalize_alert(sca, tenant_id="lab")
    assert any(k.startswith("data.sca.") for k in ev.extra_fields)


def test_missing_cluster_node_falls_back_to_manager_name():
    alert = {
        "timestamp": "2026-01-01T00:00:00.000+0000",
        "id": "123.456",
        "rule": {"id": "1", "level": 3, "description": "test", "groups": []},
        "agent": {"id": "000", "name": "test-agent"},
        "manager": {"name": "fallback-manager"},
        "full_log": "test",
        "location": "test",
    }
    ev = normalize_alert(json.dumps(alert), tenant_id="lab")
    assert ev.cluster_node == "fallback-manager"
    assert ev.cluster_node_fell_back is True


def test_malformed_line_raises_for_caller_to_count():
    try:
        normalize_alert("not json at all", tenant_id="lab")
        assert False, "expected an exception"
    except Exception:
        pass
