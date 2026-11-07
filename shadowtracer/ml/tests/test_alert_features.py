from conftest import FakeAlert
from shadowtracer_ml import alert_features as af


def test_no_source_revealing_names():
    assert [n for n in af.FEATURE_NAMES if any(s in n for s in af.FORBIDDEN_SUBSTRINGS)] == []


def test_all_features_in_unit_range():
    s = af.StreamState()
    for ip in ("", "127.0.0.1", "10.0.0.5", "8.8.8.8", "-"):
        f = af.compute(FakeAlert(src_endpoint_ip=ip, rule_level=12, rule_groups=("sshd", "authentication_failed")), s)
        assert set(f) == set(af.FEATURE_NAMES)
        assert all(0.0 <= v <= 1.0 for v in f.values())


def test_identity_fields_do_not_change_features():
    a = af.compute(FakeAlert(agent_id="001", agent_name="agent-ubuntu-1", location="/var/log/auth.log",
                             cluster_node="worker-test", actor_user="root", src_endpoint_ip="8.8.8.8"), af.StreamState())
    b = af.compute(FakeAlert(agent_id="001", agent_name="replay-x", location="EventChannel",
                             cluster_node="worker1", actor_user="root", src_endpoint_ip="8.8.8.8"), af.StreamState())
    assert a == b


def test_ip_class():
    s = af.StreamState()
    assert af.compute(FakeAlert(src_endpoint_ip="8.8.8.8"), s)["ip_public"] == 1.0
    assert af.compute(FakeAlert(src_endpoint_ip="192.168.1.9"), af.StreamState())["ip_private"] == 1.0
    assert af.compute(FakeAlert(src_endpoint_ip=""), af.StreamState())["ip_none"] == 1.0


def test_first_seen_flags_flip_on_second_sighting():
    s = af.StreamState()
    f1 = af.compute(FakeAlert(agent_id="001", actor_user="alice", src_endpoint_ip="8.8.8.8"), s)
    f2 = af.compute(FakeAlert(agent_id="001", actor_user="alice", src_endpoint_ip="8.8.8.8"), s)
    assert f1["first_seen_user"] == 1.0 and f1["first_seen_srcip"] == 1.0
    assert f2["first_seen_user"] == 0.0 and f2["first_seen_srcip"] == 0.0
    # a different agent has its own memory
    f3 = af.compute(FakeAlert(agent_id="002", actor_user="alice", src_endpoint_ip="8.8.8.8"), s)
    assert f3["first_seen_user"] == 1.0


def test_agent_rate_rises_with_bursts_and_stays_bounded():
    s = af.StreamState()
    rates = [af.compute(FakeAlert(agent_id="001", time=f"2026-11-07T09:30:{i:02d}+00:00"), s)["local_rate"]
             for i in range(0, 30)]
    assert rates[-1] > rates[0] and all(0.0 <= r < 1.0 for r in rates)


def test_state_is_bounded():
    s = af.StreamState()
    for i in range(af.LRU_CAP + 50):
        af.compute(FakeAlert(agent_id="001", actor_user=f"u{i}", src_endpoint_ip=f"10.0.{i // 256}.{i % 256}"), s)
    st = s.get("001")
    assert len(st.users) == af.LRU_CAP and len(st.ips) == af.LRU_CAP
    for a in range(af.MAX_AGENTS + 20):
        s.get(f"agent{a}")
    assert len(s.agents) == af.MAX_AGENTS
