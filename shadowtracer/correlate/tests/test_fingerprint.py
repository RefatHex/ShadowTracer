import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shadowtracer_correlate.fingerprint import compute_fingerprint  # noqa: E402

INTERNAL_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

NOW = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _fp(
    rule_groups=("sshd", "authentication_failed"),
    mitre_ids=("T1110.001",),
    source_ips=("8.8.8.8",),
    alert_count=20,
    first_seen=NOW,
    last_seen=None,
    os_family="linux",
    role_tag=None,
):
    return compute_fingerprint(
        list(rule_groups), list(mitre_ids), list(source_ips), alert_count,
        first_seen, last_seen or (first_seen + datetime.timedelta(minutes=2)),
        os_family, role_tag, INTERNAL_RANGES,
    )


def test_same_shape_different_ips_users_and_times_same_fingerprint():
    fp1 = _fp(source_ips=["8.8.8.8"], first_seen=NOW)
    fp2 = _fp(source_ips=["1.2.3.4"], first_seen=NOW + datetime.timedelta(days=3))
    assert fp1 == fp2


def test_different_technique_order_different_fingerprint():
    fp1 = compute_fingerprint(
        ["sshd"], ["T1110.001", "T1021.004"], ["8.8.8.8"], 20, NOW, NOW + datetime.timedelta(minutes=2),
        "linux", None, INTERNAL_RANGES,
    )
    fp2 = compute_fingerprint(
        ["sshd"], ["T1021.004", "T1110.001"], ["8.8.8.8"], 20, NOW, NOW + datetime.timedelta(minutes=2),
        "linux", None, INTERNAL_RANGES,
    )
    assert fp1 != fp2


def test_rule_group_order_does_not_matter_sorted_before_hashing():
    fp1 = _fp(rule_groups=["sshd", "authentication_failed"])
    fp2 = _fp(rule_groups=["authentication_failed", "sshd"])
    assert fp1 == fp2


def test_a_different_attack_has_a_different_fingerprint():
    ssh_brute_force = _fp(rule_groups=["sshd", "authentication_failed"], mitre_ids=["T1110.001"])
    local_user_created = compute_fingerprint(
        ["authentication", "syscheck"], ["T1136.001"], [], 3, NOW, NOW + datetime.timedelta(seconds=5),
        "linux", None, INTERNAL_RANGES,
    )
    assert ssh_brute_force != local_user_created


def test_no_source_ip_is_classified_as_local_actor():
    with_ip = _fp(source_ips=["8.8.8.8"])
    without_ip = _fp(source_ips=[])
    assert with_ip != without_ip


def test_internal_vs_external_source_ip_changes_fingerprint():
    internal = _fp(source_ips=["10.1.2.3"])
    external = _fp(source_ips=["8.8.8.8"])
    assert internal != external


def test_role_tag_change_changes_fingerprint():
    no_role = _fp(role_tag=None)
    with_role = _fp(role_tag="domain-controller")
    assert no_role != with_role


def test_volume_bucket_uses_floor_log2():
    low_volume = _fp(alert_count=4)   # floor(log2(4)) = 2
    high_volume = _fp(alert_count=1000)  # floor(log2(1000)) = 9
    assert low_volume != high_volume

    # Same bucket (floor(log2(4))==floor(log2(7))==2) -> same fingerprint
    same_bucket_a = _fp(alert_count=4)
    same_bucket_b = _fp(alert_count=7)
    assert same_bucket_a == same_bucket_b


def test_fingerprint_never_contains_ip_or_username_substrings():
    """Belt and suspenders beyond the hash-equality tests above: the
    canonical shape actually serialized for hashing must not contain the
    raw IP string anywhere, even transiently."""
    from shadowtracer_correlate.fingerprint import fingerprint_shape
    import json

    shape = fingerprint_shape(
        ["sshd"], ["T1110.001"], ["203.0.113.77"], 20, NOW, NOW + datetime.timedelta(minutes=2),
        "linux", None, INTERNAL_RANGES,
    )
    serialized = json.dumps(shape)
    assert "203.0.113.77" not in serialized
