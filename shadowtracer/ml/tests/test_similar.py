"""Phase 7.5: the structured-text builder and helpers (pure - no model or Qdrant needed; the heavy
imports in similar.py are lazy, inside Embedder/QdrantIndex)."""
import datetime as dt

from shadowtracer_ml import similar


def test_point_id_deterministic_and_tenant_scoped():
    assert similar.point_id("tA", 42) == similar.point_id("tA", 42)
    assert similar.point_id("tA", 42) != similar.point_id("tB", 42)   # tenant in the id
    assert similar.point_id("tA", 42) != similar.point_id("tA", 43)


def test_actor_class_internal_vs_external():
    ir = ["10.0.0.0/8"]
    assert similar._actor_class(["10.0.0.5"], ir) == "internal"
    assert similar._actor_class(["45.33.32.171"], ir) == "external"   # public, not internal
    assert similar._actor_class([], ir) == "none"


def test_file_classes_bucket_paths_not_raw():
    assert set(similar._file_classes(["/var/www/x.php", "/tmp/evil", "/etc/cron.d/bad", "/root/.bashrc"])) == \
        {"web-root", "temp", "persistence", "home"}


def test_duration_and_count_buckets():
    now = dt.datetime(2026, 11, 16, 12, 0, 0)
    assert similar._duration_bucket(now, now + dt.timedelta(seconds=30)) == "<1m"
    assert similar._duration_bucket(now, now + dt.timedelta(hours=3)) == "<6h"
    assert similar._bucket(1) == "<=1" and similar._bucket(5) == "<=10" and similar._bucket(5000) == ">1000"


def test_build_text_is_shape_only_and_versioned():
    facts = {
        "rule_descriptions": ["sshd: invalid user"], "rule_groups": ["authentication_failed"],
        "mitre_techniques": ["T1110"], "mitre_tactics": ["TA0006"], "actor_class": "external",
        "target_class": "linux", "target_role": "web", "alert_count_bucket": "<=30",
        "duration_bucket": "<5m", "ti_sources": ["abuseipdb"], "yara_rules": [], "file_classes": [],
        "verdict": "escalated",
    }
    text = similar.build_text(facts)
    # the structured shape is present; no raw usernames/IPs/hostnames ever enter the builder
    assert "mitre techniques: T1110" in text
    assert "actor: external" in text and "target: linux web" in text and "verdict: escalated" in text
    # deterministic
    assert similar.build_text(facts) == text
    assert similar.TEXT_VERSION == "sim-text-v1" and similar.VECTOR_DIM == 384
