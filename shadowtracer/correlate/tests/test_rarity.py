"""Phase 5B Step 3: rare-pattern alerting with a warm-up guard. Real
PostgreSQL (incidents, tenant_alert_settings) and real ClickHouse
(fingerprint_occurrences) - no mocks."""

import datetime
import os
import sys
import uuid

from sqlalchemy import insert

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shadowtracer_correlate.models import fingerprints, incidents, tenant_alert_settings  # noqa: E402
from shadowtracer_correlate.rarity import (  # noqa: E402
    DEFAULT_WARMUP_DAYS, DEFAULT_WARMUP_MIN_INCIDENTS, evaluate_rare_pattern,
    get_tenant_prior_occurrence_threshold, get_tenant_warmup_config, warmup_status,
)

from conftest import TEST_CLICKHOUSE_DB as TEST_CH_DB, insert_tenant  # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc)


def _insert_incident(db, tenant_key, created_at=None, agent_id=None):
    result = db.execute(
        insert(incidents).values(
            tenant_key=tenant_key,
            correlation_key=f"k-{uuid.uuid4().hex[:8]}",
            correlation_basis="source_ip",
            agent_id=agent_id or f"agent-{uuid.uuid4().hex[:8]}",
            first_seen=NOW, last_seen=NOW,
            created_at=created_at or NOW,
        ).returning(incidents.c.id)
    )
    db.commit()
    return result.scalar_one()


def _set_warmup_config(db, tenant_key, days, min_incidents, prior_occurrence_threshold=0):
    db.execute(
        insert(tenant_alert_settings).values(
            tenant_key=tenant_key, rare_alert_warmup_days=days, rare_alert_warmup_min_incidents=min_incidents,
            rare_alert_prior_occurrence_threshold=prior_occurrence_threshold,
        )
    )
    db.commit()


def test_get_tenant_warmup_config_falls_back_to_defaults_when_no_row(db):
    days, min_incidents = get_tenant_warmup_config(db, f"t-{uuid.uuid4().hex[:8]}")
    assert days == DEFAULT_WARMUP_DAYS
    assert min_incidents == DEFAULT_WARMUP_MIN_INCIDENTS


def test_get_tenant_warmup_config_uses_the_per_tenant_override(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    _set_warmup_config(db, tenant, days=1, min_incidents=2)
    days, min_incidents = get_tenant_warmup_config(db, tenant)
    assert (days, min_incidents) == (1, 2)


def test_warmup_status_incomplete_with_no_incidents_at_all(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    status = warmup_status(db, tenant)
    assert status["complete"] is False
    assert status["incident_count"] == 0
    assert status["days_elapsed"] == 0
    assert status["warmup_days"] == DEFAULT_WARMUP_DAYS
    assert status["warmup_min_incidents"] == DEFAULT_WARMUP_MIN_INCIDENTS


def test_warmup_status_incomplete_enough_incidents_but_not_enough_days(db):
    """Real incidents, all created 'now' - plenty of count, zero days
    elapsed since the earliest one. Both conditions must hold; one alone
    isn't enough."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    _set_warmup_config(db, tenant, days=7, min_incidents=2)
    _insert_incident(db, tenant, created_at=NOW)
    _insert_incident(db, tenant, created_at=NOW)
    status = warmup_status(db, tenant)
    assert status["incident_count"] == 2
    assert status["days_elapsed"] == 0
    assert status["complete"] is False


def test_warmup_status_incomplete_enough_days_but_not_enough_incidents(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    _set_warmup_config(db, tenant, days=1, min_incidents=5)
    old = NOW - datetime.timedelta(days=10)
    _insert_incident(db, tenant, created_at=old)
    status = warmup_status(db, tenant)
    assert status["days_elapsed"] >= 1
    assert status["incident_count"] == 1
    assert status["complete"] is False


def test_warmup_status_complete_when_both_conditions_hold(db):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    _set_warmup_config(db, tenant, days=1, min_incidents=2)
    old = NOW - datetime.timedelta(days=10)
    _insert_incident(db, tenant, created_at=old)
    _insert_incident(db, tenant, created_at=old)
    status = warmup_status(db, tenant)
    assert status["complete"] is True


def test_fresh_tenant_during_warmup_never_gets_a_rare_flag(db, ch_client):
    """A fresh tenant (default 7 days / 30 incidents, neither met) must
    never produce a rare-pattern flag, even for a fingerprint that has
    genuinely never been seen before."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    _insert_incident(db, tenant, created_at=NOW)  # 1 incident, 0 days - nowhere near default warmup
    result = evaluate_rare_pattern(db, ch_client, TEST_CH_DB, tenant, f"fp-{uuid.uuid4().hex}")
    assert result is None


def test_past_warmup_never_seen_fingerprint_gets_a_rare_flag_with_correct_count(db, ch_client):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    _set_warmup_config(db, tenant, days=1, min_incidents=1)
    _insert_incident(db, tenant, created_at=NOW - datetime.timedelta(days=10))

    fingerprint_key = f"fp-{uuid.uuid4().hex}"
    result = evaluate_rare_pattern(db, ch_client, TEST_CH_DB, tenant, fingerprint_key)

    assert result is not None
    assert result["flag"] is True
    assert result["occurrence_count"] == 0
    assert "First seen for this tenant" in result["reason"]


def test_past_warmup_already_seen_fingerprint_does_not_get_a_rare_flag(db, ch_client):
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    _set_warmup_config(db, tenant, days=1, min_incidents=1)
    _insert_incident(db, tenant, created_at=NOW - datetime.timedelta(days=10))

    fingerprint_key = f"fp-{uuid.uuid4().hex}"
    # Simulate a prior closure: one occurrence row already recorded.
    ch_client.insert(
        "fingerprint_occurrences",
        [[tenant, fingerprint_key, 1, NOW, 5]],
        column_names=["tenant_id", "fingerprint_key", "incident_id", "closed_at", "alert_count"],
    )

    result = evaluate_rare_pattern(db, ch_client, TEST_CH_DB, tenant, fingerprint_key)
    assert result is None


def test_past_warmup_fingerprint_seen_several_times_does_not_get_a_rare_flag(db, ch_client):
    """Boundary test, the other side of occurrence_count==0: rarity isn't
    "not flagged only at exactly 1 prior occurrence and flagged again
    above that" - any prior occurrence at all (here, several) must not
    flag, the same as exactly one does in the test above."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    _set_warmup_config(db, tenant, days=1, min_incidents=1)
    _insert_incident(db, tenant, created_at=NOW - datetime.timedelta(days=10))

    fingerprint_key = f"fp-{uuid.uuid4().hex}"
    ch_client.insert(
        "fingerprint_occurrences",
        [[tenant, fingerprint_key, i, NOW, 5] for i in range(1, 4)],
        column_names=["tenant_id", "fingerprint_key", "incident_id", "closed_at", "alert_count"],
    )

    result = evaluate_rare_pattern(db, ch_client, TEST_CH_DB, tenant, fingerprint_key)
    assert result is None


def test_get_tenant_prior_occurrence_threshold_falls_back_to_zero_when_no_row(db):
    assert get_tenant_prior_occurrence_threshold(db, f"t-{uuid.uuid4().hex[:8]}") == 0


def test_per_tenant_prior_occurrence_threshold_is_configurable(db, ch_client):
    """Phase 5C Step 0 follow-up: "rare" means NOVEL, not strictly
    "never seen" - a tenant can configure how many prior occurrences
    still count as novel (default 0, unchanged). With threshold=2: seen
    exactly 2 times before -> still flagged (reason text says "seen 2
    times before", not "first seen" - that's reserved for prior_count==0
    specifically); seen 3 times -> not flagged at all."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    _set_warmup_config(db, tenant, days=1, min_incidents=1, prior_occurrence_threshold=2)
    _insert_incident(db, tenant, created_at=NOW - datetime.timedelta(days=10))
    assert get_tenant_prior_occurrence_threshold(db, tenant) == 2

    at_threshold = f"fp-{uuid.uuid4().hex}"
    ch_client.insert(
        "fingerprint_occurrences",
        [[tenant, at_threshold, i, NOW, 5] for i in range(1, 3)],  # exactly 2 prior occurrences
        column_names=["tenant_id", "fingerprint_key", "incident_id", "closed_at", "alert_count"],
    )
    result_at = evaluate_rare_pattern(db, ch_client, TEST_CH_DB, tenant, at_threshold)
    assert result_at is not None
    assert result_at["flag"] is True
    assert result_at["occurrence_count"] == 2
    # Seen > 0 times before (even within threshold) must use the second
    # reason form, never "First seen" - that phrase is reserved for
    # prior_count == 0 specifically, regardless of the tenant's threshold.
    assert result_at["reason"] == "Seen 2 times before for this tenant (at or below the rare threshold of 2)"

    above_threshold = f"fp-{uuid.uuid4().hex}"
    ch_client.insert(
        "fingerprint_occurrences",
        [[tenant, above_threshold, i, NOW, 5] for i in range(1, 4)],  # 3 prior occurrences
        column_names=["tenant_id", "fingerprint_key", "incident_id", "closed_at", "alert_count"],
    )
    result_above = evaluate_rare_pattern(db, ch_client, TEST_CH_DB, tenant, above_threshold)
    assert result_above is None


def test_suppressed_fingerprint_never_gets_a_rare_flag(db, ch_client):
    """suppression_state 'active' must suppress the rare FLAG only - this
    test only proves the flag doesn't fire; the incident/data visibility
    guarantee is structural (the flag is additive, nothing reads it to
    decide whether to show the incident at all - see closer.py)."""
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant)
    _set_warmup_config(db, tenant, days=1, min_incidents=1)
    _insert_incident(db, tenant, created_at=NOW - datetime.timedelta(days=10))

    fingerprint_key = f"fp-{uuid.uuid4().hex}"
    db.execute(
        insert(fingerprints).values(tenant_key=tenant, fingerprint_key=fingerprint_key, suppression_state="active")
    )
    db.commit()

    result = evaluate_rare_pattern(db, ch_client, TEST_CH_DB, tenant, fingerprint_key)
    assert result is None


def test_rarity_is_strictly_per_tenant_not_cross_tenant(db, ch_client):
    """Tenant A has seen this exact fingerprint many times; tenant B never
    has. Tenant B's evaluation must still flag it as rare - tenant A's
    history must have zero effect on tenant B's result."""
    tenant_a = f"t-a-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant_a)
    tenant_b = f"t-b-{uuid.uuid4().hex[:8]}"
    insert_tenant(db, tenant_b)
    shared_fingerprint = f"fp-{uuid.uuid4().hex}"  # same fingerprint_key value for both tenants

    _set_warmup_config(db, tenant_a, days=1, min_incidents=1)
    _set_warmup_config(db, tenant_b, days=1, min_incidents=1)
    _insert_incident(db, tenant_a, created_at=NOW - datetime.timedelta(days=10))
    _insert_incident(db, tenant_b, created_at=NOW - datetime.timedelta(days=10))

    # Tenant A has 5 prior occurrences of this fingerprint.
    ch_client.insert(
        "fingerprint_occurrences",
        [[tenant_a, shared_fingerprint, i, NOW, 5] for i in range(1, 6)],
        column_names=["tenant_id", "fingerprint_key", "incident_id", "closed_at", "alert_count"],
    )

    result_a = evaluate_rare_pattern(db, ch_client, TEST_CH_DB, tenant_a, shared_fingerprint)
    result_b = evaluate_rare_pattern(db, ch_client, TEST_CH_DB, tenant_b, shared_fingerprint)

    assert result_a is None, "tenant A has seen this 5 times before - not rare for A"
    assert result_b is not None, "tenant B has never seen this - must still be rare for B, unaffected by A's history"
    assert result_b["occurrence_count"] == 0
