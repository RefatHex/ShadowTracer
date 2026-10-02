"""Tests against the ClickHouse schema itself (shadowtracer/ingest/schema/),
independent of the shipper/writer - see the "rollup's distinct-count layer,
tested in isolation" section of PHASE3_DATA_PLATFORM.md for why this needs
its own test: follow-up 1's replay test went through writer.py, which also
sets insert_deduplication_token - that test alone couldn't tell you whether
the rollup is correct on its own, or only because the token happened to
prevent the duplicate insert from reaching it in the first place.
"""

COLUMNS = [
    "tenant_id", "time", "cluster_node", "manager_name", "alert_id",
    "agent_id", "agent_name", "agent_ip",
    "rule_id", "rule_level", "rule_description", "rule_groups",
    "mitre_ids", "mitre_tactics", "mitre_techniques",
    "src_endpoint_ip", "src_endpoint_port", "dst_endpoint_ip", "dst_endpoint_port",
    "actor_user", "target_user",
    "decoder_name", "location", "message", "extra_fields", "raw_event",
]


def _row(alert_id: str) -> list:
    return [
        "lab", "2026-01-01 12:00:00.000", "schematest", "wazuh-schematest", alert_id,
        "agent-schematest", "agent-schematest", "10.0.0.1",
        "9999", 5, "rollup isolation test", [], [], [], [],
        "", 0, "", 0, "", "",
        "test", "test", "test message", {}, "{}",
    ]


def test_events_hourly_rollup_is_an_aggregate_state_not_a_number(ch_client):
    """Pins the storage mechanism the isolation test below depends on -
    if a future schema change ever turns this back into a plain count(),
    this test (not just the one below) should be the one that fails."""
    ddl = ch_client.command("SHOW CREATE TABLE events_hourly_rollup")
    assert "AggregateFunction(uniqExact" in ddl
    assert "AggregatingMergeTree" in ddl


def test_rollup_survives_replay_with_no_dedup_token_and_different_batch_shapes(ch_client):
    """The real isolation test: insert the same 20 identities twice, with
    insert_deduplication_token never set at all (unlike writer.py, which
    always sets one), and split into a DIFFERENT batch shape the second
    time (1 batch of 20, then 3+7+10) - proving the rollup's correctness
    doesn't secretly depend on the writer's batching or its token."""
    marker = "schema-isolation-test"
    alert_ids = [f"{marker}-{i}" for i in range(20)]
    rows = [_row(a) for a in alert_ids]

    ch_client.command(f"ALTER TABLE events DELETE WHERE cluster_node = 'schematest'")
    ch_client.command(f"ALTER TABLE events_hourly_rollup DELETE WHERE rule_id = '9999'")

    # No settings= at all - no insert_deduplication_token.
    ch_client.insert("events", rows, column_names=COLUMNS)

    for start, size in [(0, 3), (3, 7), (10, 10)]:
        ch_client.insert("events", rows[start:start + size], column_names=COLUMNS)

    raw_count = ch_client.query(
        "SELECT count() FROM events WHERE cluster_node = 'schematest'"
    ).result_rows[0][0]
    assert raw_count == 40, "both un-deduplicated inserts should have landed as real rows"

    rollup_count = ch_client.query(
        "SELECT uniqExactMerge(identity_state) FROM events_hourly_rollup WHERE rule_id = '9999'"
    ).result_rows[0][0]
    assert rollup_count == 20, (
        f"rollup must still show the original 20 distinct identities with no token "
        f"and a different batch shape on replay, got {rollup_count}"
    )

    ch_client.command("ALTER TABLE events DELETE WHERE cluster_node = 'schematest'")
    ch_client.command("ALTER TABLE events_hourly_rollup DELETE WHERE rule_id = '9999'")
