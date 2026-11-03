#!/usr/bin/env bash
# Phase 5.6 Item 1: provisions SCRAM credentials and ACLs - run ONCE,
# against the broker BEFORE SASL/the authorizer are turned on
# (chicken-and-egg: kafka-configs.sh/kafka-acls.sh are themselves admin
# clients, so provisioning must happen while the broker still accepts
# unauthenticated admin connections; SCRAM credentials and ACLs are
# stored in the broker's own metadata log, so they survive the
# subsequent restart into SASL_SSL - see docs/design/KAFKA_AUTH.md and
# deploy/lab/README.md for the two-phase sequence this is step one of).
#
# Credentials, one per real-component ROLE (shared across that role's
# own replicas - see .env.example's own comment):
#   admin             - KAFKA_SUPER_USERS, bypasses ACLs entirely: this
#                        script's own future re-runs, topic/ACL management.
#   shipper            - producer only, TENANT_KEY's own two topics.
#   shipper-test       - producer only, TEST_TENANT_KEY's own two topics.
#   writer, correlator - consumer (pattern: every tenant's alerts topic)
#                        + producer (pattern: every tenant's dead-letter
#                        topic) - never producer on alerts, never
#                        consumer on dead-letter.
#   console-backend    - Describe + Read (never Write) on every
#                        tenant's topics, for /health/detail's lag
#                        reporting - Read is needed to fetch the oldest
#                        lagging message's own timestamp, not just
#                        offsets/watermarks.
set -euo pipefail
cd "$(dirname "$0")"
set -a; source .env; set +a

# ACLs specifically (unlike SCRAM credential writes) are refused with
# SecurityDisabledException until an authorizer is actually configured
# on the broker - confirmed for real, not assumed: this script's ACL
# section fails outright on a from-scratch run and must be re-run AFTER
# switching the broker to SASL_SSL + the authorizer (which is itself
# only possible once the "admin" SCRAM credential below already exists -
# see deploy/lab/README.md for the full two-phase sequence). Auto-detected
# the same way create-kafka-topics.sh does - see its own comment.
CLIENT_CONFIG_ARGS=()
if [ -f "kafka-certs/admin-client.properties" ]; then
    CLIENT_CONFIG_ARGS=(--command-config /etc/kafka/certs/admin-client.properties)
fi

add_scram_user() {
    local user="$1" password="$2"
    docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-configs.sh \
        --bootstrap-server localhost:9092 "${CLIENT_CONFIG_ARGS[@]}" --alter --entity-type users --entity-name "$user" \
        --add-config "SCRAM-SHA-256=[password=${password}]"
}

acl() {
    docker exec shadowtracer-lab-kafka-1 /opt/kafka/bin/kafka-acls.sh "${CLIENT_CONFIG_ARGS[@]}" \
        --bootstrap-server localhost:9092 "$@"
}

echo "--- SCRAM credentials ---"
add_scram_user admin "${KAFKA_ADMIN_PASSWORD:?set KAFKA_ADMIN_PASSWORD in deploy/lab/.env}"
add_scram_user shipper "${KAFKA_SHIPPER_PASSWORD:?set KAFKA_SHIPPER_PASSWORD in deploy/lab/.env}"
add_scram_user shipper-test "${KAFKA_SHIPPER_TEST_PASSWORD:?set KAFKA_SHIPPER_TEST_PASSWORD in deploy/lab/.env}"
add_scram_user writer "${KAFKA_WRITER_PASSWORD:?set KAFKA_WRITER_PASSWORD in deploy/lab/.env}"
add_scram_user correlator "${KAFKA_CORRELATOR_PASSWORD:?set KAFKA_CORRELATOR_PASSWORD in deploy/lab/.env}"
add_scram_user console-backend "${KAFKA_CONSOLE_BACKEND_PASSWORD:?set KAFKA_CONSOLE_BACKEND_PASSWORD in deploy/lab/.env}"

echo "--- ACLs ---"
# Shipper: producer only, on its OWN tenant's two topics - never
# --consumer, never another tenant's topic. This is the broker-enforced
# half of KAFKA_AUTH.md's "tenant A cannot produce as tenant B": the
# ACL is scoped to the literal topic name, not a pattern, so a produce
# attempt to any other topic is refused before the message is ever
# written, regardless of what the message's own headers claim.
acl --add --allow-principal "User:shipper" --operation Write --operation Describe \
    --topic "shadowtracer.t.${TENANT_KEY:?set TENANT_KEY in deploy/lab/.env}.alerts" --resource-pattern-type LITERAL
acl --add --allow-principal "User:shipper" --operation Write --operation Describe \
    --topic "shadowtracer.t.${TENANT_KEY}.dead-letter" --resource-pattern-type LITERAL

acl --add --allow-principal "User:shipper-test" --operation Write --operation Describe \
    --topic "shadowtracer.t.${TEST_TENANT_KEY:?set TEST_TENANT_KEY in deploy/lab/.env}.alerts" --resource-pattern-type LITERAL
acl --add --allow-principal "User:shipper-test" --operation Write --operation Describe \
    --topic "shadowtracer.t.${TEST_TENANT_KEY}.dead-letter" --resource-pattern-type LITERAL

# Writer/correlator: consume every tenant's alerts topic (PREFIXED
# pattern - onboarding a new tenant never needs touching this grant),
# produce to every tenant's dead-letter topic, scoped to their real
# consumer groups. Never producer on alerts, never consumer on
# dead-letter.
for user in writer correlator; do
    # shadowtracer-writer / shadowtracer-correlate - see run_writer.py's/
    # run_correlator.py's own KAFKA_GROUP_ID defaults.
    if [ "$user" = "correlator" ]; then group="shadowtracer-correlate"; else group="shadowtracer-writer"; fi
    acl --add --allow-principal "User:${user}" --operation Read --operation Describe \
        --topic "shadowtracer.t." --resource-pattern-type PREFIXED
    acl --add --allow-principal "User:${user}" --operation Write --operation Describe \
        --topic "shadowtracer.t." --resource-pattern-type PREFIXED
    acl --add --allow-principal "User:${user}" --operation Read \
        --group "$group"
done

# Console-backend: Describe + Read + DescribeConfigs, never Write -
# /health/detail's lag reporting needs group offsets and topic
# watermarks (Describe), the oldest lagging message's own timestamp
# (Read - genuinely fetches that one message, not just metadata), AND
# the topic's retention.ms to compute how close a stalled consumer is
# to falling off retention (health.py's _topic_retention_ms calls
# admin.describe_configs(), which is its OWN separate authorizable
# operation - DescribeConfigs, not plain Describe - found the hard way:
# granting only Describe+Read still left this one call failing with
# TOPIC_AUTHORIZATION_FAILED, degraded gracefully by health.py but
# still a real gap in the retention-fraction feature specifically).
acl --add --allow-principal "User:console-backend" --operation Describe --operation Read --operation DescribeConfigs \
    --topic "shadowtracer.t." --resource-pattern-type PREFIXED
acl --add --allow-principal "User:console-backend" --operation Describe \
    --group "shadowtracer-console-lag-check" --resource-pattern-type LITERAL
acl --add --allow-principal "User:console-backend" --operation Describe \
    --group "shadowtracer-writer" --resource-pattern-type LITERAL

echo "done - credentials and ACLs provisioned. Next: switch docker-compose.yml's kafka service to SASL_SSL and restart it."
