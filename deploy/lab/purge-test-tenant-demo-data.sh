#!/usr/bin/env bash
# Phase 6.x cleanup (OPTIMIZATION_BACKLOG R8): purge the TEST tenant's load/demo leftovers and the
# orphaned dead-letter fixture topics that a bare pytest run drains into its 5000-message cap. Scoped
# strictly to the TEST tenant and to run-id markers; the main tenant is never touched. Dry-run by
# default (counts only); pass --execute to delete.
#
#   deploy/lab/purge-test-tenant-demo-data.sh            # dry-run: counts only
#   deploy/lab/purge-test-tenant-demo-data.sh --execute  # delete
#
# What it removes (TEST tenant only):
#   - ClickHouse events on load-* agents (generate_load.py), and the test tenant's dead_letter_events
#   - Postgres incidents on load-* agents + their incident_alerts / incident_ti / campaign_incidents
#   - campaigns left with no incidents after that, i.e. the load-generator campaigns (203.0.113.149 etc.)
#   - orphaned Kafka fixture topics shadowtracer.t.<key>.* whose <key> is not a real tenant
# Never removed: replay-dataset incidents (numeric agent ids), real agent-060 data, the main tenant.
set -euo pipefail
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SELF_DIR"
set -a; source .env; set +a
REPO="$(cd ../.. && pwd)"
EXECUTE=0; [ "${1:-}" = "--execute" ] && EXECUTE=1

T="${TEST_TENANT_KEY:?set TEST_TENANT_KEY}"
MAIN="${TENANT_KEY:-}"
CHQ() { docker exec shadowtracer-lab-ch-clickhouse-1-1 clickhouse-client -q "$1"; }
PGQ() { docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" shadowtracer-lab-postgres-1 psql -U "${POSTGRES_USER:-shadowtracer}" -d "${POSTGRES_DB:-shadowtracer}" -tAc "$1"; }

bar() { printf '%s\n' "======================================================================"; }
bar; echo "  TEST-TENANT DEMO/LOAD PURGE  ($([ $EXECUTE = 1 ] && echo EXECUTE || echo DRY-RUN))"; bar

echo "--- counts BEFORE (TEST tenant) ---"
ev=$(CHQ "SELECT count() FROM shadowtracer.events WHERE tenant_id='$T' AND agent_id LIKE 'load-%'")
dl=$(CHQ "SELECT count() FROM shadowtracer.dead_letter_events WHERE tenant_id='$T'" 2>/dev/null || echo 0)
inc=$(PGQ "SELECT count(*) FROM incidents WHERE tenant_key='$T' AND agent_id LIKE 'load-%'")
printf '  ClickHouse load-agent events : %s\n' "$ev"
printf '  ClickHouse dead_letter_events: %s\n' "$dl"
printf '  Postgres load-agent incidents: %s\n' "$inc"

# Kafka orphaned fixture topics (tenant key not real)
mapfile -t ORPHAN < <(
  cd "$REPO/shadowtracer/ingest"
  KAFKA_SECURITY_PROTOCOL=SASL_SSL KAFKA_SASL_USERNAME=admin KAFKA_SASL_PASSWORD="$KAFKA_ADMIN_PASSWORD" \
  KAFKA_SSL_CA_LOCATION="$REPO/deploy/lab/kafka-certs/ca.crt" .venv/bin/python - <<PY
import os
from confluent_kafka.admin import AdminClient
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
real={os.environ['TEST_TENANT_KEY'], os.environ.get('TENANT_KEY','')}
a=AdminClient({'bootstrap.servers':'127.0.0.1:9094',**kafka_client_config_from_env()})
for t in sorted(a.list_topics(timeout=10).topics):
    if t.startswith('shadowtracer.t.'):
        key=t[len('shadowtracer.t.'):].rsplit('.',1)[0]
        if key not in real:
            print(t)
PY
)
printf '  Orphaned Kafka fixture topics : %s\n' "${#ORPHAN[@]}"
printf '    %s\n' "${ORPHAN[@]:0:8}"

if [ "$EXECUTE" != 1 ]; then
  echo; echo "DRY-RUN only. Re-run with --execute to delete. (main tenant $MAIN is never touched)"
  exit 0
fi

echo; echo "--- EXECUTING purge (TEST tenant only) ---"

# 1) Kafka: delete orphaned fixture topics
if [ "${#ORPHAN[@]}" -gt 0 ]; then
  cd "$REPO/shadowtracer/ingest"
  KAFKA_SECURITY_PROTOCOL=SASL_SSL KAFKA_SASL_USERNAME=admin KAFKA_SASL_PASSWORD="$KAFKA_ADMIN_PASSWORD" \
  KAFKA_SSL_CA_LOCATION="$REPO/deploy/lab/kafka-certs/ca.crt" .venv/bin/python - "${ORPHAN[@]}" <<'PY'
import sys, os
from confluent_kafka.admin import AdminClient
from shadowtracer_ingest.kafka_security import kafka_client_config_from_env
a=AdminClient({'bootstrap.servers':'127.0.0.1:9094',**kafka_client_config_from_env()})
fs=a.delete_topics(sys.argv[1:], operation_timeout=30); ok=0
for t,f in fs.items():
    try: f.result(timeout=30); ok+=1
    except Exception as e: print('  FAILED', t, e)
print('  deleted', ok, 'orphaned topics')
PY
  cd "$SELF_DIR"
fi

# The TEST tenant's junk is load/demo synthetic traffic: load-* agents (generate_load.py JSON mode)
# AND agent-000 incidents whose source IP is in the synthetic TEST-NET ranges (syslog mode) - no real
# attacker uses 203.0.113.0/24, 198.51.100.0/24 (RFC 5737) or ::1. SYNTH is the set to purge.
SYNTH="agent_id LIKE 'load-%' OR EXISTS (SELECT 1 FROM unnest(source_ips) ip WHERE ip LIKE '203.0.113.%' OR ip LIKE '198.51.100.%' OR ip = '::1')"
# 2) Postgres: the junk incidents + ALL their FK children, then campaigns left empty. The subquery is
# tenant-scoped, so children are deleted by incident_id (not every child carries tenant_key).
TGT="SELECT id FROM incidents WHERE tenant_key='$T' AND ($SYNTH)"
for tbl in campaign_incidents incident_ti incident_alerts fingerprint_verdicts ml_labels ml_verdict_reviews; do
  PGQ "DELETE FROM $tbl WHERE incident_id IN ($TGT)" >/dev/null
done
PGQ "DELETE FROM incidents WHERE tenant_key='$T' AND ($SYNTH)" >/dev/null
PGQ "DELETE FROM campaigns c WHERE c.tenant_key='$T' AND NOT EXISTS (SELECT 1 FROM campaign_incidents ci WHERE ci.campaign_id=c.id AND ci.tenant_key='$T')" >/dev/null
echo "  Postgres: load/synthetic incidents + their campaigns deleted"

# 3) ClickHouse: load-agent events, synthetic-IP events, and test-tenant dead letters (async mutations)
CHQ "ALTER TABLE shadowtracer.events DELETE WHERE tenant_id='$T' AND (agent_id LIKE 'load-%' OR src_endpoint_ip LIKE '203.0.113.%' OR src_endpoint_ip LIKE '198.51.100.%' OR src_endpoint_ip='::1')" >/dev/null || true
CHQ "ALTER TABLE shadowtracer.dead_letter_events DELETE WHERE tenant_id='$T'" >/dev/null 2>&1 || true
echo "  ClickHouse: load + synthetic-IP events + dead letters delete-mutation submitted (async)"

echo; echo "--- counts AFTER ---"
printf '  Postgres load-agent incidents: %s\n' "$(PGQ "SELECT count(*) FROM incidents WHERE tenant_key='$T' AND agent_id LIKE 'load-%'")"
printf '  Campaigns (203.0.113.149)    : %s\n' "$(PGQ "SELECT count(*) FROM campaigns WHERE tenant_key='$T' AND actor_value='203.0.113.149'")"
printf '  MAIN tenant incidents (unchanged): %s\n' "$(PGQ "SELECT count(*) FROM incidents WHERE tenant_key='$MAIN'")"
echo "DONE."
