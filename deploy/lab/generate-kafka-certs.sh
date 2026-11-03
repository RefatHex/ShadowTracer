#!/usr/bin/env bash
# Phase 5.6 Item 1: self-signed lab CA + broker keystore for Kafka's new
# SASL_SSL listeners - same "self-signed, lab-only" pattern already used
# for wazuh-authd's cert (docs/DECISIONS.md's Phase 2 Pass B entry) and
# Caddy's "tls internal" cert for the console. TLS here is for
# encryption + a served cert clients can verify, not client
# authentication - that's what SASL/SCRAM is for (ssl.client.auth=none
# on the broker, so clients need no certificate of their own, only the
# CA's public cert to verify the broker's).
#
# PKCS12, not JKS: Kafka (3.9) accepts either; PKCS12 needs no `keytool`
# (a JDK tool not installed on this host) since openssl alone can build
# one. Never committed - deploy/lab/kafka-certs/ is gitignored, same as
# .env, since these are generated fresh per environment.
set -euo pipefail
cd "$(dirname "$0")"

CERT_DIR="kafka-certs"
DAYS=3650  # lab-only, self-signed - long-lived on purpose, never rotated in this environment
STOREPASS="${KAFKA_SSL_KEYSTORE_PASSWORD:?set KAFKA_SSL_KEYSTORE_PASSWORD in deploy/lab/.env}"

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

if [ -f ca.crt ] && [ -f broker.p12 ]; then
    echo "kafka-certs/ already has a CA and broker keystore - leaving them alone (delete this dir to regenerate)"
    exit 0
fi

echo "generating lab CA..."
openssl req -new -x509 -days "$DAYS" -nodes \
    -subj "/CN=shadowtracer-lab-kafka-ca" \
    -keyout ca.key -out ca.crt 2>/dev/null

echo "generating broker key + CSR..."
openssl req -new -nodes \
    -subj "/CN=kafka" \
    -keyout broker.key -out broker.csr 2>/dev/null

# SAN covers both names a client might connect as (the in-network
# hostname "kafka", and localhost for the EXTERNAL listener a host
# process - like every pytest suite, VERIFY script, and run_*.py this
# session's tests use - reaches over 127.0.0.1:9094).
cat > broker.ext <<EOF
subjectAltName = DNS:kafka, DNS:localhost, IP:127.0.0.1
EOF

echo "signing broker cert..."
openssl x509 -req -days "$DAYS" \
    -in broker.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out broker.crt -extfile broker.ext 2>/dev/null

echo "bundling broker keystore (PKCS12)..."
openssl pkcs12 -export \
    -in broker.crt -inkey broker.key -certfile ca.crt \
    -name kafka -out broker.p12 -passout "pass:${STOREPASS}"

chmod 644 ca.crt broker.p12  # readable by the container's kafka user via the bind mount
rm -f broker.csr broker.ext ca.srl

# Admin client properties for the healthcheck and any kafka-*.sh script
# run via `docker exec` once SASL is enforced (create-kafka-topics.sh/
# create-kafka-acls.sh's --command-config support) - "admin" is the
# KAFKA_SUPER_USERS principal, bypasses ACL checks entirely.
cat > admin-client.properties <<EOF
security.protocol=SASL_SSL
sasl.mechanism=SCRAM-SHA-256
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username="admin" password="${KAFKA_ADMIN_PASSWORD:?set KAFKA_ADMIN_PASSWORD in deploy/lab/.env}";
ssl.truststore.type=PEM
ssl.truststore.location=/etc/kafka/certs/ca.crt
EOF
chmod 644 admin-client.properties

echo "done: kafka-certs/ca.crt (clients' ssl.ca.location), kafka-certs/broker.p12 (broker keystore), kafka-certs/admin-client.properties"
