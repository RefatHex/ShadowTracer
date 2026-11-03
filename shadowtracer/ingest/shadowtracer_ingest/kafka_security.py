"""Phase 5.6 Item 1: builds the TLS/SASL client config block shared by
every Kafka client in this project (shipper, writer, correlator) from
one consistent set of env vars - see docs/design/KAFKA_AUTH.md. Defaults
to PLAINTEXT (the lab's behavior before this item) when
KAFKA_SECURITY_PROTOCOL isn't set, so anything that doesn't set it (an
older deployment, a test that doesn't care) keeps working unchanged."""

import os


def kafka_client_config_from_env() -> dict:
    protocol = os.environ.get("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
    config: dict = {"security.protocol": protocol}
    if protocol in ("SASL_SSL", "SASL_PLAINTEXT"):
        config["sasl.mechanism"] = os.environ.get("KAFKA_SASL_MECHANISM", "SCRAM-SHA-256")
        config["sasl.username"] = os.environ["KAFKA_SASL_USERNAME"]
        config["sasl.password"] = os.environ["KAFKA_SASL_PASSWORD"]
    if protocol in ("SASL_SSL", "SSL"):
        # ssl.ca.pem (the cert CONTENT, inline) over ssl.ca.location (a
        # file path) when both could apply - lets every in-container
        # service (shipper/writer/correlator/console-backend) trust the
        # lab's self-signed CA via one env var instead of a volume mount
        # added to every one of those compose services; a host-side
        # script (pytest, a VERIFY script) that already has the cert
        # file on disk can still use KAFKA_SSL_CA_LOCATION directly.
        ca_pem = os.environ.get("KAFKA_SSL_CA_PEM")
        ca_location = os.environ.get("KAFKA_SSL_CA_LOCATION")
        if ca_pem:
            config["ssl.ca.pem"] = ca_pem
        elif ca_location:
            config["ssl.ca.location"] = ca_location
    return config
