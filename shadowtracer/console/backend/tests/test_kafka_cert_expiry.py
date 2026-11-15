"""Phase 6.6 (A.2): the Kafka TLS cert-expiry check surfaced in /health/detail. No broker needed -
generates self-signed certs with known notAfter dates into a temp dir."""
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import health


def _write_cert(path, days_valid):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-kafka-ca")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days_valid))
            .sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_healthy_cert_not_flagged(tmp_path, monkeypatch):
    ca = tmp_path / "ca.crt"; _write_cert(ca, days_valid=3000)
    monkeypatch.setenv("KAFKA_SSL_CA_LOCATION", str(ca))
    monkeypatch.delenv("KAFKA_SSL_CERTIFICATE_LOCATION", raising=False)
    r = health.kafka_cert_expiry(None)
    assert r["alert"] is False
    assert r["certs"]["ca"]["days_remaining"] > 2900
    assert r["certs"]["ca"]["expiring_soon"] is False


def test_near_expiry_cert_alerts(tmp_path, monkeypatch):
    ca = tmp_path / "ca.crt"; _write_cert(ca, days_valid=10)   # < 30-day warn window
    monkeypatch.setenv("KAFKA_SSL_CA_LOCATION", str(ca))
    monkeypatch.delenv("KAFKA_SSL_CERTIFICATE_LOCATION", raising=False)
    r = health.kafka_cert_expiry(None)
    assert r["alert"] is True
    assert r["certs"]["ca"]["expiring_soon"] is True


def test_missing_cert_is_skipped_not_raised(tmp_path, monkeypatch):
    monkeypatch.setenv("KAFKA_SSL_CA_LOCATION", str(tmp_path / "nope.crt"))
    monkeypatch.delenv("KAFKA_SSL_CERTIFICATE_LOCATION", raising=False)
    r = health.kafka_cert_expiry(None)
    assert r == {"warn_days": 30, "certs": {}, "alert": False}
