"""Envelope encryption for tenant-managed paid-source API keys (Phase 6.5 B).

A tenant's third-party key (VirusTotal, MalwareBazaar, AbuseIPDB, GreyNoise) is never
stored or logged in clear. Each key is sealed with envelope encryption:

  - a fresh 256-bit data key (DEK) encrypts the key with AES-256-GCM;
  - the DEK itself is wrapped with AES-256-GCM under the deployment's key-encryption
    key (KEK), which comes from KEY_ENCRYPTION_KEY and never touches the database.

Only the wrapped DEK and the ciphertext are stored, so rotating the KEK re-wraps the
small DEKs (rewrap()) without re-encrypting every secret. Both GCM operations bind the
tenant_key and source as additional authenticated data, so a sealed blob cannot be
replayed into another tenant's or source's row.

Write-only by construction: seal() takes a plaintext and returns a blob + non-secret
fingerprint/last4 for display; nothing here ever returns a stored plaintext except
open(), which only the intel worker calls with the KEK to make the outbound API call.
"""
import base64
import hashlib
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEK_BYTES = 32            # AES-256
DEK_BYTES = 32
NONCE_BYTES = 12
_VERSION = 1
_MAGIC = b"STK1"         # ShadowTracer Key, format 1


class KeyEncryptionError(RuntimeError):
    """KEK missing/malformed, or a blob that fails to authenticate."""


def load_kek(raw: str | None) -> bytes:
    """Decode and validate the KEK from KEY_ENCRYPTION_KEY (base64 of 32 bytes).
    Raises at startup if absent or the wrong size - never run with a guessed key."""
    if not raw:
        raise KeyEncryptionError(
            "KEY_ENCRYPTION_KEY (or KEY_ENCRYPTION_KEY_FILE) is required and not set "
            "(generate with: openssl rand -base64 32)")
    try:
        kek = base64.b64decode(raw.strip(), validate=True)
    except (ValueError, base64.binascii.Error) as e:
        raise KeyEncryptionError(f"KEY_ENCRYPTION_KEY is not valid base64: {e}") from None
    if len(kek) != KEK_BYTES:
        raise KeyEncryptionError(
            f"KEY_ENCRYPTION_KEY decodes to {len(kek)} bytes, need {KEK_BYTES} (AES-256)")
    return kek


def _aad(tenant_key: str, source: str) -> bytes:
    return f"{tenant_key}|{source}".encode()


def fingerprint(plaintext: str) -> str:
    """Non-secret, stable id of a key value: lets the UI show whether two tenants use
    the same key and detect an unchanged re-submit, without storing the key. SHA-256,
    first 16 hex - a prefix, not the whole digest, so it is not a verifier for the key."""
    return hashlib.sha256(plaintext.encode()).hexdigest()[:16]


def last4(plaintext: str) -> str:
    return plaintext[-4:] if len(plaintext) >= 4 else ""


def _pack(wrapped_dek: bytes, dek_nonce: bytes, ct_nonce: bytes, ciphertext: bytes) -> str:
    body = (_MAGIC + struct.pack("!BH", _VERSION, len(wrapped_dek))
            + wrapped_dek + dek_nonce + ct_nonce + ciphertext)
    return base64.b64encode(body).decode()


def _unpack(blob: str) -> tuple[bytes, bytes, bytes, bytes]:
    try:
        body = base64.b64decode(blob, validate=True)
    except (ValueError, base64.binascii.Error):
        raise KeyEncryptionError("sealed key is not valid base64") from None
    if body[:4] != _MAGIC:
        raise KeyEncryptionError("sealed key has an unexpected format")
    version, wlen = struct.unpack("!BH", body[4:7])
    if version != _VERSION:
        raise KeyEncryptionError(f"sealed key version {version} is not supported")
    off = 7
    wrapped_dek = body[off:off + wlen]; off += wlen
    dek_nonce = body[off:off + NONCE_BYTES]; off += NONCE_BYTES
    ct_nonce = body[off:off + NONCE_BYTES]; off += NONCE_BYTES
    ciphertext = body[off:]
    if len(wrapped_dek) != wlen or len(dek_nonce) != NONCE_BYTES or len(ct_nonce) != NONCE_BYTES:
        raise KeyEncryptionError("sealed key is truncated")
    return wrapped_dek, dek_nonce, ct_nonce, ciphertext


def seal(kek: bytes, tenant_key: str, source: str, plaintext: str) -> str:
    """Envelope-encrypt one key. Returns the opaque blob to store (base64)."""
    aad = _aad(tenant_key, source)
    dek = os.urandom(DEK_BYTES)
    ct_nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(ct_nonce, plaintext.encode(), aad)
    dek_nonce = os.urandom(NONCE_BYTES)
    wrapped_dek = AESGCM(kek).encrypt(dek_nonce, dek, aad)
    return _pack(wrapped_dek, dek_nonce, ct_nonce, ciphertext)


def open(kek: bytes, tenant_key: str, source: str, blob: str) -> str:   # noqa: A003
    """Decrypt a sealed key. Only the intel worker calls this, with the KEK."""
    aad = _aad(tenant_key, source)
    wrapped_dek, dek_nonce, ct_nonce, ciphertext = _unpack(blob)
    try:
        dek = AESGCM(kek).decrypt(dek_nonce, wrapped_dek, aad)
        return AESGCM(dek).decrypt(ct_nonce, ciphertext, aad).decode()
    except InvalidTag:
        raise KeyEncryptionError(
            "sealed key failed to authenticate - wrong KEK, or blob/tenant/source mismatch") from None


def rewrap(old_kek: bytes, new_kek: bytes, tenant_key: str, source: str, blob: str) -> str:
    """Re-wrap a blob's DEK under a new KEK without touching the ciphertext (KEK rotation).
    The ciphertext and its nonce are preserved; only the small wrapped DEK changes."""
    aad = _aad(tenant_key, source)
    wrapped_dek, dek_nonce, ct_nonce, ciphertext = _unpack(blob)
    try:
        dek = AESGCM(old_kek).decrypt(dek_nonce, wrapped_dek, aad)
    except InvalidTag:
        raise KeyEncryptionError("rewrap: old KEK does not authenticate this blob") from None
    new_dek_nonce = os.urandom(NONCE_BYTES)
    new_wrapped = AESGCM(new_kek).encrypt(new_dek_nonce, dek, aad)
    return _pack(new_wrapped, new_dek_nonce, ct_nonce, ciphertext)


def demo() -> None:
    """Runnable self-check: round-trip, tamper/AAD binding, and KEK rotation."""
    kek = os.urandom(KEK_BYTES)
    blob = seal(kek, "acme", "virustotal", "VT-SECRET-abcd")
    assert open(kek, "acme", "virustotal", blob) == "VT-SECRET-abcd"
    # AAD binding: same blob under a different tenant or source must not open
    for t, s in (("other", "virustotal"), ("acme", "greynoise")):
        try:
            open(kek, t, s, blob); assert False, "AAD not enforced"
        except KeyEncryptionError:
            pass
    # wrong KEK must not open
    try:
        open(os.urandom(KEK_BYTES), "acme", "virustotal", blob); assert False
    except KeyEncryptionError:
        pass
    # KEK rotation: rewrap under a new KEK, old KEK no longer opens, new one does
    new_kek = os.urandom(KEK_BYTES)
    blob2 = rewrap(kek, new_kek, "acme", "virustotal", blob)
    assert open(new_kek, "acme", "virustotal", blob2) == "VT-SECRET-abcd"
    try:
        open(kek, "acme", "virustotal", blob2); assert False
    except KeyEncryptionError:
        pass
    # display helpers never expose the whole secret
    assert last4("VT-SECRET-abcd") == "abcd"
    assert len(fingerprint("VT-SECRET-abcd")) == 16
    print("secrets_crypto demo: OK")


if __name__ == "__main__":
    demo()
