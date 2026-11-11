"""Open envelope-sealed paid-source keys on the intel side (Phase 6.5 B).

The console seals a tenant's API key (app/secrets_crypto.py); the intel worker opens it here
to make the outbound call. This is the decrypt half of the SAME STK1 format - the worker never
seals, so only open_sealed()/load_kek() live here. A cross-compatibility test
(tests/test_keyvault.py) seals with the console module and opens with this one, so the two
implementations can never drift.
"""
import base64
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEK_BYTES = 32
NONCE_BYTES = 12
_MAGIC = b"STK1"
_VERSION = 1


class KeyVaultError(RuntimeError):
    pass


def load_kek(raw: str | None) -> bytes:
    if not raw:
        raise KeyVaultError("KEY_ENCRYPTION_KEY is required to open tenant source keys and is not set")
    try:
        kek = base64.b64decode(raw.strip(), validate=True)
    except (ValueError, base64.binascii.Error):
        raise KeyVaultError("KEY_ENCRYPTION_KEY is not valid base64") from None
    if len(kek) != KEK_BYTES:
        raise KeyVaultError(f"KEY_ENCRYPTION_KEY decodes to {len(kek)} bytes, need {KEK_BYTES}")
    return kek


def open_sealed(kek: bytes, tenant_key: str, source: str, blob: str) -> str:
    aad = f"{tenant_key}|{source}".encode()
    try:
        body = base64.b64decode(blob, validate=True)
    except (ValueError, base64.binascii.Error):
        raise KeyVaultError("sealed key is not valid base64") from None
    if body[:4] != _MAGIC:
        raise KeyVaultError("sealed key has an unexpected format")
    version, wlen = struct.unpack("!BH", body[4:7])
    if version != _VERSION:
        raise KeyVaultError(f"sealed key version {version} is not supported")
    off = 7
    wrapped_dek = body[off:off + wlen]; off += wlen
    dek_nonce = body[off:off + NONCE_BYTES]; off += NONCE_BYTES
    ct_nonce = body[off:off + NONCE_BYTES]; off += NONCE_BYTES
    ciphertext = body[off:]
    if len(wrapped_dek) != wlen or len(dek_nonce) != NONCE_BYTES or len(ct_nonce) != NONCE_BYTES:
        raise KeyVaultError("sealed key is truncated")
    try:
        dek = AESGCM(kek).decrypt(dek_nonce, wrapped_dek, aad)
        return AESGCM(dek).decrypt(ct_nonce, ciphertext, aad).decode()
    except InvalidTag:
        raise KeyVaultError("sealed key failed to authenticate (wrong KEK or tenant/source mismatch)") from None
