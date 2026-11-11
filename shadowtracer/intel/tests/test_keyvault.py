"""6.5 B: the intel keyvault opens exactly what the console seals (no format drift), and the
VT worker prefers a live DB key over the legacy static env key."""
import os
import sys

from shadowtracer_intel import keyvault, vt

# import the console's sealing module so the cross-compat test uses the real producer
_CONSOLE = os.path.join(os.path.dirname(__file__), "..", "..", "console", "backend")
sys.path.insert(0, _CONSOLE)
from app import secrets_crypto  # noqa: E402


def test_console_seal_opens_with_intel_keyvault():
    kek = os.urandom(32)
    blob = secrets_crypto.seal(kek, "acme", "virustotal", "VT-KEY-1234")
    assert keyvault.open_sealed(kek, "acme", "virustotal", blob) == "VT-KEY-1234"


def test_aad_and_kek_are_enforced_on_open():
    kek = os.urandom(32)
    blob = secrets_crypto.seal(kek, "acme", "virustotal", "VT-KEY-1234")
    for t, s in (("other", "virustotal"), ("acme", "greynoise")):
        try:
            keyvault.open_sealed(kek, t, s, blob); assert False, "AAD not enforced"
        except keyvault.KeyVaultError:
            pass
    try:
        keyvault.open_sealed(os.urandom(32), "acme", "virustotal", blob); assert False
    except keyvault.KeyVaultError:
        pass


def test_rewrapped_blob_opens_with_new_kek():
    old, new = os.urandom(32), os.urandom(32)
    blob = secrets_crypto.seal(old, "acme", "virustotal", "VT-KEY-1234")
    blob2 = secrets_crypto.rewrap(old, new, "acme", "virustotal", blob)
    assert keyvault.open_sealed(new, "acme", "virustotal", blob2) == "VT-KEY-1234"


def test_load_kek_validates():
    import base64
    assert len(keyvault.load_kek(base64.b64encode(os.urandom(32)).decode())) == 32
    for bad in (None, "", "not-base64!!", base64.b64encode(os.urandom(16)).decode()):
        try:
            keyvault.load_kek(bad); assert False, f"accepted {bad!r}"
        except keyvault.KeyVaultError:
            pass


def test_worker_key_loader_overrides_static_and_falls_back():
    w = vt.VTWorker(engine=None, clusters=[], keys={"t1": "static-key", "t2": "static-2"},
                    node_factory=lambda n, c: None, key_loader=lambda t: {"t1": "db-key"}.get(t))
    assert w._key("t1") == "db-key"           # DB key wins
    assert w._key("t2") == "static-2"         # loader returns None -> falls back to static
    assert w._key("t3") is None
