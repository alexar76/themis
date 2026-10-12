"""A small-order Ed25519 key has no secret; `cryptography` accepts, under the identity key, a
signature valid for every message. Attestations from such an "issuer" are refused (2026-10-12)."""

import base64

from attestations import verify

IDENTITY = bytes.fromhex("01" + "00" * 31)
BASE = bytes.fromhex("58" + "66" * 31)
ONE = (1).to_bytes(32, "little")


def test_an_identity_key_attestation_is_refused_for_any_message():
    issuer = base64.b64encode(IDENTITY).decode()
    forged = base64.b64encode(BASE + ONE).decode()
    for message in (b"evidence A", b"permissions B"):
        assert verify(issuer=issuer, signature=forged, message=message) is False


def test_a_small_order_r_under_an_honest_key_is_refused():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = Ed25519PrivateKey.generate()
    issuer = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    sig = key.sign(b"m")
    assert verify(issuer=issuer, signature=base64.b64encode(sig).decode(), message=b"m") is True
    assert verify(issuer=issuer, signature=base64.b64encode(IDENTITY + sig[32:]).decode(), message=b"m") is False
