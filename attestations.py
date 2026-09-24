"""Offline attestation checks for a bounded candidate dossier.

THEMIS never fetches a candidate URL, so it cannot know that
``https://audit.example.com/report.pdf`` exists, let alone that it says
anything useful. A URL plus a digest is a *claim*; an attestation is that claim
signed by a key, which is something this service can check with no network at
all.

Two statements are defined. Both are canonical JSON (sorted keys, no spaces)
so an issuer and a verifier cannot disagree about the signed bytes:

``aimarket.evidence.v1``
    ``{"kind":…,"sha256":…,"statement":"aimarket.evidence.v1","url":…}``
    Signed by whoever vouches for that exact artifact. A third-party auditor
    signing its own report is strong; a publisher signing its own SBOM is
    weaker but still non-repudiable.

``aimarket.permissions.v1``
    ``{"permissions":{…},"product_id":…,"publisher_id":…,
    "statement":"aimarket.permissions.v1"}``
    Signed by the candidate's ``provider_pubkey``. Declared permissions remain
    a declaration — but a signed declaration is one the publisher cannot later
    deny, which is what makes a stake slashable.

``aimarket.violation.v1``
    ``{"capability_id":…,"permission":…,"permissions_sha256":…,"product_id":…,
    "statement":"aimarket.violation.v1"}``
    Signed by a party that *observed* the capability doing what it declared it
    would not do. This is what turns a declaration into a falsifiable claim: the
    report is bound to the digest of the exact declaration it contradicts, so
    fixing the declaration honestly retires old reports instead of branding the
    publisher forever, and a report cannot be replayed against a different
    declaration or a different capability.

A forged or malformed proof is always worse than an absent one: verification
failures are reported as findings, while merely missing attestations are only
scored when the buyer's policy asks for them.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EVIDENCE_STATEMENT = "aimarket.evidence.v1"
PERMISSIONS_STATEMENT = "aimarket.permissions.v1"
VIOLATION_STATEMENT = "aimarket.violation.v1"

_ED25519_KEY_BYTES = 32
_ED25519_SIGNATURE_BYTES = 64


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def evidence_message(kind: str, url: str, sha256: str) -> bytes:
    """Bytes an evidence issuer signs. The digest is mandatory by construction."""
    return canonical(
        {
            "kind": kind,
            "sha256": sha256.lower(),
            "statement": EVIDENCE_STATEMENT,
            "url": url.strip(),
        }
    )


def permissions_message(
    *, product_id: str, publisher_id: str, permissions: dict[str, bool]
) -> bytes:
    """Bytes a publisher signs to stand behind its own permission declaration."""
    return canonical(
        {
            "permissions": {key: bool(value) for key, value in sorted(permissions.items())},
            "product_id": product_id,
            "publisher_id": publisher_id,
            "statement": PERMISSIONS_STATEMENT,
        }
    )


def permissions_digest(permissions: dict[str, bool]) -> str:
    """Digest of a declaration, independent of who published it.

    Deliberately covers the permissions alone: a violation report names the
    capability separately, so binding the digest to a product would make the
    same declaration hash differently per listing for no gain.
    """
    canonical_permissions = canonical(
        {key: bool(value) for key, value in sorted(permissions.items())}
    )
    return hashlib.sha256(canonical_permissions).hexdigest()


def violation_message(
    *, capability_id: str, permission: str, permissions_sha256: str, product_id: str
) -> bytes:
    """Bytes an observer signs to contradict one declared permission."""
    return canonical(
        {
            "capability_id": capability_id,
            "permission": permission,
            "permissions_sha256": permissions_sha256.lower(),
            "product_id": product_id,
            "statement": VIOLATION_STATEMENT,
        }
    )


def _decode(value: str, expected: int) -> bytes | None:
    try:
        raw = base64.b64decode(value.encode(), validate=True)
    except (ValueError, UnicodeEncodeError):
        return None
    if len(raw) != expected or base64.b64encode(raw).decode() != value:
        return None
    return raw


def decode_public_key(value: str) -> bytes | None:
    """Return the raw 32 bytes of a canonical base64 Ed25519 public key."""
    return _decode(value, _ED25519_KEY_BYTES)


def verify(*, issuer: str, signature: str, message: bytes) -> bool:
    """True only for a canonical key, a canonical signature and an exact match.

    Every failure mode — bad base64, wrong length, non-canonical encoding, a
    point that is not on the curve, a signature over different bytes — returns
    False. Nothing here touches the network or the filesystem.
    """
    key_bytes = decode_public_key(issuer)
    signature_bytes = _decode(signature, _ED25519_SIGNATURE_BYTES)
    if key_bytes is None or signature_bytes is None:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature_bytes, message)
    except (InvalidSignature, ValueError):
        return False
    return True
