"""AIMarket federation surface — the two GETs a hub crawler needs to index this node.

THEMIS served only ``/invoke``, and only on loopback: the Hub calls
``AIMARKET_SUPPLY_CHAIN_AUDITOR_URL`` (default ``http://127.0.0.1:8080/invoke``) inside its
own netns, because the Hub's SSRF guard refuses docker-network names. That placement is
deliberate and stays exactly as it is — the admission path never traverses nginx.

What this module adds is the *other* half: being discoverable. A hub crawler finds nodes
through ``GET /.well-known/ai-market.json`` → a **signed** manifest, and a node it cannot
find never enters the federated catalogue. ``signal-hunt`` holds no node list at all — it
derives its sources from ``tool["source_hub"]`` in that catalogue — and the LOGOS assistant
answers from the same live capability list.

Listing the admission gate in the catalogue it gates is not circular. The verdict is not for
sale: ``auditor.audit()`` is deterministic and takes no payment signal (price appears only as
a policy check *about the candidate*), it returns ``decision`` plus
``human_approval_required`` rather than granting anything, and the Hub independently
re-derives the permissions digest instead of trusting what THEMIS says. Bootstrap ("who
admitted the admitter?") is answered the same way it is for every other seed: an
operator-vouched Ed25519 key pinned in ``federation_seeds.json``.

Nothing here formats a document by hand. Both come from ``oracle_core.Protocol`` — the
manifest signature is over the **hub's** canonical form, and that form has teeth: when the
hub grew a fifth ``by_hub_hash`` field, "every oracle manifest failed with 'Invalid manifest
signature' and no oracle could federate at all". A satellite that reimplements the layout
signs itself out of the federation on the next protocol bump.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "v2"
#: oracle_core reads the seed from here before it ever looks at a key file.
_SEED_ENV = "ORACLE_SIGNING_SEED_B64"

#: Declared, not measured. The manifest schema declares `p50_latency_ms` as an integer.
DECLARED_P50_MS = 2500
DECLARED_SUCCESS_RATE = 0.99
CATEGORIES = ("security", "procurement", "supply-chain", "admission")


def load_capability(path: str | Path | None = None) -> dict[str, Any]:
    """The committed capability descriptor this node publishes."""
    target = Path(path) if path else Path(__file__).resolve().parent / "capability.json"
    return json.loads(target.read_text(encoding="utf-8"))


def oracle_signer(seed: bytes, *, key_path: str | Path | None = None):
    """An ``oracle_core`` Signer that IS this node — no second keypair, no new file.

    ``oracle_core.Signer`` keeps a 64-byte key file (seed ‖ pubkey) while this satellite's
    :class:`~themis.provider_signing.ProviderSigner` keeps 32 (seed only), so the same path
    cannot be shared — each rejects the other's size as corrupt. The seed goes in through the
    environment because that branch runs before ``_ensure_keypair``, so ``key_path`` is never
    read or written; it still points somewhere we own, in case a future release does touch it.
    """
    from oracle_core.signing import Signer

    previous = os.environ.get(_SEED_ENV)
    os.environ[_SEED_ENV] = base64.b64encode(seed).decode()
    try:
        # The Signer copies the seed in __init__, so restoring the env immediately is safe —
        # leaving it set would silently re-key any other Signer built later.
        return Signer(key_path=str(key_path or "data/themis_manifest_key_unused"))
    finally:
        if previous is None:
            os.environ.pop(_SEED_ENV, None)
        else:
            os.environ[_SEED_ENV] = previous


def _protocol(*, public_url: str, version: str, seed: bytes,
              capability: dict[str, Any], key_path: str | Path | None = None):
    """An ``oracle_core.Protocol`` describing this one capability.

    ``handler`` is required by the dataclass but never invoked: only ``well_known()`` and
    ``manifest()`` are used, and ``/invoke`` stays this satellite's own route.
    """
    from oracle_core import Capability, OracleSpec
    from oracle_core.protocol import Protocol

    unused = str(key_path or "data/themis_manifest_key_unused")
    cap = Capability(
        capability_id=capability["capability_id"],
        description=capability["description"],
        handler=lambda _payload: {},
        product_id=capability["product_id"],
        input_schema=capability["input_schema"],
        output_schema=capability["output_schema"],
        price_per_call_usd=capability["price_per_call_usd"],
        p50_latency_ms=DECLARED_P50_MS,
        success_rate_30d=DECLARED_SUCCESS_RATE,
    )
    spec = OracleSpec(
        name=capability["name"],
        product_id=capability["product_id"],
        description=capability["description"],
        public_url=public_url.rstrip("/"),
        categories=list(CATEGORIES),
        capabilities=[cap],
        signing_key_path=unused,
        version=version,
    )
    return Protocol(spec, signer=oracle_signer(seed, key_path=unused))


def well_known(*, public_url: str, version: str, seed: bytes,
               capability: dict[str, Any], key_path: str | Path | None = None) -> dict[str, Any]:
    """``GET /.well-known/ai-market.json`` — the crawler's entry point."""
    return _protocol(
        public_url=public_url, version=version, seed=seed,
        capability=capability, key_path=key_path,
    ).well_known()


def manifest(*, public_url: str, version: str, seed: bytes,
             capability: dict[str, Any], key_path: str | Path | None = None) -> dict[str, Any]:
    """``GET /ai-market/v2/manifest`` — signed with this node's own identity."""
    return _protocol(
        public_url=public_url, version=version, seed=seed,
        capability=capability, key_path=key_path,
    ).manifest()
