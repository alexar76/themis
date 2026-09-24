from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "docs" / "landing" / "console"
BUNDLE = CONSOLE / "receipts.json"


def _canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def test_published_console_is_the_same_file_the_agent_serves():
    """A drifted copy would show visitors a console the agent does not have."""
    served = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
    published = (CONSOLE / "index.html").read_text(encoding="utf-8")
    assert served == published, "run: cp ui/index.html docs/landing/console/index.html"


def _walk_keys(value, out: set[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            out.add(key.lower())
            _walk_keys(child, out)
    elif isinstance(value, list):
        for child in value:
            _walk_keys(child, out)


def test_bundle_carries_no_key_material():
    """Substring matching would trip on permissions.secret_exfiltration_path, which is
    a finding code, not a secret. Check the shape instead: field names and PEM blocks."""
    raw = BUNDLE.read_text(encoding="utf-8")
    assert "-----BEGIN" not in raw
    bundle = json.loads(raw)
    names: set[str] = set()
    _walk_keys(bundle, names)
    for scenario in bundle["scenarios"]:
        for text in (scenario["submitted_text"], scenario["receipt_text"]):
            _walk_keys(json.loads(text), names)
    forbidden = {"private_key", "privatekey", "seed", "secret", "secret_key", "api_key", "token"}
    assert not (names & forbidden), sorted(names & forbidden)
    # The only key material present is the public key the console verifies against.
    assert len(base64.b64decode(bundle["provider_pubkey"], validate=True)) == 32


@pytest.mark.parametrize("scenario_id", ["attested", "safe", "unsafe"])
def test_every_published_receipt_signature_still_verifies(scenario_id):
    """The console's whole claim is that these are re-checkable. Prove it here too."""
    bundle = json.loads(BUNDLE.read_text(encoding="utf-8"))
    key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(bundle["provider_pubkey"], validate=True)
    )
    scenario = next(s for s in bundle["scenarios"] if s["id"] == scenario_id)
    submitted = json.loads(scenario["submitted_text"])
    receipt = json.loads(scenario["receipt_text"])
    message = _canonical(
        {
            "capability_id": submitted["capability_id"],
            "product_id": submitted["product_id"],
            "input_sha256": hashlib.sha256(_canonical(submitted["input"])).hexdigest(),
            "result": receipt["result"],
        }
    )
    try:
        key.verify(base64.b64decode(scenario["signature"], validate=True), message)
    except InvalidSignature:  # pragma: no cover - the failure we are guarding against
        pytest.fail(
            f"{scenario_id}: the published receipt no longer verifies — regenerate with "
            "docs/landing/console/build_bundle.py"
        )


def test_bundle_covers_both_outcomes_and_the_attested_path():
    bundle = json.loads(BUNDLE.read_text(encoding="utf-8"))
    decisions = {s["id"]: s["decision"] for s in bundle["scenarios"]}
    assert decisions == {"attested": "approve", "safe": "approve", "unsafe": "reject"}
    attested = next(s for s in bundle["scenarios"] if s["id"] == "attested")
    proof = json.loads(attested["receipt_text"])["result"]["attestations"]
    assert proof["evidence_verified"] == 2
    assert proof["permissions_bound_to_provider_key"] is True
