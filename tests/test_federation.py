"""Federation surface — the two GETs that make this node discoverable.

THEMIS was reachable only from the Hub, on loopback: the Hub calls
``AIMARKET_SUPPLY_CHAIN_AUDITOR_URL`` (default ``http://127.0.0.1:8080/invoke``) inside its
own netns because its SSRF guard refuses docker-network names. That admission path is
unchanged and never traverses nginx. What is new is discoverability — a hub crawler finds
nodes through ``/.well-known/ai-market.json`` → a signed manifest, and a node it cannot find
never enters the federated catalogue that signal-hunt derives its sources from and the LOGOS
assistant answers from.

The signature is the part that breaks silently: the hub verifies it with ITS canonical form,
so these tests check the real thing — that ``oracle_core``'s signer, byte-identical to the
hub's, accepts what we produce.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from federation import PROTOCOL_VERSION, load_capability, manifest, oracle_signer, well_known
from provider_signing import ProviderSigner

PUBLIC = "https://themis.example"


@pytest.fixture
def signer(tmp_path, monkeypatch) -> ProviderSigner:
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(tmp_path / "provider.key"))
    return ProviderSigner()


def _doc(fn, signer: ProviderSigner, tmp_path) -> dict:
    return fn(
        public_url=PUBLIC,
        version="0.1.0",
        seed=signer.seed,
        capability=load_capability(),
        key_path=tmp_path / "never-written.key",
    )


def test_well_known_carries_what_the_crawler_requires(signer, tmp_path):
    wk = _doc(well_known, signer, tmp_path)
    # aimarket_hub.validator._basic_well_known_check requires exactly these two.
    assert isinstance(wk["name"], str) and wk["name"]
    assert wk["manifest_url"] == f"{PUBLIC}/ai-market/v2/manifest"
    assert wk["signer_public_key"] == signer.public_key_b64
    assert wk["protocol_version"] == PROTOCOL_VERSION


def test_manifest_signature_verifies_with_the_hubs_own_canonical(signer, tmp_path):
    m = _doc(manifest, signer, tmp_path)
    verifier = oracle_signer(signer.seed, key_path=tmp_path / "verifier-unused.key")
    assert verifier.verify_manifest_signature(m, signer.public_key_b64)


def test_manifest_and_audit_report_are_signed_by_ONE_identity(signer, tmp_path):
    """Two keypairs would make the manifest advertise one key while capability.json and the
    report signature advertise another — a verifier following the chain stops there."""
    m = _doc(manifest, signer, tmp_path)
    assert m["signature"]["public_key"] == signer.public_key_b64


def test_borrowing_the_seed_creates_no_second_key_file_and_leaks_no_env(signer, tmp_path):
    target = tmp_path / "must-not-exist.key"
    before = os.environ.get("ORACLE_SIGNING_SEED_B64")
    oracle_signer(signer.seed, key_path=target)
    assert not target.exists(), "the env seed path must never touch a key file"
    assert os.environ.get("ORACLE_SIGNING_SEED_B64") == before, (
        "a leaked seed env var would silently re-key any oracle_core Signer built later"
    )


def test_tampering_with_the_tool_row_invalidates_the_signature(signer, tmp_path):
    m = _doc(manifest, signer, tmp_path)
    verifier = oracle_signer(signer.seed, key_path=tmp_path / "v2-unused.key")
    m["tools"][0]["price_per_call_usd"] = 0.0
    assert not verifier.verify_manifest_signature(m, signer.public_key_b64)


def test_published_invoke_url_obeys_the_rule_themis_enforces_on_others(signer, tmp_path):
    """`auditor` flags a candidate whose public invoke_url is plaintext HTTP. Listing itself
    in the catalogue means holding itself to that."""
    cap = load_capability()
    assert cap["invoke_url"].startswith("https://"), cap["invoke_url"]
    assert "127.0.0.1" not in cap["invoke_url"], "a loopback URL is not purchasable"


# ── the routes ────────────────────────────────────────────────────────────────


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIMARKET_PROVIDER_IDENTITY_FILE", str(tmp_path / "agent.key"))
    monkeypatch.setenv("THEMIS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("THEMIS_PUBLIC_URL", PUBLIC)
    import importlib

    import agent

    importlib.reload(agent)
    with TestClient(agent.app) as c:
        yield c, agent


def test_routes_serve_a_verifiable_pair(client):
    c, agent = client
    wk = c.get("/.well-known/ai-market.json")
    assert wk.status_code == 200
    body = wk.json()
    assert body["manifest_url"].endswith("/ai-market/v2/manifest")

    man = c.get("/ai-market/v2/manifest")
    assert man.status_code == 200
    m = man.json()
    verifier = oracle_signer(agent.SIGNER.seed, key_path=agent.DATA_DIR / "v-unused.key")
    assert verifier.verify_manifest_signature(m, agent.SIGNER.public_key_b64)
    assert body["signer_public_key"] == m["signature"]["public_key"]


def test_the_catalogue_row_names_the_admission_capability(client):
    c, _agent = client
    row = c.get("/ai-market/v2/manifest").json()["tools"][0]
    assert row["capability_id"] == "agent.security.supply-chain.audit@v1"
    assert row["product_id"] == "themis"
    assert isinstance(row["p50_latency_ms"], int)
