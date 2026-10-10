"""Decisions require a single authentic, complete snapshot; omissions never mean zero."""

import base64
import copy
from datetime import UTC, datetime

import httpx
import pytest
from awr import SigningKey, canonicalize
from fastapi.testclient import TestClient

import agent
import mcp_verdict as m

NOW = datetime.now(UTC)
STAMP = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
KEY = SigningKey.generate()
QUERY = {"package": "npm:fixture"}


def answer():
    return {
        "type": "histor.check/v1",
        "issuer": KEY.did,
        "checkedAt": STAMP,
        "query": QUERY,
        "target": {
            "id": "0123456789abcdef",
            "endpoint": "npm:fixture",
            "page": "https://histor.test/s/fixture",
            "lastStatus": "ok",
            "listed": True,
            "packageVersion": "1",
            "packageSignals": {
                "version": "1",
                "flags": [],
                "metadataComplete": True,
                "provenanceVerified": True,
                "behaviour": {
                    "version": "1",
                    "complete": True,
                    **{p: {"complete": True} for p in ("startup", "calls", "installScripts")},
                },
            },
        },
        "observed": {
            "toolSetDigest": "sha256-fixture",
            "toolCount": 1,
            "lastObserved": STAMP,
            "changes": 0,
        },
        "patternScan": {
            "status": "scanned",
            "toolSetDigest": "sha256-fixture",
            "patternSet": "sha256-rules",
            "block": 0,
            "advise": 0,
        },
        "classifier": {
            "status": "classified",
            "toolSetDigest": "sha256-fixture",
            "checkedTools": 1,
            "toolCount": 1,
            "truncatedTools": 0,
            "flagged": 0,
            "classifiedAt": STAMP,
        },
    }


def signed(a, key=KEY):
    return {
        **a,
        "signature": {
            "alg": "Ed25519",
            "verificationMethod": f"{key.did}#{key.did.split(':')[-1]}",
            "value": base64.urlsafe_b64encode(key.sign(canonicalize(a))).decode().rstrip("="),
        },
    }


def client_for(a):
    calls = []

    def handle(req):
        calls.append(req.url.path)
        if req.url.path == "/api/v1/issuer":
            return httpx.Response(200, json={"did": KEY.did})
        if req.url.path == "/api/v1/check":
            return httpx.Response(200, json=a)
        raise AssertionError("unsigned second record must never be consulted")

    return httpx.Client(transport=httpx.MockTransport(handle)), calls


def test_complete_snapshot_and_only_that_snapshot_can_approve():
    assert m.decide(answer(), now=NOW) == {"decision": "approve", "reasons": []}
    assert (
        m.decide(
            {"target": {"id": "x"}}, {"server": {"toolSetDigest": "x", "blockMatches": 0}}, now=NOW
        )["decision"]
        == "unknown"
    )


@pytest.mark.parametrize(
    "path,value",
    [
        ("patternScan", None),
        ("classifier", None),
        ("target.lastStatus", "timeout"),
        ("target.listed", False),
        ("observed.lastObserved", "2000-01-01T00:00:00Z"),
        ("observed.toolSetDigest", None),
        ("checkedAt", "2000-01-01T00:00:00Z"),
        ("checkedAt", "2099-01-01T00:00:00Z"),
        ("patternScan.toolSetDigest", "other"),
        ("classifier.checkedTools", 0),
        ("classifier.truncatedTools", 1),
        ("classifier.classifiedAt", None),
        ("target.packageSignals", None),
        ("target.packageSignals.behaviour.complete", False),
        ("target.packageSignals.behaviour.version", "2"),
        ("target.packageSignals.provenanceVerified", None),
        ("target.packageSignals.metadataComplete", False),
        ("patternScan.block", None),
        ("classifier.flagged", None),
        ("observed.toolCount", None),
    ],
)
def test_incomplete_or_stale_never_approves(path, value):
    a = answer()
    cursor = a
    keys = path.split(".")
    for k in keys[:-1]:
        cursor = cursor[k]
    cursor[keys[-1]] = value
    assert m.decide(a, now=NOW)["decision"] != "approve"


def test_all_phases_and_env_and_hidden_email_copy_are_evidence():
    a = answer()
    sig = a["target"]["packageSignals"]
    sig["flags"] = [
        "provenance-lost",
        "publisher-changed",
        "install-scripts-added",
        "new-dependencies",
        "dependency-specs-changed",
    ]
    for phase in ("startup", "calls", "installScripts"):
        sig["behaviour"][phase].update(
            decoys=[".env"],
            network=["mail.test:443"],
            writes=[".bashrc"],
            unexpectedRecipients=["copy@extra.invalid"],
        )
    a["patternScan"].update(block=2, advise=1)
    a["classifier"]["flagged"] = 1
    a["packageLookalike"] = {"of": "npm:popular"}
    a["observed"].update(changes=1, unchangedSince=STAMP)
    r = m.decide(a, now=NOW)
    codes = {i["code"] for i in r["reasons"]}
    assert r["decision"] == "reject"
    assert {
        "READS_SECRETS",
        "UNEXPECTED_RECIPIENT",
        "CALL_NETWORK",
        "INSTALL_NETWORK",
        "STARTUP_NETWORK",
        "RECENT_CHANGE",
        "CLASSIFIER_FLAGS",
        "LOOKALIKE",
        "BLOCK_TIER_PATTERNS",
    } <= codes
    assert any(".env" in i["detail"] for i in r["reasons"])
    assert m.decide({"packageLookalike": {"of": "npm:popular"}}, now=NOW)["decision"] == "review"
    assert m.decide({}, now=NOW)["decision"] == "unknown"


def test_crypto_query_type_and_issuer_binding(monkeypatch):
    monkeypatch.setenv("THEMIS_HISTOR_ISSUER_DID", KEY.did)
    a = signed(answer())
    client, calls = client_for(a)
    assert m.fetch_evidence(QUERY, client) == a
    assert calls == ["/api/v1/check"]
    wrong_key = SigningKey.generate()
    variants = []
    altered = copy.deepcopy(a)
    altered["target"]["lastStatus"] = "tampered"
    variants.append(altered)
    for k, v in [
        ("type", "histor.sth/v1"),
        ("issuer", wrong_key.did),
        ("query", {"package": "npm:other"}),
    ]:
        bad = answer()
        bad[k] = v
        variants.append(signed(bad))
    variants.append(signed(answer(), wrong_key))
    for bad in variants:
        with pytest.raises(Exception):
            m.fetch_evidence(QUERY, client_for(bad)[0])
    monkeypatch.setattr(m, "HISTOR_URL", "http://histor.test")
    with pytest.raises(ValueError):
        m.fetch_evidence(QUERY, client)


def test_route_carries_exact_signed_evidence_and_caches(monkeypatch):
    monkeypatch.delenv("THEMIS_HISTOR_ISSUER_DID", raising=False)
    a = answer()
    a["patternScan"]["block"] = 1
    a = signed(a)
    client, calls = client_for(a)
    monkeypatch.setattr(agent, "histor_client", lambda: client)
    monkeypatch.setattr(agent, "MCP_CACHE", m.VerdictCache())
    api = TestClient(agent.app)
    response = api.get("/mcp/verdict", params=QUERY)
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["decision"] == "reject" and result["policy"] == "themis-mcp/2"
    assert result["evidence"]["check"] == a
    assert response.headers["x-provider-signature"]
    assert api.get("/mcp/verdict", params=QUERY).json()["result"] == result
    assert calls == ["/api/v1/issuer", "/api/v1/check"]
    assert api.get("/mcp/verdict", params={"package": "oci:x"}).status_code == 400
    cache = m.VerdictCache(ttl_s=-1, size=1)
    cache.put("a", {})
    cache.put("b", {})
    assert cache.get("b") is None


def test_bad_queries_and_no_evidence_no_verdict(monkeypatch):
    assert m.parse_query("npm:@a/b", None) == {"package": "npm:@a/b"}
    assert m.parse_query(None, "https://example.test") == {"endpoint": "https://example.test"}
    for args in [
        (None, None),
        ("oci:x", None),
        ("npm:x", "https://x"),
        (None, "http://x"),
        (None, "https://a b"),
    ]:
        with pytest.raises(m.BadQuery):
            m.parse_query(*args)
    client, _ = client_for({"signature": {"value": "fake"}})
    monkeypatch.setattr(agent, "histor_client", lambda: client)
    monkeypatch.setattr(agent, "MCP_CACHE", m.VerdictCache())
    assert TestClient(agent.app).get("/mcp/verdict", params=QUERY).status_code == 503
