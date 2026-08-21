from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

import agent


def _envelope(input_payload: dict) -> dict:
    return {
        "input": input_payload,
        "product_id": agent.PRODUCT_ID,
        "capability_id": agent.CAPABILITY_ID,
    }


def _verify_signature(response, input_payload: dict) -> None:
    body = response.json()
    signature = base64.b64decode(response.headers["x-provider-signature"], validate=True)
    input_json = json.dumps(input_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    canonical = json.dumps(
        {
            "capability_id": agent.CAPABILITY_ID,
            "product_id": agent.PRODUCT_ID,
            "input_sha256": hashlib.sha256(input_json.encode()).hexdigest(),
            "result": body["result"],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    public_key = base64.b64decode(TestClient(agent.app).get("/health").json()["provider_pubkey"])
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical.encode())


def test_health_and_invoke_return_signed_deterministic_report(safe_payload):
    with TestClient(agent.app) as client:
        health = client.get("/health")
        assert health.json()["ok"] is True
        response = client.post("/invoke", json=_envelope(safe_payload))
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["result"]["decision"] == "approve"
    assert body["result"]["metis"] == {"status": "skipped", "reason": "not_requested"}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    _verify_signature(response, safe_payload)


def test_signature_is_bound_to_exact_audit_input(safe_payload):
    with TestClient(agent.app) as client:
        first = client.post("/invoke", json=_envelope(safe_payload))
        changed = deepcopy(safe_payload)
        changed["usage"]["monthly_invocations"] += 1
        second = client.post("/invoke", json=_envelope(changed))
    assert first.headers["x-provider-signature"] != second.headers["x-provider-signature"]


def test_provider_identity_cannot_be_selected_by_caller(safe_payload):
    with TestClient(agent.app) as client:
        wrong_product = _envelope(safe_payload)
        wrong_product["product_id"] = "another-product"
        wrong_capability = _envelope(safe_payload)
        wrong_capability["capability_id"] = "another.audit@v1"
        assert client.post("/invoke", json=wrong_product).status_code == 400
        assert client.post("/invoke", json=wrong_capability).status_code == 400


def test_request_boundary_and_closed_framework_routes(safe_payload):
    with TestClient(agent.app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        oversized = client.post("/invoke", content=b"x" * (agent.MAX_INVOKE_BYTES + 1))
        malformed = client.post(
            "/invoke",
            content=b"{}",
            headers={"content-type": "application/json", "content-length": "invalid"},
        )
        invalid = client.post("/invoke", json={"input": {"unexpected": True}})
    assert oversized.status_code == 413
    assert malformed.status_code == 413
    assert invalid.status_code == 422
    assert invalid.headers["cache-control"] == "no-store"


def test_duplicate_json_keys_are_rejected(safe_payload):
    candidate = json.dumps(safe_payload["candidate"], separators=(",", ":"))
    permissions = json.dumps(safe_payload["permissions"], separators=(",", ":"))
    evidence = json.dumps(safe_payload["evidence"], separators=(",", ":"))
    usage = json.dumps(safe_payload["usage"], separators=(",", ":"))
    policy = json.dumps(safe_payload["policy"], separators=(",", ":"))
    raw = (
        '{"input":{"candidate":' + candidate
        + ',"permissions":' + permissions
        + ',"evidence":' + evidence
        + ',"usage":' + usage
        + ',"policy":' + policy
        + ',"request_metis":false,"request_metis":false},'
        + f'"product_id":"{agent.PRODUCT_ID}","capability_id":"{agent.CAPABILITY_ID}"}}'
    )
    with TestClient(agent.app) as client:
        response = client.post("/invoke", content=raw, headers={"content-type": "application/json"})
    assert response.status_code == 400
    assert response.json()["detail"] == "request must contain unambiguous JSON"


def test_lazy_metis_status_is_returned_and_pollable(monkeypatch, safe_payload):
    class FakeQueue:
        class Advisor:
            enabled = True

        advisor = Advisor()

        async def submit(self, prompt):
            assert "untrusted data" in prompt
            return {
                "status": "pending",
                "verification_id": "test-job-123",
                "poll_url": "/verification/test-job-123",
            }

        async def get(self, job_id):
            if job_id != "test-job-123":
                return None
            return {
                "status": "completed",
                "verification_id": job_id,
                "poll_url": f"/verification/{job_id}",
                "assessment_verified": True,
            }

        async def close(self):
            return None

    monkeypatch.setattr(agent, "METIS_QUEUE", FakeQueue())
    safe_payload["request_metis"] = True
    with TestClient(agent.app) as client:
        response = client.post("/invoke", json=_envelope(safe_payload))
        assert response.json()["result"]["metis"]["status"] == "pending"
        poll = client.get("/verification/test-job-123")
        missing = client.get("/verification/not-found")
        malformed = client.get("/verification/!!!")
    assert poll.status_code == 200
    assert poll.json()["result"]["metis"]["status"] == "completed"
    _verify_signature(poll, {"verification_id": "test-job-123"})
    assert missing.status_code == 404
    assert malformed.status_code == 404
