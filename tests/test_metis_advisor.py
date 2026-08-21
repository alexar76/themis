from __future__ import annotations

import asyncio

import httpx
import pytest

from metis_advisor import MetisAdvisor, VerificationQueue, _bounded_float, _bounded_int


def _transport(status=200, body=None, content=None):
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == "Bearer test-key"
        assert request.url.path == "/v1/verify"
        if content is not None:
            return httpx.Response(status, content=content)
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_successful_metis_envelope_is_bounded():
    advisor = MetisAdvisor(
        api_key="test-key",
        transport=_transport(
            body={
                "status": "success",
                "verified": True,
                "verify_performed": True,
                "verify_score": 0.91,
                "route": "fast",
                "answer": "sound" * 1_000,
            }
        ),
    )
    result = await advisor.assess("review")
    assert result["status"] == "completed"
    assert result["assessment_verified"] is True
    assert result["verify_score"] == 0.91
    assert len(result["assessment"]) == 2_000


@pytest.mark.asyncio
@pytest.mark.parametrize("score", [True, "100", -1, 101])
async def test_untrusted_metis_score_is_sanitized(score):
    advisor = MetisAdvisor(
        api_key="test-key",
        transport=_transport(
            body={
                "status": "success",
                "verified": True,
                "verify_performed": True,
                "verify_score": score,
                "route": "attacker-controlled",
                "answer": "assessment",
            }
        ),
    )
    result = await advisor.assess("review")
    assert result["verify_score"] is None
    assert result["route"] == "fast"


@pytest.mark.asyncio
async def test_non_finite_json_from_metis_is_rejected():
    advisor = MetisAdvisor(
        api_key="test-key",
        transport=_transport(
            content=(
                b'{"status":"success","verified":true,"verify_performed":true,'
                b'"verify_score":Infinity}'
            )
        ),
    )
    assert (await advisor.assess("review"))["reason"] == "metis_invalid_json"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "body", "content", "expected"),
    [
        (401, {}, None, "unavailable"),
        (200, None, b"not-json", "failed"),
        (200, ["wrong"], None, "failed"),
        (200, {"status": "error"}, None, "failed"),
        (200, {"status": "error", "error": "timeout"}, None, "timeout"),
        (
            200,
            {"status": "success", "verified": False, "verify_performed": False, "answer": "x"},
            None,
            "not_performed",
        ),
    ],
)
async def test_metis_failures_are_allowlisted(status, body, content, expected):
    advisor = MetisAdvisor(api_key="test-key", transport=_transport(status, body, content))
    assert (await advisor.assess("review"))["status"] == expected


@pytest.mark.asyncio
async def test_oversized_metis_response_is_rejected():
    advisor = MetisAdvisor(
        api_key="test-key", transport=_transport(content=b"x" * 262_145)
    )
    result = await advisor.assess("review")
    assert result == {"status": "failed", "reason": "metis_response_too_large"}


@pytest.mark.asyncio
async def test_transport_and_timeout_errors_are_hidden():
    async def timeout(_: httpx.Request):
        raise httpx.ReadTimeout("secret upstream details")

    async def broken(_: httpx.Request):
        raise httpx.ConnectError("secret host details")

    timed = MetisAdvisor(api_key="test-key", transport=httpx.MockTransport(timeout))
    failed = MetisAdvisor(api_key="test-key", transport=httpx.MockTransport(broken))
    assert (await timed.assess("x"))["reason"] == "metis_timeout"
    assert (await failed.assess("x"))["reason"] == "metis_transport_error"


@pytest.mark.asyncio
async def test_disabled_advisor_and_queue_do_not_create_jobs():
    advisor = MetisAdvisor(api_key="")
    assert await advisor.assess("x") == {"status": "unavailable", "reason": "metis_not_configured"}
    queue = VerificationQueue(advisor)
    assert await queue.submit("x") == {"status": "unavailable", "reason": "metis_not_configured"}


@pytest.mark.asyncio
async def test_lazy_queue_moves_from_pending_to_completed():
    started = asyncio.Event()
    release = asyncio.Event()

    class FakeAdvisor:
        enabled = True

        async def assess(self, prompt):
            assert prompt == "bounded report"
            started.set()
            await release.wait()
            return {"status": "completed", "assessment_verified": True}

    queue = VerificationQueue(FakeAdvisor(), max_jobs=2)
    pending = await queue.submit("bounded report")
    assert pending["status"] == "pending"
    await started.wait()
    assert (await queue.get(pending["verification_id"]))["status"] == "pending"
    release.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert (await queue.get(pending["verification_id"]))["status"] == "completed"
    await queue.close()


@pytest.mark.asyncio
async def test_queue_is_bounded_and_expires_jobs():
    now = [100.0]
    release = asyncio.Event()

    class FakeAdvisor:
        enabled = True

        async def assess(self, _):
            await release.wait()
            return {"status": "completed"}

    queue = VerificationQueue(FakeAdvisor(), max_jobs=1, ttl_seconds=30, clock=lambda: now[0])
    first = await queue.submit("one")
    assert (await queue.submit("two"))["reason"] == "verification_queue_full"
    now[0] = 131.0
    assert await queue.get(first["verification_id"]) is None
    assert (await queue.submit("two"))["reason"] == "verification_queue_full"
    release.set()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    second = await queue.submit("two")
    assert second["status"] == "pending"
    await queue.close()


@pytest.mark.asyncio
async def test_queue_limits_concurrent_metis_calls():
    active = 0
    peak = 0
    two_started = asyncio.Event()
    release = asyncio.Event()

    class FakeAdvisor:
        enabled = True

        async def assess(self, _):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            if active == 2:
                two_started.set()
            await release.wait()
            active -= 1
            return {"status": "completed"}

    queue = VerificationQueue(FakeAdvisor(), max_jobs=4, max_concurrent=2)
    jobs = [await queue.submit(str(index)) for index in range(4)]
    assert all(job["status"] == "pending" for job in jobs)
    await two_started.wait()
    assert peak == 2
    release.set()
    await queue.close()


@pytest.mark.asyncio
async def test_queue_hides_unexpected_errors_and_cancel_state():
    class BrokenAdvisor:
        enabled = True

        async def assess(self, _):
            raise RuntimeError("secret")

    queue = VerificationQueue(BrokenAdvisor())
    job = await queue.submit("x")
    await asyncio.sleep(0)
    state = await queue.get(job["verification_id"])
    assert state["reason"] == "verification_internal_error"
    await queue.close()


def test_configuration_bounds_and_rejects_unsafe_urls(monkeypatch):
    assert _bounded_int("bad", 7, 1, 9) == 7
    assert _bounded_int("100", 7, 1, 9) == 9
    assert _bounded_float("bad", 7.0, 1.0, 9.0) == 7.0
    assert _bounded_float("-1", 7.0, 1.0, 9.0) == 1.0
    with pytest.raises(ValueError):
        MetisAdvisor(api_key="x", base_url="http://example.com")
    with pytest.raises(ValueError):
        MetisAdvisor(api_key="x", base_url="https://example.com:99999")
    with pytest.raises(ValueError):
        MetisAdvisor(api_key="x", base_url="relative")
    with pytest.raises(ValueError):
        MetisAdvisor(api_key="x", base_url="https://user:pass@example.com")
    with pytest.raises(ValueError):
        MetisAdvisor(api_key="x", route="magic")
    monkeypatch.setenv("METIS_API_KEY", "env-key")
    monkeypatch.setenv("METIS_URL", "http://127.0.0.1:9999")
    monkeypatch.setenv("METIS_ROUTE", "council")
    assert MetisAdvisor.from_env().route == "council"
