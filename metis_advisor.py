from __future__ import annotations

import asyncio
import json
import math
import os
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx

MAX_METIS_RESPONSE_BYTES = 262_144


def _bounded_float(raw: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _bounded_int(raw: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _safe_service_url(raw: str) -> str:
    try:
        url = urlsplit(raw.strip())
        _ = url.port
    except ValueError as exc:
        raise ValueError(f"METIS_URL is malformed: {exc}") from exc
    if url.scheme not in {"http", "https"} or not url.hostname:
        raise ValueError("METIS_URL must be an absolute HTTP(S) URL")
    if url.username or url.password or url.query or url.fragment:
        raise ValueError("METIS_URL must not contain credentials, query parameters, or fragments")
    if url.scheme != "https" and url.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("METIS_URL must use HTTPS unless it is loopback development")
    return raw.strip().rstrip("/")


class MetisAdvisor:
    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = "https://metis.modelmarket.dev",
        route: str = "fast",
        timeout_seconds: float = 620.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.api_key = api_key.strip()
        self.base_url = _safe_service_url(base_url)
        self.route = route.strip().lower()
        if self.route not in {"fast", "thinking", "council"}:
            raise ValueError("METIS_ROUTE must be fast, thinking, or council")
        self.timeout_seconds = max(3.0, min(float(timeout_seconds), 620.0))
        self.transport = transport

    @classmethod
    def from_env(cls) -> "MetisAdvisor":
        return cls(
            api_key=os.getenv("METIS_API_KEY", ""),
            base_url=os.getenv("METIS_URL", "https://metis.modelmarket.dev"),
            route=os.getenv("METIS_ROUTE", "fast"),
            timeout_seconds=_bounded_float(
                os.getenv("METIS_TIMEOUT_SECONDS", "620"), 620.0, 3.0, 620.0
            ),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def assess(self, prompt: str) -> dict[str, Any]:
        if not self.enabled:
            return {"status": "unavailable", "reason": "metis_not_configured"}
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/v1/verify",
                    headers=headers,
                    json={"input": prompt, "route": self.route},
                ) as response:
                    declared_size = response.headers.get("content-length")
                    if declared_size is not None:
                        try:
                            if int(declared_size) > MAX_METIS_RESPONSE_BYTES:
                                return {"status": "failed", "reason": "metis_response_too_large"}
                        except ValueError:
                            return {"status": "failed", "reason": "metis_invalid_content_length"}
                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        content.extend(chunk)
                        if len(content) > MAX_METIS_RESPONSE_BYTES:
                            return {"status": "failed", "reason": "metis_response_too_large"}
                    status_code = response.status_code
        except httpx.TimeoutException:
            return {"status": "timeout", "reason": "metis_timeout"}
        except httpx.HTTPError:
            return {"status": "unavailable", "reason": "metis_transport_error"}
        if status_code >= 400:
            return {
                "status": "unavailable",
                "reason": "metis_http_error",
                "http_status": status_code,
            }
        try:
            body = json.loads(
                content,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"non-finite JSON number: {value}")
                ),
            )
        except (UnicodeDecodeError, ValueError):
            return {"status": "failed", "reason": "metis_invalid_json"}
        if not isinstance(body, dict):
            return {"status": "failed", "reason": "metis_invalid_envelope"}

        status = str(body.get("status") or "error")
        if status != "success":
            reason = "metis_timeout" if body.get("error") == "timeout" else "metis_error"
            return {"status": "timeout" if reason == "metis_timeout" else "failed", "reason": reason}
        assessment = body.get("answer")
        assessment_text = assessment.strip()[:2_000] if isinstance(assessment, str) else ""
        verified = body.get("verified") is True
        performed = body.get("verify_performed") is True or verified
        score = body.get("verify_score")
        if (
            not performed
            or isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(score)
            or not 0 <= score <= 100
        ):
            score = None
        route = body.get("route")
        if not isinstance(route, str) or route not in {"fast", "thinking", "council"}:
            route = self.route
        return {
            "status": "completed" if performed else "not_performed",
            "assessment_verified": verified,
            "verify_performed": performed,
            "verify_score": score,
            "route": route,
            "assessment": assessment_text,
        }


@dataclass
class _Job:
    created_at: float
    state: dict[str, Any]


class VerificationQueue:
    def __init__(
        self,
        advisor: MetisAdvisor,
        *,
        max_jobs: int = 100,
        max_concurrent: int = 2,
        ttl_seconds: int = 900,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.advisor = advisor
        self.max_jobs = max(1, min(int(max_jobs), 1_000))
        self.max_concurrent = max(1, min(int(max_concurrent), self.max_jobs, 32))
        self.ttl_seconds = max(30, min(int(ttl_seconds), 86_400))
        self.clock = clock
        self._jobs: OrderedDict[str, _Job] = OrderedDict()
        self._tasks: set[asyncio.Task] = set()
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._lock = asyncio.Lock()

    @classmethod
    def from_env(cls) -> "VerificationQueue":
        return cls(
            MetisAdvisor.from_env(),
            max_jobs=_bounded_int(os.getenv("METIS_MAX_JOBS", "100"), 100, 1, 1_000),
            max_concurrent=_bounded_int(
                os.getenv("METIS_MAX_CONCURRENT", "2"), 2, 1, 32
            ),
            ttl_seconds=_bounded_int(
                os.getenv("METIS_JOB_TTL_SECONDS", "900"), 900, 30, 86_400
            ),
        )

    def _prune_locked(self) -> None:
        cutoff = self.clock() - self.ttl_seconds
        expired = [job_id for job_id, job in self._jobs.items() if job.created_at < cutoff]
        for job_id in expired:
            self._jobs.pop(job_id, None)

    @staticmethod
    def _public(job_id: str, state: dict[str, Any]) -> dict[str, Any]:
        return {"verification_id": job_id, **state, "poll_url": f"/verification/{job_id}"}

    async def submit(self, prompt: str) -> dict[str, Any]:
        if not self.advisor.enabled:
            return {"status": "unavailable", "reason": "metis_not_configured"}
        async with self._lock:
            self._prune_locked()
            # Expired status records must not let still-running tasks bypass the
            # hard process bound.
            if len(self._jobs) >= self.max_jobs or len(self._tasks) >= self.max_jobs:
                return {"status": "unavailable", "reason": "verification_queue_full"}
            job_id = secrets.token_urlsafe(18)
            state = {"status": "pending"}
            self._jobs[job_id] = _Job(self.clock(), state)
            task = asyncio.create_task(self._run(job_id, prompt))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
            return self._public(job_id, state)

    async def _run(self, job_id: str, prompt: str) -> None:
        try:
            async with self._semaphore:
                result = await self.advisor.assess(prompt)
        except asyncio.CancelledError:
            result = {"status": "failed", "reason": "verification_cancelled"}
        except Exception:
            result = {"status": "failed", "reason": "verification_internal_error"}
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.state = result

    async def get(self, job_id: str) -> dict[str, Any] | None:
        async with self._lock:
            self._prune_locked()
            job = self._jobs.get(job_id)
            return self._public(job_id, dict(job.state)) if job else None

    async def close(self) -> None:
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
