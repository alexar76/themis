from __future__ import annotations

import asyncio
import sqlite3

import pytest

from metis_advisor import (
    MemoryJobStore,
    SqliteJobStore,
    VerificationQueue,
    build_job_store,
)


class _Advisor:
    enabled = True

    def __init__(self, result=None):
        self.result = result or {"status": "completed", "assessment_verified": True}

    async def assess(self, prompt):
        return self.result


@pytest.mark.asyncio
async def test_a_second_replica_can_serve_a_poll_it_never_accepted(tmp_path):
    """The published gap: in-memory job state 404s behind a load balancer."""
    db = str(tmp_path / "jobs.sqlite3")
    accepting = VerificationQueue(_Advisor(), store=SqliteJobStore(db))
    polling = VerificationQueue(_Advisor(), store=SqliteJobStore(db))

    submitted = await accepting.submit("bounded report")
    assert submitted["status"] == "pending"
    for _ in range(50):
        state = await polling.get(submitted["verification_id"])
        if state and state["status"] == "completed":
            break
        await asyncio.sleep(0.01)

    seen = await polling.get(submitted["verification_id"])
    assert seen is not None, "a shared store must be readable from another replica"
    assert seen["status"] == "completed"
    assert seen["poll_url"].endswith(submitted["verification_id"])
    await accepting.close()
    await polling.close()


@pytest.mark.asyncio
async def test_memory_store_still_isolates_replicas(tmp_path):
    accepting = VerificationQueue(_Advisor(), store=MemoryJobStore())
    polling = VerificationQueue(_Advisor(), store=MemoryJobStore())
    submitted = await accepting.submit("x")
    assert await polling.get(submitted["verification_id"]) is None
    await accepting.close()
    await polling.close()


def test_memory_store_is_refused_for_multiple_replicas():
    with pytest.raises(RuntimeError, match="THEMIS_REPLICAS"):
        build_job_store(kind="memory", replicas=2)


def test_store_selection_is_explicit_and_validated(tmp_path):
    path = str(tmp_path / "nested" / "jobs.sqlite3")
    chosen = build_job_store(path=path, replicas=4)
    assert (chosen.kind, chosen.shared) == ("sqlite", True)
    chosen.close()
    single = build_job_store()
    assert (single.kind, single.shared) == ("memory", False)
    with pytest.raises(ValueError, match="memory or sqlite"):
        build_job_store(kind="redis")


def test_from_env_picks_the_shared_store(monkeypatch, tmp_path):
    monkeypatch.setenv("METIS_JOB_DB", str(tmp_path / "env.sqlite3"))
    monkeypatch.setenv("THEMIS_REPLICAS", "3")
    queue = VerificationQueue.from_env()
    assert queue.store.kind == "sqlite"
    queue.store.close()


def test_from_env_fails_closed_when_replicas_have_no_shared_store(monkeypatch):
    monkeypatch.delenv("METIS_JOB_DB", raising=False)
    monkeypatch.setenv("THEMIS_REPLICAS", "2")
    with pytest.raises(RuntimeError):
        VerificationQueue.from_env()


def test_shared_store_expires_jobs_on_wall_clock(tmp_path):
    store = SqliteJobStore(str(tmp_path / "ttl.sqlite3"))
    store.insert("keep", store.now(), {"status": "pending"})
    store.insert("drop", store.now() - 10_000, {"status": "pending"})
    store.prune(store.now() - 900)
    assert store.fetch("keep") == {"status": "pending"}
    assert store.fetch("drop") is None
    assert store.count() == 1
    store.close()


def test_shared_store_survives_a_corrupted_row(tmp_path):
    path = str(tmp_path / "corrupt.sqlite3")
    store = SqliteJobStore(path)
    store.insert("job", store.now(), {"status": "pending"})
    raw = sqlite3.connect(path)
    raw.execute("UPDATE metis_jobs SET state = ? WHERE job_id = ?", ("{not json", "job"))
    raw.execute("INSERT INTO metis_jobs VALUES (?,?,?)", ("listy", store.now(), "[1,2]"))
    raw.commit()
    raw.close()
    assert store.fetch("job") is None
    assert store.fetch("listy") is None
    assert store.fetch("absent") is None
    store.close()


@pytest.mark.asyncio
async def test_shared_store_makes_the_job_cap_global(tmp_path):
    db = str(tmp_path / "cap.sqlite3")
    first = VerificationQueue(_Advisor(), max_jobs=1, store=SqliteJobStore(db))
    second = VerificationQueue(_Advisor(), max_jobs=1, store=SqliteJobStore(db))
    assert (await first.submit("a"))["status"] == "pending"
    assert await second.submit("b") == {
        "status": "unavailable",
        "reason": "verification_queue_full",
    }
    await first.close()
    await second.close()


def test_memory_store_update_ignores_unknown_jobs():
    store = MemoryJobStore()
    store.update("missing", {"status": "completed"})
    assert store.fetch("missing") is None
    assert store.count() == 0
