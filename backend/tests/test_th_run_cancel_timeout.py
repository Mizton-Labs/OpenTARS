"""
Tests for issue-local-019's run cancellation and stalled-run timeout
handling in backend/threat_hunting/agents/runner.py.
"""

from __future__ import annotations

import asyncio
import sqlite3
import uuid
from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents import runner


async def _seed_package(db_path: Path, pkg_id: str) -> None:
    await th_db.init_threat_hunting_db()
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) VALUES (?,?,?,?,?,?)",
            (pkg_id, "test", "", "draft", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        )
        await db.commit()


def _status(db_path: Path, run_id: str) -> str:
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT generation_status FROM hunting_packages WHERE id=?", (run_id,)
    ).fetchone()
    conn.close()
    assert row is not None
    return row[0]


def _errors(db_path: Path, run_id: str) -> str:
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT generation_errors FROM hunting_packages WHERE id=?", (run_id,)
    ).fetchone()
    conn.close()
    return row[0] if row else ""


class _HangingGraph:
    """Stub compiled-graph whose astream() never yields — simulates a node
    stuck on an unresponsive LLM/fetch call."""

    def astream(self, _initial_state):
        async def _gen():
            await asyncio.sleep(1000)
            yield {}  # pragma: no cover — unreachable, keeps this an async generator

        return _gen()


@pytest.mark.asyncio
async def test_cancel_generation_raises_for_unknown_run(tmp_path: Path) -> None:
    with patch.object(th_db, "_TH_DB_PATH", tmp_path / "th.db"):
        await th_db.init_threat_hunting_db()
        with pytest.raises(ValueError, match="No generation run found"):
            await runner.cancel_generation("nonexistent-run-id")


@pytest.mark.asyncio
async def test_cancel_generation_raises_when_not_running(tmp_path: Path) -> None:
    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await _seed_package(db_path, pkg_id)
        await runner._save_generation_state(run_id, pkg_id, {}, status="completed")
        with pytest.raises(ValueError, match="not currently running"):
            await runner.cancel_generation(run_id)


@pytest.mark.asyncio
async def test_cancel_generation_orphaned_run_directly_marks_cancelled(tmp_path: Path) -> None:
    """No live task in _ACTIVE_JOBS (e.g. after a restart) — cancel_generation
    must still resolve the stale 'running' status rather than erroring out."""
    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
    ):
        await _seed_package(db_path, pkg_id)
        await runner._save_generation_state(run_id, pkg_id, {}, status="running")

        result = await runner.cancel_generation(run_id)

    assert result["generation_status"] == "cancelled"
    assert _status(db_path, run_id) == "cancelled"
    assert "orphaned by a server restart" in _errors(db_path, run_id)


@pytest.mark.asyncio
async def test_cancel_generation_live_task_is_actually_cancelled(tmp_path: Path) -> None:
    """The realistic path: a task is genuinely hung (e.g. mid LLM call) and
    tracked in _ACTIVE_JOBS. cancel_generation() must interrupt it and the
    pipeline's own CancelledError handler must persist status='cancelled'."""
    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch(
            "backend.threat_hunting.agents.pipeline.get_compiled_graph",
            return_value=_HangingGraph(),
        ),
    ):
        await _seed_package(db_path, pkg_id)

        task = asyncio.create_task(
            runner._run_pipeline(run_id, pkg_id, {"hunt_package_id": pkg_id})
        )
        runner._ACTIVE_JOBS[run_id] = task
        # Let the task start and reach the (hanging) astream await point.
        await asyncio.sleep(0.05)
        assert _status(db_path, run_id) == "running"

        result = await runner.cancel_generation(run_id)
        assert result["generation_status"] == "cancelling"

        with pytest.raises(asyncio.CancelledError):
            await task

    assert _status(db_path, run_id) == "cancelled"
    assert "Cancelled by operator" in _errors(db_path, run_id)
    assert run_id not in runner._CANCEL_REQUESTED


@pytest.mark.asyncio
async def test_route_cancel_run_404_for_unknown_package(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app

    with patch.object(th_db, "_TH_DB_PATH", tmp_path / "th.db"):
        await th_db.init_threat_hunting_db()
        client = TestClient(app)
        resp = client.post("/api/threat-hunting/packages/no-such-pkg/runs/run-1/cancel")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_route_cancel_run_400_when_not_running(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("pkg", "")
        run_id = str(uuid.uuid4())
        await runner._save_generation_state(run_id, pkg["id"], {}, status="completed")

        client = TestClient(app)
        resp = client.post(f"/api/threat-hunting/packages/{pkg['id']}/runs/{run_id}/cancel")
        assert resp.status_code == 400
        assert "not currently running" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_route_cancel_run_success(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app

    db_path = tmp_path / "th.db"
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
    ):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("pkg", "")
        run_id = str(uuid.uuid4())
        await runner._save_generation_state(run_id, pkg["id"], {}, status="running")

        client = TestClient(app)
        resp = client.post(f"/api/threat-hunting/packages/{pkg['id']}/runs/{run_id}/cancel")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["generation_status"] == "cancelled"
        assert _status(db_path, run_id) == "cancelled"


@pytest.mark.asyncio
async def test_stalled_node_times_out_and_marks_run_errored(tmp_path: Path) -> None:
    """A node that never returns (e.g. an unresponsive LLM/fetch backend)
    must not hang the run forever — it should time out and mark the run
    'error' with a clear reason, rather than staying 'running' indefinitely."""
    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch.object(runner, "_node_timeout_seconds", return_value=0.05),
        patch(
            "backend.threat_hunting.agents.pipeline.get_compiled_graph",
            return_value=_HangingGraph(),
        ),
    ):
        await _seed_package(db_path, pkg_id)

        await runner._run_pipeline(run_id, pkg_id, {"hunt_package_id": pkg_id})

    assert _status(db_path, run_id) == "error"
    assert "timed out after 0.05s" in _errors(db_path, run_id)
    assert run_id not in runner._ACTIVE_JOBS
