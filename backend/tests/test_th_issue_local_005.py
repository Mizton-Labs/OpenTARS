"""
Tests for issue-local-005:
  - DB schema v4 (run_id columns on hunt_reports + task_results)
  - Migration from v3 → v4 (ALTER + backfill)
  - Runner: new run per start_generation; no overwrite; concurrent runs of
    the same package are allowed (issue-local-014 removed the old
    sequential/one-active-run-per-package guard)
  - Runner: _save_generation_state writes by run_id not hunt_package_id
  - Per-hunt model selection threads through start_generation
  - report_writer scopes results to run_id
  - API: GET /runs, run-scoped status/approve/reject/results/report
  - Legacy back-compat routes still work (resolve to latest run)
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

# ── DB schema v4 ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_db_v4_fresh_has_run_id_columns(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

    conn = sqlite3.connect(db_path)
    report_cols = {row[1] for row in conn.execute("PRAGMA table_info(hunt_reports)")}
    result_cols = {row[1] for row in conn.execute("PRAGMA table_info(task_results)")}
    version = conn.execute("SELECT version FROM th_schema_version LIMIT 1").fetchone()[0]
    conn.close()

    assert "run_id" in report_cols, "hunt_reports must have run_id"
    assert "run_id" in result_cols, "task_results must have run_id"
    assert version == th_db._TH_SCHEMA_VERSION


@pytest.mark.asyncio
async def test_db_v4_migration_from_v3(tmp_path: Path) -> None:
    """A v3 schema must gain run_id columns after v4 migration."""
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th_v3.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE th_schema_version (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO th_schema_version VALUES (3)")
    conn.execute(
        """CREATE TABLE hunt_packages (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '',
            status TEXT DEFAULT 'draft', created_by TEXT, created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE hunting_packages (
            id TEXT PRIMARY KEY, hunt_package_id TEXT NOT NULL,
            threat_context TEXT, hypotheses TEXT, hunting_leads TEXT,
            deep_retrohunt TEXT, ttp_analysis TEXT, query_drafts TEXT,
            llm_provider TEXT, llm_model TEXT, generation_status TEXT,
            generation_errors TEXT, created_at TEXT NOT NULL,
            current_step TEXT, completed_steps TEXT, step_logs TEXT, research_effort TEXT)"""
    )
    conn.execute(
        """CREATE TABLE task_results (
            id TEXT PRIMARY KEY, hunt_package_id TEXT NOT NULL,
            task_type TEXT NOT NULL, siem_connector TEXT,
            query_text TEXT, earliest TEXT, latest TEXT, hunt_id TEXT,
            status TEXT NOT NULL, raw_result TEXT, interpreted_findings TEXT,
            confidence REAL, created_at TEXT NOT NULL, completed_at TEXT)"""
    )
    conn.execute(
        """CREATE TABLE hunt_reports (
            id TEXT PRIMARY KEY, hunt_package_id TEXT NOT NULL,
            executive_summary TEXT, full_report TEXT,
            created_at TEXT NOT NULL, created_by TEXT)"""
    )
    conn.commit()
    conn.close()

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

    conn = sqlite3.connect(db_path)
    report_cols = {row[1] for row in conn.execute("PRAGMA table_info(hunt_reports)")}
    result_cols = {row[1] for row in conn.execute("PRAGMA table_info(task_results)")}
    version = conn.execute("SELECT version FROM th_schema_version LIMIT 1").fetchone()[0]
    conn.close()

    assert "run_id" in report_cols
    assert "run_id" in result_cols
    assert version == th_db._TH_SCHEMA_VERSION


# ── DB CRUD helpers ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_generation_runs_empty(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        runs = await th_db.list_generation_runs("no-such-pkg")
    assert runs == []


@pytest.mark.asyncio
async def test_get_generation_run_by_id(tmp_path: Path) -> None:
    """get_generation_run returns a specific row by its id."""
    import uuid

    import aiosqlite

    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        run_id = str(uuid.uuid4())
        pkg_id = str(uuid.uuid4())
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                """INSERT INTO hunting_packages
                   (id, hunt_package_id, generation_status, created_at)
                   VALUES (?,?,?,?)""",
                (run_id, pkg_id, "completed", "2026-01-01T00:00:00+00:00"),
            )
            await db.commit()

        row = await th_db.get_generation_run(run_id)
        assert row is not None
        assert row["id"] == run_id
        assert row["hunt_package_id"] == pkg_id


@pytest.mark.asyncio
async def test_task_result_stores_run_id(tmp_path: Path) -> None:
    import uuid

    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        # need a hunt_packages row to satisfy FK
        async with __import__("aiosqlite").connect(db_path) as db:
            await db.execute(
                "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) VALUES (?,?,?,?,?,?)",
                (
                    pkg_id,
                    "test",
                    "",
                    "draft",
                    "2026-01-01T00:00:00+00:00",
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            await db.commit()

        result = await th_db.create_task_result(pkg_id, task_type="retrohunt", run_id=run_id)
        assert result["run_id"] == run_id

        by_run = await th_db.list_task_results_by_run(run_id)
        assert len(by_run) == 1
        assert by_run[0]["id"] == result["id"]


@pytest.mark.asyncio
async def test_hunt_report_stores_run_id_and_get_by_run(tmp_path: Path) -> None:
    import uuid

    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        async with __import__("aiosqlite").connect(db_path) as db:
            await db.execute(
                "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) VALUES (?,?,?,?,?,?)",
                (
                    pkg_id,
                    "test",
                    "",
                    "completed",
                    "2026-01-01T00:00:00+00:00",
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            await db.commit()

        report = await th_db.create_hunt_report(
            pkg_id,
            executive_summary="summary",
            full_report={"hunt_name": "test"},
            run_id=run_id,
        )
        assert report["run_id"] == run_id

        by_run = await th_db.get_hunt_report_by_run(run_id)
        assert by_run is not None
        assert by_run["run_id"] == run_id


# ── Runner: no overwrite, independent runs ────────────────────────────────────


@pytest.mark.asyncio
async def test_start_generation_creates_new_row_each_time(tmp_path: Path) -> None:
    """Two start_generation calls on the same pkg_id create two distinct rows."""
    import uuid

    import aiosqlite

    from backend.threat_hunting import db as th_db
    from backend.threat_hunting.agents import runner

    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())

    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        # Stub out the actual LangGraph pipeline so it doesn't run
        patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
    ):
        mock_task.return_value = object()  # dummy task handle
        await th_db.init_threat_hunting_db()

        # Seed a hunt_packages row
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) VALUES (?,?,?,?,?,?)",
                (
                    pkg_id,
                    "test",
                    "",
                    "draft",
                    "2026-01-01T00:00:00+00:00",
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            await db.commit()

        # First run
        result1 = await runner.start_generation(pkg_id)
        run_id_1 = result1["run_id"]
        # Persist via _save_generation_state (normally done by _run_pipeline)
        await runner._save_generation_state(run_id_1, pkg_id, {}, status="completed")

        # Clear _ACTIVE_JOBS/_ACTIVE_RUN_PKG to simulate the first run finishing
        runner._ACTIVE_JOBS.clear()
        runner._ACTIVE_RUN_PKG.clear()

        # Second run
        result2 = await runner.start_generation(pkg_id)
        run_id_2 = result2["run_id"]
        await runner._save_generation_state(run_id_2, pkg_id, {}, status="running")

    # Both runs must have distinct IDs
    assert run_id_1 != run_id_2

    # Two separate hunting_packages rows must exist (no overwrite)
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT id FROM hunting_packages WHERE hunt_package_id=?", (pkg_id,)
    ).fetchall()
    conn.close()
    assert len(rows) == 2, f"Expected 2 rows but got {len(rows)}: {[r[0] for r in rows]}"


@pytest.mark.asyncio
async def test_start_generation_allows_concurrent_runs(tmp_path: Path) -> None:
    """issue-local-014: starting a new run while one is active creates an
    independent second run rather than returning the already-active one —
    the re-run button must work at any time, including mid-run."""
    import uuid

    import aiosqlite

    from backend.threat_hunting import db as th_db
    from backend.threat_hunting.agents import runner

    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())

    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
    ):
        mock_task.return_value = object()
        await th_db.init_threat_hunting_db()

        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) VALUES (?,?,?,?,?,?)",
                (
                    pkg_id,
                    "test",
                    "",
                    "draft",
                    "2026-01-01T00:00:00+00:00",
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            await db.commit()

        result1 = await runner.start_generation(pkg_id)
        run_id_1 = result1["run_id"]
        # create_task is mocked (pipeline never actually runs) — persist the
        # row manually, as _run_pipeline would have done on its first step.
        await runner._save_generation_state(run_id_1, pkg_id, {}, status="running")

        # First run still registered as active — the second call must NOT
        # short-circuit to it; it must create a brand-new, distinct run.
        assert pkg_id in runner._ACTIVE_RUN_PKG.values()
        result2 = await runner.start_generation(pkg_id)
        run_id_2 = result2["run_id"]
        await runner._save_generation_state(run_id_2, pkg_id, {}, status="running")

        assert run_id_2 != run_id_1
        assert pkg_id in runner._ACTIVE_RUN_PKG.values()
        assert list(runner._ACTIVE_RUN_PKG.values()).count(pkg_id) == 2

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT id FROM hunting_packages WHERE hunt_package_id=?", (pkg_id,)
    ).fetchall()
    conn.close()
    assert len(rows) == 2, f"Expected 2 rows but got {len(rows)}: {[r[0] for r in rows]}"


@pytest.mark.asyncio
async def test_start_generation_model_stored(tmp_path: Path) -> None:
    """provider_name/model_name passed to start_generation end up in the run record."""
    import uuid

    import aiosqlite

    from backend.threat_hunting import db as th_db
    from backend.threat_hunting.agents import runner

    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())

    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
    ):
        mock_task.return_value = object()
        await th_db.init_threat_hunting_db()

        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) VALUES (?,?,?,?,?,?)",
                (
                    pkg_id,
                    "test",
                    "",
                    "draft",
                    "2026-01-01T00:00:00+00:00",
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            await db.commit()

        result = await runner.start_generation(
            pkg_id,
            provider_name="azure-ai-foundry-claude",
            model_name="claude-opus-4-8",
        )
        run_id = result["run_id"]

        # Save the initial state so the row exists
        await runner._save_generation_state(
            run_id,
            pkg_id,
            {
                "provider_name": "azure-ai-foundry-claude",
                "model_name": "claude-opus-4-8",
                "research_effort": "medium",
            },
            status="running",
        )
        row = await th_db.get_generation_run(run_id)

    assert row is not None
    assert row.get("llm_provider") == "azure-ai-foundry-claude"
    assert row.get("llm_model") == "claude-opus-4-8"


# ── API routes ────────────────────────────────────────────────────────────────


def _test_client():
    from fastapi.testclient import TestClient

    from backend.main import app

    return TestClient(app)


@pytest.mark.asyncio
async def test_api_list_runs_empty(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th_api.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        import uuid

        pkg_id = str(uuid.uuid4())
        async with __import__("aiosqlite").connect(db_path) as db:
            await db.execute(
                "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) VALUES (?,?,?,?,?,?)",
                (
                    pkg_id,
                    "test",
                    "",
                    "draft",
                    "2026-01-01T00:00:00+00:00",
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            await db.commit()

        client = _test_client()
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            r = client.get(f"/api/threat-hunting/packages/{pkg_id}/runs")
        assert r.status_code == 200
        assert r.json() == []


def test_api_run_status_404_unknown_package() -> None:
    """Run-scoped status returns 404 when the hunt package itself doesn't exist."""
    import uuid

    from fastapi.testclient import TestClient

    from backend.main import app

    client = TestClient(app)
    r = client.get(f"/api/threat-hunting/packages/{uuid.uuid4()}/runs/{uuid.uuid4()}/status")
    # The route first calls _pkg_or_404 → 404
    assert r.status_code == 404
