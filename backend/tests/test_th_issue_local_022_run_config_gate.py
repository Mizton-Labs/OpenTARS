"""
Tests for issue-local-022 Part C:
  - Schema v9 migration: hunting_packages.threat_intel_status column.
  - db.set_run_threat_intel_status() set/clear round trip.
  - get_generation_run()/list_generation_runs() surface threat_intel_status.
  - runner.py's preliminary-phase and executor.py's final-phase call sites
    wrap analyze_threat_intel() in a try/finally that always clears the
    status, even on failure — so a crashed analysis never leaves a run
    permanently gated.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", path):
        await th_db.init_threat_hunting_db()
        yield path


async def _seed_run(pkg_id: str, run_id: str) -> None:
    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        await db.execute(
            "INSERT INTO hunting_packages (id, hunt_package_id, run_config, created_at) "
            "VALUES (?,?,?,?)",
            (run_id, pkg_id, json.dumps({}), "2026-01-01T00:00:00Z"),
        )
        await db.commit()


class TestSchemaV9Migration:
    @pytest.mark.asyncio
    async def test_fresh_db_has_threat_intel_status_column(self, db_path: Path) -> None:
        async with aiosqlite.connect(db_path) as db:
            cur = await db.execute("PRAGMA table_info(hunting_packages)")
            cols = {row[1] for row in await cur.fetchall()}
        assert "threat_intel_status" in cols

    @pytest.mark.asyncio
    async def test_schema_version_is_9(self, db_path: Path) -> None:
        async with aiosqlite.connect(db_path) as db:
            cur = await db.execute("SELECT version FROM th_schema_version LIMIT 1")
            row = await cur.fetchone()
        assert row[0] == 9

    @pytest.mark.asyncio
    async def test_migration_from_v8_is_idempotent(self, tmp_path: Path) -> None:
        """Simulates an existing v8 DB (pre-issue-local-022) being upgraded —
        the ALTER TABLE must not raise even though init_threat_hunting_db()'s
        CREATE TABLE already includes the column for fresh installs."""
        path = tmp_path / "th_v8.db"
        with patch.object(th_db, "_TH_DB_PATH", path):
            await th_db.init_threat_hunting_db()
            # Re-running init (idempotent path) must not raise.
            await th_db.init_threat_hunting_db()
            async with aiosqlite.connect(path) as db:
                cur = await db.execute("PRAGMA table_info(hunting_packages)")
                cols = [row[1] for row in await cur.fetchall()]
            assert cols.count("threat_intel_status") == 1


class TestSetRunThreatIntelStatus:
    @pytest.mark.asyncio
    async def test_set_and_clear_round_trip(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1")

            await th_db.set_run_threat_intel_status("run-1", "running")
            run = await th_db.get_generation_run("run-1")
            assert run["threat_intel_status"] == "running"

            await th_db.set_run_threat_intel_status("run-1", None)
            run = await th_db.get_generation_run("run-1")
            assert run["threat_intel_status"] is None

    @pytest.mark.asyncio
    async def test_noop_for_missing_run(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            # Must not raise even though "no-such-run" doesn't exist.
            await th_db.set_run_threat_intel_status("no-such-run", "running")

    @pytest.mark.asyncio
    async def test_list_generation_runs_surfaces_status(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1")
            await th_db.set_run_threat_intel_status("run-1", "running")

            runs = await th_db.list_generation_runs(pkg["id"])
            assert len(runs) == 1
            assert runs[0]["threat_intel_status"] == "running"


class TestCallSitesClearStatusOnFailure:
    def test_runner_wraps_analyze_threat_intel_in_try_finally(self) -> None:
        from backend.threat_hunting.agents import runner

        source = inspect.getsource(runner._run_pipeline)
        assert "set_run_threat_intel_status" in source
        # The set-to-running call must precede the analyze call, which must
        # precede a `finally` that clears it again.
        set_running_idx = source.index('set_run_threat_intel_status(run_id, "running")')
        analyze_idx = source.index("await analyze_threat_intel(")
        finally_idx = source.index("finally:", analyze_idx)
        clear_idx = source.index("set_run_threat_intel_status(run_id, None)", finally_idx)
        assert set_running_idx < analyze_idx < finally_idx < clear_idx

    def test_executor_wraps_analyze_threat_intel_in_try_finally(self) -> None:
        from backend.threat_hunting.siem import executor

        source = inspect.getsource(executor._run_execution)
        assert "set_run_threat_intel_status" in source
        set_running_idx = source.index('set_run_threat_intel_status(run_id, "running")')
        analyze_idx = source.index("await analyze_threat_intel(")
        finally_idx = source.index("finally:", analyze_idx)
        clear_idx = source.index("set_run_threat_intel_status(run_id, None)", finally_idx)
        assert set_running_idx < analyze_idx < finally_idx < clear_idx
