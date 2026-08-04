"""
Tests for issue-local-021's Assess & Compare run picker: compare_runs()'s new
run_ids param, and the /compare route's run_ids passthrough.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents.nodes import comparison_analyst


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", path):
        await th_db.init_threat_hunting_db()
        yield path


async def _seed_run(pkg_id: str, run_id: str, *, created_at: str = "2026-01-01T00:00:00Z") -> None:
    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        await db.execute(
            "INSERT INTO hunting_packages (id, hunt_package_id, threat_context, created_at) "
            "VALUES (?,?,?,?)",
            (run_id, pkg_id, json.dumps({"summary": run_id}), created_at),
        )
        await db.commit()


LLM_RESPONSE = json.dumps(
    {
        "summary": "Runs largely agree.",
        "key_differences": [],
        "gaps": [],
        "enrichment_opportunities": [],
        "recommended_combination": "",
    }
)


class TestCompareRunsRunIdsFilter:
    @pytest.mark.asyncio
    async def test_run_ids_none_compares_all_runs(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", created_at="2026-01-01T00:00:00Z")
            await _seed_run(pkg["id"], "run-2", created_at="2026-01-02T00:00:00Z")

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                result = await comparison_analyst.compare_runs(pkg["id"], run_ids=None)

            assert set(result["full_report"]["compared_run_ids"]) == {"run-1", "run-2"}

    @pytest.mark.asyncio
    async def test_run_ids_narrows_to_subset(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", created_at="2026-01-01T00:00:00Z")
            await _seed_run(pkg["id"], "run-2", created_at="2026-01-02T00:00:00Z")
            await _seed_run(pkg["id"], "run-3", created_at="2026-01-03T00:00:00Z")

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                result = await comparison_analyst.compare_runs(
                    pkg["id"], run_ids=["run-1", "run-3"]
                )

            assert set(result["full_report"]["compared_run_ids"]) == {"run-1", "run-3"}
            assert len(result["full_report"]["diff_table"]) == 2

    @pytest.mark.asyncio
    async def test_run_ids_matching_nothing_raises(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1")

            with pytest.raises(ValueError):
                await comparison_analyst.compare_runs(pkg["id"], run_ids=["no-such-run"])

    @pytest.mark.asyncio
    async def test_route_accepts_run_ids_and_narrows_comparison(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", created_at="2026-01-01T00:00:00Z")
            await _seed_run(pkg["id"], "run-2", created_at="2026-01-02T00:00:00Z")

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                client = TestClient(app)
                resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare",
                    json={"run_ids": ["run-1"]},
                )
                assert resp.status_code == 202, resp.text
                result = await comparison_analyst.compare_runs(pkg["id"], run_ids=["run-1"])
            assert result["full_report"]["compared_run_ids"] == ["run-1"]

    @pytest.mark.asyncio
    async def test_route_omits_run_ids_compares_all(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1")
            await _seed_run(pkg["id"], "run-2")

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                client = TestClient(app)
                resp = client.post(f"/api/threat-hunting/packages/{pkg['id']}/compare", json={})
                assert resp.status_code == 202, resp.text
                result = await comparison_analyst.compare_runs(pkg["id"])
            assert set(result["full_report"]["compared_run_ids"]) == {"run-1", "run-2"}
