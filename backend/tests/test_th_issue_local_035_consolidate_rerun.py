"""Tests for issue-local-035's Recommended Combination actions: consolidated
report snapshot (no new execution) and re-run from recommendation (package
seeding + generation trigger)."""

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


async def _seed_run(
    pkg_id: str,
    run_id: str,
    *,
    deep_retrohunt: dict | None = None,
    generation_status: str = "completed",
    llm_model: str = "gpt-test",
    created_at: str = "2026-01-01T00:00:00Z",
) -> None:
    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        await db.execute(
            "INSERT INTO hunting_packages (id, hunt_package_id, deep_retrohunt, "
            "generation_status, llm_model, created_at) VALUES (?,?,?,?,?,?)",
            (
                run_id,
                pkg_id,
                json.dumps(deep_retrohunt) if deep_retrohunt is not None else None,
                generation_status,
                llm_model,
                created_at,
            ),
        )
        await db.commit()


LLM_RESPONSE = json.dumps(
    {
        "summary": "Runs largely agree.",
        "key_differences": [],
        "gaps": [],
        "enrichment_opportunities": [],
        "recommended_combination": "Combine kept IOCs from both runs.",
    }
)


class TestCreateConsolidatedReport:
    @pytest.mark.asyncio
    async def test_raises_when_no_comparison_exists(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            with pytest.raises(ValueError):
                await th_db.create_consolidated_report(pkg["id"], phase="full")

    @pytest.mark.asyncio
    async def test_snapshots_the_latest_comparison_no_llm_call(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1")
            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                await comparison_analyst.compare_runs(pkg["id"], phase="full")

            # create_consolidated_report itself must never call the LLM.
            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(side_effect=AssertionError("should not be called")),
            ):
                consolidated = await th_db.create_consolidated_report(pkg["id"], phase="full")

            assert consolidated["full_report"]["report_kind"] == "consolidated"
            assert consolidated["full_report"]["phase"] == "full"
            assert consolidated["full_report"]["summary"] == "Runs largely agree."

    @pytest.mark.asyncio
    async def test_consolidated_report_does_not_shadow_normal_report(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1")
            await th_db.create_hunt_report(
                pkg["id"], executive_summary="real report", full_report={"hunt_name": "pkg"}
            )
            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                await comparison_analyst.compare_runs(pkg["id"], phase="full")
            await th_db.create_consolidated_report(pkg["id"], phase="full")

            normal = await th_db.get_hunt_report(pkg["id"])
            assert normal is not None
            assert normal["executive_summary"] == "real report"

    @pytest.mark.asyncio
    async def test_consolidated_and_comparison_are_independent_slots(self, db_path: Path) -> None:
        """Re-running the comparison afterward must not affect the already
        -snapshotted consolidated report."""
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1")
            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                await comparison_analyst.compare_runs(pkg["id"], phase="full")
            await th_db.create_consolidated_report(pkg["id"], phase="full")

            newer_response = json.dumps(
                {
                    "summary": "Updated summary after re-comparing.",
                    "key_differences": [],
                    "gaps": [],
                    "enrichment_opportunities": [],
                    "recommended_combination": "",
                }
            )
            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=newer_response),
            ):
                await comparison_analyst.compare_runs(pkg["id"], phase="full")

            consolidated = await th_db.get_latest_consolidated_report(pkg["id"], phase="full")
            assert consolidated["full_report"]["summary"] == "Runs largely agree."


class TestCreateRerunPackage:
    @pytest.mark.asyncio
    async def test_copies_evidence_and_adds_recommendation_item(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("src pkg", "")
            await th_db.add_evidence_item(
                pkg["id"], item_type="text", label="original", source_ref="x", extracted_text="hi"
            )

            new_pkg = await th_db.create_rerun_package(
                pkg["id"],
                "New Combined Hunt",
                ioc_csv="ioc,ioc_type,ioc_description\nevil.example.com,domain,\n",
                recommendation_text="Merge run 1 and run 2's IOCs.",
            )

            assert new_pkg["name"] == "New Combined Hunt"
            items = await th_db.list_evidence_items(new_pkg["id"])
            labels = {i["label"] for i in items}
            assert "original" in labels
            assert "Recommended combination (from comparison)" in labels
            rec_item = next(i for i in items if i["label"] == "Recommended combination (from comparison)")
            assert "Merge run 1 and run 2's IOCs." in rec_item["extracted_text"]
            assert "evil.example.com" in rec_item["extracted_text"]
            assert rec_item["parse_status"] == "ok"

    @pytest.mark.asyncio
    async def test_original_package_runs_not_copied(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("src pkg", "")
            await th_db.add_evidence_item(pkg["id"], item_type="text", label="x", source_ref="x")
            await _seed_run(pkg["id"], "run-1")

            new_pkg = await th_db.create_rerun_package(
                pkg["id"], "New Hunt", ioc_csv="", recommendation_text=""
            )
            runs = await th_db.list_generation_runs(new_pkg["id"])
            assert runs == []


class TestConsolidateRoute:
    @pytest.mark.asyncio
    async def test_consolidate_route_creates_and_is_downloadable(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1")
            client = TestClient(app)

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                compare_resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare", json={"phase": "full"}
                )
                assert compare_resp.status_code == 202, compare_resp.text
                await comparison_analyst.compare_runs(pkg["id"], phase="full")

            consolidate_resp = client.post(
                f"/api/threat-hunting/packages/{pkg['id']}/compare/consolidate",
                json={"phase": "full"},
            )
            assert consolidate_resp.status_code == 201, consolidate_resp.text
            assert consolidate_resp.json()["full_report"]["report_kind"] == "consolidated"

            get_resp = client.get(
                f"/api/threat-hunting/packages/{pkg['id']}/consolidated?phase=full"
            )
            assert get_resp.status_code == 200

            md_resp = client.get(
                f"/api/threat-hunting/packages/{pkg['id']}/consolidated/markdown?phase=full"
            )
            assert md_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_consolidate_route_404_when_no_comparison(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)
            resp = client.post(
                f"/api/threat-hunting/packages/{pkg['id']}/compare/consolidate",
                json={"phase": "full"},
            )
            assert resp.status_code == 404


class TestRerunRoute:
    @pytest.mark.asyncio
    async def test_rerun_route_creates_package_and_triggers_generation(
        self, db_path: Path
    ) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.add_evidence_item(pkg["id"], item_type="text", label="x", source_ref="x")
            await _seed_run(
                pkg["id"],
                "run-1",
                deep_retrohunt={
                    "sanitized_iocs": [
                        {"ioc": "evil.example.com", "ioc_type": "domain", "action": "keep"}
                    ]
                },
            )
            client = TestClient(app)

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                compare_resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare", json={"phase": "full"}
                )
                assert compare_resp.status_code == 202, compare_resp.text
                await comparison_analyst.compare_runs(pkg["id"], phase="full")

            fake_record = {"id": "new-run-1", "generation_status": "running"}
            with patch(
                "backend.threat_hunting.agents.runner.start_generation",
                new=AsyncMock(return_value=fake_record),
            ):
                rerun_resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare/rerun",
                    json={"phase": "full"},
                )
            assert rerun_resp.status_code == 202, rerun_resp.text
            body = rerun_resp.json()
            assert body["generation"] == fake_record
            assert body["package"]["name"] == "pkg (recommended combination)"

            new_pkg_id = body["package"]["id"]
            items = await th_db.list_evidence_items(new_pkg_id)
            rec_item = next(
                i for i in items if i["label"] == "Recommended combination (from comparison)"
            )
            assert "evil.example.com" in rec_item["extracted_text"]

    @pytest.mark.asyncio
    async def test_rerun_route_404_when_no_comparison(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)
            resp = client.post(
                f"/api/threat-hunting/packages/{pkg['id']}/compare/rerun", json={"phase": "full"}
            )
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_rerun_route_scoped_to_selected_run_ids(self, db_path: Path) -> None:
        """Option 3: a user-picked subset only pulls kept IOCs from those runs."""
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.add_evidence_item(pkg["id"], item_type="text", label="x", source_ref="x")
            await _seed_run(
                pkg["id"],
                "run-1",
                deep_retrohunt={
                    "sanitized_iocs": [{"ioc": "a.example.com", "ioc_type": "domain", "action": "keep"}]
                },
            )
            await _seed_run(
                pkg["id"],
                "run-2",
                deep_retrohunt={
                    "sanitized_iocs": [{"ioc": "b.example.com", "ioc_type": "domain", "action": "keep"}]
                },
                created_at="2026-01-02T00:00:00Z",
            )
            client = TestClient(app)

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare", json={"phase": "full"}
                )
                await comparison_analyst.compare_runs(pkg["id"], phase="full")

            with patch(
                "backend.threat_hunting.agents.runner.start_generation",
                new=AsyncMock(return_value={"id": "new-run", "generation_status": "running"}),
            ):
                resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare/rerun",
                    json={"phase": "full", "run_ids": ["run-1"]},
                )
            assert resp.status_code == 202, resp.text
            new_pkg_id = resp.json()["package"]["id"]
            items = await th_db.list_evidence_items(new_pkg_id)
            rec_item = next(
                i for i in items if i["label"] == "Recommended combination (from comparison)"
            )
            assert "a.example.com" in rec_item["extracted_text"]
            assert "b.example.com" not in rec_item["extracted_text"]
