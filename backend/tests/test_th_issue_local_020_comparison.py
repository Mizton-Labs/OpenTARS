"""
Tests for issue-local-020 Part D: the Comparison Module
(backend.threat_hunting.agents.nodes.comparison_analyst.compare_runs), its
Markdown/PDF renderers in report_writer.py, and the new comparison API routes.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents.nodes import comparison_analyst
from backend.threat_hunting.agents.nodes.report_writer import (
    render_comparison_markdown,
    render_comparison_pdf,
)


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
    threat_context: dict | None = None,
    hypotheses: list | None = None,
    ttp_analysis: dict | None = None,
    generation_status: str = "completed",
    llm_model: str = "gpt-test",
    research_effort: str = "medium",
    created_at: str = "2026-01-01T00:00:00Z",
) -> None:
    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        await db.execute(
            "INSERT INTO hunting_packages (id, hunt_package_id, threat_context, hypotheses, "
            "ttp_analysis, generation_status, llm_model, research_effort, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                pkg_id,
                json.dumps(threat_context) if threat_context is not None else None,
                json.dumps(hypotheses) if hypotheses is not None else None,
                json.dumps(ttp_analysis) if ttp_analysis is not None else None,
                generation_status,
                llm_model,
                research_effort,
                created_at,
            ),
        )
        await db.commit()


LLM_RESPONSE = json.dumps(
    {
        "summary": "Runs largely agree on the threat actor.",
        "key_differences": ["Run 2 found an additional C2 domain"],
        "gaps": ["Run 1 did not check DNS logs"],
        "enrichment_opportunities": ["Merge IOC sets from both runs"],
        "recommended_combination": "Combine IOC lists from run 1 and run 2.",
    }
)


class TestCompareRuns:
    @pytest.mark.asyncio
    async def test_raises_for_missing_package(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            with pytest.raises(ValueError):
                await comparison_analyst.compare_runs("no-such-pkg")

    @pytest.mark.asyncio
    async def test_raises_for_package_with_no_runs(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            with pytest.raises(ValueError):
                await comparison_analyst.compare_runs(pkg["id"])

    @pytest.mark.asyncio
    async def test_single_run_produces_diff_table_and_report(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(
                pkg["id"],
                "run-1",
                threat_context={"summary": "FIN7 targeting retail"},
                hypotheses=[{"id": "H1", "title": "POS malware", "relevance": "high"}],
                ttp_analysis={"techniques": [{"technique_id": "T1059", "technique_name": "CLI"}]},
            )

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                result = await comparison_analyst.compare_runs(pkg["id"])

            full_report = result["full_report"]
            assert full_report["compared_run_ids"] == ["run-1"]
            assert len(full_report["diff_table"]) == 1
            assert full_report["diff_table"][0]["hypothesis_count"] == 1
            assert full_report["diff_table"][0]["technique_count"] == 1
            assert full_report["summary"] == "Runs largely agree on the threat actor."
            assert "_markdown" in full_report

    @pytest.mark.asyncio
    async def test_multiple_runs_diff_table_counts_correct(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(
                pkg["id"],
                "run-1",
                threat_context={"summary": "run 1"},
                hypotheses=[{"id": "H1", "title": "A"}, {"id": "H2", "title": "B"}],
                created_at="2026-01-01T00:00:00Z",
            )
            await _seed_run(
                pkg["id"],
                "run-2",
                threat_context={"summary": "run 2"},
                hypotheses=[{"id": "H1", "title": "A"}],
                ttp_analysis={"techniques": [{"technique_id": "T1"}, {"technique_id": "T2"}]},
                created_at="2026-01-02T00:00:00Z",
            )

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                result = await comparison_analyst.compare_runs(pkg["id"])

            full_report = result["full_report"]
            diff_by_run = {row["run_id"]: row for row in full_report["diff_table"]}
            assert diff_by_run["run-1"]["hypothesis_count"] == 2
            assert diff_by_run["run-2"]["hypothesis_count"] == 1
            assert diff_by_run["run-2"]["technique_count"] == 2
            assert set(full_report["compared_run_ids"]) == {"run-1", "run-2"}

    @pytest.mark.asyncio
    async def test_llm_failure_falls_back_to_deterministic_summary(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(side_effect=Exception("LLM unavailable")),
            ):
                result = await comparison_analyst.compare_runs(pkg["id"])

            full_report = result["full_report"]
            assert full_report["summary"]
            assert len(full_report["diff_table"]) == 1

    @pytest.mark.asyncio
    async def test_comparison_report_does_not_shadow_normal_report(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            await th_db.create_hunt_report(
                pkg["id"], executive_summary="real report", full_report={"hunt_name": "pkg"}
            )

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                await comparison_analyst.compare_runs(pkg["id"])

            normal = await th_db.get_hunt_report(pkg["id"])
            assert normal is not None
            assert normal["executive_summary"] == "real report"


class TestComparisonRenderers:
    def test_render_comparison_markdown_contains_expected_sections(self) -> None:
        full_report = {
            "hunt_name": "Test Hunt",
            "hunt_id_display": "TH01",
            "compared_run_ids": ["run-1", "run-2"],
            "diff_table": [
                {
                    "run_id_display": "TH01-X01",
                    "model": "gpt-test",
                    "effort": "medium",
                    "status": "completed",
                    "hypothesis_count": 2,
                    "sanitized_ioc_count": 3,
                    "removed_ioc_count": 1,
                    "technique_count": 1,
                    "event_count": 5,
                }
            ],
            "summary": "Summary text",
            "key_differences": ["diff 1"],
            "gaps": ["gap 1"],
            "enrichment_opportunities": ["enrich 1"],
            "recommended_combination": "combine them",
        }
        markdown = render_comparison_markdown(full_report)
        assert "Comparison Assessment" in markdown
        assert "TH01-X01" in markdown
        assert "diff 1" in markdown
        assert "gap 1" in markdown
        assert "enrich 1" in markdown
        assert "combine them" in markdown

    def test_render_comparison_pdf_returns_bytes(self) -> None:
        full_report = {
            "hunt_name": "Test Hunt",
            "compared_run_ids": ["run-1"],
            "diff_table": [
                {
                    "run_id_display": "TH01-X01",
                    "model": "gpt-test",
                    "status": "completed",
                    "hypothesis_count": 1,
                    "sanitized_ioc_count": 0,
                    "removed_ioc_count": 0,
                    "technique_count": 0,
                    "event_count": 0,
                }
            ],
            "summary": "Summary text",
        }
        pdf_bytes = render_comparison_pdf(full_report)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes[:4] == b"%PDF"


class TestComparisonRoutes:
    @pytest.mark.asyncio
    async def test_get_comparison_404_when_absent(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)
            resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/comparison")
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_compare_route_400_when_no_runs(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)
            resp = client.post(f"/api/threat-hunting/packages/{pkg['id']}/compare", json={})
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_compare_then_get_and_download(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                client = TestClient(app)
                compare_resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare", json={}
                )
                assert compare_resp.status_code == 201, compare_resp.text

                get_resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/comparison")
                assert get_resp.status_code == 200

                md_resp = client.get(
                    f"/api/threat-hunting/packages/{pkg['id']}/comparison/markdown"
                )
                assert md_resp.status_code == 200
                assert "Comparison Assessment" in md_resp.text

                pdf_resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/comparison/pdf")
                assert pdf_resp.status_code == 200
                assert pdf_resp.content[:4] == b"%PDF"
