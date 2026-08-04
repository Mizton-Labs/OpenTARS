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
    async def test_compare_route_starts_a_job_and_returns_202(self, db_path: Path) -> None:
        """issue-local-035 follow-up: /compare is now fire-and-forget — it
        returns a running job immediately rather than awaiting the LLM call
        inline (which used to die if the client disconnected mid-request)."""
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            client = TestClient(app)

            compare_resp = client.post(f"/api/threat-hunting/packages/{pkg['id']}/compare", json={})
            assert compare_resp.status_code == 202, compare_resp.text
            job = compare_resp.json()
            assert job["status"] == "running"
            assert job["phase"] == "full"
            assert job["hunt_package_id"] == pkg["id"]

            status_resp = client.get(
                f"/api/threat-hunting/packages/{pkg['id']}/compare/status?phase=full"
            )
            assert status_resp.status_code == 200
            assert status_resp.json()["id"] == job["id"]

    @pytest.mark.asyncio
    async def test_compare_then_get_and_download(self, db_path: Path) -> None:
        """The job-status route only starts the job; this test drives the
        actual comparison to completion by calling compare_runs() directly
        (same function the background task calls) so it can assert on the
        resulting report/downloads, matching how TestClient can't reliably
        run a fire-and-forget asyncio.create_task to completion."""
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            client = TestClient(app)

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                compare_resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare", json={}
                )
                assert compare_resp.status_code == 202, compare_resp.text

                await comparison_analyst.compare_runs(pkg["id"])

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

    @pytest.mark.asyncio
    async def test_preliminary_and_full_phases_are_independent_slots(self, db_path: Path) -> None:
        """issue-local-035: preliminary and full comparisons don't overwrite
        each other — each phase has its own latest-report slot."""
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            client = TestClient(app)

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                prelim_resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare",
                    json={"phase": "preliminary"},
                )
                assert prelim_resp.status_code == 202, prelim_resp.text
                await comparison_analyst.compare_runs(pkg["id"], phase="preliminary")

                # No 'full' report exists yet — must 404, not fall back to preliminary.
                full_get = client.get(
                    f"/api/threat-hunting/packages/{pkg['id']}/comparison?phase=full"
                )
                assert full_get.status_code == 404

                full_resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare", json={"phase": "full"}
                )
                assert full_resp.status_code == 202, full_resp.text
                await comparison_analyst.compare_runs(pkg["id"], phase="full")

            prelim_get = client.get(
                f"/api/threat-hunting/packages/{pkg['id']}/comparison?phase=preliminary"
            )
            assert prelim_get.status_code == 200
            assert prelim_get.json()["full_report"]["phase"] == "preliminary"

            full_get = client.get(
                f"/api/threat-hunting/packages/{pkg['id']}/comparison?phase=full"
            )
            assert full_get.status_code == 200
            assert full_get.json()["full_report"]["phase"] == "full"

    @pytest.mark.asyncio
    async def test_default_phase_query_is_full(self, db_path: Path) -> None:
        """issue-local-035: omitting ?phase= must match the pre-035 default
        (full), so old bookmarks/clients keep working unchanged."""
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            client = TestClient(app)

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                client.post(f"/api/threat-hunting/packages/{pkg['id']}/compare", json={})
                await comparison_analyst.compare_runs(pkg["id"])

            resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/comparison")
            assert resp.status_code == 200
            assert resp.json()["full_report"]["phase"] == "full"


class TestComparisonJobs:
    """issue-local-035 follow-up: comparison_jobs DB functions and
    compare_runs()'s job_id-gated progress reporting."""

    @pytest.mark.asyncio
    async def test_create_comparison_job_starts_running(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            job = await th_db.create_comparison_job(
                pkg["id"], phase="full", run_ids=["run-1"], provider_name="p", model_name="m"
            )
            assert job["status"] == "running"
            assert job["current_step"] == "loading_runs"
            assert job["phase"] == "full"
            assert job["hunt_package_id"] == pkg["id"]
            assert job["run_ids"] == ["run-1"]
            assert job["report_id"] is None
            assert job["error_message"] is None

    @pytest.mark.asyncio
    async def test_update_comparison_job_changes_only_given_fields(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            job = await th_db.create_comparison_job(pkg["id"], phase="full")
            await th_db.update_comparison_job(job["id"], current_step="building_tables")
            updated = await th_db.get_comparison_job(job["id"])
            assert updated["current_step"] == "building_tables"
            assert updated["status"] == "running"  # unchanged

            await th_db.update_comparison_job(job["id"], status="completed", report_id="rep-1")
            done = await th_db.get_comparison_job(job["id"])
            assert done["status"] == "completed"
            assert done["report_id"] == "rep-1"
            assert done["current_step"] == "building_tables"  # unchanged by this call

    @pytest.mark.asyncio
    async def test_update_comparison_job_error(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            job = await th_db.create_comparison_job(pkg["id"], phase="full")
            await th_db.update_comparison_job(
                job["id"], status="error", error_message="LLM disabled"
            )
            errored = await th_db.get_comparison_job(job["id"])
            assert errored["status"] == "error"
            assert errored["error_message"] == "LLM disabled"

    @pytest.mark.asyncio
    async def test_get_latest_comparison_job_returns_most_recent_per_phase(
        self, db_path: Path
    ) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            job1 = await th_db.create_comparison_job(pkg["id"], phase="full")
            job2 = await th_db.create_comparison_job(pkg["id"], phase="full")
            prelim_job = await th_db.create_comparison_job(pkg["id"], phase="preliminary")

            latest_full = await th_db.get_latest_comparison_job(pkg["id"], phase="full")
            assert latest_full["id"] in (job1["id"], job2["id"])
            # Most recently created wins — job2 was created after job1.
            assert latest_full["id"] == job2["id"]

            latest_prelim = await th_db.get_latest_comparison_job(pkg["id"], phase="preliminary")
            assert latest_prelim["id"] == prelim_job["id"]

    @pytest.mark.asyncio
    async def test_get_latest_comparison_job_none_when_absent(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            assert await th_db.get_latest_comparison_job(pkg["id"], phase="full") is None

    @pytest.mark.asyncio
    async def test_compare_runs_reports_progress_through_all_steps(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            job = await th_db.create_comparison_job(pkg["id"], phase="full")

            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                result = await comparison_analyst.compare_runs(
                    pkg["id"], phase="full", job_id=job["id"]
                )

            finished = await th_db.get_comparison_job(job["id"])
            assert finished["status"] == "completed"
            assert finished["current_step"] == "finalizing"
            assert finished["report_id"] == result["id"]

    @pytest.mark.asyncio
    async def test_compare_runs_without_job_id_does_not_touch_jobs_table(
        self, db_path: Path
    ) -> None:
        """Direct calls (no job_id) must behave exactly as before — this is
        what every pre-existing test in this file already relies on."""
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                await comparison_analyst.compare_runs(pkg["id"])
            assert await th_db.get_latest_comparison_job(pkg["id"], phase="full") is None

    @pytest.mark.asyncio
    async def test_route_background_wrapper_marks_job_error_on_exception(
        self, db_path: Path
    ) -> None:
        """The route's background wrapper must never let an exception vanish
        silently — it has to land on the job row as status=error."""
        from backend.api.routes_threat_hunting import _run_comparison_job

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            job = await th_db.create_comparison_job(pkg["id"], phase="full")

            await _run_comparison_job(
                job["id"],
                pkg["id"],
                run_ids=None,
                provider_name=None,
                model_name=None,
                created_by=None,
                phase="full",
            )

            failed = await th_db.get_comparison_job(job["id"])
            assert failed["status"] == "error"
            assert failed["error_message"]  # "No runs to compare..." — the seeded ValueError


class TestComparisonPhaseSplit:
    """issue-local-035: preliminary comparisons omit SIEM-execution-only
    data; full comparisons behave as before the phase split."""

    @pytest.mark.asyncio
    async def test_preliminary_event_count_is_none(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                result = await comparison_analyst.compare_runs(pkg["id"], phase="preliminary")
            assert result["full_report"]["diff_table"][0]["event_count"] is None

    @pytest.mark.asyncio
    async def test_full_event_count_is_a_number(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                result = await comparison_analyst.compare_runs(pkg["id"], phase="full")
            assert result["full_report"]["diff_table"][0]["event_count"] == 0

    @pytest.mark.asyncio
    async def test_invalid_phase_raises(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            with pytest.raises(ValueError):
                await comparison_analyst.compare_runs(pkg["id"], phase="bogus")

    @pytest.mark.asyncio
    async def test_default_phase_is_full(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"summary": "x"})
            with patch(
                "backend.threat_hunting.agents.nodes.comparison_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                result = await comparison_analyst.compare_runs(pkg["id"])
            assert result["full_report"]["phase"] == "full"

    @pytest.mark.asyncio
    async def test_legacy_report_without_phase_key_surfaces_as_full(
        self, db_path: Path
    ) -> None:
        """Pre-035 comparison reports have no 'phase' key at all — must still
        surface under get_latest_comparison_report(phase='full')."""
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            legacy_full_report = {"report_kind": "comparison", "hunt_name": "pkg"}
            await th_db.create_hunt_report(
                pkg["id"],
                executive_summary="legacy",
                full_report=legacy_full_report,
                run_id=None,
            )
            result = await th_db.get_latest_comparison_report(pkg["id"], phase="full")
            assert result is not None
            assert result["executive_summary"] == "legacy"

            result_prelim = await th_db.get_latest_comparison_report(pkg["id"], phase="preliminary")
            assert result_prelim is None
