"""
Tests for issue-local-040: Hunt Playbooks.

This file grows alongside the feature's implementation. This first section
covers the runner.py extensions: playbook_id/playbook_name/run_origin
persistence + restoration across a resume, and the auto_approve hook.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents import runner
from backend.threat_hunting.agents.nodes import comparison_analyst, recommendation_synthesizer


async def _seed_package(db_path: Path, pkg_id: str) -> None:
    await th_db.init_threat_hunting_db()
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (pkg_id, "test", "", "draft", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        )
        await db.commit()


def _row(db_path: Path, run_id: str) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM hunting_packages WHERE id=?", (run_id,)).fetchone()
    conn.close()
    assert row is not None
    return dict(row)


class _StubGraph:
    """Compiled-graph stub whose single astream() chunk sets a target
    generation_status, mirroring _HangingGraph's role in the cancel/timeout
    tests but yielding immediately instead of hanging."""

    def __init__(self, status: str) -> None:
        self._status = status

    def astream(self, initial_state):
        async def _gen():
            yield {"query_drafting_agent": {"generation_status": self._status}}

        return _gen()


@pytest.mark.asyncio
async def test_start_generation_persists_playbook_fields(tmp_path: Path) -> None:
    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
    ):
        mock_task.return_value = object()
        await _seed_package(db_path, pkg_id)

        result = await runner.start_generation(
            pkg_id,
            provider_name="p1",
            model_name="m1",
            playbook_id="pb-1",
            playbook_name="My Playbook",
            run_origin="playbook",
            auto_approve=True,
        )
        assert result["playbook_id"] == "pb-1"
        assert result["playbook_name"] == "My Playbook"
        assert result["run_origin"] == "playbook"

        # Simulate what _run_pipeline's first _save_generation_state call
        # would persist, using the coroutine build_initial_state actually
        # produced — matches this file's sibling test's own convention for
        # asserting persistence without running the real graph.
        from backend.threat_hunting.agents.pipeline import build_initial_state

        state = build_initial_state(
            pkg_id,
            provider_name="p1",
            model_name="m1",
            playbook_id="pb-1",
            playbook_name="My Playbook",
            run_origin="playbook",
            auto_approve=True,
        )
        await runner._save_generation_state(result["run_id"], pkg_id, state, status="running")

    row = _row(db_path, result["run_id"])
    assert row["playbook_id"] == "pb-1"
    assert row["playbook_name"] == "My Playbook"
    assert row["run_origin"] == "playbook"


@pytest.mark.asyncio
async def test_manual_run_defaults_run_origin(tmp_path: Path) -> None:
    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
    ):
        mock_task.return_value = object()
        await _seed_package(db_path, pkg_id)
        result = await runner.start_generation(pkg_id, provider_name="p1", model_name="m1")
        assert result["run_origin"] == "manual"
        assert result["playbook_id"] is None

        from backend.threat_hunting.agents.pipeline import build_initial_state

        state = build_initial_state(pkg_id, provider_name="p1", model_name="m1")
        await runner._save_generation_state(result["run_id"], pkg_id, state, status="running")

    row = _row(db_path, result["run_id"])
    assert row["run_origin"] == "manual"
    assert row["playbook_id"] is None


@pytest.mark.asyncio
async def test_resume_preserves_playbook_fields(tmp_path: Path) -> None:
    """A resumed run (approve_generation -> _run_pipeline(resume=True)) must
    not null out playbook_id/playbook_name/run_origin on its next save —
    _load_pipeline_state has to restore them from the DB row first."""
    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
    ):
        await _seed_package(db_path, pkg_id)
        await runner._save_generation_state(
            run_id,
            pkg_id,
            {
                "provider_name": "p1",
                "model_name": "m1",
                "playbook_id": "pb-1",
                "playbook_name": "My Playbook",
                "run_origin": "playbook",
            },
            status="awaiting_approval",
        )

        state = await runner._load_pipeline_state(run_id)
        assert state is not None
        assert state["playbook_id"] == "pb-1"
        assert state["playbook_name"] == "My Playbook"
        assert state["run_origin"] == "playbook"

        # Re-save using the reconstructed state, as the resumed pipeline
        # would on its very next node — this is the exact regression this
        # test guards against.
        await runner._save_generation_state(run_id, pkg_id, state, status="running")

    row = _row(db_path, run_id)
    assert row["playbook_id"] == "pb-1"
    assert row["playbook_name"] == "My Playbook"
    assert row["run_origin"] == "playbook"


@pytest.mark.asyncio
async def test_auto_approve_schedules_approve_generation(tmp_path: Path) -> None:
    """When a run reaches awaiting_approval with auto_approve=True,
    _run_pipeline must schedule approve_generation(run_id) as a new task —
    not await it inline (see the in-code comment on why: self-cancellation
    risk if called before this task deregisters from _ACTIVE_JOBS)."""
    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    scheduled: list = []

    def _capture_create_task(coro):
        scheduled.append(coro)
        coro.close()  # never actually run it — just inspect what was scheduled
        return object()

    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch(
            "backend.threat_hunting.agents.pipeline.get_compiled_graph",
            return_value=_StubGraph("awaiting_approval"),
        ),
        patch("backend.threat_hunting.agents.runner.asyncio.create_task", _capture_create_task),
    ):
        await _seed_package(db_path, pkg_id)
        await runner._run_pipeline(
            run_id,
            pkg_id,
            {
                "hunt_package_id": pkg_id,
                "auto_approve": True,
                "run_config": {"include_threat_intel": False},
            },
        )

    assert len(scheduled) == 1
    assert scheduled[0].cr_code.co_name == "approve_generation"


@pytest.mark.asyncio
async def test_no_auto_approve_leaves_run_awaiting_approval(tmp_path: Path) -> None:
    """A manual run (auto_approve unset/False) must NOT self-approve — the
    human approval gate stays intact for every run except Playbook-triggered
    ones with the toggle on."""
    db_path = tmp_path / "th.db"
    pkg_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch(
            "backend.threat_hunting.agents.pipeline.get_compiled_graph",
            return_value=_StubGraph("awaiting_approval"),
        ),
        patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
    ):
        mock_task.return_value = object()
        await _seed_package(db_path, pkg_id)
        await runner._run_pipeline(
            run_id,
            pkg_id,
            {"hunt_package_id": pkg_id, "run_config": {"include_threat_intel": False}},
        )

    mock_task.assert_not_called()
    assert _row(db_path, run_id)["generation_status"] == "awaiting_approval"


LLM_COMPARISON_RESPONSE = json.dumps(
    {
        "summary": "Both runs largely agree.",
        "key_differences": [],
        "gaps": [],
        "enrichment_opportunities": [],
        "recommended_combination": "Combine the IOC coverage of both runs.",
    }
)


async def _seed_run_with_outputs(pkg_id: str, run_id: str, *, llm_model: str) -> None:
    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        await db.execute(
            "INSERT INTO hunting_packages "
            "(id, hunt_package_id, generation_status, llm_model, created_at, "
            " hypotheses, ttp_analysis, hunting_leads, query_drafts) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                pkg_id,
                "completed",
                llm_model,
                "2026-01-01T00:00:00Z",
                json.dumps([{"id": "h1", "title": f"Hypothesis from {llm_model}", "relevance": "high"}]),
                json.dumps({"techniques": [{"technique_id": "T1059", "technique_name": "Scripting"}]}),
                json.dumps([{"title": f"Lead from {llm_model}"}]),
                json.dumps([{"language": "SPL", "query": f"index=main {llm_model}"}]),
            ),
        )
        await db.commit()


class TestSynthesizeRecommendationRun:
    @pytest.mark.asyncio
    async def test_raises_when_no_comparison_exists(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            with pytest.raises(ValueError, match="No preliminary comparison report"):
                await recommendation_synthesizer.synthesize_recommendation_run(
                    pkg["id"], phase="preliminary"
                )

    @pytest.mark.asyncio
    async def test_seeds_a_new_run_in_the_same_package(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(runner, "_ACTIVE_JOBS", {}),
            patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        ):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run_with_outputs(pkg["id"], "run-a", llm_model="gpt-4o")
            await _seed_run_with_outputs(pkg["id"], "run-b", llm_model="claude")

            with patch.object(
                comparison_analyst, "call_llm", new=AsyncMock(return_value=LLM_COMPARISON_RESPONSE)
            ):
                await comparison_analyst.compare_runs(pkg["id"], phase="preliminary")

            with (
                patch.object(
                    recommendation_synthesizer,
                    "call_llm",
                    new=AsyncMock(return_value="Synthesized consolidated plan text."),
                ),
                patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
            ):
                mock_task.return_value = object()
                run_record = await recommendation_synthesizer.synthesize_recommendation_run(
                    pkg["id"], phase="preliminary"
                )

            # Same package, not a clone — the whole point of the redesign.
            assert run_record["hunt_package_id"] == pkg["id"]
            assert run_record["run_origin"] == "consolidated"

            evidence = await th_db.list_evidence_items(pkg["id"])
            assert any(
                "Consolidated plan (from comparison recommendations)" == e["label"] for e in evidence
            )
            synthesized = next(
                e for e in evidence if e["label"] == "Consolidated plan (from comparison recommendations)"
            )
            assert "Synthesized consolidated plan text." in synthesized["extracted_text"]
            assert "gpt-4o" in synthesized["extracted_text"] or "claude" in synthesized["extracted_text"]

    @pytest.mark.asyncio
    async def test_run_ids_narrows_to_a_subset(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(runner, "_ACTIVE_JOBS", {}),
            patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        ):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run_with_outputs(pkg["id"], "run-a", llm_model="gpt-4o")
            await _seed_run_with_outputs(pkg["id"], "run-b", llm_model="claude")

            with patch.object(
                comparison_analyst, "call_llm", new=AsyncMock(return_value=LLM_COMPARISON_RESPONSE)
            ):
                await comparison_analyst.compare_runs(pkg["id"], phase="full")

            captured_context: list = []

            async def _capture(user_prompt, **_kw):
                captured_context.append(user_prompt)
                return "plan"

            with (
                patch.object(recommendation_synthesizer, "call_llm", new=AsyncMock(side_effect=_capture)),
                patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
            ):
                mock_task.return_value = object()
                await recommendation_synthesizer.synthesize_recommendation_run(
                    pkg["id"], phase="full", run_ids=["run-a"]
                )

            assert len(captured_context) == 1
            assert "gpt-4o" in captured_context[0]
            assert "claude" not in captured_context[0]

    @pytest.mark.asyncio
    async def test_llm_failure_falls_back_to_raw_recommendation(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(runner, "_ACTIVE_JOBS", {}),
            patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        ):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run_with_outputs(pkg["id"], "run-a", llm_model="gpt-4o")

            with patch.object(
                comparison_analyst, "call_llm", new=AsyncMock(return_value=LLM_COMPARISON_RESPONSE)
            ):
                await comparison_analyst.compare_runs(pkg["id"], phase="preliminary")

            with (
                patch.object(
                    recommendation_synthesizer,
                    "call_llm",
                    new=AsyncMock(side_effect=RuntimeError("upstream down")),
                ),
                patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
            ):
                mock_task.return_value = object()
                await recommendation_synthesizer.synthesize_recommendation_run(
                    pkg["id"], phase="preliminary"
                )

            evidence = await th_db.list_evidence_items(pkg["id"])
            synthesized = next(
                e for e in evidence if e["label"] == "Consolidated plan (from comparison recommendations)"
            )
            assert "Combine the IOC coverage of both runs." in synthesized["extracted_text"]


from backend.threat_hunting.agents import playbook_runner  # noqa: E402


async def _simulate_run_terminal(
    pkg_id: str,
    run_id: str,
    *,
    provider_name: str = "p1",
    model_name: str = "m1",
    playbook_id: str | None = None,
    playbook_name: str | None = None,
    run_origin: str = "manual",
    status: str = "completed",
) -> None:
    """Simulate what _run_pipeline's first _save_generation_state call would
    have persisted, for tests that mock away asyncio.create_task and so
    never let the real pipeline run."""
    await runner._save_generation_state(
        run_id,
        pkg_id,
        {
            "provider_name": provider_name,
            "model_name": model_name,
            "playbook_id": playbook_id,
            "playbook_name": playbook_name,
            "run_origin": run_origin,
        },
        status=status,
    )


class TestRunPlaybookDispatch:
    @pytest.mark.asyncio
    async def test_run_playbook_creates_a_job_and_returns_immediately(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch("backend.threat_hunting.agents.playbook_runner.asyncio.create_task") as mock_task,
        ):
            mock_task.return_value = object()
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            pb = await th_db.create_playbook("PB1", models=[{"model_name": "m1"}])

            job = await playbook_runner.run_playbook(pkg["id"], pb["id"])
            assert job["status"] == "running"
            assert job["playbook_id"] == pb["id"]
            mock_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_raises_for_unknown_playbook(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            with pytest.raises(ValueError, match="not found"):
                await playbook_runner.run_playbook(pkg["id"], "nonexistent")

    @pytest.mark.asyncio
    async def test_raises_for_unknown_package(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pb = await th_db.create_playbook("PB1", models=[{"model_name": "m1"}])
            with pytest.raises(ValueError, match="not found"):
                await playbook_runner.run_playbook("nonexistent", pb["id"])


class TestRunPlaybookJobChain:
    @pytest.mark.asyncio
    async def test_fires_one_run_per_model(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(runner, "_ACTIVE_JOBS", {}),
            patch.object(runner, "_ACTIVE_RUN_PKG", {}),
            patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
        ):
            mock_task.return_value = object()
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            pb = await th_db.create_playbook(
                "PB1",
                models=[{"model_name": "m1"}, {"model_name": "m2"}],
                auto_approve_analysis=False,
            )
            job = await th_db.create_playbook_job(
                pkg["id"], playbook_id=pb["id"], playbook_name=pb["name"]
            )
            await playbook_runner._run_playbook_job(job["id"], pkg["id"], pb, created_by=None)

            final_job = await th_db.get_playbook_job(job["id"])
        assert final_job["status"] == "completed"
        assert final_job["current_step"] == "awaiting_manual_approval"
        assert len(final_job["run_ids"]) == 2

    @pytest.mark.asyncio
    async def test_full_chain_with_all_toggles_on(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(runner, "_ACTIVE_JOBS", {}),
            patch.object(runner, "_ACTIVE_RUN_PKG", {}),
            patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
        ):
            mock_task.return_value = object()
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            pb = await th_db.create_playbook(
                "PB1",
                models=[{"model_name": "gpt-4o"}, {"model_name": "claude"}],
                auto_approve_analysis=True,
                auto_run_comparison=True,
                auto_compare_preliminary=True,
                auto_compare_full=True,
                auto_create_run_from_recommendations=True,
                auto_generate_full_report=True,
            )
            job = await th_db.create_playbook_job(
                pkg["id"], playbook_id=pb["id"], playbook_name=pb["name"]
            )

            # Patch _wait_for_terminal to skip real polling — the runs need
            # real DB rows with real hypotheses/etc for the comparison and
            # recommendation-run legs to have something to work with, so
            # seed them directly rather than trying to race the poll loop.
            async def _fake_wait(run_ids):
                for i, run_id in enumerate(run_ids):
                    await _seed_run_with_outputs(pkg["id"], run_id, llm_model=f"model-{i}")
                return list(run_ids)

            with (
                patch.object(playbook_runner, "_wait_for_terminal", _fake_wait),
                patch.object(
                    comparison_analyst, "call_llm", new=AsyncMock(return_value=LLM_COMPARISON_RESPONSE)
                ),
                patch.object(
                    recommendation_synthesizer,
                    "call_llm",
                    new=AsyncMock(return_value="Synthesized plan."),
                ),
            ):
                await playbook_runner._run_playbook_job(job["id"], pkg["id"], pb, created_by="alice")

            final_job = await th_db.get_playbook_job(job["id"])
            # Named with the playbook's own name as prefix, not "manual".
            prelim = await th_db.get_latest_comparison_report(pkg["id"], phase="preliminary")

        assert final_job["status"] == "completed"
        assert final_job["comparison_preliminary_report_id"] is not None
        assert final_job["comparison_full_report_id"] is not None
        # The recommendation-synthesis run's own shape (same package,
        # run_origin='consolidated') is covered directly by
        # TestSynthesizeRecommendationRun — this asserts only that the
        # orchestrator actually invoked it and recorded the resulting run_id
        # (create_task is mocked away here too, so no DB row exists to
        # re-query for this particular run).
        assert final_job["recommendation_run_id"] is not None
        assert final_job["consolidated_report_id"] is not None
        assert prelim["name"].startswith("PB1_")

    @pytest.mark.asyncio
    async def test_fewer_than_two_completed_runs_skips_comparison(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(runner, "_ACTIVE_JOBS", {}),
            patch.object(runner, "_ACTIVE_RUN_PKG", {}),
            patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
        ):
            mock_task.return_value = object()
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            pb = await th_db.create_playbook(
                "PB1",
                models=[{"model_name": "gpt-4o"}],
                auto_approve_analysis=True,
                auto_run_comparison=True,
                auto_compare_full=True,
            )
            job = await th_db.create_playbook_job(
                pkg["id"], playbook_id=pb["id"], playbook_name=pb["name"]
            )

            async def _fake_wait_one_completes(run_ids):
                await _seed_run_with_outputs(pkg["id"], run_ids[0], llm_model="gpt-4o")
                return [run_ids[0]]

            with patch.object(playbook_runner, "_wait_for_terminal", _fake_wait_one_completes):
                await playbook_runner._run_playbook_job(job["id"], pkg["id"], pb, created_by=None)

            final_job = await th_db.get_playbook_job(job["id"])
        assert final_job["status"] == "completed"
        assert final_job["comparison_full_report_id"] is None

    @pytest.mark.asyncio
    async def test_recommendation_toggle_without_preliminary_compare_is_a_noop(
        self, tmp_path: Path
    ) -> None:
        """auto_create_run_from_recommendations=True but
        auto_compare_preliminary=False must not crash the job — there is
        nothing to synthesize from, so it's silently skipped."""
        db_path = tmp_path / "th.db"
        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(runner, "_ACTIVE_JOBS", {}),
            patch.object(runner, "_ACTIVE_RUN_PKG", {}),
            patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
        ):
            mock_task.return_value = object()
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            pb = await th_db.create_playbook(
                "PB1",
                models=[{"model_name": "gpt-4o"}, {"model_name": "claude"}],
                auto_approve_analysis=True,
                auto_run_comparison=True,
                auto_compare_full=True,
                auto_create_run_from_recommendations=True,
            )
            job = await th_db.create_playbook_job(
                pkg["id"], playbook_id=pb["id"], playbook_name=pb["name"]
            )

            async def _fake_wait(run_ids):
                for i, run_id in enumerate(run_ids):
                    await _seed_run_with_outputs(pkg["id"], run_id, llm_model=f"model-{i}")
                return list(run_ids)

            with (
                patch.object(playbook_runner, "_wait_for_terminal", _fake_wait),
                patch.object(
                    comparison_analyst, "call_llm", new=AsyncMock(return_value=LLM_COMPARISON_RESPONSE)
                ),
            ):
                await playbook_runner._run_playbook_job(job["id"], pkg["id"], pb, created_by=None)

            final_job = await th_db.get_playbook_job(job["id"])
        assert final_job["status"] == "completed"
        assert final_job["comparison_full_report_id"] is not None
        assert final_job["recommendation_run_id"] is None

    @pytest.mark.asyncio
    async def test_job_marked_error_on_unexpected_failure(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(runner, "_ACTIVE_JOBS", {}),
            patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        ):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            pb = await th_db.create_playbook("PB1", models=[{"model_name": "m1"}])
            job = await th_db.create_playbook_job(
                pkg["id"], playbook_id=pb["id"], playbook_name=pb["name"]
            )

            with patch(
                "backend.threat_hunting.agents.runner.asyncio.create_task",
                side_effect=RuntimeError("boom"),
            ):
                await playbook_runner._run_playbook_job(job["id"], pkg["id"], pb, created_by=None)

            final_job = await th_db.get_playbook_job(job["id"])
        assert final_job["status"] == "error"
        assert "boom" in final_job["error_message"]


class TestPlaybookCrudRoutes:
    @pytest.mark.asyncio
    async def test_create_list_get_update_delete_clone(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            client = TestClient(app)

            create_resp = client.post(
                "/api/threat-hunting/playbooks",
                json={
                    "name": "My Playbook",
                    "models": [{"provider_name": "p1", "model_name": "m1"}],
                    "auto_approve_analysis": True,
                },
            )
            assert create_resp.status_code == 201, create_resp.text
            playbook = create_resp.json()
            assert playbook["name"] == "My Playbook"
            assert playbook["auto_approve_analysis"] is True

            list_resp = client.get("/api/threat-hunting/playbooks")
            assert list_resp.status_code == 200
            assert len(list_resp.json()) == 1

            get_resp = client.get(f"/api/threat-hunting/playbooks/{playbook['id']}")
            assert get_resp.status_code == 200
            assert get_resp.json()["name"] == "My Playbook"

            update_resp = client.put(
                f"/api/threat-hunting/playbooks/{playbook['id']}",
                json={"name": "Renamed", "auto_run_comparison": True},
            )
            assert update_resp.status_code == 200, update_resp.text
            assert update_resp.json()["name"] == "Renamed"
            assert update_resp.json()["auto_run_comparison"] is True
            # Untouched fields survive a partial update.
            assert update_resp.json()["auto_approve_analysis"] is True

            clone_resp = client.post(
                f"/api/threat-hunting/playbooks/{playbook['id']}/clone",
                json={"name": "Cloned"},
            )
            assert clone_resp.status_code == 201, clone_resp.text
            assert clone_resp.json()["id"] != playbook["id"]
            assert clone_resp.json()["name"] == "Cloned"

            delete_resp = client.delete(f"/api/threat-hunting/playbooks/{playbook['id']}")
            assert delete_resp.status_code == 204
            assert client.get(f"/api/threat-hunting/playbooks/{playbook['id']}").status_code == 404

    @pytest.mark.asyncio
    async def test_create_rejects_empty_models(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            client = TestClient(app)
            resp = client.post(
                "/api/threat-hunting/playbooks", json={"name": "Empty", "models": []}
            )
            assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_get_update_delete_404_for_unknown_playbook(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            client = TestClient(app)
            assert client.get("/api/threat-hunting/playbooks/nonexistent").status_code == 404
            assert (
                client.put(
                    "/api/threat-hunting/playbooks/nonexistent", json={"name": "x"}
                ).status_code
                == 404
            )
            assert client.delete("/api/threat-hunting/playbooks/nonexistent").status_code == 404
            assert (
                client.post(
                    "/api/threat-hunting/playbooks/nonexistent/clone", json={"name": "x"}
                ).status_code
                == 404
            )


class TestRunPlaybookRoute:
    @pytest.mark.asyncio
    async def test_run_route_creates_a_job(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            pb = await th_db.create_playbook("PB1", models=[{"model_name": "m1"}])
            client = TestClient(app)

            resp = client.post(f"/api/threat-hunting/packages/{pkg['id']}/playbooks/{pb['id']}/run")
            assert resp.status_code == 202, resp.text
            assert resp.json()["status"] == "running"

            status_resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/playbooks/status")
            assert status_resp.status_code == 200
            assert status_resp.json()["playbook_id"] == pb["id"]

    @pytest.mark.asyncio
    async def test_run_route_404_for_unknown_playbook(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)
            resp = client.post(
                f"/api/threat-hunting/packages/{pkg['id']}/playbooks/nonexistent/run"
            )
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_status_route_404_when_no_job_yet(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)
            resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/playbooks/status")
            assert resp.status_code == 404


class TestNamedComparisonRoutes:
    @pytest.mark.asyncio
    async def test_compare_route_saves_a_custom_name(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run_with_outputs(pkg["id"], "run-1", llm_model="gpt-4o")
            client = TestClient(app)

            with patch.object(
                comparison_analyst, "call_llm", new=AsyncMock(return_value=LLM_COMPARISON_RESPONSE)
            ):
                resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare",
                    json={"phase": "full", "name": "Q1 review"},
                )
                assert resp.status_code == 202, resp.text
                # Run the comparison synchronously (route only fires a
                # detached task) — mirrors this suite's existing convention.
                await comparison_analyst.compare_runs(pkg["id"], phase="full", name="Q1 review")

            report = await th_db.get_latest_comparison_report(pkg["id"], phase="full")
            assert report["name"] == "Q1 review"

    @pytest.mark.asyncio
    async def test_list_comparisons_route_returns_every_saved_assessment(
        self, tmp_path: Path
    ) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.create_comparison_report(
                pkg["id"], executive_summary="s1", full_report={}, phase="full", name="First"
            )
            await th_db.create_comparison_report(
                pkg["id"], executive_summary="s2", full_report={}, phase="full", name="Second"
            )
            client = TestClient(app)

            resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/comparisons?phase=full")
            assert resp.status_code == 200
            names = [r["name"] for r in resp.json()]
            assert names == ["Second", "First"]


class TestRecommendationRunRoute:
    @pytest.mark.asyncio
    async def test_404_when_no_comparison_exists(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)
            resp = client.post(
                f"/api/threat-hunting/packages/{pkg['id']}/compare/recommendation-run",
                json={"phase": "preliminary"},
            )
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_seeds_a_new_run_via_the_route(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(runner, "_ACTIVE_JOBS", {}),
            patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        ):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run_with_outputs(pkg["id"], "run-a", llm_model="gpt-4o")
            client = TestClient(app)

            with patch.object(
                comparison_analyst, "call_llm", new=AsyncMock(return_value=LLM_COMPARISON_RESPONSE)
            ):
                await comparison_analyst.compare_runs(pkg["id"], phase="preliminary")

            with (
                patch.object(
                    recommendation_synthesizer, "call_llm", new=AsyncMock(return_value="plan")
                ),
                patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
            ):
                mock_task.return_value = object()
                resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/compare/recommendation-run",
                    json={"phase": "preliminary"},
                )
            assert resp.status_code == 202, resp.text
            assert resp.json()["hunt_package_id"] == pkg["id"]
            assert resp.json()["run_origin"] == "consolidated"
