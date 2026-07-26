"""
Tests for issue-local-021's two-phase Threat Intel analysis:
  - analyze_threat_intel(phase=...) behavior (preliminary vs final).
  - The final phase additionally ingests this run's SIEM execution results.
  - runner.py's preliminary-phase call site and executor.py's final-phase
    call site both gate on the run_config.include_threat_intel flag.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents.nodes import threat_intel_analyst


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
    run_config: dict | None = None,
) -> None:
    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        await db.execute(
            "INSERT INTO hunting_packages (id, hunt_package_id, threat_context, run_config, "
            "created_at) VALUES (?,?,?,?,?)",
            (
                run_id,
                pkg_id,
                json.dumps(threat_context) if threat_context is not None else None,
                json.dumps(run_config) if run_config is not None else "{}",
                "2026-01-01T00:00:00Z",
            ),
        )
        await db.commit()


class TestTwoPhaseAnalysis:
    @pytest.mark.asyncio
    async def test_preliminary_phase_has_no_execution_findings(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"threat_actor": "APT1"})

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(side_effect=Exception("no llm in test")),
            ):
                result = await threat_intel_analyst.analyze_threat_intel(
                    pkg["id"], run_id="run-1", phase="preliminary"
                )

            assert result is not None
            assert result["full_analysis"]["phase"] == "preliminary"
            assert result["full_analysis"]["execution_findings"] is None

    @pytest.mark.asyncio
    async def test_final_phase_ingests_execution_results(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"threat_actor": "APT1"})
            result_row = await th_db.create_task_result(
                pkg["id"], task_type="retrohunt", run_id="run-1"
            )
            await th_db.update_task_result(
                result_row["id"],
                status="completed",
                raw_result=[{"_time": "2026-01-01T00:00:00Z"}, {"_time": "2026-01-01T00:01:00Z"}],
                interpreted_findings="Confirmed beaconing activity to known C2 domain.",
            )

            captured_prompt: dict[str, str] = {}

            async def _fake_call_llm(user, **kwargs):
                captured_prompt["system"] = kwargs.get("system", "")
                captured_prompt["user"] = user
                raise Exception("no llm in test")

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(side_effect=_fake_call_llm),
            ):
                result = await threat_intel_analyst.analyze_threat_intel(
                    pkg["id"], run_id="run-1", phase="final"
                )

            assert result is not None
            assert result["full_analysis"]["phase"] == "final"
            findings = result["full_analysis"]["execution_findings"]
            assert findings is not None
            assert "2 SIEM event(s)" in findings
            assert "Confirmed beaconing activity" in findings
            # The prompt sent to the LLM must also carry the execution findings.
            assert "Confirmed beaconing activity" in captured_prompt["user"]

    @pytest.mark.asyncio
    async def test_final_phase_with_no_execution_results_is_graceful(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"threat_actor": "APT1"})

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(side_effect=Exception("no llm in test")),
            ):
                result = await threat_intel_analyst.analyze_threat_intel(
                    pkg["id"], run_id="run-1", phase="final"
                )

            assert result is not None
            assert "no matching events" in result["full_analysis"]["execution_findings"]

    @pytest.mark.asyncio
    async def test_default_phase_is_final_for_backward_compat(self, db_path: Path) -> None:
        """The on-demand POST .../threat-intel route calls analyze_threat_intel
        without a phase kwarg — must still default sensibly (final)."""
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"threat_actor": "APT1"})

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(side_effect=Exception("no llm in test")),
            ):
                result = await threat_intel_analyst.analyze_threat_intel(pkg["id"], run_id="run-1")

            assert result is not None
            assert result["full_analysis"]["phase"] == "final"

    @pytest.mark.asyncio
    async def test_step_log_records_phase(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"threat_actor": "APT1"})

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(side_effect=Exception("no llm in test")),
            ):
                await threat_intel_analyst.analyze_threat_intel(
                    pkg["id"], run_id="run-1", phase="preliminary"
                )

            run = await th_db.get_generation_run("run-1")
            # issue-local-022: distinct step id per phase (was a single
            # "threat_intel_analyst" name with a "[phase]" decision prefix).
            steps = [
                s
                for s in (run.get("step_logs") or [])
                if s.get("step") == "threat_intel_preliminary"
            ]
            assert len(steps) == 1


class TestRunConfigDecoding:
    @pytest.mark.asyncio
    async def test_get_generation_run_decodes_run_config(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(
                pkg["id"],
                "run-1",
                run_config={"include_threat_intel": False, "ioc_mode": "active_cleaning"},
            )
            run = await th_db.get_generation_run("run-1")
            assert isinstance(run["run_config"], dict)
            assert run["run_config"]["include_threat_intel"] is False


class TestCallSiteStructure:
    def test_runner_preliminary_call_gated_and_before_report(self) -> None:
        from backend.threat_hunting.agents import runner

        source = inspect.getsource(runner._run_pipeline)
        assert "analyze_threat_intel" in source
        assert 'phase="preliminary"' in source
        assert "include_threat_intel" in source
        assert source.index("analyze_threat_intel") < source.index("write_report(")

    def test_runner_preliminary_call_gated_on_awaiting_approval_not_completed(self) -> None:
        """issue-local-023: the preliminary call used to gate on
        final_status == "completed", which only happens on the RESUMED run
        after a human approves it — i.e. it ran AFTER approval, not before
        it, contradicting the "preliminary" naming and the pipeline
        diagrams (which already show threat_intel_preliminary positioned
        before approval_gate). Must gate on "awaiting_approval" instead —
        the point the pipeline first reaches the approval gate."""
        from backend.threat_hunting.agents import runner

        source = inspect.getsource(runner._run_pipeline)
        preliminary_idx = source.index('phase="preliminary"')
        # Walk backward from the preliminary call to its own `if` gate,
        # not report_writer's separate final_status == "completed" block.
        gate_start = source.rindex("if final_status ==", 0, preliminary_idx)
        gate_line = source[gate_start : source.index(":", gate_start)]
        assert '"awaiting_approval"' in gate_line
        assert '"completed"' not in gate_line

    def test_executor_final_call_gated_and_passes_phase(self) -> None:
        from backend.threat_hunting.siem import executor

        source = inspect.getsource(executor._run_execution)
        assert "analyze_threat_intel" in source
        assert 'phase="final"' in source
        assert "include_threat_intel" in source
