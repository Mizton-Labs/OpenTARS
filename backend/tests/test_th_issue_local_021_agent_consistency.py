"""
Tests for issue-local-021 Part C: agent consistency audit — nodes that
previously emitted zero debug_lines (ttp_analyst, hypothesis_generator,
hunting_lead_planner, report_writer, threat_intel_analyst, comparison_analyst)
now populate them, so WorkflowVisualizer.tsx's per-run "Pipeline Log" debug
console isn't half-empty.
"""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, patch

import pytest


class TestTtpAnalystDebugLines:
    @pytest.mark.asyncio
    async def test_success_path_populates_debug_lines(self) -> None:
        from backend.threat_hunting.agents.nodes.ttp_analyst import ttp_analyst

        response = (
            '{"summary":"s","techniques":[{"technique_id":"T1059"}],"detection_opportunities":[]}'
        )
        with patch(
            "backend.threat_hunting.agents.nodes.ttp_analyst.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await ttp_analyst({"threat_context": {}, "hypotheses": []})

        step_log = result["step_logs"][-1]
        assert step_log["debug_lines"]
        assert any("LLM_CALL" in line for line in step_log["debug_lines"])
        assert any("LLM_RESPONSE" in line for line in step_log["debug_lines"])

    @pytest.mark.asyncio
    async def test_error_path_populates_debug_lines(self) -> None:
        from backend.threat_hunting.agents.nodes.ttp_analyst import ttp_analyst

        with patch(
            "backend.threat_hunting.agents.nodes.ttp_analyst.call_llm",
            new=AsyncMock(side_effect=Exception("boom")),
        ):
            result = await ttp_analyst({"threat_context": {}, "hypotheses": []})

        step_log = result["step_logs"][-1]
        assert step_log["status"] == "error"
        assert any("LLM_ERROR" in line for line in step_log["debug_lines"])


class TestHypothesisGeneratorDebugLines:
    @pytest.mark.asyncio
    async def test_success_path_populates_debug_lines(self) -> None:
        from backend.threat_hunting.agents.nodes.hypothesis_generator import hypothesis_generator

        response = '[{"id":"H1","title":"t","description":"d","relevance":"high"}]'
        with patch(
            "backend.threat_hunting.agents.nodes.hypothesis_generator.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await hypothesis_generator(
                {"threat_context": {}, "ioc_summary": {}, "research_effort": "medium"}
            )

        step_log = result["step_logs"][-1]
        assert step_log["debug_lines"]
        assert any("1 hypothesis(es) parsed" in line for line in step_log["debug_lines"])


class TestHuntingLeadPlannerDebugLines:
    @pytest.mark.asyncio
    async def test_success_path_populates_debug_lines(self) -> None:
        from backend.threat_hunting.agents.nodes.hunting_lead_planner import hunting_lead_planner

        response = '[{"id":"L1","hypothesis_id":"H1","title":"t","tasks":[]}]'
        with patch(
            "backend.threat_hunting.agents.nodes.hunting_lead_planner.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await hunting_lead_planner(
                {"threat_context": {}, "hypotheses": [], "research_effort": "medium"}
            )

        step_log = result["step_logs"][-1]
        assert step_log["debug_lines"]
        assert any("1 hunting lead(s) parsed" in line for line in step_log["debug_lines"])


class TestThreatIntelAnalystDebugLines:
    @pytest.mark.asyncio
    async def test_llm_failure_records_debug_line(self, tmp_path) -> None:
        import json

        import aiosqlite

        from backend.threat_hunting import db as th_db
        from backend.threat_hunting.agents.nodes import threat_intel_analyst

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, threat_context, "
                    "created_at) VALUES (?,?,?,?)",
                    ("run-1", pkg["id"], json.dumps({"threat_actor": "X"}), "2026-01-01T00:00:00Z"),
                )
                await db.commit()

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(side_effect=Exception("down")),
            ):
                await threat_intel_analyst.analyze_threat_intel(pkg["id"], run_id="run-1")

            run = await th_db.get_generation_run("run-1")
            # issue-local-022: step id now includes the phase (default "final").
            steps = [
                s for s in (run.get("step_logs") or []) if s.get("step") == "threat_intel_final"
            ]
            assert len(steps) == 1
            assert any("LLM_ERROR" in line for line in steps[0]["debug_lines"])


class TestReportWriterDebugLinesStructure:
    def test_report_step_log_accepts_debug_lines_param(self) -> None:
        from backend.threat_hunting.agents.nodes.report_writer import _report_step_log

        sig = inspect.signature(_report_step_log)
        assert "debug_lines" in sig.parameters

    def test_write_report_source_records_llm_fallback_debug_lines(self) -> None:
        from backend.threat_hunting.agents.nodes.report_writer import write_report

        source = inspect.getsource(write_report)
        assert "fallback_debug" in source
        assert "LLM_DISABLED" in source
        assert "LLM_ERROR" in source


class TestNoLongerSilentNodes:
    """Structural guard: the 5 run-scoped nodes that previously emitted zero
    debug_lines must now reference the field. (comparison_analyst is
    intentionally excluded — it's package-level, not run-scoped, so it has
    no single run's step_logs to attach debug_lines to; see module comment.)"""

    @pytest.mark.parametrize(
        "module_path,attr",
        [
            ("backend.threat_hunting.agents.nodes.ttp_analyst", "ttp_analyst"),
            ("backend.threat_hunting.agents.nodes.hypothesis_generator", "hypothesis_generator"),
            ("backend.threat_hunting.agents.nodes.hunting_lead_planner", "hunting_lead_planner"),
            ("backend.threat_hunting.agents.nodes.report_writer", "write_report"),
            ("backend.threat_hunting.agents.nodes.threat_intel_analyst", "analyze_threat_intel"),
        ],
    )
    def test_module_references_debug_lines(self, module_path: str, attr: str) -> None:
        import importlib

        module = importlib.import_module(module_path)
        source = inspect.getsource(module)
        assert "debug_lines" in source, f"{module_path} still has no debug_lines"
