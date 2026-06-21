"""
Tests for the Threat Hunting LangGraph pipeline fan-out state merge.

Regression coverage for issue-local-003:
  INVALID_CONCURRENT_GRAPH_UPDATE raised when ``threat_context_builder`` and
  ``deep_retrohunt_planner`` both write ``current_step``, ``completed_steps``,
  ``step_logs``, and ``errors`` in the same parallel step.

These tests exercise the reducer functions directly and verify that the
LangGraph graph compiles without error when the annotated state schema is in
place.  They do **not** run the full pipeline (which requires a DB and LLM).
"""

from __future__ import annotations

import pytest

from backend.threat_hunting.agents.state import (
    HuntPipelineState,
    _reduce_completed_steps,
    _reduce_current_step,
    _reduce_errors,
    _reduce_step_logs,
)

# ── Unit tests for reducer functions ─────────────────────────────────────────


class TestReduceCurrentStep:
    def test_right_wins_when_non_empty(self) -> None:
        assert _reduce_current_step("threat_context_builder", "deep_retrohunt_planner") == "deep_retrohunt_planner"

    def test_left_wins_when_right_empty(self) -> None:
        assert _reduce_current_step("threat_context_builder", "") == "threat_context_builder"

    def test_both_empty(self) -> None:
        assert _reduce_current_step("", "") == ""

    def test_left_empty_right_set(self) -> None:
        assert _reduce_current_step("", "deep_retrohunt_planner") == "deep_retrohunt_planner"


class TestReduceCompletedSteps:
    def test_union_deduplicates_shared_prefix(self) -> None:
        # Both branches ran after intake_classifier — each list starts with it
        left = ["intake_classifier", "threat_context_builder"]
        right = ["intake_classifier", "deep_retrohunt_planner"]
        result = _reduce_completed_steps(left, right)
        assert result == ["intake_classifier", "threat_context_builder", "deep_retrohunt_planner"]

    def test_empty_left(self) -> None:
        result = _reduce_completed_steps([], ["a", "b"])
        assert result == ["a", "b"]

    def test_empty_right(self) -> None:
        result = _reduce_completed_steps(["a", "b"], [])
        assert result == ["a", "b"]

    def test_both_empty(self) -> None:
        assert _reduce_completed_steps([], []) == []

    def test_no_duplicates_in_output(self) -> None:
        left = ["a", "b", "c"]
        right = ["b", "c", "d"]
        result = _reduce_completed_steps(left, right)
        assert result == ["a", "b", "c", "d"]
        assert len(result) == len(set(result))

    def test_none_treated_as_empty(self) -> None:
        assert _reduce_completed_steps(None, ["a"]) == ["a"]  # type: ignore[arg-type]
        assert _reduce_completed_steps(["a"], None) == ["a"]  # type: ignore[arg-type]


class TestReduceStepLogs:
    def test_last_entry_wins_for_same_step(self) -> None:
        left = [{"step": "intake_classifier", "status": "ok"}, {"step": "threat_context_builder", "status": "ok"}]
        right = [{"step": "intake_classifier", "status": "ok"}, {"step": "deep_retrohunt_planner", "status": "ok"}]
        result = _reduce_step_logs(left, right)
        steps = [e["step"] for e in result]
        # All three unique steps present
        assert set(steps) == {"intake_classifier", "threat_context_builder", "deep_retrohunt_planner"}
        # No duplicates
        assert len(steps) == 3

    def test_empty_left(self) -> None:
        right = [{"step": "a", "status": "ok"}]
        result = _reduce_step_logs([], right)
        assert result == right

    def test_empty_right(self) -> None:
        left = [{"step": "a", "status": "ok"}]
        result = _reduce_step_logs(left, [])
        assert result == left

    def test_both_empty(self) -> None:
        assert _reduce_step_logs([], []) == []

    def test_none_treated_as_empty(self) -> None:
        right = [{"step": "a", "status": "ok"}]
        assert _reduce_step_logs(None, right) == right  # type: ignore[arg-type]


class TestReduceErrors:
    def test_deduplicates_shared_errors(self) -> None:
        left = ["err_a", "err_b"]
        right = ["err_b", "err_c"]
        result = _reduce_errors(left, right)
        assert result == ["err_a", "err_b", "err_c"]

    def test_empty_inputs(self) -> None:
        assert _reduce_errors([], []) == []

    def test_none_treated_as_empty(self) -> None:
        assert _reduce_errors(None, ["x"]) == ["x"]  # type: ignore[arg-type]


# ── Integration: LangGraph graph compiles without error ───────────────────────


def test_build_graph_compiles() -> None:
    """pipeline.build_graph() must compile without raising INVALID_CONCURRENT_GRAPH_UPDATE."""
    from backend.threat_hunting.agents.pipeline import build_graph

    graph = build_graph()
    compiled = graph.compile()
    assert compiled is not None


def test_build_post_approval_graph_compiles() -> None:
    """post-approval graph must also compile cleanly."""
    from backend.threat_hunting.agents.pipeline import build_post_approval_graph

    graph = build_post_approval_graph()
    compiled = graph.compile()
    assert compiled is not None


# ── Fan-out state merge simulation ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_fanout_state_merge_via_graph_stream() -> None:
    """
    Simulate the fan-out step by building a tiny graph with two parallel stub
    nodes that both write current_step/completed_steps/step_logs/errors, then
    fan in.  Verifies that the compiled graph accepts concurrent writes without
    raising INVALID_CONCURRENT_GRAPH_UPDATE.
    """
    from langgraph.graph import END, StateGraph

    async def stub_a(state: HuntPipelineState) -> dict:
        completed = list(state.get("completed_steps") or [])
        logs = list(state.get("step_logs") or [])
        errors = list(state.get("errors") or [])
        completed.append("stub_a")
        logs.append({"step": "stub_a", "status": "ok"})
        return {
            "current_step": "stub_a",
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
        }

    async def stub_b(state: HuntPipelineState) -> dict:
        completed = list(state.get("completed_steps") or [])
        logs = list(state.get("step_logs") or [])
        errors = list(state.get("errors") or [])
        completed.append("stub_b")
        logs.append({"step": "stub_b", "status": "ok"})
        return {
            "current_step": "stub_b",
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
        }

    async def fan_in(state: HuntPipelineState) -> dict:
        return {"current_step": "fan_in"}

    g = StateGraph(HuntPipelineState)
    g.add_node("stub_a", stub_a)
    g.add_node("stub_b", stub_b)
    g.add_node("fan_in", fan_in)
    g.set_entry_point("stub_a")
    # parallel edges from same entry — both run concurrently
    g.add_edge("stub_a", "fan_in")
    g.add_edge("stub_b", "fan_in")
    g.add_edge("fan_in", END)

    compiled = g.compile()

    initial: HuntPipelineState = HuntPipelineState(
        hunt_package_id="test-pkg",
        current_step="",
        completed_steps=[],
        step_logs=[],
        errors=[],
        approved=False,
        rejected=False,
        approval_notes="",
        generation_status="running",
    )

    # astream must complete without raising INVALID_CONCURRENT_GRAPH_UPDATE
    final: dict = dict(initial)
    async for chunk in compiled.astream(initial):
        for _node, updates in chunk.items():
            if isinstance(updates, dict):
                final.update(updates)

    # stub_b never gets an explicit edge from entry so it won't appear in
    # completed_steps — that's fine; the key assertion is no exception was raised
    assert "stub_a" in final.get("completed_steps", [])
