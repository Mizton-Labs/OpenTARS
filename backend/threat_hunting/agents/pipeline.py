"""
LangGraph pipeline definition for the Threat Hunting agent workflow.

Graph topology:

  intake_classifier
        │
        ├──────────────────────────────────┐
        ▼                                  ▼
  threat_context_builder         deep_retrohunt_planner
        │                                  │
  hypothesis_generator           (joins at hypothesis_generator via fan-in)
        │
  hunting_lead_planner
        │
  ttp_analyst
        │
  query_drafting_agent
        │
  [approval gate — pipeline pauses here, resumes via API]
        │
  [complete]

Fan-out / fan-in:
  ``intake_classifier`` fans out to both ``threat_context_builder`` and
  ``deep_retrohunt_planner`` in parallel.  LangGraph merges both outputs
  before ``hypothesis_generator`` runs (fan-in at ``hypothesis_generator``).

Approval gate implementation:
  LangGraph does not have a built-in interrupt mechanism that persists across
  process restarts in our in-memory setup.  We implement the gate as a
  conditional edge: after ``query_drafting_agent`` the graph checks whether
  ``state["approved"]`` is True.  If not, the state is persisted to the DB
  and the pipeline exits returning status ``awaiting_approval``.  The runner
  resumes the pipeline (re-entering after the gate) when the operator calls
  the approve API.
"""

from __future__ import annotations

import logging

from langgraph.graph import END, StateGraph

from backend.threat_hunting.agents.nodes.deep_retrohunt_planner import deep_retrohunt_planner
from backend.threat_hunting.agents.nodes.hunting_lead_planner import hunting_lead_planner
from backend.threat_hunting.agents.nodes.hypothesis_generator import hypothesis_generator
from backend.threat_hunting.agents.nodes.intake_classifier import intake_classifier
from backend.threat_hunting.agents.nodes.query_drafting_agent import query_drafting_agent
from backend.threat_hunting.agents.nodes.threat_context_builder import threat_context_builder
from backend.threat_hunting.agents.nodes.ttp_analyst import ttp_analyst
from backend.threat_hunting.agents.state import HuntPipelineState

logger = logging.getLogger(__name__)


# ── Approval gate edge ────────────────────────────────────────────────────────


def _approval_gate(state: HuntPipelineState) -> str:
    """Conditional edge after query_drafting_agent.

    Returns:
      'approved'  — operator has approved the package → proceed to complete
      'rejected'  — operator has rejected → go to complete (with rejected status)
      'pending'   — waiting for operator → end this execution (will be resumed)
    """
    if state.get("rejected"):
        return "rejected"
    if state.get("approved"):
        return "approved"
    return "pending"


async def _mark_awaiting_approval(state: HuntPipelineState) -> dict:
    """Terminal node for the pending path — marks the pipeline as paused."""
    return {
        "generation_status": "awaiting_approval",
        "current_step": "approval_gate",
    }


async def _mark_completed(state: HuntPipelineState) -> dict:
    """Terminal node for the approved path."""
    return {
        "generation_status": "completed",
        "current_step": "complete",
    }


async def _mark_rejected(state: HuntPipelineState) -> dict:
    """Terminal node for the rejected path."""
    return {
        "generation_status": "rejected",
        "current_step": "complete",
    }


# ── Graph construction ────────────────────────────────────────────────────────


def build_graph() -> StateGraph:
    """Build and return the compiled LangGraph state graph."""
    graph = StateGraph(HuntPipelineState)

    # Add nodes
    graph.add_node("intake_classifier", intake_classifier)
    graph.add_node("threat_context_builder", threat_context_builder)
    graph.add_node("deep_retrohunt_planner", deep_retrohunt_planner)
    graph.add_node("hypothesis_generator", hypothesis_generator)
    graph.add_node("hunting_lead_planner", hunting_lead_planner)
    graph.add_node("ttp_analyst", ttp_analyst)
    graph.add_node("query_drafting_agent", query_drafting_agent)
    graph.add_node("awaiting_approval", _mark_awaiting_approval)
    graph.add_node("mark_completed", _mark_completed)
    graph.add_node("mark_rejected", _mark_rejected)

    # Entry point
    graph.set_entry_point("intake_classifier")

    # Fan-out: intake_classifier → threat_context_builder AND deep_retrohunt_planner (parallel)
    graph.add_edge("intake_classifier", "threat_context_builder")
    graph.add_edge("intake_classifier", "deep_retrohunt_planner")

    # Fan-in: both parallel branches must complete before hypothesis_generator
    graph.add_edge("threat_context_builder", "hypothesis_generator")
    graph.add_edge("deep_retrohunt_planner", "hypothesis_generator")

    # Remainder of pipeline
    graph.add_edge("hypothesis_generator", "hunting_lead_planner")
    graph.add_edge("hunting_lead_planner", "ttp_analyst")
    graph.add_edge("ttp_analyst", "query_drafting_agent")

    # Conditional edge at approval gate
    graph.add_conditional_edges(
        "query_drafting_agent",
        _approval_gate,
        {
            "pending": "awaiting_approval",
            "approved": "mark_completed",
            "rejected": "mark_rejected",
        },
    )

    # All terminal nodes go to END
    graph.add_edge("awaiting_approval", END)
    graph.add_edge("mark_completed", END)
    graph.add_edge("mark_rejected", END)

    return graph


# ── Compiled graph (singleton) ────────────────────────────────────────────────

_COMPILED_GRAPH = None


def get_compiled_graph():
    """Return the compiled graph, building it on first call."""
    global _COMPILED_GRAPH
    if _COMPILED_GRAPH is None:
        _COMPILED_GRAPH = build_graph().compile()
    return _COMPILED_GRAPH


# ── Resume graph (post-approval) ─────────────────────────────────────────────


def build_post_approval_graph() -> StateGraph:
    """Build a minimal graph for resuming after operator approval.

    This graph starts at query_drafting_agent and goes through the
    approval gate directly.  Used when the operator approves a package
    that was already in awaiting_approval status.
    """
    graph = StateGraph(HuntPipelineState)

    graph.add_node("query_drafting_agent", query_drafting_agent)
    graph.add_node("mark_completed", _mark_completed)
    graph.add_node("mark_rejected", _mark_rejected)
    graph.add_node("awaiting_approval", _mark_awaiting_approval)

    graph.set_entry_point("query_drafting_agent")
    graph.add_conditional_edges(
        "query_drafting_agent",
        _approval_gate,
        {
            "pending": "awaiting_approval",
            "approved": "mark_completed",
            "rejected": "mark_rejected",
        },
    )
    graph.add_edge("awaiting_approval", END)
    graph.add_edge("mark_completed", END)
    graph.add_edge("mark_rejected", END)

    return graph


_COMPILED_POST_APPROVAL_GRAPH = None


def get_post_approval_graph():
    global _COMPILED_POST_APPROVAL_GRAPH
    if _COMPILED_POST_APPROVAL_GRAPH is None:
        _COMPILED_POST_APPROVAL_GRAPH = build_post_approval_graph().compile()
    return _COMPILED_POST_APPROVAL_GRAPH


def build_initial_state(
    hunt_package_id: str,
    *,
    provider_name: str | None = None,
    model_name: str | None = None,
) -> HuntPipelineState:
    """Build the initial pipeline state for a new generation run."""
    return HuntPipelineState(
        hunt_package_id=hunt_package_id,
        provider_name=provider_name,
        model_name=model_name,
        approved=False,
        rejected=False,
        approval_notes="",
        errors=[],
        step_logs=[],
        completed_steps=[],
        current_step="",
        generation_status="running",
    )
