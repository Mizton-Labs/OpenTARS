"""
LangGraph pipeline state for the Threat Hunting agent workflow.

The ``HuntPipelineState`` TypedDict is the single shared state object that
flows through every node in the LangGraph directed graph.  Each node reads
what it needs and writes back its outputs — LangGraph merges the updates
between nodes.

Design principles:
  - All fields are Optional so partial state is valid at any pipeline step.
  - Lists are accumulated (append-style); dicts are replaced on each update.
  - ``errors`` and ``step_logs`` accumulate across all nodes for auditability.
  - ``current_step`` tracks which node last ran for progress reporting.
  - The ``approved`` flag is set by the operator via the approval API; the
    graph checks it at the approval gate node to decide whether to continue.
"""

from __future__ import annotations

from typing import Any, TypedDict


class Hypothesis(TypedDict):
    id: str
    title: str
    description: str
    justification: str
    relevance: str  # 'high' | 'medium' | 'low'
    ioc_basis: list[str]  # IOC values that support this hypothesis


class HuntTask(TypedDict):
    id: str
    title: str
    description: str
    datasource: str
    query_hint: str


class HuntingLead(TypedDict):
    id: str
    hypothesis_id: str
    title: str
    description: str
    tasks: list[HuntTask]
    priority: str  # 'high' | 'medium' | 'low'


class TTPTechnique(TypedDict):
    technique_id: str  # e.g. T1059.001
    technique_name: str
    tactic: str
    description: str
    evidence_basis: str


class BehavioralTTPAnalysis(TypedDict):
    summary: str
    techniques: list[TTPTechnique]
    detection_opportunities: list[str]


class QueryDraft(TypedDict):
    id: str
    language: str  # 'spl' | 'kql' | 'eql' | 'cql' | 'es_dsl'
    title: str
    description: str
    query: str
    data_sources: list[str]
    lead_id: str | None  # links back to a HuntingLead


class IOCSummary(TypedDict):
    total: int
    by_type: dict[str, int]
    noisy_count: int
    sample: list[dict[str, Any]]  # first N IOCs for context


class HuntPipelineState(TypedDict, total=False):
    # ── Inputs ────────────────────────────────────────────────────────────────
    hunt_package_id: str
    provider_name: str | None  # override LLM provider; None = use default
    model_name: str | None  # override model; None = provider default

    # ── Evidence summary (set by intake_classifier) ───────────────────────────
    evidence_text_corpus: str  # concatenated extracted text from all evidence
    ioc_summary: IOCSummary  # counts + sample IOCs for prompt context
    raw_ioc_list: list[dict[str, Any]]  # full extracted IOC list

    # ── Generated outputs ─────────────────────────────────────────────────────
    threat_context: dict[str, Any]  # set by threat_context_builder
    hypotheses: list[Hypothesis]  # set by hypothesis_generator
    hunting_leads: list[HuntingLead]  # set by hunting_lead_planner
    ttp_analysis: BehavioralTTPAnalysis  # set by ttp_analyst
    query_drafts: list[QueryDraft]  # set by query_drafting_agent

    # ── Approval gate ─────────────────────────────────────────────────────────
    approved: bool  # set externally via API; False = pipeline paused
    approval_notes: str  # operator notes on approval/rejection
    rejected: bool  # True when operator explicitly rejects

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    current_step: str  # last completed node name
    completed_steps: list[str]  # all completed node names in order
    errors: list[str]  # accumulated errors (non-fatal)
    step_logs: list[dict[str, Any]]  # per-step timing and status records
    generation_status: (
        str  # 'running' | 'awaiting_approval' | 'approved' | 'rejected' | 'completed' | 'error'
    )
