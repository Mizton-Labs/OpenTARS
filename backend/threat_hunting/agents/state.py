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

Fan-out concurrency (Phase 4+):
  ``intake_classifier`` fans out to ``threat_context_builder`` AND
  ``deep_retrohunt_planner`` in parallel.  Both branches read from the same
  state snapshot and each returns a *full* accumulated list for the lifecycle
  fields (completed_steps, step_logs, errors) and a string for current_step.
  Without reducer annotations LangGraph raises INVALID_CONCURRENT_GRAPH_UPDATE
  when both branches write the same key in the same step.

  The four lifecycle fields therefore use ``Annotated[T, reducer]`` so
  LangGraph knows how to merge concurrent updates:
    - current_step  — keep the last non-empty value
    - completed_steps — ordered union (dedup while preserving insertion order)
    - step_logs     — ordered union keyed on the 'step' field
    - errors        — ordered union (dedup by value)
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

# ── Reducer helpers ───────────────────────────────────────────────────────────


def _reduce_current_step(left: str, right: str) -> str:
    """Return the last non-empty step name."""
    return right if right else left


def _reduce_completed_steps(left: list[str], right: list[str]) -> list[str]:
    """Ordered union: keep all unique step names in first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in (left or []) + (right or []):
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _reduce_step_logs(
    left: list[dict[str, Any]], right: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Ordered union keyed on the 'step' field; last entry wins for a given step."""
    merged: dict[str, dict[str, Any]] = {}
    for entry in (left or []) + (right or []):
        key = entry.get("step", id(entry))
        merged[key] = entry
    return list(merged.values())


def _reduce_errors(left: list[str], right: list[str]) -> list[str]:
    """Ordered union of error strings; dedup while preserving insertion order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in (left or []) + (right or []):
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


class Hypothesis(TypedDict):
    id: str
    title: str
    description: str
    justification: str
    relevance: str  # 'high' | 'medium' | 'low'
    ioc_basis: list[str]  # IOC values that support this hypothesis
    # issue-006-E: specific tool/artifact/query/technical details for this hypothesis
    suggested_actions: list[str]


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


class SanitizedIOC(TypedDict):
    """A single IOC after deterministic sanitization."""

    ioc: str  # normalized IOC value (defanged notation removed, casing normalized)
    ioc_type: str  # canonical type string
    ioc_description: str
    noise_score: float  # 0.0–1.0; higher = noisier
    noise_reasons: list[str]  # human-readable reasons contributing to score
    search_token: str  # shortest search-ready token for SIEM queries


class DeepRetrohuntLead(TypedDict):
    """Output of the deep_retrohunt_planner node.

    Always generated when atomic IOCs are present.  Contains:
    - The sanitized / deduplicated IOC CSV (canonical format).
    - Per-IOC sanitization details for operator review.
    - An LLM-generated SPL macro draft.
    - A plain-text search hint for non-Splunk SIEMs.
    - Statistics about noisy IOCs flagged for review.
    """

    sanitized_iocs: list[SanitizedIOC]  # deduplicated, noise-scored
    ioc_csv: str  # canonical CSV (ioc,ioc_type,ioc_description)
    total_ioc_count: int
    noisy_ioc_count: int  # IOCs with noise_score >= 0.5
    high_noise_ioc_count: int  # IOCs with noise_score >= 0.8
    spl_draft: str  # Splunk SPL macro draft
    spl_macro_name: str  # suggested macro name e.g. threathunt_ioc_<hunt_id>
    search_hint: str  # plain-language hunt scope for non-SPL SIEMs
    analyst_notes: str  # LLM-generated notes on sanitization decisions
    llm_parse_error: bool  # True if LLM step failed (deterministic output still present)


class HuntPipelineState(TypedDict, total=False):
    # ── Inputs ────────────────────────────────────────────────────────────────
    hunt_package_id: str
    provider_name: str | None  # override LLM provider; None = use default
    model_name: str | None  # override model; None = provider default
    research_effort: str  # 'high' | 'medium' | 'low' (default 'medium')

    # ── Evidence summary (set by intake_classifier) ───────────────────────────
    evidence_text_corpus: str  # concatenated extracted text from all evidence
    ioc_summary: IOCSummary  # counts + sample IOCs for prompt context
    raw_ioc_list: list[dict[str, Any]]  # full extracted IOC list

    # ── Generated outputs ─────────────────────────────────────────────────────
    threat_context: dict[str, Any]  # set by threat_context_builder
    hypotheses: list[Hypothesis]  # set by hypothesis_generator
    hunting_leads: list[HuntingLead]  # set by hunting_lead_planner
    deep_retrohunt: DeepRetrohuntLead | None  # set by deep_retrohunt_planner
    ttp_analysis: BehavioralTTPAnalysis  # set by ttp_analyst
    query_drafts: list[QueryDraft]  # set by query_drafting_agent

    # ── Approval gate ─────────────────────────────────────────────────────────
    approved: bool  # set externally via API; False = pipeline paused
    approval_notes: str  # operator notes on approval/rejection
    rejected: bool  # True when operator explicitly rejects

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    # Annotated reducers allow concurrent fan-out branches to write these keys
    # simultaneously without triggering INVALID_CONCURRENT_GRAPH_UPDATE.
    current_step: Annotated[str, _reduce_current_step]
    completed_steps: Annotated[list[str], _reduce_completed_steps]
    errors: Annotated[list[str], _reduce_errors]
    step_logs: Annotated[list[dict[str, Any]], _reduce_step_logs]
    generation_status: (
        str  # 'running' | 'awaiting_approval' | 'approved' | 'rejected' | 'completed' | 'error'
    )
