"""Recommendation-synthesis run (issue-local-040).

The Comparison Assessment's "Recommended Combination" card already offers
three re-run actions (issue-local-035) — but all three clone into a BRAND
NEW hunt package and simply paste the comparison's raw recommendation text
in as one evidence item. issue-local-040 adds a fourth action, "Create a new
run from recommendations", that instead:

  1. Reads each compared run's ACTUAL hypotheses/TTPs/hunting leads/query
     drafts (not just the comparison report's summary-level diff table).
  2. Asks the LLM to synthesize ONE consolidated hunt plan combining the
     best approach from each, with consistent coverage (not just concatenate
     the comparison's own free-text `recommended_combination`).
  3. Injects that synthesized plan as a new evidence item on the SAME hunt
     package (not a clone) and starts a new run there, tagged
     run_origin='consolidated' — this is what backs the Hunt Packages page's
     "Consolidated Runs" sub-tab.
"""

from __future__ import annotations

from typing import Any

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm
from backend.threat_hunting.agents.logging_utils import get_run_logger

#: Detailed context is expensive (full hypotheses/TTPs/leads/queries per
#: run) — cap how many compared runs get the full treatment, same rationale
#: and same cap as comparison_analyst._MAX_DETAILED_RUNS.
_MAX_DETAILED_RUNS = 6

_SYSTEM_PROMPT = (
    "You are the Threat Hunting Recommendation Synthesizer for OpenTARS. You combine the "
    "outputs of several completed hunt runs (each analyzed the same evidence with a different "
    "LLM model or effort level) into ONE consolidated hunt execution plan. You never invent "
    "hypotheses, techniques, leads or queries that are not grounded in what the source runs "
    "actually produced — your job is to combine and de-duplicate, not to imagine new findings."
)

_OUTPUT_FORMAT = (
    "Plain text (NOT JSON, NOT markdown code fences) — a short paragraph naming the source "
    "models and what was combined, followed by clearly labeled sections: Hypotheses, "
    "Techniques/TTPs, Hunting Leads, Query Approaches. Each section should list the combined, "
    "de-duplicated items to pursue, briefly noting which source run(s) they come from when it "
    "adds useful context."
)


def _kept_ioc_csv(ioc_overview: list[dict], run_ids: set[str]) -> str:
    """Build the canonical IOC CSV from a comparison's ioc_overview, limited
    to occurrences within *run_ids* and kept (non-'remove') in at least one
    of them. Mirrors routes_threat_hunting._kept_ioc_csv_for_runs — kept as a
    local copy rather than importing from the routes module, which should
    depend on this agents package, not the other way around."""
    from backend.threat_hunting.agents.nodes.deep_retrohunt_planner import _build_ioc_csv

    sanitized = []
    for row in ioc_overview:
        occurrences = [o for o in (row.get("occurrences") or []) if o.get("run_id") in run_ids]
        if not occurrences:
            continue
        if any(o.get("verdict") != "remove" for o in occurrences):
            sanitized.append(
                {
                    "ioc": row.get("ioc", ""),
                    "ioc_type": row.get("ioc_type", ""),
                    "ioc_description": "",
                }
            )
    return _build_ioc_csv(sanitized)


async def _gather_run_context(run_ids: list[str]) -> list[tuple[str, str]]:
    """Build one (label, text) context section per compared run, reading its
    actual hypotheses/TTPs/hunting leads/query drafts — not just the
    comparison report's summary-level diff table row."""
    sections: list[tuple[str, str]] = []
    for run_id in run_ids[:_MAX_DETAILED_RUNS]:
        record = await th_db.get_generation_run(run_id)
        if not record:
            continue
        label = record.get("run_id_display") or run_id[:8]
        hyp_lines = "; ".join(
            f"{h.get('title', '')} ({h.get('relevance', '')}): {str(h.get('description', ''))[:200]}"
            for h in (record.get("hypotheses") or [])[:8]
        )
        techniques = ", ".join(
            f"{t.get('technique_id', '')} {t.get('technique_name', '')}"
            for t in ((record.get("ttp_analysis") or {}).get("techniques") or [])[:8]
        )
        leads = "; ".join(
            str(lead.get("title", "")) for lead in (record.get("hunting_leads") or [])[:8]
        )
        queries = "; ".join(
            f"{q.get('language', '')}: {str(q.get('query', ''))[:200]}"
            for q in (record.get("query_drafts") or [])[:6]
        )
        text = (
            f"model={record.get('llm_model', '')}, "
            f"hypotheses=[{hyp_lines or 'none'}], "
            f"techniques=[{techniques or 'none'}], "
            f"hunting_leads=[{leads or 'none'}], "
            f"query_drafts=[{queries or 'none'}]"
        )
        sections.append((f"Run {label}", text))
    return sections


async def synthesize_recommendation_run(
    hunt_package_id: str,
    *,
    phase: str = "preliminary",
    run_ids: list[str] | None = None,
    provider_name: str | None = None,
    model_name: str | None = None,
    research_effort: str | None = None,
    created_by: str | None = None,
    playbook_id: str | None = None,
    playbook_name: str | None = None,
    auto_approve: bool = False,
) -> dict[str, Any]:
    """Synthesize a consolidated hunt plan from the latest comparison report
    of *phase* and start a new IN-PACKAGE run seeded from it.

    *run_ids*, when given, narrows synthesis to that subset of the
    comparison's compared runs (mirrors the existing rerun buttons' "with
    selected runs" option); None uses every run the comparison covered.

    Raises ValueError if no comparison report of *phase* exists yet, or it
    covers no runs (narrowed to none by *run_ids*).
    """
    log = get_run_logger(__name__, hunt_package_id, None)

    report = await th_db.get_latest_comparison_report(hunt_package_id, phase=phase)
    if report is None:
        raise ValueError(f"No {phase} comparison report to synthesize a run from.")

    full_report = report.get("full_report") or {}
    compared_run_ids = full_report.get("compared_run_ids") or []
    wanted_run_ids = (
        [r for r in compared_run_ids if r in set(run_ids)]
        if run_ids is not None
        else list(compared_run_ids)
    )
    if not wanted_run_ids:
        raise ValueError("No runs to synthesize a recommendation from.")

    diff_table = full_report.get("diff_table") or []
    models_used = sorted(
        {row.get("model") for row in diff_table if row.get("run_id") in wanted_run_ids and row.get("model")}
    )
    recommendation_text = full_report.get("recommended_combination") or ""
    context_sections = await _gather_run_context(wanted_run_ids)

    try:
        system, user = build_prompt(
            system=_SYSTEM_PROMPT,
            task_description=(
                f"Synthesize ONE consolidated hunt execution plan from these "
                f"{len(context_sections)} run(s) of the same hunt package "
                f"({', '.join(models_used) or 'unspecified models'}). Combine the best "
                "hypotheses, techniques, hunting leads and query approaches into a single "
                "coherent plan with consistent coverage — avoid redundancy, and where runs "
                "disagree, prefer the more specific or better-supported approach."
            ),
            context_sections=context_sections,
            output_format=_OUTPUT_FORMAT,
            additional_instructions=(
                f"The comparison assessment's own recommendation, for reference: "
                f"{recommendation_text or '(none was generated)'}"
            ),
            json_output=False,
        )
        synthesized_text = await call_llm(
            user,
            system=system,
            provider_name=provider_name,
            model=model_name,
            max_tokens=2000,
        )
    except Exception as exc:  # noqa: BLE001 — soft-fail, same convention as comparison_analyst
        from backend.llm.errors import LLMDisabledError

        if isinstance(exc, LLMDisabledError):
            log.info(
                "recommendation_synthesizer: LLM disabled — falling back to the raw "
                "comparison recommendation"
            )
        else:
            log.warning("recommendation_synthesizer: LLM synthesis failed (non-fatal): %s", exc)
        synthesized_text = (
            "(LLM synthesis was unavailable — using the comparison assessment's own "
            f"recommendation as-is)\n\n{recommendation_text or 'No narrative recommendation was available.'}"
        )

    ioc_csv = _kept_ioc_csv(full_report.get("ioc_overview") or [], set(wanted_run_ids))
    evidence_block = (
        f"Consolidated hunt plan synthesized from {len(wanted_run_ids)} run(s) "
        f"({', '.join(models_used) or 'unspecified models'}) of this hunt package's "
        f"Comparison Assessment ({phase} phase):\n\n"
        f"{synthesized_text}\n\n"
        f"Kept IOCs from the compared run(s):\n{ioc_csv or '(no kept IOCs)'}"
    )
    await th_db.add_evidence_item(
        hunt_package_id,
        item_type="text",
        label="Consolidated plan (from comparison recommendations)",
        extracted_text=evidence_block,
        parse_status="ok",
        provenance_notes=(
            "issue-local-040: auto-generated from a Comparison Assessment's recommendations."
        ),
    )

    from backend.config.loader import load_th_research_effort
    from backend.threat_hunting.agents.runner import start_generation

    effort = research_effort or load_th_research_effort()
    run_record = await start_generation(
        hunt_package_id,
        provider_name=provider_name,
        model_name=model_name,
        research_effort=effort,
        run_config={},
        created_by=created_by,
        playbook_id=playbook_id,
        playbook_name=playbook_name,
        run_origin="consolidated",
        auto_approve=auto_approve,
    )
    log.info(
        "recommendation_synthesizer: seeded consolidated run %s from %d compared run(s)",
        run_record.get("run_id", "")[:8],
        len(wanted_run_ids),
    )
    return run_record
