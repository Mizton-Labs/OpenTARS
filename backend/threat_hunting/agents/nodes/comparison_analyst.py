"""Threat Hunt Comparison Analyst (issue-local-020).

**Not a LangGraph node** — a plain async function, called synchronously from
`POST /packages/{pkg_id}/compare` in `routes_threat_hunting.py`. Compares ALL
generation runs of one hunt package (regardless of run status) and produces a
comparison report: a deterministic per-run diff table plus an LLM-generated
narrative (key differences, gaps, enrichment opportunities, a recommendation
for combining data across runs).

Persisted via `backend.threat_hunting.db.create_comparison_report`, which
reuses the `hunt_reports` table with a `report_kind: "comparison"`
discriminator (see db.py's "Comparison reports" section for why).

issue-local-021 agent-consistency note: unlike every other node in this
package, this function intentionally does NOT emit `debug_lines`/step_logs.
`append_run_step_log` is scoped to a single run_id, but a comparison spans
MULTIPLE runs at once — there is no single run's "Pipeline Log" console this
belongs in. LLM failures still soft-fail into `log.warning(...)` (captured in
app.log) and a deterministic fallback `summary`, matching this codebase's
error-visibility convention as closely as the package-level shape allows.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm, parse_json_response
from backend.threat_hunting.agents.logging_utils import get_run_logger

_OUTPUT_FORMAT = """{
  "summary": "...",
  "key_differences": ["...", "..."],
  "gaps": ["...", "..."],
  "enrichment_opportunities": ["...", "..."],
  "recommended_combination": "..."
}"""

_SYSTEM_PROMPT = (
    "You are a Threat Hunt analyst comparing multiple runs of the same hunt package. "
    "Identify meaningful differences between runs (not just noise), gaps where one run "
    "found something another missed, and concrete opportunities to enrich the hunt by "
    "combining data across runs. Do not fabricate findings not supported by the "
    "per-run data provided — when genuinely unsure, omit the item rather than inventing "
    "detail."
)

# Full narrative detail (hypotheses/TTPs/retrohunt summary) is only included
# in the LLM prompt for the most recent N runs — older runs get a one-line
# summary instead. Keeps prompt size bounded on packages with 10+ runs
# (matches report_writer.py's item-count-cap convention; this codebase has no
# token counting anywhere, only hardcoded char/item caps).
_MAX_DETAILED_RUNS = 3


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def compare_runs(
    hunt_package_id: str,
    *,
    run_ids: list[str] | None = None,
    provider_name: str | None = None,
    model_name: str | None = None,
    created_by: str | None = None,
) -> dict[str, Any]:
    """Compare runs of a hunt package and persist a comparison report.

    issue-local-021: *run_ids*, when provided, narrows the comparison to that
    subset of runs (the "Assess & Compare" dialog's run picker). ``None``
    (the default) compares every run, unchanged from issue-local-020.

    Raises ValueError if the package doesn't exist or has no (matching)
    runs — callers (the route) translate that into an HTTP 404/400.
    """
    log = get_run_logger(__name__, hunt_package_id, None)

    pkg = await th_db.get_hunt_package(hunt_package_id)
    if not pkg:
        raise ValueError(f"Hunt package {hunt_package_id!r} not found")

    runs_summary = await th_db.list_generation_runs(hunt_package_id)
    if run_ids is not None:
        wanted = set(run_ids)
        runs_summary = [r for r in runs_summary if r["id"] in wanted]
    if not runs_summary:
        raise ValueError("No runs to compare for this hunt package")

    full_records: dict[str, dict[str, Any]] = {}
    for run in runs_summary:
        record = await th_db.get_generation_run(run["id"])
        if record:
            full_records[run["id"]] = record

    # ── Deterministic per-run diff table (no LLM) ────────────────────────────
    diff_rows: list[dict[str, Any]] = []
    for run in runs_summary:
        record = full_records.get(run["id"]) or {}
        hypotheses = record.get("hypotheses") or []
        ttp_analysis = record.get("ttp_analysis") or {}
        task_results = await th_db.list_task_results_by_run(run["id"])
        event_count = sum(len(r.get("raw_result") or []) for r in task_results)
        diff_rows.append(
            {
                "run_id": run["id"],
                "run_id_display": run.get("run_id_display", ""),
                "model": run.get("llm_model", ""),
                "effort": run.get("research_effort", ""),
                "status": run.get("generation_status", ""),
                "hypothesis_count": len(hypotheses),
                "sanitized_ioc_count": run.get("sanitized_ioc_count", 0),
                "removed_ioc_count": run.get("removed_ioc_count", 0),
                "technique_count": len(ttp_analysis.get("techniques") or []),
                "event_count": event_count,
                "created_at": run.get("created_at", ""),
            }
        )

    # ── LLM enrichment — soft-fail, the diff table above is still persisted ──
    summary = ""
    key_differences: list[str] = []
    gaps: list[str] = []
    enrichment_opportunities: list[str] = []
    recommended_combination = ""
    try:
        context_sections: list[tuple[str, str]] = []
        for idx, run in enumerate(runs_summary):
            record = full_records.get(run["id"]) or {}
            label = run.get("run_id_display") or run["id"][:8]
            threat_context = record.get("threat_context") or {}
            if idx < _MAX_DETAILED_RUNS:
                hyp_lines = "; ".join(
                    f"[{h.get('id', '')}] {h.get('title', '')} ({h.get('relevance', '')})"
                    for h in (record.get("hypotheses") or [])[:5]
                )
                techniques = ", ".join(
                    f"{t.get('technique_id', '')} {t.get('technique_name', '')}"
                    for t in ((record.get("ttp_analysis") or {}).get("techniques") or [])[:6]
                )
                retro = record.get("deep_retrohunt") or {}
                text = (
                    f"status={run.get('generation_status', '')}, model={run.get('llm_model', '')}, "
                    f"threat_summary={str(threat_context.get('summary', ''))[:500]}, "
                    f"hypotheses=[{hyp_lines or 'none'}], techniques=[{techniques or 'none'}], "
                    f"iocs={retro.get('total_ioc_count', 0)} total/"
                    f"{retro.get('noisy_ioc_count', 0)} noisy"
                )
            else:
                text = (
                    f"status={run.get('generation_status', '')}, model={run.get('llm_model', '')}, "
                    f"threat_summary={str(threat_context.get('summary', ''))[:200]}, "
                    f"sanitized_iocs={run.get('sanitized_ioc_count', 0)}, "
                    f"removed_iocs={run.get('removed_ioc_count', 0)}"
                )
            context_sections.append((f"Run {label}", text))

        system, user = build_prompt(
            system=_SYSTEM_PROMPT,
            task_description=(
                f"Compare these {len(runs_summary)} run(s) of the same hunt package and identify "
                "meaningful differences, gaps, and enrichment opportunities."
            ),
            context_sections=context_sections,
            output_format=_OUTPUT_FORMAT,
            additional_instructions=(
                "If only one run exists, note that no comparison is possible yet and "
                "summarize that single run instead. Do not invent differences that aren't "
                "supported by the data above."
            ),
        )
        response = await call_llm(
            user,
            system=system,
            provider_name=provider_name,
            model=model_name,
            max_tokens=2000,
        )
        parsed = parse_json_response(response, context="comparison_analyst")
        if isinstance(parsed, dict):
            summary = str(parsed.get("summary") or "")
            key_differences = list(parsed.get("key_differences") or [])
            gaps = list(parsed.get("gaps") or [])
            enrichment_opportunities = list(parsed.get("enrichment_opportunities") or [])
            recommended_combination = str(parsed.get("recommended_combination") or "")
    except Exception as exc:  # noqa: BLE001
        from backend.llm.errors import LLMDisabledError

        if isinstance(exc, LLMDisabledError):
            log.info("comparison_analyst: LLM disabled — using deterministic diff table only")
        else:
            log.warning("comparison_analyst: LLM enrichment failed (non-fatal): %s", exc)
        if not summary:
            summary = (
                f"Deterministic comparison of {len(runs_summary)} run(s). LLM-based analysis "
                "was unavailable — see the diff table below."
            )

    full_report: dict[str, Any] = {
        "hunt_name": pkg.get("name", ""),
        "hunt_id": pkg.get("id", ""),
        "hunt_id_display": pkg.get("hunt_id_display", ""),
        "compared_run_ids": [r["id"] for r in runs_summary],
        "generated_at": _utc_now(),
        "diff_table": diff_rows,
        "summary": summary,
        "key_differences": key_differences,
        "gaps": gaps,
        "enrichment_opportunities": enrichment_opportunities,
        "recommended_combination": recommended_combination,
    }

    # Pre-render markdown (mirrors write_report's _markdown convention) so the
    # download route doesn't need to re-render on every GET.
    try:
        from backend.threat_hunting.agents.nodes.report_writer import render_comparison_markdown

        full_report["_markdown"] = render_comparison_markdown(full_report)
    except Exception as exc:  # noqa: BLE001
        log.warning("comparison_analyst: markdown pre-render failed (non-fatal): %s", exc)

    report = await th_db.create_comparison_report(
        hunt_package_id,
        executive_summary=summary,
        full_report=full_report,
        created_by=created_by,
    )

    log.info(
        "comparison_analyst: compared %d run(s) for %s", len(runs_summary), hunt_package_id[:8]
    )
    return report
