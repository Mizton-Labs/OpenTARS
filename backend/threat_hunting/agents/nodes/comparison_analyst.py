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


def _build_ioc_overview(
    runs_summary: list[dict[str, Any]],
    full_records: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deterministic, deduplicated cross-run IOC table (issue-local-026,
    consolidated in issue-local-035): every UNIQUE IOC found by any compared
    run, one row per (ioc_type, ioc) — not one row per (run, ioc) occurrence
    — with a per-run breakdown of which run/model extracted it, its verdict
    (kept/removed), and a confidence figure, plus the union of hypotheses
    referencing it across all runs.

    No LLM involved — everything here comes from already-computed, already-
    persisted per-run data:
      - verdict: the deep_retrohunt sanitization's own 'keep'/'remove' action,
        tracked per run (the same IOC can be kept in one run and removed in
        another — that disagreement is exactly what this table should surface,
        not hide behind a single collapsed verdict).
      - confidence: this schema has no per-IOC "confidence" field anywhere
        (SanitizedIOC only carries noise_score, a noise/quality signal, not a
        threat-confidence one). Rather than fabricate a number, confidence is
        derived from noise_score by inversion (lower noise = higher
        confidence) — a defensible proxy, not a fabricated value, and is
        documented as such via the field name below.
      - hypotheses: this schema's only IOC<->hypothesis link is
        Hypothesis.ioc_basis (a list of IOC value strings the hypothesis
        cites), so coverage is matched by exact IOC value against each run's
        hypotheses. An IOC not cited by any hypothesis' ioc_basis legitimately
        has an empty list here — that's not a gap in this function.
    """
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []

    for run in runs_summary:
        record = full_records.get(run["id"]) or {}
        deep_retrohunt = record.get("deep_retrohunt") or {}
        sanitized_iocs = deep_retrohunt.get("sanitized_iocs") or []
        hypotheses = record.get("hypotheses") or []
        for item in sanitized_iocs:
            if not isinstance(item, dict):
                continue
            ioc_value = item.get("ioc", "")
            ioc_type = item.get("ioc_type", "")
            key = (ioc_type, ioc_value)
            covering_hypotheses = [
                h.get("title") or h.get("id", "")
                for h in hypotheses
                if isinstance(h, dict) and ioc_value in (h.get("ioc_basis") or [])
            ]
            noise_score = item.get("noise_score")
            confidence_pct = (
                round((1 - noise_score) * 100) if isinstance(noise_score, (int, float)) else None
            )
            verdict = item.get("action") or "keep"

            if key not in grouped:
                order.append(key)
                grouped[key] = {
                    "ioc": ioc_value,
                    "ioc_type": ioc_type,
                    "occurrences": [],
                    "hypotheses": [],
                }
            entry = grouped[key]
            entry["occurrences"].append(
                {
                    "run_id": run["id"],
                    "run_id_display": run.get("run_id_display", ""),
                    "model": run.get("llm_model", ""),
                    # Derived from (1 - noise_score); None when the item
                    # predates noise scoring or noise_score is missing.
                    "confidence_pct": confidence_pct,
                    "verdict": verdict,
                }
            )
            for h in covering_hypotheses:
                if h not in entry["hypotheses"]:
                    entry["hypotheses"].append(h)

    rows: list[dict[str, Any]] = []
    for key in order:
        entry = grouped[key]
        occurrences = entry["occurrences"]
        kept = sum(1 for o in occurrences if o["verdict"] != "remove")
        removed = sum(1 for o in occurrences if o["verdict"] == "remove")
        if kept and removed:
            verdict_summary = f"kept in {kept}, removed in {removed}"
        elif removed:
            verdict_summary = f"removed in {removed}"
        else:
            verdict_summary = f"kept in {kept}"
        rows.append(
            {
                "ioc": entry["ioc"],
                "ioc_type": entry["ioc_type"],
                "run_count": len(occurrences),
                "verdict_summary": verdict_summary,
                "occurrences": occurrences,
                "hypotheses": entry["hypotheses"],
            }
        )
    return sorted(rows, key=lambda r: (r["ioc_type"], r["ioc"]))


async def compare_runs(
    hunt_package_id: str,
    *,
    run_ids: list[str] | None = None,
    provider_name: str | None = None,
    model_name: str | None = None,
    created_by: str | None = None,
    phase: str = "full",
    job_id: str | None = None,
) -> dict[str, Any]:
    """Compare runs of a hunt package and persist a comparison report.

    issue-local-021: *run_ids*, when provided, narrows the comparison to that
    subset of runs (the "Assess & Compare" dialog's run picker). ``None``
    (the default) compares every run, unchanged from issue-local-020.

    issue-local-035: *phase* selects which of the two independent comparison
    slots to write — "preliminary" (pre-SIEM-execution: threat context,
    hypotheses, TTPs, sanitized IOCs) or "full" (adds SIEM execution results,
    i.e. event counts). Preliminary comparisons always compare that
    pre-execution subset even for runs that have SINCE finished SIEM
    execution — this compares the *phase*, not "whatever a run's current
    status happens to be" — so re-running the Preliminary tab later stays
    reproducible instead of drifting as runs progress.

    issue-local-035 follow-up: *job_id*, when provided, is a
    `comparison_jobs` row this call reports progress to at each of its four
    stages (loading_runs/building_tables/generating_narrative/finalizing) —
    see routes_threat_hunting.py's `_run_comparison_job`, the only caller
    that passes one. ``None`` (direct calls, e.g. from tests) skips all
    progress reporting — behavior is otherwise identical either way.

    Raises ValueError if the package doesn't exist or has no (matching)
    runs — callers (the route) translate that into an HTTP 404/400.
    """
    if phase not in ("preliminary", "full"):
        raise ValueError(f"phase must be 'preliminary' or 'full', got {phase!r}")
    log = get_run_logger(__name__, hunt_package_id, None)

    async def _step(name: str) -> None:
        if job_id:
            await th_db.update_comparison_job(job_id, current_step=name)

    await _step("loading_runs")

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

    await _step("building_tables")

    # ── Deterministic per-run diff table (no LLM) ────────────────────────────
    diff_rows: list[dict[str, Any]] = []
    for run in runs_summary:
        record = full_records.get(run["id"]) or {}
        hypotheses = record.get("hypotheses") or []
        ttp_analysis = record.get("ttp_analysis") or {}
        # issue-local-035: event_count comes from SIEM execution results,
        # which is exactly the "full" vs "preliminary" boundary — omit it
        # (None, not 0) for preliminary comparisons rather than showing a
        # number that isn't part of that phase's scope.
        if phase == "full":
            task_results = await th_db.list_task_results_by_run(run["id"])
            event_count: int | None = sum(len(r.get("raw_result") or []) for r in task_results)
        else:
            event_count = None
        # sanitized_ioc_count/removed_ioc_count can be present but None
        # (no deep_retrohunt lead yet for this run) — coalesce, not just
        # .get(..., 0), since the key itself is always present.
        sanitized_ioc_count = run.get("sanitized_ioc_count") or 0
        removed_ioc_count = run.get("removed_ioc_count") or 0
        diff_rows.append(
            {
                "run_id": run["id"],
                "run_id_display": run.get("run_id_display", ""),
                "model": run.get("llm_model", ""),
                "effort": run.get("research_effort", ""),
                "status": run.get("generation_status", ""),
                "hypothesis_count": len(hypotheses),
                "sanitized_ioc_count": sanitized_ioc_count,
                "removed_ioc_count": removed_ioc_count,
                # issue-local-026: explicit total, always the sum of the two
                # counts above (never a separately-computed number).
                "total_ioc_count": sanitized_ioc_count + removed_ioc_count,
                "technique_count": len(ttp_analysis.get("techniques") or []),
                "event_count": event_count,
                "created_at": run.get("created_at", ""),
            }
        )

    # ── LLM enrichment — soft-fail, the diff table above is still persisted ──
    await _step("generating_narrative")
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

        phase_note = (
            "This is a PRELIMINARY comparison — only pre-SIEM-execution data (threat context, "
            "hypotheses, TTPs, sanitized IOCs) is in scope. Do not comment on SIEM findings or "
            "event counts, which belong to the separate Full Assessment comparison."
            if phase == "preliminary"
            else "This is a FULL comparison, covering each run's complete pipeline output "
            "including SIEM execution results."
        )
        system, user = build_prompt(
            system=_SYSTEM_PROMPT,
            task_description=(
                f"Compare these {len(runs_summary)} run(s) of the same hunt package and identify "
                f"meaningful differences, gaps, and enrichment opportunities. {phase_note}"
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
        "phase": phase,
        "compared_run_ids": [r["id"] for r in runs_summary],
        # issue-local-035: persist the trigger parameters alongside the
        # result, so the tab can display "last triggered with: <model>, N
        # runs" the next time it's opened, not just the report content.
        "trigger_provider_name": provider_name,
        "trigger_model_name": model_name,
        "generated_at": _utc_now(),
        "diff_table": diff_rows,
        "ioc_overview": _build_ioc_overview(runs_summary, full_records),
        "summary": summary,
        "key_differences": key_differences,
        "gaps": gaps,
        "enrichment_opportunities": enrichment_opportunities,
        "recommended_combination": recommended_combination,
    }

    await _step("finalizing")

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
        phase=phase,
    )

    if job_id:
        await th_db.update_comparison_job(
            job_id, status="completed", current_step="finalizing", report_id=report.get("id")
        )

    log.info(
        "comparison_analyst: compared %d run(s) for %s (phase=%s)",
        len(runs_summary),
        hunt_package_id[:8],
        phase,
    )
    return report
