"""LangGraph node: report_writer

Assembles the final Hunt Report from all pipeline outputs and execution results.

Two-stage process:
  1. Deterministic assembly — collects all structured data (threat context,
     hypotheses, leads, TTPs, deep retrohunt summary, execution results) and
     builds a ``full_report`` dict.

  2. LLM executive summary — calls the LLM with the assembled data to produce
     a concise 3-6 sentence executive summary suitable for non-technical
     stakeholders.  Soft-fails if LLM is unavailable.

The completed report is persisted to ``hunt_reports`` via ``db.create_hunt_report``.
The hunt package status is updated to ``completed``.

This node can be called:
  a) Automatically at the end of a successful execution run (triggered by the
     executor after results are collected).
  b) Manually via ``POST /packages/{id}/report`` by the operator at any time
     after the package is approved (even with no execution results).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm
from backend.threat_hunting.agents.logging_utils import get_run_logger
from backend.threat_hunting.db import format_run_id


def _clean_prose_response(text: str) -> str:
    """Strip JSON framing from a prose LLM response.

    issue-local-009 Part 2: ``build_prompt`` historically injected a JSON-only
    system prompt.  Some models still wrap prose answers in a JSON object even
    when instructed otherwise.  This helper:

      1. Strips ```json / ``` fences.
      2. If the remainder parses as a JSON object whose *only value* is a
         non-empty string, unwraps that string (handles the common pattern of
         ``{"executive_summary": "…"}`` or ``{"summary": "…"}``).
      3. Otherwise returns the text as-is (no destructive edits).
    """
    import json as _json
    import re

    cleaned = text.strip()
    # Strip markdown fences
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned, flags=re.MULTILINE)
    cleaned = cleaned.strip()

    # Attempt to detect a single-value JSON wrapper
    try:
        parsed = _json.loads(cleaned)
        if isinstance(parsed, dict):
            values = [v for v in parsed.values() if isinstance(v, str) and v.strip()]
            if len(parsed) == 1 and values:
                return values[0].strip()
            # Also handle {"text": "...", ...} when all non-string values are empty/None
            non_empty = {k: v for k, v in parsed.items() if v not in (None, "", [], {})}
            if len(non_empty) == 1:
                only = next(iter(non_empty.values()))
                if isinstance(only, str) and only.strip():
                    return only.strip()
    except Exception:  # noqa: BLE001
        pass
    return cleaned


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Deterministic report assembly ─────────────────────────────────────────────


def _evidence_summary(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    ioc_total = sum(int(e.get("ioc_count", 0)) for e in evidence_items)
    return {
        "total_items": len(evidence_items),
        "ioc_count": ioc_total,
        "item_types": list({e.get("item_type", "unknown") for e in evidence_items}),
    }


def _evidence_items_full(evidence_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-item detail for every extracted/parsed evidence item.

    The report previously only surfaced an aggregate count/type summary
    (``_evidence_summary``) — the underlying parsed content never appeared
    anywhere in the report, so a reader had no way to see what the hunt was
    actually built from. This keeps the report consistent with how
    thoroughly every other section (hypotheses, leads, TTPs) is documented.
    """
    return [
        {
            "id": e.get("id", ""),
            "label": e.get("label") or e.get("source_ref") or e.get("item_type") or "Evidence item",
            "item_type": e.get("item_type", "unknown"),
            "source_ref": e.get("source_ref", ""),
            "parser_used": e.get("parser_used", ""),
            "parse_status": e.get("parse_status", ""),
            "extracted_text": e.get("extracted_text") or "",
        }
        for e in evidence_items
    ]


def _retrohunt_summary(deep_retrohunt: dict[str, Any] | None) -> dict[str, Any] | None:
    if not deep_retrohunt:
        return None
    return {
        "total_iocs": deep_retrohunt.get("total_ioc_count", 0),
        "noisy_iocs": deep_retrohunt.get("noisy_ioc_count", 0),
        "high_noise_iocs": deep_retrohunt.get("high_noise_ioc_count", 0),
        "spl_macro_name": deep_retrohunt.get("spl_macro_name", ""),
        "search_hint": deep_retrohunt.get("search_hint", ""),
    }


def _execution_summary(task_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": r.get("id", ""),
            "status": r.get("status", ""),
            "earliest": r.get("earliest", ""),
            "latest": r.get("latest", ""),
            "event_count": len(r.get("raw_result") or []),
            "interpreted_findings": r.get("interpreted_findings", ""),
            "completed_at": r.get("completed_at", ""),
        }
        for r in task_results
    ]


def assemble_report(
    hunt_package: dict[str, Any],
    generation_record: dict[str, Any],
    evidence_items: list[dict[str, Any]],
    task_results: list[dict[str, Any]],
    *,
    executive_summary: str = "",
    findings: str = "",
) -> dict[str, Any]:
    """Build the full_report dict from all available data."""
    hypotheses = generation_record.get("hypotheses") or []
    hunting_leads = generation_record.get("hunting_leads") or []
    ttp_analysis = generation_record.get("ttp_analysis")
    deep_retrohunt = generation_record.get("deep_retrohunt")
    query_drafts = generation_record.get("query_drafts") or []
    threat_context = generation_record.get("threat_context")

    # issue-local-019: the human-readable HuntID/RunID (e.g. "TH55"/"TH55-X02")
    # alongside the internal UUID (`hunt_id`, kept unchanged below) — computed
    # the same way list_hunt_packages()/list_generation_runs() do, from data
    # already present on hunt_package/generation_record (no extra DB query).
    hunt_id_display = hunt_package.get("hunt_id_display") or ""
    run_id_display = format_run_id(hunt_id_display, generation_record.get("run_seq"))

    # Derive recommendations from hypotheses and execution results
    recommendations: list[str] = []
    for h in hypotheses[:3]:
        title = h.get("title", "")
        if title:
            recommendations.append(f"Investigate: {title}")
    completed_results = [r for r in task_results if r.get("status") == "completed"]
    if completed_results:
        total_events = sum(len(r.get("raw_result") or []) for r in completed_results)
        if total_events > 0:
            recommendations.append(
                f"Review {total_events} SIEM event(s) identified during retrohunt execution."
            )
        else:
            recommendations.append(
                "No SIEM events matched the retrohunt IOCs — consider broadening the time range or reviewing IOC quality."
            )

    return {
        "executive_summary": executive_summary,
        "hunt_name": hunt_package.get("name", ""),
        "hunt_id": hunt_package.get("id", ""),
        "hunt_id_display": hunt_id_display,
        "run_id_display": run_id_display,
        "generated_at": _utc_now(),
        "generated_by": None,
        "package_status": hunt_package.get("status", ""),
        "evidence_summary": _evidence_summary(evidence_items),
        "evidence_items": _evidence_items_full(evidence_items),
        # issue-local-019: full per-IOC list (same shape RetrohuntPanel.tsx's
        # All/Sanitized/Removed table uses), not just the aggregate counts in
        # deep_retrohunt_summary below.
        "sanitized_iocs": (deep_retrohunt or {}).get("sanitized_iocs") or [],
        "threat_context": threat_context,
        "hypotheses": hypotheses,
        "hunting_leads": hunting_leads,
        "deep_retrohunt_summary": _retrohunt_summary(deep_retrohunt),
        "ttp_analysis": ttp_analysis,
        "query_drafts_count": len(query_drafts),
        "execution_results": _execution_summary(task_results),
        "recommendations": recommendations,
        # issue-008-2C-C: placed last, generated by a separate LLM call
        "findings": findings or None,
    }


# ── LLM executive summary ─────────────────────────────────────────────────────

_EXEC_SUMMARY_FORMAT = (
    "A plain-text executive summary of 3-6 sentences. "
    "No markdown, no bullet points. "
    "Suitable for a non-technical stakeholder."
)


async def _generate_executive_summary(
    full_report: dict[str, Any],
    *,
    provider_name: str | None,
    model_name: str | None,
) -> str:

    threat_ctx = full_report.get("threat_context") or {}
    hypotheses = full_report.get("hypotheses") or []
    exec_results = full_report.get("execution_results") or []
    retro_summary = full_report.get("deep_retrohunt_summary") or {}

    hyp_titles = ", ".join(h.get("title", "") for h in hypotheses[:3] if h.get("title"))
    total_events = sum(r.get("event_count", 0) for r in exec_results)
    findings_texts = [
        r["interpreted_findings"]
        for r in exec_results
        if r.get("interpreted_findings") and "unavailable" not in r.get("interpreted_findings", "")
    ]

    context_sections = [
        ("Hunt Name", full_report.get("hunt_name", "")),
        ("Threat Summary", str(threat_ctx.get("summary", "Not available"))),
        (
            "Top Hypotheses",
            hyp_titles or "None generated",
        ),
        (
            "Retrohunt",
            f"{retro_summary.get('total_iocs', 0)} IOCs searched, "
            f"{total_events} SIEM events matched"
            if retro_summary
            else "No retrohunt performed",
        ),
        (
            "Key Findings",
            "\n".join(findings_texts[:3]) if findings_texts else "No execution findings available",
        ),
    ]

    system, user = build_prompt(
        task_description=(
            "Write a concise executive summary for a completed Threat Hunt. "
            "Explain what was hunted, what was found, and what action is recommended. "
            "Write for a non-technical stakeholder."
        ),
        context_sections=context_sections,
        output_format=_EXEC_SUMMARY_FORMAT,
        additional_instructions=(
            "Do NOT use markdown. Do NOT use bullet points. "
            "3-6 plain sentences only. Be factual — do not invent details."
        ),
        json_output=False,
    )

    raw = await call_llm(
        user,
        system=system,
        provider_name=provider_name,
        model=model_name,
        max_tokens=400,
    )
    return _clean_prose_response(raw)


# ── LLM Findings/Conclusion section (issue-008-2C-C) ────────────────────────

_FINDINGS_FORMAT = (
    "A detailed Findings/Conclusion section in plain text. "
    "4-8 paragraphs or 10-20 sentences. "
    "More detailed than the executive summary. "
    "Synthesize the most important facts from the entire hunt: "
    "specific IOCs of interest, confirmed TTPs, hunting-lead outcomes, "
    "SIEM evidence, and a clear conclusion statement. "
    "Suitable for a security analyst. No markdown formatting."
)


async def _generate_findings(
    full_report: dict[str, Any],
    *,
    provider_name: str | None,
    model_name: str | None,
) -> str:
    """Generate a detailed Findings/Conclusion section via LLM.

    Placed at the bottom of the report, after Recommendations.
    More detailed than the executive summary; synthesizes the full hunt outcome.
    Returns a plain-text string; empty string on error (soft-fail).
    """
    threat_ctx = full_report.get("threat_context") or {}
    hypotheses = full_report.get("hypotheses") or []
    exec_results = full_report.get("execution_results") or []
    retro_summary = full_report.get("deep_retrohunt_summary") or {}
    ttp_analysis = full_report.get("ttp_analysis") or {}
    recommendations = full_report.get("recommendations") or []

    hyp_lines = "\n".join(
        f"- [{h.get('id', '')}] {h.get('title', '')} ({h.get('relevance', '')}) — "
        f"{str(h.get('description') or '')[:200]}"
        for h in hypotheses
    )
    total_events = sum(r.get("event_count", 0) for r in exec_results)
    findings_texts = "\n".join(
        r.get("interpreted_findings", "")
        for r in exec_results
        if r.get("interpreted_findings") and "unavailable" not in r.get("interpreted_findings", "")
    )
    techniques = ", ".join(
        f"{t.get('technique_id', '')} {t.get('technique_name', '')}"
        for t in (ttp_analysis.get("techniques") or [])[:6]
    )
    ioc_count = retro_summary.get("total_iocs") or 0
    noisy_iocs = retro_summary.get("noisy_iocs") or 0

    context_sections = [
        ("Hunt Name", full_report.get("hunt_name", "")),
        ("Threat Actor / Campaign", str(threat_ctx.get("summary", "Not available"))[:500]),
        ("Attack Vector", str(threat_ctx.get("attack_vector", "Unknown"))),
        ("Confidence", str(threat_ctx.get("confidence", "Unknown"))),
        (
            "Hypotheses",
            hyp_lines[:1500] if hyp_lines else "None generated",
        ),
        (
            "IOC Retrohunt",
            f"{ioc_count} IOCs searched ({noisy_iocs} noisy/filtered), "
            f"{total_events} SIEM events matched"
            if retro_summary
            else "Not performed",
        ),
        (
            "SIEM Execution Findings",
            findings_texts[:1000] if findings_texts else "No execution run",
        ),
        ("MITRE ATT&CK Techniques", techniques or "Not mapped"),
        ("Recommendations", "; ".join(recommendations[:5]) or "None"),
    ]

    system, user = build_prompt(
        task_description=(
            "Write a comprehensive Findings/Conclusion section for a completed Threat Hunt report. "
            "This section goes at the END of the report, after Recommendations. "
            "It should be more detailed than the executive summary, intended for security analysts. "
            "Cover: key IOCs and their significance, confirmed or suspected adversary behaviours, "
            "what the SIEM evidence did or did not reveal, assessment of each major hypothesis, "
            "and a clear conclusion about whether the threat was detected in the environment."
        ),
        context_sections=context_sections,
        output_format=_FINDINGS_FORMAT,
        additional_instructions=(
            "Write in plain paragraphs (no markdown, no bullets). "
            "Be specific — reference IOCs, technique IDs, and event counts where available. "
            "Conclude with a clear statement of confidence and recommended next steps. "
            "If no SIEM execution was performed, state that clearly and base conclusions "
            "on the available threat intelligence and hypotheses only."
        ),
        json_output=False,
    )

    try:
        raw = await call_llm(
            user,
            system=system,
            provider_name=provider_name,
            model=model_name,
            max_tokens=1200,
        )
        return _clean_prose_response(raw)
    except Exception as exc:  # noqa: BLE001
        log = get_run_logger(__name__, full_report.get("hunt_id"), None)
        log.warning("report_writer: findings generation failed: %s", exc)
        return _build_fallback_findings(full_report)


def _build_fallback_findings(full_report: dict[str, Any]) -> str:
    """Build a templated Findings/Conclusion when the LLM is unavailable."""
    hypotheses = full_report.get("hypotheses") or []
    exec_results = full_report.get("execution_results") or []
    total_events = sum(r.get("event_count", 0) for r in exec_results)
    retro = full_report.get("deep_retrohunt_summary") or {}
    hunt_name = full_report.get("hunt_name", "this hunt")

    parts: list[str] = [
        f"FINDINGS AND CONCLUSION — {hunt_name.upper()}",
        "",
        f"This hunt assessed {len(hypotheses)} hypothesis(es) based on the collected threat "
        "intelligence evidence.",
    ]
    if hypotheses:
        parts.append(
            "The following hypotheses were evaluated: "
            + "; ".join(
                f"{h.get('id', '')} {h.get('title', '')} "
                f"(relevance: {h.get('relevance', 'unknown')})"
                for h in hypotheses[:5]
            )
            + "."
        )
    if retro:
        parts.append(
            f"The deep retrohunt searched {retro.get('total_iocs', 0)} IOCs "
            f"({retro.get('noisy_iocs', 0)} flagged as noisy)."
        )
    if total_events > 0:
        parts.append(
            f"SIEM execution identified {total_events} event(s) matching the hunt criteria. "
            "Manual review of these events is recommended to determine whether they represent "
            "genuine threat activity or false positives."
        )
    else:
        parts.append(
            "No SIEM execution events matched the hunt criteria at the time of report generation. "
            "This may indicate the threat has not been active in this environment, "
            "or that the search time range or IOC set requires adjustment."
        )
    parts += [
        "",
        "This report was generated automatically. The findings and recommendations should be "
        "reviewed by a qualified threat analyst before any action is taken.",
    ]
    return "\n".join(parts)


# ── Public entry point ────────────────────────────────────────────────────────


async def _report_step_log(
    run_id: str | None,
    step: str,
    status: str,
    *,
    elapsed_s: float | None = None,
    decision: str = "",
    debug_lines: list[str] | None = None,
) -> None:
    """Write a report-phase step entry into the run's step_logs (soft-fail).

    issue-local-021: *debug_lines* feeds WorkflowVisualizer.tsx's per-run
    "Pipeline Log" debug console — this node previously never populated it.
    """
    if not run_id:
        return
    try:
        from backend.threat_hunting import db as th_db

        entry: dict[str, Any] = {"step": step, "status": status}
        if elapsed_s is not None:
            entry["elapsed_s"] = round(elapsed_s, 2)
        if decision:
            entry["decision"] = decision
        if debug_lines:
            entry["debug_lines"] = debug_lines
        await th_db.append_run_step_log(run_id, entry)
    except Exception as exc:  # noqa: BLE001
        get_run_logger(__name__, None, run_id).debug(
            "_report_step_log soft-fail step=%s: %s", step, exc
        )


async def write_report(
    hunt_package_id: str,
    *,
    run_id: str | None = None,
    provider_name: str | None = None,
    model_name: str | None = None,
    created_by: str | None = None,
    report_formats: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """Assemble and persist the Hunt Report for a completed/approved package.

    When *run_id* is supplied the report is scoped to that specific run:
    - generation record loaded by run_id
    - task_results filtered to that run_id
    - report stored with run_id

    When *run_id* is None the latest run is used (back-compat).

    issue-local-009: writes fine-grained step_logs (report_assemble,
    report_exec_summary, report_findings, report_render) and sets
    generation_status=reporting during execution.

    Returns the persisted report dict.
    """
    start = time.monotonic()
    log = get_run_logger(__name__, hunt_package_id, run_id)
    from backend.threat_hunting import db as th_db

    # Signal reporting phase on the run row (soft-fail)
    if run_id:
        try:
            await th_db.set_run_generation_status(run_id, "reporting")
        except Exception:  # noqa: BLE001
            pass

    # ── Step: report_assemble ─────────────────────────────────────────────────
    await _report_step_log(run_id, "report_assemble", "running", decision="Loading hunt data…")
    t_step = time.monotonic()

    # Load all source data
    pkg = await th_db.get_hunt_package(hunt_package_id)
    if not pkg:
        raise ValueError(f"Hunt package {hunt_package_id!r} not found")

    generation_record = (
        await th_db.get_generation_record_public(hunt_package_id, run_id=run_id) or {}
    )
    evidence_items = await th_db.list_evidence_items(hunt_package_id)
    # Scope SIEM results to this run if run_id is provided
    if run_id:
        task_results = await th_db.list_task_results_by_run(run_id)
    else:
        task_results = await th_db.list_task_results(hunt_package_id)

    # Stage 1: deterministic assembly (no LLM)
    full_report = assemble_report(
        pkg,
        generation_record,
        evidence_items,
        task_results,
    )
    await _report_step_log(
        run_id,
        "report_assemble",
        "ok",
        elapsed_s=time.monotonic() - t_step,
        decision=(
            f"Assembled report: {len(evidence_items)} evidence item(s), "
            f"{len(task_results)} execution result(s)"
        ),
    )

    # ── Step: report_exec_summary ─────────────────────────────────────────────
    await _report_step_log(
        run_id, "report_exec_summary", "running", decision="LLM generating executive summary…"
    )
    t_step = time.monotonic()
    executive_summary = ""
    try:
        from backend.llm.errors import LLMDisabledError

        executive_summary = await _generate_executive_summary(
            full_report, provider_name=provider_name, model_name=model_name
        )
        await _report_step_log(
            run_id,
            "report_exec_summary",
            "ok",
            elapsed_s=time.monotonic() - t_step,
            decision="Executive summary generated",
        )
    except Exception as exc:
        from backend.llm.errors import LLMDisabledError

        if isinstance(exc, LLMDisabledError):
            log.info("report_writer: LLM disabled — skipping executive summary")
            fallback_debug = ["LLM_DISABLED: skipping executive summary, using template"]
        else:
            log.exception("report_writer: executive summary generation failed: %s", exc)
            fallback_debug = [f"LLM_ERROR: {exc}"]
        executive_summary = _build_fallback_summary(full_report)
        await _report_step_log(
            run_id,
            "report_exec_summary",
            "ok",
            elapsed_s=time.monotonic() - t_step,
            decision="Executive summary generated (template fallback)",
            debug_lines=fallback_debug,
        )

    full_report["executive_summary"] = executive_summary

    # ── Step: report_findings ─────────────────────────────────────────────────
    await _report_step_log(
        run_id, "report_findings", "running", decision="LLM generating findings section…"
    )
    t_step = time.monotonic()
    findings = ""
    try:
        from backend.llm.errors import LLMDisabledError

        findings = await _generate_findings(
            full_report, provider_name=provider_name, model_name=model_name
        )
        await _report_step_log(
            run_id,
            "report_findings",
            "ok",
            elapsed_s=time.monotonic() - t_step,
            decision="Findings/Conclusion section generated",
        )
    except Exception as exc:
        from backend.llm.errors import LLMDisabledError

        if isinstance(exc, LLMDisabledError):
            log.info("report_writer: LLM disabled — using templated findings")
            fallback_debug = ["LLM_DISABLED: skipping findings section, using template"]
        else:
            log.warning("report_writer: findings generation failed: %s", exc)
            fallback_debug = [f"LLM_ERROR: {exc}"]
        findings = _build_fallback_findings(full_report)
        await _report_step_log(
            run_id,
            "report_findings",
            "ok",
            elapsed_s=time.monotonic() - t_step,
            decision="Findings/Conclusion section generated (template fallback)",
            debug_lines=fallback_debug,
        )
    full_report["findings"] = findings or None

    # ── Step: report_render ───────────────────────────────────────────────────
    await _report_step_log(run_id, "report_render", "running", decision="Rendering report formats…")
    t_step = time.monotonic()

    # Stage 3: resolve which formats to generate (default from loader if not provided)
    if report_formats is None:
        try:
            from backend.config.loader import load_th_report_formats

            report_formats = load_th_report_formats()
        except Exception:
            report_formats = {"pdf": True, "markdown": True}

    # Render ancillary formats — stored as metadata fields for download endpoints
    markdown_content: str | None = None
    if report_formats.get("markdown", True):
        try:
            markdown_content = render_report_markdown(full_report)
        except Exception as exc:
            log.warning("report_writer: markdown render failed: %s", exc)

    # PDF is generated on-demand at the download endpoint (not stored as a blob)
    # to keep DB lean. We still note whether it was requested.
    full_report["_report_formats"] = report_formats
    if markdown_content:
        full_report["_markdown"] = markdown_content

    # Stage 4: persist (with run_id linkage for independent re-run reports)
    report = await th_db.create_hunt_report(
        hunt_package_id,
        executive_summary=executive_summary,
        full_report=full_report,
        created_by=created_by,
        run_id=run_id,
    )

    # Update package to completed if it was approved
    if pkg.get("status") == "approved":
        await th_db.update_hunt_package(hunt_package_id, status="completed")

    elapsed = time.monotonic() - start
    fmt_names = [k for k, v in (report_formats or {}).items() if v]
    await _report_step_log(
        run_id,
        "report_render",
        "ok",
        elapsed_s=time.monotonic() - t_step,
        decision=f"Report saved — formats: {', '.join(fmt_names) or 'default'}",
    )

    # Restore generation_status to completed (soft-fail)
    if run_id:
        try:
            await th_db.set_run_generation_status(run_id, "completed")
        except Exception:  # noqa: BLE001
            pass

    log.info("report_writer: report generated for %s in %.2fs", hunt_package_id[:8], elapsed)
    return report


# ── Markdown renderer ─────────────────────────────────────────────────────────


def render_report_markdown(full_report: dict[str, Any]) -> str:
    """Render the full_report dict as a Markdown document string."""
    lines: list[str] = []

    def _h(level: int, text: str) -> None:
        lines.append(f"{'#' * level} {text}\n")

    def _p(text: str) -> None:
        if text:
            lines.append(f"{text}\n")

    def _li(text: str) -> None:
        lines.append(f"- {text}")

    def _code(text: str, lang: str = "") -> None:
        lines.append(f"```{lang}")
        lines.append(text)
        lines.append("```\n")

    hunt_id_display = full_report.get("hunt_id_display", "")
    run_id_display = full_report.get("run_id_display", "")
    title_prefix = f"[{hunt_id_display}] " if hunt_id_display else ""
    _h(1, f"{title_prefix}Threat Hunt Report: {full_report.get('hunt_name', 'Unnamed Hunt')}")
    if hunt_id_display:
        lines.append(f"**HuntID:** {hunt_id_display}")
    if run_id_display:
        lines.append(f"**RunID:** {run_id_display}")
    lines.append(f"**Internal ID:** {full_report.get('hunt_id', '')}")
    lines.append(f"**Generated At:** {full_report.get('generated_at', '')}")
    lines.append(f"**Status:** {full_report.get('package_status', '')}\n")

    exec_summary = full_report.get("executive_summary", "")
    if exec_summary:
        _h(2, "Executive Summary")
        _p(exec_summary)

    ev = full_report.get("evidence_summary") or {}
    _h(2, "Evidence Summary")
    lines.append(f"- Evidence items: {ev.get('total_items', 0)}")
    lines.append(f"- IOCs extracted: {ev.get('ioc_count', 0)}")
    lines.append(f"- Item types: {', '.join(ev.get('item_types', []) or [])}\n")

    evidence_items = full_report.get("evidence_items") or []
    if evidence_items:
        _h(2, f"Evidence Items ({len(evidence_items)})")
        for item in evidence_items:
            _h(3, str(item.get("label", "Evidence item")))
            meta_bits = [
                f"Type: {item['item_type']}" if item.get("item_type") else "",
                f"Parser: {item['parser_used']}" if item.get("parser_used") else "",
                f"Status: {item['parse_status']}" if item.get("parse_status") else "",
            ]
            meta_line = "  |  ".join(b for b in meta_bits if b)
            if meta_line:
                lines.append(f"*{meta_line}*\n")
            if item.get("source_ref"):
                lines.append(f"Source: `{item['source_ref']}`\n")
            if item.get("extracted_text"):
                _code(item["extracted_text"])
            else:
                _p("(no extracted text)")

    tc = full_report.get("threat_context") or {}
    if tc and not tc.get("parse_error"):
        _h(2, "Threat Context")
        if tc.get("summary"):
            _p(tc["summary"])
        for k, label in [
            ("threat_actor", "Threat Actor"),
            ("campaign_name", "Campaign"),
            ("attack_vector", "Attack Vector"),
            ("confidence", "Confidence"),
        ]:
            if tc.get(k):
                lines.append(f"- **{label}:** {tc[k]}")
        for family in tc.get("malware_families") or []:
            lines.append(f"- **Malware Family:** {family}")
        lines.append("")

    hypotheses = full_report.get("hypotheses") or []
    if hypotheses:
        _h(2, f"Hypotheses ({len(hypotheses)})")
        for h in hypotheses:
            _h(3, f"[{h.get('id', '')}] {h.get('title', '')}")
            lines.append(f"**Relevance:** {h.get('relevance', '')}")
            _p(h.get("description", ""))
            if h.get("justification"):
                _p(f"*Justification: {h['justification']}*")
            if h.get("ioc_basis"):
                _p(f"*IOC Basis: {', '.join(str(i) for i in h['ioc_basis'][:5])}*")
            # issue-006-E: suggested_actions
            if h.get("suggested_actions"):
                lines.append("**Suggested Actions:**")
                for action in h["suggested_actions"]:
                    lines.append(f"  - `{action}`")
                lines.append("")

    hunting_leads = full_report.get("hunting_leads") or []
    if hunting_leads:
        _h(2, f"Hunting Leads ({len(hunting_leads)})")
        for lead in hunting_leads:
            _h(3, f"[{lead.get('id', '')}] {lead.get('title', '')}")
            lines.append(
                f"**Priority:** {lead.get('priority', '')}  **Hypothesis:** {lead.get('hypothesis_id', '')}"
            )
            _p(lead.get("description", ""))
            for task in lead.get("tasks") or []:
                lines.append(
                    f"  - **{task.get('id', '')} {task.get('title', '')}** — {task.get('description', '')}"
                )
            lines.append("")

    retro = full_report.get("deep_retrohunt_summary") or {}
    if retro:
        _h(2, "Deep Retrohunt Summary")
        lines.append(
            f"- IOCs: {retro.get('total_iocs', 0)} total, {retro.get('noisy_iocs', 0)} noisy, {retro.get('high_noise_iocs', 0)} high-noise"
        )
        if retro.get("spl_macro_name"):
            lines.append(f"- SPL Macro: `{retro['spl_macro_name']}`")
        if retro.get("search_hint"):
            lines.append(f"- Search hint: {retro['search_hint']}")
        lines.append("")

    # issue-local-019: full IOC table — the same All/Sanitized/Removed data
    # RetrohuntPanel.tsx's review table shows, not just the aggregate counts
    # above. One combined table (every IOC, a Verdict column distinguishes
    # kept vs. removed) rather than split tables, since Markdown has no
    # interactive filter to switch between them.
    sanitized_iocs = full_report.get("sanitized_iocs") or []
    if sanitized_iocs:
        removed_n = sum(1 for i in sanitized_iocs if i.get("action") == "remove")
        _h(
            2,
            f"IOC Table ({len(sanitized_iocs)} total, {len(sanitized_iocs) - removed_n} kept, {removed_n} removed)",
        )
        lines.append("| IOC | Type | Verdict | Noise | Description | Reasons |")
        lines.append("|---|---|---|---|---|---|")
        for ioc in sanitized_iocs:
            verdict = "Removed" if ioc.get("action") == "remove" else "Keep"
            noise_pct = f"{round(float(ioc.get('noise_score', 0)) * 100)}%"
            desc = str(ioc.get("ioc_description", "") or "").replace("|", "\\|").replace("\n", " ")
            reasons = "; ".join(str(r) for r in (ioc.get("noise_reasons") or [])).replace(
                "|", "\\|"
            )
            lines.append(
                f"| `{ioc.get('ioc', '')}` | {ioc.get('ioc_type', '')} | {verdict} | {noise_pct} | {desc} | {reasons} |"
            )
        lines.append("")

    ttp = full_report.get("ttp_analysis") or {}
    if ttp and not ttp.get("parse_error"):
        _h(2, "TTP Analysis")
        if ttp.get("summary"):
            _p(ttp["summary"])
        for t in ttp.get("techniques") or []:
            lines.append(
                f"- **{t.get('technique_id', '')} {t.get('technique_name', '')}** ({t.get('tactic', '')}): {t.get('description', '')}"
            )
        for opp in ttp.get("detection_opportunities") or []:
            lines.append(f"  - Detection: {opp}")
        lines.append("")

    exec_results = full_report.get("execution_results") or []
    if exec_results:
        _h(2, f"Execution Results ({len(exec_results)} run(s))")
        for r in exec_results:
            lines.append(
                f"- **{r.get('id', '')}** status={r.get('status', '')} events={r.get('event_count', 0)}"
            )
            if r.get("interpreted_findings"):
                _p(f"  *{r['interpreted_findings']}*")
        lines.append("")

    recs = full_report.get("recommendations") or []
    if recs:
        _h(2, "Recommendations")
        for rec in recs:
            _li(rec)
        lines.append("")

    # issue-008-2C-C: Findings/Conclusion — placed LAST
    findings = full_report.get("findings")
    if findings:
        _h(2, "Findings and Conclusion")
        _p(findings)
        lines.append("")

    return "\n".join(lines)


# ── PDF renderer ──────────────────────────────────────────────────────────────


def render_report_pdf(full_report: dict[str, Any]) -> bytes:
    """Render the full_report dict as a PDF byte string using reportlab.

    Print-oriented light theme (previously used a dark-UI color scheme —
    near-white headings and dark table fills — which is illegible/ugly on a
    printed white page). Cover includes the configured branding logo and app
    title when set (backend.config.loader.resolve_logo_file/load_app_title).

    - Cover: logo + app title (if configured), report title, colored rule,
      metadata row.
    - Running footer on every page: app title (left) + page number (center).
    - Tables: light header fill with dark text, subtle alternating rows,
      thin borders, header row repeats across a page break.
    - Colored accent rule above each H2 section header.
    """
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.lib.utils import ImageReader
    from reportlab.platypus import (
        HRFlowable,
        Image,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    from backend.config.loader import load_app_title, resolve_logo_file

    PAGE_W, PAGE_H = A4
    LEFT_MARGIN = 2 * cm
    RIGHT_MARGIN = 2 * cm
    TOP_MARGIN = 2.5 * cm
    BOT_MARGIN = 2 * cm

    buf = BytesIO()

    app_title = load_app_title().strip()
    logo_path = resolve_logo_file()
    logo_flowable: Image | None = None
    if logo_path is not None:
        try:
            reader = ImageReader(str(logo_path))
            iw, ih = reader.getSize()
            target_h = 1.3 * cm
            target_w = iw * (target_h / ih) if ih else target_h
            logo_flowable = Image(str(logo_path), width=target_w, height=target_h)
        except Exception:  # noqa: BLE001
            logo_flowable = None

    # ── Print-friendly color palette ─────────────────────────────────────────
    _COL_H1 = colors.HexColor("#0f172a")  # slate-900 — cover title
    _COL_H2 = colors.HexColor("#1e293b")  # slate-800 — section headings
    _COL_ACCENT_RULE = colors.HexColor("#2f58f0")  # brand blue — section/cover rules
    _COL_META = colors.HexColor("#64748b")  # slate-500 — metadata/footer text
    _COL_TABLE_HEADER_BG = colors.HexColor("#e0e7ff")  # indigo-100
    _COL_TABLE_HEADER_FG = colors.HexColor("#1e293b")  # slate-800
    _COL_TABLE_ROW_ALT = colors.HexColor("#f8fafc")  # slate-50
    _COL_TABLE_ROW_NORM = colors.white
    _COL_TABLE_BORDER = colors.HexColor("#cbd5e1")  # slate-300
    _COL_EVIDENCE_BG = colors.HexColor("#f8fafc")  # slate-50 — extracted-text box

    # ── Page callbacks: running footer (app title + page number) ────────────
    def _footer(canvas, doc):  # type: ignore[no-untyped-def]
        canvas.saveState()
        canvas.setStrokeColor(_COL_TABLE_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(LEFT_MARGIN, BOT_MARGIN * 0.75, PAGE_W - RIGHT_MARGIN, BOT_MARGIN * 0.75)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(_COL_META)
        if app_title:
            canvas.drawString(LEFT_MARGIN, BOT_MARGIN * 0.4, app_title)
        canvas.drawCentredString(PAGE_W / 2.0, BOT_MARGIN * 0.4, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=RIGHT_MARGIN,
        leftMargin=LEFT_MARGIN,
        topMargin=TOP_MARGIN,
        bottomMargin=BOT_MARGIN,
        title=full_report.get("hunt_name", "Threat Hunt Report"),
    )
    styles = getSampleStyleSheet()
    h1_style = ParagraphStyle(
        "CoverH1",
        parent=styles["Heading1"],
        fontSize=19,
        spaceAfter=4,
        textColor=_COL_H1,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontSize=13,
        spaceAfter=6,
        textColor=_COL_H2,
        spaceBefore=10,
    )
    h3_style = ParagraphStyle(
        "SectionH3",
        parent=styles["Heading3"],
        fontSize=11,
        textColor=_COL_H2,
        spaceBefore=6,
        spaceAfter=2,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        textColor=colors.HexColor("#1f2937"),
        leading=14,
    )
    meta_style = ParagraphStyle(
        "Meta",
        parent=body_style,
        fontSize=9,
        textColor=_COL_META,
    )
    branding_style = ParagraphStyle(
        "Branding",
        parent=body_style,
        fontSize=10,
        textColor=_COL_META,
    )
    code_style = ParagraphStyle(
        "Code",
        parent=body_style,
        fontName="Courier",
        fontSize=8,
        leftIndent=12,
        spaceAfter=4,
    )
    evidence_text_style = ParagraphStyle(
        "EvidenceText",
        parent=body_style,
        fontSize=8.5,
        fontName="Courier",
        leading=11,
    )

    story: list = []

    def _esc(text: str | None) -> str:
        """Escape XML chars for reportlab Paragraph.

        issue-local-022: defensive `str(text or "")` — LLM-generated report
        fields (relevance/priority/hypothesis_id/task description/technique
        fields, etc.) are frequently explicitly `None` rather than merely
        absent, and `dict.get(key, default)` only substitutes the default
        when the key is *missing*, not when its value is `None`. Every call
        site used to assume a non-None string; some didn't, causing
        run-dependent PDF-download crashes. Guarding here, once, is more
        robust than chasing every call site.
        """
        return str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _h1(text: str) -> None:
        story.append(Paragraph(_esc(text), h1_style))

    def _h2(text: str) -> None:
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_COL_ACCENT_RULE))
        story.append(Paragraph(_esc(text), h2_style))

    def _h3(text: str) -> None:
        story.append(Paragraph(_esc(text), h3_style))

    def _p(text: str, style: ParagraphStyle | None = None) -> None:
        if text:
            story.append(Paragraph(_esc(text), style or body_style))

    def _p_raw(html: str, style: ParagraphStyle | None = None) -> None:
        """Emit a paragraph with pre-escaped HTML tags (bold/italic allowed)."""
        if html:
            story.append(Paragraph(html, style or body_style))

    def _sp(h: int = 4) -> None:
        story.append(Spacer(1, h))

    def _styled_table(
        rows: list[list[str]], col_widths: list, extra_style: list | None = None
    ) -> Table:  # type: ignore[type-arg]
        table = Table(rows, colWidths=col_widths, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), _COL_TABLE_HEADER_BG),
                    ("TEXTCOLOR", (0, 0), (-1, 0), _COL_TABLE_HEADER_FG),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_COL_TABLE_ROW_NORM, _COL_TABLE_ROW_ALT]),
                    ("GRID", (0, 0), (-1, -1), 0.5, _COL_TABLE_BORDER),
                    ("BOX", (0, 0), (-1, -1), 0.75, _COL_TABLE_BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    *(extra_style or []),
                ]
            )
        )
        return table

    # ── Cover: branding (logo + app title), report title, metadata ──────────
    if logo_flowable is not None or app_title:
        brand_cells = [
            logo_flowable or "",
            Paragraph(_esc(app_title), branding_style) if app_title else "",
        ]
        brand_row = Table([brand_cells], colWidths=[3 * cm, None])
        brand_row.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        story.append(brand_row)
        _sp(10)

    hunt_name = full_report.get("hunt_name", "Unnamed Hunt")
    hunt_id_display = full_report.get("hunt_id_display", "")
    run_id_display = full_report.get("run_id_display", "")
    title_prefix = f"[{hunt_id_display}] " if hunt_id_display else ""
    _h1(f"{title_prefix}Threat Hunt Report: {hunt_name}")
    story.append(HRFlowable(width="100%", thickness=2.5, color=_COL_ACCENT_RULE))
    _sp(6)

    meta_parts = []
    if hunt_id_display:
        meta_parts.append(f"HuntID: {hunt_id_display}")
    if run_id_display:
        meta_parts.append(f"RunID: {run_id_display}")
    if full_report.get("hunt_id"):
        meta_parts.append(f"Internal ID: {full_report['hunt_id']}")
    if full_report.get("generated_at"):
        meta_parts.append(f"Generated: {full_report['generated_at']}")
    if full_report.get("package_status"):
        meta_parts.append(f"Status: {full_report['package_status']}")
    if full_report.get("generated_by"):
        meta_parts.append(f"By: {full_report['generated_by']}")
    if meta_parts:
        story.append(Paragraph("  |  ".join(_esc(m) for m in meta_parts), meta_style))
    _sp(8)

    exec_summary = full_report.get("executive_summary", "")
    if exec_summary:
        _h2("Executive Summary")
        _p(exec_summary)

    # ── Evidence Summary — Table ──────────────────────────────────────────────
    ev = full_report.get("evidence_summary") or {}
    _h2("Evidence Summary")
    try:
        ev_rows = [
            ["Metric", "Value"],
            ["Evidence Items", str(ev.get("total_items", 0))],
            ["IOCs Extracted", str(ev.get("ioc_count", 0))],
            ["Evidence Types", ", ".join(ev.get("item_types", []) or [])],
        ]
        story.append(_styled_table(ev_rows, [5 * cm, None]))
    except Exception:  # noqa: BLE001
        _p(f"Items: {ev.get('total_items', 0)}  |  IOCs: {ev.get('ioc_count', 0)}")

    # ── Evidence Items — full extracted/parsed content ───────────────────────
    evidence_items = full_report.get("evidence_items") or []
    if evidence_items:
        _h2(f"Evidence Items ({len(evidence_items)})")
        for item in evidence_items:
            _h3(str(item.get("label", "Evidence item")))
            meta_bits = [
                f"<b>Type:</b> {_esc(str(item['item_type']))}" if item.get("item_type") else "",
                f"<b>Parser:</b> {_esc(str(item['parser_used']))}"
                if item.get("parser_used")
                else "",
                f"<b>Status:</b> {_esc(str(item['parse_status']))}"
                if item.get("parse_status")
                else "",
            ]
            meta_line = "  &nbsp;|&nbsp;  ".join(b for b in meta_bits if b)
            if meta_line:
                _p_raw(meta_line, meta_style)
            if item.get("source_ref"):
                story.append(Paragraph(f"Source: {_esc(str(item['source_ref']))}", code_style))
            extracted = item.get("extracted_text") or ""
            if extracted:
                try:
                    box = Table(
                        [[Paragraph(_esc(extracted), evidence_text_style)]],
                        colWidths=[None],
                    )
                    box.setStyle(
                        TableStyle(
                            [
                                ("BACKGROUND", (0, 0), (-1, -1), _COL_EVIDENCE_BG),
                                ("BOX", (0, 0), (-1, -1), 0.5, _COL_TABLE_BORDER),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                ("TOPPADDING", (0, 0), (-1, -1), 6),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ]
                        )
                    )
                    story.append(box)
                except Exception:  # noqa: BLE001
                    _p(extracted, evidence_text_style)
            else:
                _p("(no extracted text)", meta_style)
            _sp(6)

    # ── Threat Context ────────────────────────────────────────────────────────
    tc = full_report.get("threat_context") or {}
    if tc and not tc.get("parse_error"):
        _h2("Threat Context")
        if tc.get("summary"):
            _p(tc["summary"])
        for k, label in [
            ("threat_actor", "Threat Actor"),
            ("campaign_name", "Campaign"),
            ("attack_vector", "Attack Vector"),
            ("confidence", "Confidence"),
        ]:
            if tc.get(k):
                _p_raw(f"<b>{label}:</b> {_esc(str(tc[k]))}")
        for f in tc.get("malware_families") or []:
            _p_raw(f"<b>Malware Family:</b> {_esc(str(f))}")

    # ── Hypotheses ────────────────────────────────────────────────────────────
    hypotheses = full_report.get("hypotheses") or []
    if hypotheses:
        _h2(f"Hypotheses ({len(hypotheses)})")
        for h in hypotheses:
            relevance = h.get("relevance", "")
            _h3(f"[{h.get('id', '')}] {h.get('title', '')}")
            _p_raw(f"<b>Relevance:</b> {_esc(relevance)}")
            _p(h.get("description", ""))
            if h.get("justification"):
                _p_raw(f"<i>{_esc(h['justification'])}</i>")
            if h.get("ioc_basis"):
                _p_raw(f"<i>IOC Basis: {_esc(', '.join(str(i) for i in h['ioc_basis'][:5]))}</i>")
            if h.get("suggested_actions"):
                _p_raw("<b>Suggested Actions:</b>")
                for action in h["suggested_actions"]:
                    _p_raw(f"• {_esc(str(action))}")
            _sp()

    # ── Hunting Leads ─────────────────────────────────────────────────────────
    hunting_leads = full_report.get("hunting_leads") or []
    if hunting_leads:
        _h2(f"Hunting Leads ({len(hunting_leads)})")
        for lead in hunting_leads:
            _h3(f"[{lead.get('id', '')}] {lead.get('title', '')}")
            _p_raw(
                f"<b>Priority:</b> {_esc(lead.get('priority', ''))}  "
                f"<b>Hypothesis:</b> {_esc(lead.get('hypothesis_id', ''))}"
            )
            _p(lead.get("description", ""))
            for task in lead.get("tasks") or []:
                _p_raw(
                    f"• <b>{_esc(task.get('id', ''))} {_esc(task.get('title', ''))}</b> "
                    f"— {_esc(task.get('description', ''))}"
                )
            _sp()

    # ── Deep Retrohunt Summary ────────────────────────────────────────────────
    retro = full_report.get("deep_retrohunt_summary") or {}
    if retro:
        _h2("Deep Retrohunt Summary")
        _p_raw(
            f"IOCs: {retro.get('total_iocs', 0)} total, "
            f"{retro.get('noisy_iocs', 0)} noisy, "
            f"{retro.get('high_noise_iocs', 0)} high-noise"
        )
        if retro.get("spl_macro_name"):
            story.append(Paragraph(_esc(str(retro["spl_macro_name"])), code_style))
        if retro.get("search_hint"):
            _p(str(retro["search_hint"]))

    # ── IOC Table — full All/Sanitized/Removed data ──────────────────────────
    # issue-local-019: mirrors RetrohuntPanel.tsx's review table (one combined
    # table, a Verdict column distinguishes kept vs. removed — no interactive
    # filter in a PDF). Description/Reasons cells use Paragraph flowables so
    # the LLM's rationale wraps across lines instead of being cut off.
    sanitized_iocs = full_report.get("sanitized_iocs") or []
    if sanitized_iocs:
        removed_n = sum(1 for i in sanitized_iocs if i.get("action") == "remove")
        _h2(
            f"IOC Table ({len(sanitized_iocs)} total, {len(sanitized_iocs) - removed_n} kept, {removed_n} removed)"
        )
        ioc_cell_style = ParagraphStyle("IocCell", parent=body_style, fontSize=7.5, leading=9.5)
        ioc_mono_style = ParagraphStyle("IocMono", parent=ioc_cell_style, fontName="Courier")
        try:
            ioc_rows: list[list] = [["IOC", "Type", "Verdict", "Description", "Reasons"]]
            for ioc in sanitized_iocs:
                removed = ioc.get("action") == "remove"
                noise_pct = round(float(ioc.get("noise_score", 0)) * 100)
                verdict = f"Removed ({noise_pct}%)" if removed else f"Keep ({noise_pct}%)"
                reasons = "; ".join(str(r) for r in (ioc.get("noise_reasons") or []))
                ioc_rows.append(
                    [
                        Paragraph(_esc(str(ioc.get("ioc", ""))), ioc_mono_style),
                        str(ioc.get("ioc_type", "")),
                        verdict,
                        Paragraph(_esc(str(ioc.get("ioc_description", "") or "—")), ioc_cell_style),
                        Paragraph(_esc(reasons) if reasons else "—", ioc_cell_style),
                    ]
                )
            story.append(
                _styled_table(
                    ioc_rows,
                    [3 * cm, 1.8 * cm, 2.2 * cm, 4.2 * cm, None],
                )
            )
        except Exception:  # noqa: BLE001
            for ioc in sanitized_iocs:
                removed = ioc.get("action") == "remove"
                _p_raw(
                    f"• <b>{_esc(str(ioc.get('ioc', '')))}</b> "
                    f"({_esc(str(ioc.get('ioc_type', '')))}) — "
                    f"{'Removed' if removed else 'Keep'}: {_esc(str(ioc.get('ioc_description', '')))}"
                )

    # ── TTP Analysis — Table ──────────────────────────────────────────────────
    ttp = full_report.get("ttp_analysis") or {}
    if ttp and not ttp.get("parse_error"):
        _h2("TTP Analysis")
        if ttp.get("summary"):
            _p(ttp["summary"])
        techniques = ttp.get("techniques") or []
        if techniques:
            try:
                ttp_rows = [["ID", "Name", "Tactic", "Detection"]]
                for t in techniques:
                    ttp_rows.append(
                        [
                            t.get("technique_id", ""),
                            t.get("technique_name", ""),
                            t.get("tactic", ""),
                            str(t.get("description") or "")[:80],
                        ]
                    )
                story.append(
                    _styled_table(
                        ttp_rows,
                        [2.2 * cm, 4 * cm, 3 * cm, None],
                        extra_style=[("WORDWRAP", (3, 1), (3, -1), "CJK")],
                    )
                )
            except Exception:  # noqa: BLE001
                for t in techniques:
                    _p_raw(
                        f"• <b>{_esc(t.get('technique_id', ''))} "
                        f"{_esc(t.get('technique_name', ''))}</b> "
                        f"({_esc(t.get('tactic', ''))}): "
                        f"{_esc(t.get('description', ''))}"
                    )
        for opp in ttp.get("detection_opportunities") or []:
            _p_raw(f"  Detection: {_esc(str(opp))}")

    # ── Execution Results — Table ─────────────────────────────────────────────
    exec_results = full_report.get("execution_results") or []
    if exec_results:
        _h2(f"Execution Results ({len(exec_results)} run(s))")
        try:
            er_rows = [["Run ID", "Status", "Events", "Findings"]]
            for r in exec_results:
                status = r.get("status", "")
                er_rows.append(
                    [
                        str(r.get("id", ""))[:12],
                        status,
                        str(r.get("event_count", 0)),
                        (r.get("interpreted_findings") or "")[:80],
                    ]
                )
            story.append(_styled_table(er_rows, [3 * cm, 2.5 * cm, 2 * cm, None]))
        except Exception:  # noqa: BLE001
            for r in exec_results:
                _p_raw(
                    f"• <b>{_esc(str(r.get('id', '')))}</b> status={_esc(r.get('status', ''))} "
                    f"events={r.get('event_count', 0)}"
                )
                if r.get("interpreted_findings"):
                    _p_raw(f"  <i>{_esc(str(r['interpreted_findings']))}</i>")

    # ── Recommendations ───────────────────────────────────────────────────────
    recs = full_report.get("recommendations") or []
    if recs:
        _h2("Recommendations")
        for rec in recs:
            _p_raw(f"• {_esc(str(rec))}")

    # ── Findings and Conclusion (issue-008-2C-C) — placed LAST ────────────────
    findings = full_report.get("findings")
    if findings:
        _h2("Findings and Conclusion")
        # Split into paragraphs (double newline) for readable PDF rendering.
        # issue-local-022: _p() already calls _esc() internally — escaping
        # here too double-escaped every '&'/'<'/'>' in LLM-generated text
        # (e.g. "&" -> "&amp;" -> "&amp;amp;", rendering literally in the PDF).
        for para in str(findings).split("\n\n"):
            para = para.strip()
            if para:
                _p(para)
        _sp(8)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


# ── Comparison report renderers (issue-local-020) ─────────────────────────────
#
# Siblings of render_report_markdown/render_report_pdf above, but for a
# *comparison* full_report (see comparison_analyst.py's compare_runs()) —
# NOT reuse of the single-run renderers, since every helper above assumes one
# hypotheses/ttp/threat_context set, not N runs' worth of a diff table.


def render_comparison_markdown(full_report: dict[str, Any]) -> str:
    """Render a comparison full_report dict (see compare_runs()) as Markdown."""
    lines: list[str] = []

    def _h(level: int, text: str) -> None:
        lines.append(f"{'#' * level} {text}\n")

    def _p(text: str) -> None:
        if text:
            lines.append(f"{text}\n")

    def _li(text: str) -> None:
        lines.append(f"- {text}")

    hunt_id_display = full_report.get("hunt_id_display", "")
    title_prefix = f"[{hunt_id_display}] " if hunt_id_display else ""
    _h(1, f"{title_prefix}Comparison Assessment: {full_report.get('hunt_name', 'Unnamed Hunt')}")
    lines.append(f"**Internal ID:** {full_report.get('hunt_id', '')}")
    lines.append(f"**Generated At:** {full_report.get('generated_at', '')}")
    compared = full_report.get("compared_run_ids") or []
    lines.append(f"**Runs Compared:** {len(compared)}\n")

    summary = full_report.get("summary", "")
    if summary:
        _h(2, "Summary")
        _p(summary)

    diff_table = full_report.get("diff_table") or []
    if diff_table:
        _h(2, f"Run Diff Table ({len(diff_table)} run(s))")
        lines.append(
            "| Run | Model | Effort | Status | Hypotheses | IOCs (kept/removed) | "
            "Total IOCs | Techniques | Events |"
        )
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for row in diff_table:
            # issue-local-026: explicit total, always the sum of kept+removed
            # shown in the same row (falls back to summing those two when an
            # older persisted report predates this field).
            total_iocs = row.get("total_ioc_count")
            if total_iocs is None:
                total_iocs = (row.get("sanitized_ioc_count") or 0) + (
                    row.get("removed_ioc_count") or 0
                )
            lines.append(
                f"| {row.get('run_id_display', '')} | {row.get('model', '')} | "
                f"{row.get('effort', '')} | {row.get('status', '')} | "
                f"{row.get('hypothesis_count', 0)} | "
                f"{row.get('sanitized_ioc_count', 0)}/{row.get('removed_ioc_count', 0)} | "
                f"{total_iocs} | "
                f"{row.get('technique_count', 0)} | {row.get('event_count', 0)} |"
            )
        lines.append("")

    key_differences = full_report.get("key_differences") or []
    if key_differences:
        _h(2, "Key Differences")
        for item in key_differences:
            _li(str(item))
        lines.append("")

    gaps = full_report.get("gaps") or []
    if gaps:
        _h(2, "Gaps")
        for item in gaps:
            _li(str(item))
        lines.append("")

    enrichment = full_report.get("enrichment_opportunities") or []
    if enrichment:
        _h(2, "Enrichment Opportunities")
        for item in enrichment:
            _li(str(item))
        lines.append("")

    recommended = full_report.get("recommended_combination", "")
    if recommended:
        _h(2, "Recommended Combination")
        _p(recommended)

    return "\n".join(lines)


def render_comparison_pdf(full_report: dict[str, Any]) -> bytes:
    """Render a comparison full_report dict as a PDF byte string using reportlab.

    Shares the same print-oriented light palette/table helpers as
    render_report_pdf() (re-derived here rather than shared, matching that
    function's self-contained local-import style).
    """
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    from backend.config.loader import load_app_title

    PAGE_W, PAGE_H = A4
    LEFT_MARGIN = 2 * cm
    RIGHT_MARGIN = 2 * cm
    TOP_MARGIN = 2.5 * cm
    BOT_MARGIN = 2 * cm

    buf = BytesIO()
    app_title = load_app_title().strip()

    _COL_H1 = colors.HexColor("#0f172a")
    _COL_H2 = colors.HexColor("#1e293b")
    _COL_ACCENT_RULE = colors.HexColor("#2f58f0")
    _COL_META = colors.HexColor("#64748b")
    _COL_TABLE_HEADER_BG = colors.HexColor("#e0e7ff")
    _COL_TABLE_HEADER_FG = colors.HexColor("#1e293b")
    _COL_TABLE_ROW_ALT = colors.HexColor("#f8fafc")
    _COL_TABLE_ROW_NORM = colors.white
    _COL_TABLE_BORDER = colors.HexColor("#cbd5e1")

    def _footer(canvas, doc):  # type: ignore[no-untyped-def]
        canvas.saveState()
        canvas.setStrokeColor(_COL_TABLE_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(LEFT_MARGIN, BOT_MARGIN * 0.75, PAGE_W - RIGHT_MARGIN, BOT_MARGIN * 0.75)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(_COL_META)
        if app_title:
            canvas.drawString(LEFT_MARGIN, BOT_MARGIN * 0.4, app_title)
        canvas.drawCentredString(PAGE_W / 2.0, BOT_MARGIN * 0.4, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=RIGHT_MARGIN,
        leftMargin=LEFT_MARGIN,
        topMargin=TOP_MARGIN,
        bottomMargin=BOT_MARGIN,
        title=f"Comparison Assessment: {full_report.get('hunt_name', 'Threat Hunt')}",
    )
    styles = getSampleStyleSheet()
    h1_style = ParagraphStyle(
        "CoverH1", parent=styles["Heading1"], fontSize=19, spaceAfter=4, textColor=_COL_H1
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontSize=13,
        spaceAfter=6,
        textColor=_COL_H2,
        spaceBefore=10,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["BodyText"], textColor=colors.HexColor("#1f2937"), leading=14
    )
    meta_style = ParagraphStyle("Meta", parent=body_style, fontSize=9, textColor=_COL_META)

    story: list = []

    def _esc(text: str | None) -> str:
        """Escape XML chars for reportlab Paragraph (issue-local-022:
        defensive against explicit-None dict values — see render_report_pdf's
        `_esc()` docstring for why)."""
        return str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _h1(text: str) -> None:
        story.append(Paragraph(_esc(text), h1_style))

    def _h2(text: str) -> None:
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_COL_ACCENT_RULE))
        story.append(Paragraph(_esc(text), h2_style))

    def _p(text: str) -> None:
        if text:
            story.append(Paragraph(_esc(text), body_style))

    def _sp(h: int = 4) -> None:
        story.append(Spacer(1, h))

    def _styled_table(rows: list[list[str]], col_widths: list) -> Table:  # type: ignore[type-arg]
        table = Table(rows, colWidths=col_widths, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), _COL_TABLE_HEADER_BG),
                    ("TEXTCOLOR", (0, 0), (-1, 0), _COL_TABLE_HEADER_FG),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_COL_TABLE_ROW_NORM, _COL_TABLE_ROW_ALT]),
                    ("GRID", (0, 0), (-1, -1), 0.5, _COL_TABLE_BORDER),
                    ("BOX", (0, 0), (-1, -1), 0.75, _COL_TABLE_BORDER),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        return table

    hunt_name = full_report.get("hunt_name", "Unnamed Hunt")
    hunt_id_display = full_report.get("hunt_id_display", "")
    title_prefix = f"[{hunt_id_display}] " if hunt_id_display else ""
    _h1(f"{title_prefix}Comparison Assessment: {hunt_name}")
    story.append(HRFlowable(width="100%", thickness=2.5, color=_COL_ACCENT_RULE))
    _sp(6)

    meta_parts = []
    if hunt_id_display:
        meta_parts.append(f"HuntID: {hunt_id_display}")
    if full_report.get("hunt_id"):
        meta_parts.append(f"Internal ID: {full_report['hunt_id']}")
    if full_report.get("generated_at"):
        meta_parts.append(f"Generated: {full_report['generated_at']}")
    compared = full_report.get("compared_run_ids") or []
    meta_parts.append(f"Runs Compared: {len(compared)}")
    if meta_parts:
        story.append(Paragraph("  |  ".join(_esc(m) for m in meta_parts), meta_style))
    _sp(8)

    summary = full_report.get("summary", "")
    if summary:
        _h2("Summary")
        _p(summary)

    diff_table = full_report.get("diff_table") or []
    if diff_table:
        _h2(f"Run Diff Table ({len(diff_table)} run(s))")
        try:
            rows = [
                [
                    "Run",
                    "Model",
                    "Effort",
                    "Status",
                    "Hyps",
                    "IOCs kept/rm",
                    "Total IOCs",
                    "TTPs",
                    "Events",
                ]
            ]
            for row in diff_table:
                # issue-local-026: explicit total, falls back to summing
                # kept+removed for reports persisted before this field existed.
                total_iocs = row.get("total_ioc_count")
                if total_iocs is None:
                    total_iocs = (row.get("sanitized_ioc_count") or 0) + (
                        row.get("removed_ioc_count") or 0
                    )
                rows.append(
                    [
                        row.get("run_id_display", ""),
                        row.get("model", ""),
                        row.get("effort", ""),
                        row.get("status", ""),
                        str(row.get("hypothesis_count", 0)),
                        f"{row.get('sanitized_ioc_count', 0)}/{row.get('removed_ioc_count', 0)}",
                        str(total_iocs),
                        str(row.get("technique_count", 0)),
                        str(row.get("event_count", 0)),
                    ]
                )
            story.append(
                _styled_table(
                    rows,
                    [
                        2 * cm,
                        2.2 * cm,
                        1.6 * cm,
                        1.8 * cm,
                        1.4 * cm,
                        2 * cm,
                        1.6 * cm,
                        1.4 * cm,
                        None,
                    ],
                )
            )
        except Exception:  # noqa: BLE001
            for row in diff_table:
                _p(
                    f"{row.get('run_id_display', '')}: {row.get('model', '')}, "
                    f"status={row.get('status', '')}, hypotheses={row.get('hypothesis_count', 0)}"
                )

    key_differences = full_report.get("key_differences") or []
    if key_differences:
        _h2("Key Differences")
        for item in key_differences:
            _p(f"• {item}")

    gaps = full_report.get("gaps") or []
    if gaps:
        _h2("Gaps")
        for item in gaps:
            _p(f"• {item}")

    enrichment = full_report.get("enrichment_opportunities") or []
    if enrichment:
        _h2("Enrichment Opportunities")
        for item in enrichment:
            _p(f"• {item}")

    recommended = full_report.get("recommended_combination", "")
    if recommended:
        _h2("Recommended Combination")
        _p(recommended)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def _build_fallback_summary(full_report: dict[str, Any]) -> str:
    """Build a deterministic plain-text executive summary without the LLM."""
    hunt_name = full_report.get("hunt_name", "this hunt")
    hypotheses = full_report.get("hypotheses") or []
    retro = full_report.get("deep_retrohunt_summary") or {}
    exec_results = full_report.get("execution_results") or []
    total_events = sum(r.get("event_count", 0) for r in exec_results)
    ioc_count = retro.get("total_iocs", 0)
    threat_ctx = full_report.get("threat_context") or {}
    threat_summary = str(threat_ctx.get("summary", "")).strip()

    parts: list[str] = []
    parts.append(
        f"Threat hunt '{hunt_name}' has been completed with "
        f"{len(hypotheses)} hypothesis(es) generated."
    )
    if threat_summary:
        parts.append(threat_summary)
    if ioc_count:
        parts.append(
            f"The deep retrohunt searched {ioc_count} IOC(s) against the SIEM, "
            f"returning {total_events} event(s)."
        )
    elif exec_results:
        parts.append(f"Execution produced {total_events} SIEM event(s).")
    parts.append("Review the full report for detailed findings and recommendations.")
    return " ".join(parts)
