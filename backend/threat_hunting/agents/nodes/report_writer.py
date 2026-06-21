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

import logging
import time
from datetime import datetime, timezone
from typing import Any

from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm

logger = logging.getLogger(__name__)


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
) -> dict[str, Any]:
    """Build the full_report dict from all available data."""
    hypotheses = generation_record.get("hypotheses") or []
    hunting_leads = generation_record.get("hunting_leads") or []
    ttp_analysis = generation_record.get("ttp_analysis")
    deep_retrohunt = generation_record.get("deep_retrohunt")
    query_drafts = generation_record.get("query_drafts") or []
    threat_context = generation_record.get("threat_context")

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
        "generated_at": _utc_now(),
        "generated_by": None,
        "package_status": hunt_package.get("status", ""),
        "evidence_summary": _evidence_summary(evidence_items),
        "threat_context": threat_context,
        "hypotheses": hypotheses,
        "hunting_leads": hunting_leads,
        "deep_retrohunt_summary": _retrohunt_summary(deep_retrohunt),
        "ttp_analysis": ttp_analysis,
        "query_drafts_count": len(query_drafts),
        "execution_results": _execution_summary(task_results),
        "recommendations": recommendations,
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
    )

    return await call_llm(
        user,
        system=system,
        provider_name=provider_name,
        model=model_name,
        max_tokens=400,
    )


# ── Public entry point ────────────────────────────────────────────────────────


async def write_report(
    hunt_package_id: str,
    *,
    provider_name: str | None = None,
    model_name: str | None = None,
    created_by: str | None = None,
) -> dict[str, Any]:
    """Assemble and persist the Hunt Report for a completed/approved package.

    Loads all relevant data from the DB, assembles the structured report,
    generates an LLM executive summary (soft-fail), and writes to hunt_reports.

    Returns the persisted report dict.
    """
    start = time.monotonic()
    from backend.threat_hunting import db as th_db

    # Load all source data
    pkg = await th_db.get_hunt_package(hunt_package_id)
    if not pkg:
        raise ValueError(f"Hunt package {hunt_package_id!r} not found")

    generation_record = await th_db.get_generation_record_public(hunt_package_id) or {}
    evidence_items = await th_db.list_evidence_items(hunt_package_id)
    task_results = await th_db.list_task_results(hunt_package_id)

    # Stage 1: deterministic assembly (no LLM)
    full_report = assemble_report(
        pkg,
        generation_record,
        evidence_items,
        task_results,
    )

    # Stage 2: LLM executive summary (soft-fail)
    executive_summary = ""
    try:
        from backend.llm.errors import LLMDisabledError

        executive_summary = await _generate_executive_summary(
            full_report, provider_name=provider_name, model_name=model_name
        )
    except Exception as exc:
        from backend.llm.errors import LLMDisabledError

        if isinstance(exc, LLMDisabledError):
            logger.info("report_writer: LLM disabled — skipping executive summary")
        else:
            logger.exception("report_writer: executive summary generation failed: %s", exc)
        executive_summary = _build_fallback_summary(full_report)

    full_report["executive_summary"] = executive_summary

    # Stage 3: persist
    report = await th_db.create_hunt_report(
        hunt_package_id,
        executive_summary=executive_summary,
        full_report=full_report,
        created_by=created_by,
    )

    # Update package to completed if it was approved
    if pkg.get("status") == "approved":
        await th_db.update_hunt_package(hunt_package_id, status="completed")

    elapsed = time.monotonic() - start
    logger.info("report_writer: report generated for %s in %.2fs", hunt_package_id[:8], elapsed)
    return report


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
