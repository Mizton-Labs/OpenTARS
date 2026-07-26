"""Threat Hunt Intelligence Analyst (issue-local-020, two-phase in issue-local-021).

**Not a LangGraph node** — unlike the other files in this `nodes/` package,
this module is a plain async function, not a `HuntPipelineState`-consuming
graph node. It runs in two phases, gated by the run's `include_threat_intel`
config flag (default on):

  - ``phase="preliminary"`` — called from
    `backend/threat_hunting/agents/runner.py` right after the generation
    pipeline reaches ``completed`` (hypotheses/threat_context/ttp_analysis/
    deep_retrohunt exist, but no SIEM execution results yet).
  - ``phase="final"`` — called from `backend/threat_hunting/siem/executor.py`
    after SIEM execution completes and before the report is written. This
    phase ADDITIONALLY ingests this run's execution results
    (`task_results`/`interpreted_findings`) to confirm/refine the
    preliminary findings — the only behavioral difference between the phases.

Both call sites mirror `report_writer.write_report()`'s "plain function,
not a graph node" shape (SIEM execution lives entirely outside
`agents/pipeline.py`'s graph, so there is no node to attach this to).

Correlates the current run's threat context, hypotheses, TTPs, and kept IOCs
against ALL OTHER hunt packages (shared IOCs), producing threat actors,
attribution, malware families, campaigns, related vendor reporting, and a
cross-package IOC correlation list. Persisted via
`backend.threat_hunting.db.create_threat_intel_analysis` — each phase's call
persists a new row for the same run_id, so `get_threat_intel_analysis_by_run`
(latest-by-created_at) naturally surfaces the final/richer phase once it has
run, without needing a separate `phase` column (last-write-wins).

Soft-fail throughout: an LLM failure still persists the deterministic fields
(extracted directly from threat_context) plus the DB-derived cross-package
IOC correlations, so the Threat Intelligence tab is never left completely
empty just because the LLM step failed.
"""

from __future__ import annotations

from typing import Any

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm, parse_json_response
from backend.threat_hunting.agents.logging_utils import get_run_logger

_OUTPUT_FORMAT = """{
  "threat_actors": [{"name": "...", "confidence": "high|medium|low", "rationale": "..."}],
  "attribution": {"assessment": "...", "confidence": "high|medium|low", "rationale": "..."},
  "malware_families": ["...", "..."],
  "campaigns": [{"name": "...", "description": "..."}],
  "related_vendors": [{"vendor": "...", "report": "...", "campaign": "..."}],
  "correlated_ioc_notes": "...",
  "summary": "..."
}"""

_SYSTEM_PROMPT = (
    "You are a Threat Intelligence Analyst. Given a hunt's threat context, hypotheses, TTP "
    "analysis, and a list of IOCs this hunt shares with OTHER hunt packages already in the "
    "system, extract and correlate: threat actors, attribution signals, malware families, "
    "campaigns, and any related third-party vendor reporting you are aware of for the same "
    "actor/campaign/malware family. Do not fabricate actors, campaigns, or vendor reports not "
    "supported by the evidence provided — when genuinely unsure, omit the item or lower your "
    "confidence rather than inventing detail."
)

# Cap on how many cross-package IOC matches are included in the prompt —
# matches report_writer.py's per-field truncation convention (character/
# item-count slices, no token counting anywhere in this codebase).
_MAX_CORRELATED_IOCS_IN_PROMPT = 20


async def analyze_threat_intel(
    hunt_package_id: str,
    *,
    run_id: str,
    phase: str = "final",
    provider_name: str | None = None,
    model_name: str | None = None,
    created_by: str | None = None,
) -> dict[str, Any] | None:
    """Analyze and persist Threat Intelligence for one run. Returns the
    persisted record, or None if the run doesn't exist. Never raises —
    callers (runner.py/executor.py) still wrap this in try/except as defense
    in depth, matching the existing soft-fail convention for post-execution
    steps.

    ``phase="final"`` (the default) additionally ingests this run's SIEM
    execution results; ``phase="preliminary"`` analyzes only the
    hypotheses/threat-context/TTP/IOC data available before execution."""
    log = get_run_logger(__name__, hunt_package_id, run_id)
    # issue-local-021: feeds WorkflowVisualizer.tsx's per-run "Pipeline Log"
    # debug console — this node previously emitted none.
    debug_lines: list[str] = []

    record = await th_db.get_generation_run(run_id)
    if not record:
        log.warning("threat_intel_analyst: run not found, skipping")
        return None

    threat_context = record.get("threat_context") or {}
    hypotheses = record.get("hypotheses") or []
    ttp_analysis = record.get("ttp_analysis") or {}

    # Deterministic extraction — seeds structured fields even if the LLM
    # step below fails entirely.
    det_actor = str(threat_context.get("threat_actor") or "").strip()
    det_campaign = str(threat_context.get("campaign_name") or "").strip()
    det_malware_families = [
        str(m) for m in (threat_context.get("malware_families") or []) if str(m).strip()
    ]
    det_attack_vector = str(threat_context.get("attack_vector") or "").strip()

    threat_actors: list[dict[str, Any]] = (
        [
            {
                "name": det_actor,
                "confidence": str(threat_context.get("confidence") or "unknown"),
                "rationale": "From this run's threat context analysis.",
            }
        ]
        if det_actor
        else []
    )
    attribution: dict[str, Any] | None = (
        {
            "assessment": det_actor or "Unknown",
            "confidence": str(threat_context.get("confidence") or "unknown"),
            "rationale": str(threat_context.get("summary") or "")[:500],
        }
        if det_actor
        else None
    )
    campaigns: list[dict[str, Any]] = (
        [{"name": det_campaign, "description": ""}] if det_campaign else []
    )
    related_vendors: list[dict[str, Any]] = []
    summary = str(threat_context.get("summary") or "")

    # Cross-package IOC correlation — authoritative from the DB, never
    # LLM-generated (the LLM only gets a capped preview for narrative context).
    try:
        this_run_iocs = await th_db.list_extracted_iocs(hunt_package_id, run_id)
        kept_iocs = [
            i["ioc"] for i in this_run_iocs if i.get("action") != "remove" and i.get("ioc")
        ]
        correlated_iocs = await th_db.find_cross_package_ioc_matches(hunt_package_id, kept_iocs)
    except Exception as exc:  # noqa: BLE001
        log.warning("threat_intel_analyst: IOC correlation query failed (non-fatal): %s", exc)
        debug_lines.append(f"IOC_CORRELATION_ERROR: {exc}")
        correlated_iocs = []

    # issue-local-021: the final phase additionally ingests this run's SIEM
    # execution results — the only content difference between the two phases.
    # Soft-fail: an error here just means the LLM context is missing this
    # section, not that the whole analysis fails.
    execution_findings_line = "not yet executed (preliminary phase)"
    if phase == "final":
        try:
            task_results = await th_db.list_task_results_by_run(run_id)
            completed_results = [r for r in task_results if r.get("status") == "completed"]
            total_events = sum(len(r.get("raw_result") or []) for r in completed_results)
            findings_texts = [
                r["interpreted_findings"]
                for r in completed_results
                if r.get("interpreted_findings")
                and "unavailable" not in r.get("interpreted_findings", "")
            ]
            execution_findings_line = (
                f"{total_events} SIEM event(s) matched across {len(completed_results)} "
                f"execution(s). Findings: {'; '.join(findings_texts[:3]) or 'none reported'}"
                if completed_results
                else "SIEM execution completed with no matching events"
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("threat_intel_analyst: execution-results fetch failed (non-fatal): %s", exc)
            execution_findings_line = "execution results unavailable"

    # LLM enrichment — soft-fail, deterministic fields above still get persisted.
    try:
        techniques = ", ".join(
            f"{t.get('technique_id', '')} {t.get('technique_name', '')}"
            for t in (ttp_analysis.get("techniques") or [])[:6]
        )
        hyp_titles = "; ".join(h.get("title", "") for h in hypotheses[:5] if h.get("title"))
        ioc_lines = "\n".join(
            f"- {m['ioc']} ({m['ioc_type']}) also seen in hunt {m.get('hunt_name', '')!r}"
            for m in correlated_iocs[:_MAX_CORRELATED_IOCS_IN_PROMPT]
        )

        system, user = build_prompt(
            system=_SYSTEM_PROMPT,
            task_description=(
                "Correlate this hunt's threat context, hypotheses, TTPs, and cross-package IOC "
                "matches into structured threat intelligence."
            ),
            context_sections=[
                ("Threat Context Summary", str(threat_context.get("summary") or "")[:1000]),
                (
                    "Threat Actor / Campaign / Attack Vector",
                    f"actor={det_actor or 'unknown'}, campaign={det_campaign or 'unknown'}, "
                    f"vector={det_attack_vector or 'unknown'}",
                ),
                (
                    "Malware Families (from threat context)",
                    ", ".join(det_malware_families) or "none",
                ),
                ("Top Hypotheses", hyp_titles or "none"),
                ("MITRE ATT&CK Techniques", techniques or "none mapped"),
                (
                    "IOCs Also Found In Other Hunt Packages",
                    ioc_lines or "none — no IOC overlap with other hunt packages",
                ),
                ("SIEM Execution Findings", execution_findings_line),
            ],
            output_format=_OUTPUT_FORMAT,
            additional_instructions=(
                "Prefer the deterministic actor/campaign already given over inventing a new one, "
                "but you may add corroborating detail. If related vendor reporting is not "
                "something you can confidently cite, return an empty related_vendors list. "
                + (
                    "This is the final, post-execution analysis — use the SIEM Execution "
                    "Findings to confirm, refine, or raise/lower confidence on the preliminary "
                    "assessment."
                    if phase == "final"
                    else "This is a preliminary, pre-execution analysis based only on the "
                    "gathered threat intelligence — no SIEM results exist yet."
                )
            ),
        )
        debug_lines.append(f"LLM_CALL: [{phase}] threat intel enrichment requested")
        response = await call_llm(
            user,
            system=system,
            provider_name=provider_name,
            model=model_name,
            max_tokens=1500,
        )
        parsed = parse_json_response(response, context="threat_intel_analyst")
        if isinstance(parsed, dict):
            if parsed.get("threat_actors"):
                threat_actors = parsed["threat_actors"]
            if parsed.get("attribution"):
                attribution = parsed["attribution"]
            if parsed.get("malware_families"):
                det_malware_families = parsed["malware_families"]
            if parsed.get("campaigns"):
                campaigns = parsed["campaigns"]
            if parsed.get("related_vendors"):
                related_vendors = parsed["related_vendors"]
            if parsed.get("summary"):
                summary = parsed["summary"]
            debug_lines.append(f"LLM_RESPONSE: {len(threat_actors)} actor(s) merged from LLM")
    except Exception as exc:  # noqa: BLE001
        from backend.llm.errors import LLMDisabledError

        if isinstance(exc, LLMDisabledError):
            log.info("threat_intel_analyst: LLM disabled — using deterministic fields only")
            debug_lines.append("LLM_DISABLED: using deterministic fields only")
        else:
            log.warning("threat_intel_analyst: LLM enrichment failed (non-fatal): %s", exc)
            debug_lines.append(f"LLM_ERROR: {exc}")

    full_analysis = {
        "phase": phase,
        "threat_actors": threat_actors,
        "attribution": attribution,
        "malware_families": det_malware_families,
        "campaigns": campaigns,
        "related_vendors": related_vendors,
        "correlated_iocs": correlated_iocs,
        "summary": summary,
        "execution_findings": execution_findings_line if phase == "final" else None,
    }

    persisted = await th_db.create_threat_intel_analysis(
        hunt_package_id,
        run_id=run_id,
        threat_actors=threat_actors,
        attribution=attribution,
        malware_families=det_malware_families,
        campaigns=campaigns,
        related_vendors=related_vendors,
        correlated_iocs=correlated_iocs,
        summary=summary,
        full_analysis=full_analysis,
        created_by=created_by,
    )

    try:
        await th_db.append_run_step_log(
            run_id,
            {
                # issue-local-022: distinct step id per phase — both phases
                # previously logged under the same "threat_intel_analyst"
                # name, so the frontend's step_logs-keyed-by-step-name lookup
                # silently overwrote the preliminary phase's entry the moment
                # the final phase ran. Must match PIPELINE_STEPS entries in
                # WorkflowVisualizer.tsx/MermaidVisualizer.tsx/
                # ReactFlowVisualizer.tsx.
                "step": f"threat_intel_{phase}",
                "status": "ok",
                "decision": (
                    f"{len(threat_actors)} actor(s), {len(correlated_iocs)} "
                    f"cross-package IOC match(es)"
                ),
                "debug_lines": debug_lines,
            },
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("threat_intel_analyst: step log append skipped: %s", exc)

    log.info(
        "threat_intel_analyst: %s analysis complete (actors=%d, correlated_iocs=%d)",
        phase,
        len(threat_actors),
        len(correlated_iocs),
    )
    return persisted
