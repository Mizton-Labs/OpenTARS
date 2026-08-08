"""LangGraph node: query_drafting_agent

Uses the LLM to produce SIEM query drafts for the hunting leads and TTP
techniques identified in earlier pipeline nodes, in whichever query
languages are enabled (issue-local-041): SPL, KQL, CQL (CrowdStrike Query
Language / LogScale), and Elasticsearch Query DSL. Which languages draft
defaults to the configured global default (th_query_languages), overridable
per-run via run_config.query_languages. Always generates at least one draft
in the first enabled language.
"""

from __future__ import annotations

import json
import time

from backend.threat_hunting.agents.effort_profile import get_effort_profile
from backend.threat_hunting.agents.llm_bridge import (
    build_prompt,
    call_llm,
    call_llm_with_tools,
    parse_json_response,
)
from backend.threat_hunting.agents.logging_utils import get_run_logger
from backend.threat_hunting.agents.state import HuntPipelineState

# issue-local-041: config key (th_query_languages / run_config.query_languages)
# -> the 'language' field value the LLM should emit on each draft. Kept
# distinct because "es_dsl" (the pre-existing convention for drafts) predates
# and doesn't match the config key "elasticsearch".
_LANGUAGE_DRAFT_ID: dict[str, str] = {
    "spl": "spl",
    "kql": "kql",
    "cql": "cql",
    "elasticsearch": "es_dsl",
}
_LANGUAGE_DESCRIPTIONS: dict[str, str] = {
    "spl": "Splunk Search Processing Language (SPL)",
    "kql": "Kusto Query Language (KQL), for Microsoft Sentinel/Defender",
    "cql": "CrowdStrike Query Language (CQL), for Falcon LogScale",
    "elasticsearch": "Elasticsearch Query DSL (serialize the query object to a JSON string)",
}


def _resolve_query_languages(state: HuntPipelineState) -> list[str]:
    """Which config keys (spl/kql/cql/elasticsearch) are enabled for this
    run — per-run run_config.query_languages override, else the global
    default. Always returns at least one key (falls back to ['spl'] if
    every language somehow ended up disabled)."""
    from backend.config.loader import load_th_query_languages

    run_config = state.get("run_config") or {}
    override = run_config.get("query_languages")
    languages = dict(load_th_query_languages())
    if isinstance(override, dict) and override:
        languages.update({k: bool(v) for k, v in override.items() if k in languages})
    enabled = [lang for lang in ("spl", "kql", "cql", "elasticsearch") if languages.get(lang)]
    return enabled or ["spl"]

_OUTPUT_FORMAT = """[
  {
    "id": "Q1",
    "language": "spl",
    "title": "...",
    "description": "...",
    "query": "index=* (...) | stats ...",
    "data_sources": ["endpoint", "network"],
    "lead_id": "L1"
  },
  {
    "id": "Q2",
    "language": "kql",
    "title": "...",
    "description": "...",
    "query": "...",
    "data_sources": ["endpoint"],
    "lead_id": "L1"
  }
]"""


_TOOL_NAMES = ["validate_spl", "mitre_lookup"]


async def query_drafting_agent(state: HuntPipelineState) -> dict:
    start = time.monotonic()
    step = "query_drafting_agent"
    log = get_run_logger(__name__, state.get("hunt_package_id"), state.get("run_id"))
    logs = list(state.get("step_logs") or [])
    errors = list(state.get("errors") or [])
    completed = list(state.get("completed_steps") or [])
    tools_used: list[str] = []
    debug_lines: list[str] = []
    decision = ""
    try:
        from backend.config.loader import load_agent_tools
        from backend.llm.errors import LLMDisabledError
        from backend.threat_hunting.agents.tools import call_tool, get_enabled_tool_specs

        profile = get_effort_profile(state.get("research_effort"))
        ioc_sample_limit = profile["ioc_sample_limit"]

        hunting_leads = state.get("hunting_leads") or []
        ttp_analysis = state.get("ttp_analysis") or {}
        raw_ioc_list = state.get("raw_ioc_list") or []

        hunting_leads_text = json.dumps(hunting_leads, indent=2)
        ttp_analysis_text = json.dumps(ttp_analysis, indent=2)

        enabled_languages = _resolve_query_languages(state)
        draft_ids = [_LANGUAGE_DRAFT_ID[lang] for lang in enabled_languages]
        languages_text = ", ".join(_LANGUAGE_DESCRIPTIONS[lang] for lang in enabled_languages)

        # Use a capped sample of IOCs to keep prompt size manageable
        ioc_sample = raw_ioc_list[:ioc_sample_limit]
        ioc_sample_text = json.dumps(
            [
                {
                    "ioc": i.get("ioc"),
                    "ioc_type": i.get("ioc_type"),
                    "description": i.get("ioc_description"),
                }
                for i in ioc_sample
            ],
            indent=2,
        )

        system, user = build_prompt(
            task_description=(
                f"Draft SIEM search queries ({languages_text}) for the provided "
                "hunting leads and TTP techniques. Each query should be concrete, "
                "incorporate the available IOCs where relevant, and be directly "
                "usable in the stated SIEM/search environment."
            ),
            context_sections=[
                ("Hunting Leads", hunting_leads_text),
                ("TTP Analysis", ttp_analysis_text),
                (f"IOC Sample (first {ioc_sample_limit})", ioc_sample_text),
            ],
            output_format=_OUTPUT_FORMAT,
            additional_instructions=(
                f"Draft ONLY in these languages, using exactly these 'language' field values: "
                f"{', '.join(draft_ids)}. Always include at least one {draft_ids[0]!r} query. "
                "Produce equivalents in the other enabled languages for each lead where applicable. "
                "Assign sequential IDs: Q1, Q2, Q3, etc. "
                "Set lead_id to the matching hunting lead ID (e.g. 'L1') or null if the "
                "query is TTP-driven rather than lead-specific. "
                "Queries should use realistic field names and operators for the stated language. "
                "'query' MUST always be a plain string, even for language='es_dsl' — if the "
                "query is naturally a JSON object (Elasticsearch Query DSL), serialize it to a "
                "JSON string rather than emitting a nested object."
            ),
        )

        usage: dict = {}
        prompts: list = []
        response = await call_llm(
            user,
            system=system,
            provider_name=state.get("provider_name"),
            model=state.get("model_name"),
            max_tokens=profile["query_tokens"],
            usage_out=usage,
            prompt_log_out=prompts,
        )

        parsed = parse_json_response(response, context=step)

        # Ensure result is a list
        if isinstance(parsed, list):
            query_drafts = parsed
        elif isinstance(parsed, dict):
            log.warning("query_drafting_agent: got dict instead of list, wrapping")
            query_drafts = [parsed]
        else:
            log.error(
                "query_drafting_agent: unexpected parse result type=%s", type(parsed).__name__
            )
            errors.append(f"{step}: unexpected LLM response type, using empty list")
            query_drafts = []

        # Defensive normalization: models occasionally return the ES DSL
        # 'query' as a nested JSON object instead of the string the schema
        # asks for (e.g. {"bool": {"must": [...]}}), or omit it (None).
        # Every consumer (the tool-validation join just below, DB/JSON
        # storage, and the frontend render) expects a plain string — a
        # None here breaks str.join() and crashes this whole step (losing
        # every draft, not just the bad one); an object survives to the
        # frontend and crashes the page (React refuses to render a raw
        # object as a child). Normalize both to a string up front.
        query_drafts = [d for d in query_drafts if isinstance(d, dict)]
        for draft in query_drafts:
            q = draft.get("query")
            if q is None:
                draft["query"] = ""
            elif not isinstance(q, str):
                draft["query"] = json.dumps(q, indent=2, ensure_ascii=False)

        # ── Post-draft tool validation (issue-007: gated by enabled toggles) ──
        # issue-local-041: validate_spl only makes sense when SPL is one of
        # this run's enabled languages — skip entirely otherwise rather than
        # "validating" zero queries.
        if query_drafts and "spl" in enabled_languages:
            tool_specs = get_enabled_tool_specs(_TOOL_NAMES, load_agent_tools())
            if tool_specs:
                spl_queries = [
                    q.get("query", "") for q in query_drafts if q.get("language") == "spl"
                ]
                spl_preview = "\n---\n".join(spl_queries[:3])[:1500]
                validate_prompt = (
                    f"Validate these {len(spl_queries)} SPL queries for syntax issues "
                    f"and look up any MITRE technique IDs referenced in the hunting leads. "
                    f"SPL queries:\n{spl_preview}\n"
                    "Respond with a brief validation summary."
                )
                try:
                    _text, tool_calls = await call_llm_with_tools(
                        validate_prompt,
                        tool_specs,
                        provider_name=state.get("provider_name"),
                        model=state.get("model_name"),
                        max_tokens=400,
                    )
                    decision = _text or "Query validation complete."
                    for tc in tool_calls:
                        tool_name = tc.get("name", "")
                        tool_args = tc.get("arguments", {})
                        debug_lines.append(f"TOOL_CALL: {tool_name}({tool_args})")
                        try:
                            result_val = await call_tool(tool_name, tool_args)
                            tools_used.append(tool_name)
                            debug_lines.append(f"TOOL_RESULT: {str(result_val)[:300]}")
                        except Exception as tool_exc:  # noqa: BLE001
                            debug_lines.append(f"TOOL_ERROR: {tool_exc}")
                except Exception as llm_exc:  # noqa: BLE001
                    debug_lines.append(f"TOOL_LLM_ERROR: {llm_exc}")

        elapsed = time.monotonic() - start
        debug_lines.insert(0, f"LANGUAGES: {', '.join(draft_ids)}")
        logs.append(
            {
                "step": step,
                "status": "ok",
                "elapsed_s": round(elapsed, 2),
                "item_count": len(query_drafts),
                "effort": state.get("research_effort", "medium"),
                "tools_used": tools_used,
                "decision": decision,
                "debug_lines": debug_lines,
                "tokens": usage or None,
                "prompts": prompts or None,
            }
        )
        completed.append(step)
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
            "query_drafts": query_drafts,
        }
    except Exception as exc:
        from backend.llm.errors import LLMDisabledError

        if isinstance(exc, LLMDisabledError):
            log.warning("Node %s: LLM is disabled — skipping", step)
        else:
            log.exception("Node %s failed: %s", step, exc)
        errors.append(f"{step}: {exc}")
        elapsed = time.monotonic() - start
        logs.append(
            {
                "step": step,
                "status": "error",
                "elapsed_s": round(elapsed, 2),
                "error": str(exc),
                "tools_used": tools_used,
                "debug_lines": debug_lines,
            }
        )
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
        }
