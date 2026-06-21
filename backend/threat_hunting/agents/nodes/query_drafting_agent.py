"""LangGraph node: query_drafting_agent

Uses the LLM to produce SIEM query drafts (SPL, KQL, and ES DSL) for the
hunting leads and TTP techniques identified in earlier pipeline nodes.
Always generates at least one SPL draft; adds KQL and ES DSL versions where
applicable.
"""

from __future__ import annotations

import json
import logging
import time

from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm, parse_json_response
from backend.threat_hunting.agents.state import HuntPipelineState

logger = logging.getLogger(__name__)

_IOC_SAMPLE_LIMIT = 20  # cap IOCs sent in the query-drafting prompt

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


async def query_drafting_agent(state: HuntPipelineState) -> dict:
    start = time.monotonic()
    step = "query_drafting_agent"
    logs = list(state.get("step_logs") or [])
    errors = list(state.get("errors") or [])
    completed = list(state.get("completed_steps") or [])
    try:
        from backend.llm.errors import LLMDisabledError

        hunting_leads = state.get("hunting_leads") or []
        ttp_analysis = state.get("ttp_analysis") or {}
        raw_ioc_list = state.get("raw_ioc_list") or []

        hunting_leads_text = json.dumps(hunting_leads, indent=2)
        ttp_analysis_text = json.dumps(ttp_analysis, indent=2)

        # Use a capped sample of IOCs to keep prompt size manageable
        ioc_sample = raw_ioc_list[:_IOC_SAMPLE_LIMIT]
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
                "Draft SIEM search queries (SPL, KQL, and ES DSL) for the provided "
                "hunting leads and TTP techniques. Each query should be concrete, "
                "incorporate the available IOCs where relevant, and be directly "
                "usable in a Splunk, Microsoft Sentinel, or Elastic SIEM environment."
            ),
            context_sections=[
                ("Hunting Leads", hunting_leads_text),
                ("TTP Analysis", ttp_analysis_text),
                ("IOC Sample (first 20)", ioc_sample_text),
            ],
            output_format=_OUTPUT_FORMAT,
            additional_instructions=(
                "Always include at least one SPL query. "
                "Also produce KQL and ES DSL equivalents for each lead where applicable. "
                "Assign sequential IDs: Q1, Q2, Q3, etc. "
                "Set lead_id to the matching hunting lead ID (e.g. 'L1') or null if the "
                "query is TTP-driven rather than lead-specific. "
                "Queries should use realistic field names and operators for the stated language."
            ),
        )

        response = await call_llm(
            user,
            system=system,
            provider_name=state.get("provider_name"),
            model=state.get("model_name"),
            max_tokens=3000,
        )

        parsed = parse_json_response(response, context=step)

        # Ensure result is a list
        if isinstance(parsed, list):
            query_drafts = parsed
        elif isinstance(parsed, dict):
            logger.warning("query_drafting_agent: got dict instead of list, wrapping")
            query_drafts = [parsed]
        else:
            logger.error(
                "query_drafting_agent: unexpected parse result type=%s", type(parsed).__name__
            )
            errors.append(f"{step}: unexpected LLM response type, using empty list")
            query_drafts = []

        elapsed = time.monotonic() - start
        logs.append({"step": step, "status": "ok", "elapsed_s": round(elapsed, 2)})
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
            logger.warning("Node %s: LLM is disabled — skipping", step)
        else:
            logger.exception("Node %s failed: %s", step, exc)
        errors.append(f"{step}: {exc}")
        elapsed = time.monotonic() - start
        logs.append(
            {"step": step, "status": "error", "elapsed_s": round(elapsed, 2), "error": str(exc)}
        )
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
        }
