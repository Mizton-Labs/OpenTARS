"""LangGraph node: hunting_lead_planner

Uses the LLM to generate 2-4 concrete hunting leads from the hypotheses,
each with sub-tasks that map to specific data sources and detection activities.
"""

from __future__ import annotations

import json
import logging
import time

from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm, parse_json_response
from backend.threat_hunting.agents.state import HuntPipelineState

logger = logging.getLogger(__name__)

_OUTPUT_FORMAT = """[
  {
    "id": "L1",
    "hypothesis_id": "H1",
    "title": "...",
    "description": "...",
    "priority": "high|medium|low",
    "tasks": [
      {
        "id": "T1.1",
        "title": "...",
        "description": "...",
        "datasource": "endpoint|network|cloud|email|proxy",
        "query_hint": "..."
      }
    ]
  }
]"""


async def hunting_lead_planner(state: HuntPipelineState) -> dict:
    start = time.monotonic()
    step = "hunting_lead_planner"
    logs = list(state.get("step_logs") or [])
    errors = list(state.get("errors") or [])
    completed = list(state.get("completed_steps") or [])
    try:
        from backend.llm.errors import LLMDisabledError

        threat_context = state.get("threat_context") or {}
        hypotheses = state.get("hypotheses") or []

        threat_context_text = json.dumps(threat_context, indent=2)
        hypotheses_text = json.dumps(hypotheses, indent=2)

        system, user = build_prompt(
            task_description=(
                "Generate 2-4 concrete, actionable threat hunting leads from the "
                "provided hypotheses and threat context. Each lead must include "
                "specific sub-tasks with data source guidance and query hints."
            ),
            context_sections=[
                ("Threat Context Summary", threat_context_text),
                ("Hypotheses", hypotheses_text),
            ],
            output_format=_OUTPUT_FORMAT,
            additional_instructions=(
                "Return a JSON array with 2-4 hunting lead objects. "
                "Assign sequential IDs: L1, L2, etc. "
                "Task IDs should follow the pattern T<lead_num>.<task_num> (e.g. T1.1, T1.2). "
                "Each lead must reference an existing hypothesis_id. "
                "Prioritize leads by their likelihood of surfacing adversary activity."
            ),
        )

        response = await call_llm(
            user,
            system=system,
            provider_name=state.get("provider_name"),
            model=state.get("model_name"),
            max_tokens=2500,
        )

        parsed = parse_json_response(response, context=step)

        # Ensure result is a list
        if isinstance(parsed, list):
            hunting_leads = parsed
        elif isinstance(parsed, dict):
            logger.warning("hunting_lead_planner: got dict instead of list, wrapping")
            hunting_leads = [parsed]
        else:
            logger.error(
                "hunting_lead_planner: unexpected parse result type=%s", type(parsed).__name__
            )
            errors.append(f"{step}: unexpected LLM response type, using empty list")
            hunting_leads = []

        elapsed = time.monotonic() - start
        logs.append({"step": step, "status": "ok", "elapsed_s": round(elapsed, 2)})
        completed.append(step)
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
            "hunting_leads": hunting_leads,
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
