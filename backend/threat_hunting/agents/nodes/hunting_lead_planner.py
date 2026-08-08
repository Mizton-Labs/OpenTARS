"""LangGraph node: hunting_lead_planner

Uses the LLM to generate 2-4 concrete hunting leads from the hypotheses,
each with sub-tasks that map to specific data sources and detection activities.
"""

from __future__ import annotations

import json
import time

from backend.threat_hunting.agents.effort_profile import get_effort_profile
from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm, parse_json_response
from backend.threat_hunting.agents.logging_utils import get_run_logger
from backend.threat_hunting.agents.state import HuntPipelineState

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
    log = get_run_logger(__name__, state.get("hunt_package_id"), state.get("run_id"))
    logs = list(state.get("step_logs") or [])
    errors = list(state.get("errors") or [])
    completed = list(state.get("completed_steps") or [])
    # issue-local-021: feeds WorkflowVisualizer.tsx's per-run "Pipeline Log"
    # debug console — this node previously emitted none.
    debug_lines: list[str] = []
    try:
        from backend.llm.errors import LLMDisabledError

        profile = get_effort_profile(state.get("research_effort"))
        l_min, l_max = profile["leads_range"]

        threat_context = state.get("threat_context") or {}
        hypotheses = state.get("hypotheses") or []

        threat_context_text = json.dumps(threat_context, indent=2)
        hypotheses_text = json.dumps(hypotheses, indent=2)

        system, user = build_prompt(
            task_description=(
                f"Generate {l_min}-{l_max} concrete, actionable threat hunting leads from the "
                "provided hypotheses and threat context. Each lead must include "
                "specific sub-tasks with data source guidance and query hints."
            ),
            context_sections=[
                ("Threat Context Summary", threat_context_text),
                ("Hypotheses", hypotheses_text),
            ],
            output_format=_OUTPUT_FORMAT,
            additional_instructions=(
                f"Return a JSON array with {l_min}-{l_max} hunting lead objects. "
                "Assign sequential IDs: L1, L2, etc. "
                "Task IDs should follow the pattern T<lead_num>.<task_num> (e.g. T1.1, T1.2). "
                "Each lead must reference an existing hypothesis_id. "
                "Prioritize leads by their likelihood of surfacing adversary activity."
            ),
        )

        debug_lines.append(f"LLM_CALL: requesting {l_min}-{l_max} hunting leads")
        usage: dict = {}
        prompts: list = []
        response = await call_llm(
            user,
            system=system,
            provider_name=state.get("provider_name"),
            model=state.get("model_name"),
            max_tokens=profile["leads_tokens"],
            usage_out=usage,
            prompt_log_out=prompts,
        )

        parsed = parse_json_response(response, context=step)

        # Ensure result is a list
        if isinstance(parsed, list):
            hunting_leads = parsed
        elif isinstance(parsed, dict):
            log.warning("hunting_lead_planner: got dict instead of list, wrapping")
            debug_lines.append("LLM_RESPONSE: got dict instead of list, wrapping as single item")
            hunting_leads = [parsed]
        else:
            log.error(
                "hunting_lead_planner: unexpected parse result type=%s", type(parsed).__name__
            )
            errors.append(f"{step}: unexpected LLM response type, using empty list")
            debug_lines.append(f"LLM_PARSE_ERROR: unexpected type {type(parsed).__name__}")
            hunting_leads = []

        # issue-local-015: discarded is always app-set, never trusted from
        # the LLM even if it happens to echo the field back — same pattern
        # as Hypothesis.discarded in hypothesis_generator.py.
        for lead in hunting_leads:
            if isinstance(lead, dict):
                lead["discarded"] = False

        debug_lines.append(f"LLM_RESPONSE: {len(hunting_leads)} hunting lead(s) parsed")
        elapsed = time.monotonic() - start
        logs.append(
            {
                "step": step,
                "status": "ok",
                "elapsed_s": round(elapsed, 2),
                "item_count": len(hunting_leads),
                "effort": state.get("research_effort", "medium"),
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
            "hunting_leads": hunting_leads,
        }
    except Exception as exc:
        from backend.llm.errors import LLMDisabledError

        if isinstance(exc, LLMDisabledError):
            log.warning("Node %s: LLM is disabled — skipping", step)
            debug_lines.append("LLM_DISABLED: skipping hunting lead planning")
        else:
            log.exception("Node %s failed: %s", step, exc)
            debug_lines.append(f"LLM_ERROR: {exc}")
        errors.append(f"{step}: {exc}")
        elapsed = time.monotonic() - start
        logs.append(
            {
                "step": step,
                "status": "error",
                "elapsed_s": round(elapsed, 2),
                "error": str(exc),
                "debug_lines": debug_lines,
            }
        )
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
        }
