"""LangGraph node: ttp_analyst

Uses the LLM to produce a behavioral TTP (Tactics, Techniques, and Procedures)
analysis aligned with the MITRE ATT&CK framework, derived from the threat
context built by earlier pipeline nodes.
"""

from __future__ import annotations

import json
import logging
import time

from backend.threat_hunting.agents.effort_profile import get_effort_profile
from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm, parse_json_response
from backend.threat_hunting.agents.state import HuntPipelineState

logger = logging.getLogger(__name__)

_OUTPUT_FORMAT = """{
  "summary": "...",
  "techniques": [
    {
      "technique_id": "T1059.001",
      "technique_name": "PowerShell",
      "tactic": "Execution",
      "description": "...",
      "evidence_basis": "..."
    }
  ],
  "detection_opportunities": ["...", "..."]
}"""


async def ttp_analyst(state: HuntPipelineState) -> dict:
    start = time.monotonic()
    step = "ttp_analyst"
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
                "Perform a behavioral TTP analysis aligned with the MITRE ATT&CK framework "
                "based on the threat context and hunting hypotheses. Identify specific ATT&CK "
                "techniques observed or suspected, and highlight detection opportunities."
            ),
            context_sections=[
                ("Threat Context", threat_context_text),
                ("Hunting Hypotheses", hypotheses_text),
            ],
            output_format=_OUTPUT_FORMAT,
            additional_instructions=(
                "Use canonical MITRE ATT&CK technique IDs (e.g. T1059.001). "
                "Only include techniques that are supported by evidence in the threat context. "
                "Detection opportunities should be actionable — reference specific log sources, "
                "artifacts, or behavioral indicators."
            ),
        )

        profile = get_effort_profile(state.get("research_effort"))
        response = await call_llm(
            user,
            system=system,
            provider_name=state.get("provider_name"),
            model=state.get("model_name"),
            max_tokens=profile["ttp_tokens"],
        )

        parsed = parse_json_response(response, context=step)

        if isinstance(parsed, dict):
            ttp_analysis = parsed
        else:
            logger.error("ttp_analyst: unexpected parse result type=%s", type(parsed).__name__)
            errors.append(f"{step}: unexpected LLM response type; storing raw")
            ttp_analysis = {"raw_response": str(parsed), "parse_error": True}

        elapsed = time.monotonic() - start
        logs.append(
            {
                "step": step,
                "status": "ok",
                "elapsed_s": round(elapsed, 2),
                "effort": state.get("research_effort", "medium"),
            }
        )
        completed.append(step)
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
            "ttp_analysis": ttp_analysis,
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
