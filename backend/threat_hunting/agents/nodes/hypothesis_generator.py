"""LangGraph node: hypothesis_generator

Uses the LLM to generate 3-6 hunting hypotheses from the threat context and
IOC summary built by earlier pipeline nodes.
"""

from __future__ import annotations

import json
import logging
import time

from backend.threat_hunting.agents.effort_profile import get_effort_profile
from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm, parse_json_response
from backend.threat_hunting.agents.state import HuntPipelineState

logger = logging.getLogger(__name__)

_OUTPUT_FORMAT = """[
  {
    "id": "H1",
    "title": "...",
    "description": "...",
    "justification": "...",
    "relevance": "high|medium|low",
    "ioc_basis": ["ioc1", "ioc2"],
    "suggested_actions": [
      "Run SPL: index=main sourcetype=firewall dest_ip=<IOC>",
      "Check EDR for process creation by <artifact>",
      "MITRE T1059.001 — search PowerShell execution logs"
    ]
  }
]"""


async def hypothesis_generator(state: HuntPipelineState) -> dict:
    start = time.monotonic()
    step = "hypothesis_generator"
    logs = list(state.get("step_logs") or [])
    errors = list(state.get("errors") or [])
    completed = list(state.get("completed_steps") or [])
    try:
        from backend.llm.errors import LLMDisabledError

        profile = get_effort_profile(state.get("research_effort"))
        h_min, h_max = profile["hypotheses_range"]

        threat_context = state.get("threat_context") or {}
        ioc_summary = state.get("ioc_summary") or {}

        threat_context_text = json.dumps(threat_context, indent=2)
        ioc_summary_text = json.dumps(ioc_summary, indent=2)

        system, user = build_prompt(
            task_description=(
                f"Generate {h_min}-{h_max} actionable threat hunting hypotheses derived from the "
                "threat context and IOC summary. Each hypothesis should be testable "
                "and grounded in the available evidence."
            ),
            context_sections=[
                ("Threat Context", threat_context_text),
                ("IOC Summary", ioc_summary_text),
            ],
            output_format=_OUTPUT_FORMAT,
            additional_instructions=(
                f"Return a JSON array with {h_min}-{h_max} hypothesis objects. "
                "Assign sequential IDs: H1, H2, H3, etc. "
                "Prioritize hypotheses that can be hunted with available IOCs. "
                "For each hypothesis, include 2-4 'suggested_actions': specific, actionable "
                "detection steps such as a concrete SIEM query fragment, an EDR artifact to check, "
                "a MITRE ATT&CK technique reference (e.g. T1059.001), or a log source to query. "
                "suggested_actions must be strings, not nested objects."
            ),
        )

        response = await call_llm(
            user,
            system=system,
            provider_name=state.get("provider_name"),
            model=state.get("model_name"),
            max_tokens=profile["hypothesis_tokens"],
        )

        parsed = parse_json_response(response, context=step)

        # Ensure result is a list
        if isinstance(parsed, list):
            hypotheses = parsed
        elif isinstance(parsed, dict):
            logger.warning("hypothesis_generator: got dict instead of list, wrapping")
            hypotheses = [parsed]
        else:
            logger.error(
                "hypothesis_generator: unexpected parse result type=%s", type(parsed).__name__
            )
            errors.append(f"{step}: unexpected LLM response type, using empty list")
            hypotheses = []

        elapsed = time.monotonic() - start
        logs.append(
            {
                "step": step,
                "status": "ok",
                "elapsed_s": round(elapsed, 2),
                "item_count": len(hypotheses),
                "effort": state.get("research_effort", "medium"),
            }
        )
        completed.append(step)
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
            "hypotheses": hypotheses,
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
