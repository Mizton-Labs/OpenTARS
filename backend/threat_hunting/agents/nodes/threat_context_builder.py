"""LangGraph node: threat_context_builder

Uses the LLM to produce a structured threat context summary from the evidence
corpus and IOC summary produced by intake_classifier.
"""

from __future__ import annotations

import json
import logging
import time

from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm, parse_json_response
from backend.threat_hunting.agents.state import HuntPipelineState

logger = logging.getLogger(__name__)

_EVIDENCE_TRUNCATE = 12_000  # chars — keep prompts within safe token budget

_OUTPUT_FORMAT = """{
  "threat_actor": "...",
  "campaign_name": "...",
  "malware_families": ["..."],
  "attack_vector": "...",
  "target_sectors": ["..."],
  "target_regions": ["..."],
  "summary": "3-5 sentence threat context summary",
  "key_observations": ["...", "..."],
  "confidence": "high|medium|low",
  "evidence_gaps": ["..."]
}"""


async def threat_context_builder(state: HuntPipelineState) -> dict:
    start = time.monotonic()
    step = "threat_context_builder"
    logs = list(state.get("step_logs") or [])
    errors = list(state.get("errors") or [])
    completed = list(state.get("completed_steps") or [])
    try:
        from backend.llm.errors import LLMDisabledError

        corpus: str = state.get("evidence_text_corpus") or ""
        ioc_summary = state.get("ioc_summary") or {}

        # Truncate corpus to avoid token overflow
        corpus_snippet = corpus[:_EVIDENCE_TRUNCATE]
        if len(corpus) > _EVIDENCE_TRUNCATE:
            corpus_snippet += "\n\n[... evidence truncated for context window ...]"

        ioc_summary_text = json.dumps(ioc_summary, indent=2)

        system, user = build_prompt(
            task_description=(
                "Produce a structured threat context summary from the provided evidence "
                "corpus and IOC summary."
            ),
            context_sections=[
                ("Evidence Corpus", corpus_snippet),
                ("IOC Summary", ioc_summary_text),
            ],
            output_format=_OUTPUT_FORMAT,
            additional_instructions=(
                "Base all fields strictly on evidence present in the corpus. "
                "Set confidence based on how conclusive the evidence is."
            ),
        )

        response = await call_llm(
            user,
            system=system,
            provider_name=state.get("provider_name"),
            model=state.get("model_name"),
            max_tokens=1500,
        )

        parsed = parse_json_response(response, context=step)

        if isinstance(parsed, str):
            # Parse failed — store raw response with error marker
            threat_context: dict = {"raw_response": parsed, "parse_error": True}
            errors.append(f"{step}: JSON parse failed; raw response stored")
            logger.warning("threat_context_builder: JSON parse failed, storing raw response")
        else:
            threat_context = (
                parsed
                if isinstance(parsed, dict)
                else {"raw_response": str(parsed), "parse_error": True}
            )

        elapsed = time.monotonic() - start
        logs.append({"step": step, "status": "ok", "elapsed_s": round(elapsed, 2)})
        completed.append(step)
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
            "threat_context": threat_context,
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
