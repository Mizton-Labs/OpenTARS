"""LangGraph node: threat_context_builder

Uses the LLM to produce a structured threat context summary from the evidence
corpus and IOC summary produced by intake_classifier.

Tool-calling (issue-006-B):
  When the LLM provider supports tools, this node may call:
  - ``mitre_lookup``  — look up MITRE ATT&CK technique details
  - ``refetch_url``   — re-fetch a URL for additional context
  Tool calls and decisions are recorded in the step_log entry.
"""

from __future__ import annotations

import json
import logging
import time

from backend.threat_hunting.agents.llm_bridge import (
    build_prompt,
    call_llm,
    call_llm_with_tools,
    parse_json_response,
)
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


_TOOL_NAMES = ["mitre_lookup", "refetch_url"]


async def threat_context_builder(state: HuntPipelineState) -> dict:
    start = time.monotonic()
    step = "threat_context_builder"
    logs = list(state.get("step_logs") or [])
    errors = list(state.get("errors") or [])
    completed = list(state.get("completed_steps") or [])
    tools_used: list[str] = []
    debug_lines: list[str] = []
    decision = ""
    try:
        from backend.llm.errors import LLMDisabledError
        from backend.threat_hunting.agents.tools import TOOL_SPEC_BY_NAME, call_tool

        corpus: str = state.get("evidence_text_corpus") or ""
        ioc_summary = state.get("ioc_summary") or {}

        # Truncate corpus to avoid token overflow
        corpus_snippet = corpus[:_EVIDENCE_TRUNCATE]
        if len(corpus) > _EVIDENCE_TRUNCATE:
            corpus_snippet += "\n\n[... evidence truncated for context window ...]"

        ioc_summary_text = json.dumps(ioc_summary, indent=2)

        # ── Pre-context tool enrichment ────────────────────────────────────
        # Allow the model to look up MITRE techniques or re-fetch URLs before
        # producing the final context summary.
        tool_specs = [TOOL_SPEC_BY_NAME[n] for n in _TOOL_NAMES if n in TOOL_SPEC_BY_NAME]
        if tool_specs:
            enrich_prompt = (
                f"You are building a threat context. "
                f"Evidence corpus (first 2000 chars): {corpus_snippet[:2000]}\n"
                f"IOC summary: {ioc_summary_text[:500]}\n"
                "Look up any MITRE ATT&CK techniques you can identify from the evidence, "
                "or re-fetch any URLs that appear in the evidence for richer context. "
                "When done, respond with a brief note of what you found."
            )
            try:
                _text, tool_calls = await call_llm_with_tools(
                    enrich_prompt,
                    tool_specs,
                    provider_name=state.get("provider_name"),
                    model=state.get("model_name"),
                    max_tokens=512,
                )
                decision = _text or "Context enrichment complete."
                extra_context_parts: list[str] = []
                for tc in tool_calls:
                    tool_name = tc.get("name", "")
                    tool_args = tc.get("arguments", {})
                    debug_lines.append(f"TOOL_CALL: {tool_name}({tool_args})")
                    try:
                        result = await call_tool(tool_name, tool_args)
                        tools_used.append(tool_name)
                        debug_lines.append(f"TOOL_RESULT: {str(result)[:500]}")
                        if result:
                            extra_context_parts.append(
                                f"[{tool_name} result for {tool_args}]: {str(result)[:1000]}"
                            )
                    except Exception as tool_exc:  # noqa: BLE001
                        debug_lines.append(f"TOOL_ERROR: {tool_exc}")
                if extra_context_parts:
                    corpus_snippet += "\n\n## Tool-enriched context\n" + "\n".join(extra_context_parts)
            except Exception as llm_exc:  # noqa: BLE001
                debug_lines.append(f"TOOL_LLM_ERROR: {llm_exc}")

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
        logs.append({
            "step": step,
            "status": "ok",
            "elapsed_s": round(elapsed, 2),
            "tools_used": tools_used,
            "decision": decision,
            "debug_lines": debug_lines,
        })
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
        logs.append({
            "step": step,
            "status": "error",
            "elapsed_s": round(elapsed, 2),
            "error": str(exc),
            "tools_used": tools_used,
            "debug_lines": debug_lines,
        })
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
        }
