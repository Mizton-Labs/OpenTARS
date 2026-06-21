"""LangGraph node: intake_classifier

Loads all evidence items and extracted IOCs for the hunt package from the DB,
builds the evidence text corpus, IOC summary, and raw IOC list that downstream
nodes consume.

Tool-calling (issue-006-B):
  When the LLM provider supports tools, this node may call:
  - ``extract_iocs``  — re-extract IOCs from additional text snippets
  - ``refetch_url``   — re-fetch a source URL if the evidence text seems thin
  Tool calls and decisions are recorded in the step_log entry.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from backend.threat_hunting.agents.state import HuntPipelineState

logger = logging.getLogger(__name__)

_TOOL_NAMES = ["extract_iocs", "refetch_url"]


async def intake_classifier(state: HuntPipelineState) -> dict:
    start = time.monotonic()
    step = "intake_classifier"
    logs = list(state.get("step_logs") or [])
    errors = list(state.get("errors") or [])
    completed = list(state.get("completed_steps") or [])
    tools_used: list[str] = []
    debug_lines: list[str] = []
    decision = ""
    try:
        from backend.threat_hunting import db as th_db
        from backend.threat_hunting.agents.llm_bridge import call_llm_with_tools
        from backend.threat_hunting.agents.tools import TOOL_SPEC_BY_NAME, call_tool

        pkg_id = state["hunt_package_id"]

        # Load evidence items
        evidence_items = await th_db.list_evidence_items(pkg_id)

        # Build text corpus
        texts: list[str] = []
        intake_sources: list[dict[str, Any]] = []
        for item in evidence_items:
            label = item.get("label") or item.get("source_ref") or item.get("item_type", "")
            text = item.get("extracted_text") or ""
            if text.strip():
                texts.append(f"=== {label} ===\n{text.strip()}")
            intake_sources.append({
                "label": label,
                "item_type": item.get("item_type", ""),
                "text_length": len(text),
            })
        evidence_text_corpus = "\n\n".join(texts) if texts else ""

        # Load IOCs
        all_iocs: list[dict[str, Any]] = await th_db.list_extracted_iocs(pkg_id)

        # ── Tool-calling enrichment ───────────────────────────────────────────
        # When evidence is thin (< 500 chars) and there are URL-type items,
        # ask the LLM whether it wants to re-fetch or extract additional IOCs.
        url_items = [
            i for i in evidence_items
            if i.get("item_type") in ("url", "page") and len(i.get("extracted_text") or "") < 500
        ]
        if url_items:
            tool_specs = [TOOL_SPEC_BY_NAME[n] for n in _TOOL_NAMES if n in TOOL_SPEC_BY_NAME]
            tool_prompt = (
                f"The hunt package has {len(evidence_items)} evidence items with "
                f"{len(all_iocs)} IOCs already extracted. "
                f"There are {len(url_items)} URL evidence items with thin content (<500 chars). "
                "Decide whether to re-fetch any URLs or extract IOCs from additional text. "
                "If satisfied with the existing data, respond with a brief decision statement only."
            )
            try:
                _text, tool_calls = await call_llm_with_tools(
                    tool_prompt,
                    tool_specs,
                    provider_name=state.get("provider_name"),
                    model=state.get("model_name"),
                    max_tokens=512,
                )
                decision = _text or "Data assessed — no additional fetch needed."
                for tc in tool_calls:
                    tool_name = tc.get("name", "")
                    tool_args = tc.get("arguments", {})
                    debug_lines.append(f"TOOL_CALL: {tool_name}({tool_args})")
                    try:
                        result = await call_tool(tool_name, tool_args)
                        tools_used.append(tool_name)
                        debug_lines.append(f"TOOL_RESULT: {str(result)[:500]}")
                        # Integrate refetch results into corpus
                        if tool_name == "refetch_url" and isinstance(result, str) and result.strip():
                            url_val = tool_args.get("url", "")
                            texts.append(f"=== refetched: {url_val} ===\n{result.strip()}")
                            evidence_text_corpus = "\n\n".join(texts)
                        # Integrate extra extracted IOCs
                        elif tool_name == "extract_iocs" and isinstance(result, list):
                            for ioc_item in result:
                                if ioc_item not in all_iocs:
                                    all_iocs.append(ioc_item)
                    except Exception as tool_exc:  # noqa: BLE001
                        debug_lines.append(f"TOOL_ERROR: {tool_exc}")
            except Exception as llm_exc:  # noqa: BLE001
                debug_lines.append(f"TOOL_LLM_ERROR: {llm_exc}")

        # Summarize IOCs by type
        by_type: dict[str, int] = {}
        for ioc in all_iocs:
            t = ioc.get("ioc_type", "other")
            by_type[t] = by_type.get(t, 0) + 1
        noisy = sum(1 for i in all_iocs if i.get("flagged_noisy"))

        ioc_summary: dict[str, Any] = {
            "total": len(all_iocs),
            "by_type": by_type,
            "noisy_count": noisy,
            "sample": [
                {
                    "ioc": i.get("ioc"),
                    "ioc_type": i.get("ioc_type"),
                    "description": i.get("ioc_description"),
                }
                for i in all_iocs[:50]  # first 50 for prompt context
            ],
        }

        logger.info(
            "intake_classifier: pkg=%s evidence=%d iocs=%d tools_used=%s",
            pkg_id,
            len(evidence_items),
            len(all_iocs),
            tools_used,
        )

        elapsed = time.monotonic() - start
        logs.append({
            "step": step,
            "status": "ok",
            "elapsed_s": round(elapsed, 2),
            "tools_used": tools_used,
            "decision": decision,
            "debug_lines": debug_lines,
            "intake_sources": intake_sources,
        })
        completed.append(step)
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
            "evidence_text_corpus": evidence_text_corpus,
            "ioc_summary": ioc_summary,
            "raw_ioc_list": all_iocs,
        }
    except Exception as exc:
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
