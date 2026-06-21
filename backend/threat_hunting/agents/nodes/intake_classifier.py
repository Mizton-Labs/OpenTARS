"""LangGraph node: intake_classifier

Performs three distinct tasks (issue-008-2B):

1. **URL evidence fetch**: Any evidence item with parse_status='pending' (i.e.
   a URL registered at upload time but not yet fetched) is fetched here via
   fetch_url(). This enables effort-aware fetching (e.g. Playwright-first on
   high research effort) and defers the network cost to analysis time.

2. **IOC extraction** (issue-008-2B): All evidence item texts are scanned by the
   deterministic extract_iocs_from_text() extractor. Prior IOC rows are cleared
   first (clear_extracted_iocs) so re-runs always produce a clean, non-duplicated
   set. Making IOC extraction a pipeline task rather than an upload-time side-effect
   ensures the IOCs tab only populates after analysis runs, matching the intended
   workflow.

3. **LLM tool-calling enrichment** (issue-006-B): When the LLM provider supports
   tools, this node may call:
   - ``extract_iocs`` — re-extract IOCs from additional text snippets
   - ``refetch_url``  — re-fetch a URL for richer content
   Tool calls and decisions are recorded in the step_log entry.
   When research_effort == 'high', all tools are always invoked (issue-008-2D).

issue-008-2D: URL fetching via fetch_url() uses prefer_playwright=True when
research_effort == 'high', ensuring Playwright headless-Chromium is used for
all URL evidence on high-effort runs.
"""

from __future__ import annotations

import hashlib
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
    fetched_count = 0
    ioc_count_extracted = 0
    try:
        from backend.threat_hunting import db as th_db
        from backend.threat_hunting.agents.llm_bridge import call_llm_with_tools
        from backend.threat_hunting.agents.tools import call_tool, get_enabled_tool_specs
        from backend.threat_hunting.iocs import extract_iocs_from_text

        pkg_id = state["hunt_package_id"]
        effort = state.get("research_effort", "medium")
        prefer_playwright = effort == "high"  # issue-008-2D: high effort → Playwright-first

        # ── 1. Fetch pending URL evidence items ──────────────────────────────
        # Evidence items created via POST /evidence/url have parse_status='pending'.
        # Fetch them now with effort-aware settings before building the corpus.
        evidence_items = await th_db.list_evidence_items(pkg_id)

        pending_urls = [
            i
            for i in evidence_items
            if i.get("parse_status") == "pending" and i.get("item_type") == "url"
        ]

        if pending_urls:
            from backend.threat_hunting.extractors.url_fetcher import fetch_url

            for item in pending_urls:
                url = item.get("fetch_url") or item.get("source_ref") or ""
                if not url:
                    continue
                try:
                    result = await fetch_url(url, prefer_playwright=prefer_playwright)
                    await th_db.update_evidence_item(
                        item["id"],
                        extracted_text=result.extracted_text,
                        parser_used=result.parser_used,
                        parser_version="",
                        parse_status="ok" if result.extracted_text else "partial",
                        parse_warnings=result.warnings,
                        fetch_metadata=result.fetch_metadata,
                        final_url=result.final_url,
                        content_hash=hashlib.sha256(result.raw_bytes).hexdigest(),
                        mime_type=result.content_type,
                    )
                    fetched_count += 1
                    debug_lines.append(
                        f"URL_FETCH: {url} → {len(result.extracted_text)} chars "
                        f"({result.parser_used})"
                        + (" [playwright-first]" if prefer_playwright else "")
                    )
                except Exception as fetch_exc:  # noqa: BLE001
                    await th_db.update_evidence_item(
                        item["id"],
                        parse_status="error",
                        parse_warnings=[f"Pipeline fetch failed: {fetch_exc}"],
                    )
                    debug_lines.append(f"URL_FETCH_ERR: {url} → {fetch_exc}")
                    logger.warning("intake_classifier: URL fetch failed for %s: %s", url, fetch_exc)

            # Reload evidence items after fetching
            evidence_items = await th_db.list_evidence_items(pkg_id)

        # ── 2. Build text corpus ──────────────────────────────────────────────
        texts: list[str] = []
        intake_sources: list[dict[str, Any]] = []
        for item in evidence_items:
            label = item.get("label") or item.get("source_ref") or item.get("item_type", "")
            text = item.get("extracted_text") or ""
            if text.strip():
                texts.append(f"=== {label} ===\n{text.strip()}")
            intake_sources.append(
                {
                    "label": label,
                    "item_type": item.get("item_type", ""),
                    "text_length": len(text),
                    "parse_status": item.get("parse_status", "ok"),
                }
            )
        evidence_text_corpus = "\n\n".join(texts) if texts else ""

        # ── 3. Deterministic IOC extraction (issue-008-2B) ───────────────────
        # Clear prior IOCs first to ensure a clean slate on re-runs.
        cleared = await th_db.clear_extracted_iocs(pkg_id)
        if cleared:
            debug_lines.append(f"IOC_CLEAR: cleared {cleared} prior IOC rows")

        all_iocs: list[dict[str, Any]] = []
        for item in evidence_items:
            text = item.get("extracted_text") or ""
            if not text.strip():
                continue
            item_iocs = extract_iocs_from_text(text)
            if item_iocs:
                await th_db.add_extracted_iocs(pkg_id, item["id"], item_iocs)
                all_iocs.extend(item_iocs)
                ioc_count_extracted += len(item_iocs)

        # Reload from DB for deduplication guarantees
        all_iocs = await th_db.list_extracted_iocs(pkg_id)
        debug_lines.append(
            f"IOC_EXTRACT: extracted {ioc_count_extracted} raw → {len(all_iocs)} unique stored"
        )

        # ── 4. LLM tool-calling enrichment (issue-006-B / 008-2D) ────────────
        # On high effort, always run tool enrichment.
        # On medium/low, only when URL items have thin content.
        from backend.config.loader import load_agent_tools
        from backend.threat_hunting.agents.effort_profile import get_effort_profile

        profile = get_effort_profile(effort)
        force_tools = profile.get("force_all_tools", False)

        url_items_thin = [
            i
            for i in evidence_items
            if i.get("item_type") in ("url", "page") and len(i.get("extracted_text") or "") < 500
        ]
        run_tool_enrichment = force_tools or bool(url_items_thin)

        if run_tool_enrichment:
            tool_specs = get_enabled_tool_specs(_TOOL_NAMES, load_agent_tools())
            if tool_specs:
                tool_prompt = (
                    f"The hunt package has {len(evidence_items)} evidence items with "
                    f"{len(all_iocs)} IOCs extracted. "
                    + (
                        "Research effort is HIGH — perform all available enrichment steps. "
                        if force_tools
                        else f"There are {len(url_items_thin)} URL evidence items with thin "
                        f"content (<500 chars). "
                    )
                    + "Decide whether to re-fetch any URLs or extract IOCs from additional "
                    "text. If satisfied, respond with a brief decision statement only."
                )
                try:
                    _text, tool_calls = await call_llm_with_tools(
                        tool_prompt,
                        tool_specs,
                        provider_name=state.get("provider_name"),
                        model=state.get("model_name"),
                        max_tokens=512,
                    )
                    decision = _text or "Data assessed — no additional enrichment needed."
                    for tc in tool_calls:
                        tool_name = tc.get("name", "")
                        tool_args = tc.get("arguments", {})
                        debug_lines.append(f"TOOL_CALL: {tool_name}({tool_args})")
                        try:
                            result = await call_tool(tool_name, tool_args)
                            tools_used.append(tool_name)
                            debug_lines.append(f"TOOL_RESULT: {str(result)[:500]}")
                            if (
                                tool_name == "refetch_url"
                                and isinstance(result, str)
                                and result.strip()
                            ):
                                url_val = tool_args.get("url", "")
                                texts.append(f"=== refetched: {url_val} ===\n{result.strip()}")
                                evidence_text_corpus = "\n\n".join(texts)
                            elif tool_name == "extract_iocs" and isinstance(result, list):
                                for ioc_item in result:
                                    if not any(
                                        x.get("ioc") == ioc_item.get("ioc")
                                        and x.get("ioc_type") == ioc_item.get("ioc_type")
                                        for x in all_iocs
                                    ):
                                        all_iocs.append(ioc_item)
                        except Exception as tool_exc:  # noqa: BLE001
                            debug_lines.append(f"TOOL_ERROR: {tool_exc}")
                except Exception as llm_exc:  # noqa: BLE001
                    debug_lines.append(f"TOOL_LLM_ERROR: {llm_exc}")

        # ── 5. Build IOC summary ──────────────────────────────────────────────
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
                for i in all_iocs[:50]
            ],
        }

        logger.info(
            "intake_classifier: pkg=%s evidence=%d fetched=%d iocs=%d tools_used=%s",
            pkg_id,
            len(evidence_items),
            fetched_count,
            len(all_iocs),
            tools_used,
        )

        elapsed = time.monotonic() - start
        logs.append(
            {
                "step": step,
                "status": "ok",
                "elapsed_s": round(elapsed, 2),
                "ioc_count": len(all_iocs),
                "item_count": len(evidence_items),
                "tools_used": tools_used,
                "decision": decision,
                "debug_lines": debug_lines,
                "intake_sources": intake_sources,
                "fetched_url_count": fetched_count,
            }
        )
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
