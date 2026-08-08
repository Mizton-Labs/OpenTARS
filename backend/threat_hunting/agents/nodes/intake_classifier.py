"""LangGraph node: intake_classifier

Performs four distinct tasks:

1. **File evidence parse** (issue-local-011): Any evidence item with
   parse_status='pending' and item_type='file' (i.e. a file uploaded without
   parsing — the new default since issue-011) is parsed here using the dispatcher
   (PyMuPDF / Docling / plain-text). The chosen parser_mode is read from
   fetch_metadata['parser_mode']. This defers all CPU-intensive parsing to
   analysis time, making uploads instant.

2. **URL evidence fetch** (issue-008-2B): Any evidence item with parse_status='pending'
   and item_type='url' is fetched here via fetch_url(). Effort-aware (Playwright-first
   on high research effort).

3. **IOC extraction** (issue-008-2B): All evidence item texts are scanned by the
   deterministic extract_iocs_from_text() extractor. Prior IOC rows for THIS RUN
   are cleared first (clear_extracted_iocs, run_id-scoped since issue-local-015)
   so re-runs always produce a clean, non-duplicated set — without touching any
   other run's IOC rows, which is what makes each run's IOC set independent.
   Each IOC's keep/remove `action` is then computed from the run's `run_config`
   (issue-local-015 "IOC active cleaning" — see `iocs.compute_ioc_action`) and
   persisted; `tagging_only` mode (default) keeps everything, matching the
   pre-015 behavior exactly.

4. **LLM tool-calling enrichment** (issue-006-B): When the LLM provider supports
   tools, this node may call:
   - ``extract_iocs`` — re-extract IOCs from additional text snippets
   - ``refetch_url``  — re-fetch a URL for richer content
   Tool calls and decisions are recorded in the step_log entry.
   When research_effort == 'high', all tools are always invoked (issue-008-2D).

5. **LLM IOC triage** (issue-local-014): a second, narrowly-scoped LLM call
   (dedicated persona, see ``_IOC_TRIAGE_SYSTEM_PROMPT``) reviews IOCs the
   deterministic noise scorer did NOT already flag and catches what
   regex/allowlists can't — generic/placeholder values, documentation
   ranges, off-topic indicators. Only adjusts ``flagged_noisy``/
   ``noise_score``/``ioc_description`` on the in-memory list that feeds
   ``ioc_summary``/``raw_ioc_list`` (and therefore every downstream node);
   never deletes an IOC. Gated behind the same condition as step 4.

issue-008-2D: URL fetching via fetch_url() uses prefer_playwright=True when
research_effort == 'high', ensuring Playwright headless-Chromium is used for
all URL evidence on high-effort runs.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any

from backend.threat_hunting.agents.logging_utils import get_run_logger
from backend.threat_hunting.agents.state import HuntPipelineState

_TOOL_NAMES = ["extract_iocs", "refetch_url"]

# issue-local-014: dedicated persona for the LLM IOC-triage pass below —
# narrower than the generic analyst persona in llm_bridge.build_prompt() so
# the model stays focused on one job (spotting noise the deterministic
# regex/allowlist scorer can't catch) instead of drifting into general
# threat analysis.
#
# issue-local-035: extended to also catch reference/citation-style URLs —
# links from a source article's "References"/"Further reading"/footnote
# section rather than the incident's actual infrastructure. The extractor
# only sees flat text (no DOM/section structure survives HTML extraction —
# see iocs.py), so this is a best-effort heuristic over each URL's
# surrounding text snippet, not a structural guarantee.
_IOC_TRIAGE_SYSTEM_PROMPT = (
    "You are an IOC Triage Analyst. Your ONLY job is to review a list of "
    "already-extracted, already-defanged indicators of compromise and flag "
    "any that are generic, placeholder, clearly unrelated to the described "
    "incident, or otherwise not worth hunting on. You do not invent new "
    "IOCs, rewrite values, or comment on anything outside the given list. "
    "Deterministic filters have already removed known-benign CDN domains, "
    "private IP ranges, and empty-file hashes — only flag additional items "
    "those filters would miss: version-number-shaped false positives "
    "(e.g. an IP-looking string that is really a software version), "
    "documentation/example values (example.com, RFC 5737 test ranges "
    "192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), and IOCs that read as "
    "generic infrastructure with no connection to the incident narrative. "
    "For 'url' type items, a surrounding text snippet is provided when "
    "available — flag the URL if that snippet reads as a bibliography/"
    "citation/footnote entry (e.g. a numbered reference, a 'References' or "
    "'Further reading' list, a vendor blog/news link cited as a source "
    "rather than mentioned as attacker infrastructure) instead of inline "
    "narrative describing attacker activity. When genuinely unsure, do not "
    "flag it — false negatives are cheaper than losing a real indicator. "
    "Always output valid JSON only."
)

# issue-local-035: chars of context captured on each side of a URL's first
# occurrence in the evidence corpus, for the citation/reference heuristic
# above. Small on purpose — enough to see "[12] " or "References:" prefixes
# without ballooning prompt size on evidence-heavy runs.
_URL_CONTEXT_RADIUS = 150


def _url_context_snippet(url: str, corpus: str) -> str:
    """Best-effort surrounding text for *url*'s first occurrence in *corpus*.

    Returns "" if not found — callers must treat a missing snippet as "no
    extra signal available", never as an error.
    """
    idx = corpus.find(url)
    if idx == -1:
        return ""
    start = max(0, idx - _URL_CONTEXT_RADIUS)
    end = min(len(corpus), idx + len(url) + _URL_CONTEXT_RADIUS)
    return corpus[start:end].replace("\n", " ").strip()


async def _llm_triage_iocs(
    all_iocs: list[dict[str, Any]],
    *,
    provider_name: str | None,
    model_name: str | None,
    evidence_text_corpus: str = "",
) -> list[dict[str, str]]:
    """Ask the LLM to flag additional noisy/irrelevant IOCs the deterministic
    scorer missed. Returns a list of {ioc, ioc_type, reason} dicts for items
    to flag — never raises; callers treat this as best-effort enrichment.

    issue-local-035: *evidence_text_corpus*, when provided, is used to give
    url-type candidates a short surrounding-text snippet so the LLM can spot
    reference/citation-style links (see _IOC_TRIAGE_SYSTEM_PROMPT).
    """
    from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm, parse_json_response

    # Only worth asking about IOCs the deterministic scorer hasn't already
    # flagged — no point re-asking about things already excluded.
    candidates = [i for i in all_iocs if not i.get("flagged_noisy")]
    if not candidates:
        return []

    lines = []
    for i in candidates[:200]:
        line = f"- type={i.get('ioc_type')} value={i.get('ioc')}"
        if i.get("ioc_type") == "url" and evidence_text_corpus:
            snippet = _url_context_snippet(str(i.get("ioc", "")), evidence_text_corpus)
            if snippet:
                line += f" context=\"...{snippet}...\""
        lines.append(line)
    ioc_lines = "\n".join(lines)
    system, user = build_prompt(
        system=_IOC_TRIAGE_SYSTEM_PROMPT,
        task_description=(
            "Review this list of extracted IOCs and identify any that are generic, "
            "placeholder, unrelated to a real threat, or (for URLs) a citation/reference "
            "link rather than attacker infrastructure, and should be flagged as noisy."
        ),
        context_sections=[("Extracted IOCs (not yet flagged noisy)", ioc_lines)],
        output_format=(
            '[{"ioc": "<exact value from the list>", "ioc_type": "<exact type from the list>", '
            '"reason": "<short reason>"}, ...] — return [] if none should be flagged.'
        ),
    )
    response = await call_llm(
        user,
        system=system,
        provider_name=provider_name,
        model=model_name,
        max_tokens=1024,
    )
    parsed = parse_json_response(response, context="intake_classifier.ioc_triage")
    if not isinstance(parsed, list):
        return []
    return [
        item
        for item in parsed
        if isinstance(item, dict) and item.get("ioc") and item.get("ioc_type")
    ]


async def intake_classifier(state: HuntPipelineState) -> dict:
    start = time.monotonic()
    step = "intake_classifier"
    log = get_run_logger(__name__, state.get("hunt_package_id"), state.get("run_id"))
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

        # ── 0. Load evidence items ────────────────────────────────────────────
        # issue-local-041: scoped to this run — excludes another run's
        # synthetic consolidated-plan evidence item (see
        # recommendation_synthesizer.py / list_evidence_items' docstring).
        run_id = state.get("run_id")
        evidence_items = await th_db.list_evidence_items(pkg_id, run_id=run_id)

        # ── 1. Parse pending FILE evidence items (issue-local-011) ───────────
        # Files uploaded after issue-011 are stored with parse_status='pending';
        # the raw blob is in evidence_blobs. Parse them here so the pipeline
        # always sees extracted text regardless of when the file was uploaded.
        pending_files = [
            i
            for i in evidence_items
            if i.get("parse_status") == "pending" and i.get("item_type") == "file"
        ]

        if pending_files:
            from backend.threat_hunting.extractors.dispatcher import extract_file

            for item in pending_files:
                item_id = item["id"]
                label = item.get("label") or item.get("source_ref") or "upload"
                mime_type_hint = item.get("mime_type") or ""
                # parser_mode stored in fetch_metadata by the upload route
                fetch_meta = item.get("fetch_metadata") or {}
                parser_mode = (
                    fetch_meta.get("parser_mode", "auto")
                    if isinstance(fetch_meta, dict)
                    else "auto"
                )
                debug_lines.append(f"FILE_PARSE_START: {label} mode={parser_mode}")
                try:
                    raw = await th_db.get_evidence_blob(item_id)
                    if raw is None:
                        # Blob missing — mark error so the user can re-upload
                        await th_db.update_evidence_item(
                            item_id,
                            parse_status="error",
                            parse_warnings=["Blob missing — file may need to be re-uploaded."],
                        )
                        debug_lines.append(f"FILE_PARSE_ERR: {label} — blob missing")
                        continue
                    result = await asyncio.to_thread(
                        extract_file, raw, label, mime_type_hint, parser_mode
                    )
                    # issue-local-034: best-effort vendor/organization
                    # extraction, now that the file's text is available —
                    # soft-fail, never blocks the pipeline.
                    from backend.threat_hunting.evidence_source import (
                        resolve_source_entity_from_text,
                    )

                    source_entity = await resolve_source_entity_from_text(
                        result["extracted_text"],
                        provider_name=state.get("provider_name"),
                        model_name=state.get("model_name"),
                    )
                    await th_db.update_evidence_item(
                        item_id,
                        extracted_text=result["extracted_text"],
                        parser_used=result["parser_used"],
                        parser_version=result["parser_version"],
                        parse_status=result["parse_status"],
                        parse_warnings=result["parse_warnings"],
                        content_hash=result["content_hash"],
                        mime_type=result["mime_type"],
                        source_entity=source_entity,
                    )
                    debug_lines.append(
                        f"FILE_PARSE_OK: {label} → {len(result['extracted_text'])} chars "
                        f"({result['parser_used']})"
                    )
                except Exception as parse_exc:  # noqa: BLE001
                    await th_db.update_evidence_item(
                        item_id,
                        parse_status="error",
                        parse_warnings=[f"Pipeline parse failed: {parse_exc}"],
                    )
                    debug_lines.append(f"FILE_PARSE_ERR: {label} → {parse_exc}")
                    log.warning("intake_classifier: file parse failed for %s: %s", label, parse_exc)

            # Reload after parsing
            evidence_items = await th_db.list_evidence_items(pkg_id, run_id=run_id)

        # ── 2. Fetch pending URL evidence items ──────────────────────────────
        # Evidence items created via POST /evidence/url have parse_status='pending'.
        # Fetch them now with effort-aware settings before building the corpus.
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
                    log.warning("intake_classifier: URL fetch failed for %s: %s", url, fetch_exc)

            # Reload evidence items after fetching
            evidence_items = await th_db.list_evidence_items(pkg_id, run_id=run_id)

        # ── 3. Build text corpus ──────────────────────────────────────────────
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
                    # sub_status mirrors parse_status for live diagram coloring
                    "sub_status": item.get("parse_status", "ok"),
                    "parser_used": item.get("parser_used") or "",
                }
            )
        evidence_text_corpus = "\n\n".join(texts) if texts else ""

        # ── 4. Deterministic IOC extraction (issue-008-2B) ───────────────────
        # issue-local-015: scoped to this run_id — each run keeps its own
        # independent IOC set instead of overwriting the package's shared one.
        run_id = state.get("run_id", "")
        cleared = await th_db.clear_extracted_iocs(pkg_id, run_id)
        if cleared:
            debug_lines.append(f"IOC_CLEAR: cleared {cleared} prior IOC rows for this run")

        all_iocs: list[dict[str, Any]] = []
        for item in evidence_items:
            text = item.get("extracted_text") or ""
            if not text.strip():
                continue
            item_iocs = extract_iocs_from_text(text)
            if item_iocs:
                await th_db.add_extracted_iocs(pkg_id, item["id"], item_iocs, run_id=run_id)
                all_iocs.extend(item_iocs)
                ioc_count_extracted += len(item_iocs)

        # Reload from DB for deduplication guarantees
        all_iocs = await th_db.list_extracted_iocs(pkg_id, run_id)
        debug_lines.append(
            f"IOC_EXTRACT: extracted {ioc_count_extracted} raw → {len(all_iocs)} unique stored"
        )

        # ── 5. LLM tool-calling enrichment (issue-006-B / 008-2D) ────────────
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

            # ── 5b. LLM IOC triage (issue-local-014) ──────────────────────
            # Semantic cleanup pass on top of the deterministic noise
            # scorer: catches generic/placeholder/off-topic IOCs a regex +
            # allowlist can't (e.g. doc-example domains, RFC 5737 ranges,
            # version numbers that happen to look like an IP). Gated behind
            # the same run_tool_enrichment condition as the tool-calling
            # pass above — same cost/effort tradeoff, one extra call.
            try:
                flags = await _llm_triage_iocs(
                    all_iocs,
                    provider_name=state.get("provider_name"),
                    model_name=state.get("model_name"),
                    evidence_text_corpus=evidence_text_corpus,
                )
                triaged = 0
                for flag in flags:
                    for ioc_item in all_iocs:
                        if (
                            ioc_item.get("ioc") == flag["ioc"]
                            and ioc_item.get("ioc_type") == flag["ioc_type"]
                            and not ioc_item.get("flagged_noisy")
                        ):
                            ioc_item["flagged_noisy"] = True
                            ioc_item["noise_score"] = max(
                                float(ioc_item.get("noise_score") or 0.0), 0.75
                            )
                            reason = flag.get("reason", "").strip()
                            if reason:
                                existing_desc = ioc_item.get("ioc_description") or ""
                                ioc_item["ioc_description"] = (
                                    f"{existing_desc} [LLM triage: {reason}]".strip()
                                )
                            triaged += 1
                            break
                if triaged:
                    debug_lines.append(
                        f"IOC_LLM_TRIAGE: flagged {triaged} additional IOC(s) as noisy"
                    )
            except Exception as triage_exc:  # noqa: BLE001
                debug_lines.append(f"IOC_LLM_TRIAGE_ERROR: {triage_exc}")

        # ── 5c. IOC active-cleaning decision (issue-local-015) ────────────────
        # Compute each IOC's keep/remove action from this run's config, now
        # that noise scoring (step 4) and both enrichment passes (5, 5b) have
        # had their say. Persist to the rows inserted in step 4 (tool-added
        # IOCs from step 5 were never DB-backed to begin with — unchanged
        # pre-existing behavior). In tagging_only mode (default) everything
        # stays "keep" and downstream sees the full list, same as before this
        # feature existed.
        run_config = state.get("run_config") or {}
        ioc_mode = run_config.get("ioc_mode", "tagging_only")
        cleaning_options = run_config.get("ioc_cleaning_options") or {}
        from backend.threat_hunting.iocs import compute_ioc_action

        db_rows = await th_db.list_extracted_iocs(pkg_id, run_id)
        db_row_keys = {(r.get("ioc"), r.get("ioc_type")) for r in db_rows}
        action_updates: list[tuple[str, str, str]] = []
        for ioc_item in all_iocs:
            action, removal_reason = compute_ioc_action(
                ioc_item, ioc_mode=ioc_mode, cleaning_options=cleaning_options
            )
            ioc_item["action"] = action
            if removal_reason:
                ioc_item["removal_reason"] = removal_reason
            key = (ioc_item.get("ioc"), ioc_item.get("ioc_type"))
            if key in db_row_keys:
                action_updates.append(
                    (ioc_item.get("ioc", ""), ioc_item.get("ioc_type", ""), action)
                )
        if action_updates:
            await th_db.update_ioc_actions(run_id, action_updates)
        removed_count = sum(1 for i in all_iocs if i.get("action") == "remove")
        if ioc_mode == "active_cleaning":
            debug_lines.append(
                f"IOC_ACTIVE_CLEANING: {removed_count} IOC(s) marked removed, "
                f"{len(all_iocs) - removed_count} kept for downstream analysis"
            )
            all_iocs_for_downstream = [i for i in all_iocs if i.get("action") != "remove"]
        else:
            all_iocs_for_downstream = all_iocs

        # ── 6. Build IOC summary ──────────────────────────────────────────────
        # ioc_summary/raw_ioc_list (returned to state below) are built from
        # all_iocs_for_downstream — the LLM-facing set, already excluding
        # action=="remove" items in active_cleaning mode. Log/DB-facing
        # counts below intentionally use the full all_iocs so operators can
        # still see everything that was extracted, not just what survived.
        by_type: dict[str, int] = {}
        for ioc in all_iocs_for_downstream:
            t = ioc.get("ioc_type", "other")
            by_type[t] = by_type.get(t, 0) + 1
        noisy_downstream = sum(1 for i in all_iocs_for_downstream if i.get("flagged_noisy"))
        noisy = sum(1 for i in all_iocs if i.get("flagged_noisy"))

        ioc_summary: dict[str, Any] = {
            "total": len(all_iocs_for_downstream),
            "by_type": by_type,
            "noisy_count": noisy_downstream,
            "sample": [
                {
                    "ioc": i.get("ioc"),
                    "ioc_type": i.get("ioc_type"),
                    "description": i.get("ioc_description"),
                }
                for i in all_iocs_for_downstream[:50]
            ],
        }

        log.info(
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
                "noisy_count": noisy,
                "item_count": len(evidence_items),
                "tools_used": tools_used,
                "decision": decision,
                "debug_lines": debug_lines,
                "intake_sources": intake_sources,
                "fetched_url_count": fetched_count,
                "parsed_file_count": len(pending_files),
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
            "raw_ioc_list": all_iocs_for_downstream,
            "all_extracted_iocs": all_iocs,
        }
    except Exception as exc:
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
