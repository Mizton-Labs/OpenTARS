"""
Evidence source-entity resolution (issue-local-034) — backs the Data
Explorer "Feed sources" category, which used to show unrelated Threat-Intel
ingestion stats and now aggregates *where hunt evidence actually came from*.

Resolved once, at evidence-add/parse time, and persisted to
``evidence_items.source_entity`` — never computed live in the Explorer route
(that would mean a network/LLM round trip on every page load).

  - URL evidence: deterministic, no LLM — the domain from the URL itself.
  - File/text/watcher evidence: one best-effort LLM call over the extracted
    text, asking for the reporting vendor/organization if the text plainly
    states one (a byline, header, dateline, "Source:" line, ...). Soft-fail
    like every other LLM-assisted step in this pipeline — a flaky provider
    must never block evidence being added or a hunt from running. Returns
    None on failure or when no entity is identifiable; callers/aggregation
    fall back to a generic item-type bucket rather than storing a sentinel.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_MAX_TEXT_CHARS = 3000

_SYSTEM_PROMPT = (
    "You identify the reporting vendor, organization, or publication that "
    "authored a piece of threat intelligence or incident evidence, when it "
    "is plainly stated in the text (a byline, header, dateline, or explicit "
    "'Source:'/'Published by:' line). You do not guess or infer from "
    "writing style — only report a name that is actually present in the "
    "text. If none is stated, say so."
)


def domain_from_url(url: str) -> str | None:
    """Deterministic domain extraction — no LLM, always available for URL
    evidence regardless of whether the fetch itself later succeeds."""
    try:
        netloc = urlparse(url.strip()).netloc
    except Exception:  # noqa: BLE001
        return None
    if not netloc:
        return None
    host = netloc.split("@")[-1].split(":")[0].lower()
    return host.removeprefix("www.") or None


async def resolve_source_entity_from_text(
    extracted_text: str,
    *,
    provider_name: str | None = None,
    model_name: str | None = None,
) -> str | None:
    """Best-effort LLM extraction of a reporting vendor/organization from
    evidence text. Never raises — returns None on any failure or when the
    model reports no identifiable source."""
    text = (extracted_text or "").strip()
    if not text:
        return None
    try:
        from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm

        system, user = build_prompt(
            system=_SYSTEM_PROMPT,
            task_description=(
                "Identify the reporting vendor/organization/publication for this "
                "evidence text, if one is plainly stated."
            ),
            context_sections=[("Evidence text", text[:_MAX_TEXT_CHARS])],
            output_format='A single line: the entity name, or exactly "unknown".',
            json_output=False,
        )
        response = await call_llm(
            user,
            system=system,
            provider_name=provider_name,
            model=model_name,
            max_tokens=32,
        )
        candidate = (response or "").strip().strip('"').strip()
        # Guard against a verbose/non-compliant response — a real entity
        # name is short; anything sentence-shaped is treated as "unknown".
        if not candidate or candidate.lower() == "unknown" or len(candidate) > 80:
            return None
        return candidate
    except Exception as exc:  # noqa: BLE001 — best-effort, never block evidence handling
        logger.warning("resolve_source_entity_from_text failed (non-fatal): %s", exc)
        return None
