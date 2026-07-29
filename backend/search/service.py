"""Deterministic, role-scoped global search (issue-local-031).

Fans a plain text query out across the application's own stores and returns
hits grouped by the section they were found in, each with a short context
snippet and the route that opens it.

SECURITY
--------
Every source declares the minimum role required to read it and is skipped
entirely when the caller lacks it, so search can never surface data the caller
could not already reach through the normal API. In particular:

* the settings catalogue holds *names and locations only, never values* (see
  ``catalog.py``), so no credential can appear in a result;
* sources that carry secrets — LLM providers, SSO configuration, ingest source
  headers, SIEM connectors, user records — are **not searched at all**, only
  their Configuration destinations are, and only for admins;
* snippets are truncated and stripped of control characters before leaving
  here, so a hostile document cannot smuggle terminal escapes or layout-
  breaking content into a result.

This module is also the retrieval layer for SmartSearch (``smart.py``). Because
the model is fed nothing but these already-role-filtered snippets, the chatbot
inherits the same access boundary by construction rather than by prompt.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass
from typing import Any

from backend import docs_registry
from backend.search.catalog import catalog_for_role, role_allows

logger = logging.getLogger(__name__)

#: Longest query we will act on. Anything longer is almost certainly not a
#: search — it is a paste, or an attempt to stuff a prompt.
MAX_QUERY_CHARS = 200
#: Per-source and overall result caps, keeping responses (and the SmartSearch
#: prompt built from them) bounded.
MAX_PER_SECTION = 10
MAX_TOTAL_RESULTS = 50
#: Longest snippet returned for a single hit.
SNIPPET_CHARS = 220

# Characters stripped from anything that came out of a data store before it is
# returned or shown to a model. Beyond the C0/C1 control ranges this covers the
# invisible and directional formatting characters, because a search result is
# read by an analyst deciding whether an indicator is malicious: a right-to-left
# override (U+202E) inside an attacker-supplied hostname makes the rendered text
# differ from the stored value, which is exactly the kind of misreading this
# tool must not introduce. Tab/newline/CR are deliberately absent — they are
# legitimate content and are collapsed as whitespace just below.
_CONTROL_CHARS_RE = re.compile(
    "["
    "\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"  # C0 and C1 controls
    "​-‏"  # zero-width spaces/joiners, LRM/RLM
    "‪-‮"  # bidi embeddings and overrides
    "⁠-⁤"  # word joiner and invisible operators
    "⁦-⁩"  # bidi isolates
    "﻿"  # zero-width no-break space / BOM
    "]"
)
_WHITESPACE_RE = re.compile(r"\s+")
#: Three or more newlines collapse to a paragraph break in the multiline
#: sanitiser, so a model cannot pad an answer into a wall of empty space.
_BLANK_LINES_RE = re.compile(r"\n{3,}")


@dataclass(frozen=True)
class SearchHit:
    """One match, in the section it was found in."""

    section: str
    title: str
    snippet: str
    #: SPA route that opens the match.
    route: str
    #: Stable identifier of the underlying record, when there is one.
    ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def clean_query(raw: str) -> str:
    """Normalise a user query: strip control characters, collapse whitespace, cap length."""
    return sanitize_text(raw, MAX_QUERY_CHARS)


def sanitize_text(text: Any, limit: int | None = None) -> str:
    """Render arbitrary stored content safe to place in a result payload.

    Hunt evidence and threat-intel entries are adversary-controlled text, so
    control characters (terminal escapes, bidi overrides) are stripped and
    whitespace collapsed before the value is ever returned or shown to a model.
    """
    if text is None:
        return ""
    cleaned = _WHITESPACE_RE.sub(" ", _CONTROL_CHARS_RE.sub(" ", str(text))).strip()
    return cleaned[:limit] if limit is not None else cleaned


def sanitize_multiline(text: Any, limit: int | None = None) -> str:
    """Like :func:`sanitize_text`, but preserves line structure.

    SmartSearch answers are Markdown, and Markdown is newline-significant —
    running them through the single-line sanitiser collapses every table, list
    and fenced block onto one line, which then renders as an unreadable
    paragraph. Line breaks and leading indentation are therefore kept (nested
    lists and code blocks depend on the latter), while the same control,
    invisible and bidi characters are still removed, runs of blank lines are
    capped, and trailing whitespace is trimmed.
    """
    if text is None:
        return ""
    cleaned = str(text).replace("\r\n", "\n").replace("\r", "\n")
    cleaned = _CONTROL_CHARS_RE.sub(" ", cleaned)
    cleaned = "\n".join(line.rstrip() for line in cleaned.split("\n"))
    cleaned = _BLANK_LINES_RE.sub("\n\n", cleaned).strip()
    return cleaned[:limit] if limit is not None else cleaned


def _snippet(text: Any, query: str, *, width: int = SNIPPET_CHARS) -> str:
    """Return a short window of *text* centred on the first match of *query*."""
    clean = sanitize_text(text)
    if not clean:
        return ""
    idx = clean.lower().find(query.lower()) if query else -1
    if idx < 0:
        return clean[:width] + ("…" if len(clean) > width else "")
    start = max(0, idx - width // 3)
    end = min(len(clean), start + width)
    return ("…" if start > 0 else "") + clean[start:end] + ("…" if end < len(clean) else "")


def _matches(query: str, *fields: Any) -> bool:
    needle = query.lower()
    return any(needle in sanitize_text(f).lower() for f in fields if f)


# ── Sources ───────────────────────────────────────────────────────────────────


def _search_catalog(query: str, role: str | None) -> list[SearchHit]:
    """Destinations: pages, Configuration tabs, documentation topics.

    Deliberately NOT truncated here. Unlike the other sources this one spans
    three sections (Navigation, Settings, Docs), and the catalogue is ordered
    pages → config → docs, so capping the combined list would let Navigation
    starve the other two — `global_search` applies the per-section cap once the
    hits are bucketed by their own section.
    """
    hits: list[SearchHit] = []
    needle = query.lower()
    for entry in catalog_for_role(role):
        if needle in entry.haystack():
            hits.append(
                SearchHit(
                    section=entry.section,
                    title=entry.title,
                    snippet=entry.description,
                    route=entry.route,
                    ref=entry.id,
                )
            )
    return hits


async def _search_hunts(query: str, role: str | None) -> list[SearchHit]:
    """Hunt packages, via the existing deep search (name/description, stored
    run analysis JSON, and extracted IOCs)."""
    if not role_allows(role, "threat-viewer"):
        return []
    # Imported lazily, here and in the sources below: it keeps backend.search
    # importable on its own and means a role that cannot reach a source never
    # pays to load it.
    from backend.threat_hunting import db as th_db

    packages = await th_db.list_hunt_packages(search=query)
    hits: list[SearchHit] = []
    for pkg in packages[:MAX_PER_SECTION]:
        label = sanitize_text(pkg.get("hunt_id_display")) or ""
        title = sanitize_text(pkg.get("name")) or "(unnamed hunt)"
        hits.append(
            SearchHit(
                section="Threat Hunting",
                title=f"{label} {title}".strip(),
                snippet=_snippet(pkg.get("description"), query)
                or f"Status: {sanitize_text(pkg.get('status'))}",
                route=f"/threat-hunting/{pkg['id']}",
                ref=str(pkg["id"]),
            )
        )
    return hits


async def _search_threat_intel(query: str, role: str | None) -> list[SearchHit]:
    """Ingested threat-intel entries (raw store)."""
    if not role_allows(role, "threat-viewer"):
        return []
    from backend.db.manager import query_entries

    rows = await query_entries(search=query, limit=MAX_PER_SECTION)
    hits: list[SearchHit] = []
    for row in rows[:MAX_PER_SECTION]:
        title = sanitize_text(row.get("title")) or sanitize_text(row.get("indicator")) or "(entry)"
        body = row.get("description") or row.get("tags") or row.get("indicator")
        hits.append(
            SearchHit(
                section="Threat Intel",
                title=title,
                snippet=_snippet(body, query),
                route="/viewer",
                # The raw store's feed column is "source" (backend/db/schema.py);
                # "source_name" is the normalized store's spelling and would
                # silently be absent from every row here.
                ref=sanitize_text(row.get("source")) or None,
            )
        )
    return hits


async def _search_watchers(query: str, role: str | None) -> list[SearchHit]:
    """Watcher rules. Admin-only, matching the Watchers page itself."""
    if not role_allows(role, "admin"):
        return []
    from backend.db.watchers import list_watchers

    hits: list[SearchHit] = []
    for watcher in await list_watchers():
        if not _matches(query, watcher.get("name"), watcher.get("id"), watcher.get("severity")):
            continue
        hits.append(
            SearchHit(
                section="Watchers",
                title=sanitize_text(watcher.get("name")) or "(watcher)",
                snippet=_snippet(
                    f"Severity {sanitize_text(watcher.get('severity'))} · "
                    f"dataset {sanitize_text(watcher.get('dataset'))} · "
                    f"mode {sanitize_text(watcher.get('mode'))}",
                    query,
                ),
                route="/watchers",
                ref=sanitize_text(watcher.get("id")) or None,
            )
        )
        if len(hits) >= MAX_PER_SECTION:
            break
    return hits


def _search_docs(query: str, role: str | None) -> list[SearchHit]:
    """Full-text search within the allowlisted documentation."""
    if not role_allows(role, "threat-viewer"):
        return []
    hits: list[SearchHit] = []
    needle = query.lower()
    # Each document gets a share of the section's budget rather than
    # first-come-first-served: a common word matches ten topics in the first
    # document, which would otherwise mean later documents are never opened.
    per_doc = max(1, MAX_PER_SECTION // max(1, len(docs_registry.DOCUMENTS)))
    for doc_id, document in docs_registry.DOCUMENTS.items():
        path = docs_registry.resolve(doc_id)
        if path is None:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover — defensive
            logger.warning("Could not read searchable doc %s: %s", path, exc)
            continue
        # Report the nearest preceding heading so a hit lands on a topic rather
        # than an anonymous line, and emit at most one hit per topic — otherwise
        # a common word floods the section with near-identical lines from the
        # same part of one document.
        heading: str | None = None
        seen_headings: set[str | None] = set()
        found_here = 0
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("## "):
                heading = stripped[3:].strip()
            if heading in seen_headings or needle not in stripped.lower():
                continue
            seen_headings.add(heading)
            hits.append(
                SearchHit(
                    section="Docs",
                    title=f"{document.title} — {heading}" if heading else document.title,
                    snippet=_snippet(stripped, query),
                    route="/about",
                    ref=doc_id,
                )
            )
            found_here += 1
            if found_here >= per_doc:
                break  # move on to the next document, don't abandon them
    return hits[:MAX_PER_SECTION]


async def global_search(query: str, *, role: str | None, limit: int = MAX_TOTAL_RESULTS) -> dict:
    """Search everything the caller is allowed to read.

    Returns ``{"query", "total", "sections": [{"section", "hits": [...]}, ...]}``
    with sections in a stable, most-actionable-first order.
    """
    cleaned = clean_query(query)
    if not cleaned:
        return {"query": "", "total": 0, "sections": []}

    collected: list[SearchHit] = [
        *await _search_hunts(cleaned, role),
        *await _search_threat_intel(cleaned, role),
        *await _search_watchers(cleaned, role),
        # The catalogue spans several sections (Navigation, Settings, Docs), so
        # hits are grouped by their own section below rather than by source.
        *_search_catalog(cleaned, role),
        *_search_docs(cleaned, role),
    ]

    # Bucket by section first, capping each section, but WITHOUT spending the
    # overall budget in source order — otherwise a query that matches many
    # hunts leaves nothing for Settings or Docs, and the point of this search
    # is to show which sections a term appears in.
    buckets: dict[str, list[SearchHit]] = {}
    for hit in collected:
        bucket = buckets.setdefault(hit.section, [])
        if len(bucket) < MAX_PER_SECTION:
            bucket.append(hit)

    # Stable, most-actionable-first ordering; any section not listed (a future
    # source) still appears, after the known ones.
    order = ["Threat Hunting", "Threat Intel", "Watchers", "Navigation", "Settings", "Docs"]
    ranked = sorted(buckets, key=lambda s: (order.index(s) if s in order else len(order), s))

    # Spend the overall limit round-robin across sections, so trimming thins
    # every section evenly instead of dropping the last ones outright.
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in ranked}
    total = 0
    for depth in range(MAX_PER_SECTION):
        if total >= limit:
            break
        for name in ranked:
            if total >= limit:
                break
            source = buckets[name]
            if depth < len(source):
                grouped[name].append(source[depth].to_dict())
                total += 1

    return {
        "query": cleaned,
        "total": total,
        "sections": [{"section": name, "hits": grouped[name]} for name in ranked if grouped[name]],
    }
