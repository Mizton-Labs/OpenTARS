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
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import asdict, dataclass
from typing import Any, TypeVar

from backend import docs_registry
from backend.search.catalog import catalog_for_role, role_allows

logger = logging.getLogger(__name__)

T = TypeVar("T")

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

# Words that name a Threat Intel Tracking *category* rather than an entry.
# Asking "which malware families show up?" should list the families, even
# though none of them is called "malware". Kept narrow on purpose: a term
# broad enough to appear in ordinary prose would make every query dump the
# whole category.
_ACTOR_TERMS = ("threat actor", "actors", "actor", "adversary", "adversaries", "apt group")
_CAMPAIGN_TERMS = ("campaign", "campaigns")
_MALWARE_TERMS = ("malware", "malware family", "malware families")
_TECHNIQUE_TERMS = ("ttp", "ttps", "technique", "techniques", "mitre", "att&ck")


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


def interleave(sequences: Iterable[Sequence[T]]) -> Iterator[T]:
    """Yield items round-robin across *sequences*.

    Used everywhere several producers share one bounded budget. Draining them
    one at a time instead lets whichever runs first consume the whole budget
    and silently drop the rest — which has bitten this feature repeatedly: raw
    threat intel hiding the normalized store, correlated IOCs hiding the threat
    actor and malware aggregates, and one section hiding another in a
    SmartSearch term's retrieval. Round-robin makes "everything gets a share"
    the default rather than something each call site has to remember.
    """
    lists = [s for s in sequences if s]
    for depth in range(max((len(s) for s in lists), default=0)):
        for seq in lists:
            if depth < len(seq):
                yield seq[depth]


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
                title=f"{title} (raw)",
                snippet=_snippet(body, query),
                route="/viewer?tab=raw",
                # The raw store's feed column is "source" (backend/db/schema.py);
                # "source_name" is the normalized store's spelling and would
                # silently be absent from every row here.
                ref=sanitize_text(row.get("source")) or None,
            )
        )
    return hits


async def _search_normalized(query: str, role: str | None) -> list[SearchHit]:
    """The normalized threat-intel store.

    Raw and normalized are independent stores — the same term can match rows in
    one and not the other — so searching only the raw table missed half of the
    Threat Intel module.
    """
    if not role_allows(role, "threat-viewer"):
        return []
    from backend.normalizer.db import query_normalized

    rows = await query_normalized(search=query, limit=MAX_PER_SECTION)
    hits: list[SearchHit] = []
    for row in rows[:MAX_PER_SECTION]:
        title = sanitize_text(row.get("title")) or sanitize_text(row.get("indicator")) or "(entry)"
        body = row.get("description") or row.get("tags") or row.get("indicator")
        hits.append(
            SearchHit(
                section="Threat Intel",
                title=f"{title} (normalized)",
                snippet=_snippet(body, query),
                route="/viewer?tab=normalized",
                ref=sanitize_text(row.get("source_name")) or None,
            )
        )
    return hits


async def _search_feeds(query: str, role: str | None) -> list[SearchHit]:
    """Configured threat-intel feeds, by name and entry count.

    Only the per-source counts are read — never the source *definitions*, which
    carry request headers and API tokens and stay admin-only elsewhere.
    """
    if not role_allows(role, "threat-viewer"):
        return []
    from backend.db.manager import get_summary

    hits: list[SearchHit] = []
    for row in await get_summary():
        name = sanitize_text(row.get("source"))
        if not name or name == "__total__" or not _matches(query, name):
            continue
        hits.append(
            SearchHit(
                section="Feeds",
                title=name,
                snippet=f"{row.get('count', 0)} ingested entries",
                route="/viewer",
                ref=name,
            )
        )
        if len(hits) >= MAX_PER_SECTION:
            break
    return hits


async def _search_tracking(query: str, role: str | None) -> list[SearchHit]:
    """The Threat Intel Tracking submodule: correlated IOCs and CVEs, plus the
    threat actors, campaigns, malware families and MITRE techniques aggregated
    across every hunt's latest Threat Intelligence analysis.

    Researcher and above, matching the Tracking pages themselves — the tracking
    routes sit outside the viewer's ``/api/threat-hunting/packages`` allowlist.
    """
    if not role_allows(role, "threat-researcher"):
        return []
    from backend.threat_hunting import db as th_db

    def _hunts_of(record: dict[str, Any]) -> str:
        """Name the hunts a tracked item came from.

        The two aggregations spell this differently: `list_correlated_iocs`
        attaches `hunt_packages`, while the entity aggregates attach `sources`.
        Reading only one of them silently reported "no linked hunt" for every
        IOC and CVE, which is worse than saying nothing — it told the model the
        opposite of the truth, and the model repeated it.
        """
        linked = record.get("hunt_packages") or record.get("sources") or []
        names = [sanitize_text(item.get("hunt_id_display") or item.get("name")) for item in linked]
        seen = [n for n in names if n]
        if not seen:
            return "not linked to a hunt package"
        shown = ", ".join(seen[:4])
        return f"Seen in {len(seen)} hunt package(s): {shown}" if len(seen) > 4 else shown

    def _hit(title: str, record: dict[str, Any], ref: str | None) -> SearchHit:
        return SearchHit(
            section="Threat Intel Tracking",
            title=title,
            snippet=_hunts_of(record),
            route="/threat-hunting/tracking",
            ref=ref,
        )

    # IOCs and CVEs share one aggregation; the store already filters by substring.
    ioc_hits = [
        _hit(
            f"{sanitize_text(row.get('ioc'))} ({sanitize_text(row.get('ioc_type')) or 'ioc'})",
            row,
            sanitize_text(row.get("ioc")) or None,
        )
        for row in await th_db.list_correlated_iocs(search=query, limit=MAX_PER_SECTION)
    ]

    # Kept per category and interleaved with the IOCs below. Appending them
    # after a full IOC list meant a term like "malware" — which matches plenty
    # of IOC URLs — filled the section before the malware-family and
    # threat-actor aggregates were ever reached.
    grouped: list[list[SearchHit]] = [ioc_hits]
    needle = query.lower()
    for label, keywords, records in (
        ("threat actor", _ACTOR_TERMS, await th_db.aggregate_threat_actors()),
        ("campaign", _CAMPAIGN_TERMS, await th_db.aggregate_campaigns()),
        ("malware family", _MALWARE_TERMS, await th_db.aggregate_malware_families()),
        ("technique", _TECHNIQUE_TERMS, await th_db.aggregate_ttps()),
    ):
        # "which malware families show up across my hunts?" asks for the
        # category, not for an entry whose *name* contains "malware" — the
        # families here are called msaRAT and Chaos ransomware, so a substring
        # match returns nothing. When the query names the category, list its
        # entries; otherwise fall back to matching individual names.
        wants_category = any(word in needle for word in keywords)
        matched: list[SearchHit] = []
        for record in records:
            name = sanitize_text(record.get("name") or record.get("technique_id"))
            if not name:
                continue
            if not wants_category and not _matches(query, name, record.get("description")):
                continue
            matched.append(_hit(f"{name} ({label})", record, name))
            if len(matched) >= MAX_PER_SECTION:
                break
        grouped.append(matched)

    hits: list[SearchHit] = []
    for hit in interleave(grouped):
        hits.append(hit)
        if len(hits) >= MAX_PER_SECTION:
            break
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

    # Kept per source rather than flattened, because several sources feed the
    # same section: raw and normalized threat intel both land in "Threat Intel",
    # and the catalogue alone spans Navigation, Settings and Docs.
    per_source: list[list[SearchHit]] = [
        await _search_hunts(cleaned, role),
        await _search_threat_intel(cleaned, role),
        await _search_normalized(cleaned, role),
        await _search_tracking(cleaned, role),
        await _search_feeds(cleaned, role),
        await _search_watchers(cleaned, role),
        _search_catalog(cleaned, role),
        _search_docs(cleaned, role),
    ]

    # Bucket by section, capping each section, interleaving the sources as we
    # go. Draining one source at a time would let raw threat intel fill the
    # whole "Threat Intel" bucket and silently discard every normalized match —
    # the two are independent stores, so that would report only half the module.
    buckets: dict[str, list[SearchHit]] = {}
    for hit in interleave(per_source):
        bucket = buckets.setdefault(hit.section, [])
        if len(bucket) < MAX_PER_SECTION:
            bucket.append(hit)

    # Stable, most-actionable-first ordering; any section not listed (a future
    # source) still appears, after the known ones.
    order = [
        "Threat Hunting",
        "Threat Intel",
        "Threat Intel Tracking",
        "Feeds",
        "Watchers",
        "Navigation",
        "Settings",
        "Docs",
    ]
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
