"""The project documents the application exposes — single source of truth.

Two surfaces read the shipped documentation: ``GET /api/app/docs/{doc_id}``
serves a document to the About page's API Docs tab (issue-local-030), and
global search indexes the same documents (issue-local-031). Both consult this
registry rather than keeping their own copy.

That matters beyond tidiness: this mapping is a **path allowlist**. ``doc_id``
is only ever used as a dict key here and is never concatenated into a
filesystem path, which is what stops either surface from becoming an
arbitrary-file-read primitive no matter what a caller passes. Two hand-synced
copies of an allowlist drift, and a drifted allowlist is a security bug — so
there is exactly one.

Adding a document here exposes it to both surfaces at once.
"""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

_PROJECT_ROOT = Path(__file__).resolve().parents[1]

#: Directory holding the shipped documentation.
DOCS_DIR = _PROJECT_ROOT / "docs"


class Document(NamedTuple):
    """A document exposed to the UI and to search."""

    #: Human-readable name, used as the search-result title.
    title: str
    #: Filename within :data:`DOCS_DIR`. Never taken from a request.
    filename: str


#: doc_id → document. The keys are the public identifiers used in URLs.
DOCUMENTS: dict[str, Document] = {
    "api-threat-hunting": Document("Threat Hunting API reference", "api-threat-hunting.md"),
}


def resolve(doc_id: str) -> Path | None:
    """Return the on-disk path for *doc_id*, or None when it is not allowlisted.

    Returns None for an unknown id and for an allowlisted document whose file
    is missing, so callers cannot distinguish the two and probe the filesystem.
    """
    document = DOCUMENTS.get(doc_id)
    if document is None:
        return None
    path = DOCS_DIR / document.filename
    return path if path.is_file() else None
