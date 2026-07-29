"""Named scopes for API-key access (issue-local-029).

An API key is never granted the role-based access a session gets — it is
authorized purely by an explicit, curated set of named *scopes*, each
resolving to a small allowlist of (HTTP method, path pattern) pairs under the
Threat Hunting API. There is deliberately no scope that reaches the
admin/configuration surface (user management, LLM provider secrets, SSO
config, API-key management itself, etc.) — those stay session-only regardless
of what scopes a key holds, since "select all" in the wizard must never be
equivalent to admin access.

Adding a new scope means adding an entry to :data:`API_SCOPES` below; nothing
else needs to change (the wizard's toggle list and "select all" are both
driven by :func:`list_scopes`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Path fragments reused across several scopes' patterns.
_PKG = r"/api/threat-hunting/packages/[^/]+"
_RUN = rf"{_PKG}/runs/[^/]+"


@dataclass(frozen=True)
class ApiScope:
    id: str
    label: str
    description: str
    routes: tuple[tuple[str, re.Pattern[str]], ...] = field(repr=False)


def _scope(id_: str, label: str, description: str, routes: list[tuple[str, str]]) -> ApiScope:
    return ApiScope(
        id=id_,
        label=label,
        description=description,
        routes=tuple((method, re.compile(pattern)) for method, pattern in routes),
    )


API_SCOPES: dict[str, ApiScope] = {
    s.id: s
    for s in [
        _scope(
            "hunts:create",
            "Create hunt packages",
            "Create a new hunt package.",
            [("POST", r"^/api/threat-hunting/packages$")],
        ),
        _scope(
            "hunts:read",
            "List / view hunt packages",
            "List hunt packages and view a single package's details.",
            [
                ("GET", r"^/api/threat-hunting/packages$"),
                ("GET", rf"^{_PKG}$"),
            ],
        ),
        _scope(
            "hunts:update",
            "Update hunt packages",
            "Rename/re-describe an existing hunt package.",
            [("PUT", rf"^{_PKG}$")],
        ),
        _scope(
            "hunts:delete",
            "Delete hunt packages",
            "Delete a hunt package.",
            [("DELETE", rf"^{_PKG}$")],
        ),
        _scope(
            "evidence:add",
            "Add evidence",
            "Add evidence to a hunt package (file upload, URL, manual text, or watcher import).",
            [
                ("POST", rf"^{_PKG}/evidence/file$"),
                ("POST", rf"^{_PKG}/evidence/url$"),
                ("POST", rf"^{_PKG}/evidence/text$"),
                ("POST", rf"^{_PKG}/evidence/watcher$"),
            ],
        ),
        _scope(
            "evidence:read",
            "List evidence",
            "List a hunt package's evidence items.",
            [("GET", rf"^{_PKG}/evidence$")],
        ),
        _scope(
            "evidence:delete",
            "Delete evidence",
            "Remove an evidence item from a hunt package.",
            [("DELETE", rf"^{_PKG}/evidence/[^/]+$")],
        ),
        _scope(
            "runs:generate",
            "Run hunt generation",
            "Trigger the analysis pipeline for a hunt package and check its progress.",
            [
                ("POST", rf"^{_PKG}/generate$"),
                ("GET", rf"^{_PKG}/generate/status$"),
                ("GET", rf"^{_PKG}/runs$"),
                ("GET", rf"^{_RUN}/status$"),
            ],
        ),
        _scope(
            "reports:download",
            "Download reports",
            "Download a hunt report (Markdown, PDF, or JSON), package-level or per-run.",
            [
                ("GET", rf"^{_PKG}/report$"),
                ("GET", rf"^{_PKG}/report/markdown$"),
                ("GET", rf"^{_PKG}/report/pdf$"),
                ("GET", rf"^{_RUN}/report$"),
                ("GET", rf"^{_RUN}/report/markdown$"),
                ("GET", rf"^{_RUN}/report/pdf$"),
            ],
        ),
        _scope(
            "iocs:read",
            "Download IOC list",
            "List the IOCs extracted for a hunt package.",
            [("GET", rf"^{_PKG}/iocs$")],
        ),
        _scope(
            "threat_intel:read",
            "Download Threat Intelligence reports",
            "Read a run's (or a package's latest) Threat Intelligence analysis.",
            [
                ("GET", rf"^{_PKG}/threat-intel$"),
                ("GET", rf"^{_RUN}/threat-intel$"),
            ],
        ),
        _scope(
            "threat_intel_tracking:read",
            "Query Threat Intel Tracking data",
            "Query the cross-hunt Threat Intel Tracking dashboard aggregation.",
            [
                ("GET", r"^/api/threat-hunting/tracking/dashboard$"),
                ("GET", r"^/api/threat-hunting/tracking/hunts$"),
            ],
        ),
        _scope(
            "comparison:read",
            "Download comparison reports",
            "Read/download a hunt package's run-comparison report.",
            [
                ("GET", rf"^{_PKG}/comparison$"),
                ("GET", rf"^{_PKG}/comparison/markdown$"),
                ("GET", rf"^{_PKG}/comparison/pdf$"),
            ],
        ),
    ]
}

# issue-local-029: the wizard's "default profile" — exactly the capabilities
# the issue enumerates (create a hunt, add evidence, download every report
# type, download the IOC list, download a run's Threat Intel report, query
# Threat Intel Tracking data from hunt history).
DEFAULT_PROFILE_SCOPES: list[str] = [
    "hunts:create",
    "evidence:add",
    "reports:download",
    "iocs:read",
    "threat_intel:read",
    "threat_intel_tracking:read",
]


def list_scopes() -> list[dict[str, str]]:
    """Return every defined scope's public shape (id/label/description) —
    the wizard's toggle list and "select all" are both driven by this."""
    return [
        {"id": s.id, "label": s.label, "description": s.description} for s in API_SCOPES.values()
    ]


def valid_scope_ids(scope_ids: list[str]) -> list[str]:
    """Filter *scope_ids* down to only those that are actually defined,
    preserving order and dropping duplicates. Used to sanitize input on
    create/update — an unknown scope id is silently dropped rather than
    rejected outright, so a client sending a stale id from an older scope
    list doesn't hard-fail the whole request."""
    seen: set[str] = set()
    out: list[str] = []
    for sid in scope_ids:
        if sid in API_SCOPES and sid not in seen:
            seen.add(sid)
            out.append(sid)
    return out


def scope_allows(scope_ids: list[str], method: str, path: str) -> bool:
    """Return True if any of *scope_ids* grants (method, path)."""
    for sid in scope_ids:
        scope = API_SCOPES.get(sid)
        if scope is None:
            continue
        for scope_method, pattern in scope.routes:
            if scope_method == method and pattern.match(path):
                return True
    return False
