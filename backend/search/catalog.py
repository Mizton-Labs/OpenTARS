"""Static catalogue of application destinations for global search (issue-local-031).

This is the "where do I find X" half of the search index: navigation pages,
Configuration tabs, and documentation topics. Each entry is a *destination* —
a name, what it does, and the route that opens it.

SECURITY — this catalogue deliberately indexes **names and locations only,
never configured values**. Searching settings must never become a way to read
the LLM ``api_key``, the SSO ``client_secret``, per-source request headers,
SIEM connector credentials, or any other secret the Configuration pages can
hold. Because no value is ever placed in the index, that class of leak is
impossible by construction rather than by redaction — there is nothing to
redact. Anything added here must keep that property.

Every entry carries a ``min_role``; :func:`catalog_for_role` filters the
catalogue before any matching happens, so a lower-privileged caller cannot
learn that an admin-only page exists, let alone what it contains.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Roles, ordered least → most privileged. "feed-sender" is deliberately absent:
# it is a push-only machine account with no read access to anything here.
_ROLE_RANK: dict[str, int] = {
    "threat-viewer": 1,
    "threat-researcher": 2,
    "admin": 3,
}


def role_rank(role: str | None) -> int:
    """Rank a role for comparison. Unknown/absent roles fail closed at 0."""
    return _ROLE_RANK.get(role or "", 0)


def role_allows(role: str | None, min_role: str) -> bool:
    return role_rank(role) >= role_rank(min_role)


@dataclass(frozen=True)
class CatalogEntry:
    """A searchable destination within the application."""

    id: str
    section: str
    title: str
    description: str
    route: str
    min_role: str = "threat-viewer"
    #: Extra search terms that should match this entry but do not belong in the
    #: visible title/description (synonyms, older names operators may know).
    keywords: tuple[str, ...] = field(default=())

    def haystack(self) -> str:
        return " ".join((self.title, self.description, self.section, *self.keywords)).lower()


def _e(
    id_: str,
    section: str,
    title: str,
    description: str,
    route: str,
    min_role: str = "threat-viewer",
    keywords: tuple[str, ...] = (),
) -> CatalogEntry:
    return CatalogEntry(
        id=id_,
        section=section,
        title=title,
        description=description,
        route=route,
        min_role=min_role,
        keywords=keywords,
    )


# ── Navigation ────────────────────────────────────────────────────────────────

_PAGES: list[CatalogEntry] = [
    _e(
        "page:home",
        "Navigation",
        "Home",
        "Dashboard overview of ingestion, normalization, and hunting activity.",
        "/home",
        keywords=("dashboard", "overview", "start"),
    ),
    _e(
        "page:viewer",
        "Navigation",
        "Viewer",
        "Browse the raw and normalized threat-intel tables with search and natural-language query.",
        "/viewer",
        keywords=("entries", "raw", "normalized", "browse", "events"),
    ),
    _e(
        "page:th-dashboard",
        "Navigation",
        "Threat Hunting Dashboard",
        "Metrics overview: hunt packages, runs, evidence, IOCs, hypotheses, "
        "hunting leads, queries, and threat intel identified across hunts.",
        "/threat-hunting",
        keywords=("dashboard", "metrics", "stats", "kpi", "overview", "hunts"),
    ),
    _e(
        "page:threat-hunting",
        "Navigation",
        "Hunt Packages",
        "Create hunt packages, add evidence, run the agent pipeline, and read reports.",
        "/threat-hunting/packages",
        keywords=("hunts", "hunt packages", "investigations"),
    ),
    _e(
        "page:th-tracking",
        "Navigation",
        "Threat Intel Tracking",
        "Cross-hunt aggregation of IOCs, CVEs, threat actors, campaigns, malware "
        "families, and TTPs.",
        "/threat-hunting/tracking",
        min_role="threat-researcher",
        keywords=("correlation", "aggregate", "actors", "campaigns", "ttp", "cve"),
    ),
    _e(
        "page:normalizer",
        "Navigation",
        "Normalizer",
        "Run and monitor the normalization engine and review per-run history.",
        "/normalizer",
        min_role="admin",
        keywords=("normalize", "mapping", "canonical"),
    ),
    _e(
        "page:watchers",
        "Navigation",
        "Watchers",
        "Standing alert rules over incoming threat intel, each with its own feed.",
        "/watchers",
        min_role="admin",
        keywords=("alerts", "rules", "monitor", "feed"),
    ),
    _e(
        "page:account",
        "Navigation",
        "Account",
        "Your own account: change password and personal theme.",
        "/account",
        keywords=("profile", "password", "theme", "me"),
    ),
    _e(
        "page:about",
        "Navigation",
        "About",
        "Version and licence information, the API reference, and the interactive API Swagger.",
        "/about",
        keywords=("version", "licence", "license", "api docs", "swagger", "openapi"),
    ),
]


# ── Configuration tabs (names and locations only — never values) ──────────────
#
# Routes carry ?tab=<id> so a result actually opens the tab it names; the
# Configuration and About pages read that parameter (issue-local-031).
# Without it every Settings hit would land on the default tab, which makes
# a result that says "SSO / OIDC" quietly wrong.

_CONFIG: list[CatalogEntry] = [
    _e(
        "config:application",
        "Settings",
        "Application settings",
        "Display title, branding logo, base URL prefix, default theme, and pagination limits.",
        "/configuration?tab=application",
        min_role="admin",
        keywords=("title", "logo", "branding", "prefix", "theme", "pagination"),
    ),
    _e(
        "config:llm-providers",
        "Settings",
        "LLM Providers",
        "Configure and enable the LLM providers and models used by the agent "
        "pipeline, natural-language query, and smart search.",
        "/configuration?tab=llm-providers",
        min_role="admin",
        keywords=("llm", "openai", "anthropic", "azure", "ollama", "model", "smart search"),
    ),
    _e(
        "config:siem-connectors",
        "Settings",
        "SIEM Connectors",
        "Connection profiles used to execute hunts against a SIEM.",
        "/configuration?tab=siem-connectors",
        min_role="admin",
        keywords=("splunk", "siem", "connector", "execute"),
    ),
    _e(
        "config:sso",
        "Settings",
        "SSO / OIDC",
        "Single sign-on configuration for authenticating users against an identity provider.",
        "/configuration?tab=sso-config",
        min_role="admin",
        keywords=("sso", "oidc", "identity", "login", "saml"),
    ),
    _e(
        "config:user-management",
        "Settings",
        "User Management",
        "Create user accounts, assign roles, reset passwords, and disable access.",
        "/configuration?tab=user-management",
        min_role="admin",
        keywords=("users", "roles", "accounts", "permissions", "password reset"),
    ),
    _e(
        "config:api-access",
        "Settings",
        "API Access",
        "Enable programmatic API access and manage scoped API keys.",
        "/configuration?tab=api-access",
        min_role="admin",
        keywords=("api key", "token", "programmatic", "scopes", "bearer"),
    ),
    _e(
        "config:threat-intel-feeds",
        "Settings",
        "Threat Intel feeds",
        "Open threat feeds, local and external feeds, RSS, external API pulls, and "
        "the listener endpoint.",
        "/configuration?tab=threat-intel",
        min_role="admin",
        keywords=("feeds", "rss", "ingest", "listener", "sources", "pull"),
    ),
    _e(
        "config:global-fields",
        "Settings",
        "Global Field Defaults",
        "Canonical field namespace and per-field defaults used by normalization.",
        "/configuration?tab=global-fields",
        min_role="admin",
        keywords=("fields", "schema", "canonical", "mapping"),
    ),
    _e(
        "config:agents",
        "Settings",
        "Agents Configuration",
        "Agent tools, document parsers, workflow verbosity, and visualization style.",
        "/configuration?tab=agents-config",
        min_role="admin",
        keywords=("agents", "tools", "parsers", "docling", "workflow"),
    ),
    _e(
        "config:th-settings",
        "Settings",
        "Threat Hunting Settings",
        "Research effort, report formats, HuntID prefix, and LLM retry behaviour for hunts.",
        "/configuration?tab=th-settings",
        min_role="admin",
        keywords=("effort", "report", "pdf", "markdown", "huntid", "retry"),
    ),
]


# ── Documentation topics ──────────────────────────────────────────────────────

_DOCS: list[CatalogEntry] = [
    _e(
        "doc:api-threat-hunting",
        "Docs",
        "Threat Hunting API reference",
        "Every /api/threat-hunting endpoint, session vs. scoped API-key access, and "
        "the API-key management routes.",
        "/about?tab=api-docs",
        keywords=("api", "endpoint", "reference", "rest", "curl", "integration"),
    ),
    _e(
        "doc:api-swagger",
        "Docs",
        "Interactive API Swagger",
        "Try the API from the browser against the running server's OpenAPI schema.",
        "/about?tab=api-swagger",
        keywords=("swagger", "openapi", "interactive", "try it"),
    ),
]


CATALOG: tuple[CatalogEntry, ...] = tuple(_PAGES + _CONFIG + _DOCS)


def catalog_for_role(role: str | None) -> list[CatalogEntry]:
    """Return only the entries *role* is permitted to see.

    Applied before matching, so a caller never learns that a destination they
    cannot reach exists.
    """
    return [entry for entry in CATALOG if role_allows(role, entry.min_role)]
