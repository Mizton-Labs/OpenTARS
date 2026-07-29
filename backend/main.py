"""
OpenTARS — FastAPI application entry point.
Mounts all API routers; the APScheduler instance lives in backend.scheduler.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend import __version__
from backend import scheduler as scheduler_mod
from backend.api.routes_app import router as app_config_router
from backend.api.routes_auth import router as auth_router
from backend.api.routes_control import router as control_router
from backend.api.routes_feed import router as feed_router
from backend.api.routes_fields import router as fields_router
from backend.api.routes_ingest import router as ingest_router
from backend.api.routes_jobs import router as jobs_router
from backend.api.routes_llm import router as llm_router
from backend.api.routes_mappings import router as mappings_router
from backend.api.routes_normalizer import router as normalizer_router
from backend.api.routes_query import router as query_router
from backend.api.routes_smart import router as smart_router
from backend.api.routes_sources import router as sources_router
from backend.api.routes_threat_hunting import router as threat_hunting_router
from backend.api.routes_viewer import router as viewer_router
from backend.api.routes_watchers import router as watchers_router
from backend.auth.api_scopes import scope_allows
from backend.auth.db import init_users_db
from backend.auth.service import (
    SESSION_COOKIE_NAME,
    bootstrap_admin_if_empty,
    resolve_api_key,
    resolve_session,
)
from backend.config.loader import (
    load_api_access_enabled,
    load_app_base_prefix,
    load_auth_enabled,
)
from backend.db.watchers import init_watchers_db
from backend.logging_config import setup_logging
from backend.normalizer.consolidated import init_consolidated_db
from backend.normalizer.db import check_and_handle_schema_bump
from backend.normalizer.mappings import (
    init_mappings_db,
    migrate_yaml_manual_mappings_once,
)
from backend.normalizer.proposals import init_proposals_db
from backend.normalizer.run_history import init_run_history_db
from backend.threat_hunting.db import init_threat_hunting_db

_LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
setup_logging(_LOG_DIR)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Reconcile normalized.db schema before scheduling jobs. On a schema
    # version bump this drops & recreates normalized.db and resets the
    # normalized flag on all source rows so the next run rebuilds.
    try:
        await check_and_handle_schema_bump()
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("Normalized DB schema reconciliation failed: %s", exc)
    try:
        await init_proposals_db()
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("Proposals DB init failed: %s", exc)
    # prompts-021F: init mapping_versions.db and run the idempotent
    # one-shot seed from yaml manual_mappings. Both calls are safe to
    # re-run on every startup.
    try:
        await init_mappings_db()
        seeded = await migrate_yaml_manual_mappings_once()
        if seeded:
            logger.info(
                "mapping_versions migration seeded %d row(s) from yaml",
                seeded,
            )
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("Mapping versions init/migration failed: %s", exc)
    # prompts-032: init the consolidated (global) mapping store. Separate
    # table in the same DB file; safe to re-run on every startup.
    try:
        await init_consolidated_db()
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("Consolidated mappings init failed: %s", exc)
    # prompts-039: init the run-history store (its own DB file, never wiped
    # by a normalized.db schema bump). Safe to re-run on every startup.
    try:
        await init_run_history_db()
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("Run history init failed: %s", exc)
    # issue_local_006: init the watchers store (its own DB file, never wiped by
    # a normalized.db schema bump). Safe to re-run on every startup.
    try:
        await init_watchers_db()
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("Watchers DB init failed: %s", exc)
    # issue-local-002: init the threat hunting store (its own DB file, never
    # wiped by a normalized.db schema bump). Safe to re-run on every startup.
    try:
        await init_threat_hunting_db()
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("Threat hunting DB init failed: %s", exc)
    # prompts-045: when authentication is enabled, ensure the users/sessions
    # store exists and bootstrap a first-run admin account. When auth is
    # disabled the app stays fully open and this is skipped entirely.
    if load_auth_enabled():
        try:
            await init_users_db()
            await bootstrap_admin_if_empty()
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning("Auth init/bootstrap failed: %s", exc)
    scheduler_mod.reload()
    scheduler_mod.start()
    yield
    scheduler_mod.stop()


app = FastAPI(
    title="OpenTARS",
    version=__version__,
    description="Lightweight Threat Intelligence feed receiver, normaliser, and viewer.",
    lifespan=lifespan,
    # When deployed behind a reverse proxy at a sub-path, root_path makes
    # the OpenAPI docs / schema URLs reflect the external mount point.
    # Empty string == mounted at root (default).
    root_path=load_app_base_prefix(),
    # issue-local-030: the stock docs pages are replaced by the relative-URL
    # versions defined below (see _swagger_ui / _redoc). Disabling them here
    # frees /docs and /redoc for those custom routes; /openapi.json is left
    # auto-registered (openapi_url is untouched) — only the URL the HTML
    # *references* changes, not where the schema is actually served.
    docs_url=None,
    redoc_url=None,
)
if app.root_path:
    logger.info("Application mounted under base prefix: %s", app.root_path)

# Allow frontend dev server (Vite on :5173) during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(ingest_router)
app.include_router(viewer_router)
app.include_router(sources_router)
app.include_router(fields_router)
app.include_router(control_router)
app.include_router(normalizer_router)
app.include_router(query_router)
app.include_router(jobs_router)
app.include_router(app_config_router)
app.include_router(llm_router)
app.include_router(smart_router)
app.include_router(mappings_router)
app.include_router(auth_router)
app.include_router(watchers_router)
app.include_router(threat_hunting_router)
# Public per-watcher feed (issue_local_006). Registered before the SPA
# catch-all (defined later in this module) so /feed/watcher/<id>/ resolves to
# the renderer rather than the index.html fallback. It lives OUTSIDE /api/ so
# the auth middleware (which only guards /api/) leaves it public by design.
app.include_router(feed_router)


# ── Authentication enforcement (prompts-045) ──────────────────────────────────
#
# When auth is DISABLED (default) this middleware is a no-op and the app is
# fully open, exactly as before prompts-045. When ENABLED it gates every
# /api/* route:
#   - a small public allowlist is always reachable (login, status, health,
#     the branding logo image);
#   - everything else requires a valid session cookie (401 otherwise);
#   - 'threat-researcher': full Threat Hunting access + TI Viewer reads;
#   - 'threat-viewer' (read-only): limited to TI Viewer reads and TH reads;
#   - 'feed-sender' (listener-only machine): POST /api/ingest/listener only
#     (issue-local-002: replaces old 'normal'/'sender' roles).
# Non-API paths (the SPA shell + static assets) are always served so the login
# page can load; the SPA itself redirects to /login when unauthenticated. The
# one exception is FastAPI's own docs/redoc/openapi.json (issue-local-030,
# see _DOCS_PATHS below), which — despite living outside /api/ — are gated
# the same as everything else once auth is enabled.

# Exact public API paths (method-checked below).
_PUBLIC_API_PATHS = frozenset(
    {
        "/api/health",
        "/api/auth/login",
        "/api/auth/status",
        # issue-local-010: OIDC flow endpoints — must be public (no session yet)
        "/api/auth/oidc/login",
        "/api/auth/oidc/callback",
    }
)

# Self-service paths any authenticated user may reach regardless of role.
_SELF_PATHS = frozenset(
    {
        "/api/auth/me",
        "/api/auth/logout",
        "/api/auth/password",
        # issue-local-016: any authenticated user (not just admins, who
        # already bypass role-gating entirely below) may set their own theme.
        "/api/auth/me/theme",
    }
)

# GET-only prefixes a 'threat-viewer' (read-only) user may reach. Scoped to
# exactly what the Viewer page and Threat Hunting read-only views fetch.
#
# NOTE (prompts-045 security audit): the /api/sources/*-pull list endpoints are
# DELIBERATELY excluded. They return raw source config that carries per-source
# request `headers` (API keys / Authorization tokens). Source management is an
# admin-only surface; a viewer has no need to read it and must never see those
# credentials. The endpoints are additionally redacted server-side
# (routes_sources._redact_source) as defense-in-depth.
_VIEWER_GET_PREFIXES = (
    "/api/viewer",
    "/api/normalizer/entries",
    "/api/normalizer/config",
    "/api/normalizer/summary",
    "/api/normalizer/runs",
    "/api/app/pagination-max",
    "/api/app/logo",
    "/api/smart-mappings/active",
    # Threat Hunting read-only access (issue-local-002, Phase 1)
    "/api/threat-hunting/packages",
    # Project docs (About page's API Docs tab, issue-local-030) — read-only,
    # allowlisted content (see routes_app.get_doc).
    "/api/app/docs",
)

# POST endpoints a 'threat-viewer' (read-only) account may reach. The
# natural-language query endpoint (prompts-064) is a read operation expressed
# as a POST (it carries a JSON body). The push-only 'feed-sender' role is
# deliberately NOT granted this.
_VIEWER_POST_PATHS = ("/api/query/nl",)

# GET prefixes a 'threat-researcher' may read (everything viewer can + more).
# Researchers can also mutate Threat Hunting resources; those mutations are
# gated per-route via require_researcher_or_admin (added in Phase 1f routes).
#
# issue-local-026: /api/llm/ was missing here, so GET /api/llm/providers and
# GET /api/llm/config 403'd for threat-researcher — the model-selector dropdown
# in the Threat Hunting UI (which every researcher can see and use) silently
# came back empty for anyone who wasn't admin, since its provider-list fetch
# never got past the middleware. Both GET routes under /api/llm/ already
# redact api_key server-side (redact_config / list_provider_names), so this
# is safe to open to researcher without leaking secrets.
_RESEARCHER_GET_PREFIXES = _VIEWER_GET_PREFIXES + ("/api/llm/",)

# POST / PUT / DELETE paths a 'threat-researcher' may reach (TH mutations).
_RESEARCHER_WRITE_PREFIXES = (
    "/api/threat-hunting/",
    "/api/query/nl",
)


def _viewer_role_allowed(method: str, path: str) -> bool:
    if path in _SELF_PATHS:
        return True
    if method == "GET" and any(path.startswith(p) for p in _VIEWER_GET_PREFIXES):
        return True
    if method == "POST" and path in _VIEWER_POST_PATHS:
        return True
    return False


def _researcher_role_allowed(method: str, path: str) -> bool:
    if path in _SELF_PATHS:
        return True
    # All GET access the viewer has
    if method == "GET" and any(path.startswith(p) for p in _RESEARCHER_GET_PREFIXES):
        return True
    # Read-only TI Viewer POST (NL query)
    if method == "POST" and path in _VIEWER_POST_PATHS:
        return True
    # Full Threat Hunting write access
    if method in ("GET", "POST", "PUT", "DELETE", "PATCH") and any(
        path.startswith(p) for p in _RESEARCHER_WRITE_PREFIXES
    ):
        return True
    return False


# The only ingest path a 'feed-sender' (listener-only machine account) may
# reach. Feed-senders get self-service paths (login / forced-password-change /
# logout) plus this single POST endpoint — nothing else (issue-local-002;
# replaces old 'sender' role).
_FEED_SENDER_POST_PATH = "/api/ingest/listener"


def _feed_sender_role_allowed(method: str, path: str) -> bool:
    if path in _SELF_PATHS:
        return True
    return method == "POST" and path == _FEED_SENDER_POST_PATH


def _role_allowed(role: str, method: str, path: str) -> bool:
    """Authorize a non-admin role for a given request. Unknown roles fail closed."""
    if role == "threat-viewer":
        return _viewer_role_allowed(method, path)
    if role == "threat-researcher":
        return _researcher_role_allowed(method, path)
    if role == "feed-sender":
        return _feed_sender_role_allowed(method, path)
    return False


# FastAPI auto-registers its interactive docs (Swagger UI), ReDoc, and the raw
# OpenAPI schema OUTSIDE /api/ — the "only guard /api/" bypass below would
# otherwise leave them fully public regardless of auth_enabled, exposing the
# entire route/schema surface (including admin/config/user-management routes,
# not just Threat Hunting) to anyone who requests the URL directly, even
# though the About page that links to them (issue-local-030) is itself behind
# the authenticated SPA shell. Require a valid session for these three exact
# paths, same as everything else once auth is on.
_DOCS_PATHS = frozenset({"/docs", "/redoc", "/openapi.json"})


@app.middleware("http")
async def auth_enforcement(request, call_next):
    if not load_auth_enabled():
        return await call_next(request)

    method = request.method
    path = request.url.path

    if path in _DOCS_PATHS:
        if method != "GET":
            return await call_next(request)
        token = request.cookies.get(SESSION_COOKIE_NAME)
        user = await resolve_session(token or "")
        if user is None:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
        return await call_next(request)

    # Only guard the API surface; serve the SPA/static unconditionally.
    if not path.startswith("/api/"):
        return await call_next(request)

    # CORS preflight carries no credentials — never block it.
    if method == "OPTIONS":
        return await call_next(request)

    # Public endpoints.
    if path in _PUBLIC_API_PATHS:
        return await call_next(request)
    if method == "GET" and path == "/api/app/logo":
        return await call_next(request)
    # issue-local-016: the login screen (pre-authentication) must be able to
    # apply the instance-wide theme, so GET /api/app/theme needs the same
    # public carve-out as /api/app/logo above. While adding this, also fixed
    # a pre-existing gap: GET /api/app/title's docstring already claimed
    # "Public — no auth required" but had no matching carve-out here, so it
    # actually 401'd for unauthenticated visitors — the sidebar/tab-title
    # just silently fell back to the default, masking the bug. Both are
    # branding-ish settings shown pre-login, so fixed together.
    if method == "GET" and path in ("/api/app/theme", "/api/app/title"):
        return await call_next(request)

    # Require a valid credential for everything else — the session cookie,
    # or (issue-local-029) an API key when api_access_enabled.
    token = request.cookies.get(SESSION_COOKIE_NAME)
    user = await resolve_session(token or "")
    if user is None and load_api_access_enabled():
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            user = await resolve_api_key(auth_header[len("Bearer ") :])
    if user is None:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    # issue-local-029: an API key is authorized purely by its granted scopes
    # (backend.auth.api_scopes), never the role model below. Defense in
    # depth on top of every scope's own route patterns already being
    # confined to /api/threat-hunting/: hard-cap API-key requests to that
    # prefix here too, so a future scope-definition mistake can't
    # accidentally reach the admin/configuration surface.
    if user.get("is_api_key"):
        if not path.startswith("/api/threat-hunting/") or not scope_allows(
            user.get("scopes") or [], method, path
        ):
            return JSONResponse(status_code=403, content={"detail": "Insufficient privileges"})
        request.state.user = user
        return await call_next(request)

    # Forced password change (prompts-047): a user whose password is a generated
    # default (first-run bootstrap or --reset-admin-password) must change it
    # before doing anything else. Allow only the self-service paths needed to
    # complete that flow — read identity (/me), change the password, and log out.
    #
    # issue-local-013: SSO-authenticated accounts (idp is set) are exempt from
    # this gate.  The _upsert_sso_user function already clears the flag at SSO
    # login time (Layer 1), but this is a defense-in-depth guard that ensures
    # an SSO-linked user can never be trapped by the gate even if the flag
    # somehow persists (e.g. set by an admin after the account was linked).
    if user.get("must_change_password") and not user.get("idp") and path not in _SELF_PATHS:
        return JSONResponse(status_code=403, content={"detail": "Password change required"})

    # Role gate: admins may reach everything; non-admin roles are constrained
    # to their allowlist (threat-viewer = reads; threat-researcher = TH writes;
    # feed-sender = listener POST only).
    if user.get("role") != "admin" and not _role_allowed(user.get("role", ""), method, path):
        return JSONResponse(status_code=403, content={"detail": "Insufficient privileges"})

    request.state.user = user
    return await call_next(request)


# ── Interactive API docs (issue-local-030) ────────────────────────────────────
#
# FastAPI's stock /docs and /redoc hardcode a ROOT-ANCHORED schema URL
# ("/openapi.json"). That breaks whenever the app is served under a
# reverse-proxy alias whose location block strips the prefix before
# forwarding, e.g.
#
#     location /opentars/ { proxy_pass http://host:8003/; }   # note the slash
#
# The backend then only ever sees "/docs" and cannot learn its external mount
# point from the path, so the page it returns still points at "/openapi.json".
# The browser resolves that against the proxy ROOT — not the alias — and loads
# whatever *other* application is mounted there. Observed in the real
# deployment: the docs page rendered the parent app-manager's endpoints
# instead of this application's.
#
# Fix: reference the schema RELATIVELY, which is the same document-relative
# strategy the SPA already relies on (see _render_index_html's <base href="./">
# and the API client's relative "api" BASE). The browser is at
# <origin><alias>/docs, so "openapi.json" resolves to
# <origin><alias>/openapi.json and is routed straight back to this app. This
# is correct with OR without app_base_prefix configured, and needs no
# cooperation from the proxy (the X-Script-Name header it sends is
# deliberately NOT trusted — it is client-controllable, and relative URLs make
# it unnecessary).
#
# Note the docs route is exactly "/docs" ("/docs/" 404s), so the relative
# reference is unambiguous.
_OPENAPI_RELATIVE_URL = "openapi.json"


@app.get("/docs", include_in_schema=False)
async def _swagger_ui() -> HTMLResponse:
    return get_swagger_ui_html(
        openapi_url=_OPENAPI_RELATIVE_URL,
        title=f"{app.title} — Swagger UI",
    )


@app.get("/redoc", include_in_schema=False)
async def _redoc() -> HTMLResponse:
    return get_redoc_html(
        openapi_url=_OPENAPI_RELATIVE_URL,
        title=f"{app.title} — ReDoc",
    )


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/api/scheduler/reload")
async def reload_scheduler() -> dict:
    """Re-read sources.yaml + normalizer-config.yaml and reschedule all jobs."""
    scheduler_mod.reload()
    return {"status": "rescheduled"}


# ── Frontend serving ──────────────────────────────────────────────────────────
#
# In production the React SPA is built into frontend/dist/. We serve it with
# two pieces:
#   1. /assets/* (and any other static subdir) directly from disk via
#      StaticFiles — chunked JS/CSS files emitted by Vite live there.
#   2. A catch-all SPA route that returns index.html for any non-API,
#      non-static path, injecting <meta name="app-base-prefix"> so the
#      client knows the base prefix to use for routing and API calls.
#
# The injection-at-request-time approach lets the same built dist/ serve
# correctly under any prefix without a rebuild — only a backend restart.

_FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
_INDEX_FILE = _FRONTEND_DIST / "index.html"
_META_PREFIX_NAME = "app-base-prefix"


def _strip_tag(html: str, marker: str) -> str:
    """Remove a single tag from ``html`` whose opening starts with ``marker``.

    Safe for either self-closing (`<base ...>`) or attribute-only tags. Removes
    the first matching tag plus any immediately preceding newline+indent so the
    document does not accumulate blank lines on repeated renders.
    """
    if marker not in html:
        return html
    start = html.index(marker)
    end = html.index(">", start) + 1
    # Trim a preceding "\n    " (or "\n") inserted by a previous render.
    lead = start
    while lead > 0 and html[lead - 1] in " \t":
        lead -= 1
    if lead > 0 and html[lead - 1] == "\n":
        lead -= 1
    return html[:lead] + html[end:]


def _render_index_html(prefix: str) -> str:
    """Return index.html with link-generation tags injected per the contract.

    Contract (prompts-019):
      prefix == ""     → inject <base href="./">; OMIT the prefix <meta> tag
      prefix != ""     → inject <base href="<prefix>/">; inject the <meta> tag

    A <base href> makes document-relative URLs in the SPA (asset references,
    API fetches, router-emitted hrefs) resolve consistently regardless of
    which deep route the document is loaded at. Omitting the <meta> when the
    prefix is empty signals "the prefix machinery is disabled".

    Idempotent: any prior <base href=...> and prior <meta name="app-base-prefix"...>
    are stripped before injection, so repeated renders at different prefixes
    never accumulate stale tags.

    Security: ``prefix`` is validated upstream by ``_APP_PREFIX_RE`` in
    backend.config.loader to characters [A-Za-z0-9._\\-/] only, so direct
    interpolation into HTML attribute values is safe (no XSS sink). Relaxing
    that validator would require HTML-escaping here.
    """
    html = _INDEX_FILE.read_text(encoding="utf-8")

    # Strip any prior injections (order-insensitive).
    html = _strip_tag(html, '<meta name="' + _META_PREFIX_NAME + '"')
    html = _strip_tag(html, "<base href=")

    base_href = f"{prefix}/" if prefix else "./"
    base_tag = f'<base href="{base_href}">'
    meta_tag = f'<meta name="{_META_PREFIX_NAME}" content="{prefix}">' if prefix else ""

    # Compose the injection block: <base> first so it scopes any same-document
    # relative URLs that follow; <meta> second if applicable.
    injection = "\n    " + base_tag
    if meta_tag:
        injection += "\n    " + meta_tag

    head_idx = html.find("<head>")
    if head_idx >= 0:
        insert_at = head_idx + len("<head>")
        html = html[:insert_at] + injection + html[insert_at:]
    else:
        # No <head> — prepend.
        html = base_tag + meta_tag + html
    return html


if _FRONTEND_DIST.exists():
    # Serve hashed asset bundles (JS/CSS/fonts) directly from disk.
    _ASSETS_DIR = _FRONTEND_DIST / "assets"
    if _ASSETS_DIR.exists():
        app.mount("/assets", StaticFiles(directory=str(_ASSETS_DIR)), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_catch_all(full_path: str):
        """Serve index.html for any non-API, non-asset path (SPA fallback).

        FastAPI matches route paths internally without root_path, so
        full_path here never includes the configured prefix.
        """
        # Defensive: never swallow API/docs paths.
        if full_path.startswith(("api/", "docs", "openapi.json", "redoc")):
            raise HTTPException(status_code=404)
        # Direct non-HTML static file hit (e.g. /favicon.ico, /robots.txt)
        # under the dist root — serve verbatim with proper content type.
        if full_path:
            candidate = _FRONTEND_DIST / full_path
            if candidate.is_file() and candidate.suffix not in {".html", ""}:
                from fastapi.responses import FileResponse

                return FileResponse(str(candidate))
        # Otherwise: serve the SPA shell with the active prefix injected.
        prefix = load_app_base_prefix()
        return HTMLResponse(content=_render_index_html(prefix))

    logger.info("Serving frontend from %s", _FRONTEND_DIST)
else:

    @app.get("/")
    async def frontend_not_built() -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={
                "error": "Frontend not built.",
                "hint": "Run: ./opentars start",
            },
        )

    logger.warning(
        "Frontend dist not found at %s. "
        "Serving fallback error on GET /. Run './opentars start' to build.",
        _FRONTEND_DIST,
    )
