"""Tests for the SPA catch-all + base-prefix injection.

Originally added in prompts-017; updated in prompts-019 for the (since
revised) no-prefix-relative contract, then again in the issue-local-035
follow-up once the relative "./" base was found to break any nested route
(e.g. /threat-hunting/<uuid>) on a hard refresh — see
backend.main._render_index_html's docstring for the full root-cause writeup.
Current contract:

    prefix == ""   →  inject <base href="/">; OMIT the app-base-prefix <meta>
    prefix != ""   →  inject <base href="<prefix>/"> AND the <meta> tag
"""

from __future__ import annotations

import pytest
import yaml
from fastapi.testclient import TestClient

from backend.config import loader


@pytest.fixture
def client_with_prefix(tmp_path, monkeypatch):
    """TestClient bound to a tmp application.yaml so we can set the prefix."""
    fake = tmp_path / "application.yaml"
    fake.write_text(yaml.safe_dump({"app_base_prefix": "/feeds"}), encoding="utf-8")
    monkeypatch.setattr(loader, "APP_CONFIG_PATH", fake)
    # The catch-all reads load_app_base_prefix() per request, so we can use
    # the existing app without reloading the module.
    from backend.main import app

    return TestClient(app)


@pytest.fixture
def client_empty_prefix(tmp_path, monkeypatch):
    fake = tmp_path / "application.yaml"
    fake.write_text(yaml.safe_dump({"app_base_prefix": ""}), encoding="utf-8")
    monkeypatch.setattr(loader, "APP_CONFIG_PATH", fake)
    from backend.main import app

    return TestClient(app)


def _frontend_dist_present() -> bool:
    from backend.main import _FRONTEND_DIST

    return (_FRONTEND_DIST / "index.html").exists()


@pytest.mark.skipif(not _frontend_dist_present(), reason="frontend/dist not built")
def test_spa_index_has_meta_and_base_with_prefix(client_with_prefix):
    """Non-empty prefix → both <base href="/feeds/"> and the meta tag present."""
    resp = client_with_prefix.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    assert '<meta name="app-base-prefix" content="/feeds">' in body
    assert '<base href="/feeds/">' in body


@pytest.mark.skipif(not _frontend_dist_present(), reason="frontend/dist not built")
def test_spa_index_empty_prefix_omits_meta_and_uses_root_base(client_empty_prefix):
    """Empty prefix → <base href="/"> present, app-base-prefix <meta> ABSENT."""
    resp = client_empty_prefix.get("/")
    assert resp.status_code == 200
    body = resp.text
    assert '<base href="/">' in body
    # The contract is "no prefix machinery visible in the document".
    assert 'name="app-base-prefix"' not in body


@pytest.mark.skipif(not _frontend_dist_present(), reason="frontend/dist not built")
def test_spa_catch_all_serves_index_for_deep_link(client_empty_prefix):
    """A SPA deep-link path returns the index.html shell, not 404."""
    resp = client_empty_prefix.get("/viewer")
    assert resp.status_code == 200
    # In the empty-prefix case we expect the root-anchored <base href="/"> marker.
    assert '<base href="/">' in resp.text


@pytest.mark.skipif(not _frontend_dist_present(), reason="frontend/dist not built")
def test_spa_catch_all_serves_index_for_multi_segment_deep_link(client_empty_prefix):
    """issue-local-035 follow-up regression: a hard refresh on a NESTED SPA
    route (e.g. /threat-hunting/<uuid>, /threat-hunting/tracking) must still
    get the root-anchored <base href="/">, not the old relative "./" which
    resolved one directory too deep for any path more than one segment long
    and broke asset loading entirely."""
    for path in ("/threat-hunting/abc123", "/threat-hunting/tracking", "/threat-hunting/explorer"):
        resp = client_empty_prefix.get(path)
        assert resp.status_code == 200, path
        assert '<base href="/">' in resp.text, path
        assert '<base href="./">' not in resp.text, path


@pytest.mark.skipif(not _frontend_dist_present(), reason="frontend/dist not built")
def test_spa_catch_all_does_not_swallow_api_paths(client_empty_prefix):
    """API paths must still be routed normally even when catch-all exists."""
    resp = client_empty_prefix.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.skipif(not _frontend_dist_present(), reason="frontend/dist not built")
def test_spa_injection_is_idempotent_across_prefix_changes():
    """Re-rendering at different prefixes leaves exactly one <base>/<meta>.

    Also checks that switching from a non-empty prefix to an empty prefix
    correctly REMOVES the prior <meta> tag.
    """
    from backend.main import _render_index_html

    once = _render_index_html("/a")
    assert once.count("<base href=") == 1
    assert once.count('name="app-base-prefix"') == 1
    assert '<base href="/a/">' in once

    twice = _render_index_html("/b")
    assert twice.count("<base href=") == 1
    assert twice.count('name="app-base-prefix"') == 1
    assert '<base href="/b/">' in twice
    assert '<base href="/a/">' not in twice

    # Going back to empty must drop the meta tag entirely.
    thrice = _render_index_html("")
    assert thrice.count("<base href=") == 1
    assert '<base href="/">' in thrice
    assert 'name="app-base-prefix"' not in thrice


@pytest.mark.skipif(not _frontend_dist_present(), reason="frontend/dist not built")
def test_spa_index_empty_prefix_has_no_meta_after_repeated_renders():
    """Regression: idempotency must not silently re-introduce the meta tag."""
    from backend.main import _render_index_html

    for _ in range(3):
        out = _render_index_html("")
        assert '<base href="/">' in out
        assert 'name="app-base-prefix"' not in out


# ── API docs pages under a reverse-proxy alias (issue-local-030) ──────────────
#
# The deployment pattern that motivated these: nginx serves the app under an
# alias with `location /ALIAS/ { proxy_pass http://host:port/; }` — the
# TRAILING SLASH makes nginx strip `/ALIAS` before forwarding, so the backend
# only ever sees `/docs` and cannot learn its external mount point from the
# path. FastAPI's stock docs pages hardcode a ROOT-ANCHORED `/openapi.json`,
# which the browser then resolves against the proxy ROOT — landing on whatever
# other application is mounted there (in the real deployment, the parent app's
# schema was rendered instead of this app's).
#
# The fix: reference `openapi.json` relatively (no leading slash) so it
# always resolves inside the alias, with or without app_base_prefix set.
# Safe here specifically because /docs and /redoc are each served at one
# FIXED, single-segment path — unlike the SPA's own routes (which vary in
# depth and, per the issue-local-035 follow-up above, need an ABSOLUTE
# <base href> instead precisely because relative resolution isn't
# depth-safe), a relative reference from a fixed one-segment page has no
# depth ambiguity to get wrong.


def test_swagger_references_openapi_relatively(client_empty_prefix):
    """Swagger must NOT reference a root-anchored /openapi.json."""
    body = client_empty_prefix.get("/docs").text
    assert "url: 'openapi.json'" in body
    assert "'/openapi.json'" not in body


def test_redoc_references_openapi_relatively(client_empty_prefix):
    """ReDoc must NOT reference a root-anchored /openapi.json."""
    body = client_empty_prefix.get("/redoc").text
    assert 'spec-url="openapi.json"' in body
    assert '"/openapi.json"' not in body


def test_docs_pages_stay_relative_even_with_a_configured_prefix(client_with_prefix):
    """A configured app_base_prefix must not reintroduce a root-anchored URL.

    Relative resolution is correct in BOTH cases: the browser is at
    <origin><alias>/docs either way, so `openapi.json` resolves to
    <origin><alias>/openapi.json, which the proxy routes back to this app.
    """
    body = client_with_prefix.get("/docs").text
    assert "url: 'openapi.json'" in body
    assert "'/openapi.json'" not in body


def test_openapi_schema_route_still_served_and_is_this_app(client_empty_prefix):
    """The relative URL must still resolve to a real, correct schema route."""
    resp = client_empty_prefix.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    assert schema["info"]["title"] == "OpenTARS"
    # A route unique to this application, proving it isn't another app's schema.
    assert "/api/threat-hunting/packages" in schema["paths"]


# ── Vendored (offline-capable) API-docs assets (issue-local-030) ─────────────
#
# FastAPI's stock docs pages load Swagger UI / ReDoc from cdn.jsdelivr.net (and
# ReDoc additionally pulls Google Fonts). OpenTARS is a standalone, local
# platform routinely run on isolated or air-gapped networks, where those
# fetches fail and the page renders blank. The bundles are vendored under
# backend/static/api-docs and served at /docs-assets.

_VENDORED_ASSETS = [
    "swagger-ui-bundle.js",
    "swagger-ui.css",
    "redoc.standalone.js",
]


@pytest.mark.parametrize("name", _VENDORED_ASSETS)
def test_vendored_docs_assets_are_present_on_disk(name):
    from backend.main import _DOCS_ASSETS_DIR

    path = _DOCS_ASSETS_DIR / name
    assert path.is_file(), f"vendored asset missing: {path}"
    assert path.stat().st_size > 1024, f"vendored asset looks truncated: {path}"


@pytest.mark.parametrize("name", _VENDORED_ASSETS)
def test_vendored_docs_assets_are_served(client_empty_prefix, name):
    resp = client_empty_prefix.get(f"/docs-assets/{name}")
    assert resp.status_code == 200
    assert len(resp.content) > 1024


@pytest.mark.parametrize("page", ["/docs", "/redoc"])
def test_docs_pages_reference_no_external_hosts(client_empty_prefix, page):
    """The offline guarantee: nothing on these pages may be fetched remotely."""
    body = client_empty_prefix.get(page).text
    assert "http://" not in body
    assert "https://" not in body
    # The specific hosts FastAPI's defaults would have used.
    for host in ("cdn.jsdelivr.net", "fastapi.tiangolo.com", "fonts.googleapis.com"):
        assert host not in body


@pytest.mark.parametrize("page", ["/docs", "/redoc"])
def test_docs_asset_urls_are_relative_not_root_anchored(client_empty_prefix, page):
    """Root-anchored asset URLs would break under a proxy alias exactly like
    the schema URL did — they must stay document-relative too."""
    body = client_empty_prefix.get(page).text
    assert "docs-assets/" in body
    assert '"/docs-assets/' not in body
    assert "'/docs-assets/" not in body


# ── API-key-scoped schema variant (issue-local-030) ──────────────────────────
#
# The About page's API Swagger tab defaults to the subset an API key can
# actually call, with a toggle for the full application API. The subset is
# derived from backend.auth.api_scopes — the same source the auth middleware
# authorizes against — so the documentation cannot drift from enforcement.

_HTTP_METHODS = {"get", "put", "post", "delete", "patch"}


def _operations(schema: dict) -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, ops in schema["paths"].items()
        for method in ops
        if method.lower() in _HTTP_METHODS
    }


def test_api_key_schema_contains_exactly_the_scope_defined_routes(client_empty_prefix):
    """One operation per (method, pattern) declared across every scope.

    Guards both directions: a missed route would under-count, and an
    over-broad pattern would over-count.
    """
    from backend.auth.api_scopes import API_SCOPES

    declared = sum(len(scope.routes) for scope in API_SCOPES.values())
    schema = client_empty_prefix.get("/openapi-api-keys.json").json()
    assert len(_operations(schema)) == declared


def test_api_key_schema_is_confined_to_threat_hunting(client_empty_prefix):
    """The hard guarantee: no key may reach anything outside this prefix."""
    schema = client_empty_prefix.get("/openapi-api-keys.json").json()
    offenders = [p for _, p in _operations(schema) if not p.startswith("/api/threat-hunting/")]
    assert offenders == []


def test_api_key_schema_excludes_session_only_surfaces(client_empty_prefix):
    """Spot-check surfaces an API key can never reach, including the routes
    that manage API keys themselves."""
    schema = client_empty_prefix.get("/openapi-api-keys.json").json()
    paths = {p for _, p in _operations(schema)}
    for forbidden in (
        "/api/auth/users",
        "/api/auth/api-keys",
        "/api/llm/providers",
        "/api/threat-hunting/connectors",
    ):
        assert forbidden not in paths


def test_api_key_schema_is_a_strict_subset_of_the_full_schema(client_empty_prefix):
    full = _operations(client_empty_prefix.get("/openapi.json").json())
    subset = _operations(client_empty_prefix.get("/openapi-api-keys.json").json())
    assert subset < full


def test_filtering_does_not_mutate_the_cached_full_schema(client_empty_prefix):
    """app.openapi() memoises; filtering in place would truncate the real
    schema for every later caller."""
    before = len(_operations(client_empty_prefix.get("/openapi.json").json()))
    client_empty_prefix.get("/openapi-api-keys.json")
    after = len(_operations(client_empty_prefix.get("/openapi.json").json()))
    assert after == before


def test_swagger_defaults_to_full_schema_and_opts_in_to_the_subset(client_empty_prefix):
    assert "url: 'openapi.json'" in client_empty_prefix.get("/docs").text
    narrowed = client_empty_prefix.get("/docs?api_keys_only=1").text
    assert "url: 'openapi-api-keys.json'" in narrowed
    # Still offline and still relative, like the unfiltered page.
    assert "https://" not in narrowed
    assert "'/openapi-api-keys.json'" not in narrowed


def test_openapi_description_describes_opentars_not_the_former_product(client_empty_prefix):
    schema = client_empty_prefix.get("/openapi.json").json()
    description = schema["info"]["description"]
    assert "OpenTARS" in description
    assert "Threat Agentic Research System" in description
    # The stale pre-rebrand wording must not come back.
    assert "feed receiver, normaliser, and viewer" not in description
