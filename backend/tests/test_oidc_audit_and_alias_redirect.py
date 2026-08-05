"""Tests for two SSO bugfixes:

  1. SSO sign-ins (success AND failure) were invisible in the audit log —
     only the local-password /login route recorded anything.
  2. The OIDC callback's post-login/error redirects were plain root-relative
     paths (e.g. "Location: /viewer"), which the browser resolves against
     the domain ROOT — behind a reverse-proxy alias (callback_base_url,
     issue-local-036) that lands in a DIFFERENT application, not this one.

Coverage:
  - oidc.build_redirect_path: unit tests (no override / override / trailing
    slash normalisation).
  - /api/auth/oidc/callback (routes_auth.oidc_callback): end-to-end via
    TestClient with backend.auth.oidc.handle_callback monkeypatched (no real
    IdP), covering the success path and every failure branch — asserting
    both the redirect Location and the resulting audit_events row.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.audit import db as audit_db
from backend.auth import db as auth_db
from backend.auth import oidc_config
from backend.main import app

# ── build_redirect_path ───────────────────────────────────────────────────────


def test_build_redirect_path_no_override_unchanged():
    from backend.auth.oidc import build_redirect_path

    assert build_redirect_path("/viewer", "") == "/viewer"


def test_build_redirect_path_with_override_prepends_alias():
    from backend.auth.oidc import build_redirect_path

    assert (
        build_redirect_path("/viewer", "https://host.example.com/tars")
        == "/tars/viewer"
    )


def test_build_redirect_path_override_trailing_slash_normalised():
    from backend.auth.oidc import build_redirect_path

    assert build_redirect_path("/login?sso_error=auth_failed", "https://host/tars/") == (
        "/tars/login?sso_error=auth_failed"
    )


def test_build_redirect_path_override_without_path_is_noop_prefix():
    from backend.auth.oidc import build_redirect_path

    assert build_redirect_path("/viewer", "https://host.example.com") == "/viewer"


# ── /api/auth/oidc/callback: route-level ──────────────────────────────────────


@pytest.fixture
def sso_env(tmp_path, monkeypatch):
    """Isolated users.db + audit.db, SSO config with a reverse-proxy alias."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.setattr(audit_db, "_DB_PATH", tmp_path / "audit.db")
    monkeypatch.setattr(oidc_config, "_SSO_CONFIG_PATH", tmp_path / "sso.yaml")
    (tmp_path / "sso.yaml").write_text(
        "enabled: true\n"
        "client_id: cid\n"
        "client_secret: secret\n"
        "issuer: https://idp.example.com\n"
        "callback_base_url: https://host.example.com/tars\n",
        encoding="utf-8",
    )

    async def _seed():
        await auth_db.init_users_db()
        await audit_db.init_audit_db()

    asyncio.run(_seed())
    yield


def _client() -> TestClient:
    return TestClient(app, follow_redirects=False)


def _last_audit_event() -> dict:
    # category="user" excludes the unrelated logging→audit bridge
    # (backend.audit.log_bridge.AuditLogHandler, "application"/"system"
    # categories) which also fires on this route's own logger.warning() call
    # and would otherwise race the explicit record_event() calls under test.
    async def _fetch():
        events, _total = await audit_db.list_events(category="user", limit=1)
        return events[0]

    return asyncio.run(_fetch())


def test_oidc_callback_success_redirects_inside_alias_and_records_audit(sso_env, monkeypatch):
    async def fake_handle_callback(*, code, state, request_base_url):
        user = {"id": 1, "username": "alice@acme.com", "role": "threat-viewer", "idp": "entra"}
        return user, "raw-session-token", "/viewer"

    monkeypatch.setattr("backend.auth.oidc.handle_callback", fake_handle_callback)

    r = _client().get("/api/auth/oidc/callback?code=abc&state=xyz")

    assert r.status_code == 302
    assert r.headers["location"] == "/tars/viewer"

    event = _last_audit_event()
    assert event["category"] == "user"
    assert event["action"] == "Signed in"
    assert event["username"] == "alice@acme.com"
    assert "SSO" in event["summary"]


def test_oidc_callback_idp_error_redirects_inside_alias_and_records_audit(sso_env):
    r = _client().get("/api/auth/oidc/callback?error=access_denied&error_description=nope")

    assert r.status_code == 302
    assert r.headers["location"] == "/tars/login?sso_error=access_denied"

    event = _last_audit_event()
    assert event["action"] == "Failed sign-in attempt"
    assert "access_denied" in event["summary"]


def test_oidc_callback_missing_params_redirects_inside_alias_and_records_audit(sso_env):
    r = _client().get("/api/auth/oidc/callback")

    assert r.status_code == 302
    assert r.headers["location"] == "/tars/login?sso_error=missing_params"

    event = _last_audit_event()
    assert event["action"] == "Failed sign-in attempt"


def test_oidc_callback_auth_rejected_redirects_inside_alias_and_records_audit(sso_env, monkeypatch):
    async def fake_handle_callback(*, code, state, request_base_url):
        raise ValueError("Invalid or expired OIDC state parameter")

    monkeypatch.setattr("backend.auth.oidc.handle_callback", fake_handle_callback)

    r = _client().get("/api/auth/oidc/callback?code=abc&state=xyz")

    assert r.status_code == 302
    assert r.headers["location"] == "/tars/login?sso_error=auth_failed"

    event = _last_audit_event()
    assert event["action"] == "Failed sign-in attempt"
    assert "state parameter" in event["summary"]


def test_oidc_callback_server_error_redirects_inside_alias_and_records_audit(sso_env, monkeypatch):
    async def fake_handle_callback(*, code, state, request_base_url):
        raise RuntimeError("token endpoint unreachable")

    monkeypatch.setattr("backend.auth.oidc.handle_callback", fake_handle_callback)

    r = _client().get("/api/auth/oidc/callback?code=abc&state=xyz")

    assert r.status_code == 302
    assert r.headers["location"] == "/tars/login?sso_error=server_error"

    event = _last_audit_event()
    assert event["action"] == "Failed sign-in attempt"


def test_oidc_callback_success_without_alias_uses_bare_path(tmp_path, monkeypatch):
    """No callback_base_url configured — unchanged root-relative behavior."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.setattr(audit_db, "_DB_PATH", tmp_path / "audit.db")
    monkeypatch.setattr(oidc_config, "_SSO_CONFIG_PATH", tmp_path / "sso.yaml")
    (tmp_path / "sso.yaml").write_text(
        "enabled: true\nclient_id: cid\nclient_secret: secret\nissuer: https://idp.example.com\n",
        encoding="utf-8",
    )

    async def _seed():
        await auth_db.init_users_db()
        await audit_db.init_audit_db()

    asyncio.run(_seed())

    async def fake_handle_callback(*, code, state, request_base_url):
        user = {"id": 1, "username": "bob", "role": "threat-viewer", "idp": "entra"}
        return user, "raw-session-token", "/viewer"

    monkeypatch.setattr("backend.auth.oidc.handle_callback", fake_handle_callback)

    r = _client().get("/api/auth/oidc/callback?code=abc&state=xyz")

    assert r.status_code == 302
    assert r.headers["location"] == "/viewer"
