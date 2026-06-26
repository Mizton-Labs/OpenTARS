"""Tests for issue-local-013: SSO users bypass the forced password-reset gate.

Coverage:
  1. _upsert_sso_user (new user path) — must_change_password stays False.
  2. _upsert_sso_user (existing-user / matched path) — clears must_change_password.
  3. DB persistence of the cleared flag after SSO login.
  4. Middleware: idp-linked user with must_change_password=True is NOT blocked (403).
  5. Middleware: local (non-idp) user with must_change_password=True IS still blocked.
  6. _public_user exposes the idp field.
  7. /me response carries idp for an SSO-provisioned user.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────


def _run(coro):
    return asyncio.run(coro)


# ── 1 & 2. _upsert_sso_user: new + existing user paths ───────────────────────


@pytest.mark.asyncio
async def test_upsert_sso_user_new_user_has_no_must_change(tmp_path, monkeypatch):
    """Auto-provisioned SSO users must NOT have must_change_password set."""
    from backend.auth import db as auth_db
    from backend.auth.oidc import _upsert_sso_user

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()

    user = await _upsert_sso_user(
        username="alice@example.com",
        sub="sub-alice-001",
        idp="entra",
        role="threat-viewer",
        auto_provision=True,
    )

    assert user is not None, "User should be auto-provisioned"
    assert user.get("must_change_password") is False, (
        "New SSO users must NOT have must_change_password=True"
    )
    assert user.get("idp") == "entra"
    assert user.get("external_id") == "sub-alice-001"


@pytest.mark.asyncio
async def test_upsert_sso_user_existing_user_flag_cleared(tmp_path, monkeypatch):
    """When an existing flagged user logs in via SSO, must_change_password is cleared."""
    from backend.auth import db as auth_db
    from backend.auth import service
    from backend.auth.oidc import _upsert_sso_user

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()

    # Create a local user with must_change_password=True (e.g. bootstrap admin)
    await auth_db.create_user(
        "admin",
        service.hash_password("TempPass1!"),
        role="admin",
        must_change_password=True,
    )

    # Verify the flag is set before SSO login
    before = await auth_db.get_user_by_username("admin")
    assert before is not None
    assert bool(before.get("must_change_password")) is True, "Pre-condition: flag must be set"

    # SSO login matches by username (no external_id yet)
    user = await _upsert_sso_user(
        username="admin",
        sub="sub-admin-entra",
        idp="entra",
        role="admin",
        auto_provision=True,
    )

    assert user is not None
    assert user.get("must_change_password") is False, (
        "must_change_password must be cleared on SSO login for existing users"
    )


@pytest.mark.asyncio
async def test_upsert_sso_user_existing_user_flag_cleared_persisted(tmp_path, monkeypatch):
    """Clearing must_change_password is persisted in the DB, not just in the returned dict."""
    from backend.auth import db as auth_db
    from backend.auth import service
    from backend.auth.oidc import _upsert_sso_user

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()

    await auth_db.create_user(
        "bob",
        service.hash_password("TempPass1!"),
        role="threat-researcher",
        must_change_password=True,
    )

    await _upsert_sso_user(
        username="bob",
        sub="sub-bob-okta",
        idp="okta",
        role="threat-researcher",
        auto_provision=True,
    )

    # Re-read from DB to confirm persistence
    after = await auth_db.get_user_by_username("bob")
    assert after is not None
    assert bool(after.get("must_change_password")) is False, (
        "DB row must have must_change_password=0 after SSO login"
    )


@pytest.mark.asyncio
async def test_upsert_sso_user_matched_by_external_id_clears_flag(tmp_path, monkeypatch):
    """Match by (idp, sub) also clears the flag — covers returning SSO users."""
    from backend.auth import db as auth_db
    from backend.auth import service
    from backend.auth.oidc import _upsert_sso_user

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()

    # Create SSO user then somehow the flag gets re-set (edge case / admin action)
    uid = await auth_db.create_user(
        "carol@example.com",
        service.hash_password("unusable"),
        role="threat-viewer",
        must_change_password=True,  # simulate flag being set on an SSO account
        idp="google",
        external_id="sub-carol-google",
    )
    before = await auth_db.get_user_by_id(uid)
    assert bool(before.get("must_change_password")) is True

    # SSO login — matched by (idp, sub)
    user = await _upsert_sso_user(
        username="carol@example.com",
        sub="sub-carol-google",
        idp="google",
        role="threat-viewer",
        auto_provision=True,
    )

    assert user is not None
    assert user.get("must_change_password") is False


# ── 3. Middleware: idp-linked user with flag is NOT blocked ───────────────────


@pytest.fixture
def auth_env_sso_user(tmp_path, monkeypatch):
    """Enable auth, seed one SSO-linked admin with must_change_password=True."""
    from backend.auth import db as auth_db
    from backend.auth import service

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.setenv("MIZTON_THREATBOX_ENABLE_AUTH", "1")
    service._failures.clear()

    async def _seed():
        await auth_db.init_users_db()
        # SSO-linked admin: idp set, must_change_password=True
        # (simulates admin whose flag was set after being linked to SSO)
        await auth_db.create_user(
            "sso-admin",
            service.hash_password("unused-local-password"),
            role="admin",
            must_change_password=True,
            idp="entra",
            external_id="sub-sso-admin",
        )
        # Normal local admin for local-login tests
        await auth_db.create_user(
            "local-admin",
            service.hash_password("Adminpass1"),
            role="admin",
            must_change_password=True,
        )

    _run(_seed())
    yield
    service._failures.clear()


def _test_client_no_auth():
    """Return a TestClient that can present arbitrary session cookies."""
    from fastapi.testclient import TestClient

    from backend.main import app

    return TestClient(app, raise_server_exceptions=False)


def test_middleware_idp_user_not_blocked_by_must_change(auth_env_sso_user, tmp_path):
    """SSO-linked user (idp set) with must_change_password=True passes the middleware gate."""
    from fastapi.testclient import TestClient

    from backend.main import app

    c = TestClient(app)
    # Log in via local password — this is the linked-account local-login scenario.
    # The middleware should skip the gate because idp is set.
    r = c.post(
        "/api/auth/login", json={"username": "sso-admin", "password": "unused-local-password"}
    )
    assert r.status_code == 200

    # A protected endpoint must be reachable (NOT 403)
    me = c.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["must_change_password"] is True  # flag still set (not cleared here)
    assert me.json()["user"]["idp"] == "entra"

    # Full-access endpoint: NOT blocked
    users_r = c.get("/api/auth/users")
    assert users_r.status_code == 200, (
        f"SSO-linked user should not be blocked by must_change_password gate; got {users_r.status_code}"
    )


def test_middleware_local_user_still_blocked_by_must_change(auth_env_sso_user):
    """Local (non-idp) user with must_change_password=True IS still blocked (existing behavior)."""
    from fastapi.testclient import TestClient

    from backend.main import app

    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": "local-admin", "password": "Adminpass1"})
    assert r.status_code == 200

    # Must still be blocked on non-self endpoints
    users_r = c.get("/api/auth/users")
    assert users_r.status_code == 403
    assert users_r.json()["detail"] == "Password change required"


# ── 4. _public_user exposes idp ───────────────────────────────────────────────


def test_public_user_exposes_idp():
    """_public_user must include 'idp' in its output dict."""
    from backend.api.routes_auth import _public_user

    user_with_idp = {
        "id": 1,
        "username": "alice",
        "role": "threat-viewer",
        "enabled": True,
        "created_at": "2025-01-01T00:00:00+00:00",
        "must_change_password": False,
        "idp": "entra",
        "external_id": "sub-001",
    }
    result = _public_user(user_with_idp)
    assert "idp" in result, "_public_user must expose 'idp'"
    assert result["idp"] == "entra"


def test_public_user_idp_none_for_local_accounts():
    """_public_user exposes idp=None for accounts with no IdP."""
    from backend.api.routes_auth import _public_user

    local_user = {
        "id": 2,
        "username": "bob",
        "role": "admin",
        "enabled": True,
        "created_at": None,
        "must_change_password": True,
        "idp": None,
        "external_id": None,
    }
    result = _public_user(local_user)
    assert "idp" in result
    assert result["idp"] is None


# ── 5. /me response carries idp ───────────────────────────────────────────────


@pytest.fixture
def auth_env_with_sso_account(tmp_path, monkeypatch):
    """Enable auth and seed an SSO-provisioned user."""
    from backend.auth import db as auth_db
    from backend.auth import service

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.setenv("MIZTON_THREATBOX_ENABLE_AUTH", "1")
    service._failures.clear()

    async def _seed():
        await auth_db.init_users_db()
        await auth_db.create_user(
            "sso.user@example.com",
            service.hash_password("local-unusable"),
            role="threat-viewer",
            must_change_password=False,
            idp="google",
            external_id="sub-google-999",
        )

    _run(_seed())
    yield
    service._failures.clear()


def test_me_exposes_idp_for_sso_user(auth_env_with_sso_account):
    """/me response includes idp for SSO-provisioned accounts."""
    from fastapi.testclient import TestClient

    from backend.main import app

    c = TestClient(app)
    r = c.post(
        "/api/auth/login",
        json={"username": "sso.user@example.com", "password": "local-unusable"},
    )
    assert r.status_code == 200

    me = c.get("/api/auth/me")
    assert me.status_code == 200
    data = me.json()["user"]
    assert "idp" in data, "/me must return idp field"
    assert data["idp"] == "google"
    assert data["must_change_password"] is False


# ── 6. Structural: middleware source code includes idp guard ──────────────────


def test_middleware_source_includes_idp_guard():
    """The auth_enforcement middleware must check user.get('idp') before blocking."""
    import backend.main as main_module

    src = inspect.getsource(main_module)
    assert 'user.get("idp")' in src or "user.get('idp')" in src, (
        "Middleware must check idp to skip the must_change_password gate for SSO users"
    )
    # Confirm the guard is on the SAME condition line as must_change_password
    for line in src.splitlines():
        if "must_change_password" in line and "_SELF_PATHS" in line:
            assert "idp" in line, f"must_change_password gate line must include idp guard: {line!r}"
            break


# ── 7. _upsert_sso_user source: must_change_password cleared in matched branch ──


def test_upsert_sso_user_source_clears_flag():
    """_upsert_sso_user must include must_change_password=0 in the UPDATE statement."""
    from backend.auth.oidc import _upsert_sso_user

    src = inspect.getsource(_upsert_sso_user)
    assert "must_change_password" in src, "_upsert_sso_user must reference must_change_password"
    assert (
        "must_change_password = 0" in src
        or "must_change_password=0" in src
        or "must_change_password = False" in src
    ), "_upsert_sso_user must clear must_change_password in the UPDATE"
