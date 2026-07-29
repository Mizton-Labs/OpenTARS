"""Tests for /api/auth routes + global enforcement middleware (prompts-045)."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.auth import db as auth_db
from backend.auth import service
from backend.main import app


@pytest.fixture
def auth_env(tmp_path, monkeypatch):
    """Enable auth, isolate users.db, and seed one admin (admin/Adminpass1)."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.setenv("OPENTARS_ENABLE_AUTH", "1")
    service._failures.clear()

    async def _seed():
        await auth_db.init_users_db()
        await auth_db.create_user("admin", service.hash_password("Adminpass1"), role="admin")

    asyncio.run(_seed())
    yield
    service._failures.clear()


def _client() -> TestClient:
    return TestClient(app)


def _login(username: str, password: str) -> TestClient:
    c = _client()
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return c


# ── status / disabled mode ────────────────────────────────────────────────────


def test_status_reports_enabled(auth_env):
    r = _client().get("/api/auth/status")
    assert r.status_code == 200
    body = r.json()
    assert body["auth_enabled"] is True
    assert body["password_policy"] == {
        "min_length": 8,
        "required_classes": 3,
        "max_bytes": 72,
    }


def test_disabled_mode_is_open(tmp_path, monkeypatch):
    """With auth disabled, protected API is reachable and status is false."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.delenv("OPENTARS_ENABLE_AUTH", raising=False)
    monkeypatch.setattr("backend.config.loader.load_app_config", lambda: {"auth_enabled": False})
    c = _client()
    assert c.get("/api/auth/status").json()["auth_enabled"] is False
    # A protected endpoint is not gated when auth is off.
    assert c.get("/api/health").status_code == 200


# ── login ─────────────────────────────────────────────────────────────────────


def test_login_success_sets_cookie_and_me(auth_env):
    c = _login("admin", "Adminpass1")
    assert service.SESSION_COOKIE_NAME in c.cookies
    me = c.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["username"] == "admin"
    assert me.json()["user"]["role"] == "admin"
    assert "password_hash" not in me.json()["user"]


def test_login_wrong_password_generic_401(auth_env):
    r = _client().post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid username or password"


def test_login_unknown_user_generic_401(auth_env):
    r = _client().post("/api/auth/login", json={"username": "ghost", "password": "whatever"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid username or password"


def test_login_throttled_after_five_failures(auth_env):
    c = _client()
    for _ in range(5):
        c.post("/api/auth/login", json={"username": "admin", "password": "bad"})
    # 6th attempt, even with the CORRECT password, is throttled.
    r = c.post("/api/auth/login", json={"username": "admin", "password": "Adminpass1"})
    assert r.status_code == 401


# ── enforcement ───────────────────────────────────────────────────────────────


def test_unauthenticated_protected_returns_401(auth_env):
    r = _client().get("/api/auth/users")
    assert r.status_code == 401


def test_logout_revokes_session(auth_env):
    c = _login("admin", "Adminpass1")
    assert c.get("/api/auth/me").status_code == 200
    assert c.post("/api/auth/logout").status_code == 200
    # The destroyed session no longer authenticates (cookie may linger).
    c.cookies.clear()  # simulate the cleared cookie
    assert c.get("/api/auth/me").status_code == 401


# ── FastAPI's own docs/redoc/openapi.json (issue-local-030) ────────────────────
# These live OUTSIDE /api/ (auto-registered by FastAPI), so they are NOT
# covered by the generic "/api/" prefix check — they get their own explicit
# gate in the middleware, tested here rather than the generic 401 test above.


_DOCS_PATHS = ["/docs", "/redoc", "/openapi.json", "/openapi-api-keys.json"]


@pytest.mark.parametrize("path", _DOCS_PATHS)
def test_docs_paths_require_auth_when_enabled(auth_env, path):
    r = _client().get(path)
    assert r.status_code == 401


@pytest.mark.parametrize("path", _DOCS_PATHS)
def test_docs_paths_reachable_once_authenticated(auth_env, path):
    c = _login("admin", "Adminpass1")
    r = c.get(path)
    assert r.status_code == 200


def test_docs_paths_reachable_by_non_admin_role(auth_env):
    """Any authenticated role may view the docs, not just admin — matches the
    About page itself, which has no role restriction."""
    asyncio.run(
        auth_db.create_user("viewer1", service.hash_password("Viewerpass1"), role="threat-viewer")
    )
    c = _login("viewer1", "Viewerpass1")
    assert c.get("/docs").status_code == 200


def test_docs_paths_open_when_auth_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.delenv("OPENTARS_ENABLE_AUTH", raising=False)
    monkeypatch.setattr("backend.config.loader.load_app_config", lambda: {"auth_enabled": False})
    r = _client().get("/docs")
    assert r.status_code == 200


# ── self password change ──────────────────────────────────────────────────────


def test_change_own_password(auth_env):
    c = _login("admin", "Adminpass1")
    r = c.put(
        "/api/auth/password",
        json={"current_password": "Adminpass1", "new_password": "Adminpass2"},
    )
    assert r.status_code == 200
    # Old password no longer works; new one does.
    assert (
        _client()
        .post("/api/auth/login", json={"username": "admin", "password": "Adminpass1"})
        .status_code
        == 401
    )
    assert (
        _client()
        .post("/api/auth/login", json={"username": "admin", "password": "Adminpass2"})
        .status_code
        == 200
    )


def test_change_own_password_keeps_caller_evicts_others(auth_env):
    """Self-service change keeps the caller's session but logs out other devices."""
    caller = _login("admin", "Adminpass1")
    other = _login("admin", "Adminpass1")  # a second "device" for the same user
    assert other.get("/api/auth/me").status_code == 200

    r = caller.put(
        "/api/auth/password",
        json={"current_password": "Adminpass1", "new_password": "Adminpass2"},
    )
    assert r.status_code == 200
    # Caller stays logged in; the other session is revoked.
    assert caller.get("/api/auth/me").status_code == 200
    assert other.get("/api/auth/me").status_code == 401


def test_admin_reset_password_evicts_target_sessions(auth_env):
    """Admin reset of a user must invalidate that user's existing session."""
    admin = _login("admin", "Adminpass1")
    created = admin.post(
        "/api/auth/users",
        json={"username": "bob", "password": "Bobpass12", "role": "threat-viewer"},
    )
    assert created.status_code == 200
    uid = created.json()["id"]
    bob = _login("bob", "Bobpass12")
    assert bob.get("/api/auth/me").status_code == 200

    # issue-local-016: bodyless — the backend generates the new password.
    r = admin.put(f"/api/auth/users/{uid}/password")
    assert r.status_code == 200
    # Bob's old session is dead; the admin is unaffected.
    assert bob.get("/api/auth/me").status_code == 401
    assert admin.get("/api/auth/me").status_code == 200


def test_admin_reset_password_generates_random_password(auth_env):
    """issue-local-016: the response carries a freshly generated password (not
    admin-supplied), the target must change it on next login, and it works."""
    admin = _login("admin", "Adminpass1")
    uid = admin.post(
        "/api/auth/users",
        json={"username": "dave", "password": "Davepass12", "role": "threat-viewer"},
    ).json()["id"]

    r = admin.put(f"/api/auth/users/{uid}/password")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "password_reset"
    assert body["username"] == "dave"
    generated = body["generated_password"]
    assert isinstance(generated, str) and len(generated) >= 20  # token_urlsafe(18)

    # must_change_password is set on the target (visible via the admin's own
    # list_users view — GET /api/auth/users returns the raw DB projection).
    users = {u["username"]: u for u in admin.get("/api/auth/users").json()}
    assert users["dave"]["must_change_password"] is True

    # The generated password actually works, and a second reset differs.
    login = _client().post("/api/auth/login", json={"username": "dave", "password": generated})
    assert login.status_code == 200

    r2 = admin.put(f"/api/auth/users/{uid}/password")
    assert r2.status_code == 200
    assert r2.json()["generated_password"] != generated


def test_admin_reset_password_requires_admin(auth_env):
    admin = _login("admin", "Adminpass1")
    uid = admin.post(
        "/api/auth/users",
        json={"username": "eve", "password": "Evepass123", "role": "threat-viewer"},
    ).json()["id"]
    viewer = _login("eve", "Evepass123")
    r = viewer.put(f"/api/auth/users/{uid}/password")
    assert r.status_code == 403


def test_change_own_password_wrong_current(auth_env):
    c = _login("admin", "Adminpass1")
    r = c.put(
        "/api/auth/password",
        json={"current_password": "WRONG", "new_password": "Adminpass2"},
    )
    assert r.status_code == 400


def test_change_own_password_too_short(auth_env):
    c = _login("admin", "Adminpass1")
    r = c.put(
        "/api/auth/password",
        json={"current_password": "Adminpass1", "new_password": "short"},
    )
    assert r.status_code == 400


def test_change_own_password_rejects_insufficient_classes(auth_env):
    """A long password with only 2 character classes is rejected (needs 3)."""
    c = _login("admin", "Adminpass1")
    r = c.put(
        "/api/auth/password",
        json={"current_password": "Adminpass1", "new_password": "lowercaseonly1"},
    )
    assert r.status_code == 400
    assert "lowercase, uppercase, number, symbol" in r.json()["detail"]


def test_change_own_password_rejects_reuse_of_current(auth_env):
    """New password identical to current is rejected on self-change."""
    c = _login("admin", "Adminpass1")
    r = c.put(
        "/api/auth/password",
        json={"current_password": "Adminpass1", "new_password": "Adminpass1"},
    )
    assert r.status_code == 400
    assert "differ" in r.json()["detail"].lower()


# ── self theme override (issue-local-016) ─────────────────────────────────────


def test_set_own_theme_round_trip(auth_env):
    c = _login("admin", "Adminpass1")
    r = c.put("/api/auth/me/theme", json={"theme": "energy"})
    assert r.status_code == 200
    assert r.json()["theme"] == "energy"
    assert c.get("/api/auth/me").json()["user"]["theme"] == "energy"


def test_set_own_theme_accepts_light(auth_env):
    """issue-local-017: 'light' is a valid third personal theme override."""
    c = _login("admin", "Adminpass1")
    r = c.put("/api/auth/me/theme", json={"theme": "light"})
    assert r.status_code == 200
    assert r.json()["theme"] == "light"
    assert c.get("/api/auth/me").json()["user"]["theme"] == "light"


def test_set_own_theme_accepts_ocean(auth_env):
    """issue-local-018 follow-up: 'ocean' is a valid fourth personal theme override."""
    c = _login("admin", "Adminpass1")
    r = c.put("/api/auth/me/theme", json={"theme": "ocean"})
    assert r.status_code == 200
    assert r.json()["theme"] == "ocean"
    assert c.get("/api/auth/me").json()["user"]["theme"] == "ocean"


def test_set_own_theme_null_clears_override(auth_env):
    c = _login("admin", "Adminpass1")
    c.put("/api/auth/me/theme", json={"theme": "energy"})
    r = c.put("/api/auth/me/theme", json={"theme": None})
    assert r.status_code == 200
    assert r.json()["theme"] is None
    assert c.get("/api/auth/me").json()["user"]["theme"] is None


def test_set_own_theme_rejects_invalid_value(auth_env):
    c = _login("admin", "Adminpass1")
    r = c.put("/api/auth/me/theme", json={"theme": "not-a-real-theme"})
    assert r.status_code == 400


def test_set_own_theme_reachable_by_non_admin_role(auth_env):
    """Regression for the _SELF_PATHS entry: without it, a non-admin role
    would be blocked by the middleware's role allowlist before ever reaching
    this route (admins bypass role-gating entirely, so this must be tested
    with a non-admin caller to actually exercise the fix)."""
    admin = _login("admin", "Adminpass1")
    uid = admin.post(
        "/api/auth/users",
        json={"username": "frank", "password": "Frankpass1", "role": "threat-viewer"},
    ).json()["id"]
    assert uid > 0
    viewer = _login("frank", "Frankpass1")
    r = viewer.put("/api/auth/me/theme", json={"theme": "energy"})
    assert r.status_code == 200
    assert r.json()["theme"] == "energy"


# ── forced password change (prompts-047) ──────────────────────────────────────


@pytest.fixture
def auth_env_must_change(tmp_path, monkeypatch):
    """Enable auth and seed one admin whose password must be changed."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.setenv("OPENTARS_ENABLE_AUTH", "1")
    service._failures.clear()

    async def _seed():
        await auth_db.init_users_db()
        await auth_db.create_user(
            "admin",
            service.hash_password("Adminpass1"),
            role="admin",
            must_change_password=True,
        )

    asyncio.run(_seed())
    yield
    service._failures.clear()


def test_login_and_me_expose_must_change_flag(auth_env_must_change):
    c = _login("admin", "Adminpass1")
    me = c.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["must_change_password"] is True


def test_must_change_blocks_other_endpoints(auth_env_must_change):
    c = _login("admin", "Adminpass1")
    # A normal protected endpoint is blocked with 403 while the flag is set.
    r = c.get("/api/auth/users")
    assert r.status_code == 403
    assert r.json()["detail"] == "Password change required"


def test_must_change_allows_self_paths(auth_env_must_change):
    c = _login("admin", "Adminpass1")
    # /me and /password must remain reachable to complete the flow.
    assert c.get("/api/auth/me").status_code == 200


def test_must_change_cleared_after_change_restores_access(auth_env_must_change):
    c = _login("admin", "Adminpass1")
    assert c.get("/api/auth/users").status_code == 403

    r = c.put(
        "/api/auth/password",
        json={"current_password": "Adminpass1", "new_password": "Adminpass2"},
    )
    assert r.status_code == 200

    # Flag cleared: /me reflects it and full access is restored, no re-login.
    assert c.get("/api/auth/me").json()["user"]["must_change_password"] is False
    assert c.get("/api/auth/users").status_code == 200


def test_admin_created_user_must_change_password(auth_env):
    """An admin-created user is forced to change their password on first login.

    Mirrors the admin-reset behavior (issue-local-016) — an admin-supplied
    password is, from the new user's perspective, the same trust situation
    as a reset, so the same forced-change protection applies.
    """
    admin = _login("admin", "Adminpass1")
    created = admin.post(
        "/api/auth/users",
        json={"username": "bob", "password": "Bobpass12", "role": "threat-viewer"},
    )
    assert created.status_code == 200
    assert created.json()["must_change_password"] is True
    bob = _login("bob", "Bobpass12")
    assert bob.get("/api/auth/me").json()["user"]["must_change_password"] is True
    # Gated by the forced-change 403 until the password is changed.
    assert bob.get("/api/viewer/sources").status_code == 403


def test_admin_created_user_can_change_password_and_regain_access(auth_env):
    """The create -> forced-change -> cleared-access path works end to end,
    mirroring test_must_change_cleared_after_change_restores_access but
    starting from a freshly-created (not admin-reset) user."""
    admin = _login("admin", "Adminpass1")
    admin.post(
        "/api/auth/users",
        json={"username": "carol", "password": "Carolpass1", "role": "threat-viewer"},
    )
    carol = _login("carol", "Carolpass1")
    assert carol.get("/api/viewer/sources").status_code == 403

    r = carol.put(
        "/api/auth/password",
        json={"current_password": "Carolpass1", "new_password": "Newcarolpass2"},
    )
    assert r.status_code == 200
    assert carol.get("/api/auth/me").json()["user"]["must_change_password"] is False
    assert carol.get("/api/viewer/sources").status_code != 403


def test_create_user_rejects_insufficient_classes(auth_env):
    """Admin-created passwords must satisfy the complexity policy."""
    c = _login("admin", "Adminpass1")
    r = c.post(
        "/api/auth/users",
        json={"username": "weakuser", "password": "alllowercase1", "role": "threat-viewer"},
    )
    assert r.status_code == 400


def test_admin_reset_password_no_body_required(auth_env):
    """issue-local-016: the endpoint takes no request body at all — the admin
    no longer supplies a password, so there's nothing left to validate here
    (unlike the old reuse-constraint test this replaces, which tested an
    admin-supplied value that no longer exists)."""
    c = _login("admin", "Adminpass1")
    r = c.post(
        "/api/auth/users",
        json={"username": "carol", "password": "Carolpass1", "role": "threat-viewer"},
    )
    uid = r.json()["id"]
    r2 = c.put(f"/api/auth/users/{uid}/password")
    assert r2.status_code == 200, r2.text
    assert r2.json()["generated_password"] != "Carolpass1"


# ── admin user management ─────────────────────────────────────────────────────


def test_admin_user_crud(auth_env):
    c = _login("admin", "Adminpass1")
    # Create
    r = c.post(
        "/api/auth/users",
        json={"username": "viewer1", "password": "Viewerpass1", "role": "threat-viewer"},
    )
    assert r.status_code == 200, r.text
    uid = r.json()["id"]
    assert r.json()["role"] == "threat-viewer"
    # List
    users = c.get("/api/auth/users").json()
    assert {u["username"] for u in users} == {"admin", "viewer1"}
    assert all("password_hash" not in u for u in users)
    # Promote
    assert c.put(f"/api/auth/users/{uid}/role", json={"role": "admin"}).status_code == 200
    assert c.put(f"/api/auth/users/{uid}/role", json={"role": "threat-viewer"}).status_code == 200
    # Disable
    assert c.put(f"/api/auth/users/{uid}/enabled", json={"enabled": False}).status_code == 200
    # Disabled user cannot log in.
    assert (
        _client()
        .post("/api/auth/login", json={"username": "viewer1", "password": "Viewerpass1"})
        .status_code
        == 401
    )
    # Re-enable + admin reset password (issue-local-016: bodyless, generated)
    c.put(f"/api/auth/users/{uid}/enabled", json={"enabled": True})
    reset = c.put(f"/api/auth/users/{uid}/password")
    assert reset.status_code == 200
    assert (
        _client()
        .post(
            "/api/auth/login",
            json={"username": "viewer1", "password": reset.json()["generated_password"]},
        )
        .status_code
        == 200
    )
    # Delete
    assert c.delete(f"/api/auth/users/{uid}").status_code == 200
    assert {u["username"] for u in c.get("/api/auth/users").json()} == {"admin"}


def test_create_user_duplicate_409(auth_env):
    c = _login("admin", "Adminpass1")
    r = c.post(
        "/api/auth/users",
        json={"username": "admin", "password": "Anotherpass1", "role": "threat-viewer"},
    )
    assert r.status_code == 409


@pytest.mark.parametrize("bad", ["has space", "x" * 41, "", "bad/slash"])
def test_create_user_bad_username(auth_env, bad):
    c = _login("admin", "Adminpass1")
    r = c.post(
        "/api/auth/users",
        json={"username": bad, "password": "Validpass1", "role": "threat-viewer"},
    )
    assert r.status_code == 400


def test_create_user_bad_role(auth_env):
    c = _login("admin", "Adminpass1")
    r = c.post(
        "/api/auth/users",
        json={"username": "ok1", "password": "Validpass1", "role": "root"},
    )
    assert r.status_code == 400


# ── last-admin / self guards ──────────────────────────────────────────────────


def test_cannot_demote_last_admin(auth_env):
    c = _login("admin", "Adminpass1")
    me_id = c.get("/api/auth/me").json()["user"]["id"]
    # Self-role change blocked first.
    assert c.put(f"/api/auth/users/{me_id}/role", json={"role": "threat-viewer"}).status_code == 400


def test_cannot_disable_or_delete_self(auth_env):
    c = _login("admin", "Adminpass1")
    me_id = c.get("/api/auth/me").json()["user"]["id"]
    assert c.put(f"/api/auth/users/{me_id}/enabled", json={"enabled": False}).status_code == 400
    assert c.delete(f"/api/auth/users/{me_id}").status_code == 400


def test_cannot_demote_last_admin_via_other(auth_env):
    """Two admins: the second may demote the first; the lone remaining admin
    cannot then be demoted."""
    c = _login("admin", "Adminpass1")
    c.post(
        "/api/auth/users",
        json={"username": "admin2", "password": "Admin2pass1", "role": "admin"},
    )
    admin1_id = c.get("/api/auth/me").json()["user"]["id"]
    c2 = _login("admin2", "Admin2pass1")
    # issue-local-016: admin-created accounts are must_change_password by
    # default — clear it so admin2 can exercise non-self endpoints below.
    c2.put(
        "/api/auth/password",
        json={"current_password": "Admin2pass1", "new_password": "Admin2pass2"},
    )
    admin2_id = c2.get("/api/auth/me").json()["user"]["id"]
    # admin2 demotes admin1 → allowed (admin2 remains an admin).
    assert (
        c2.put(f"/api/auth/users/{admin1_id}/role", json={"role": "threat-viewer"}).status_code
        == 200
    )
    # admin2 is now the last admin; another admin cannot exist to demote them,
    # and self-demotion is blocked.
    assert (
        c2.put(f"/api/auth/users/{admin2_id}/role", json={"role": "threat-viewer"}).status_code
        == 400
    )


# ── role gate (normal = Viewer-only) ──────────────────────────────────────────


def test_normal_role_blocked_from_admin_endpoints(auth_env):
    c = _login("admin", "Adminpass1")
    c.post(
        "/api/auth/users",
        json={"username": "viewer1", "password": "Viewerpass1", "role": "threat-viewer"},
    )
    nc = _login("viewer1", "Viewerpass1")
    # Self endpoints allowed.
    assert nc.get("/api/auth/me").status_code == 200
    # issue-local-016: clear the forced-password-change gate first so the
    # assertions below actually exercise the ROLE gate, not the must-change
    # gate (both return 403, which would otherwise mask which one fired).
    nc.put(
        "/api/auth/password",
        json={"current_password": "Viewerpass1", "new_password": "Viewerpass2"},
    )
    # Admin user list blocked.
    assert nc.get("/api/auth/users").status_code == 403
    # Mutating endpoint blocked.
    assert nc.post("/api/normalizer/run").status_code == 403


def test_normal_role_allowed_viewer_reads(auth_env):
    c = _login("admin", "Adminpass1")
    c.post(
        "/api/auth/users",
        json={"username": "viewer1", "password": "Viewerpass1", "role": "threat-viewer"},
    )
    nc = _login("viewer1", "Viewerpass1")
    # issue-local-016: clear the forced-password-change gate so this test
    # exercises the ROLE allowlist, not the must-change gate.
    nc.put(
        "/api/auth/password",
        json={"current_password": "Viewerpass1", "new_password": "Viewerpass2"},
    )
    # A whitelisted Viewer read must pass the gate (not 401/403).
    r = nc.get("/api/viewer/summary")
    assert r.status_code not in (401, 403)


def test_admin_role_reaches_everything(auth_env):
    c = _login("admin", "Adminpass1")
    assert c.get("/api/auth/users").status_code == 200


def test_researcher_role_reaches_llm_providers_and_config(auth_env):
    """issue-local-026: /api/llm/ was missing from _RESEARCHER_GET_PREFIXES,
    so the Threat Hunting model-selector dropdown's provider-list fetch
    403'd for anyone who wasn't admin, even though threat-researcher is
    exactly the role meant to see and use it."""
    c = _login("admin", "Adminpass1")
    c.post(
        "/api/auth/users",
        json={
            "username": "researcher1",
            "password": "Researchpass1",
            "role": "threat-researcher",
        },
    )
    nc = _login("researcher1", "Researchpass1")
    nc.put(
        "/api/auth/password",
        json={"current_password": "Researchpass1", "new_password": "Researchpass2"},
    )
    assert nc.get("/api/llm/providers").status_code not in (401, 403)
    assert nc.get("/api/llm/config").status_code not in (401, 403)


def test_viewer_role_still_blocked_from_llm_providers(auth_env):
    """The researcher-only /api/llm/ grant must not leak to threat-viewer —
    _RESEARCHER_GET_PREFIXES adds to _VIEWER_GET_PREFIXES, it must not widen
    it in place (that would be a shared-tuple aliasing bug)."""
    c = _login("admin", "Adminpass1")
    c.post(
        "/api/auth/users",
        json={"username": "viewer2", "password": "Viewerpass1", "role": "threat-viewer"},
    )
    nc = _login("viewer2", "Viewerpass1")
    nc.put(
        "/api/auth/password",
        json={"current_password": "Viewerpass1", "new_password": "Viewerpass2"},
    )
    assert nc.get("/api/llm/providers").status_code == 403


# ── Throttle key derivation (prompts-045 audit, MAJOR #2) ──────────────────────


def test_client_ip_uses_socket_peer_not_forwarded_header():
    """X-Forwarded-For is attacker-controlled and must NOT influence the key."""
    from backend.api.routes_auth import _client_ip

    class _FakeClient:
        host = "10.0.0.5"

    class _FakeReq:
        client = _FakeClient()
        headers = {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"}

    assert _client_ip(_FakeReq()) == "10.0.0.5"


def test_client_ip_handles_missing_client():
    from backend.api.routes_auth import _client_ip

    class _FakeReq:
        client = None
        headers: dict = {}

    assert _client_ip(_FakeReq()) == "unknown"


# ── Defence-in-depth admin gate (prompts-045 audit MINOR) ─────────────────────


@pytest.mark.asyncio
async def test_require_admin_when_enabled_noop_when_auth_disabled(monkeypatch):
    """With auth disabled the gate is a no-op (app is fully open)."""
    from backend.auth import dependencies as deps

    monkeypatch.setattr(deps, "load_auth_enabled", lambda: False)

    class _Req:
        cookies: dict = {}

    assert await deps.require_admin_when_enabled(_Req()) is None


@pytest.mark.asyncio
async def test_require_admin_when_enabled_requires_admin(monkeypatch):
    """With auth enabled and no session, the gate raises 401."""
    from fastapi import HTTPException

    from backend.auth import dependencies as deps

    monkeypatch.setattr(deps, "load_auth_enabled", lambda: True)

    class _Req:
        cookies: dict = {}

    with pytest.raises(HTTPException) as exc:
        await deps.require_admin_when_enabled(_Req())
    assert exc.value.status_code == 401


# ── Global search / SmartSearch route gating (issue-local-031) ────────────────


def test_search_requires_authentication(auth_env):
    assert _client().get("/api/search?q=hunt").status_code == 401
    assert _client().get("/api/search/status").status_code == 401
    assert _client().post("/api/search/smart", json={"question": "hi"}).status_code == 401


def test_search_is_reachable_by_every_reading_role(auth_env):
    """Viewers and researchers may search; results are scoped inside the
    service, so opening the route does not widen what they can see."""
    for username, role in (("viewer1", "threat-viewer"), ("res1", "threat-researcher")):
        asyncio.run(auth_db.create_user(username, service.hash_password("Passw0rd1"), role=role))
        c = _login(username, "Passw0rd1")
        assert c.get("/api/search?q=hunt").status_code == 200
        assert c.get("/api/search/status").status_code == 200


def test_search_is_closed_to_the_push_only_role(auth_env):
    """feed-sender is a machine account with no read access anywhere."""
    asyncio.run(
        auth_db.create_user("pusher", service.hash_password("Passw0rd1"), role="feed-sender")
    )
    c = _login("pusher", "Passw0rd1")
    assert c.get("/api/search?q=hunt").status_code == 403
    assert c.post("/api/search/smart", json={"question": "hi"}).status_code == 403


def test_search_results_are_scoped_to_the_callers_role(auth_env):
    """The same query must not reveal admin-only destinations to a viewer."""
    asyncio.run(
        auth_db.create_user("viewer2", service.hash_password("Passw0rd1"), role="threat-viewer")
    )

    def sections_for(client):
        body = client.get("/api/search?q=providers").json()
        return {s["section"] for s in body["sections"]}

    assert "Settings" in sections_for(_login("admin", "Adminpass1"))
    assert "Settings" not in sections_for(_login("viewer2", "Passw0rd1"))
