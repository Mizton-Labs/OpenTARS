"""Tests for issue-local-038's first-login onboarding wizard gate:

  - users.onboarded column + migration (grandfathers existing rows True,
    new accounts default False via create_user()).
  - PUT /api/auth/me/onboarding (self, any role) — marks the caller done.
  - PUT /api/auth/users/{id}/onboarding (admin-only) — resets a target
    user's flag, e.g. to force the wizard again.
  - _public_user exposes "onboarded".
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.auth import db as auth_db
from backend.auth import service
from backend.main import app


def _run(coro):
    return asyncio.run(coro)


# ── db.py: schema + create_user default + set_onboarded ──────────────────────


@pytest.mark.asyncio
async def test_schema_v8_fresh_db_has_onboarded_column(tmp_path: Path) -> None:
    db_path = tmp_path / "users.db"
    with patch.object(auth_db, "_USERS_DB_PATH", db_path):
        await auth_db.init_users_db()

    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    version = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()[0]
    conn.close()

    assert "onboarded" in cols
    assert version == auth_db._USERS_SCHEMA_VERSION


@pytest.mark.asyncio
async def test_v7_migrates_to_v8_and_grandfathers_existing_rows(tmp_path: Path) -> None:
    """A pre-existing row (created before this column existed) must come out
    onboarded=True after migration — never retroactively interrupted."""
    db_path = tmp_path / "users.db"

    conn = sqlite3.connect(db_path)
    conn.execute(
        """CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'threat-viewer',
            enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            idp TEXT, external_id TEXT, theme TEXT, org_id INTEGER
        )"""
    )
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at) "
        "VALUES ('preexisting', 'x', '2026-01-01T00:00:00+00:00')"
    )
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO schema_version (version) VALUES (7)")
    conn.commit()
    conn.close()

    with patch.object(auth_db, "_USERS_DB_PATH", db_path):
        await auth_db.init_users_db()
        user = await auth_db.get_user_by_username("preexisting")

    assert user["onboarded"] is True


@pytest.mark.asyncio
async def test_create_user_defaults_onboarded_false(tmp_path: Path) -> None:
    """A brand-new account (however created — admin Create User, SSO
    auto-provisioning) should see the wizard once."""
    db_path = tmp_path / "users.db"
    with patch.object(auth_db, "_USERS_DB_PATH", db_path):
        await auth_db.init_users_db()
        uid = await auth_db.create_user("newbie", service.hash_password("Validpass1"))
        user = await auth_db.get_user_by_id(uid)

    assert user["onboarded"] is False


@pytest.mark.asyncio
async def test_set_onboarded_round_trip(tmp_path: Path) -> None:
    db_path = tmp_path / "users.db"
    with patch.object(auth_db, "_USERS_DB_PATH", db_path):
        await auth_db.init_users_db()
        uid = await auth_db.create_user("bob", service.hash_password("Validpass1"))

        assert (await auth_db.get_user_by_id(uid))["onboarded"] is False
        assert await auth_db.set_onboarded(uid, True) is True
        assert (await auth_db.get_user_by_id(uid))["onboarded"] is True
        assert await auth_db.set_onboarded(uid, False) is True
        assert (await auth_db.get_user_by_id(uid))["onboarded"] is False


# ── routes ─────────────────────────────────────────────────────────────────


@pytest.fixture
def auth_env(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.setenv("OPENTARS_ENABLE_AUTH", "1")
    service._failures.clear()

    async def _seed():
        await auth_db.init_users_db()
        await auth_db.create_user(
            "admin", service.hash_password("Adminpass1"), role="admin", onboarded=True
        )

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


def test_public_user_exposes_onboarded(auth_env):
    c = _login("admin", "Adminpass1")
    assert c.get("/api/auth/me").json()["user"]["onboarded"] is True


def test_new_user_created_via_route_is_not_onboarded(auth_env):
    c = _login("admin", "Adminpass1")
    created = c.post("/api/auth/users", json={"username": "bob", "role": "threat-viewer"}).json()
    assert created["onboarded"] is False


def test_complete_own_onboarding(auth_env):
    admin = _login("admin", "Adminpass1")
    created = admin.post(
        "/api/auth/users", json={"username": "bob", "role": "threat-viewer"}
    ).json()
    bob = _login("bob", created["generated_password"])

    r = bob.put("/api/auth/me/onboarding")
    assert r.status_code == 200, r.text
    assert r.json()["onboarded"] is True
    assert bob.get("/api/auth/me").json()["user"]["onboarded"] is True


def test_complete_own_onboarding_reachable_by_non_admin_role(auth_env):
    """Regression for the _SELF_PATHS entry — a non-admin role would
    otherwise be blocked by the role allowlist before reaching this route."""
    admin = _login("admin", "Adminpass1")
    created = admin.post(
        "/api/auth/users", json={"username": "viewer1", "role": "threat-viewer"}
    ).json()
    viewer = _login("viewer1", created["generated_password"])
    r = viewer.put("/api/auth/me/onboarding")
    assert r.status_code == 200


def test_admin_resets_user_onboarded_flag(auth_env):
    admin = _login("admin", "Adminpass1")
    created = admin.post(
        "/api/auth/users", json={"username": "bob", "role": "threat-viewer"}
    ).json()
    uid = created["id"]
    bob = _login("bob", created["generated_password"])
    bob.put("/api/auth/me/onboarding")
    assert bob.get("/api/auth/me").json()["user"]["onboarded"] is True

    r = admin.put(f"/api/auth/users/{uid}/onboarding", json={"onboarded": False})
    assert r.status_code == 200, r.text
    assert r.json()["onboarded"] is False
    assert bob.get("/api/auth/me").json()["user"]["onboarded"] is False


def test_set_user_onboarding_requires_admin(auth_env):
    admin = _login("admin", "Adminpass1")
    created = admin.post(
        "/api/auth/users", json={"username": "bob", "role": "threat-viewer"}
    ).json()
    uid = created["id"]
    bob = _login("bob", created["generated_password"])
    r = bob.put(f"/api/auth/users/{uid}/onboarding", json={"onboarded": False})
    assert r.status_code == 403


def test_set_user_onboarding_404s_for_unknown_user(auth_env):
    admin = _login("admin", "Adminpass1")
    r = admin.put("/api/auth/users/999999/onboarding", json={"onboarded": False})
    assert r.status_code == 404
