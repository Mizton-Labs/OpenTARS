"""Tests for the API access key feature (issue-local-029):
- backend.auth.db: api_keys CRUD.
- backend.auth.service: create_api_key / resolve_api_key.
- backend.auth.api_scopes: scope_allows / valid_scope_ids.
- backend.main's auth_enforcement middleware: the Bearer-token branch,
  scope enforcement, the /api/threat-hunting/ hard cap, and that API-key
  auth can never satisfy the admin-only management routes.
- backend.api.routes_auth: the /api/auth/api-keys management routes.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.auth import db as auth_db
from backend.auth import service
from backend.auth.api_scopes import (
    API_SCOPES,
    DEFAULT_PROFILE_SCOPES,
    scope_allows,
    valid_scope_ids,
)
from backend.main import app


@pytest.fixture
def auth_env(tmp_path, monkeypatch):
    """Enable auth + API access, isolate users.db, seed one admin."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.setenv("OPENTARS_ENABLE_AUTH", "1")
    # load_api_access_enabled is imported by reference into both main.py and
    # routes_auth.py (`from backend.config.loader import ...`) — each holds
    # its own binding, so both must be patched.
    monkeypatch.setattr("backend.main.load_api_access_enabled", lambda: True)
    monkeypatch.setattr("backend.api.routes_auth.load_api_access_enabled", lambda: True)
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


# ── backend.auth.db: api_keys CRUD ─────────────────────────────────────────────


class TestApiKeyDbCrud:
    @pytest.mark.asyncio
    async def test_create_and_get_by_client_id(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        await auth_db.create_api_key(
            "ak_deadbeef0001", "hash1", "CI pipeline", ["hunts:create"], created_by="admin"
        )
        record = await auth_db.get_api_key_by_client_id("ak_deadbeef0001")
        assert record is not None
        assert record["name"] == "CI pipeline"
        assert record["scopes"] == ["hunts:create"]
        assert record["enabled"] is True
        assert record["created_by"] == "admin"
        assert record["last_used_at"] is None

    @pytest.mark.asyncio
    async def test_duplicate_client_id_rejected(self, tmp_path, monkeypatch):
        import sqlite3

        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        await auth_db.create_api_key("ak_dup", "h", "a", [])
        with pytest.raises(sqlite3.IntegrityError):
            await auth_db.create_api_key("ak_dup", "h2", "b", [])

    @pytest.mark.asyncio
    async def test_list_update_touch_delete(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        await auth_db.create_api_key("ak_x", "h", "orig", ["hunts:read"])

        assert len(await auth_db.list_api_keys()) == 1

        assert await auth_db.set_api_key_name("ak_x", "renamed") is True
        assert await auth_db.set_api_key_scopes("ak_x", ["iocs:read", "hunts:read"]) is True
        assert await auth_db.set_api_key_enabled("ak_x", False) is True
        record = await auth_db.get_api_key_by_client_id("ak_x")
        assert record["name"] == "renamed"
        assert record["scopes"] == ["iocs:read", "hunts:read"]
        assert record["enabled"] is False

        await auth_db.touch_api_key_last_used("ak_x")
        record = await auth_db.get_api_key_by_client_id("ak_x")
        assert record["last_used_at"] is not None

        assert await auth_db.delete_api_key("ak_x") is True
        assert await auth_db.get_api_key_by_client_id("ak_x") is None
        assert await auth_db.delete_api_key("ak_x") is False

    @pytest.mark.asyncio
    async def test_fresh_db_has_api_keys_table(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        import aiosqlite

        async with aiosqlite.connect(tmp_path / "users.db") as db:
            cur = await db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in await cur.fetchall()}
        assert "api_keys" in tables


# ── backend.auth.service: create_api_key / resolve_api_key ────────────────────


class TestApiKeyService:
    @pytest.mark.asyncio
    async def test_create_returns_secret_once_and_persists_only_hash(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        created = await service.create_api_key("test key", ["hunts:read"], created_by="admin")
        assert created["client_id"].startswith("ak_")
        assert created["secret"]
        assert created["api_key"] == f"{created['client_id']}.{created['secret']}"

        record = await auth_db.get_api_key_by_client_id(created["client_id"])
        assert record["secret_hash"] != created["secret"]
        assert record["secret_hash"] == service.hash_token(created["secret"])

    @pytest.mark.asyncio
    async def test_create_drops_unknown_scopes(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        created = await service.create_api_key("k", ["hunts:read", "not-a-real-scope"])
        assert created["scopes"] == ["hunts:read"]

    @pytest.mark.asyncio
    async def test_resolve_valid_key(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        created = await service.create_api_key("k", ["hunts:read"])
        resolved = await service.resolve_api_key(created["api_key"])
        assert resolved is not None
        assert resolved["is_api_key"] is True
        assert resolved["client_id"] == created["client_id"]
        assert resolved["scopes"] == ["hunts:read"]

    @pytest.mark.asyncio
    async def test_resolve_wrong_secret_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        created = await service.create_api_key("k", [])
        bad = f"{created['client_id']}.wrong-secret-entirely"
        assert await service.resolve_api_key(bad) is None

    @pytest.mark.asyncio
    async def test_resolve_unknown_client_id_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        assert await service.resolve_api_key("ak_nonexistent.somesecret") is None

    @pytest.mark.asyncio
    async def test_resolve_disabled_key_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        created = await service.create_api_key("k", [])
        await auth_db.set_api_key_enabled(created["client_id"], False)
        assert await service.resolve_api_key(created["api_key"]) is None

    @pytest.mark.asyncio
    async def test_resolve_malformed_bearer_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        await auth_db.init_users_db()
        assert await service.resolve_api_key("") is None
        assert await service.resolve_api_key("no-dot-in-here") is None
        assert await service.resolve_api_key("ak_x.") is None
        assert await service.resolve_api_key(".secretonly") is None


# ── backend.auth.api_scopes ─────────────────────────────────────────────────


class TestApiScopes:
    def test_default_profile_matches_the_issue(self):
        assert set(DEFAULT_PROFILE_SCOPES) == {
            "hunts:create",
            "evidence:add",
            "reports:download",
            "iocs:read",
            "threat_intel:read",
            "threat_intel_tracking:read",
        }

    def test_scope_allows_matching_route(self):
        assert scope_allows(["hunts:create"], "POST", "/api/threat-hunting/packages") is True

    def test_scope_allows_rejects_wrong_method(self):
        assert scope_allows(["hunts:read"], "POST", "/api/threat-hunting/packages") is False

    def test_scope_allows_rejects_unrelated_scope(self):
        assert scope_allows(["iocs:read"], "POST", "/api/threat-hunting/packages") is False

    def test_scope_allows_dynamic_segment(self):
        assert (
            scope_allows(
                ["evidence:add"], "POST", "/api/threat-hunting/packages/pkg-123/evidence/file"
            )
            is True
        )

    def test_scope_allows_run_scoped_report(self):
        assert (
            scope_allows(
                ["reports:download"],
                "GET",
                "/api/threat-hunting/packages/pkg-1/runs/run-1/report/pdf",
            )
            is True
        )

    def test_scope_allows_never_matches_admin_routes(self):
        # No defined scope should ever resolve to a non-threat-hunting path —
        # even a deliberately-crafted "all scopes" list must not reach here.
        all_scopes = list(API_SCOPES.keys())
        assert scope_allows(all_scopes, "GET", "/api/auth/users") is False
        assert scope_allows(all_scopes, "GET", "/api/llm/providers") is False

    def test_valid_scope_ids_dedupes_and_drops_unknown(self):
        assert valid_scope_ids(["hunts:read", "bogus", "hunts:read"]) == ["hunts:read"]


# ── Middleware integration (full HTTP stack) ───────────────────────────────────


class TestApiKeyMiddleware:
    def test_valid_key_with_matching_scope_succeeds(self, auth_env):
        c = _login("admin", "Adminpass1")
        created = c.post("/api/auth/api-keys", json={"name": "k", "scopes": ["hunts:read"]}).json()
        anon = _client()
        r = anon.get(
            "/api/threat-hunting/packages",
            headers={"Authorization": f"Bearer {created['api_key']}"},
        )
        assert r.status_code == 200

    def test_valid_key_without_matching_scope_is_403(self, auth_env):
        c = _login("admin", "Adminpass1")
        created = c.post("/api/auth/api-keys", json={"name": "k", "scopes": ["iocs:read"]}).json()
        anon = _client()
        r = anon.post(
            "/api/threat-hunting/packages",
            json={"name": "x"},
            headers={"Authorization": f"Bearer {created['api_key']}"},
        )
        assert r.status_code == 403

    def test_invalid_key_is_401(self, auth_env):
        anon = _client()
        r = anon.get(
            "/api/threat-hunting/packages",
            headers={"Authorization": "Bearer ak_fake.notreal"},
        )
        assert r.status_code == 401

    def test_key_rejected_when_api_access_disabled(self, auth_env, monkeypatch):
        c = _login("admin", "Adminpass1")
        created = c.post("/api/auth/api-keys", json={"name": "k", "scopes": ["hunts:read"]}).json()
        monkeypatch.setattr("backend.main.load_api_access_enabled", lambda: False)
        anon = _client()
        r = anon.get(
            "/api/threat-hunting/packages",
            headers={"Authorization": f"Bearer {created['api_key']}"},
        )
        assert r.status_code == 401

    def test_api_key_cannot_reach_admin_management_routes(self, auth_env):
        """A key authenticates fine (it IS valid) but is still hard-capped to
        /api/threat-hunting/ by the middleware's defense-in-depth check, so
        /api/auth/users 403s regardless of what scopes the key holds — and
        even if it somehow got past that cap, require_admin resolves the
        session cookie directly (never request.state.user), so an API key
        could never satisfy it anyway."""
        c = _login("admin", "Adminpass1")
        created = c.post("/api/auth/api-keys", json={"name": "k", "scopes": ["hunts:read"]}).json()
        anon = _client()
        r = anon.get("/api/auth/users", headers={"Authorization": f"Bearer {created['api_key']}"})
        assert r.status_code == 403

    def test_api_key_cannot_reach_non_threat_hunting_paths(self, auth_env):
        c = _login("admin", "Adminpass1")
        created = c.post("/api/auth/api-keys", json={"name": "k", "scopes": ["hunts:read"]}).json()
        anon = _client()
        r = anon.get(
            "/api/llm/providers", headers={"Authorization": f"Bearer {created['api_key']}"}
        )
        assert r.status_code == 403

    def test_disabled_key_is_401(self, auth_env):
        c = _login("admin", "Adminpass1")
        created = c.post("/api/auth/api-keys", json={"name": "k", "scopes": ["hunts:read"]}).json()
        c.put(f"/api/auth/api-keys/{created['client_id']}", json={"enabled": False})
        anon = _client()
        r = anon.get(
            "/api/threat-hunting/packages",
            headers={"Authorization": f"Bearer {created['api_key']}"},
        )
        assert r.status_code == 401


# ── Management routes ───────────────────────────────────────────────────────


class TestApiKeyRoutes:
    def test_non_admin_cannot_manage_keys(self, auth_env):
        c = _login("admin", "Adminpass1")
        created = c.post(
            "/api/auth/users",
            json={
                "username": "researcher1",
                "role": "threat-researcher",
            },
        ).json()
        nc = _login("researcher1", created["generated_password"])
        nc.put(
            "/api/auth/password",
            json={"current_password": created["generated_password"], "new_password": "Researchpass2"},
        )
        assert nc.get("/api/auth/api-keys").status_code == 403
        assert nc.post("/api/auth/api-keys", json={"name": "x", "scopes": []}).status_code == 403

    def test_create_list_update_delete_roundtrip(self, auth_env):
        c = _login("admin", "Adminpass1")
        created = c.post(
            "/api/auth/api-keys", json={"name": "CI", "scopes": DEFAULT_PROFILE_SCOPES}
        )
        assert created.status_code == 201
        body = created.json()
        assert "secret" in body and "api_key" in body and "endpoint" in body
        assert body["scopes"] == DEFAULT_PROFILE_SCOPES

        listed = c.get("/api/auth/api-keys").json()
        assert len(listed) == 1
        assert "secret_hash" not in listed[0]
        assert "secret" not in listed[0]

        updated = c.put(f"/api/auth/api-keys/{body['client_id']}", json={"name": "CI renamed"})
        assert updated.json()["name"] == "CI renamed"

        deleted = c.delete(f"/api/auth/api-keys/{body['client_id']}")
        assert deleted.status_code == 200
        assert c.get("/api/auth/api-keys").json() == []

    def test_scopes_route_lists_definitions_and_default_profile(self, auth_env):
        c = _login("admin", "Adminpass1")
        r = c.get("/api/auth/api-keys/scopes")
        assert r.status_code == 200
        body = r.json()
        assert body["default_profile"] == DEFAULT_PROFILE_SCOPES
        ids = {s["id"] for s in body["scopes"]}
        assert "hunts:create" in ids
        assert all({"id", "label", "description"} <= s.keys() for s in body["scopes"])

    def test_test_route_reports_ok_for_a_healthy_key(self, auth_env):
        c = _login("admin", "Adminpass1")
        created = c.post("/api/auth/api-keys", json={"name": "k", "scopes": ["hunts:read"]}).json()
        r = c.post(f"/api/auth/api-keys/{created['client_id']}/test")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_test_route_reports_error_for_disabled_key(self, auth_env):
        c = _login("admin", "Adminpass1")
        created = c.post("/api/auth/api-keys", json={"name": "k", "scopes": ["hunts:read"]}).json()
        c.put(f"/api/auth/api-keys/{created['client_id']}", json={"enabled": False})
        r = c.post(f"/api/auth/api-keys/{created['client_id']}/test")
        assert r.json()["status"] == "error"

    def test_test_route_warns_when_api_access_globally_disabled(self, auth_env, monkeypatch):
        c = _login("admin", "Adminpass1")
        created = c.post("/api/auth/api-keys", json={"name": "k", "scopes": ["hunts:read"]}).json()
        monkeypatch.setattr("backend.api.routes_auth.load_api_access_enabled", lambda: False)
        r = c.post(f"/api/auth/api-keys/{created['client_id']}/test")
        assert r.json()["status"] == "warning"

    def test_create_rejects_blank_name(self, auth_env):
        c = _login("admin", "Adminpass1")
        r = c.post("/api/auth/api-keys", json={"name": "   ", "scopes": []})
        assert r.status_code == 400

    def test_update_unknown_key_404(self, auth_env):
        c = _login("admin", "Adminpass1")
        r = c.put("/api/auth/api-keys/ak_doesnotexist", json={"name": "x"})
        assert r.status_code == 404
