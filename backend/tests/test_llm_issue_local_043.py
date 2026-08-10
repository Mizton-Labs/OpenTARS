"""Tests for issue-local-043: LLM provider CRUD/discover/test routes now
require an admin session when auth is enabled (previously fully open,
inconsistent with comparable settings routes like PUT /app/th-research-
effort). A no-op when auth is globally disabled, same as every other
require_admin_when_enabled-gated route.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.auth import db as auth_db
from backend.auth import service
from backend.llm import config as cfg_mod
from backend.main import app


@pytest.fixture(autouse=True)
def _isolate_llm_config(tmp_path, monkeypatch):
    monkeypatch.setattr(cfg_mod, "_LLM_CONFIG_PATH", tmp_path / "llm-providers.yaml")
    yield


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


def _clear_must_change_password(client: TestClient, generated_password: str) -> None:
    """A freshly admin-created user always has must_change_password=True
    (routes_auth.create_user), which 403s every other route until cleared —
    not the role gate this test file is actually exercising."""
    r = client.put(
        "/api/auth/password",
        json={"current_password": generated_password, "new_password": "Newpass123"},
    )
    assert r.status_code == 200, r.text


def _login_viewer(admin: TestClient) -> TestClient:
    created = admin.post(
        "/api/auth/users",
        json={"username": "viewer1", "role": "threat-viewer"},
    ).json()
    c = _login("viewer1", created["generated_password"])
    _clear_must_change_password(c, created["generated_password"])
    return c


def _login_researcher(admin: TestClient) -> TestClient:
    created = admin.post(
        "/api/auth/users",
        json={"username": "researcher1", "role": "threat-researcher"},
    ).json()
    c = _login("researcher1", created["generated_password"])
    _clear_must_change_password(c, created["generated_password"])
    return c


class TestAdminGatingWhenAuthEnabled:
    """Note: the global role middleware (backend/main.py) already denies
    every non-admin role write access to /api/llm/* (it's absent from both
    _VIEWER_WRITE_PREFIXES and _RESEARCHER_WRITE_PREFIXES), so these 403s
    are already true end-to-end today. The new require_admin_when_enabled
    dependency added on each route is defense-in-depth — same reasoning as
    every other such dependency in the app (see its own docstring): a
    future middleware allowlist change can't silently expose these routes
    without also touching the route itself. These tests assert the
    observable behavior (403 for non-admin), not which layer produced it.
    """

    def test_add_provider_requires_admin(self, auth_env):
        admin = _login("admin", "Adminpass1")
        viewer = _login_viewer(admin)
        r = viewer.post(
            "/api/llm/providers",
            json={"name": "p1", "kind": "openai", "base_url": "https://x", "model": "m", "api_key": "sk"},
        )
        assert r.status_code == 403

    def test_update_provider_requires_admin(self, auth_env):
        admin = _login("admin", "Adminpass1")
        assert admin.post(
            "/api/llm/providers",
            json={"name": "p1", "kind": "openai", "base_url": "https://x", "model": "m", "api_key": "sk"},
        ).status_code == 201
        viewer = _login_viewer(admin)
        r = viewer.put(
            "/api/llm/providers/p1",
            json={"name": "p1", "kind": "openai", "base_url": "https://x", "model": "m2", "api_key": "***"},
        )
        assert r.status_code == 403

    def test_delete_provider_requires_admin(self, auth_env):
        admin = _login("admin", "Adminpass1")
        assert admin.post(
            "/api/llm/providers",
            json={"name": "p1", "kind": "openai", "base_url": "https://x", "model": "m", "api_key": "sk"},
        ).status_code == 201
        viewer = _login_viewer(admin)
        r = viewer.delete("/api/llm/providers/p1")
        assert r.status_code == 403

    def test_discover_draft_requires_admin(self, auth_env):
        admin = _login("admin", "Adminpass1")
        viewer = _login_viewer(admin)
        r = viewer.post(
            "/api/llm/providers/discover",
            json={"kind": "openai", "base_url": "https://x", "api_key": "sk"},
        )
        assert r.status_code == 403

    def test_discover_persisted_requires_admin(self, auth_env):
        admin = _login("admin", "Adminpass1")
        assert admin.post(
            "/api/llm/providers",
            json={"name": "p1", "kind": "openai", "base_url": "https://x", "model": "m", "api_key": "sk"},
        ).status_code == 201
        viewer = _login_viewer(admin)
        r = viewer.post("/api/llm/providers/p1/discover")
        assert r.status_code == 403

    def test_test_draft_requires_admin(self, auth_env):
        admin = _login("admin", "Adminpass1")
        viewer = _login_viewer(admin)
        r = viewer.post(
            "/api/llm/providers/test",
            json={"kind": "openai", "base_url": "https://x", "api_key": "sk", "model": "m"},
        )
        assert r.status_code == 403

    def test_test_persisted_requires_admin(self, auth_env):
        admin = _login("admin", "Adminpass1")
        assert admin.post(
            "/api/llm/providers",
            json={"name": "p1", "kind": "openai", "base_url": "https://x", "model": "m", "api_key": "sk"},
        ).status_code == 201
        viewer = _login_viewer(admin)
        r = viewer.post("/api/llm/providers/p1/test")
        assert r.status_code == 403

    def test_get_providers_reachable_by_researcher(self, auth_env):
        """Read-only listing stays reachable by researcher (issue-local-026 —
        the Threat Hunting model-selector dropdown needs it), unaffected by
        this issue's write-side admin gating."""
        admin = _login("admin", "Adminpass1")
        researcher = _login_researcher(admin)
        r = researcher.get("/api/llm/providers")
        assert r.status_code == 200

    def test_add_provider_blocked_for_researcher_too(self, auth_env):
        """Mutations are admin-only, not just non-viewer — a researcher
        (who CAN read this listing) still can't write to it."""
        admin = _login("admin", "Adminpass1")
        researcher = _login_researcher(admin)
        r = researcher.post(
            "/api/llm/providers",
            json={"name": "p1", "kind": "openai", "base_url": "https://x", "model": "m", "api_key": "sk"},
        )
        assert r.status_code == 403

    def test_admin_can_add_and_update_provider(self, auth_env):
        """The gate must not block the role it's meant to allow."""
        admin = _login("admin", "Adminpass1")
        r = admin.post(
            "/api/llm/providers",
            json={"name": "p1", "kind": "openai", "base_url": "https://x", "model": "m", "api_key": "sk"},
        )
        assert r.status_code == 201, r.text
        r2 = admin.put(
            "/api/llm/providers/p1",
            json={"name": "p1", "kind": "openai", "base_url": "https://x", "model": "m2", "api_key": "***"},
        )
        assert r2.status_code == 200, r2.text


class TestAdminGatingIsNoOpWhenAuthDisabled:
    def test_add_provider_works_without_login(self):
        client = TestClient(app)
        r = client.post(
            "/api/llm/providers",
            json={"name": "p1", "kind": "openai", "base_url": "https://x", "model": "m", "api_key": "sk"},
        )
        assert r.status_code == 201, r.text
