"""Tests for issue-local-044: Data Explorer bulk archive/delete/unarchive
for Hunt Packages, scoped to the package's owner or an admin.

Archive (DELETE /packages/{id}) and unarchive (PUT /packages/{id} with a
status change) are now scoped like Hunt Playbook ownership (issue-local-041)
— admins bypass, a package with no recorded owner (created_by NULL) has no
owner to enforce and stays open to any researcher, and auth-disabled
requests are unrestricted. Renaming/description edits via the same PUT
route are deliberately NOT scoped — only status-changing calls are.
Hard delete (DELETE /packages/{id}/hard) already had its own stricter
admin-only gate (issue-local-034) and is untouched.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from backend.api.routes_threat_hunting import _require_package_owner_or_admin
from backend.threat_hunting import db as th_db


def _fake_request(user=None):
    return SimpleNamespace(state=SimpleNamespace(user=user))


class TestRequirePackageOwnerOrAdmin:
    def test_auth_disabled_is_unrestricted(self):
        _require_package_owner_or_admin({"created_by": "alice"}, _fake_request(None))

    def test_owner_may_archive_own_package(self):
        _require_package_owner_or_admin(
            {"created_by": "alice"}, _fake_request({"username": "alice", "role": "threat-researcher"})
        )

    def test_non_owner_researcher_is_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            _require_package_owner_or_admin(
                {"created_by": "alice"}, _fake_request({"username": "bob", "role": "threat-researcher"})
            )
        assert exc_info.value.status_code == 403

    def test_admin_bypasses_ownership_entirely(self):
        _require_package_owner_or_admin(
            {"created_by": "alice"}, _fake_request({"username": "someone-else", "role": "admin"})
        )

    def test_no_recorded_owner_is_actionable_by_any_researcher(self):
        _require_package_owner_or_admin(
            {"created_by": None}, _fake_request({"username": "bob", "role": "threat-researcher"})
        )


class TestPackageOwnershipRoutesHttp404Ordering:
    @pytest.mark.asyncio
    async def test_archive_404s_before_ownership_check_for_unknown_package(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            client = TestClient(app)
            resp = client.delete("/api/threat-hunting/packages/does-not-exist")
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_unarchive_404s_before_ownership_check_for_unknown_package(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            client = TestClient(app)
            resp = client.put(
                "/api/threat-hunting/packages/does-not-exist", json={"status": "draft"}
            )
            assert resp.status_code == 404


# ── Real end-to-end HTTP, auth enabled ───────────────────────────────────────


@pytest.fixture
def auth_env(tmp_path, monkeypatch):
    from backend.auth import db as auth_db
    from backend.auth import service

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    monkeypatch.setenv("OPENTARS_ENABLE_AUTH", "1")
    service._failures.clear()

    async def _seed():
        await auth_db.init_users_db()
        await auth_db.create_user("admin", service.hash_password("Adminpass1"), role="admin")

    asyncio.run(_seed())
    yield
    service._failures.clear()


def _client():
    from fastapi.testclient import TestClient

    from backend.main import app

    return TestClient(app)


def _login(username: str, password: str):
    c = _client()
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return c


def _clear_must_change_password(client, generated_password: str) -> None:
    r = client.put(
        "/api/auth/password",
        json={"current_password": generated_password, "new_password": "Newpass123"},
    )
    assert r.status_code == 200, r.text


def _login_researcher(admin, username: str):
    created = admin.post(
        "/api/auth/users",
        json={"username": username, "role": "threat-researcher"},
    ).json()
    c = _login(username, created["generated_password"])
    _clear_must_change_password(c, created["generated_password"])
    return c


class TestPackageOwnershipEndToEnd:
    def test_owner_can_archive_and_unarchive_own_package(self, tmp_path: Path, auth_env) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            asyncio.run(th_db.init_threat_hunting_db())
            admin = _login("admin", "Adminpass1")
            alice = _login_researcher(admin, "alice")

            pkg = alice.post("/api/threat-hunting/packages", json={"name": "Alice pkg"}).json()

            archive_resp = alice.delete(f"/api/threat-hunting/packages/{pkg['id']}")
            assert archive_resp.status_code == 204, archive_resp.text

            unarchive_resp = alice.put(
                f"/api/threat-hunting/packages/{pkg['id']}", json={"status": "draft"}
            )
            assert unarchive_resp.status_code == 200, unarchive_resp.text

    def test_non_owner_researcher_cannot_archive_or_unarchive(self, tmp_path: Path, auth_env) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            asyncio.run(th_db.init_threat_hunting_db())
            admin = _login("admin", "Adminpass1")
            alice = _login_researcher(admin, "alice")
            bob = _login_researcher(admin, "bob")

            pkg = alice.post("/api/threat-hunting/packages", json={"name": "Alice pkg"}).json()

            archive_resp = bob.delete(f"/api/threat-hunting/packages/{pkg['id']}")
            assert archive_resp.status_code == 403

            unarchive_resp = bob.put(
                f"/api/threat-hunting/packages/{pkg['id']}", json={"status": "draft"}
            )
            assert unarchive_resp.status_code == 403

    def test_non_owner_researcher_can_still_rename(self, tmp_path: Path, auth_env) -> None:
        """Ownership scoping applies only to status changes — renaming a
        package someone else created is unaffected (existing behavior)."""
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            asyncio.run(th_db.init_threat_hunting_db())
            admin = _login("admin", "Adminpass1")
            alice = _login_researcher(admin, "alice")
            bob = _login_researcher(admin, "bob")

            pkg = alice.post("/api/threat-hunting/packages", json={"name": "Alice pkg"}).json()

            rename_resp = bob.put(
                f"/api/threat-hunting/packages/{pkg['id']}", json={"name": "Renamed by bob"}
            )
            assert rename_resp.status_code == 200, rename_resp.text

    def test_admin_can_archive_any_package(self, tmp_path: Path, auth_env) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            asyncio.run(th_db.init_threat_hunting_db())
            admin = _login("admin", "Adminpass1")
            alice = _login_researcher(admin, "alice")

            pkg = alice.post("/api/threat-hunting/packages", json={"name": "Alice pkg"}).json()

            archive_resp = admin.delete(f"/api/threat-hunting/packages/{pkg['id']}")
            assert archive_resp.status_code == 204, archive_resp.text

    def test_any_researcher_can_archive_a_no_owner_package(self, tmp_path: Path, auth_env) -> None:
        """A package created while auth was disabled (or pre-ownership-
        tracking) has created_by=NULL — open to any researcher."""
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            asyncio.run(th_db.init_threat_hunting_db())
            pkg = asyncio.run(th_db.create_hunt_package("No owner", ""))
            admin = _login("admin", "Adminpass1")
            bob = _login_researcher(admin, "bob")

            archive_resp = bob.delete(f"/api/threat-hunting/packages/{pkg['id']}")
            assert archive_resp.status_code == 204, archive_resp.text
