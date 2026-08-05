"""Tests for issue-local-037: user Organizations + org-derived usernames.

Coverage:
  1. backend.auth.organizations: validate_organization, build_username,
     local_part_of, domain_of_email.
  2. backend.auth.db: Organizations CRUD (create/get/list/update/delete,
     count_users_in_org, get_organization_by_domain), and
     set_user_username_and_org.
  3. /api/auth/organizations routes (admin-only CRUD, 409 on collision/
     non-empty delete).
  4. /api/auth/users routes: org_id + use_email_username on create, and the
     PUT .../organization change-org route.
  5. SSO auto-match by email domain (_upsert_sso_user) — org_id resynced on
     every login, username never touched.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.auth import db as auth_db
from backend.auth import service
from backend.main import app

# ── backend.auth.organizations (pure functions) ──────────────────────────────


def test_validate_organization_normalises_and_lowercases():
    from backend.auth.organizations import validate_organization

    name, domain = validate_organization("  Acme Corp  ", "  ACME.com  ")
    assert name == "Acme Corp"
    assert domain == "acme.com"


@pytest.mark.parametrize(
    "name,domain",
    [
        ("", "acme.com"),
        ("Acme", ""),
        ("Acme", "not a domain"),
        ("Acme", "@acme.com"),
        ("Acme", "https://acme.com"),
        ("Acme", "acme.com/path"),
    ],
)
def test_validate_organization_rejects_bad_input(name, domain):
    from backend.auth.organizations import validate_organization

    with pytest.raises(ValueError):
        validate_organization(name, domain)


def test_build_username_with_org_and_email_username():
    from backend.auth.organizations import build_username

    org = {"id": 1, "name": "Acme", "email_domain": "acme.com"}
    assert build_username("alice", org, True) == "alice@acme.com"


def test_build_username_with_org_but_email_username_disabled():
    from backend.auth.organizations import build_username

    org = {"id": 1, "name": "Acme", "email_domain": "acme.com"}
    assert build_username("alice", org, False) == "alice"


def test_build_username_no_org_is_local_user():
    from backend.auth.organizations import build_username

    assert build_username("alice", None, True) == "alice"


def test_local_part_of():
    from backend.auth.organizations import local_part_of

    assert local_part_of("alice@acme.com") == "alice"
    assert local_part_of("alice") == "alice"


def test_domain_of_email():
    from backend.auth.organizations import domain_of_email

    assert domain_of_email("alice@Acme.COM") == "acme.com"
    assert domain_of_email("alice") is None
    assert domain_of_email("alice@") is None


# ── backend.auth.db: Organizations CRUD ───────────────────────────────────────


def _run(coro):
    return asyncio.run(coro)


def test_organizations_crud_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    _run(auth_db.init_users_db())

    org_id = _run(auth_db.create_organization("Acme", "acme.com"))
    org = _run(auth_db.get_organization(org_id))
    assert org["name"] == "Acme"
    assert org["email_domain"] == "acme.com"

    listed = _run(auth_db.list_organizations())
    assert len(listed) == 1
    assert listed[0]["user_count"] == 0

    assert _run(auth_db.update_organization(org_id, "Acme Corp", "acme.io")) is True
    updated = _run(auth_db.get_organization(org_id))
    assert updated["name"] == "Acme Corp"
    assert updated["email_domain"] == "acme.io"

    assert _run(auth_db.count_users_in_org(org_id)) == 0
    assert _run(auth_db.delete_organization(org_id)) is True
    assert _run(auth_db.get_organization(org_id)) is None


def test_get_organization_by_domain_case_insensitive(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    _run(auth_db.init_users_db())
    _run(auth_db.create_organization("Acme", "acme.com"))

    found = _run(auth_db.get_organization_by_domain("ACME.COM"))
    assert found is not None
    assert found["email_domain"] == "acme.com"

    assert _run(auth_db.get_organization_by_domain("nope.com")) is None


def test_create_organization_duplicate_name_or_domain_raises(tmp_path, monkeypatch):
    import aiosqlite

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    _run(auth_db.init_users_db())
    _run(auth_db.create_organization("Acme", "acme.com"))

    with pytest.raises(aiosqlite.IntegrityError):
        _run(auth_db.create_organization("Acme", "other.com"))
    with pytest.raises(aiosqlite.IntegrityError):
        _run(auth_db.create_organization("Other", "acme.com"))


def test_set_user_username_and_org(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    _run(auth_db.init_users_db())
    org_id = _run(auth_db.create_organization("Acme", "acme.com"))
    uid = _run(auth_db.create_user("alice", service.hash_password("Validpass1")))

    assert _run(auth_db.set_user_username_and_org(uid, "alice@acme.com", org_id)) is True
    updated = _run(auth_db.get_user_by_id(uid))
    assert updated["username"] == "alice@acme.com"
    assert updated["org_id"] == org_id


# ── /api/auth/organizations + /api/auth/users routes ─────────────────────────


@pytest.fixture
def auth_env(tmp_path, monkeypatch):
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


def test_organizations_crud_routes(auth_env):
    c = _login("admin", "Adminpass1")

    r = c.post("/api/auth/organizations", json={"name": "Acme", "email_domain": "acme.com"})
    assert r.status_code == 201, r.text
    org = r.json()
    assert org["name"] == "Acme"
    assert org["email_domain"] == "acme.com"
    assert org["user_count"] == 0

    orgs = c.get("/api/auth/organizations").json()
    assert len(orgs) == 1

    r = c.put(
        f"/api/auth/organizations/{org['id']}",
        json={"name": "Acme Corp", "email_domain": "acme.io"},
    )
    assert r.status_code == 200
    assert r.json()["name"] == "Acme Corp"

    r = c.delete(f"/api/auth/organizations/{org['id']}")
    assert r.status_code == 200
    assert c.get("/api/auth/organizations").json() == []


def test_create_organization_duplicate_409(auth_env):
    c = _login("admin", "Adminpass1")
    c.post("/api/auth/organizations", json={"name": "Acme", "email_domain": "acme.com"})
    r = c.post("/api/auth/organizations", json={"name": "Acme", "email_domain": "other.com"})
    assert r.status_code == 409


def test_organization_bad_domain_400(auth_env):
    c = _login("admin", "Adminpass1")
    r = c.post("/api/auth/organizations", json={"name": "Acme", "email_domain": "not a domain"})
    assert r.status_code == 400


def test_update_delete_organization_404(auth_env):
    c = _login("admin", "Adminpass1")
    assert (
        c.put("/api/auth/organizations/999", json={"name": "X", "email_domain": "x.com"}).status_code
        == 404
    )
    assert c.delete("/api/auth/organizations/999").status_code == 404


def test_delete_organization_with_users_409(auth_env):
    c = _login("admin", "Adminpass1")
    org = c.post(
        "/api/auth/organizations", json={"name": "Acme", "email_domain": "acme.com"}
    ).json()
    c.post(
        "/api/auth/users",
        json={
            "username": "alice",
            "password": "Validpass1",
            "role": "threat-viewer",
            "org_id": org["id"],
        },
    )
    r = c.delete(f"/api/auth/organizations/{org['id']}")
    assert r.status_code == 409
    assert "1" in r.json()["detail"]


def test_create_user_with_org_and_email_username_builds_full_email(auth_env):
    c = _login("admin", "Adminpass1")
    org = c.post(
        "/api/auth/organizations", json={"name": "Acme", "email_domain": "acme.com"}
    ).json()
    r = c.post(
        "/api/auth/users",
        json={
            "username": "alice",
            "password": "Validpass1",
            "role": "threat-viewer",
            "org_id": org["id"],
            "use_email_username": True,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["username"] == "alice@acme.com"
    assert r.json()["org_id"] == org["id"]


def test_create_user_with_org_but_email_username_disabled_keeps_local_part(auth_env):
    c = _login("admin", "Adminpass1")
    org = c.post(
        "/api/auth/organizations", json={"name": "Acme", "email_domain": "acme.com"}
    ).json()
    r = c.post(
        "/api/auth/users",
        json={
            "username": "alice",
            "password": "Validpass1",
            "role": "threat-viewer",
            "org_id": org["id"],
            "use_email_username": False,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["username"] == "alice"
    assert r.json()["org_id"] == org["id"]


def test_create_user_no_org_is_local_user(auth_env):
    c = _login("admin", "Adminpass1")
    r = c.post(
        "/api/auth/users",
        json={"username": "bob", "password": "Validpass1", "role": "threat-viewer"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["username"] == "bob"
    assert r.json()["org_id"] is None


def test_create_user_unknown_org_404(auth_env):
    c = _login("admin", "Adminpass1")
    r = c.post(
        "/api/auth/users",
        json={
            "username": "bob",
            "password": "Validpass1",
            "role": "threat-viewer",
            "org_id": 999,
        },
    )
    assert r.status_code == 404


def test_create_user_org_email_collision_409(auth_env):
    c = _login("admin", "Adminpass1")
    org = c.post(
        "/api/auth/organizations", json={"name": "Acme", "email_domain": "acme.com"}
    ).json()
    c.post(
        "/api/auth/users",
        json={
            "username": "alice",
            "password": "Validpass1",
            "role": "threat-viewer",
            "org_id": org["id"],
        },
    )
    r = c.post(
        "/api/auth/users",
        json={
            "username": "alice",
            "password": "Validpass1",
            "role": "threat-viewer",
            "org_id": org["id"],
        },
    )
    assert r.status_code == 409


def test_set_user_organization_route_updates_username(auth_env):
    c = _login("admin", "Adminpass1")
    org = c.post(
        "/api/auth/organizations", json={"name": "Acme", "email_domain": "acme.com"}
    ).json()
    created = c.post(
        "/api/auth/users",
        json={"username": "alice", "password": "Validpass1", "role": "threat-viewer"},
    ).json()
    assert created["username"] == "alice"

    r = c.put(
        f"/api/auth/users/{created['id']}/organization",
        json={"org_id": org["id"], "use_email_username": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["username"] == "alice@acme.com"
    assert r.json()["org_id"] == org["id"]

    # Moving back to "Local user" recomputes the bare local-part.
    r = c.put(
        f"/api/auth/users/{created['id']}/organization",
        json={"org_id": None},
    )
    assert r.status_code == 200
    assert r.json()["username"] == "alice"
    assert r.json()["org_id"] is None


def test_set_user_organization_unknown_org_404(auth_env):
    c = _login("admin", "Adminpass1")
    created = c.post(
        "/api/auth/users",
        json={"username": "alice", "password": "Validpass1", "role": "threat-viewer"},
    ).json()
    r = c.put(f"/api/auth/users/{created['id']}/organization", json={"org_id": 999})
    assert r.status_code == 404


def test_list_users_does_not_leak_external_id(auth_env):
    c = _login("admin", "Adminpass1")
    users = c.get("/api/auth/users").json()
    assert all("external_id" not in u for u in users)


# ── SSO auto-match org by email domain ────────────────────────────────────────


@pytest.mark.asyncio
async def test_upsert_sso_user_new_user_auto_matches_org_by_domain(tmp_path, monkeypatch):
    from backend.auth.oidc import _upsert_sso_user

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()
    org_id = await auth_db.create_organization("Acme", "acme.com")

    user = await _upsert_sso_user(
        username="alice@acme.com",
        sub="sub-alice",
        idp="entra",
        role="threat-viewer",
        auto_provision=True,
    )

    assert user is not None
    assert user["org_id"] == org_id
    assert user["username"] == "alice@acme.com"


@pytest.mark.asyncio
async def test_upsert_sso_user_no_matching_domain_is_local_user(tmp_path, monkeypatch):
    from backend.auth.oidc import _upsert_sso_user

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()
    await auth_db.create_organization("Acme", "acme.com")

    user = await _upsert_sso_user(
        username="bob@other.com",
        sub="sub-bob",
        idp="entra",
        role="threat-viewer",
        auto_provision=True,
    )

    assert user is not None
    assert user["org_id"] is None


@pytest.mark.asyncio
async def test_upsert_sso_user_existing_user_org_resynced_on_login(tmp_path, monkeypatch):
    """org_id is resynced on every SSO login (like role) — but username never changes."""
    from backend.auth.oidc import _upsert_sso_user

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()

    await auth_db.create_user(
        "alice@acme.com", service.hash_password("Validpass1"), role="threat-viewer"
    )
    org_id = await auth_db.create_organization("Acme", "acme.com")

    user = await _upsert_sso_user(
        username="alice@acme.com",
        sub="sub-alice",
        idp="entra",
        role="threat-viewer",
        auto_provision=True,
    )

    assert user["org_id"] == org_id
    assert user["username"] == "alice@acme.com"  # unchanged

    persisted = await auth_db.get_user_by_id(user["id"])
    assert persisted["org_id"] == org_id
