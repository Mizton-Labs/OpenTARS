"""Regression test: SSO login must never overwrite an existing user's role.

Bug: on every SSO login, `_upsert_sso_user` unconditionally wrote the role
computed from `map_claims_to_role` (IdP claims, falling back to the SSO
config's `default_role`) over the matched user's existing role — so an
admin who manually promoted/demoted a user via User Management would have
that change silently reverted back to `default_role` on the user's next
SSO login, unless every relevant IdP claim value happened to be mapped.

Role is an admin-owned field, same as username: it must only ever be set by
an explicit admin action (Create, or the role dropdown) — never as a side
effect of a background login step. `role` mapped from IdP claims is still
applied when auto-provisioning a BRAND NEW account (no admin assignment
exists yet to protect).
"""

from __future__ import annotations

import asyncio

import pytest

from backend.auth import db as auth_db
from backend.auth import service
from backend.auth.oidc import _upsert_sso_user


def _run(coro):
    return asyncio.run(coro)


@pytest.mark.asyncio
async def test_existing_user_role_not_overwritten_by_default_role(tmp_path, monkeypatch):
    """Admin promoted a user to admin; a later SSO login with no matching
    role claim (role=default_role="threat-viewer") must NOT demote them."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()
    await auth_db.create_user(
        "alice", service.hash_password("Validpass1"), role="admin", idp="entra",
        external_id="sub-alice",
    )

    user = await _upsert_sso_user(
        username="alice",
        sub="sub-alice",
        idp="entra",
        role="threat-viewer",  # what map_claims_to_role fell back to (default_role)
        auto_provision=True,
    )

    assert user["role"] == "admin", "existing user's role must not be overwritten by SSO login"
    persisted = await auth_db.get_user_by_id(user["id"])
    assert persisted["role"] == "admin"


@pytest.mark.asyncio
async def test_existing_user_role_not_overwritten_even_when_idp_role_differs(tmp_path, monkeypatch):
    """Same guarantee when the IdP DOES supply a mapped role that differs
    from the admin-assigned one — still must not apply automatically."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()
    await auth_db.create_user(
        "bob", service.hash_password("Validpass1"), role="threat-viewer", idp="entra",
        external_id="sub-bob",
    )

    user = await _upsert_sso_user(
        username="bob",
        sub="sub-bob",
        idp="entra",
        role="admin",  # IdP claim mapped to admin this time
        auto_provision=True,
    )

    assert user["role"] == "threat-viewer"
    persisted = await auth_db.get_user_by_id(user["id"])
    assert persisted["role"] == "threat-viewer"


@pytest.mark.asyncio
async def test_existing_user_matched_by_username_role_not_overwritten(tmp_path, monkeypatch):
    """Same guarantee on the username-match path (no external_id yet — e.g.
    an existing local admin linking to SSO for the first time)."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()
    await auth_db.create_user(
        "carol", service.hash_password("Validpass1"), role="admin",
    )

    user = await _upsert_sso_user(
        username="carol",
        sub="sub-carol-new",
        idp="entra",
        role="threat-viewer",
        auto_provision=True,
    )

    assert user["role"] == "admin"
    persisted = await auth_db.get_user_by_id(user["id"])
    assert persisted["role"] == "admin"


@pytest.mark.asyncio
async def test_new_user_still_gets_provisioned_with_mapped_role(tmp_path, monkeypatch):
    """Auto-provisioning a BRAND NEW account still uses the mapped/default
    role — there is no admin assignment yet to protect."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()

    user = await _upsert_sso_user(
        username="dave@example.com",
        sub="sub-dave",
        idp="entra",
        role="threat-researcher",
        auto_provision=True,
    )

    assert user is not None
    assert user["role"] == "threat-researcher"


@pytest.mark.asyncio
async def test_existing_user_other_fields_still_resync(tmp_path, monkeypatch):
    """idp/external_id/must_change_password/org_id resync must be unaffected
    by excluding role from the UPDATE — only role is now protected."""
    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()
    await auth_db.create_user(
        "erin", service.hash_password("Validpass1"), role="admin",
        must_change_password=True,
    )

    user = await _upsert_sso_user(
        username="erin",
        sub="sub-erin",
        idp="entra",
        role="threat-viewer",
        auto_provision=True,
    )

    assert user["role"] == "admin"  # protected
    assert user["idp"] == "entra"  # still stamped
    assert user["external_id"] == "sub-erin"  # still stamped
    assert user["must_change_password"] is False  # still cleared
