"""Tests for issue-local-010: SSO / OIDC authentication support.

Coverage:
  1. oidc_config: validate_sso_config, map_claims_to_role, redaction,
     write-only-secret merge, env overrides.
  2. auth/db: v4 schema migration (idp/external_id columns, oidc_flows table),
     create_oidc_flow / consume_oidc_flow, get_user_by_external_id.
  3. oidc: _sanitize_next, _build_callback_url, URL helpers.
  4. routes: /api/auth/status includes sso_enabled/sso_button_label;
     OIDC paths are in the public allowlist.
  5. Structural: routes_auth has the SSO/OIDC endpoints.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

# ── 1. oidc_config ────────────────────────────────────────────────────────────


def test_validate_sso_config_disabled_passes_empty() -> None:
    """Disabled config with empty fields is valid (nothing is required)."""
    from backend.auth.oidc_config import validate_sso_config

    validate_sso_config({"enabled": False, "default_role": "threat-viewer"})


def test_validate_sso_config_enabled_requires_client_id() -> None:
    from backend.auth.oidc_config import validate_sso_config

    with pytest.raises(ValueError, match="client_id"):
        validate_sso_config(
            {
                "enabled": True,
                "client_id": "",
                "client_secret": "secret",
                "issuer": "https://example.com",
                "default_role": "threat-viewer",
            }
        )


def test_validate_sso_config_enabled_requires_issuer() -> None:
    from backend.auth.oidc_config import validate_sso_config

    with pytest.raises(ValueError, match="issuer"):
        validate_sso_config(
            {
                "enabled": True,
                "client_id": "some-id",
                "client_secret": "secret",
                "issuer": "",
                "default_role": "threat-viewer",
            }
        )


def test_validate_sso_config_invalid_role_in_mapping() -> None:
    from backend.auth.oidc_config import validate_sso_config

    with pytest.raises(ValueError, match="role_mapping"):
        validate_sso_config(
            {
                "enabled": False,
                "default_role": "threat-viewer",
                "role_mapping": {"group1": "not-a-role"},
            }
        )


def test_validate_sso_config_invalid_default_role() -> None:
    from backend.auth.oidc_config import validate_sso_config

    with pytest.raises(ValueError, match="default_role"):
        validate_sso_config({"enabled": False, "default_role": "superuser"})


def test_validate_sso_config_invalid_preset() -> None:
    from backend.auth.oidc_config import validate_sso_config

    with pytest.raises(ValueError, match="provider_preset"):
        validate_sso_config(
            {
                "enabled": False,
                "provider_preset": "saml2",
                "default_role": "threat-viewer",
            }
        )


def test_load_sso_config_redacts_secret(tmp_path, monkeypatch) -> None:
    """load_sso_config must always return '***' for client_secret."""
    from backend.auth import oidc_config

    monkeypatch.setattr(oidc_config, "_SSO_CONFIG_PATH", tmp_path / "sso.yaml")

    # Write a config with a real secret
    (tmp_path / "sso.yaml").write_text(
        "enabled: false\nclient_secret: my-real-secret\n",
        encoding="utf-8",
    )

    cfg = oidc_config.load_sso_config()
    assert cfg["client_secret"] == "***", "Secret must be redacted"


def test_save_sso_config_preserves_secret_on_sentinel(tmp_path, monkeypatch) -> None:
    """Saving with client_secret='***' must preserve the existing secret."""
    from backend.auth import oidc_config

    monkeypatch.setattr(oidc_config, "_SSO_CONFIG_PATH", tmp_path / "sso.yaml")

    # Seed with a real secret
    (tmp_path / "sso.yaml").write_text(
        "enabled: false\nclient_id: cid\nclient_secret: original-secret\ndefault_role: threat-viewer\n",
        encoding="utf-8",
    )

    oidc_config.save_sso_config(
        {
            "enabled": False,
            "client_id": "cid",
            "client_secret": "***",  # sentinel
            "default_role": "threat-viewer",
            "role_mapping": {},
        }
    )

    # Re-read raw file — secret must be unchanged
    saved = oidc_config._load_raw()
    assert saved["client_secret"] == "original-secret", (
        "Sentinel should not overwrite the stored secret"
    )


def test_save_sso_config_updates_secret_when_changed(tmp_path, monkeypatch) -> None:
    """Saving with a new plaintext secret must replace the old one."""
    from backend.auth import oidc_config

    monkeypatch.setattr(oidc_config, "_SSO_CONFIG_PATH", tmp_path / "sso.yaml")

    (tmp_path / "sso.yaml").write_text(
        "enabled: false\nclient_id: cid\nclient_secret: old\ndefault_role: threat-viewer\n",
        encoding="utf-8",
    )

    oidc_config.save_sso_config(
        {
            "enabled": False,
            "client_id": "cid",
            "client_secret": "new-secret",
            "default_role": "threat-viewer",
            "role_mapping": {},
        }
    )

    saved = oidc_config._load_raw()
    assert saved["client_secret"] == "new-secret"


def test_load_sso_config_env_override(tmp_path, monkeypatch) -> None:
    """OPENTARS_SSO_CLIENT_ID env var overrides yaml."""
    from backend.auth import oidc_config

    monkeypatch.setattr(oidc_config, "_SSO_CONFIG_PATH", tmp_path / "sso.yaml")
    monkeypatch.setenv("OPENTARS_SSO_CLIENT_ID", "env-client-id")
    monkeypatch.setenv("OPENTARS_SSO_ENABLED", "true")

    cfg = oidc_config.load_sso_config()
    assert cfg["client_id"] == "env-client-id"
    assert cfg["enabled"] is True


def test_load_sso_config_tenant_id_env_substitution(tmp_path, monkeypatch) -> None:
    """OPENTARS_SSO_TENANT_ID replaces <tenant_id> in the issuer."""
    from backend.auth import oidc_config

    monkeypatch.setattr(oidc_config, "_SSO_CONFIG_PATH", tmp_path / "sso.yaml")
    (tmp_path / "sso.yaml").write_text(
        "enabled: false\nissuer: 'https://login.microsoftonline.com/<tenant_id>/v2.0'\n"
        "default_role: threat-viewer\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENTARS_SSO_TENANT_ID", "my-tenant-uuid")

    cfg = oidc_config.load_sso_config()
    assert "my-tenant-uuid" in cfg["issuer"]
    assert "<tenant_id>" not in cfg["issuer"]


def test_load_sso_config_legacy_env_names_still_work(tmp_path, monkeypatch) -> None:
    """issue-local-024: the deprecated MIZTON_THREATBOX_SSO_* env var names
    still apply when the new OPENTARS_SSO_* names are absent."""
    from backend.auth import oidc_config

    monkeypatch.setattr(oidc_config, "_SSO_CONFIG_PATH", tmp_path / "sso.yaml")
    monkeypatch.delenv("OPENTARS_SSO_CLIENT_ID", raising=False)
    monkeypatch.delenv("OPENTARS_SSO_ENABLED", raising=False)
    monkeypatch.setenv("MIZTON_THREATBOX_SSO_CLIENT_ID", "legacy-client-id")
    monkeypatch.setenv("MIZTON_THREATBOX_SSO_ENABLED", "true")

    cfg = oidc_config.load_sso_config()
    assert cfg["client_id"] == "legacy-client-id"
    assert cfg["enabled"] is True


def test_load_sso_config_new_env_name_wins_over_legacy(tmp_path, monkeypatch) -> None:
    from backend.auth import oidc_config

    monkeypatch.setattr(oidc_config, "_SSO_CONFIG_PATH", tmp_path / "sso.yaml")
    monkeypatch.setenv("OPENTARS_SSO_CLIENT_ID", "new-client-id")
    monkeypatch.setenv("MIZTON_THREATBOX_SSO_CLIENT_ID", "legacy-client-id")

    cfg = oidc_config.load_sso_config()
    assert cfg["client_id"] == "new-client-id"


# ── 2. map_claims_to_role ─────────────────────────────────────────────────────


def test_map_claims_direct_match() -> None:
    from backend.auth.oidc_config import map_claims_to_role

    role = map_claims_to_role(
        {"roles": ["ThreatBox-Admin"]},
        role_claim="roles",
        role_mapping={"ThreatBox-Admin": "admin", "ThreatBox-Viewer": "threat-viewer"},
        default_role="threat-viewer",
    )
    assert role == "admin"


def test_map_claims_most_privileged_wins() -> None:
    """When a user has multiple matching roles, the most privileged is used."""
    from backend.auth.oidc_config import map_claims_to_role

    role = map_claims_to_role(
        {"roles": ["ThreatBox-Viewer", "ThreatBox-Researcher"]},
        role_claim="roles",
        role_mapping={
            "ThreatBox-Researcher": "threat-researcher",
            "ThreatBox-Viewer": "threat-viewer",
        },
        default_role="threat-viewer",
    )
    assert role == "threat-researcher"


def test_map_claims_no_match_returns_default() -> None:
    from backend.auth.oidc_config import map_claims_to_role

    role = map_claims_to_role(
        {"roles": ["SomeOtherGroup"]},
        role_claim="roles",
        role_mapping={"ThreatBox-Admin": "admin"},
        default_role="threat-viewer",
    )
    assert role == "threat-viewer"


def test_map_claims_missing_claim_returns_default() -> None:
    from backend.auth.oidc_config import map_claims_to_role

    role = map_claims_to_role(
        {},  # no roles claim at all
        role_claim="roles",
        role_mapping={"Admin": "admin"},
        default_role="threat-researcher",
    )
    assert role == "threat-researcher"


def test_map_claims_single_string_value() -> None:
    """The claim may be a scalar string, not a list."""
    from backend.auth.oidc_config import map_claims_to_role

    role = map_claims_to_role(
        {"roles": "ThreatBox-Admin"},
        role_claim="roles",
        role_mapping={"ThreatBox-Admin": "admin"},
        default_role="threat-viewer",
    )
    assert role == "admin"


def test_map_claims_empty_mapping_returns_default() -> None:
    from backend.auth.oidc_config import map_claims_to_role

    role = map_claims_to_role(
        {"roles": ["anything"]},
        role_claim="roles",
        role_mapping={},
        default_role="threat-viewer",
    )
    assert role == "threat-viewer"


# ── 3. auth/db schema v4 ──────────────────────────────────────────────────────


def test_users_schema_version_is_4() -> None:
    """SSO (v4) schema is present — schema has since advanced further
    (issue-local-016 added v5), so this asserts >= 4 rather than pinning the
    exact current version, which is covered by test_auth_db.py instead."""
    from backend.auth.db import _USERS_SCHEMA_VERSION

    assert _USERS_SCHEMA_VERSION >= 4


def test_users_table_ddl_has_idp_and_external_id() -> None:
    """CREATE_USERS_TABLE DDL does NOT include new cols (they're added via migration),
    but the migration code must reference them."""
    import inspect

    from backend.auth import db as auth_db

    source = inspect.getsource(auth_db._migrate_users_schema)
    assert "idp" in source
    assert "external_id" in source


def test_create_oidc_flow_is_defined() -> None:
    import inspect

    from backend.auth import db as auth_db

    assert hasattr(auth_db, "create_oidc_flow")
    assert inspect.iscoroutinefunction(auth_db.create_oidc_flow)


def test_consume_oidc_flow_is_defined() -> None:
    import inspect

    from backend.auth import db as auth_db

    assert hasattr(auth_db, "consume_oidc_flow")
    assert inspect.iscoroutinefunction(auth_db.consume_oidc_flow)


def test_get_user_by_external_id_is_defined() -> None:
    import inspect

    from backend.auth import db as auth_db

    assert hasattr(auth_db, "get_user_by_external_id")
    assert inspect.iscoroutinefunction(auth_db.get_user_by_external_id)


@pytest.mark.asyncio
async def test_oidc_flow_create_consume_roundtrip(tmp_path, monkeypatch) -> None:
    """create_oidc_flow then consume_oidc_flow returns the flow and removes it."""
    from backend.auth import db as auth_db

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
    await auth_db.init_users_db()

    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    await auth_db.create_oidc_flow(
        state="s1",
        nonce="n1",
        code_verifier="cv1",
        next_path="/viewer",
        expires_at=expires_at,
    )

    flow = await auth_db.consume_oidc_flow("s1")
    assert flow is not None
    assert flow["state"] == "s1"
    assert flow["nonce"] == "n1"
    assert flow["code_verifier"] == "cv1"
    assert flow["next_path"] == "/viewer"

    # Second consume must return None (atomically deleted)
    again = await auth_db.consume_oidc_flow("s1")
    assert again is None


@pytest.mark.asyncio
async def test_oidc_flow_expired_returns_none(tmp_path, monkeypatch) -> None:
    """consume_oidc_flow returns None for an expired flow."""
    from backend.auth import db as auth_db

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users_exp.db")
    await auth_db.init_users_db()

    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    await auth_db.create_oidc_flow("s_exp", "n_exp", "cv_exp", "/", past)

    flow = await auth_db.consume_oidc_flow("s_exp")
    assert flow is None


@pytest.mark.asyncio
async def test_get_user_by_external_id_roundtrip(tmp_path, monkeypatch) -> None:
    """create_user with idp/external_id, then get_user_by_external_id returns it."""
    from backend.auth import db as auth_db

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users_ext.db")
    await auth_db.init_users_db()

    await auth_db.create_user(
        "sso.user@example.com",
        "unused-hash",
        role="threat-viewer",
        idp="entra",
        external_id="sub-12345",
    )

    user = await auth_db.get_user_by_external_id("entra", "sub-12345")
    assert user is not None
    assert user["username"] == "sso.user@example.com"
    assert user["idp"] == "entra"
    assert user["external_id"] == "sub-12345"

    # Non-existent external_id returns None
    missing = await auth_db.get_user_by_external_id("entra", "not-exist")
    assert missing is None


@pytest.mark.asyncio
async def test_users_schema_v4_migration_idempotent(tmp_path, monkeypatch) -> None:
    """Calling init_users_db twice does not raise (migration is idempotent)."""
    from backend.auth import db as auth_db

    monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users_idem.db")
    await auth_db.init_users_db()
    # Second call must not raise
    await auth_db.init_users_db()


# ── 4. oidc URL helpers ───────────────────────────────────────────────────────


def test_sanitize_next_allows_plain_path() -> None:
    from backend.auth.oidc import _sanitize_next

    assert _sanitize_next("/viewer") == "/viewer"
    assert _sanitize_next("/threat-hunting") == "/threat-hunting"


def test_sanitize_next_rejects_external_url() -> None:
    from backend.auth.oidc import _sanitize_next

    assert _sanitize_next("https://evil.com/steal") == "/"
    assert _sanitize_next("http://localhost/other") == "/"


def test_sanitize_next_empty_returns_root() -> None:
    from backend.auth.oidc import _sanitize_next

    assert _sanitize_next("") == "/"


def test_build_callback_url() -> None:
    from backend.auth.oidc import _build_callback_url

    url = _build_callback_url("https://example.com/")
    assert url == "https://example.com/api/auth/oidc/callback"


def test_build_callback_url_with_prefix() -> None:
    """When the app is mounted under a sub-path, the prefix is included in the callback URL."""
    from backend.auth.oidc import _build_callback_url

    url = _build_callback_url("https://example.com/threatbox/")
    # The prefix IS included — this is the URL that must be registered in the IdP
    assert url == "https://example.com/threatbox/api/auth/oidc/callback"


def test_get_callback_url_for_display() -> None:
    from backend.auth.oidc import get_callback_url_for_display

    url = get_callback_url_for_display("https://host.example.com/")
    assert "oidc/callback" in url
    assert url.startswith("https://")


# ── 5. routes: /api/auth/status SSO fields ───────────────────────────────────


def test_auth_status_route_includes_sso_fields() -> None:
    """auth_status handler must include sso_enabled and sso_button_label."""
    import inspect

    from backend.api import routes_auth

    source = inspect.getsource(routes_auth.auth_status)
    assert "sso_enabled" in source
    assert "sso_button_label" in source


# ── 6. Public allowlist includes OIDC paths ───────────────────────────────────


def test_oidc_paths_in_public_allowlist() -> None:
    from backend.main import _PUBLIC_API_PATHS

    assert "/api/auth/oidc/login" in _PUBLIC_API_PATHS
    assert "/api/auth/oidc/callback" in _PUBLIC_API_PATHS


# ── 7. SSO admin endpoints are defined in routes_auth ─────────────────────────


def test_routes_auth_has_sso_endpoints() -> None:
    """routes_auth must expose /sso/config GET, PUT and /sso/callback-url."""
    import inspect

    from backend.api import routes_auth

    source = inspect.getsource(routes_auth)
    assert "/sso/config" in source
    assert "/sso/callback-url" in source
    assert "get_sso_config" in source
    assert "update_sso_config" in source
    assert "get_sso_callback_url" in source


def test_oidc_login_endpoint_in_routes() -> None:
    """routes_auth must expose /oidc/login and /oidc/callback."""
    import inspect

    from backend.api import routes_auth

    source = inspect.getsource(routes_auth)
    assert "/oidc/login" in source
    assert "/oidc/callback" in source
