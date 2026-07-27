"""
OIDC / SSO provider configuration (issue-local-010).

Mirrors the write-only-secret hygiene pattern from ``backend/llm/config.py``:
  - Config is stored in the gitignored ``config/sso.yaml`` (committed example
    at ``config/sso.yaml.example``).
  - ``client_secret`` is write-only: always redacted to ``"***"`` on reads.
  - ``merge_write_only_key`` preserves the stored secret when the API sends
    back ``"***"`` (i.e. the admin saved without changing the secret field).
  - Env vars override yaml values (``OPENTARS_SSO_*`` prefix; the deprecated
    ``MIZTON_THREATBOX_SSO_*`` prefix still works as a fallback).

Provider presets
----------------
  entra    — Microsoft Entra ID / Azure AD
               issuer: https://login.microsoftonline.com/<tenant_id>/v2.0
  okta     — Okta (set issuer to your org domain)
  google   — Google Workspace
               issuer: https://accounts.google.com
  keycloak — self-hosted Keycloak realm
  generic  — any OIDC provider with a discovery endpoint

Role mapping
------------
Configure ``role_claim`` (the JWT claim that carries group/role names) and
``role_mapping`` (a dict mapping claim value → app role).  Unmapped users
get ``default_role`` (default ``"threat-viewer"``).

Example ``config/sso.yaml``::

    enabled: true
    provider_preset: entra
    issuer: "https://login.microsoftonline.com/<tenant-id>/v2.0"
    client_id: "<your-client-id>"
    client_secret: "<your-client-secret>"
    scopes: "openid profile email"
    button_label: "Sign in with Microsoft"
    username_claim: preferred_username
    role_claim: roles
    role_mapping:
      OpenTARS-Admin: admin
      OpenTARS-Researcher: threat-researcher
      OpenTARS-Viewer: threat-viewer
    default_role: threat-viewer
    auto_provision: true
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from backend.config.loader import env_with_legacy_fallback

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SSO_CONFIG_PATH = _PROJECT_ROOT / "config" / "sso.yaml"

# Env-var overrides (issue-local-024: renamed from MIZTON_THREATBOX_SSO_* to
# OPENTARS_SSO_*; each deprecated old name still works via
# env_with_legacy_fallback's warn-and-fall-back behaviour). Shared by
# load_sso_config() and load_sso_config_for_use() via _apply_sso_env_overrides.
_SSO_ENV_MAP: dict[str, tuple[str, str, Callable[[str], Any]]] = {
    "OPENTARS_SSO_ENABLED": (
        "MIZTON_THREATBOX_SSO_ENABLED",
        "enabled",
        lambda v: v.lower() in {"1", "true", "yes", "on"},
    ),
    "OPENTARS_SSO_CLIENT_ID": ("MIZTON_THREATBOX_SSO_CLIENT_ID", "client_id", str),
    "OPENTARS_SSO_CLIENT_SECRET": ("MIZTON_THREATBOX_SSO_CLIENT_SECRET", "client_secret", str),
    "OPENTARS_SSO_ISSUER": ("MIZTON_THREATBOX_SSO_ISSUER", "issuer", str),
    "OPENTARS_SSO_BUTTON_LABEL": ("MIZTON_THREATBOX_SSO_BUTTON_LABEL", "button_label", str),
    "OPENTARS_SSO_DEFAULT_ROLE": ("MIZTON_THREATBOX_SSO_DEFAULT_ROLE", "default_role", str),
}
_SSO_TENANT_ID_ENV = "OPENTARS_SSO_TENANT_ID"
_SSO_TENANT_ID_ENV_LEGACY = "MIZTON_THREATBOX_SSO_TENANT_ID"


def _apply_sso_env_overrides(cfg: dict[str, Any]) -> None:
    """Mutate *cfg* in place with env-var overrides.

    Shared by :func:`load_sso_config` and :func:`load_sso_config_for_use` so
    the override list only needs to exist once.
    """
    for new_key, (legacy_key, cfg_key, cast) in _SSO_ENV_MAP.items():
        val = env_with_legacy_fallback(new_key, legacy_key)
        if val is not None:
            cfg[cfg_key] = cast(val)

    tenant_id = env_with_legacy_fallback(_SSO_TENANT_ID_ENV, _SSO_TENANT_ID_ENV_LEGACY)
    if tenant_id and cfg.get("issuer"):
        cfg["issuer"] = (
            cfg["issuer"].replace("<tenant_id>", tenant_id).replace("<tenant-id>", tenant_id)
        )


# Supported presets
PROVIDER_PRESETS = frozenset({"entra", "okta", "google", "keycloak", "generic"})

# Well-known issuer URLs for presets (tenant_id placeholder for Entra)
PRESET_ISSUERS: dict[str, str] = {
    "google": "https://accounts.google.com",
}

# App roles accepted in role_mapping values
_VALID_ROLES = frozenset({"admin", "threat-researcher", "threat-viewer", "feed-sender"})

# Sentinel — write-only secret placeholder
_REDACTED = "***"

# ── Default config ─────────────────────────────────────────────────────────────

_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "provider_preset": "generic",
    "issuer": "",
    "client_id": "",
    "client_secret": "",
    "scopes": "openid profile email",
    "button_label": "Sign in with SSO",
    "username_claim": "preferred_username",
    "role_claim": "roles",
    "role_mapping": {},
    "default_role": "threat-viewer",
    "auto_provision": True,
}


# ── File I/O ──────────────────────────────────────────────────────────────────


def _load_raw() -> dict[str, Any]:
    if not _SSO_CONFIG_PATH.exists():
        return {}
    try:
        text = _SSO_CONFIG_PATH.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.warning("sso.yaml load error: %s", exc)
        return {}


def _write_raw(data: dict[str, Any]) -> None:
    _SSO_CONFIG_PATH.parent.mkdir(exist_ok=True)
    _SSO_CONFIG_PATH.write_text(
        yaml.dump(data, allow_unicode=True, default_flow_style=False),
        encoding="utf-8",
    )


# ── Public API ────────────────────────────────────────────────────────────────


def load_sso_config() -> dict[str, Any]:
    """Return the current SSO config, redacting the client_secret.

    Env-var overrides (``OPENTARS_SSO_*``, or the deprecated
    ``MIZTON_THREATBOX_SSO_*`` names) take precedence over yaml. The returned
    dict always has all default keys present.
    """
    raw = _load_raw()
    cfg: dict[str, Any] = {**_DEFAULTS, **raw}

    _apply_sso_env_overrides(cfg)

    # Redact secret
    cfg["client_secret"] = _REDACTED if cfg.get("client_secret") else ""
    return cfg


def save_sso_config(new_cfg: dict[str, Any]) -> None:
    """Validate and persist SSO config to sso.yaml.

    Write-only-key handling: if ``client_secret`` is ``"***"``, preserve the
    existing stored value rather than overwriting with the sentinel.
    """
    validate_sso_config(new_cfg)
    existing = _load_raw()
    merged = {**_DEFAULTS, **existing}
    for k, v in new_cfg.items():
        if k == "client_secret":
            # Preserve existing secret when sentinel sent back
            if v != _REDACTED:
                merged["client_secret"] = v
        else:
            merged[k] = v
    _write_raw(merged)


def load_sso_config_for_use() -> dict[str, Any]:
    """Return the SSO config with the plaintext client_secret for internal use.

    Never return this dict to the API layer — use ``load_sso_config()`` there.
    """
    raw = _load_raw()
    cfg: dict[str, Any] = {**_DEFAULTS, **raw}

    _apply_sso_env_overrides(cfg)
    return cfg


def validate_sso_config(cfg: dict[str, Any]) -> None:
    """Raise ValueError with a descriptive message on invalid config."""
    if not isinstance(cfg, dict):
        raise ValueError("SSO config must be a dict")

    preset = cfg.get("provider_preset", "generic")
    if preset not in PROVIDER_PRESETS:
        raise ValueError(
            f"provider_preset must be one of {sorted(PROVIDER_PRESETS)}; got {preset!r}"
        )

    if cfg.get("enabled"):
        if not cfg.get("client_id"):
            raise ValueError("client_id is required when SSO is enabled")
        secret = cfg.get("client_secret", "")
        if not secret or secret == _REDACTED:
            # Allow sentinel (means "keep existing") when config already has one
            existing_secret = _load_raw().get("client_secret", "")
            if not existing_secret:
                raise ValueError("client_secret is required when SSO is enabled")
        issuer = cfg.get("issuer", "")
        if not issuer:
            raise ValueError("issuer is required when SSO is enabled")
        if not issuer.startswith(("https://", "http://")):
            raise ValueError("issuer must be a URL starting with https:// (or http:// for dev)")

    default_role = cfg.get("default_role", "threat-viewer")
    if default_role not in _VALID_ROLES:
        raise ValueError(f"default_role must be one of {sorted(_VALID_ROLES)}")

    role_mapping = cfg.get("role_mapping", {})
    if not isinstance(role_mapping, dict):
        raise ValueError("role_mapping must be a dict (claim_value -> app_role)")
    for claim_val, role in role_mapping.items():
        if role not in _VALID_ROLES:
            raise ValueError(
                f"role_mapping[{claim_val!r}] = {role!r} is not a valid role; "
                f"valid: {sorted(_VALID_ROLES)}"
            )


def map_claims_to_role(
    claims: dict[str, Any],
    role_claim: str,
    role_mapping: dict[str, str],
    default_role: str,
) -> str:
    """Map IdP token claims to an app role.

    The ``role_claim`` value may be a list of strings (e.g. Entra ``roles``)
    or a single string.  If multiple claim values appear in ``role_mapping``,
    the *most privileged* matching role is returned (admin > researcher > viewer).

    Returns ``default_role`` if no claim value matches.
    """
    _ROLE_PRIORITY = {
        "admin": 4,
        "threat-researcher": 3,
        "threat-viewer": 2,
        "feed-sender": 1,
    }

    raw = claims.get(role_claim)
    if raw is None:
        return default_role

    claim_values: list[str] = raw if isinstance(raw, list) else [str(raw)]

    best: str | None = None
    best_priority = -1
    for cv in claim_values:
        mapped = role_mapping.get(cv)
        if mapped and _ROLE_PRIORITY.get(mapped, 0) > best_priority:
            best = mapped
            best_priority = _ROLE_PRIORITY[mapped]

    return best if best is not None else default_role
