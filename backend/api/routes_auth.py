"""
Authentication routes (prompts-045) — /api/auth.

Public:
  POST /api/auth/login     — exchange credentials for a session cookie
  GET  /api/auth/status    — whether auth is enabled (for the SPA bootstrap)

Authenticated (any role):
  POST /api/auth/logout    — revoke the current session
  GET  /api/auth/me        — current user profile
  PUT  /api/auth/password  — change own password

Admin only (user management):
  GET    /api/auth/users
  POST   /api/auth/users
  PUT    /api/auth/users/{user_id}/role
  PUT    /api/auth/users/{user_id}/enabled
  PUT    /api/auth/users/{user_id}/password
  PUT    /api/auth/users/{user_id}/organization
  DELETE /api/auth/users/{user_id}

Admin only (organization management — issue-local-037):
  GET    /api/auth/organizations
  POST   /api/auth/organizations
  PUT    /api/auth/organizations/{org_id}
  DELETE /api/auth/organizations/{org_id}

Admin only (API access keys — issue-local-029):
  GET    /api/auth/api-keys/config
  PUT    /api/auth/api-keys/config
  GET    /api/auth/api-keys/scopes
  GET    /api/auth/api-keys
  POST   /api/auth/api-keys
  PUT    /api/auth/api-keys/{client_id}
  DELETE /api/auth/api-keys/{client_id}
  POST   /api/auth/api-keys/{client_id}/test
"""

from __future__ import annotations

import logging
import re
import secrets

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from backend.audit.db import record_event
from backend.auth import db
from backend.auth.api_scopes import DEFAULT_PROFILE_SCOPES, list_scopes, valid_scope_ids
from backend.auth.dependencies import (
    clear_session_cookie,
    get_current_user,
    require_admin,
    set_session_cookie,
)
from backend.auth.oidc_config import load_sso_config, save_sso_config
from backend.auth.organizations import build_username, local_part_of, validate_organization
from backend.auth.service import (
    SESSION_COOKIE_NAME,
    SESSION_TTL,
    authenticate,
    create_api_key,
    create_session_for_user,
    destroy_session,
    hash_password,
    hash_token,
    verify_password,
)
from backend.config.loader import (
    load_api_access_enabled,
    load_app_base_prefix,
    load_auth_enabled,
    load_password_policy,
    save_api_access_enabled,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
_MAX_PASSWORD_LEN = 72  # bcrypt hard limit (fixed)

# Character-class detectors for the configurable complexity policy.
_CLASS_PATTERNS = (
    ("lowercase", re.compile(r"[a-z]")),
    ("uppercase", re.compile(r"[A-Z]")),
    ("number", re.compile(r"[0-9]")),
    ("symbol", re.compile(r"[^A-Za-z0-9]")),
)


def _password_class_count(password: str) -> int:
    """Count how many of the four character classes appear in *password*."""
    return sum(1 for _name, rx in _CLASS_PATTERNS if rx.search(password))


# ── Request models ────────────────────────────────────────────────────────────


class LoginBody(BaseModel):
    username: str
    password: str


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str


class ThemeBody(BaseModel):
    # None clears a personal override — falls back to the instance default.
    theme: str | None = None


class CreateUserBody(BaseModel):
    # issue-local-037: `username` is always the LOCAL PART — never a full
    # email typed by the admin. See backend.auth.organizations.build_username
    # for why the "@org-domain" suffix (when applicable) is always
    # constructed server-side instead.
    username: str
    password: str
    role: str = "threat-viewer"
    org_id: int | None = None
    use_email_username: bool = True


class RoleBody(BaseModel):
    role: str


class EnabledBody(BaseModel):
    enabled: bool


class OrganizationBody(BaseModel):
    name: str
    email_domain: str


class SetUserOrganizationBody(BaseModel):
    org_id: int | None = None
    use_email_username: bool = True


# ── Helpers ───────────────────────────────────────────────────────────────────


def _client_ip(request: Request) -> str:
    """Client IP used to key the login brute-force throttle.

    Security (prompts-045 audit, MAJOR #2): we deliberately use the real socket
    peer (`request.client.host`) and do NOT trust `X-Forwarded-For`. XFF is
    attacker-controlled, so honouring it would let a client rotate the header on
    each attempt and bypass the per-(username, ip) throttle entirely. Behind a
    trusted reverse proxy this collapses to the proxy's address, which only
    makes the throttle more conservative (per-username), never weaker. If you
    terminate behind a proxy and need true client IPs here, add an explicit
    trusted-proxy allowlist before re-introducing XFF parsing.
    """
    return request.client.host if request.client else "unknown"


def _safe_error_param(error: str) -> str:
    """Return a URL-safe error code (strip any attacker-supplied content)."""
    import re as _re

    return _re.sub(r"[^A-Za-z0-9_-]", "_", str(error))[:40]


def _validate_username(username: str) -> None:
    if not _USERNAME_RE.match(username or ""):
        raise HTTPException(
            status_code=400,
            detail="Username must be 1-40 chars of letters, digits, '.', '_' or '-'",
        )


def _validate_password(password: str) -> None:
    policy = load_password_policy()
    min_length = policy["min_length"]
    required_classes = policy["required_classes"]
    if not isinstance(password, str) or len(password) < min_length:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {min_length} characters",
        )
    if len(password.encode("utf-8")) > _MAX_PASSWORD_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at most {_MAX_PASSWORD_LEN} bytes",
        )
    if _password_class_count(password) < required_classes:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Password must include at least {required_classes} of: "
                "lowercase, uppercase, number, symbol"
            ),
        )


def _public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "enabled": user["enabled"],
        "created_at": user.get("created_at"),
        "must_change_password": bool(user.get("must_change_password")),
        # issue-local-013: expose idp so the SPA can exempt SSO users from the
        # forced-password-reset screen without an extra round trip.
        "idp": user.get("idp") or None,
        # issue-local-016: personal theme override, or None to use the
        # instance-wide default (GET /api/app/theme).
        "theme": user.get("theme") or None,
        # issue-local-037: organization FK, or None ("Local user"). The
        # frontend resolves this to a name/domain against the organizations
        # list it already fetches for the Create/Change-Organization
        # dropdown — no separate org lookup/join needed here.
        "org_id": user.get("org_id"),
    }


# ── Public ────────────────────────────────────────────────────────────────────


@router.get("/status")
async def auth_status() -> dict:
    """Report whether authentication enforcement is active (public).

    Also publishes the password policy so the SPA can mirror server-side
    validation. The policy is non-sensitive (length + character-class counts).

    issue-local-010: also publishes SSO availability so the login page can
    show the SSO button without an extra round trip.
    """
    sso_cfg = load_sso_config()
    return {
        "auth_enabled": load_auth_enabled(),
        "password_policy": load_password_policy(),
        "sso_enabled": bool(sso_cfg.get("enabled")),
        "sso_button_label": sso_cfg.get("button_label", "Sign in with SSO"),
    }


# ── OIDC / SSO endpoints (issue-local-010) ───────────────────────────────────


@router.get("/oidc/login")
async def oidc_login(request: Request, next: str = "/") -> Response:
    """Initiate an OIDC Authorization Code flow.

    Redirects the browser to the IdP's authorize endpoint.
    Public — no session required.
    """
    from fastapi.responses import RedirectResponse

    from backend.auth.oidc import build_authorization_url

    try:
        authorize_url = await build_authorization_url(
            request_base_url=str(request.base_url),
            next_path=next,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("OIDC login initiation failed: %s", exc)
        raise HTTPException(status_code=502, detail="SSO initiation failed") from exc

    return RedirectResponse(url=authorize_url, status_code=302)


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    response: Response,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> Response:
    """Handle the OIDC authorization callback from the IdP.

    On success: mints a session cookie and redirects to the SPA.
    On failure: redirects to the login page with an error parameter.
    Public — no session required.
    """
    from fastapi.responses import RedirectResponse

    from backend.auth.oidc import handle_callback
    from backend.auth.service import SESSION_TTL

    # IdP returned an error
    if error:
        logger.warning("OIDC callback error from IdP: %s — %s", error, error_description)
        return RedirectResponse(
            url=f"/login?sso_error={_safe_error_param(error)}",
            status_code=302,
        )

    if not code or not state:
        return RedirectResponse(url="/login?sso_error=missing_params", status_code=302)

    try:
        _user_id, raw_token, next_path = await handle_callback(
            code=code,
            state=state,
            request_base_url=str(request.base_url),
        )
    except ValueError as exc:
        logger.warning("OIDC callback rejected: %s", exc)
        return RedirectResponse(url="/login?sso_error=auth_failed", status_code=302)
    except Exception as exc:
        logger.exception("OIDC callback unexpected error: %s", exc)
        return RedirectResponse(url="/login?sso_error=server_error", status_code=302)

    redirect = RedirectResponse(url=next_path or "/viewer", status_code=302)
    set_session_cookie(request, redirect, raw_token, max_age=int(SESSION_TTL.total_seconds()))
    return redirect


# ── SSO config admin API (issue-local-010) ───────────────────────────────────


class SsoConfigBody(BaseModel):
    enabled: bool = False
    provider_preset: str = "generic"
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""
    scopes: str = "openid profile email"
    button_label: str = "Sign in with SSO"
    username_claim: str = "preferred_username"
    role_claim: str = "roles"
    role_mapping: dict[str, str] = {}
    default_role: str = "threat-viewer"
    auto_provision: bool = True
    # issue-local-036: overrides the request-derived scheme+host+path used to
    # build the redirect_uri sent to the IdP — see oidc_config.py's
    # _DEFAULTS entry for why this exists separately from app_base_prefix.
    callback_base_url: str = ""


@router.get("/sso/config")
async def get_sso_config(_user: dict = Depends(require_admin)) -> dict:
    """Return the current SSO config (client_secret redacted). Admin only."""
    return load_sso_config()


@router.put("/sso/config")
async def update_sso_config(
    body: SsoConfigBody,
    _user: dict = Depends(require_admin),
) -> dict:
    """Validate and persist SSO config. Admin only.

    Sends back the redacted config so the UI can reflect the saved state.
    """
    cfg = body.model_dump()
    try:
        save_sso_config(cfg)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return load_sso_config()


@router.get("/sso/callback-url")
async def get_sso_callback_url(request: Request, _user: dict = Depends(require_admin)) -> dict:
    """Return the OIDC callback URL that must be registered in the IdP. Admin only.

    issue-local-036: reflects callback_base_url when set, so this always
    shows the URL actually used by the login/callback flow, not just the
    current request's own (possibly un-aliased) base URL.
    """
    from backend.auth.oidc import get_callback_url_for_display
    from backend.auth.oidc_config import load_sso_config_for_use

    cfg = load_sso_config_for_use()
    return {
        "callback_url": get_callback_url_for_display(
            str(request.base_url), cfg.get("callback_base_url", "")
        )
    }


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response) -> dict:
    """Authenticate and start a session. Generic error on any failure.

    issue-local-033: login is the one action the generic user-activity audit
    middleware (main.py) structurally cannot attribute — there is no session
    cookie yet at the START of this request for it to resolve an actor from.
    Instrumented directly here instead, both on success and failure (a
    failed-login trail is itself security-relevant). Never logs the
    password; the attempted username is not secret in this app's threat
    model (it's the same value shown throughout the UI/API for that user).
    """
    user = await authenticate(body.username, body.password, _client_ip(request))
    if user is None:
        try:
            await record_event(
                "user",
                "Failed sign-in attempt",
                username=body.username,
                summary=f"Failed login attempt for '{body.username}'",
                detail={"ip": _client_ip(request)},
            )
        except Exception as exc:  # noqa: BLE001 — best-effort, never break login
            logger.warning("login: audit record_event failed: %s", exc)
        # Single generic message — never reveal whether the username exists,
        # the password was wrong, the account is disabled, or it was throttled.
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = await create_session_for_user(user["id"])
    set_session_cookie(request, response, token, max_age=int(SESSION_TTL.total_seconds()))
    try:
        await record_event(
            "user",
            "Signed in",
            username=user["username"],
            role=user.get("role"),
            summary=f"'{user['username']}' logged in",
            detail={"ip": _client_ip(request)},
        )
    except Exception as exc:  # noqa: BLE001 — best-effort, never break login
        logger.warning("login: audit record_event failed: %s", exc)
    return {"user": _public_user(user)}


# ── Authenticated (any role) ──────────────────────────────────────────────────


@router.post("/logout")
async def logout(request: Request, response: Response) -> dict:
    """Revoke the current session and clear the cookie."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        await destroy_session(token)
    clear_session_cookie(request, response)
    return {"status": "logged_out"}


@router.get("/me")
async def me(user: dict = Depends(get_current_user)) -> dict:
    return {"user": _public_user(user)}


@router.put("/password")
async def change_own_password(
    body: ChangePasswordBody,
    request: Request,
    response: Response,
    user: dict = Depends(get_current_user),
) -> dict:
    """Change the caller's own password (requires the current password)."""
    full = await db.get_user_by_id(user["id"])
    if full is None or not verify_password(body.current_password, full["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(
            status_code=400,
            detail="New password must differ from the current password",
        )
    _validate_password(body.new_password)
    # Revoke every other session for this user (a changed password should evict
    # any other live cookie) but keep the caller's current session alive.
    token = request.cookies.get(SESSION_COOKIE_NAME)
    keep = hash_token(token) if token else None
    await db.set_password(user["id"], hash_password(body.new_password), keep_token_hash=keep)
    return {"status": "password_changed"}


@router.put("/me/theme")
async def set_own_theme(body: ThemeBody, user: dict = Depends(get_current_user)) -> dict:
    """Set (or clear) the caller's personal theme override (issue-local-016).

    `theme: null` clears the override — the caller then follows the
    instance-wide default (GET /api/app/theme). Any authenticated user may
    call this regardless of role — see backend/main.py's _SELF_PATHS.
    """
    if body.theme is not None and body.theme not in db.VALID_THEMES:
        raise HTTPException(
            status_code=400,
            detail=f"theme must be one of {sorted(db.VALID_THEMES)}, or null",
        )
    await db.set_theme(user["id"], body.theme)
    return _public_user(await db.get_user_by_id(user["id"]))


# ── Admin: user management ────────────────────────────────────────────────────


@router.get("/users")
async def list_users(admin: dict = Depends(require_admin)) -> list[dict]:
    # issue-local-037 follow-up: this used to return db.list_users()'s raw
    # dicts directly, which — unlike every other endpoint on this router —
    # leaked `external_id` (the SSO subject claim) since it isn't part of
    # _public_user's curated shape. Routing through _public_user here too
    # fixes that pre-existing inconsistency and is what makes the new
    # org_id field show up in the list the same way it does everywhere else.
    return [_public_user(u) for u in await db.list_users()]


@router.post("/users")
async def create_user(body: CreateUserBody, admin: dict = Depends(require_admin)) -> dict:
    # body.username is always the LOCAL PART (see CreateUserBody) — validated
    # as such regardless of whether an org suffix ends up appended below.
    _validate_username(body.username)
    _validate_password(body.password)
    if body.role not in db.VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail="role must be 'admin', 'threat-researcher', 'threat-viewer', or 'feed-sender'",
        )
    org = None
    if body.org_id is not None:
        org = await db.get_organization(body.org_id)
        if org is None:
            raise HTTPException(status_code=404, detail="Organization not found")
    final_username = build_username(body.username, org, body.use_email_username)
    if await db.get_user_by_username(final_username) is not None:
        raise HTTPException(status_code=409, detail="Username already exists")
    # An admin-supplied password is, from the new user's perspective, the
    # same trust situation as an admin reset (issue-local-016) — force it to
    # be changed on first login rather than trusting it stays private.
    uid = await db.create_user(
        final_username,
        hash_password(body.password),
        role=body.role,
        must_change_password=True,
        org_id=body.org_id,
    )
    created = await db.get_user_by_id(uid)
    return _public_user(created)


@router.put("/users/{user_id}/role")
async def set_user_role(user_id: int, body: RoleBody, admin: dict = Depends(require_admin)) -> dict:
    if body.role not in db.VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail="role must be 'admin', 'threat-researcher', 'threat-viewer', or 'feed-sender'",
        )
    target = await _require_user(user_id)
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    # Demoting the last remaining admin would lock everyone out.
    if target["role"] == "admin" and body.role != "admin":
        if await db.count_admins(exclude_id=user_id) == 0:
            raise HTTPException(status_code=400, detail="Cannot demote the last admin")
    await db.set_role(user_id, body.role)
    return _public_user(await db.get_user_by_id(user_id))


@router.put("/users/{user_id}/enabled")
async def set_user_enabled(
    user_id: int, body: EnabledBody, admin: dict = Depends(require_admin)
) -> dict:
    target = await _require_user(user_id)
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")
    if not body.enabled and target["role"] == "admin":
        if await db.count_admins(exclude_id=user_id) == 0:
            raise HTTPException(status_code=400, detail="Cannot disable the last admin")
    await db.set_enabled(user_id, body.enabled)
    return _public_user(await db.get_user_by_id(user_id))


@router.put("/users/{user_id}/password")
async def admin_reset_password(user_id: int, admin: dict = Depends(require_admin)) -> dict:
    """Reset a user's password to a fresh random value (issue-local-016).

    The admin no longer chooses the new password — it's generated server-side
    (same `secrets.token_urlsafe(18)` pattern as `service.reset_admin_password`)
    and returned once in this response so the admin can hand it to the user
    out-of-band; it is never stored or logged. The target is flagged
    `must_change_password=True`, so they're forced through the existing
    forced-password-change flow on next login (backend/main.py's
    `auth_enforcement` middleware + ProtectedLayout's forced-reset screen
    already enforce this unconditionally — no other code needed). Admin reset
    also evicts ALL of the target's sessions (keep_token_hash=None), so
    resetting a compromised account immediately logs the attacker out.
    """
    target = await _require_user(user_id)
    new_password = secrets.token_urlsafe(18)
    await db.set_password(user_id, hash_password(new_password), must_change_password=True)
    return {
        "status": "password_reset",
        "username": target["username"],
        "generated_password": new_password,
    }


@router.delete("/users/{user_id}")
async def delete_user(user_id: int, admin: dict = Depends(require_admin)) -> dict:
    target = await _require_user(user_id)
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    if target["role"] == "admin" and await db.count_admins(exclude_id=user_id) == 0:
        raise HTTPException(status_code=400, detail="Cannot delete the last admin")
    await db.delete_user(user_id)
    return {"status": "deleted", "id": user_id}


@router.put("/users/{user_id}/organization")
async def set_user_organization(
    user_id: int, body: SetUserOrganizationBody, admin: dict = Depends(require_admin)
) -> dict:
    """Move a user to a different (or no) organization (issue-local-037).

    The username is recomputed from the user's EXISTING local-part (whatever
    they already log in with) + the newly selected org/checkbox — never from
    a client-typed string — so it stays consistent with build_username's
    single source of truth. Raises 409 if the recomputed username collides
    with a different existing user.
    """
    target = await _require_user(user_id)
    org = None
    if body.org_id is not None:
        org = await db.get_organization(body.org_id)
        if org is None:
            raise HTTPException(status_code=404, detail="Organization not found")
    local_part = local_part_of(target["username"])
    final_username = build_username(local_part, org, body.use_email_username)
    existing = await db.get_user_by_username(final_username)
    if existing is not None and existing["id"] != user_id:
        raise HTTPException(status_code=409, detail="Username already exists")
    if final_username != target["username"] or body.org_id != target.get("org_id"):
        ok = await db.set_user_username_and_org(user_id, final_username, body.org_id)
        if not ok:
            raise HTTPException(status_code=409, detail="Username already exists")
    return _public_user(await db.get_user_by_id(user_id))


async def _require_user(user_id: int) -> dict:
    user = await db.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# ── Organization management (issue-local-037) ───────────────────────────────


def _public_organization(org: dict) -> dict:
    return {
        "id": org["id"],
        "name": org["name"],
        "email_domain": org["email_domain"],
        "created_at": org.get("created_at"),
        "user_count": org.get("user_count", 0),
    }


@router.get("/organizations")
async def list_organizations(admin: dict = Depends(require_admin)) -> list[dict]:
    return [_public_organization(o) for o in await db.list_organizations()]


@router.post("/organizations", status_code=201)
async def create_organization(
    body: OrganizationBody, admin: dict = Depends(require_admin)
) -> dict:
    try:
        name, email_domain = validate_organization(body.name, body.email_domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        org_id = await db.create_organization(name, email_domain)
    except aiosqlite.IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="Organization name or email domain already exists"
        ) from exc
    return _public_organization(await db.get_organization(org_id))


@router.put("/organizations/{org_id}")
async def update_organization(
    org_id: int, body: OrganizationBody, admin: dict = Depends(require_admin)
) -> dict:
    if await db.get_organization(org_id) is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    try:
        name, email_domain = validate_organization(body.name, body.email_domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        ok = await db.update_organization(org_id, name, email_domain)
    except aiosqlite.IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="Organization name or email domain already exists"
        ) from exc
    if not ok:
        raise HTTPException(status_code=404, detail="Organization not found")
    return _public_organization(await db.get_organization(org_id))


@router.delete("/organizations/{org_id}")
async def delete_organization(org_id: int, admin: dict = Depends(require_admin)) -> dict:
    if await db.get_organization(org_id) is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    count = await db.count_users_in_org(org_id)
    if count > 0:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete: {count} user(s) are assigned to this organization",
        )
    await db.delete_organization(org_id)
    return {"status": "deleted", "id": org_id}


# ── API access keys (issue-local-029) ─────────────────────────────────────────
#
# Admin-only, session-only (require_admin resolves the SESSION cookie
# directly, never request.state.user — an API key can never authenticate its
# own management routes, by construction).


class ApiAccessConfigBody(BaseModel):
    enabled: bool


@router.get("/api-keys/config")
async def get_api_access_config(admin: dict = Depends(require_admin)) -> dict:
    return {"enabled": load_api_access_enabled()}


@router.put("/api-keys/config")
async def set_api_access_config(
    body: ApiAccessConfigBody, admin: dict = Depends(require_admin)
) -> dict:
    save_api_access_enabled(body.enabled)
    return {"enabled": body.enabled}


class CreateApiKeyBody(BaseModel):
    name: str
    scopes: list[str] = []


class UpdateApiKeyBody(BaseModel):
    name: str | None = None
    scopes: list[str] | None = None
    enabled: bool | None = None


def _public_api_key(record: dict) -> dict:
    """Redact secret_hash — never sent to the frontend after creation."""
    return {k: v for k, v in record.items() if k != "secret_hash"}


@router.get("/api-keys/scopes")
async def list_api_key_scopes(admin: dict = Depends(require_admin)) -> dict:
    """The wizard's toggle list + default-profile quick-pick source."""
    return {
        "scopes": list_scopes(),
        "default_profile": list(DEFAULT_PROFILE_SCOPES),
    }


@router.get("/api-keys")
async def list_api_keys_route(admin: dict = Depends(require_admin)) -> list[dict]:
    return [_public_api_key(k) for k in await db.list_api_keys()]


@router.post("/api-keys", status_code=201)
async def create_api_key_route(
    body: CreateApiKeyBody, request: Request, admin: dict = Depends(require_admin)
) -> dict:
    """Create a new API key. The response's ``secret``/``api_key`` fields are
    the ONLY time either value is available — only a hash is persisted."""
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    created = await create_api_key(name, body.scopes, created_by=admin["username"])
    prefix = load_app_base_prefix()
    endpoint = f"{str(request.base_url).rstrip('/')}{prefix}/api/threat-hunting"
    return {**created, "endpoint": endpoint}


@router.put("/api-keys/{client_id}")
async def update_api_key_route(
    client_id: str, body: UpdateApiKeyBody, admin: dict = Depends(require_admin)
) -> dict:
    existing = await db.get_api_key_by_client_id(client_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="API key not found")
    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="name must not be empty")
        await db.set_api_key_name(client_id, name)
    if body.scopes is not None:
        await db.set_api_key_scopes(client_id, valid_scope_ids(body.scopes))
    if body.enabled is not None:
        await db.set_api_key_enabled(client_id, body.enabled)
    return _public_api_key(await db.get_api_key_by_client_id(client_id))


@router.delete("/api-keys/{client_id}")
async def delete_api_key_route(client_id: str, admin: dict = Depends(require_admin)) -> dict:
    if await db.get_api_key_by_client_id(client_id) is None:
        raise HTTPException(status_code=404, detail="API key not found")
    await db.delete_api_key(client_id)
    return {"status": "deleted", "client_id": client_id}


@router.post("/api-keys/{client_id}/test")
async def test_api_key_route(client_id: str, admin: dict = Depends(require_admin)) -> dict:
    """Confirm a key resolves and report what it's actually granted — does
    NOT need (or ever see) the secret; it validates the stored record through
    the exact same lookup/enabled logic ``resolve_api_key`` uses, so a "pass"
    here means "this key will work" without regenerating or exposing it."""
    record = await db.get_api_key_by_client_id(client_id)
    if record is None:
        raise HTTPException(status_code=404, detail="API key not found")
    if not load_api_access_enabled():
        return {
            "status": "warning",
            "detail": "API access is currently disabled — enable it in General configuration "
            "for this key to actually authenticate requests.",
            "scopes": record["scopes"],
        }
    if not record["enabled"]:
        return {"status": "error", "detail": "This key is disabled.", "scopes": record["scopes"]}
    return {
        "status": "ok",
        "detail": f"Key resolves and is enabled, granting {len(record['scopes'])} scope(s).",
        "scopes": record["scopes"],
    }
