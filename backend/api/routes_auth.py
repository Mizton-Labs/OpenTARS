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
  DELETE /api/auth/users/{user_id}
"""

from __future__ import annotations

import logging
import re
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from backend.auth import db
from backend.auth.dependencies import (
    clear_session_cookie,
    get_current_user,
    require_admin,
    set_session_cookie,
)
from backend.auth.oidc_config import load_sso_config, save_sso_config
from backend.auth.service import (
    SESSION_COOKIE_NAME,
    SESSION_TTL,
    authenticate,
    create_session_for_user,
    destroy_session,
    hash_password,
    hash_token,
    verify_password,
)
from backend.config.loader import load_auth_enabled, load_password_policy

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
    username: str
    password: str
    role: str = "threat-viewer"


class RoleBody(BaseModel):
    role: str


class EnabledBody(BaseModel):
    enabled: bool


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
    """Return the OIDC callback URL that must be registered in the IdP. Admin only."""
    from backend.auth.oidc import get_callback_url_for_display

    return {"callback_url": get_callback_url_for_display(str(request.base_url))}


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response) -> dict:
    """Authenticate and start a session. Generic error on any failure."""
    user = await authenticate(body.username, body.password, _client_ip(request))
    if user is None:
        # Single generic message — never reveal whether the username exists,
        # the password was wrong, the account is disabled, or it was throttled.
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = await create_session_for_user(user["id"])
    set_session_cookie(request, response, token, max_age=int(SESSION_TTL.total_seconds()))
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
        raise HTTPException(status_code=400, detail="theme must be 'classic', 'energy', or null")
    await db.set_theme(user["id"], body.theme)
    return _public_user(await db.get_user_by_id(user["id"]))


# ── Admin: user management ────────────────────────────────────────────────────


@router.get("/users")
async def list_users(admin: dict = Depends(require_admin)) -> list[dict]:
    return await db.list_users()


@router.post("/users")
async def create_user(body: CreateUserBody, admin: dict = Depends(require_admin)) -> dict:
    _validate_username(body.username)
    _validate_password(body.password)
    if body.role not in db.VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail="role must be 'admin', 'threat-researcher', 'threat-viewer', or 'feed-sender'",
        )
    if await db.get_user_by_username(body.username) is not None:
        raise HTTPException(status_code=409, detail="Username already exists")
    # An admin-supplied password is, from the new user's perspective, the
    # same trust situation as an admin reset (issue-local-016) — force it to
    # be changed on first login rather than trusting it stays private.
    uid = await db.create_user(
        body.username,
        hash_password(body.password),
        role=body.role,
        must_change_password=True,
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


async def _require_user(user_id: int) -> dict:
    user = await db.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user
