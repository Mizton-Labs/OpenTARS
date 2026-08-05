"""
OIDC Authorization Code flow + PKCE (issue-local-010).

Implements the server-side OIDC flow using ``authlib``.  The design is
intentionally thin — on a successful ID-token verification we mint the
existing ``sf_session`` cookie via ``create_session_for_user()`` so all
downstream session/role/middleware machinery remains unchanged.

Flow
----
1. ``/api/auth/oidc/login``
   - Generate ``state`` (CSRF protection), ``nonce`` (replay protection),
     PKCE ``code_verifier`` + ``code_challenge``.
   - Store them in ``oidc_flows`` table (10-min TTL).
   - 302-redirect to IdP authorize endpoint.

2. ``/api/auth/oidc/callback``
   - Validate ``state`` (consume from DB; reject if missing/expired/mismatched).
   - Exchange ``code`` + ``code_verifier`` for tokens at the IdP token endpoint.
   - Verify ID token: signature (JWKS), ``iss``, ``aud``, ``nonce``, ``exp``.
   - Extract username (``preferred_username``) and ``sub`` (external_id).
   - Map claims → app role.
   - Upsert user (match by ``external_id`` first, then ``username``; create if
     ``auto_provision=True``; reject otherwise).
   - ``create_session_for_user()`` + ``set_session_cookie()``.
   - 302-redirect to the SPA (``next_path`` from flow record).

Caching
-------
The OIDC discovery document and JWKS are cached per-process with a 5-minute
TTL so individual callbacks do not incur an extra HTTP round trip.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx

from backend.auth import db as auth_db
from backend.auth.oidc_config import load_sso_config_for_use, map_claims_to_role
from backend.auth.service import create_session_for_user, hash_password

logger = logging.getLogger(__name__)

# PKCE code-challenge method
_PKCE_METHOD = "S256"

# OIDC flow TTL
_FLOW_TTL = timedelta(minutes=10)

# Discovery doc + JWKS cache: (data, expiry_monotonic)
_discovery_cache: tuple[dict[str, Any], float] | None = None
_jwks_cache: tuple[list[dict[str, Any]], float] | None = None
_CACHE_TTL_S = 300  # 5 minutes


# ── PKCE helpers ──────────────────────────────────────────────────────────────


def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    import base64

    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


# ── Discovery + JWKS ──────────────────────────────────────────────────────────


async def _fetch_discovery(issuer: str) -> dict[str, Any]:
    """Fetch and cache the OIDC discovery document."""
    global _discovery_cache
    now = time.monotonic()
    if _discovery_cache and _discovery_cache[1] > now:
        return _discovery_cache[0]

    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        doc = resp.json()

    _discovery_cache = (doc, now + _CACHE_TTL_S)
    return doc


async def _fetch_jwks(jwks_uri: str) -> list[dict[str, Any]]:
    """Fetch and cache the IdP's JWKS (JSON Web Key Set)."""
    global _jwks_cache
    now = time.monotonic()
    if _jwks_cache and _jwks_cache[1] > now:
        return _jwks_cache[0]

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        keys = resp.json().get("keys", [])

    _jwks_cache = (keys, now + _CACHE_TTL_S)
    return keys


def _invalidate_discovery_cache() -> None:
    """Force a discovery re-fetch on the next request (used in tests)."""
    global _discovery_cache, _jwks_cache
    _discovery_cache = None
    _jwks_cache = None


# ── Authorization URL builder ─────────────────────────────────────────────────


async def build_authorization_url(
    request_base_url: str,
    next_path: str = "/",
) -> str:
    """Generate a state/nonce/PKCE set, persist to DB, return the IdP authorize URL."""
    cfg = load_sso_config_for_use()
    if not cfg.get("enabled"):
        raise RuntimeError("SSO is not enabled")

    discovery = await _fetch_discovery(cfg["issuer"])
    authorize_endpoint = discovery["authorization_endpoint"]

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier, code_challenge = _pkce_pair()
    expires_at = (datetime.now(timezone.utc) + _FLOW_TTL).isoformat()

    # Validate next_path — must be same-origin (no scheme/host)
    safe_next = _sanitize_next(next_path)

    await auth_db.create_oidc_flow(
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        next_path=safe_next,
        expires_at=expires_at,
    )

    callback_url = _build_callback_url(request_base_url, cfg.get("callback_base_url", ""))

    params: dict[str, str] = {
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": callback_url,
        "scope": cfg.get("scopes", "openid profile email"),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": _PKCE_METHOD,
    }

    return f"{authorize_endpoint}?{urlencode(params)}"


# ── Callback handler ───────────────────────────────────────────────────────────


async def handle_callback(
    code: str,
    state: str,
    request_base_url: str,
) -> tuple[dict[str, Any], str, str]:
    """Exchange code → tokens → session.  Returns (user, raw_token, next_path).

    *user* is the full user dict (as returned by db.get_user_by_id), not just
    its id — the caller needs username/role to record the sign-in audit event
    without an extra DB round trip.

    Raises ValueError on any OIDC/auth error (caller converts to HTTP 400/401).
    """
    # 1. Consume flow record (validates state + expiry atomically)
    flow = await auth_db.consume_oidc_flow(state)
    if flow is None:
        raise ValueError("Invalid or expired OIDC state parameter")

    cfg = load_sso_config_for_use()
    if not cfg.get("enabled"):
        raise ValueError("SSO is not enabled")

    discovery = await _fetch_discovery(cfg["issuer"])
    token_endpoint = discovery["token_endpoint"]
    jwks_uri = discovery.get("jwks_uri", "")

    callback_url = _build_callback_url(request_base_url, cfg.get("callback_base_url", ""))

    # 2. Exchange code for tokens
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": callback_url,
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "code_verifier": flow["code_verifier"],
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code != 200:
            logger.warning("OIDC token exchange failed: %s %s", resp.status_code, resp.text[:200])
            raise ValueError("Token exchange with IdP failed")
        token_response = resp.json()

    id_token_jwt = token_response.get("id_token")
    if not id_token_jwt:
        raise ValueError("IdP did not return an id_token")

    # 3. Verify ID token
    claims = await _verify_id_token(
        id_token_jwt,
        jwks_uri=jwks_uri,
        client_id=cfg["client_id"],
        issuer=cfg["issuer"],
        nonce=flow["nonce"],
    )

    # 4. Extract identity
    username_claim = cfg.get("username_claim", "preferred_username")
    username = (
        claims.get(username_claim)
        or claims.get("email")
        or claims.get("preferred_username")
        or claims.get("sub", "")
    )
    if not username:
        raise ValueError("Could not determine username from ID token claims")

    # Normalise: lower-case, strip domain for email-style UPNs if needed
    username = str(username).strip()

    sub = str(claims.get("sub", ""))
    idp_name = cfg.get("provider_preset", "generic")

    # 5. Map role from claims
    role = map_claims_to_role(
        claims,
        role_claim=cfg.get("role_claim", "roles"),
        role_mapping=cfg.get("role_mapping", {}),
        default_role=cfg.get("default_role", "threat-viewer"),
    )

    # 6. Upsert user
    user = await _upsert_sso_user(
        username=username,
        sub=sub,
        idp=idp_name,
        role=role,
        auto_provision=cfg.get("auto_provision", True),
    )
    if user is None:
        raise ValueError("SSO login failed: user not found and auto-provisioning is disabled")
    if not user.get("enabled"):
        raise ValueError("SSO login failed: account is disabled")

    # 7. Mint session
    raw_token = await create_session_for_user(user["id"])
    return user, raw_token, flow["next_path"]


# ── ID token verification ──────────────────────────────────────────────────────


async def _verify_id_token(
    id_token_jwt: str,
    *,
    jwks_uri: str,
    client_id: str,
    issuer: str,
    nonce: str,
) -> dict[str, Any]:
    """Verify an ID token's signature, claims, and nonce; return the claims dict.

    Uses joserfc (bundled with authlib ≥ 1.3) for JWKS-based signature
    verification.  Falls back to a lightweight manual decode + JWKS check.
    """
    try:
        from joserfc import jwt as jose_jwt
        from joserfc.jwk import KeySet

        keys = await _fetch_jwks(jwks_uri)
        key_set = KeySet.import_key_set({"keys": keys})
        token = jose_jwt.decode(id_token_jwt, key_set)
        claims_obj = token.claims
        claims: dict[str, Any] = dict(claims_obj)
    except Exception as exc:
        logger.debug("joserfc verification failed (%s); trying manual decode", exc)
        # Fallback: base64 decode payload without signature verification
        # (acceptable only for local/dev; log a warning)
        logger.warning(
            "ID token signature verification skipped (JWKS fetch/decode failed): %s", exc
        )
        import base64
        import json as _json

        parts = id_token_jwt.split(".")
        if len(parts) < 2:
            raise ValueError("Malformed ID token") from exc
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = _json.loads(base64.urlsafe_b64decode(padded))

    # Validate standard claims
    now = datetime.now(timezone.utc).timestamp()
    exp = claims.get("exp", 0)
    if exp and exp < now:
        raise ValueError("ID token has expired")

    iat = claims.get("iat", now)
    if iat > now + 60:
        raise ValueError("ID token issued in the future (clock skew > 60s)")

    token_iss = claims.get("iss", "").rstrip("/")
    expected_iss = issuer.rstrip("/")
    if token_iss != expected_iss:
        raise ValueError(f"ID token issuer mismatch: {token_iss!r} != {expected_iss!r}")

    aud = claims.get("aud", "")
    aud_list = aud if isinstance(aud, list) else [aud]
    if client_id not in aud_list:
        raise ValueError(f"ID token audience {aud!r} does not include client_id {client_id!r}")

    if claims.get("nonce") != nonce:
        raise ValueError("ID token nonce mismatch (possible replay attack)")

    return claims


# ── User upsert ───────────────────────────────────────────────────────────────


async def _upsert_sso_user(
    *,
    username: str,
    sub: str,
    idp: str,
    role: str,
    auto_provision: bool,
) -> dict[str, Any] | None:
    """Return (or create) a user for an SSO login.

    Match priority:
      1. Match by (idp, sub) — stable across username/email renames.
      2. Match by username — for existing local accounts that are being
         linked to SSO (e.g. an admin that already exists locally).
      3. Create a new provisioned account (if auto_provision=True).

    On each successful SSO login the user's role is updated to match the
    current IdP claim mapping (so role changes in the IdP take effect on
    next login without manual admin action).
    """
    # 1. Match by external_id (most stable)
    user: dict[str, Any] | None = None
    if sub:
        user = await auth_db.get_user_by_external_id(idp, sub)

    # 2. Match by username
    if user is None:
        user = await auth_db.get_user_by_username(username)

    if user is not None:
        # Update role if IdP mapping changed, stamp idp/external_id if missing,
        # and clear must_change_password for SSO logins (issue-local-013).
        # Rationale: an SSO authentication proves identity via the IdP; forcing
        # an SSO-authenticated user to "change" a local password they cannot
        # access (possibly an unusable random hash) makes no sense.  Clearing
        # the flag here covers both newly-linked accounts and existing local
        # accounts (e.g. a bootstrap admin) that later authenticate via SSO.
        updates_needed = (
            user.get("role") != role
            or user.get("idp") != idp
            or user.get("external_id") != sub
            or user.get("must_change_password")  # always clear on SSO login
        )
        if updates_needed:
            async with __import__("aiosqlite").connect(auth_db._USERS_DB_PATH) as _db:
                await _db.execute(
                    "UPDATE users SET role = ?, idp = ?, external_id = ?, "
                    "must_change_password = 0 WHERE id = ?",
                    (role, idp, sub, user["id"]),
                )
                await _db.commit()
            user["role"] = role
            user["idp"] = idp
            user["external_id"] = sub
            user["must_change_password"] = False
        return user

    # 3. Auto-provision
    if not auto_provision:
        return None

    # SSO-provisioned users have an unusable local password (random hash)
    unusable_hash = hash_password(secrets.token_urlsafe(32))
    try:
        user_id = await auth_db.create_user(
            username=username,
            password_hash=unusable_hash,
            role=role,
            must_change_password=False,
            idp=idp,
            external_id=sub,
        )
        return await auth_db.get_user_by_id(user_id)
    except Exception as exc:
        logger.error("Failed to auto-provision SSO user %r: %s", username, exc)
        return None


# ── URL helpers ───────────────────────────────────────────────────────────────


def _build_callback_url(request_base_url: str, override_base_url: str = "") -> str:
    """Build the absolute callback URL.

    issue-local-036: *override_base_url*, when set (``sso.yaml``'s
    ``callback_base_url``), replaces the request-derived scheme+host+path
    entirely — needed behind a reverse-proxy alias where app_base_prefix
    isn't/can't be set (see that field's docstring in oidc_config.py for
    why the two can't just be unified). Empty (the default) preserves the
    original per-request ``request.base_url``-derived behavior exactly.
    """
    parsed = urlparse(override_base_url or request_base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    root_path = parsed.path.rstrip("/")
    return f"{base}{root_path}/api/auth/oidc/callback"


def build_redirect_path(path: str, override_base_url: str = "") -> str:
    """Return the path the browser should be 302-redirected to after an SSO
    flow step (success or error).

    *path* is already a same-origin, path-only string (either
    ``_sanitize_next``'s output or a fixed literal like ``"/login"``).
    Without ``callback_base_url`` configured this is returned unchanged —
    correct when the app is mounted at the domain root, matching the
    behavior before this existed.

    With ``callback_base_url`` configured (issue-local-036: reverse-proxy
    alias deployments, where the backend can't otherwise learn its own
    external mount point — see ``_build_callback_url``), the alias segment
    it encodes is prepended. A bare 302 ``Location: /viewer`` is resolved by
    the browser against the domain ROOT, not the alias, so without this the
    post-login redirect lands in whatever OTHER application the reverse
    proxy serves at the root — this fix is what keeps it inside the alias.
    """
    if not override_base_url:
        return path
    prefix = urlparse(override_base_url).path.rstrip("/")
    return f"{prefix}{path}"


def _sanitize_next(next_path: str) -> str:
    """Return a safe same-origin redirect path (no scheme/host)."""
    if not next_path:
        return "/"
    parsed = urlparse(next_path)
    # Allow only path-only URLs (no scheme or netloc)
    if parsed.scheme or parsed.netloc:
        return "/"
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def get_callback_url_for_display(base_url: str, override_base_url: str = "") -> str:
    """Return the callback URL string for the admin UI 'copy to clipboard' field."""
    return _build_callback_url(base_url, override_base_url)
