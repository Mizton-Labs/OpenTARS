"""
Authentication service (prompts-045).

Pure security logic on top of :mod:`backend.auth.db`:

* password hashing / verification (bcrypt, constant-time)
* opaque session-token generation and SHA-256 hashing
* login throttling (per username+IP)
* first-run bootstrap of an ``admin`` account whose credential is written to a
  0600 file (never to the application log)

Plaintext passwords and raw session tokens never leave this module's call
frames — only their hashes are persisted.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt

from backend.auth import db

logger = logging.getLogger(__name__)

# bcrypt cost factor. 12 is a sane 2020s default for interactive logins.
_BCRYPT_ROUNDS = 12

# bcrypt truncates input at 72 bytes; reject longer to avoid silent truncation.
_MAX_PASSWORD_BYTES = 72

SESSION_TTL = timedelta(hours=12)
SESSION_COOKIE_NAME = "sf_session"

# Login throttle: max failures per (username, ip) within the window.
_THROTTLE_MAX_FAILURES = 5
_THROTTLE_WINDOW_SECONDS = 300
# In-memory failure ledger: {(username, ip): [timestamps]}. Process-local; a
# restart clears it. Adequate for a single-process deployment.
_failures: dict[tuple[str, str], list[float]] = {}


# ── Password hashing ─────────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password*. Raises on empty/over-long input."""
    if not password:
        raise ValueError("password must not be empty")
    raw = password.encode("utf-8")
    if len(raw) > _MAX_PASSWORD_BYTES:
        raise ValueError(f"password must be at most {_MAX_PASSWORD_BYTES} bytes")
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    return bcrypt.hashpw(raw, salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verify *password* against a stored bcrypt hash."""
    if not password or not password_hash:
        return False
    raw = password.encode("utf-8")
    if len(raw) > _MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(raw, password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ── Session tokens ───────────────────────────────────────────────────────────


def generate_session_token() -> str:
    """Return a new opaque, URL-safe session token (~256 bits)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a session token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_session_for_user(user_id: int) -> str:
    """Create a session row for *user_id*; return the raw token for the cookie."""
    token = generate_session_token()
    expires_at = (datetime.now(timezone.utc) + SESSION_TTL).isoformat()
    await db.create_session(hash_token(token), user_id, expires_at)
    return token


async def resolve_session(token: str) -> dict | None:
    """Return the active user dict for a raw session token, else None."""
    if not token:
        return None
    session = await db.get_session(hash_token(token))
    if session is None:
        return None
    user = await db.get_user_by_id(session["user_id"])
    if user is None or not user["enabled"]:
        return None
    user.pop("password_hash", None)
    return user


async def destroy_session(token: str) -> None:
    """Revoke a session by its raw token."""
    if token:
        await db.delete_session(hash_token(token))


# ── API access keys (issue-local-029) ─────────────────────────────────────────

# client_id is public (sent in the clear, logged, shown in the UI list) — only
# the secret half is sensitive. Prefixed so it's recognizable at a glance
# (e.g. in server logs) as an API key rather than a username.
_CLIENT_ID_PREFIX = "ak_"


def generate_client_id() -> str:
    """Return a new, unique-enough public client id (``ak_<12 hex>``)."""
    return f"{_CLIENT_ID_PREFIX}{secrets.token_hex(6)}"


def generate_api_secret() -> str:
    """Return a new opaque API secret (~256 bits) — same generator as session
    tokens; shown to the operator exactly once and never persisted raw."""
    return secrets.token_urlsafe(32)


def _combined_api_key(client_id: str, secret: str) -> str:
    """The single opaque string an API client sends: ``Authorization: Bearer
    <client_id>.<secret>``. client_id is hex, secret is URL-safe base64 —
    neither alphabet contains ``.``, so splitting on the first one is safe."""
    return f"{client_id}.{secret}"


async def create_api_key(
    name: str,
    scopes: list[str],
    *,
    created_by: str | None = None,
) -> dict:
    """Create a new API key. Returns a dict including the raw ``secret`` and
    the combined ``api_key`` bearer value — the ONLY time either is available;
    only the hash is persisted. Retries client_id generation on the
    (astronomically unlikely) chance of a collision."""
    import sqlite3

    from backend.auth.api_scopes import valid_scope_ids

    clean_scopes = valid_scope_ids(scopes)
    secret = generate_api_secret()
    secret_hash = hash_token(secret)
    for _ in range(5):
        client_id = generate_client_id()
        try:
            await db.create_api_key(
                client_id, secret_hash, name, clean_scopes, created_by=created_by
            )
            break
        except sqlite3.IntegrityError:
            continue  # client_id collision — regenerate and retry
    else:
        raise RuntimeError("could not generate a unique API client id after 5 attempts")

    return {
        "client_id": client_id,
        "secret": secret,
        "api_key": _combined_api_key(client_id, secret),
        "name": name,
        "scopes": clean_scopes,
    }


async def resolve_api_key(bearer_value: str) -> dict | None:
    """Return a synthetic "user" dict for a valid, enabled API key, else None.

    *bearer_value* is the raw ``<client_id>.<secret>`` string (already
    stripped of the ``Bearer `` prefix by the caller). Mirrors
    :func:`resolve_session`'s shape closely enough that
    ``auth_enforcement`` can treat both uniformly, but carries
    ``is_api_key=True`` and ``scopes`` instead of a ``role`` — callers must
    branch on that before doing role-based authorization.
    """
    if not bearer_value or "." not in bearer_value:
        return None
    client_id, _, secret = bearer_value.partition(".")
    if not client_id or not secret:
        return None
    record = await db.get_api_key_by_client_id(client_id)
    if record is None or not record["enabled"]:
        return None
    if not secrets.compare_digest(hash_token(secret), record["secret_hash"]):
        return None
    await db.touch_api_key_last_used(client_id)
    return {
        "username": f"apikey:{record['name']}",
        "is_api_key": True,
        "client_id": client_id,
        "scopes": record["scopes"],
        "enabled": True,
        "must_change_password": False,
        "idp": None,
    }


# ── Login throttle ───────────────────────────────────────────────────────────


def _prune(key: tuple[str, str], now: float) -> list[float]:
    stamps = [t for t in _failures.get(key, []) if now - t < _THROTTLE_WINDOW_SECONDS]
    if stamps:
        _failures[key] = stamps
    else:
        _failures.pop(key, None)
    return stamps


def is_throttled(username: str, ip: str) -> bool:
    """Return True if this (username, ip) has too many recent failures."""
    key = (username, ip)
    stamps = _prune(key, time.monotonic())
    return len(stamps) >= _THROTTLE_MAX_FAILURES


def record_failure(username: str, ip: str) -> None:
    key = (username, ip)
    now = time.monotonic()
    stamps = _prune(key, now)
    stamps.append(now)
    _failures[key] = stamps


def clear_failures(username: str, ip: str) -> None:
    _failures.pop((username, ip), None)


async def authenticate(username: str, password: str, ip: str) -> dict | None:
    """Verify credentials with throttling. Return the user dict or None.

    Always performs a bcrypt comparison (against a dummy hash when the user is
    missing) to keep timing uniform and avoid username enumeration.
    """
    if is_throttled(username, ip):
        logger.warning("login throttled for %r from %s", username, ip)
        return None
    user = await db.get_user_by_username(username)
    stored_hash = user["password_hash"] if user else _DUMMY_HASH
    ok = verify_password(password, stored_hash)
    if not ok or user is None or not user["enabled"]:
        record_failure(username, ip)
        return None
    clear_failures(username, ip)
    user.pop("password_hash", None)
    return user


# Pre-computed bcrypt hash of a random string; used for timing-equalisation when
# the supplied username does not exist.
_DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)).decode(
    "utf-8"
)


# ── First-run bootstrap ──────────────────────────────────────────────────────


async def bootstrap_admin_if_empty() -> str | None:
    """Create an ``admin`` user with a random password if no users exist.

    Returns the generated plaintext password (for the runner to surface once),
    or None when users already exist. The credential is written to a 0600 file
    (``data/first-run-admin-credentials.txt``) for the operator to read once;
    it is NOT written to the application logger. The account is flagged
    ``must_change_password`` so the operator is forced to replace the generated
    default on first login (prompts-047).
    """
    if await db.count_users() > 0:
        return None
    password = secrets.token_urlsafe(18)
    await db.create_user("admin", hash_password(password), role="admin", must_change_password=True)
    _emit_credential("admin", password)
    return password


async def reset_admin_password(username: str = "admin") -> str:
    """Reset (or provision) the admin account's password to a random default.

    Operator-facing maintenance entry point behind
    ``./opentars --reset-admin-password``. Ensures the users schema
    exists, then:

    * if ``username`` does not exist, creates it as an admin (mirrors first-run
      bootstrap), or
    * if it exists, sets a fresh random password and evicts all of its sessions.

    In both cases the account is flagged ``must_change_password`` so the
    generated default must be changed on next login, and the credential is
    written to the same 0600 file as first-run. Returns the new plaintext
    password so the caller (the launcher) can print it to the terminal.
    """
    await db.init_users_db()
    password = secrets.token_urlsafe(18)
    existing = await db.get_user_by_username(username)
    if existing is None:
        await db.create_user(
            username,
            hash_password(password),
            role="admin",
            must_change_password=True,
        )
        context = "created"
    else:
        await db.set_password(existing["id"], hash_password(password), must_change_password=True)
        context = "reset"
    _emit_credential(username, password, context=context)
    return password


def format_credential_box(username: str, password: str, *, context: str = "first-run") -> str:
    """Render the admin credentials inside an ASCII frame drawn with ``#``.

    Makes the generated credential clearly visible in the operator's terminal on
    first-run start and on ``--reset-admin-password`` (prompts-059). The 0600
    credential file is still written separately by :func:`_emit_credential`; this
    is only the human-facing terminal presentation. ``context`` selects the
    title (``"first-run"`` / ``"reset"`` / ``"created"``).

    Returns a multi-line string with every row padded to an equal width.
    """
    titles = {
        "first-run": "OpenTARS — first-run admin account",
        "reset": "OpenTARS — admin password reset",
        "created": "OpenTARS — admin account provisioned",
    }
    title = titles.get(context, titles["first-run"])
    lines = [
        title,
        "",
        f"username: {username}",
        f"password: {password}",
        "",
        "Change this password immediately after logging in,",
        "then delete data/first-run-admin-credentials.txt",
    ]
    inner_width = max(len(s) for s in lines)
    pad = 2  # spaces between the border and the text
    width = inner_width + pad * 2
    border = "#" * (width + 2)
    blank = "#" + " " * width + "#"
    out = [border, blank]
    for s in lines:
        out.append("#" + " " * pad + s.ljust(inner_width) + " " * pad + "#")
    out.append(blank)
    out.append(border)
    return "\n".join(out)


# Path of the project-root data directory (backend/auth/service.py → parents[2]).
_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
_CREDENTIAL_FILE = _DATA_DIR / "first-run-admin-credentials.txt"


def _emit_credential(username: str, password: str, *, context: str = "first-run") -> None:
    """Persist a generated admin credential to an owner-only (0600) file and
    log only a pointer to it.

    ``context`` distinguishes the originating action for the file header and the
    log line: ``"first-run"`` (default), ``"reset"`` (password reset of an
    existing account), or ``"created"`` (admin provisioned on demand by
    ``--reset-admin-password``).

    Security (prompts-045 audit, MAJOR #3): the generated password must never
    reach the application logger. In production the runner redirects uvicorn
    stdout/stderr into ``backend.log`` (and that log may be shipped to a central
    store), so the credential would otherwise persist there indefinitely — long
    after the operator rotates it. Writing to a restricted-permission file the
    operator deletes after first login keeps the secret off the log entirely.
    The launcher's ``--reset-admin-password`` additionally prints the password to
    the operator's terminal (stdout), which is an explicit, interactive action —
    that path does not go through this logger.
    """
    _HEADERS = {
        "first-run": "OpenTARS — first-run admin account",
        "reset": "OpenTARS — admin password reset",
        "created": "OpenTARS — admin account provisioned",
    }
    header = _HEADERS.get(context, _HEADERS["first-run"])
    content = (
        f"{header}\n"
        f"username: {username}\n"
        f"password: {password}\n"
        "\nLog in, change this password immediately, then DELETE this file.\n"
    )
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        # O_CREAT with mode 0o600 so the secret is never momentarily world-readable.
        fd = os.open(
            _CREDENTIAL_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.chmod(_CREDENTIAL_FILE, 0o600)
        except OSError:  # pragma: no cover — best-effort on exotic filesystems
            pass
        logger.warning(
            "Admin account '%s' credential (%s) written to %s "
            "(mode 0600). Log in, change the password, then delete that file.",
            username,
            context,
            _CREDENTIAL_FILE,
        )
    except OSError as exc:  # pragma: no cover — fall back without leaking secret
        logger.error(
            "First-run admin account '%s' created but the credential file could "
            "not be written (%s). Use the password returned to the runner.",
            username,
            exc,
        )
