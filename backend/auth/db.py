"""
Authentication storage (prompts-045).

SQLite-backed users + sessions registry at ``data/users.db``.

Tables
------
users
  * id            — autoincrement PK
  * username      — unique, case-sensitive login name
  * password_hash — bcrypt hash (str); never the plaintext
  * role          — 'admin' | 'threat-researcher' | 'threat-viewer' | 'feed-sender'
                    (issue-local-002: expanded role model for Threat Hunting module)
                    - 'admin': full access including configuration and user management
                    - 'threat-researcher': full Threat Hunting access + TI Viewer read
                    - 'threat-viewer': read-only access to hunts, reports, and TI Viewer
                    - 'feed-sender': push-only machine account, POST /api/ingest/listener only
                    (migration from old roles: 'normal' -> 'threat-viewer',
                     'sender' -> 'feed-sender'; handled in _migrate_users_schema)
  * enabled       — 1 active, 0 disabled (cannot log in)
  * created_at    — UTC ISO8601
  * must_change_password — 1 when the current password is a generated default
                    (first-run bootstrap or --reset-admin-password); the user is
                    forced to change it before any other action (prompts-047)
  * idp           — NULL for local accounts; IdP identifier for SSO accounts
                    (e.g. 'entra', 'google', 'generic') (issue-local-010)
  * external_id   — NULL for local accounts; IdP subject claim (``sub``) for
                    SSO accounts; used to match returning SSO users even if
                    their username claim changes (issue-local-010)

sessions
  * token_hash    — SHA-256 hex of the opaque session token (PK). The raw
                    token is only ever held by the client cookie; the DB
                    stores its hash so a DB read cannot mint a valid cookie.
  * user_id       — FK-ish reference to users.id
  * created_at    — UTC ISO8601
  * expires_at    — UTC ISO8601; lookups reject expired rows

oidc_flows
  Short-lived OIDC state table for Authorization Code flow (issue-local-010).
  Stores the PKCE + state + nonce for each in-flight login until the callback
  arrives.  Entries expire after 10 minutes and are deleted on use.
  * state         — opaque random string (PK); validated in callback
  * nonce         — random nonce embedded in ID token; validated after exchange
  * code_verifier — PKCE verifier; sent in the token exchange
  * next_path     — safe redirect destination after login (same-origin validated)
  * expires_at    — UTC ISO8601; entries older than this are rejected

api_keys (issue-local-029)
  Machine-credential registry for the programmatic API access feature — a
  parallel authentication path alongside the session cookie, scoped to a
  curated set of Threat Hunting API capabilities (see
  ``backend.auth.api_scopes``) rather than the role model above.
  * id            — autoincrement PK
  * client_id     — public, unique identifier (``ak_<12 hex>``); sent by the
                    client alongside the secret, never treated as sensitive
                    on its own
  * secret_hash   — SHA-256 hex of the opaque secret (same hashing helper as
                    session tokens); the raw secret is shown to the operator
                    exactly once at creation time and never persisted
  * name          — operator-supplied label (e.g. "CI pipeline")
  * scopes        — JSON array of scope ids (``backend.auth.api_scopes``);
                    the explicit resolved set at creation/edit time, not a
                    wildcard — a newly-added scope never silently applies to
                    an existing key
  * enabled       — 1 active, 0 revoked (a disabled key authenticates as
                    invalid, same as a disabled user)
  * created_by    — username of the admin who created it, for audit
  * created_at    — UTC ISO8601
  * last_used_at  — UTC ISO8601, updated (best-effort) on each successful
                    authentication; NULL until first use

Security note: this module deals only in *hashes*. Plaintext passwords and raw
session tokens never touch disk. Hashing/token generation live in
``backend.auth.service``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_USERS_DB_PATH = _PROJECT_ROOT / "data" / "users.db"

_USERS_SCHEMA_VERSION = 6

# Canonical role set (issue-local-002): expanded for the Threat Hunting module.
# Old roles 'normal' and 'sender' are migrated to 'threat-viewer' and
# 'feed-sender' respectively on first startup after this change.
VALID_ROLES = frozenset({"admin", "threat-researcher", "threat-viewer", "feed-sender"})

# issue-local-016: per-user UI theme override. NULL in the DB means "use the
# instance-wide default" (backend/config/loader.load_default_theme) — see
# users.theme column, added in the v4->v5 migration below.
VALID_THEMES = frozenset({"classic", "energy", "light", "ocean"})


CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'threat-viewer',
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0
);
"""

CREATE_SESSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT    NOT NULL PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    created_at  TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL
);
"""

CREATE_SESSIONS_IDX_USER = """
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
"""

CREATE_SCHEMA_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
"""

# issue-local-010: OIDC in-flight flows (state / nonce / PKCE)
CREATE_OIDC_FLOWS_TABLE = """
CREATE TABLE IF NOT EXISTS oidc_flows (
    state         TEXT NOT NULL PRIMARY KEY,
    nonce         TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    next_path     TEXT NOT NULL DEFAULT '/',
    expires_at    TEXT NOT NULL
);
"""

# issue-local-029: API access keys (see module docstring)
CREATE_API_KEYS_TABLE = """
CREATE TABLE IF NOT EXISTS api_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     TEXT    NOT NULL UNIQUE,
    secret_hash   TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    scopes        TEXT    NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_by    TEXT,
    created_at    TEXT    NOT NULL,
    last_used_at  TEXT
);
"""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def init_users_db() -> None:
    """Create the users/sessions schema if absent. Idempotent.

    Also runs lightweight in-place migrations for existing databases created by
    an older schema version (no destructive operations, no data loss).
    """
    _USERS_DB_PATH.parent.mkdir(exist_ok=True)
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        await db.execute(CREATE_USERS_TABLE)
        await db.execute(CREATE_SESSIONS_TABLE)
        await db.execute(CREATE_SESSIONS_IDX_USER)
        await db.execute(CREATE_SCHEMA_VERSION_TABLE)
        await db.execute(CREATE_OIDC_FLOWS_TABLE)
        await db.execute(CREATE_API_KEYS_TABLE)
        await _migrate_users_schema(db)
        cur = await db.execute("SELECT version FROM schema_version LIMIT 1")
        row = await cur.fetchone()
        await cur.close()
        if row is None:
            await db.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (_USERS_SCHEMA_VERSION,),
            )
        else:
            await db.execute("UPDATE schema_version SET version = ?", (_USERS_SCHEMA_VERSION,))
        await db.commit()


async def _migrate_users_schema(db: aiosqlite.Connection) -> None:
    """Idempotently bring an existing users table up to the current schema.

    v1 -> v2 (prompts-047): add the ``must_change_password`` column. SQLite's
    ``ALTER TABLE ... ADD COLUMN`` is non-destructive and existing rows take the
    column DEFAULT (0), so legacy accounts are unaffected.

    v2 -> v3 (issue-local-002): rename legacy roles.
      'normal' -> 'threat-viewer'
      'sender' -> 'feed-sender'
    Uses UPDATE ... WHERE role = <old> so existing admins are untouched and the
    migration is idempotent (re-running on an already-migrated DB is a no-op).

    v3 -> v4 (issue-local-010): SSO support.
      - Add nullable ``idp`` column (IdP identifier for SSO accounts).
      - Add nullable ``external_id`` column (IdP subject claim for SSO accounts).
      - Ensure ``oidc_flows`` table exists (handled by CREATE_OIDC_FLOWS_TABLE in
        init_users_db; listed here for documentation completeness).

    v4 -> v5 (issue-local-016): per-user theme override.
      - Add nullable ``theme`` column. NULL means "use the instance-wide
        default" (backend/config/loader.load_default_theme); a non-NULL value
        (one of VALID_THEMES) is an explicit per-user override. Valid values
        are enforced at the API layer, not via a SQL CHECK constraint — same
        approach already used for ``role``/VALID_ROLES.

    v5 -> v6 (issue-local-029): API access keys.
      - Ensure the ``api_keys`` table exists (handled by CREATE_API_KEYS_TABLE
        in init_users_db, a whole new table rather than a column addition, so
        `CREATE TABLE IF NOT EXISTS` alone is idempotent for both fresh and
        upgrading databases; listed here for documentation completeness, same
        as the v3->v4 oidc_flows entry above).
    """
    cur = await db.execute("PRAGMA table_info(users)")
    cols = {row[1] for row in await cur.fetchall()}
    await cur.close()
    if "must_change_password" not in cols:
        logger.info("Migrating users schema v1->v2: adding must_change_password column")
        await db.execute(
            "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"
        )
    # v3 role rename — UPDATE is idempotent: if no rows have the old role name,
    # rowcount is 0 and nothing changes.
    cur = await db.execute("UPDATE users SET role = 'threat-viewer' WHERE role = 'normal'")
    if cur.rowcount:
        logger.info(
            "Migrating users schema v2->v3: renamed %d 'normal' role(s) to 'threat-viewer'",
            cur.rowcount,
        )
    cur = await db.execute("UPDATE users SET role = 'feed-sender' WHERE role = 'sender'")
    if cur.rowcount:
        logger.info(
            "Migrating users schema v2->v3: renamed %d 'sender' role(s) to 'feed-sender'",
            cur.rowcount,
        )
    # v4: SSO columns — ADD COLUMN is idempotent (no-op if column already exists)
    if "idp" not in cols:
        logger.info("Migrating users schema v3->v4: adding idp column")
        await db.execute("ALTER TABLE users ADD COLUMN idp TEXT")
    if "external_id" not in cols:
        logger.info("Migrating users schema v3->v4: adding external_id column")
        await db.execute("ALTER TABLE users ADD COLUMN external_id TEXT")
    if "theme" not in cols:
        logger.info("Migrating users schema v4->v5: adding theme column")
        await db.execute("ALTER TABLE users ADD COLUMN theme TEXT")


# ── User CRUD ────────────────────────────────────────────────────────────────


def _user_row_to_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row[0],
        "username": row[1],
        "password_hash": row[2],
        "role": row[3],
        "enabled": bool(row[4]),
        "created_at": row[5],
        "must_change_password": bool(row[6]),
        # issue-local-010: SSO columns (may be absent in old rows before migration)
        "idp": row[7] if len(row) > 7 else None,
        "external_id": row[8] if len(row) > 8 else None,
        # issue-local-016: per-user theme override (may be absent in old rows)
        "theme": row[9] if len(row) > 9 else None,
    }


_USER_COLS = (
    "id, username, password_hash, role, enabled, created_at, must_change_password, "
    "idp, external_id, theme"
)


async def create_user(
    username: str,
    password_hash: str,
    role: str = "threat-viewer",
    *,
    must_change_password: bool = False,
    idp: str | None = None,
    external_id: str | None = None,
) -> int:
    """Insert a new user; return its id. Raises on duplicate username.

    *idp* and *external_id* are set for SSO-provisioned accounts (issue-local-010).
    Local accounts leave both as NULL.
    """
    if role not in VALID_ROLES:
        raise ValueError(f"invalid role: {role!r}")
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO users "
            "(username, password_hash, role, enabled, created_at, must_change_password, "
            " idp, external_id) "
            "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
            (
                username,
                password_hash,
                role,
                _utc_now_iso(),
                1 if must_change_password else 0,
                idp,
                external_id,
            ),
        )
        await db.commit()
        return int(cur.lastrowid)


async def get_user_by_username(username: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(f"SELECT {_USER_COLS} FROM users WHERE username = ?", (username,))
        row = await cur.fetchone()
        await cur.close()
    return _user_row_to_dict(row) if row else None


async def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(f"SELECT {_USER_COLS} FROM users WHERE id = ?", (user_id,))
        row = await cur.fetchone()
        await cur.close()
    return _user_row_to_dict(row) if row else None


async def get_user_by_external_id(idp: str, external_id: str) -> dict[str, Any] | None:
    """Return a user matched by SSO IdP + subject claim, or None (issue-local-010).

    Used during OIDC callback to match a returning SSO user even if their
    ``preferred_username`` claim has changed (e.g. an email rename in Entra).
    """
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            f"SELECT {_USER_COLS} FROM users WHERE idp = ? AND external_id = ?",
            (idp, external_id),
        )
        row = await cur.fetchone()
        await cur.close()
    return _user_row_to_dict(row) if row else None


async def list_users() -> list[dict[str, Any]]:
    """Return all users (without password hashes) ordered by id."""
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(f"SELECT {_USER_COLS} FROM users ORDER BY id")
        rows = await cur.fetchall()
        await cur.close()
    out = []
    for row in rows:
        d = _user_row_to_dict(row)
        d.pop("password_hash", None)
        out.append(d)
    return out


async def count_users() -> int:
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute("SELECT COUNT(*) FROM users")
        row = await cur.fetchone()
        await cur.close()
    return int(row[0]) if row else 0


async def count_admins(exclude_id: int | None = None) -> int:
    """Count enabled admin users, optionally excluding one id."""
    q = "SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1"
    params: tuple[Any, ...] = ()
    if exclude_id is not None:
        q += " AND id != ?"
        params = (exclude_id,)
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(q, params)
        row = await cur.fetchone()
        await cur.close()
    return int(row[0]) if row else 0


async def set_password(
    user_id: int,
    password_hash: str,
    *,
    keep_token_hash: str | None = None,
    must_change_password: bool = False,
) -> bool:
    """Update a user's password hash and revoke their sessions.

    Security (prompts-045 audit): a password change/reset must terminate any
    existing sessions, otherwise a stolen session cookie survives a reset for up
    to the session TTL. ``keep_token_hash`` preserves a single session (the
    caller's own, on self-service change) so the user is not logged out by their
    own action; an admin reset passes ``None`` to evict every session.

    ``must_change_password`` writes the force-change flag in the same UPDATE
    (prompts-047): a normal self-change or admin reset clears it (default
    False); ``--reset-admin-password`` sets it to True so the operator-supplied
    default password must be changed on next login. Returns True if a row was
    updated.
    """
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            "UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?",
            (password_hash, 1 if must_change_password else 0, user_id),
        )
        if keep_token_hash is None:
            await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        else:
            await db.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
                (user_id, keep_token_hash),
            )
        await db.commit()
        return cur.rowcount > 0


async def set_enabled(user_id: int, enabled: bool) -> bool:
    """Enable/disable a user. Disabling also revokes their sessions."""
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            "UPDATE users SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, user_id),
        )
        if not enabled:
            await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        await db.commit()
        return cur.rowcount > 0


async def set_role(user_id: int, role: str) -> bool:
    if role not in VALID_ROLES:
        raise ValueError(f"invalid role: {role!r}")
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        await db.commit()
        return cur.rowcount > 0


async def set_theme(user_id: int, theme: str | None) -> bool:
    """Set (or clear, via ``theme=None``) a user's personal theme override."""
    if theme is not None and theme not in VALID_THEMES:
        raise ValueError(f"invalid theme: {theme!r}")
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute("UPDATE users SET theme = ? WHERE id = ?", (theme, user_id))
        await db.commit()
        return cur.rowcount > 0


async def delete_user(user_id: int) -> bool:
    """Delete a user and revoke their sessions. Returns True if removed."""
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        await db.commit()
        return cur.rowcount > 0


# ── Session CRUD ─────────────────────────────────────────────────────────────


async def create_session(token_hash: str, user_id: int, expires_at: str) -> None:
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        await db.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token_hash, user_id, _utc_now_iso(), expires_at),
        )
        await db.commit()


async def get_session(token_hash: str) -> dict[str, Any] | None:
    """Return a non-expired session row by token hash, else None.

    Expired rows are deleted opportunistically on lookup.
    """
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            "SELECT token_hash, user_id, created_at, expires_at FROM sessions WHERE token_hash = ?",
            (token_hash,),
        )
        row = await cur.fetchone()
        await cur.close()
        if row is None:
            return None
        expires_at = row[3]
        if _is_expired(expires_at):
            await db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            await db.commit()
            return None
    return {
        "token_hash": row[0],
        "user_id": row[1],
        "created_at": row[2],
        "expires_at": row[3],
    }


async def delete_session(token_hash: str) -> None:
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        await db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        await db.commit()


async def purge_expired_sessions() -> int:
    """Delete all expired sessions; return the number removed."""
    now = _utc_now_iso()
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        await db.commit()
        return cur.rowcount


def _is_expired(expires_at: str) -> bool:
    try:
        exp = datetime.fromisoformat(expires_at)
    except (TypeError, ValueError):
        return True
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp <= datetime.now(timezone.utc)


# ── OIDC in-flight flows (issue-local-010) ────────────────────────────────────


async def create_oidc_flow(
    state: str,
    nonce: str,
    code_verifier: str,
    next_path: str,
    expires_at: str,
) -> None:
    """Insert a short-lived OIDC flow record."""
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        await db.execute(
            "INSERT INTO oidc_flows (state, nonce, code_verifier, next_path, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (state, nonce, code_verifier, next_path, expires_at),
        )
        await db.commit()


async def consume_oidc_flow(state: str) -> dict[str, Any] | None:
    """Fetch and delete an OIDC flow by state. Returns None if missing or expired.

    Atomically consumes the record so replayed callbacks cannot reuse a state.
    """
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            "SELECT state, nonce, code_verifier, next_path, expires_at "
            "FROM oidc_flows WHERE state = ?",
            (state,),
        )
        row = await cur.fetchone()
        await cur.close()
        if row is None:
            return None
        # Always delete (consumed or expired)
        await db.execute("DELETE FROM oidc_flows WHERE state = ?", (state,))
        await db.commit()

    if _is_expired(row[4]):
        return None
    return {
        "state": row[0],
        "nonce": row[1],
        "code_verifier": row[2],
        "next_path": row[3],
        "expires_at": row[4],
    }


async def purge_expired_oidc_flows() -> int:
    """Delete all expired OIDC flow records; return the number removed."""
    now = _utc_now_iso()
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute("DELETE FROM oidc_flows WHERE expires_at < ?", (now,))
        await db.commit()
        return cur.rowcount


# ── API access keys (issue-local-029) ─────────────────────────────────────────


def _api_key_row_to_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row[0],
        "client_id": row[1],
        "secret_hash": row[2],
        "name": row[3],
        "scopes": json.loads(row[4]) if row[4] else [],
        "enabled": bool(row[5]),
        "created_by": row[6],
        "created_at": row[7],
        "last_used_at": row[8],
    }


_API_KEY_COLS = (
    "id, client_id, secret_hash, name, scopes, enabled, created_by, created_at, last_used_at"
)


async def create_api_key(
    client_id: str,
    secret_hash: str,
    name: str,
    scopes: list[str],
    *,
    created_by: str | None = None,
) -> int:
    """Insert a new API key record; return its id. Raises on duplicate client_id."""
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO api_keys (client_id, secret_hash, name, scopes, enabled, "
            "created_by, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
            (client_id, secret_hash, name, json.dumps(scopes), created_by, _utc_now_iso()),
        )
        await db.commit()
        return int(cur.lastrowid)


async def get_api_key_by_client_id(client_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            f"SELECT {_API_KEY_COLS} FROM api_keys WHERE client_id = ?", (client_id,)
        )
        row = await cur.fetchone()
        await cur.close()
    return _api_key_row_to_dict(row) if row else None


async def list_api_keys() -> list[dict[str, Any]]:
    """Return all API keys (including the secret hash — callers that expose
    this to the frontend must redact it themselves, same convention as
    ``list_users`` popping ``password_hash``)."""
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(f"SELECT {_API_KEY_COLS} FROM api_keys ORDER BY id")
        rows = await cur.fetchall()
        await cur.close()
    return [_api_key_row_to_dict(row) for row in rows]


async def set_api_key_scopes(client_id: str, scopes: list[str]) -> bool:
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            "UPDATE api_keys SET scopes = ? WHERE client_id = ?",
            (json.dumps(scopes), client_id),
        )
        await db.commit()
        return cur.rowcount > 0


async def set_api_key_name(client_id: str, name: str) -> bool:
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            "UPDATE api_keys SET name = ? WHERE client_id = ?", (name, client_id)
        )
        await db.commit()
        return cur.rowcount > 0


async def set_api_key_enabled(client_id: str, enabled: bool) -> bool:
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute(
            "UPDATE api_keys SET enabled = ? WHERE client_id = ?",
            (1 if enabled else 0, client_id),
        )
        await db.commit()
        return cur.rowcount > 0


async def touch_api_key_last_used(client_id: str) -> None:
    """Best-effort timestamp update on successful authentication. Never
    raises — a failure here must not break the request it's authenticating."""
    try:
        async with aiosqlite.connect(_USERS_DB_PATH) as db:
            await db.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE client_id = ?",
                (_utc_now_iso(), client_id),
            )
            await db.commit()
    except Exception:  # noqa: BLE001
        logger.debug("touch_api_key_last_used: failed to update %r (non-fatal)", client_id)


async def delete_api_key(client_id: str) -> bool:
    async with aiosqlite.connect(_USERS_DB_PATH) as db:
        cur = await db.execute("DELETE FROM api_keys WHERE client_id = ?", (client_id,))
        await db.commit()
        return cur.rowcount > 0
