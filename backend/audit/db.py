"""
Audit event storage (issue-local-033) — the backend for the "Audit" sidebar
section.

Four categories, matching the four Audit tabs:

  - ``application`` — ingestion/operational events. Fed by a logging.Handler
    bridge (log_bridge.py) attached to the existing ``backend.audit`` logger
    (feed pulls/pushes, watcher triggers, ...) — that logger already existed
    for the ingestion audit trail (see logging_config.py); this module gives
    it a queryable, filterable home instead of only a flat-file log.
  - ``user`` — actions a signed-in person took. Populated two ways: a generic
    ASGI middleware (main.py) records every successful authenticated
    mutating request (POST/PUT/DELETE/PATCH) with no per-route code needed,
    and a couple of identity-establishing routes (login) that the generic
    middleware structurally cannot attribute record themselves.
  - ``agent`` — AI/pipeline activity. Fed from the single existing choke
    point every agent node, SIEM execution step, and report/threat-intel
    step already calls: ``threat_hunting.db.append_run_step_log``. One
    integration point covers the whole pipeline rather than instrumenting
    each of the ~15 step call sites individually.
  - ``system`` — operational health. Fed by a logging.Handler bridge on the
    root logger filtered to WARNING+ (real problems, anywhere in the app)
    plus a dedicated ``backend.system`` logger for informational lifecycle
    milestones (startup, schema migrations).

Every row carries ``username`` (nullable — None for anonymous/system
events). Row-level ownership is what makes the "a non-admin only sees their
own activity" permission rule enforceable server-side (routes_audit.py),
the same pattern already used for Assistant sessions (backend/search/
sessions.py) — never trust a client-supplied username, always resolve one
from the request's own session.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import aiosqlite

# A distinct namespace, deliberately NOT "backend.audit.*" — the "application"
# audit-log bridge (log_bridge.py) attaches to the "backend.audit" logger, and
# child-logger records propagate to parent handlers by default. Naming this
# logger "backend.audit.db" would feed this module's own failure warnings
# back into the audit trail it is trying to write to.
logger = logging.getLogger("backend.audit_store")

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DB_PATH = _PROJECT_ROOT / "data" / "audit.db"

CATEGORIES = ("application", "user", "agent", "system")

# Retention: keep at most this many rows total. Checked probabilistically
# (not on every insert — a COUNT(*) per write would not scale) so the table
# can never grow unbounded even under sustained high-volume logging.
MAX_EVENTS = 100_000
_TRIM_CHECK_EVERY = 200
_TRIM_TARGET = 90_000  # trim back down to this many when the cap is hit

MAX_SUMMARY_CHARS = 500
MAX_DETAIL_CHARS = 4_000

_insert_count = 0

CREATE_AUDIT_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS audit_events (
    id         TEXT PRIMARY KEY,
    category   TEXT NOT NULL,
    action     TEXT NOT NULL,
    username   TEXT,
    role       TEXT,
    summary    TEXT NOT NULL,
    detail     TEXT,
    created_at TEXT NOT NULL
);
"""

CREATE_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_events(category);",
    "CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_events(username);",
    "CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at);",
)


async def init_audit_db() -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(CREATE_AUDIT_EVENTS_TABLE)
        for stmt in CREATE_INDEXES:
            await db.execute(stmt)
        await db.commit()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def record_event(
    category: str,
    action: str,
    *,
    username: str | None = None,
    role: str | None = None,
    summary: str,
    detail: dict[str, Any] | None = None,
) -> None:
    """Persist one audit event. Best-effort: a logging/audit failure must
    never break the request or job that triggered it, so every caller of
    this function does so from a try/except (or, for the logging-handler
    bridge, inside emit()'s own already-swallowed exception path)."""
    global _insert_count

    if category not in CATEGORIES:
        logger.warning("record_event: unknown category %r, dropping", category)
        return

    try:
        detail_json = json.dumps(detail, default=str)[:MAX_DETAIL_CHARS] if detail else None
        async with aiosqlite.connect(_DB_PATH) as db:
            await db.execute(
                "INSERT INTO audit_events (id, category, action, username, role, summary, "
                "detail, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    str(uuid4()),
                    category,
                    action[:200],
                    username,
                    role,
                    summary[:MAX_SUMMARY_CHARS],
                    detail_json,
                    _utc_now_iso(),
                ),
            )
            await db.commit()

            _insert_count += 1
            if _insert_count % _TRIM_CHECK_EVERY == 0:
                cur = await db.execute("SELECT COUNT(*) FROM audit_events")
                (total,) = await cur.fetchone()
                await cur.close()
                if total > MAX_EVENTS:
                    await db.execute(
                        "DELETE FROM audit_events WHERE id IN ("
                        "  SELECT id FROM audit_events ORDER BY created_at ASC "
                        "  LIMIT ?"
                        ")",
                        (total - _TRIM_TARGET,),
                    )
                    await db.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort, never propagate
        logger.warning("record_event failed (category=%s action=%s): %s", category, action, exc)


async def list_events(
    *,
    category: str | None = None,
    username: str | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """List audit events, newest first. *username*, when given, restricts to
    exactly that actor — the sole enforcement point for "a non-admin only
    sees their own activity" (routes_audit.py always passes the caller's own
    username for a non-admin; never a client-supplied value)."""
    where_clauses: list[str] = []
    params: list[Any] = []
    if category:
        where_clauses.append("category = ?")
        params.append(category)
    if username:
        where_clauses.append("username = ?")
        params.append(username)
    if search:
        where_clauses.append("(summary LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\')")
        like_term = f"%{_escape_like(search)}%"
        params.extend([like_term, like_term])
    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            f"SELECT COUNT(*) AS n FROM audit_events {where_sql}",  # noqa: S608
            params,
        )
        row = await cur.fetchone()
        await cur.close()
        total = row["n"] if row else 0

        cur = await db.execute(
            f"SELECT id, category, action, username, role, summary, detail, created_at "  # noqa: S608
            f"FROM audit_events {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        rows = await cur.fetchall()
        await cur.close()

    events = []
    for r in rows:
        detail = None
        if r["detail"]:
            try:
                detail = json.loads(r["detail"])
            except Exception:  # noqa: BLE001
                detail = None
        events.append(
            {
                "id": r["id"],
                "category": r["category"],
                "action": r["action"],
                "username": r["username"],
                "role": r["role"],
                "summary": r["summary"],
                "detail": detail,
                "created_at": r["created_at"],
            }
        )
    return events, total


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
