"""
Assistant chat session storage (issue-local-032).

A *session* is one saved SmartSearch/Assistant conversation: a name and an
ordered list of chat turns. Sessions live in their own SQLite file
(``data/assistant_sessions.db``), separate from every other store, mirroring
the rest of the backend's "one small file per concern" convention (watchers,
run history, threat hunting, ...).

Ownership: every row is scoped to an *owner* string — the signed-in
username, or the literal ``"local"`` when auth is disabled (the app is fully
open in that mode, so every session is visible to whoever is using it,
matching how every other per-user concept in this app collapses to a single
shared bucket when there is no signed-in identity). All reads/writes are
filtered by owner at the SQL level — a caller can never see or touch another
owner's sessions, even by guessing an id.

No PII beyond the chat content the user itself typed/received is stored, and
all free-text fields (name, message content) are sanitized the same way the
chat transcript itself already is (``backend.search.service.sanitize_*``)
before being persisted, so a session can't smuggle invisible/bidi characters
into the sidebar list or an exported document any more than a live answer
already can.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import aiosqlite

from backend.search.service import sanitize_multiline, sanitize_text

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DB_PATH = _PROJECT_ROOT / "data" / "assistant_sessions.db"

# Bounds — generous enough for a real conversation, small enough that a
# session can never become an unbounded storage/DoS vector.
MAX_NAME_CHARS = 200
MAX_MESSAGES = 300
MAX_MESSAGE_CHARS = 20_000
MAX_SESSIONS_PER_OWNER = 200

CREATE_SESSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS assistant_sessions (
    id         TEXT PRIMARY KEY,
    owner      TEXT NOT NULL,
    name       TEXT NOT NULL,
    messages   TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

CREATE_OWNER_INDEX = """
CREATE INDEX IF NOT EXISTS idx_assistant_sessions_owner ON assistant_sessions(owner);
"""


async def init_sessions_db() -> None:
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(CREATE_SESSIONS_TABLE)
        await db.execute(CREATE_OWNER_INDEX)
        await db.commit()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_session_name() -> str:
    """``TARS-assistant-YYYYMMDD-HHMMSS`` — computed server-side (UTC) so the
    name is stable regardless of the caller's clock/timezone."""
    return datetime.now(timezone.utc).strftime("TARS-assistant-%Y%m%d-%H%M%S")


def _clean_name(name: str) -> str:
    cleaned = sanitize_text(name, MAX_NAME_CHARS).strip()
    return cleaned or default_session_name()


def _clean_messages(messages: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Sanitize and bound an incoming message list.

    Only the shape the frontend actually sends is kept — an unrecognized or
    missing ``role``/``content`` drops the message rather than persisting
    whatever a malformed or tampered client-side blob happened to contain.
    """
    if not messages:
        return []
    cleaned: list[dict[str, Any]] = []
    for m in messages[-MAX_MESSAGES:]:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role not in ("user", "assistant"):
            continue
        content = sanitize_multiline(str(m.get("content", "")), MAX_MESSAGE_CHARS)
        entry: dict[str, Any] = {"role": role, "content": content}
        if m.get("failed"):
            entry["failed"] = True
        sources = m.get("sources")
        if isinstance(sources, list):
            # Sources are titles/routes/snippets the search index already
            # produced (never secrets) — sanitize text fields defensively,
            # same standard as everywhere else search output is displayed.
            entry["sources"] = [
                {
                    "section": sanitize_text(str(s.get("section", ""))),
                    "title": sanitize_text(str(s.get("title", ""))),
                    "route": str(s.get("route", "")),
                    "snippet": sanitize_text(str(s.get("snippet", "")))
                    if s.get("snippet")
                    else None,
                    "ref": str(s["ref"]) if s.get("ref") is not None else None,
                }
                for s in sources[:20]
                if isinstance(s, dict)
            ]
        cleaned.append(entry)
    return cleaned


def _row_to_summary(row: aiosqlite.Row) -> dict[str, Any]:
    try:
        messages = json.loads(row["messages"] or "[]")
    except Exception:  # noqa: BLE001
        messages = []
    return {
        "id": row["id"],
        "name": row["name"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "message_count": len(messages) if isinstance(messages, list) else 0,
    }


def _row_to_full(row: aiosqlite.Row) -> dict[str, Any]:
    try:
        messages = json.loads(row["messages"] or "[]")
    except Exception:  # noqa: BLE001
        messages = []
    return {
        "id": row["id"],
        "name": row["name"],
        "messages": messages if isinstance(messages, list) else [],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


async def create_session(
    owner: str,
    *,
    name: str | None = None,
    messages: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    session_id = str(uuid4())
    now = _utc_now_iso()
    clean_name = _clean_name(name) if name else default_session_name()
    clean_messages = _clean_messages(messages)

    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            "INSERT INTO assistant_sessions (id, owner, name, messages, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (session_id, owner, clean_name, json.dumps(clean_messages), now, now),
        )
        # Retention: keep at most MAX_SESSIONS_PER_OWNER — trim the oldest
        # (by updated_at) rather than let one owner's history grow without
        # bound. A real user manages this via Delete long before hitting it;
        # this is a backstop, not the primary UX.
        cur = await db.execute(
            "SELECT id FROM assistant_sessions WHERE owner = ? "
            "ORDER BY updated_at DESC LIMIT -1 OFFSET ?",
            (owner, MAX_SESSIONS_PER_OWNER),
        )
        stale_ids = [r[0] for r in await cur.fetchall()]
        await cur.close()
        if stale_ids:
            placeholders = ",".join("?" for _ in stale_ids)
            await db.execute(
                f"DELETE FROM assistant_sessions WHERE id IN ({placeholders})",  # noqa: S608
                stale_ids,
            )
        await db.commit()

    return {
        "id": session_id,
        "name": clean_name,
        "messages": clean_messages,
        "created_at": now,
        "updated_at": now,
    }


async def list_sessions(owner: str) -> list[dict[str, Any]]:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, name, messages, created_at, updated_at FROM assistant_sessions "
            "WHERE owner = ? ORDER BY updated_at DESC",
            (owner,),
        )
        rows = await cur.fetchall()
        await cur.close()
    return [_row_to_summary(r) for r in rows]


async def get_session(owner: str, session_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, name, messages, created_at, updated_at FROM assistant_sessions "
            "WHERE owner = ? AND id = ?",
            (owner, session_id),
        )
        row = await cur.fetchone()
        await cur.close()
    return _row_to_full(row) if row else None


async def update_session(
    owner: str,
    session_id: str,
    *,
    name: str | None = None,
    messages: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    existing = await get_session(owner, session_id)
    if existing is None:
        return None

    new_name = _clean_name(name) if name is not None else existing["name"]
    new_messages = _clean_messages(messages) if messages is not None else existing["messages"]
    now = _utc_now_iso()

    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            "UPDATE assistant_sessions SET name = ?, messages = ?, updated_at = ? "
            "WHERE owner = ? AND id = ?",
            (new_name, json.dumps(new_messages), now, owner, session_id),
        )
        await db.commit()

    return {
        "id": session_id,
        "name": new_name,
        "messages": new_messages,
        "created_at": existing["created_at"],
        "updated_at": now,
    }


async def delete_session(owner: str, session_id: str) -> bool:
    async with aiosqlite.connect(_DB_PATH) as db:
        cur = await db.execute(
            "DELETE FROM assistant_sessions WHERE owner = ? AND id = ?",
            (owner, session_id),
        )
        await db.commit()
        return cur.rowcount > 0


def render_session_markdown(session: dict[str, Any]) -> str:
    """Render a session's transcript as a Markdown document — the assistant's
    own answers are already Markdown, so this is close to a literal
    transcript rather than a re-formatting job."""
    lines = [f"# {session['name']}", "", f"_Exported {_utc_now_iso()}_", ""]
    for m in session.get("messages", []):
        speaker = "You" if m.get("role") == "user" else "Assistant"
        lines.append(f"## {speaker}")
        lines.append("")
        lines.append(m.get("content", ""))
        sources = m.get("sources") or []
        if sources:
            lines.append("")
            lines.append(
                "**Sources:** "
                + ", ".join(f"{s.get('section')}: {s.get('title')}" for s in sources)
            )
        lines.append("")
    return "\n".join(lines)


def render_session_pdf(session: dict[str, Any]) -> bytes:
    """Render a session's transcript as a PDF, using the same print-friendly
    palette as the Threat Hunting report PDFs (report_writer.render_report_pdf)
    for visual consistency, at a fraction of that renderer's complexity — a
    chat transcript has no tables/sections, just alternating speaker blocks."""
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2 * cm,
        title=session["name"],
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title", parent=styles["Heading1"], fontSize=17, textColor=colors.HexColor("#0f172a")
    )
    meta_style = ParagraphStyle(
        "Meta", parent=styles["BodyText"], textColor=colors.HexColor("#64748b"), fontSize=9
    )
    speaker_style = ParagraphStyle(
        "Speaker",
        parent=styles["Heading3"],
        fontSize=11,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=2,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["BodyText"], textColor=colors.HexColor("#1f2937"), leading=14
    )

    def esc(text: str) -> str:
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    story = [
        Paragraph(esc(session["name"]), title_style),
        Paragraph(f"Exported {esc(_utc_now_iso())}", meta_style),
        Spacer(1, 0.4 * cm),
    ]
    for m in session.get("messages", []):
        speaker = "You" if m.get("role") == "user" else "Assistant"
        story.append(Paragraph(esc(speaker), speaker_style))
        content = esc(m.get("content", "")).replace("\n", "<br/>")
        story.append(Paragraph(content, body_style))
        sources = m.get("sources") or []
        if sources:
            src_text = "Sources: " + ", ".join(
                esc(f"{s.get('section')}: {s.get('title')}") for s in sources
            )
            story.append(Paragraph(src_text, meta_style))

    doc.build(story)
    return buf.getvalue()
