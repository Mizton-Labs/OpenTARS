"""Global search + SmartSearch routes (issue-local-031).

  GET  /api/search          — deterministic, role-scoped search across the app
  GET  /api/search/status   — whether SmartSearch is available, and if not, why
  POST /api/search/smart    — retrieval-augmented answer over the same results

All three are READ-ONLY. Results are scoped to the caller's role by
``backend.search.service`` before anything is returned, and SmartSearch is fed
nothing but those already-scoped snippets — see that module and
``backend.search.smart`` for the full guardrail rationale.

Assistant chat sessions (issue-local-032) — save/rename/delete/export a
saved SmartSearch/Assistant conversation:

  POST   /api/search/sessions              — create (default name if omitted)
  GET    /api/search/sessions              — list the caller's sessions (summary)
  GET    /api/search/sessions/{id}         — read one session in full
  PUT    /api/search/sessions/{id}         — rename and/or replace its messages
  DELETE /api/search/sessions/{id}         — delete
  GET    /api/search/sessions/{id}/markdown — download as Markdown
  GET    /api/search/sessions/{id}/pdf      — download as PDF

Every session route is scoped to the caller's own identity —
``backend.search.sessions`` filters every query by owner, so a session id
alone is never enough to read or modify someone else's conversation.

Scoped API access keys cannot reach any route in this module: the auth
middleware hard-caps API-key requests to ``/api/threat-hunting/`` and no
scope grants anything here.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field

from backend.config.loader import (
    load_assistant_context_hits,
    load_assistant_provider,
    load_auth_enabled,
)
from backend.llm.errors import LLMProviderError, LLMTransportError
from backend.search import sessions as sessions_db
from backend.search.service import MAX_TOTAL_RESULTS, global_search
from backend.search.smart import (
    MAX_HISTORY_TURNS,
    MAX_QUESTION_CHARS,
    SmartSearchUnavailable,
    smart_answer,
    smart_search_status,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/search", tags=["search"])


def _caller_role(request: Request) -> str | None:
    """Resolve the role search should run as.

    When authentication is disabled the application is fully open — the same
    condition under which the SPA treats everyone as an admin — so search must
    behave the same way rather than returning nothing for an absent user.
    """
    if not load_auth_enabled():
        return "admin"
    user = getattr(request.state, "user", None)
    if not user:
        return None
    return user.get("role")


def _caller_owner(request: Request) -> str:
    """Resolve the Assistant-session owner key for the current caller.

    Auth disabled ⇒ the app is fully open and every session collapses into a
    single shared bucket ("local"), the same convention every other
    per-identity concept in this app uses in open mode.
    """
    if not load_auth_enabled():
        return "local"
    user = getattr(request.state, "user", None)
    username = user.get("username") if user else None
    return username or "local"


def _safe_disposition_filename(label: str, fallback: str) -> str:
    """Sanitize a fully user-controlled session name for a Content-Disposition
    header — strips quotes and control characters (including CR/LF, which
    could otherwise inject additional headers). Mirrors
    ``routes_threat_hunting._safe_disposition_filename``."""
    cleaned = "".join(ch for ch in label if ch not in '"\\' and ch.isprintable())
    cleaned = cleaned.strip()
    return cleaned or fallback


@router.get("")
async def search(
    request: Request,
    q: str = Query(default="", description="Search text"),
    limit: int = Query(default=MAX_TOTAL_RESULTS, ge=1, le=MAX_TOTAL_RESULTS),
) -> dict:
    """Search hunts, threat intel, watchers, pages, settings, and docs."""
    return await global_search(q, role=_caller_role(request), limit=limit)


@router.get("/status")
async def status() -> dict:
    """Report SmartSearch availability for the always-visible Normal/Smart switch."""
    return smart_search_status(load_assistant_provider())


class HistoryTurn(BaseModel):
    role: str
    content: str


class SmartSearchBody(BaseModel):
    question: str = Field(max_length=MAX_QUESTION_CHARS * 4)
    #: Prior turns. Trimmed and sanitised again server-side; the bound here only
    #: keeps an oversized payload from being parsed at all.
    history: list[HistoryTurn] = Field(default_factory=list, max_length=MAX_HISTORY_TURNS * 4)


@router.post("/smart")
async def smart(request: Request, body: SmartSearchBody) -> dict:
    """Answer a question from role-scoped application context."""
    try:
        return await smart_answer(
            body.question,
            role=_caller_role(request),
            history=[turn.model_dump() for turn in body.history],
            provider_name=load_assistant_provider(),
            max_context_hits=load_assistant_context_hits(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SmartSearchUnavailable as exc:
        # 503: the feature is switched off / not configured, not a bad request.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (LLMProviderError, LLMTransportError) as exc:
        logger.warning("SmartSearch upstream failure: %s", exc)
        raise HTTPException(
            status_code=502,
            detail="The LLM provider could not be reached. Check its configuration and try again.",
        ) from exc


# ── Assistant chat sessions (issue-local-032) ───────────────────────────────


class SessionMessageIn(BaseModel):
    role: str
    content: str = Field(max_length=sessions_db.MAX_MESSAGE_CHARS * 2)
    failed: bool | None = None
    # Every other field here is bounded; this one was not, unlike the rest
    # of this model — a caller could otherwise attach an unbounded list of
    # unconstrained dicts per message. sessions.py's _clean_messages() caps
    # each message to 20 sources anyway, but that trim happens AFTER the
    # full body is parsed/validated, so the size cap belongs here too.
    sources: list[dict] | None = Field(default=None, max_length=50)


class SessionCreateBody(BaseModel):
    name: str | None = Field(default=None, max_length=sessions_db.MAX_NAME_CHARS * 4)
    messages: list[SessionMessageIn] | None = Field(
        default=None, max_length=sessions_db.MAX_MESSAGES * 2
    )


class SessionUpdateBody(BaseModel):
    name: str | None = Field(default=None, max_length=sessions_db.MAX_NAME_CHARS * 4)
    messages: list[SessionMessageIn] | None = Field(
        default=None, max_length=sessions_db.MAX_MESSAGES * 2
    )


def _session_or_404(session: dict | None) -> dict:
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.post("/sessions", status_code=201)
async def create_session(request: Request, body: SessionCreateBody) -> dict:
    """Create a new Assistant session. Defaults to a timestamped name
    (``TARS-assistant-YYYYMMDD-HHMMSS``) when none is given."""
    return await sessions_db.create_session(
        _caller_owner(request),
        name=body.name,
        messages=[m.model_dump() for m in body.messages] if body.messages else None,
    )


@router.get("/sessions")
async def list_sessions(request: Request) -> list[dict]:
    """List the caller's own sessions, newest-first, summary only (no
    message bodies — kept light for a sidebar/session-picker list)."""
    return await sessions_db.list_sessions(_caller_owner(request))


@router.get("/sessions/{session_id}")
async def get_session(request: Request, session_id: str) -> dict:
    """Read one of the caller's own sessions in full, including messages."""
    return _session_or_404(await sessions_db.get_session(_caller_owner(request), session_id))


@router.put("/sessions/{session_id}")
async def update_session(request: Request, session_id: str, body: SessionUpdateBody) -> dict:
    """Rename and/or replace a session's messages (used both for the
    explicit "Save session" rename action and for continuous auto-save as a
    conversation progresses)."""
    updated = await sessions_db.update_session(
        _caller_owner(request),
        session_id,
        name=body.name,
        messages=[m.model_dump() for m in body.messages] if body.messages is not None else None,
    )
    return _session_or_404(updated)


@router.delete("/sessions/{session_id}", status_code=204)
async def delete_session(request: Request, session_id: str) -> None:
    deleted = await sessions_db.delete_session(_caller_owner(request), session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Session not found")


@router.get("/sessions/{session_id}/markdown")
async def download_session_markdown(request: Request, session_id: str) -> Response:
    session = _session_or_404(await sessions_db.get_session(_caller_owner(request), session_id))
    markdown = sessions_db.render_session_markdown(session)
    filename = _safe_disposition_filename(session["name"], session_id[:8]) + ".md"
    return Response(
        content=markdown,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/sessions/{session_id}/pdf")
async def download_session_pdf(request: Request, session_id: str) -> StreamingResponse:
    session = _session_or_404(await sessions_db.get_session(_caller_owner(request), session_id))
    try:
        pdf_bytes = sessions_db.render_session_pdf(session)
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="PDF export requires reportlab. Install it with: pip install reportlab",
        ) from None
    except Exception as exc:
        logger.exception("Session PDF render failed for %s: %s", session_id[:8], exc)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc

    from io import BytesIO

    filename = _safe_disposition_filename(session["name"], session_id[:8]) + ".pdf"
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
