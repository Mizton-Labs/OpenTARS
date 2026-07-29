"""Global search + SmartSearch routes (issue-local-031).

  GET  /api/search          — deterministic, role-scoped search across the app
  GET  /api/search/status   — whether SmartSearch is available, and if not, why
  POST /api/search/smart    — retrieval-augmented answer over the same results

All three are READ-ONLY. Results are scoped to the caller's role by
``backend.search.service`` before anything is returned, and SmartSearch is fed
nothing but those already-scoped snippets — see that module and
``backend.search.smart`` for the full guardrail rationale.

Scoped API access keys cannot reach these routes: the auth middleware
hard-caps API-key requests to ``/api/threat-hunting/`` and no scope grants
anything here.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from backend.config.loader import load_auth_enabled
from backend.llm.errors import LLMProviderError, LLMTransportError
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
    return smart_search_status()


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
