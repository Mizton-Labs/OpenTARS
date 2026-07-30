"""Audit event routes (issue-local-033) — GET /api/audit/events.

Read-only. A category is always required (the UI is tab-based, one category
at a time — the same shape Data Explorer's /api/threat-hunting/explorer/
{category} already uses). Visibility:

  - admin (or auth disabled, the open-app admin-equivalent): every category,
    every actor.
  - any other signed-in role: only the "user" and "agent" categories
    ("Application" and "System" are not a per-user concept), and always
    scoped to the CALLER'S OWN username — never a client-supplied value, the
    same non-negotiable rule backend.search.sessions already enforces for
    Assistant sessions.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from backend.audit import db as audit_db
from backend.config.loader import load_auth_enabled

router = APIRouter(prefix="/api/audit", tags=["audit"])

#: Categories a non-admin caller may ever see — see module docstring.
_USER_VISIBLE_CATEGORIES = frozenset({"user", "agent"})


def _caller(request: Request) -> tuple[str | None, str | None]:
    """Resolve (username, role) for the current caller.

    Auth disabled -> the app is fully open, the same admin-equivalent
    treatment every other read-scoped feature in this app already gives an
    absent identity (search, dashboard, ...).
    """
    if not load_auth_enabled():
        return None, "admin"
    user = getattr(request.state, "user", None)
    if not user:
        return None, None
    return user.get("username"), user.get("role")


@router.get("/events")
async def list_events(
    request: Request,
    category: str = Query(...),
    search: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    if category not in audit_db.CATEGORIES:
        raise HTTPException(status_code=404, detail=f"Unknown category: {category}")

    caller_username, role = _caller(request)
    is_admin = role == "admin"

    if is_admin:
        username = None  # every actor
    else:
        if category not in _USER_VISIBLE_CATEGORIES:
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        username = caller_username  # own activity only — never client-overridable

    events, total = await audit_db.list_events(
        category=category, username=username, search=search, limit=limit, offset=offset
    )
    return {"events": events, "total": total}
