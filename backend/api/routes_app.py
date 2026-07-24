"""
Application-config routes — read and update application.yaml.

Exposes app_base_prefix, pagination cap, and the branding logo. Lives behind
/api/app/.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from backend.auth.dependencies import require_admin_when_enabled
from backend.config.loader import (
    load_agent_show_subtasks,
    load_agent_tools,
    load_agent_verbosity,
    load_agent_visualization,
    load_app_base_prefix,
    load_app_pagination_max,
    load_app_title,
    load_default_theme,
    load_hunt_id_prefix,
    load_logo_path,
    load_th_llm_max_retries,
    load_th_llm_retry_backoff_seconds,
    load_th_report_formats,
    load_th_research_effort,
    load_watcher_max_events,
    save_agent_show_subtasks,
    save_agent_tools,
    save_agent_verbosity,
    save_agent_visualization,
    save_app_base_prefix,
    save_app_pagination_max,
    save_app_title,
    save_default_theme,
    save_hunt_id_prefix,
    save_logo_path,
    save_th_llm_max_retries,
    save_th_llm_retry_backoff_seconds,
    save_th_report_formats,
    save_th_research_effort,
    save_watcher_max_events,
)

router = APIRouter(prefix="/api/app", tags=["app"])

# ── Branding logo (prompts-045) ──────────────────────────────────────────────
#
# Uploaded images live under data/branding/. We deliberately do NOT accept SVG:
# an SVG served same-origin is a stored-XSS vector (embedded <script> executes
# when the file is opened directly). Raster formats only. Every response also
# carries X-Content-Type-Options: nosniff so a mislabelled upload cannot be
# sniffed into an executable type.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BRANDING_DIR = _PROJECT_ROOT / "data" / "branding"
_LOGO_MAX_BYTES = 2 * 1024 * 1024  # 2 MiB
_LOGO_ALLOWED: dict[str, str] = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
    "image/gif": ".gif",
}
_LOGO_MEDIA_BY_EXT = {ext: ct for ct, ext in _LOGO_ALLOWED.items()}


def _sniff_logo_ext(data: bytes) -> str | None:
    """Return the canonical extension for *data* by inspecting magic bytes.

    Security (prompts-045 audit, MINOR): the client-supplied Content-Type is not
    trusted on its own. We confirm the bytes are actually one of the allowed
    raster formats, which also rejects an SVG (or any text/script) renamed with
    an image MIME. Returns None when the content matches no allowed format.
    """
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    return None


@router.get("/base-prefix")
async def get_base_prefix() -> dict[str, str]:
    """Return the configured app_base_prefix (empty string when unset)."""
    return {"app_base_prefix": load_app_base_prefix()}


@router.put("/base-prefix")
async def set_base_prefix(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Set the app_base_prefix.

    Body: {"app_base_prefix": "" | "/feeds" | ...}

    Returns the saved value plus restart_required: true to signal the UI
    that the change does NOT take effect until uvicorn is restarted.
    """
    value = body.get("app_base_prefix")
    # Defensive type checks: reject bools (which are int subclasses) and any
    # non-string payload before forwarding to the loader's validator.
    if not isinstance(value, str) or isinstance(value, bool):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'app_base_prefix' as a string",
        )
    try:
        save_app_base_prefix(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"app_base_prefix": value, "restart_required": True}


# ── App display title (issue-local-001-rev1) ─────────────────────────────────


@router.get("/title")
async def get_app_title() -> dict[str, str]:
    """Return the operator-configured display title.

    Public — no auth required. Used by the sidebar and browser-tab title logic
    before and after login. An empty string means 'use the default'.
    """
    return {"app_title": load_app_title()}


@router.put("/title")
async def set_app_title(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, str]:
    """Set the operator display title.

    Body: {"app_title": "My Custom Name"}

    An empty string clears the override (sidebar falls back to 'Mizton-ThreatBox').
    Maximum 80 characters; no newlines. Takes effect immediately (no restart).
    """
    value = body.get("app_title")
    if not isinstance(value, str) or isinstance(value, bool):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'app_title' as a string",
        )
    try:
        save_app_title(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"app_title": value.strip()}


# ── Instance-wide default UI theme (issue-local-016) ─────────────────────────


@router.get("/theme")
async def get_default_theme() -> dict[str, str]:
    """Return the instance-wide default theme.

    Public — no auth required. The login screen (pre-authentication) needs
    this to apply the configured theme before any user is known; see the
    matching carve-out in backend/main.py's auth_enforcement middleware.
    """
    return {"theme": load_default_theme()}


@router.put("/theme")
async def set_default_theme(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, str]:
    """Set the instance-wide default theme.

    Body: {"theme": "classic" | "energy" | "light"}

    A signed-in user with a personal theme override (see PUT /api/auth/me/theme)
    is unaffected by this — it only changes what everyone else (and logged-out
    visitors) sees. Takes effect immediately (no restart).
    """
    value = body.get("theme")
    if not isinstance(value, str) or isinstance(value, bool):
        raise HTTPException(status_code=400, detail="Body must contain 'theme' as a string")
    try:
        save_default_theme(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"theme": value}


@router.get("/pagination-max")
async def get_pagination_max() -> dict[str, int]:
    """Return the Normalized-viewer pagination cap (default 1000)."""
    return {"pagination_max": load_app_pagination_max()}


@router.put("/pagination-max")
async def set_pagination_max(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Set the Normalized-viewer pagination cap.

    Body: {"pagination_max": <int in [50, 100000]>}. Takes effect immediately
    (the viewer reads it live), so no restart is required.
    """
    value = body.get("pagination_max")
    # Reject bools (int subclass) and any non-int payload before the loader.
    if isinstance(value, bool) or not isinstance(value, int):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'pagination_max' as an integer",
        )
    try:
        save_app_pagination_max(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"pagination_max": value}


@router.get("/watcher-max-events")
async def get_watcher_max_events() -> dict[str, int]:
    """Return the per-watcher stored/feed event cap (default 1000)."""
    return {"watcher_max_events": load_watcher_max_events()}


@router.put("/watcher-max-events")
async def set_watcher_max_events(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Set the per-watcher stored/feed event cap.

    Body: {"watcher_max_events": <int in [10, 100000]>}. Takes effect on the
    next watcher evaluation, so no restart is required.
    """
    value = body.get("watcher_max_events")
    # Reject bools (int subclass) and any non-int payload before the loader.
    if isinstance(value, bool) or not isinstance(value, int):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'watcher_max_events' as an integer",
        )
    try:
        save_watcher_max_events(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"watcher_max_events": value}


# ── Threat Hunting LLM call retry/backoff (issue-local-014) ──────────────────


@router.get("/th-llm-max-retries")
async def get_th_llm_max_retries() -> dict[str, int]:
    """Return the max retry count for a single TH agent LLM call (default 3)."""
    return {"th_llm_max_retries": load_th_llm_max_retries()}


@router.put("/th-llm-max-retries")
async def set_th_llm_max_retries(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Set the max retry count for a single TH agent LLM call.

    Body: {"th_llm_max_retries": <int in [0, 10]>}.
    """
    value = body.get("th_llm_max_retries")
    if isinstance(value, bool) or not isinstance(value, int):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'th_llm_max_retries' as an integer",
        )
    try:
        save_th_llm_max_retries(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"th_llm_max_retries": value}


@router.get("/th-llm-retry-backoff-seconds")
async def get_th_llm_retry_backoff_seconds() -> dict[str, float]:
    """Return the base backoff (seconds) between TH agent LLM-call retries (default 2.0)."""
    return {"th_llm_retry_backoff_seconds": load_th_llm_retry_backoff_seconds()}


@router.put("/th-llm-retry-backoff-seconds")
async def set_th_llm_retry_backoff_seconds(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Set the base backoff (seconds) between TH agent LLM-call retries.

    Body: {"th_llm_retry_backoff_seconds": <number in [0.1, 60.0]>}.
    """
    value = body.get("th_llm_retry_backoff_seconds")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'th_llm_retry_backoff_seconds' as a number",
        )
    try:
        save_th_llm_retry_backoff_seconds(float(value))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"th_llm_retry_backoff_seconds": float(value)}


# ── Agent workflow verbosity (issue-local-004) ───────────────────────────────


@router.get("/agent-verbosity")
async def get_agent_verbosity() -> dict[str, str]:
    """Return the configured agentic workflow verbosity level."""
    return {"agent_workflow_verbosity": load_agent_verbosity()}


@router.put("/agent-verbosity")
async def set_agent_verbosity(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, str]:
    """Set the agentic workflow verbosity level.

    Body: {"agent_workflow_verbosity": "info" | "verbose" | "debug"}
    """
    value = body.get("agent_workflow_verbosity")
    if not isinstance(value, str):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'agent_workflow_verbosity' as a string",
        )
    try:
        save_agent_verbosity(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"agent_workflow_verbosity": value}


@router.get("/agent-visualization")
async def get_agent_visualization() -> dict[str, str]:
    """Return the configured workflow visualization style."""
    return {"agent_workflow_visualization": load_agent_visualization()}


@router.put("/agent-visualization")
async def set_agent_visualization(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, str]:
    """Set the workflow visualization style.

    Body: {"agent_workflow_visualization": "timeline" | "mermaid" | "reactflow"}
    """
    value = body.get("agent_workflow_visualization")
    if not isinstance(value, str):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'agent_workflow_visualization' as a string",
        )
    try:
        save_agent_visualization(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"agent_workflow_visualization": value}


# ── Agent workflow granular subtasks toggle (issue-local-012) ────────────────


@router.get("/agent-show-subtasks")
async def get_agent_show_subtasks() -> dict[str, bool]:
    """Return whether granular subtask nodes are shown in the workflow diagram."""
    return {"agent_workflow_show_subtasks": load_agent_show_subtasks()}


@router.put("/agent-show-subtasks")
async def set_agent_show_subtasks(
    body: dict,
    _user: object = Depends(require_admin_when_enabled),
) -> dict[str, bool]:
    """Persist the granular subtasks toggle."""
    value = body.get("agent_workflow_show_subtasks")
    if not isinstance(value, bool):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'agent_workflow_show_subtasks' as a boolean",
        )
    try:
        save_agent_show_subtasks(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"agent_workflow_show_subtasks": value}


# ── Threat Hunting research effort (issue-local-004) ─────────────────────────


@router.get("/th-research-effort")
async def get_th_research_effort() -> dict[str, str]:
    """Return the configured TH research effort level."""
    return {"th_research_effort": load_th_research_effort()}


@router.put("/th-research-effort")
async def set_th_research_effort(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, str]:
    """Set the TH research effort level.

    Body: {"th_research_effort": "high" | "medium" | "low"}
    """
    value = body.get("th_research_effort")
    if not isinstance(value, str):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'th_research_effort' as a string",
        )
    try:
        save_th_research_effort(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"th_research_effort": value}


# ── Threat Hunting HuntID prefix (issue-local-018) ────────────────────────────


@router.get("/hunt-id-prefix")
async def get_hunt_id_prefix() -> dict[str, str]:
    """Return the configured HuntID prefix (default 'TH')."""
    return {"hunt_id_prefix": load_hunt_id_prefix()}


@router.put("/hunt-id-prefix")
async def set_hunt_id_prefix(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, str]:
    """Set the HuntID prefix.

    Body: {"hunt_id_prefix": "TH"}
    """
    value = body.get("hunt_id_prefix")
    if not isinstance(value, str):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'hunt_id_prefix' as a string",
        )
    try:
        save_hunt_id_prefix(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"hunt_id_prefix": value}


# ── Threat Hunting report formats (issue-local-004) ──────────────────────────


@router.get("/th-report-formats")
async def get_th_report_formats() -> dict[str, Any]:
    """Return the configured report-format toggles."""
    return {"th_report_formats": load_th_report_formats()}


@router.put("/th-report-formats")
async def set_th_report_formats(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Set the report-format toggles.

    Body: {"th_report_formats": {"pdf": true, "markdown": true}}
    """
    value = body.get("th_report_formats")
    if not isinstance(value, dict):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'th_report_formats' as an object with pdf/markdown booleans",
        )
    try:
        save_th_report_formats(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"th_report_formats": value}


# ── Agent tools + document parsers toggles (issue-007) ──────────────────────


@router.get("/agent-tools")
async def get_agent_tools() -> dict[str, Any]:
    """Return the enabled/disabled toggle map for agent tools and document parsers."""
    return {"agent_tools": load_agent_tools()}


@router.put("/agent-tools")
async def set_agent_tools(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Set the agent tools toggle map (admin-gated).

    Body: {"agent_tools": {"extract_iocs": true, "refetch_url": false, ...}}
    """
    value = body.get("agent_tools")
    if not isinstance(value, dict):
        raise HTTPException(
            status_code=400,
            detail=("Body must contain 'agent_tools' as an object mapping tool names to booleans"),
        )
    try:
        save_agent_tools(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"agent_tools": load_agent_tools()}


@router.get("/agent-tools/catalog")
async def get_agent_tools_catalog() -> dict[str, Any]:
    """Return the full tool catalog with metadata and runtime availability.

    Includes operator-facing labels, descriptions, per-tool agent assignments,
    implications of disabling, and a live ``available`` flag (important for
    ``marker`` which requires an optional ML package).
    """
    from backend.threat_hunting.agents.tools import TOOL_METADATA
    from backend.threat_hunting.extractors.pdf_extractor import is_docling_available

    catalog: list[dict[str, Any]] = []
    for name, meta in TOOL_METADATA.items():
        entry = dict(meta)
        # Override 'available' for docling with the runtime check
        if name == "docling":
            entry["available"] = is_docling_available()
        catalog.append({"name": name, **entry})
    return {"catalog": catalog}


# ── Branding logo endpoints (prompts-045) ────────────────────────────────────


def _resolved_logo_file() -> Path | None:
    """Return the on-disk logo path if configured and present, else None.

    Defends in depth against a tampered application.yaml: the stored path must
    resolve to a real file inside data/branding/ (no traversal escape).
    """
    rel = load_logo_path()
    if not rel:
        return None
    fp = (_PROJECT_ROOT / rel).resolve()
    branding = _BRANDING_DIR.resolve()
    try:
        fp.relative_to(branding)
    except ValueError:
        return None
    return fp if fp.is_file() else None


@router.get("/logo-info")
async def logo_info() -> dict[str, bool]:
    """Report whether a branding logo is configured (cheap boolean probe)."""
    return {"has_logo": _resolved_logo_file() is not None}


@router.get("/logo")
async def get_logo() -> FileResponse:
    """Serve the branding logo image (public). 404 when none is configured."""
    fp = _resolved_logo_file()
    if fp is None:
        raise HTTPException(status_code=404, detail="No logo configured")
    media = _LOGO_MEDIA_BY_EXT.get(fp.suffix.lower(), "application/octet-stream")
    return FileResponse(
        fp,
        media_type=media,
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-cache"},
    )


@router.post("/logo")
async def upload_logo(
    file: UploadFile = File(...),
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Upload/replace the branding logo (admin-gated by the auth middleware).

    Accepts PNG, JPEG, WebP, or GIF up to 2 MiB. SVG is rejected (stored-XSS).
    The previous logo file is removed so a format switch never leaves a stale
    image behind. The image type is determined by sniffing the file's magic
    bytes, not by trusting the client-supplied Content-Type.
    """
    if file.content_type not in _LOGO_ALLOWED:
        raise HTTPException(
            status_code=400,
            detail="Unsupported image type. Allowed: PNG, JPEG, WebP, GIF.",
        )
    # Read one byte past the cap so we can detect oversize without loading more.
    data = await file.read(_LOGO_MAX_BYTES + 1)
    if len(data) > _LOGO_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Logo exceeds the 2 MiB limit")
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    # Authoritative type check: the bytes must actually be an allowed raster
    # format, regardless of the declared Content-Type or filename.
    ext = _sniff_logo_ext(data)
    if ext is None:
        raise HTTPException(
            status_code=400,
            detail="File content is not a valid PNG, JPEG, WebP, or GIF image.",
        )

    _BRANDING_DIR.mkdir(parents=True, exist_ok=True)
    for old in _BRANDING_DIR.glob("logo.*"):
        old.unlink(missing_ok=True)
    dest = _BRANDING_DIR / f"logo{ext}"
    dest.write_bytes(data)

    rel = f"data/branding/logo{ext}"
    save_logo_path(rel)
    return {"logo_path": rel, "has_logo": True}


@router.delete("/logo")
async def delete_logo(
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, bool]:
    """Remove the branding logo and revert to the default icon (admin-gated)."""
    for old in _BRANDING_DIR.glob("logo.*"):
        old.unlink(missing_ok=True)
    save_logo_path("")
    return {"has_logo": False}
