"""
Application-config routes — read and update application.yaml.

Exposes app_base_prefix, pagination cap, the branding logo, and allowlisted
project docs (About page's API Docs tab, issue-local-030). Lives behind
/api/app/.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from backend import docs_registry
from backend.auth.dependencies import require_admin_when_enabled
from backend.config.drift import apply_config_drift_fix, compute_config_drift
from backend.config.loader import (
    load_agent_show_subtasks,
    load_agent_tools,
    load_agent_verbosity,
    load_agent_visualization,
    load_app_base_prefix,
    load_app_pagination_max,
    load_app_title,
    load_assistant_context_hits,
    load_assistant_provider,
    load_default_theme,
    load_hunt_id_prefix,
    load_th_llm_max_retries,
    load_th_llm_retry_backoff_seconds,
    load_th_node_timeout_seconds,
    load_th_query_languages,
    load_th_report_formats,
    load_th_research_effort,
    load_th_runs_table_page_size,
    load_watcher_max_events,
    resolve_logo_file,
    save_agent_show_subtasks,
    save_agent_tools,
    save_agent_verbosity,
    save_agent_visualization,
    save_app_base_prefix,
    save_app_pagination_max,
    save_app_title,
    save_assistant_context_hits,
    save_assistant_provider,
    save_default_theme,
    save_hunt_id_prefix,
    save_logo_path,
    save_th_llm_max_retries,
    save_th_llm_retry_backoff_seconds,
    save_th_node_timeout_seconds,
    save_th_query_languages,
    save_th_report_formats,
    save_th_research_effort,
    save_th_runs_table_page_size,
    save_watcher_max_events,
)
from backend.llm.registry import list_provider_names

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
_DOCS_DIR = _PROJECT_ROOT / "docs"
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

    An empty string clears the override (sidebar falls back to 'OpenTARS').
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

    Body: {"theme": "classic" | "energy" | "light" | "ocean"}

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


# ── Threat Hunting pipeline per-node timeout (issue-local-034) ───────────────


@router.get("/th-node-timeout-seconds")
async def get_th_node_timeout_seconds() -> dict[str, int]:
    """Return the per-node timeout (seconds) for the TH pipeline (default 900)."""
    return {"th_node_timeout_seconds": load_th_node_timeout_seconds()}


@router.put("/th-node-timeout-seconds")
async def set_th_node_timeout_seconds(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Set the per-node timeout (seconds) for the TH pipeline.

    Body: {"th_node_timeout_seconds": <int in [60, 3600]>}.
    """
    value = body.get("th_node_timeout_seconds")
    if isinstance(value, bool) or not isinstance(value, int):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'th_node_timeout_seconds' as an integer",
        )
    try:
        save_th_node_timeout_seconds(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"th_node_timeout_seconds": value}


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

    Body: {"agent_workflow_verbosity": "info" | "detailed" | "verbose" | "debug"}
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


# ── Threat Hunting runs-table page size (issue-local-042 item 27) ───────────


@router.get("/th-runs-table-page-size")
async def get_th_runs_table_page_size() -> dict[str, int]:
    """Return the configured RunsStatusTable page size (default 10)."""
    return {"th_runs_table_page_size": load_th_runs_table_page_size()}


@router.put("/th-runs-table-page-size")
async def set_th_runs_table_page_size(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, int]:
    """Set the RunsStatusTable page size.

    Body: {"th_runs_table_page_size": <int in [5, 200]>}
    """
    value = body.get("th_runs_table_page_size")
    if isinstance(value, bool) or not isinstance(value, int):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'th_runs_table_page_size' as an integer",
        )
    try:
        save_th_runs_table_page_size(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"th_runs_table_page_size": value}


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


# ── AI Assistant provider + context budget (issue-local-039) ────────────────


def _assistant_settings_payload() -> dict[str, Any]:
    return {
        "assistant_provider": load_assistant_provider(),
        "assistant_context_hits": load_assistant_context_hits(),
    }


@router.get("/assistant-settings")
async def get_assistant_settings(
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Return the AI Assistant's pinned LLM provider (null = follow the
    global default provider) and its retrieved-hit context budget."""
    return _assistant_settings_payload()


@router.put("/assistant-settings")
async def set_assistant_settings(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Set the AI Assistant's pinned LLM provider and context budget.

    Body: {"assistant_provider": "my-provider" | null, "assistant_context_hits": 24}
    A non-null provider must match a currently configured LLM provider name.
    """
    provider = body.get("assistant_provider")
    if provider is not None and not isinstance(provider, str):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'assistant_provider' as a string or null",
        )
    if isinstance(provider, str) and provider.strip():
        known = {p["name"] for p in list_provider_names()}
        if provider not in known:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown LLM provider {provider!r}",
            )
    else:
        provider = None

    context_hits = body.get("assistant_context_hits")
    if not isinstance(context_hits, int) or isinstance(context_hits, bool):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'assistant_context_hits' as an integer",
        )

    try:
        save_assistant_provider(provider)
        save_assistant_context_hits(context_hits)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _assistant_settings_payload()


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


# ── Threat Hunting default query languages (issue-local-041) ────────────────


@router.get("/th-query-languages")
async def get_th_query_languages() -> dict[str, Any]:
    """Return the configured default query-language toggles."""
    return {"th_query_languages": load_th_query_languages()}


@router.put("/th-query-languages")
async def set_th_query_languages(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Set the default query-language toggles.

    Body: {"th_query_languages": {"spl": true, "kql": true, "cql": false, "elasticsearch": true}}
    """
    value = body.get("th_query_languages")
    if not isinstance(value, dict):
        raise HTTPException(
            status_code=400,
            detail="Body must contain 'th_query_languages' as an object with spl/kql/cql/elasticsearch booleans",
        )
    try:
        save_th_query_languages(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"th_query_languages": value}


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
    """Return the on-disk logo path if configured and present, else None."""
    return resolve_logo_file()


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


# ── Project documentation (issue-local-030) ──────────────────────────────────
#
# Serves an allowlisted project doc's raw Markdown for in-app rendering (the
# About page's API Docs tab). doc_id is only ever used as a dict lookup key —
# never concatenated into a filesystem path — so this can't become an
# arbitrary-file-read primitive regardless of what a caller passes.
# The allowlist itself lives in backend/docs_registry.py so this route and
# global search (issue-local-031) share one copy — a drifted path allowlist is
# a security bug, not just an inconsistency.


@router.get("/docs/{doc_id}")
async def get_doc(doc_id: str) -> dict[str, str]:
    """Return an allowlisted project doc's raw Markdown content."""
    path = docs_registry.resolve(doc_id)
    if path is None:
        raise HTTPException(status_code=404, detail="Unknown document")
    return {"doc_id": doc_id, "content": path.read_text(encoding="utf-8")}


# ── Config drift (issue-local-024 follow-up) ─────────────────────────────────
#
# Admin-only: application.yaml/sources.yaml/feed-fields.yaml/normalizer-
# config.yaml are gitignored instance state (see backend/config/drift.py's
# module docstring). Every scalar setting already self-heals on upgrade; this
# surfaces the one gap that doesn't (feed-fields.yaml's core_fields list) plus,
# generically, any brand-new top-level key a future release's .example ships.


@router.get("/config-drift")
async def get_config_drift(
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Return drift reports for every tracked config file that has any.

    Empty ``reports`` means every live config file already has everything
    the shipped .example templates introduce.
    """
    return {"reports": compute_config_drift()}


@router.post("/config-drift/apply")
async def apply_config_drift(
    body: dict[str, Any],
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> dict[str, Any]:
    """Apply an admin-selected subset of a file's detected drift.

    Body: {"file": "feed-fields.yaml", "keys": [...], "core_field_names": [...]}
    Only the named keys/fields are added; everything else in the live file
    (including any customization) is left untouched. Returns the refreshed
    drift report list so the UI can confirm what's left, if anything.
    """
    file = body.get("file")
    if not isinstance(file, str) or not file:
        raise HTTPException(status_code=400, detail="Body must contain 'file' as a string")
    keys = body.get("keys") or []
    core_field_names = body.get("core_field_names") or []
    if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
        raise HTTPException(status_code=400, detail="'keys' must be a list of strings")
    if not isinstance(core_field_names, list) or not all(
        isinstance(n, str) for n in core_field_names
    ):
        raise HTTPException(status_code=400, detail="'core_field_names' must be a list of strings")
    if not keys and not core_field_names:
        raise HTTPException(
            status_code=400, detail="Body must select at least one key or core field to apply"
        )
    try:
        apply_config_drift_fix(file, keys=keys, core_field_names=core_field_names)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"reports": compute_config_drift()}
