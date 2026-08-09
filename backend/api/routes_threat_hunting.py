"""
Threat Hunting API routes (issue-local-002, Phase 1–5, issue-008).

All routes require authentication when auth is enabled. Admin and
threat-researcher roles have write access; threat-viewer has read-only access
(enforced by the middleware allowlist in main.py).

Evidence endpoints:
  POST /packages/{id}/evidence/file      — upload a file (PDF, DOCX, TXT, CSV, …)
  POST /packages/{id}/evidence/url       — register a URL (fetched by the pipeline)
  POST /packages/{id}/evidence/text      — add manual text/note
  POST /packages/{id}/evidence/watcher   — import watcher events
  GET  /packages/{id}/evidence           — list evidence items
  DELETE /packages/{id}/evidence/{eid}   — remove an evidence item
  GET  /packages/{id}/iocs               — list all extracted IOCs (populated by pipeline)

Generation endpoints (Phase 3):
  POST /packages/{id}/generate           — start LLM pipeline
  GET  /packages/{id}/generate/status    — poll generation status + draft
  POST /packages/{id}/approve            — approve generated package
  POST /packages/{id}/reject             — reject generated package

SIEM connector endpoints (Phase 5):
  GET    /connectors                     — list SIEM connectors
  POST   /connectors                     — create connector
  GET    /connectors/{id}                — get connector
  PUT    /connectors/{id}                — update connector
  DELETE /connectors/{id}                — delete connector
  POST   /connectors/{id}/test           — test connection

Execution endpoints (Phase 5):
  POST /packages/{id}/execute            — start SIEM execution
  GET  /packages/{id}/results            — list task results
  GET  /packages/{id}/results/{rid}      — get single task result
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from backend.auth.dependencies import require_admin_when_enabled
from backend.threat_hunting import db as th_db

# extract_file import removed — file parsing deferred to pipeline (issue-local-011)
# from backend.threat_hunting.extractors.dispatcher import extract_file
# issue-008-2B: fetch_url and extract_iocs_from_text are no longer called at
# upload time. URL fetching and IOC extraction are now performed by the agent
# pipeline (intake_classifier), keeping them as genuine agent tasks.
# The imports remain available for other use sites (e.g. SSRF error re-raise).
from backend.threat_hunting.extractors.url_fetcher import fetch_url  # noqa: F401 — SSRF route
from backend.threat_hunting.models import (
    AddManualTextBody,
    AddUrlBody,
    AddWatcherBody,
    EvidenceItemOut,
    ExtractedIOCOut,
    HuntPackageCreate,
    HuntPackageOut,
    HuntPackageUpdate,
)
from backend.threat_hunting.ssrf import SSRFError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/threat-hunting", tags=["threat-hunting"])

_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB


def _pkg_or_404(pkg: dict | None) -> dict:
    if pkg is None:
        raise HTTPException(status_code=404, detail="Hunt package not found")
    return pkg


def _item_or_404(item: dict | None) -> dict:
    if item is None:
        raise HTTPException(status_code=404, detail="Evidence item not found")
    return item


# ── Hunt Packages ─────────────────────────────────────────────────────────────


@router.get("/packages", response_model=list[HuntPackageOut])
async def list_packages(
    search: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
) -> list[dict]:
    """List all non-archived hunt packages.

    issue-local-020: optional deep search (name/description + this
    package's runs' stored analysis JSON + extracted IOCs) and date-range
    filtering on created_at.
    """
    return await th_db.list_hunt_packages(search=search, date_from=date_from, date_to=date_to)


@router.get("/dashboard")
async def get_dashboard(
    search: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
) -> dict:
    """Aggregate stats for the Threat Hunting Dashboard (issue-local-032) —
    the default view of the Threat Hunting module. *search*/*date_from*/
    *date_to* use the same deep-search and date-range rules as GET
    /packages, so the counts always reflect the same filtered set the
    package list would show for the same query.
    """
    return await th_db.get_hunt_dashboard_stats(search=search, date_from=date_from, date_to=date_to)


@router.get("/explorer/{category}")
async def get_explorer_rows(
    category: str,
    search: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
) -> list[dict]:
    """Row-level data backing one Dashboard panel/stat card (issue-local-033,
    Data Explorer). 404s on an unknown category rather than 500ing."""
    if category not in th_db.EXPLORER_CATEGORIES:
        raise HTTPException(status_code=404, detail=f"Unknown category: {category}")
    return await th_db.list_explorer_rows(
        category, search=search, date_from=date_from, date_to=date_to
    )


@router.post("/packages", response_model=HuntPackageOut, status_code=201)
async def create_package(body: HuntPackageCreate, request: Request) -> dict:
    """Create a new hunt package in draft status."""
    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")
    return await th_db.create_hunt_package(
        name=body.name, description=body.description, created_by=created_by
    )


@router.get("/packages/{pkg_id}", response_model=HuntPackageOut)
async def get_package(pkg_id: str) -> dict:
    """Get a single hunt package by ID."""
    return _pkg_or_404(await th_db.get_hunt_package(pkg_id))


@router.put("/packages/{pkg_id}", response_model=HuntPackageOut)
async def update_package(pkg_id: str, body: HuntPackageUpdate) -> dict:
    """Update a hunt package's name, description, or status."""
    updated = await th_db.update_hunt_package(
        pkg_id,
        name=body.name,
        description=body.description,
        status=body.status.value if body.status else None,
    )
    return _pkg_or_404(updated)


@router.delete("/packages/{pkg_id}", status_code=204)
async def archive_package(pkg_id: str) -> None:
    """Archive a hunt package (soft delete)."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    await th_db.update_hunt_package(pkg_id, status="archived")


@router.post("/packages/{pkg_id}/clone", response_model=HuntPackageOut, status_code=201)
async def clone_package(pkg_id: str, body: dict, request: Request) -> dict:
    """Clone a hunt package — copies evidence only, resets to draft.

    issue-local-012: creates a new package with the provided name, copying all
    evidence items (including file blobs) with parse_status reset to 'pending'.
    Runs, reports, IOCs, and generation state are NOT copied.

    Request body: {"name": "New package name"}
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    new_name = (body.get("name") or "").strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="'name' is required")
    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")
    return await th_db.clone_hunt_package(pkg_id, new_name, created_by=created_by)


# ── Evidence: file upload ─────────────────────────────────────────────────────


@router.post(
    "/packages/{pkg_id}/evidence/file",
    response_model=EvidenceItemOut,
    status_code=201,
)
async def add_evidence_file(
    pkg_id: str,
    file: UploadFile = File(...),
    parser_mode: str = "auto",
) -> dict:
    """Upload a file (PDF, DOCX, TXT, CSV, JSON, XML, …) as evidence.

    issue-local-011: file parsing is now **deferred to the analysis pipeline**
    (intake_classifier), exactly like URL fetching.  The raw blob is stored
    immediately; the file is parsed (text extraction, parser selection, IOC
    extraction) when the user starts an analysis run.

    This makes uploads instant regardless of file size or parser complexity
    (e.g. Docling's ML-based PDF layout analysis).  The parse_status is set
    to 'pending' to signal the deferred state to the pipeline and the UI.

    The chosen parser_mode is persisted in fetch_metadata so intake_classifier
    can use the same mode the user selected.
    """
    import hashlib as _hashlib

    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    raw = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit",
        )

    filename = file.filename or "upload"
    mime_type = file.content_type or ""

    # Cheap SHA-256 of raw bytes for content deduplication — no parse needed
    content_hash = _hashlib.sha256(raw).hexdigest()

    # Persist the blob with parse_status='pending'; intake_classifier will parse
    # it when the analysis pipeline runs.
    item = await th_db.add_evidence_item(
        pkg_id,
        item_type="file",
        label=filename,
        source_ref=filename,
        content_hash=content_hash,
        mime_type=mime_type,
        extracted_text="",
        parser_used="",
        parser_version="",
        parse_status="pending",
        parse_warnings=["File will be parsed during the analysis pipeline run."],
        blob_data=raw,
        # Carry parser_mode so intake_classifier uses the user's chosen parser
        fetch_metadata={"parser_mode": parser_mode, "original_size_bytes": len(raw)},
    )

    return item


# ── Evidence: URL fetch ───────────────────────────────────────────────────────


@router.post(
    "/packages/{pkg_id}/evidence/url",
    response_model=EvidenceItemOut,
    status_code=201,
)
async def add_evidence_url(pkg_id: str, body: AddUrlBody) -> dict:
    """Register a URL as a pending evidence item.

    issue-008-2B: URL fetching is now deferred to the agent pipeline
    (intake_classifier), which fetches the URL during analysis with
    effort-aware settings (e.g. Playwright-first on high effort).

    SSRF pre-validation is still performed here to reject obviously
    invalid/blocked URLs before they are stored, so the user gets immediate
    feedback rather than a silent pipeline failure.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    # Pre-flight SSRF check only — no HTTP fetch yet
    from backend.threat_hunting.ssrf import validate_url

    try:
        validated_url = await asyncio.to_thread(validate_url, body.url)
    except SSRFError as exc:
        raise HTTPException(status_code=400, detail=f"SSRF policy violation: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {exc}") from exc

    from backend.threat_hunting.evidence_source import domain_from_url

    item = await th_db.add_evidence_item(
        pkg_id,
        item_type="url",
        label=body.label or validated_url,
        source_ref=body.url,
        fetch_url=body.url,
        extracted_text="",
        parser_used="",
        parser_version="",
        # parse_status="pending" signals that fetch+extract hasn't happened yet
        parse_status="pending",
        parse_warnings=["URL content will be fetched during the analysis pipeline run."],
        # issue-local-034: the domain is known from the URL itself — no need
        # to wait for (or depend on the success of) the deferred fetch.
        source_entity=domain_from_url(body.url),
    )

    return item


# ── Evidence: manual text ────────────────────────────────────────────────────


@router.post(
    "/packages/{pkg_id}/evidence/text",
    response_model=EvidenceItemOut,
    status_code=201,
)
async def add_evidence_text(pkg_id: str, body: AddManualTextBody) -> dict:
    """Add a manual text note or pasted threat intel as evidence."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    import hashlib

    content_hash = hashlib.sha256(body.text.encode()).hexdigest()

    from backend.threat_hunting.evidence_source import resolve_source_entity_from_text

    item = await th_db.add_evidence_item(
        pkg_id,
        item_type="manual_text",
        label=body.label or "Manual note",
        source_ref=body.source_ref,
        content_hash=content_hash,
        extracted_text=body.text,
        parser_used="text",
        parser_version="stdlib",
        parse_status="ok",
        # issue-local-034: best-effort, soft-fail — never blocks adding evidence.
        source_entity=await resolve_source_entity_from_text(body.text),
    )

    # issue-008-2B: IOC extraction moved to intake_classifier.

    return item


# ── Evidence: watcher import ─────────────────────────────────────────────────


@router.post(
    "/packages/{pkg_id}/evidence/watcher",
    response_model=EvidenceItemOut,
    status_code=201,
)
async def add_evidence_watcher(pkg_id: str, body: AddWatcherBody) -> dict:
    """Import events from a Threat Intel watcher feed as evidence.

    Pulls the latest events from the watcher's DB using the internal
    watchers API (not the public /feed/ URL).
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    # Import from the watchers DB directly (authenticated internal path)
    try:
        from backend.db.watchers import list_events

        raw_events = await list_events(body.watcher_id, limit=body.max_events)
        # Serialize event_json payloads for the snapshot
        events = []
        for e in raw_events:
            payload = e.get("event_json") or e
            if isinstance(payload, str):
                import json as _json

                try:
                    payload = _json.loads(payload)
                except Exception:
                    pass
            events.append(payload if isinstance(payload, dict) else e)
    except Exception as exc:
        logger.warning("Watcher import failed for %r: %s", body.watcher_id, exc)
        raise HTTPException(
            status_code=502,
            detail=f"Could not import watcher events: {exc}",
        ) from exc

    snapshot = {
        "watcher_id": body.watcher_id,
        "event_count": len(events),
        "events": events,
    }
    text_blob = "\n\n".join(json.dumps(e, ensure_ascii=False) for e in events)

    import hashlib

    content_hash = hashlib.sha256(text_blob.encode()).hexdigest()

    item = await th_db.add_evidence_item(
        pkg_id,
        item_type="watcher_feed",
        label=body.label or f"Watcher {body.watcher_id}",
        source_ref=body.watcher_id,
        content_hash=content_hash,
        extracted_text=text_blob,
        parser_used="json",
        parser_version="stdlib",
        parse_status="ok",
        watcher_snapshot=snapshot,
        # issue-local-034: the watcher's own name is a more reliable "source"
        # than an LLM guess over a blob of JSON events — deterministic, free.
        source_entity=body.label or f"Watcher {body.watcher_id}",
    )

    # issue-008-2B: IOC extraction moved to intake_classifier.

    return item


# ── Evidence: list + delete ───────────────────────────────────────────────────


@router.get("/packages/{pkg_id}/evidence", response_model=list[EvidenceItemOut])
async def list_evidence(pkg_id: str) -> list[dict]:
    """List all evidence items for a hunt package."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    return await th_db.list_evidence_items(pkg_id)


@router.delete("/packages/{pkg_id}/evidence/{item_id}", status_code=204)
async def delete_evidence(pkg_id: str, item_id: str) -> None:
    """Remove an evidence item (and its blob) from a hunt package."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    item = _item_or_404(await th_db.get_evidence_item(item_id))
    if item["hunt_package_id"] != pkg_id:
        raise HTTPException(status_code=404, detail="Evidence item not found")
    await th_db.delete_evidence_item(item_id)


# ── Evidence: content viewer (issue-local-023) ──────────────────────────────────


def _safe_disposition_filename(label: str, fallback: str) -> str:
    """Sanitize a user-supplied filename for a Content-Disposition header.

    issue-local-023: ``item.label``/``source_ref`` is the raw, unsanitized
    original upload filename (``file.filename`` from the browser — fully
    attacker-controlled). The existing report-PDF download routes only
    ``.replace(" ", "_")`` before interpolating a name into this header,
    which does NOT strip quotes or CR/LF — not safe to copy for a value an
    end user directly controls. Strips quotes and control characters
    (including CR/LF, which could otherwise inject additional headers);
    falls back to *fallback* if nothing usable remains.
    """
    cleaned = "".join(ch for ch in label if ch not in '"\\' and ch.isprintable())
    cleaned = cleaned.strip()
    return cleaned or fallback


async def _evidence_item_or_404(pkg_id: str, item_id: str) -> dict:
    item = _item_or_404(await th_db.get_evidence_item(item_id))
    if item["hunt_package_id"] != pkg_id:
        raise HTTPException(status_code=404, detail="Evidence item not found")
    return item


@router.get("/packages/{pkg_id}/evidence/{item_id}/pdf")
async def get_evidence_pdf(pkg_id: str, item_id: str) -> Response:
    """Serve an evidence file's raw bytes for in-browser PDF preview.

    Security (issue-local-023): the stored ``mime_type`` is client-supplied
    at upload time and never validated (see ``add_evidence_file``) — it must
    NEVER be trusted as the response's Content-Type, or a mislabeled file
    could be rendered inline as something other than a PDF (a stored-XSS
    vector on our own origin). Instead: (1) ``media_type`` is ALWAYS the
    hardcoded string ``application/pdf``, never ``item["mime_type"]``, and
    (2) the blob's own magic bytes are verified server-side (``%PDF-``)
    before it is served at all — 415 otherwise, even if the stored
    mime_type claims to be a PDF. ``X-Content-Type-Options: nosniff``
    additionally blocks the browser from content-sniffing past this.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    item = await _evidence_item_or_404(pkg_id, item_id)
    blob = await th_db.get_evidence_blob(item_id)
    if blob is None:
        raise HTTPException(status_code=404, detail="No file content stored for this item")
    if not blob.startswith(b"%PDF-"):
        raise HTTPException(status_code=415, detail="Stored content is not a PDF file")

    safe_name = _safe_disposition_filename(item.get("label", ""), "evidence")
    if not safe_name.lower().endswith(".pdf"):
        safe_name = f"{safe_name}.pdf"

    return Response(
        content=blob,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/packages/{pkg_id}/evidence/{item_id}/download")
async def download_evidence_file(pkg_id: str, item_id: str) -> Response:
    """Download an evidence item's original file, any type (issue-local-023).

    Always served as ``application/octet-stream`` with
    ``Content-Disposition: attachment`` regardless of the stored (client-
    supplied, unvalidated) ``mime_type`` — this forces the browser to save
    the file rather than attempt to render/sniff it, so a mislabeled or
    hostile file type can't execute in the browser. See
    ``_safe_disposition_filename`` for why the filename is sanitized rather
    than reusing the existing report-download routes' weaker pattern.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    item = await _evidence_item_or_404(pkg_id, item_id)
    blob = await th_db.get_evidence_blob(item_id)
    if blob is None:
        raise HTTPException(status_code=404, detail="No file content stored for this item")

    safe_name = _safe_disposition_filename(item.get("label", ""), "evidence.bin")

    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


# ── IOCs ──────────────────────────────────────────────────────────────────────


@router.get("/packages/{pkg_id}/iocs", response_model=list[ExtractedIOCOut])
async def list_iocs(pkg_id: str, run_id: str | None = Query(default=None)) -> list[dict]:
    """List IOCs extracted for a hunt package, optionally scoped to one run.

    issue-local-015: pass run_id to see exactly that run's independent IOC
    set. Omitting it returns every row across all runs (back-compat).
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    return await th_db.list_extracted_iocs(pkg_id, run_id)


# ── Generation (Phase 3) ──────────────────────────────────────────────────────


class GenerateBody(BaseModel):
    provider_name: str | None = None
    model_name: str | None = None
    research_effort: str | None = None  # 'high'|'medium'|'low'; None = use global default
    # issue-local-015: per-run IOC handling — {"ioc_mode": "tagging_only"|
    # "active_cleaning", "ioc_cleaning_options": {"remove_noisy": bool, ...}}.
    # None/omitted = tagging_only (today's behavior), same as every field
    # here already defaults to "use current behavior" when absent.
    run_config: dict | None = None


class ApproveBody(BaseModel):
    notes: str = ""


class RejectBody(BaseModel):
    notes: str = ""


class HypothesisDiscardBody(BaseModel):
    discarded: bool


class HuntingLeadDiscardBody(BaseModel):
    discarded: bool


class IocVerdictItem(BaseModel):
    ioc: str
    ioc_type: str
    action: str  # 'keep' | 'remove'


class IocVerdictUpdateBody(BaseModel):
    updates: list[IocVerdictItem]


@router.post("/packages/{pkg_id}/generate", status_code=202)
async def start_generation(pkg_id: str, body: GenerateBody, request: Request) -> dict:
    """Start the LLM agent pipeline for a hunt package.

    Returns immediately with status=running. Poll /generate/status for progress.
    Requires at least one evidence item.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    # Require evidence
    evidence = await th_db.list_evidence_items(pkg_id)
    if not evidence:
        raise HTTPException(
            status_code=400,
            detail="Hunt package has no evidence items. Add at least one before generating.",
        )

    from backend.config.loader import load_th_research_effort
    from backend.threat_hunting.agents.runner import start_generation as _start

    # Resolve research effort: per-request override → global default
    effort = body.research_effort or load_th_research_effort()

    run_config = body.run_config or {}
    ioc_mode = run_config.get("ioc_mode", "tagging_only")
    if ioc_mode not in ("tagging_only", "active_cleaning"):
        raise HTTPException(
            status_code=400,
            detail="run_config.ioc_mode must be 'tagging_only' or 'active_cleaning'",
        )
    # issue-local-041: per-run override of the default query languages
    # query_drafting_agent drafts — same keys/shape as th_query_languages.
    query_languages = run_config.get("query_languages")
    if query_languages is not None:
        if not isinstance(query_languages, dict) or not all(
            k in ("spl", "kql", "cql", "elasticsearch") and isinstance(v, bool)
            for k, v in query_languages.items()
        ):
            raise HTTPException(
                status_code=400,
                detail="run_config.query_languages must be an object with spl/kql/cql/elasticsearch booleans",
            )

    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")

    record = await _start(
        pkg_id,
        provider_name=body.provider_name,
        model_name=body.model_name,
        research_effort=effort,
        run_config=run_config,
        created_by=created_by,
    )
    return record


@router.get("/packages/{pkg_id}/generate/status")
async def get_generation_status(pkg_id: str) -> dict:
    """Poll the generation status and retrieve the draft hunting package."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    from backend.threat_hunting.agents.runner import get_generation_status as _status

    record = await _status(pkg_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail="No generation record found. Start generation first.",
        )
    return record


@router.post("/packages/{pkg_id}/approve")
async def approve_generation(pkg_id: str, body: ApproveBody) -> dict:
    """Approve the generated hunting package (latest run).

    Back-compat route — resolves the latest run for the package.
    Prefer POST /packages/{pkg_id}/runs/{run_id}/approve for explicit run control.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    # Resolve latest run_id
    runs = await th_db.list_generation_runs(pkg_id)
    if not runs:
        raise HTTPException(status_code=404, detail="No generation run found for this package.")
    run_id = runs[0]["id"]

    from backend.threat_hunting.agents.runner import approve_generation as _approve

    try:
        return await _approve(run_id, notes=body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/packages/{pkg_id}/reject")
async def reject_generation(pkg_id: str, body: RejectBody) -> dict:
    """Reject the generated hunting package (latest run).

    Back-compat route — resolves the latest run for the package.
    Prefer POST /packages/{pkg_id}/runs/{run_id}/reject for explicit run control.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    runs = await th_db.list_generation_runs(pkg_id)
    if not runs:
        raise HTTPException(status_code=404, detail="No generation run found for this package.")
    run_id = runs[0]["id"]

    from backend.threat_hunting.agents.runner import reject_generation as _reject

    try:
        return await _reject(run_id, notes=body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ── Run-scoped generation endpoints (issue-local-005) ────────────────────────


@router.get("/packages/{pkg_id}/runs")
async def list_runs(pkg_id: str) -> list[dict]:
    """List all generation runs for a hunt package (newest first)."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    return await th_db.list_generation_runs(pkg_id)


@router.get("/packages/{pkg_id}/runs/{run_id}/status")
async def get_run_status(pkg_id: str, run_id: str) -> dict:
    """Poll the generation status for a specific run."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    from backend.threat_hunting.agents.runner import get_generation_status as _status

    record = await _status(pkg_id, run_id=run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return record


@router.post("/packages/{pkg_id}/runs/{run_id}/approve")
async def approve_run(pkg_id: str, run_id: str, body: ApproveBody) -> dict:
    """Approve a specific generation run."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    from backend.threat_hunting.agents.runner import approve_generation as _approve

    try:
        return await _approve(run_id, notes=body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/packages/{pkg_id}/runs/{run_id}/reject")
async def reject_run(pkg_id: str, run_id: str, body: RejectBody) -> dict:
    """Reject a specific generation run."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    from backend.threat_hunting.agents.runner import reject_generation as _reject

    try:
        return await _reject(run_id, notes=body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/packages/{pkg_id}/runs/{run_id}/cancel")
async def cancel_run(pkg_id: str, run_id: str) -> dict:
    """Cancel a currently-running generation run (issue-local-019)."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    from backend.threat_hunting.agents.runner import cancel_generation as _cancel

    try:
        return await _cancel(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class RunArchivedBody(BaseModel):
    archived: bool


@router.put("/packages/{pkg_id}/runs/{run_id}/archived")
async def set_run_archived_route(pkg_id: str, run_id: str, body: RunArchivedBody) -> dict:
    """Archive/unarchive a single run (issue-local-034).

    Independent of the run's own generation_status and of the parent
    package's status — hiding a bad/duplicate run doesn't require touching
    anything else. Same researcher+admin access as every other Threat
    Hunting mutation (not destructive, unlike hard delete below).
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    ok = await th_db.set_run_archived(run_id, body.archived)
    if not ok:
        raise HTTPException(status_code=404, detail="Run not found.")
    return {"run_id": run_id, "archived": body.archived}


@router.delete("/packages/{pkg_id}/runs/{run_id}", status_code=204)
async def hard_delete_run_route(
    pkg_id: str,
    run_id: str,
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> None:
    """Permanently delete a single run and everything that references it
    (issue-local-034). Irreversible — admin-only, unlike every other Threat
    Hunting mutation (researcher+admin); this is the one action in this
    router that actually destroys data rather than hiding or reversibly
    changing it.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    ok = await th_db.hard_delete_run(run_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Run not found.")


@router.delete("/packages/{pkg_id}/hard", status_code=204)
async def hard_delete_package_route(
    pkg_id: str,
    _admin: dict | None = Depends(require_admin_when_enabled),
) -> None:
    """Permanently delete a hunt package, every one of its runs, and every
    row that references either (issue-local-034). Irreversible — admin-only.
    The existing DELETE /packages/{pkg_id} (archive_package, above) is
    unchanged and stays the soft-hide every other role already relies on.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    ok = await th_db.hard_delete_package(pkg_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Hunt package not found.")


@router.patch("/packages/{pkg_id}/runs/{run_id}/hypotheses/{hypothesis_id}")
async def discard_hypothesis(
    pkg_id: str, run_id: str, hypothesis_id: str, body: HypothesisDiscardBody
) -> dict:
    """Set whether a hypothesis is excluded from further consideration/execution.

    issue-local-015: analyst-set only — never overwritten by a re-run of the
    same run_id (hypotheses aren't regenerated in place; a fresh 'discarded:
    False' only comes from a brand-new run per hypothesis_generator).
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    updated = await th_db.set_hypothesis_discarded(run_id, hypothesis_id, body.discarded)
    if updated is None:
        raise HTTPException(status_code=404, detail="Run or hypothesis not found.")
    return updated


@router.patch("/packages/{pkg_id}/runs/{run_id}/hunting-leads/{lead_id}")
async def discard_hunting_lead(
    pkg_id: str, run_id: str, lead_id: str, body: HuntingLeadDiscardBody
) -> dict:
    """Set whether a hunting lead is excluded from further consideration/execution.

    issue-local-015: same analyst-set-only semantics as discard_hypothesis.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    updated = await th_db.set_hunting_lead_discarded(run_id, lead_id, body.discarded)
    if updated is None:
        raise HTTPException(status_code=404, detail="Run or hunting lead not found.")
    return updated


@router.patch("/packages/{pkg_id}/runs/{run_id}/iocs")
async def update_ioc_verdicts(pkg_id: str, run_id: str, body: IocVerdictUpdateBody) -> dict:
    """Batch-apply manual keep/remove verdict overrides for this run's IOCs.

    issue-local-016: analyst-driven override of the automated (noise-scoring
    + active-cleaning) keep/remove decision from issue-local-015. Updates
    BOTH IOC data stores this app maintains — ``extracted_iocs`` (the real
    table backing HuntDetail's IOCs tab) and the ``deep_retrohunt`` JSON
    blob's ``sanitized_iocs`` (which has no independent id, matched by
    ``(ioc, ioc_type)`` — backing RetrohuntPanel's Sanitized IOCs table) —
    so every IOC view stays consistent without re-running the pipeline. The
    deep_retrohunt half also recomputes its derived ``ioc_csv``/count
    fields; see ``db.update_deep_retrohunt_ioc_actions``. Scoped to this run
    only — other runs of the same package are untouched.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    invalid = [u.action for u in body.updates if u.action not in ("keep", "remove")]
    if invalid:
        raise HTTPException(status_code=400, detail="action must be 'keep' or 'remove'")

    updates = [(u.ioc, u.ioc_type, u.action) for u in body.updates]
    await th_db.update_ioc_actions(run_id, updates)
    deep_retrohunt = await th_db.update_deep_retrohunt_ioc_actions(run_id, updates)

    return {
        "status": "ok",
        "updated_count": len(updates),
        "deep_retrohunt": deep_retrohunt,
    }


# ── SIEM Connector endpoints (Phase 5) ────────────────────────────────────────


class ConnectorCreateBody(BaseModel):
    name: str
    kind: str = "splunk"
    base_url: str
    auth_method: str = "token"
    api_token: str | None = None
    username: str | None = None
    password: str | None = None
    verify_tls: bool = True
    default_index: str = "main"
    retrohunt_macro: str = "threathunt_ioc_search"


class ConnectorUpdateBody(BaseModel):
    name: str | None = None
    base_url: str | None = None
    auth_method: str | None = None
    api_token: str | None = None
    username: str | None = None
    password: str | None = None
    verify_tls: bool | None = None
    default_index: str | None = None
    retrohunt_macro: str | None = None


@router.get("/connectors")
async def list_connectors() -> list[dict]:
    """List all SIEM connectors. Credentials are masked."""
    return await th_db.list_siem_connectors()


@router.post("/connectors", status_code=201)
async def create_connector(body: ConnectorCreateBody) -> dict:
    """Create a new SIEM connector profile."""
    try:
        return await th_db.create_siem_connector(
            body.name,
            kind=body.kind,
            base_url=body.base_url,
            auth_method=body.auth_method,
            api_token=body.api_token,
            username=body.username,
            password=body.password,
            verify_tls=body.verify_tls,
            default_index=body.default_index,
            retrohunt_macro=body.retrohunt_macro,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/connectors/{conn_id}")
async def get_connector(conn_id: str) -> dict:
    """Get a SIEM connector by ID (credentials masked)."""
    conn = await th_db.get_siem_connector(conn_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
    return conn


@router.put("/connectors/{conn_id}")
async def update_connector(conn_id: str, body: ConnectorUpdateBody) -> dict:
    """Update a SIEM connector. Only supplied fields are changed."""
    result = await th_db.update_siem_connector(
        conn_id,
        name=body.name,
        base_url=body.base_url,
        auth_method=body.auth_method,
        api_token=body.api_token,
        username=body.username,
        password=body.password,
        verify_tls=body.verify_tls,
        default_index=body.default_index,
        retrohunt_macro=body.retrohunt_macro,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Connector not found")
    return result


@router.delete("/connectors/{conn_id}", status_code=204)
async def delete_connector(conn_id: str) -> None:
    """Delete a SIEM connector."""
    deleted = await th_db.delete_siem_connector(conn_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Connector not found")


@router.post("/connectors/{conn_id}/test")
async def test_connector(conn_id: str) -> dict:
    """Test a SIEM connector connection.

    Returns {ok: bool, message: str, server_info: dict|null}.
    Does NOT require the connector to be verified first.
    """
    conn_raw = await th_db.get_connector_for_use(conn_id)
    if not conn_raw:
        raise HTTPException(status_code=404, detail="Connector not found")

    from backend.threat_hunting.siem.splunk import SplunkConnector

    kind = conn_raw.get("kind", "splunk")
    if kind != "splunk":
        raise HTTPException(
            status_code=400, detail=f"Connector kind {kind!r} not supported in Phase 5"
        )

    cfg = conn_raw.get("_cfg", {})
    connector = SplunkConnector(
        base_url=conn_raw["base_url"],
        auth_method=conn_raw.get("auth_method", "token"),
        api_token=cfg.get("api_token"),
        username=cfg.get("username"),
        password=cfg.get("password"),
        verify_tls=bool(cfg.get("verify_tls", True)),
    )
    result = await connector.test_connection()

    # Mark as verified if test passed
    if result.ok:
        await th_db.update_siem_connector(conn_id, verified=True)

    return {
        "ok": result.ok,
        "message": result.message,
        "server_info": result.server_info,
    }


# ── Hunt Playbooks (issue-local-040, ownership issue-local-041) ─────────────
# Global, DB-backed automation configs. Any researcher/admin can create, list,
# read, run, and clone playbooks (relies on the app-wide auth middleware's
# path-prefix role gate — /api/threat-hunting/ writes and reads both already
# require researcher-or-admin, excluding viewer). Editing/deleting an
# EXISTING playbook is additionally scoped to its owner (created_by) for
# researchers — admins bypass this and may edit/delete any playbook, same as
# every other role check in this app (main.py's admin bypass is total).


def _require_playbook_owner_or_admin(playbook: dict, request: Request) -> None:
    """Raise 403 unless *request*'s caller may edit/delete *playbook*.

    issue-local-041: "Only Threat researcher role is able to read/edit/delete
    (own) playbooks" — admins are exempt from the ownership check (they can
    edit/delete any playbook, exactly as before this change). A playbook
    with no recorded owner (created_by NULL — created before this field
    existed, or while auth was disabled) has no owner to enforce, so it
    remains editable/deletable by any researcher, same as pre-issue-local-041
    behavior. Auth-disabled requests (no request.state.user at all) are
    likewise unrestricted — there is no identity to compare against.
    """
    if not (hasattr(request.state, "user") and request.state.user):
        return
    user = request.state.user
    if user.get("role") == "admin":
        return
    owner = playbook.get("created_by")
    if owner is None or owner == user.get("username"):
        return
    raise HTTPException(status_code=403, detail="Only the playbook's owner or an admin may do this.")


class PlaybookModelEntry(BaseModel):
    provider_name: str | None = None
    model_name: str
    # issue-local-042: per-model research-effort override — was already read
    # by playbook_runner.py and sent by the frontend, but this Pydantic
    # model never declared it, so FastAPI silently dropped it before it
    # reached the database on every real request (Pydantic's default is to
    # ignore undeclared input fields, not reject or preserve them).
    effort: str | None = None
    # issue-local-042: per-model IOC cleaning override — only read when the
    # owning playbook's ioc_cleaning_scope is 'per_model'.
    ioc_mode: str | None = None
    ioc_cleaning_options: dict[str, bool] | None = None


class PlaybookCreateBody(BaseModel):
    name: str
    models: list[PlaybookModelEntry]
    auto_approve_analysis: bool = False
    auto_run_comparison: bool = False
    auto_compare_preliminary: bool = False
    auto_compare_full: bool = False
    auto_create_run_from_recommendations: bool = False
    auto_generate_full_report: bool = False
    # issue-local-042: IOC cleaning config for this playbook's runs —
    # disabled (the default) means run_config stays {} exactly as before
    # this existed.
    ioc_cleaning_enabled: bool = False
    ioc_cleaning_scope: str | None = None
    ioc_mode: str | None = None
    ioc_cleaning_options: dict[str, bool] | None = None


class PlaybookUpdateBody(BaseModel):
    name: str | None = None
    models: list[PlaybookModelEntry] | None = None
    auto_approve_analysis: bool | None = None
    auto_run_comparison: bool | None = None
    auto_compare_preliminary: bool | None = None
    auto_compare_full: bool | None = None
    auto_create_run_from_recommendations: bool | None = None
    auto_generate_full_report: bool | None = None
    ioc_cleaning_enabled: bool | None = None
    ioc_cleaning_scope: str | None = None
    ioc_mode: str | None = None
    ioc_cleaning_options: dict[str, bool] | None = None


class PlaybookCloneBody(BaseModel):
    name: str


@router.get("/playbooks")
async def list_playbooks_route() -> list[dict]:
    """List all Hunt Playbooks."""
    return await th_db.list_playbooks()


@router.post("/playbooks", status_code=201)
async def create_playbook_route(body: PlaybookCreateBody, request: Request) -> dict:
    """Create a new Hunt Playbook."""
    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")
    try:
        return await th_db.create_playbook(
            body.name,
            models=[m.model_dump() for m in body.models],
            auto_approve_analysis=body.auto_approve_analysis,
            auto_run_comparison=body.auto_run_comparison,
            auto_compare_preliminary=body.auto_compare_preliminary,
            auto_compare_full=body.auto_compare_full,
            auto_create_run_from_recommendations=body.auto_create_run_from_recommendations,
            auto_generate_full_report=body.auto_generate_full_report,
            ioc_cleaning_enabled=body.ioc_cleaning_enabled,
            ioc_cleaning_scope=body.ioc_cleaning_scope,
            ioc_mode=body.ioc_mode,
            ioc_cleaning_options=body.ioc_cleaning_options,
            created_by=created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/playbooks/{playbook_id}")
async def get_playbook_route(playbook_id: str) -> dict:
    """Get a Hunt Playbook by ID."""
    playbook = await th_db.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook


@router.put("/playbooks/{playbook_id}")
async def update_playbook_route(playbook_id: str, body: PlaybookUpdateBody, request: Request) -> dict:
    """Update a Hunt Playbook. Only supplied fields are changed."""
    existing = await th_db.get_playbook(playbook_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Playbook not found")
    _require_playbook_owner_or_admin(existing, request)
    try:
        result = await th_db.update_playbook(
            playbook_id,
            name=body.name,
            models=[m.model_dump() for m in body.models] if body.models is not None else None,
            auto_approve_analysis=body.auto_approve_analysis,
            auto_run_comparison=body.auto_run_comparison,
            auto_compare_preliminary=body.auto_compare_preliminary,
            auto_compare_full=body.auto_compare_full,
            auto_create_run_from_recommendations=body.auto_create_run_from_recommendations,
            auto_generate_full_report=body.auto_generate_full_report,
            ioc_cleaning_enabled=body.ioc_cleaning_enabled,
            ioc_cleaning_scope=body.ioc_cleaning_scope,
            ioc_mode=body.ioc_mode,
            ioc_cleaning_options=body.ioc_cleaning_options,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return result


@router.delete("/playbooks/{playbook_id}", status_code=204)
async def delete_playbook_route(playbook_id: str, request: Request) -> None:
    """Delete a Hunt Playbook. Runs already tagged with it keep their
    snapshotted playbook_id/playbook_name — they are untouched."""
    existing = await th_db.get_playbook(playbook_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Playbook not found")
    _require_playbook_owner_or_admin(existing, request)
    deleted = await th_db.delete_playbook(playbook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Playbook not found")


@router.post("/playbooks/{playbook_id}/clone", status_code=201)
async def clone_playbook_route(playbook_id: str, body: PlaybookCloneBody, request: Request) -> dict:
    """Clone a Hunt Playbook's config under a new name."""
    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name must not be empty")
    result = await th_db.clone_playbook(playbook_id, name, created_by)
    if not result:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return result


@router.post("/packages/{pkg_id}/playbooks/{playbook_id}/run", status_code=202)
async def run_playbook_route(pkg_id: str, playbook_id: str, request: Request) -> dict:
    """Fire a Hunt Playbook against this package's evidence and return the
    tracking job immediately — poll GET .../playbooks/status for progress."""
    from backend.threat_hunting.agents.playbook_runner import run_playbook

    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")
    try:
        return await run_playbook(pkg_id, playbook_id, created_by=created_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/packages/{pkg_id}/playbooks/status")
async def get_playbook_job_status(pkg_id: str) -> dict:
    """Poll the latest playbook job's status for this package."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    job = await th_db.get_latest_playbook_job(pkg_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No playbook job found.")
    return job


# ── Execution endpoints (Phase 5) ─────────────────────────────────────────────


class ExecuteBody(BaseModel):
    connector_id: str
    spl: str  # the SPL query to execute (from deep_retrohunt.spl_draft or custom)
    earliest: str = "-24h"
    latest: str = "now"
    provider_name: str | None = None
    model_name: str | None = None
    run_id: str | None = None  # link execution results to a specific generation run


@router.post("/packages/{pkg_id}/execute", status_code=202)
async def execute_hunt(pkg_id: str, body: ExecuteBody) -> dict:
    """Start SIEM execution for an approved hunt package.

    The hunt package must be in 'approved' status. Returns a TaskResult
    record immediately; execution runs in the background.
    Pass run_id to link results to a specific generation run.
    """
    pkg = _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    if pkg["status"] not in ("approved", "completed"):
        raise HTTPException(
            status_code=400,
            detail=f"Hunt package must be approved before execution (current status: {pkg['status']!r})",
        )

    from backend.threat_hunting.siem.executor import start_execution

    try:
        return await start_execution(
            pkg_id,
            body.connector_id,
            spl=body.spl,
            earliest=body.earliest,
            latest=body.latest,
            provider_name=body.provider_name,
            model_name=body.model_name,
            run_id=body.run_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/packages/{pkg_id}/results")
async def list_results(pkg_id: str) -> list[dict]:
    """List all task results for a hunt package."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    return await th_db.list_task_results(pkg_id)


@router.get("/packages/{pkg_id}/results/{result_id}")
async def get_result(pkg_id: str, result_id: str) -> dict:
    """Get a single task result."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    record = await th_db.get_task_result(result_id)
    if not record or record.get("hunt_package_id") != pkg_id:
        raise HTTPException(status_code=404, detail="Task result not found")
    from backend.threat_hunting.siem.executor import _ACTIVE_EXECUTIONS

    record["is_running"] = result_id in _ACTIVE_EXECUTIONS
    return record


# ── Report endpoints (Phase 6) ────────────────────────────────────────────────


class ReportGenerateBody(BaseModel):
    provider_name: str | None = None
    model_name: str | None = None
    report_formats: dict[str, bool] | None = None  # {"pdf": True, "markdown": True}


@router.get("/packages/{pkg_id}/report")
async def get_report(pkg_id: str) -> dict:
    """Get the latest hunt report for a package.

    Returns 404 if no report has been generated yet.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_hunt_report(pkg_id)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail="No report found. Run execution or generate a report manually.",
        )
    return report


@router.post("/packages/{pkg_id}/report", status_code=201)
async def generate_report(pkg_id: str, body: ReportGenerateBody, request: Request) -> dict:
    """Manually trigger report generation for an approved or completed package.

    Assembles all available pipeline and execution data, generates an LLM
    executive summary (soft-fail), and writes the report to the database.
    Idempotent — replaces any previous report.
    """
    pkg = _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    if pkg["status"] not in ("approved", "completed"):
        raise HTTPException(
            status_code=400,
            detail=f"Package must be approved or completed to generate a report (status: {pkg['status']!r})",
        )

    from backend.threat_hunting.agents.nodes.report_writer import write_report

    # Extract caller identity for audit trail
    created_by: str | None = None
    try:
        user = getattr(request.state, "user", None)
        if user:
            created_by = getattr(user, "username", None)
    except Exception:
        pass

    # Resolve report formats: per-request → global default
    report_formats = body.report_formats
    if report_formats is None:
        try:
            from backend.config.loader import load_th_report_formats

            report_formats = load_th_report_formats()
        except Exception:
            report_formats = {"pdf": True, "markdown": True}

    try:
        return await write_report(
            pkg_id,
            provider_name=body.provider_name,
            model_name=body.model_name,
            created_by=created_by,
            report_formats=report_formats,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/packages/{pkg_id}/report/list")
async def list_reports(pkg_id: str) -> list[dict]:
    """List all historical reports for a package (newest first)."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    return await th_db.list_hunt_reports(pkg_id)


@router.get("/packages/{pkg_id}/report/markdown")
async def download_report_markdown(pkg_id: str) -> Response:
    """Download the latest hunt report as a Markdown document."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_hunt_report(pkg_id)
    if report is None:
        raise HTTPException(status_code=404, detail="No report found.")

    full_report = report.get("full_report") or {}
    if isinstance(full_report, str):
        import json as _json

        try:
            full_report = _json.loads(full_report)
        except Exception:
            full_report = {}

    # Use pre-rendered markdown if available, otherwise render on demand
    markdown_content = full_report.get("_markdown")
    if not markdown_content:
        from backend.threat_hunting.agents.nodes.report_writer import render_report_markdown

        markdown_content = render_report_markdown(full_report)

    hunt_name = (full_report.get("hunt_name") or pkg_id[:8]).replace(" ", "_")
    filename = f"hunt_report_{hunt_name}.md"
    return Response(
        content=markdown_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/packages/{pkg_id}/report/pdf")
async def download_report_pdf(pkg_id: str) -> StreamingResponse:
    """Download the latest hunt report as a PDF document (generated on demand)."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_hunt_report(pkg_id)
    if report is None:
        raise HTTPException(status_code=404, detail="No report found.")

    full_report = report.get("full_report") or {}
    if isinstance(full_report, str):
        import json as _json

        try:
            full_report = _json.loads(full_report)
        except Exception:
            full_report = {}

    try:
        from backend.threat_hunting.agents.nodes.report_writer import render_report_pdf

        pdf_bytes = render_report_pdf(full_report)
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="PDF generation requires reportlab. Install it with: pip install reportlab",
        )
    except Exception as exc:
        logger.exception("PDF render failed for %s: %s", pkg_id[:8], exc)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc

    hunt_name = (full_report.get("hunt_name") or pkg_id[:8]).replace(" ", "_")
    filename = f"hunt_report_{hunt_name}.pdf"
    from io import BytesIO

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Run-scoped results and report endpoints (issue-local-005) ─────────────────


@router.get("/packages/{pkg_id}/runs/{run_id}/results")
async def list_run_results(pkg_id: str, run_id: str) -> list[dict]:
    """List SIEM task results scoped to a specific generation run."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    return await th_db.list_task_results_by_run(run_id)


@router.get("/packages/{pkg_id}/runs/{run_id}/report")
async def get_run_report(pkg_id: str, run_id: str) -> dict:
    """Get the hunt report for a specific generation run."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_hunt_report_by_run(run_id)
    if report is None:
        raise HTTPException(status_code=404, detail="No report found for this run.")
    return report


@router.post("/packages/{pkg_id}/runs/{run_id}/report", status_code=201)
async def generate_run_report(
    pkg_id: str, run_id: str, body: ReportGenerateBody, request: Request
) -> dict:
    """Generate a report scoped to a specific generation run."""
    pkg = _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    if pkg["status"] not in ("approved", "completed"):
        raise HTTPException(
            status_code=400,
            detail=f"Package must be approved or completed to generate a report (status: {pkg['status']!r})",
        )

    from backend.threat_hunting.agents.nodes.report_writer import write_report

    created_by: str | None = None
    try:
        user = getattr(request.state, "user", None)
        if user:
            created_by = getattr(user, "username", None)
    except Exception:
        pass

    report_formats = body.report_formats
    if report_formats is None:
        try:
            from backend.config.loader import load_th_report_formats

            report_formats = load_th_report_formats()
        except Exception:
            report_formats = {"pdf": True, "markdown": True}

    try:
        return await write_report(
            pkg_id,
            run_id=run_id,
            provider_name=body.provider_name,
            model_name=body.model_name,
            created_by=created_by,
            report_formats=report_formats,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/packages/{pkg_id}/runs/{run_id}/report/markdown")
async def download_run_report_markdown(pkg_id: str, run_id: str) -> Response:
    """Download the report for a specific run as Markdown."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_hunt_report_by_run(run_id)
    if report is None:
        raise HTTPException(status_code=404, detail="No report found for this run.")

    full_report = report.get("full_report") or {}
    markdown_content = full_report.get("_markdown")
    if not markdown_content:
        from backend.threat_hunting.agents.nodes.report_writer import render_report_markdown

        markdown_content = render_report_markdown(full_report)

    hunt_name = (full_report.get("hunt_name") or pkg_id[:8]).replace(" ", "_")
    filename = f"hunt_report_{hunt_name}_run_{run_id[:8]}.md"
    return Response(
        content=markdown_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/packages/{pkg_id}/runs/{run_id}/report/pdf")
async def download_run_report_pdf(pkg_id: str, run_id: str) -> StreamingResponse:
    """Download the report for a specific run as PDF."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_hunt_report_by_run(run_id)
    if report is None:
        raise HTTPException(status_code=404, detail="No report found for this run.")

    full_report = report.get("full_report") or {}
    try:
        from backend.threat_hunting.agents.nodes.report_writer import render_report_pdf

        pdf_bytes = render_report_pdf(full_report)
    except ImportError:
        raise HTTPException(status_code=503, detail="PDF generation requires reportlab.")
    except Exception as exc:
        # issue-local-026 follow-up: this route had no logger.exception call,
        # unlike its two siblings (download_report_pdf, download_comparison_pdf)
        # — a run-scoped PDF failure was invisible in app.log, silently
        # indistinguishable from "never attempted" when investigating reports
        # of intermittent PDF failures.
        logger.exception("Run report PDF render failed for %s/%s: %s", pkg_id[:8], run_id[:8], exc)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc

    hunt_name = (full_report.get("hunt_name") or pkg_id[:8]).replace(" ", "_")
    filename = f"hunt_report_{hunt_name}_run_{run_id[:8]}.pdf"
    from io import BytesIO

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Threat Intelligence (issue-local-020) ─────────────────────────────────────


@router.get("/packages/{pkg_id}/runs/{run_id}/threat-intel")
async def get_run_threat_intel(pkg_id: str, run_id: str) -> dict:
    """Get the Threat Intelligence analysis for a specific run."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    analysis = await th_db.get_threat_intel_analysis_by_run(run_id)
    if analysis is None:
        raise HTTPException(
            status_code=404, detail="No threat intelligence analysis found for this run."
        )
    return analysis


@router.get("/packages/{pkg_id}/threat-intel")
async def get_package_threat_intel(pkg_id: str) -> dict:
    """Get the latest Threat Intelligence analysis for a package."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    analysis = await th_db.get_latest_threat_intel_analysis(pkg_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="No threat intelligence analysis found.")
    return analysis


@router.post("/packages/{pkg_id}/runs/{run_id}/threat-intel", status_code=201)
async def trigger_run_threat_intel(pkg_id: str, run_id: str, request: Request) -> dict:
    """Manually (re-)trigger Threat Intelligence analysis for a run.

    Normally this runs automatically after SIEM execution completes; this
    on-demand route covers packages approved/completed without an execution
    run, and is useful for re-analysis after new hunt packages are added
    (more cross-package IOC correlations may now be findable).
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    from backend.threat_hunting.agents.nodes.threat_intel_analyst import analyze_threat_intel

    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")

    result = await analyze_threat_intel(pkg_id, run_id=run_id, created_by=created_by)
    if result is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    return result


# ── Comparison Module (issue-local-020) ────────────────────────────────────────


class CompareRunsBody(BaseModel):
    provider_name: str | None = None
    model_name: str | None = None
    # issue-local-021: narrow the comparison to a specific subset of runs
    # (the "Assess & Compare" dialog's run picker). None = compare all runs,
    # unchanged from issue-local-020.
    run_ids: list[str] | None = None
    # issue-local-035: which of the two independent comparison slots to
    # write — "preliminary" (pre-SIEM-execution) or "full" (post-execution,
    # the only phase that existed before issue-local-035).
    phase: Literal["preliminary", "full"] = "full"
    # issue-local-040: optional name to save this assessment under. Blank
    # auto-generates "manual_<timestamp>" — see th_db.create_comparison_report.
    name: str | None = None


async def _run_comparison_job(
    job_id: str,
    pkg_id: str,
    *,
    run_ids: list[str] | None,
    provider_name: str | None,
    model_name: str | None,
    created_by: str | None,
    phase: str,
    name: str | None = None,
) -> None:
    """Background task: run the comparison and report progress via *job_id*.

    issue-local-035 follow-up: this is what makes "Assess & Compare" survive
    the triggering dialog closing or the tab navigating away — it runs
    detached from the request/response cycle that started it, unlike the
    prior synchronous `await compare_runs(...)` directly inside the route
    (which Starlette would cancel if the client disconnected mid-request).
    """
    from backend.threat_hunting.agents.logging_utils import get_run_logger
    from backend.threat_hunting.agents.nodes.comparison_analyst import compare_runs

    log = get_run_logger(__name__, pkg_id, None)
    try:
        await compare_runs(
            pkg_id,
            run_ids=run_ids,
            provider_name=provider_name,
            model_name=model_name,
            created_by=created_by,
            phase=phase,
            job_id=job_id,
            name=name,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("comparison job %s failed: %s", job_id[:8], exc)
        await th_db.update_comparison_job(job_id, status="error", error_message=str(exc))


@router.post("/packages/{pkg_id}/compare", status_code=202)
async def compare_package_runs(pkg_id: str, body: CompareRunsBody, request: Request) -> dict:
    """Start a background comparison job for this hunt package's runs and
    return immediately with the job's initial (running) status.

    issue-local-035 follow-up: previously synchronous (a single LLM call
    awaited inline), which meant closing the "Assess & Compare" dialog or
    navigating away mid-request killed the comparison. Now fire-and-forget,
    matching /generate's pattern — poll GET /compare/status for progress.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    # Cheap, synchronous validation up front — same check compare_runs()
    # itself does, duplicated here so a bad request still gets an immediate
    # 400 instead of a job that's created only to fail a moment later.
    runs_summary = await th_db.list_generation_runs(pkg_id)
    if body.run_ids is not None:
        wanted = set(body.run_ids)
        runs_summary = [r for r in runs_summary if r["id"] in wanted]
    if not runs_summary:
        raise HTTPException(status_code=400, detail="No runs to compare for this hunt package")

    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")

    job = await th_db.create_comparison_job(
        pkg_id,
        phase=body.phase,
        run_ids=body.run_ids,
        provider_name=body.provider_name,
        model_name=body.model_name,
        created_by=created_by,
    )
    asyncio.create_task(
        _run_comparison_job(
            job["id"],
            pkg_id,
            run_ids=body.run_ids,
            provider_name=body.provider_name,
            model_name=body.model_name,
            created_by=created_by,
            phase=body.phase,
            name=body.name,
        )
    )
    return job


@router.get("/packages/{pkg_id}/comparisons")
async def list_package_comparisons(
    pkg_id: str, phase: Literal["preliminary", "full"] | None = Query(None)
) -> list[dict]:
    """List every saved comparison assessment for a package, newest first
    (issue-local-040) — unlike GET .../comparison, which only ever returns
    the single most recent one. Backs the saved-assessment selector."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    return await th_db.list_comparison_reports(pkg_id, phase=phase)


@router.get("/packages/{pkg_id}/compare/status")
async def get_comparison_job_status(
    pkg_id: str, phase: Literal["preliminary", "full"] = Query("full")
) -> dict:
    """Poll the latest comparison job's status for this package/phase."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    job = await th_db.get_latest_comparison_job(pkg_id, phase=phase)
    if job is None:
        raise HTTPException(status_code=404, detail="No comparison job found.")
    return job


@router.get("/packages/{pkg_id}/comparison")
async def get_package_comparison(
    pkg_id: str, phase: Literal["preliminary", "full"] = Query("full")
) -> dict:
    """Get the latest comparison report of *phase* for a package."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_latest_comparison_report(pkg_id, phase=phase)
    if report is None:
        raise HTTPException(status_code=404, detail="No comparison report found.")
    return report


def _decode_full_report(report: dict) -> dict:
    full_report = report.get("full_report") or {}
    if isinstance(full_report, str):
        import json as _json

        try:
            full_report = _json.loads(full_report)
        except Exception:
            full_report = {}
    return full_report


@router.get("/packages/{pkg_id}/comparison/markdown")
async def download_comparison_markdown(
    pkg_id: str, phase: Literal["preliminary", "full"] = Query("full")
) -> Response:
    """Download the latest comparison report of *phase* as a Markdown document."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_latest_comparison_report(pkg_id, phase=phase)
    if report is None:
        raise HTTPException(status_code=404, detail="No comparison report found.")

    full_report = _decode_full_report(report)
    markdown_content = full_report.get("_markdown")
    if not markdown_content:
        from backend.threat_hunting.agents.nodes.report_writer import render_comparison_markdown

        markdown_content = render_comparison_markdown(full_report)

    hunt_name = (full_report.get("hunt_name") or pkg_id[:8]).replace(" ", "_")
    filename = f"hunt_comparison_{hunt_name}.md"
    return Response(
        content=markdown_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/packages/{pkg_id}/comparison/pdf")
async def download_comparison_pdf(
    pkg_id: str, phase: Literal["preliminary", "full"] = Query("full")
) -> StreamingResponse:
    """Download the latest comparison report of *phase* as a PDF document (generated on demand)."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_latest_comparison_report(pkg_id, phase=phase)
    if report is None:
        raise HTTPException(status_code=404, detail="No comparison report found.")

    full_report = _decode_full_report(report)

    try:
        from backend.threat_hunting.agents.nodes.report_writer import render_comparison_pdf

        pdf_bytes = render_comparison_pdf(full_report)
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="PDF generation requires reportlab. Install it with: pip install reportlab",
        )
    except Exception as exc:
        logger.exception("Comparison PDF render failed for %s: %s", pkg_id[:8], exc)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc

    hunt_name = (full_report.get("hunt_name") or pkg_id[:8]).replace(" ", "_")
    filename = f"hunt_comparison_{hunt_name}.pdf"
    from io import BytesIO

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Recommended-combination actions (issue-local-035) ────────────────────────
# The Comparison Assessment's "Recommended Combination" card offers three
# actions: (1) snapshot the current comparison as a standalone consolidated
# report, no new execution; (2)/(3) re-run generation on a new package seeded
# from this package's evidence plus the recommendation, either for all
# compared runs or a user-picked subset.


class ConsolidateBody(BaseModel):
    phase: Literal["preliminary", "full"] = "full"


@router.post("/packages/{pkg_id}/compare/consolidate", status_code=201)
async def consolidate_comparison(pkg_id: str, body: ConsolidateBody, request: Request) -> dict:
    """Snapshot the latest comparison report of *phase* as a standalone
    consolidated report — a pure DB copy, no agent execution."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")
    try:
        return await th_db.create_consolidated_report(
            pkg_id, phase=body.phase, created_by=created_by
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/packages/{pkg_id}/consolidated")
async def get_package_consolidated(
    pkg_id: str, phase: Literal["preliminary", "full"] = Query("full")
) -> dict:
    """Get the latest consolidated report of *phase* for a package."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_latest_consolidated_report(pkg_id, phase=phase)
    if report is None:
        raise HTTPException(status_code=404, detail="No consolidated report found.")
    return report


@router.get("/packages/{pkg_id}/consolidated/markdown")
async def download_consolidated_markdown(
    pkg_id: str, phase: Literal["preliminary", "full"] = Query("full")
) -> Response:
    """Download the latest consolidated report of *phase* as Markdown."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_latest_consolidated_report(pkg_id, phase=phase)
    if report is None:
        raise HTTPException(status_code=404, detail="No consolidated report found.")

    full_report = _decode_full_report(report)
    markdown_content = full_report.get("_markdown")
    if not markdown_content:
        from backend.threat_hunting.agents.nodes.report_writer import render_comparison_markdown

        markdown_content = render_comparison_markdown(full_report)

    hunt_name = (full_report.get("hunt_name") or pkg_id[:8]).replace(" ", "_")
    filename = f"hunt_consolidated_{hunt_name}.md"
    return Response(
        content=markdown_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/packages/{pkg_id}/consolidated/pdf")
async def download_consolidated_pdf(
    pkg_id: str, phase: Literal["preliminary", "full"] = Query("full")
) -> StreamingResponse:
    """Download the latest consolidated report of *phase* as a PDF (generated on demand)."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    report = await th_db.get_latest_consolidated_report(pkg_id, phase=phase)
    if report is None:
        raise HTTPException(status_code=404, detail="No consolidated report found.")

    full_report = _decode_full_report(report)
    try:
        from backend.threat_hunting.agents.nodes.report_writer import render_comparison_pdf

        pdf_bytes = render_comparison_pdf(full_report)
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="PDF generation requires reportlab. Install it with: pip install reportlab",
        )
    except Exception as exc:
        logger.exception("Consolidated PDF render failed for %s: %s", pkg_id[:8], exc)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc

    hunt_name = (full_report.get("hunt_name") or pkg_id[:8]).replace(" ", "_")
    filename = f"hunt_consolidated_{hunt_name}.pdf"
    from io import BytesIO

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


class RerunFromRecommendationBody(BaseModel):
    new_package_name: str | None = None
    # None = use every run the source comparison covered; otherwise narrow
    # to a user-picked subset (option 3's run picker).
    run_ids: list[str] | None = None
    phase: Literal["preliminary", "full"] = "full"
    provider_name: str | None = None
    model_name: str | None = None
    research_effort: str | None = None


def _kept_ioc_csv_for_runs(ioc_overview: list[dict], run_ids: set[str]) -> str:
    """Build the canonical IOC CSV from a comparison's ioc_overview, limited
    to occurrences within *run_ids* and kept (non-'remove') in at least one
    of them."""
    from backend.threat_hunting.agents.nodes.deep_retrohunt_planner import _build_ioc_csv

    sanitized = []
    for row in ioc_overview:
        occurrences = [o for o in (row.get("occurrences") or []) if o.get("run_id") in run_ids]
        if not occurrences:
            continue
        if any(o.get("verdict") != "remove" for o in occurrences):
            sanitized.append(
                {
                    "ioc": row.get("ioc", ""),
                    "ioc_type": row.get("ioc_type", ""),
                    "ioc_description": "",
                }
            )
    return _build_ioc_csv(sanitized)


@router.post("/packages/{pkg_id}/compare/rerun", status_code=202)
async def rerun_from_recommendation(
    pkg_id: str, body: RerunFromRecommendationBody, request: Request
) -> dict:
    """Create a new hunt package seeded from this package's evidence plus the
    comparison's recommended combination, then trigger generation on it.

    Options 2/3 of the Recommended Combination card: *run_ids*=None uses
    every compared run (option 2); a specific list narrows to a user-picked
    subset (option 3).
    """
    pkg = _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    source = await th_db.get_latest_comparison_report(pkg_id, phase=body.phase)
    if source is None:
        raise HTTPException(
            status_code=404, detail=f"No {body.phase} comparison report to re-run from."
        )
    full_report = _decode_full_report(source)
    compared_run_ids = full_report.get("compared_run_ids") or []
    wanted_run_ids = set(body.run_ids) if body.run_ids is not None else set(compared_run_ids)
    if not wanted_run_ids:
        raise HTTPException(status_code=400, detail="No runs selected to re-run from.")

    ioc_csv = _kept_ioc_csv_for_runs(full_report.get("ioc_overview") or [], wanted_run_ids)
    recommendation_text = full_report.get("recommended_combination") or ""

    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")

    new_name = body.new_package_name or f"{pkg.get('name', 'Hunt')} (recommended combination)"
    new_pkg = await th_db.create_rerun_package(
        pkg_id,
        new_name,
        ioc_csv=ioc_csv,
        recommendation_text=recommendation_text,
        created_by=created_by,
    )

    from backend.config.loader import load_th_research_effort
    from backend.threat_hunting.agents.runner import start_generation as _start

    effort = body.research_effort or load_th_research_effort()
    record = await _start(
        new_pkg["id"],
        provider_name=body.provider_name,
        model_name=body.model_name,
        research_effort=effort,
        run_config={},
        created_by=created_by,
    )
    return {"package": new_pkg, "generation": record}


class RecommendationRunBody(BaseModel):
    run_ids: list[str] | None = None
    phase: Literal["preliminary", "full"] = "preliminary"
    provider_name: str | None = None
    model_name: str | None = None
    research_effort: str | None = None


@router.post("/packages/{pkg_id}/compare/recommendation-run", status_code=202)
async def create_recommendation_run(
    pkg_id: str, body: RecommendationRunBody, request: Request
) -> dict:
    """"Create a new run from recommendations" (issue-local-040) — unlike
    /compare/rerun above, this does NOT clone into a new package: it
    synthesizes one consolidated hunt plan from the comparison's compared
    runs' actual outputs (not just its summary text) and starts a new run
    IN THIS SAME PACKAGE, tagged run_origin='consolidated'. Backs the Hunt
    Packages page's "Consolidated Runs" sub-tab.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")

    from backend.threat_hunting.agents.nodes.recommendation_synthesizer import (
        synthesize_recommendation_run,
    )

    try:
        return await synthesize_recommendation_run(
            pkg_id,
            phase=body.phase,
            run_ids=body.run_ids,
            provider_name=body.provider_name,
            model_name=body.model_name,
            research_effort=body.research_effort,
            created_by=created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ── Run Comments (issue-local-018) ────────────────────────────────────────────


class RunCommentCreateBody(BaseModel):
    body: str


@router.get("/packages/{pkg_id}/runs/{run_id}/comments")
async def list_run_comments(pkg_id: str, run_id: str) -> list[dict]:
    """List analyst comments for a specific run, oldest first."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    return await th_db.list_run_comments(run_id)


@router.post("/packages/{pkg_id}/runs/{run_id}/comments", status_code=201)
async def create_run_comment(
    pkg_id: str, run_id: str, body: RunCommentCreateBody, request: Request
) -> dict:
    """Post a new analyst comment on a specific run."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    if not body.body.strip():
        raise HTTPException(status_code=400, detail="Comment body must not be empty")
    created_by = None
    if hasattr(request.state, "user") and request.state.user:
        created_by = request.state.user.get("username")
    return await th_db.create_run_comment(pkg_id, run_id, body.body.strip(), created_by=created_by)


@router.delete("/packages/{pkg_id}/runs/{run_id}/comments/{comment_id}", status_code=204)
async def delete_run_comment(pkg_id: str, run_id: str, comment_id: str) -> None:
    """Delete an analyst comment."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    deleted = await th_db.delete_run_comment(comment_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Comment not found")


# ── Threat Intel Tracking dashboard (issue-local-021) ──────────────────────────
# Cross-hunt aggregation endpoints for the new "Threat Intel Tracking" sidebar
# subsection — read-only aggregate views (Dashboard tab) plus per-hunt
# include/exclude/delete controls (Hunts tab). All aggregation logic lives in
# db.py; these routes are thin wrappers.


@router.get("/tracking/dashboard")
async def get_tracking_dashboard(
    search: str | None = Query(default=None),
) -> dict:
    """Aggregated cross-hunt Threat Intel data: IOCs, threat actors,
    campaigns, malware families, TTPs, and CVEs (ioc_type='cve', same IOC
    aggregation — CVEs are already extracted as a normal IOC type).
    *search* filters the IOCs/CVEs panels by substring match.
    """
    all_iocs = await th_db.list_correlated_iocs(search=search)
    return {
        "iocs": [i for i in all_iocs if i["ioc_type"] != "cve"],
        "cves": [i for i in all_iocs if i["ioc_type"] == "cve"],
        "threat_actors": await th_db.aggregate_threat_actors(),
        "campaigns": await th_db.aggregate_campaigns(),
        "malware_families": await th_db.aggregate_malware_families(),
        "ttps": await th_db.aggregate_ttps(),
    }


@router.get("/tracking/hunts")
async def list_tracking_hunts() -> list[dict]:
    """List every non-archived hunt package with its correlation-inclusion
    state, for the Hunts tab."""
    return await th_db.list_tracking_hunts()


class TrackingHuntExcludeBody(BaseModel):
    excluded: bool


@router.post("/tracking/hunts/{pkg_id}/exclude")
async def set_tracking_hunt_excluded(pkg_id: str, body: TrackingHuntExcludeBody) -> dict:
    """Include/exclude a hunt package from every cross-hunt aggregation above.
    Reversible — the hunt package and its data are untouched."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    await th_db.set_hunt_correlation_excluded(pkg_id, body.excluded)
    return _pkg_or_404(await th_db.get_hunt_package(pkg_id))


@router.delete("/tracking/hunts/{pkg_id}", status_code=204)
async def delete_tracking_hunt(pkg_id: str) -> None:
    """Delete a hunt package from the Hunts tab — a real, permanent removal
    (not a correlation-only soft action), reusing the same archive mechanism
    as the main Threat Hunting list's delete (DELETE /packages/{pkg_id})."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    await th_db.update_hunt_package(pkg_id, status="archived")
