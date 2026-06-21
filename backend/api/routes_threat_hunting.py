"""
Threat Hunting API routes (issue-local-002, Phase 1 + 2 + 3).

All routes require authentication when auth is enabled. Admin and
threat-researcher roles have write access; threat-viewer has read-only access
(enforced by the middleware allowlist in main.py).

Evidence endpoints:
  POST /packages/{id}/evidence/file      — upload a file (PDF, DOCX, TXT, CSV, …)
  POST /packages/{id}/evidence/url       — fetch and extract a URL
  POST /packages/{id}/evidence/text      — add manual text/note
  POST /packages/{id}/evidence/watcher   — import watcher events
  GET  /packages/{id}/evidence           — list evidence items
  DELETE /packages/{id}/evidence/{eid}   — remove an evidence item
  GET  /packages/{id}/iocs               — list all extracted IOCs

Generation endpoints (Phase 3):
  POST /packages/{id}/generate           — start LLM pipeline
  GET  /packages/{id}/generate/status    — poll generation status + draft
  POST /packages/{id}/approve            — approve generated package
  POST /packages/{id}/reject             — reject generated package
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from pydantic import BaseModel

from backend.threat_hunting import db as th_db
from backend.threat_hunting.extractors.dispatcher import extract_file
from backend.threat_hunting.extractors.url_fetcher import fetch_url
from backend.threat_hunting.iocs import extract_iocs_from_text
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
async def list_packages() -> list[dict]:
    """List all non-archived hunt packages."""
    return await th_db.list_hunt_packages()


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

    The file is parsed immediately and IOCs are extracted from the result.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    raw = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {_MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit",
        )

    filename = file.filename or "upload"
    mime_type = file.content_type or ""

    # Dispatch to appropriate extractor in a thread (CPU work)
    result = await asyncio.to_thread(extract_file, raw, filename, mime_type, parser_mode)

    item = await th_db.add_evidence_item(
        pkg_id,
        item_type="file",
        label=filename,
        source_ref=filename,
        content_hash=result["content_hash"],
        mime_type=result["mime_type"],
        extracted_text=result["extracted_text"],
        parser_used=result["parser_used"],
        parser_version=result["parser_version"],
        parse_status=result["parse_status"],
        parse_warnings=result["parse_warnings"],
        blob_data=raw,
    )

    # Extract and store IOCs
    iocs = extract_iocs_from_text(result["extracted_text"])
    if iocs:
        await th_db.add_extracted_iocs(pkg_id, item["id"], iocs)  # type: ignore[arg-type]

    return item


# ── Evidence: URL fetch ───────────────────────────────────────────────────────


@router.post(
    "/packages/{pkg_id}/evidence/url",
    response_model=EvidenceItemOut,
    status_code=201,
)
async def add_evidence_url(pkg_id: str, body: AddUrlBody) -> dict:
    """Fetch a URL and add its content as evidence.

    SSRF policy is enforced before and during fetch.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    try:
        fetch_result = await fetch_url(body.url)
    except SSRFError as exc:
        raise HTTPException(status_code=400, detail=f"SSRF policy violation: {exc}") from exc
    except Exception as exc:
        logger.warning("URL fetch failed for %r: %s", body.url, exc)
        raise HTTPException(status_code=502, detail=f"URL fetch failed: {exc}") from exc

    import hashlib

    content_hash = hashlib.sha256(fetch_result.raw_bytes).hexdigest()

    item = await th_db.add_evidence_item(
        pkg_id,
        item_type="url",
        label=body.label or fetch_result.final_url,
        source_ref=body.url,
        content_hash=content_hash,
        mime_type=fetch_result.content_type,
        fetch_url=body.url,
        final_url=fetch_result.final_url,
        extracted_text=fetch_result.extracted_text,
        parser_used=fetch_result.parser_used,
        parser_version="",
        parse_status="ok" if fetch_result.extracted_text else "partial",
        parse_warnings=fetch_result.warnings,
        fetch_metadata=fetch_result.fetch_metadata,
        blob_data=fetch_result.raw_bytes,
    )

    iocs = extract_iocs_from_text(fetch_result.extracted_text)
    if iocs:
        await th_db.add_extracted_iocs(pkg_id, item["id"], iocs)  # type: ignore[arg-type]

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
    )

    iocs = extract_iocs_from_text(body.text)
    if iocs:
        await th_db.add_extracted_iocs(pkg_id, item["id"], iocs)  # type: ignore[arg-type]

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
    )

    iocs = extract_iocs_from_text(text_blob)
    if iocs:
        await th_db.add_extracted_iocs(pkg_id, item["id"], iocs)  # type: ignore[arg-type]

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


# ── IOCs ──────────────────────────────────────────────────────────────────────


@router.get("/packages/{pkg_id}/iocs", response_model=list[ExtractedIOCOut])
async def list_iocs(pkg_id: str) -> list[dict]:
    """List all IOCs extracted across all evidence items for a hunt package."""
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))
    return await th_db.list_extracted_iocs(pkg_id)


# ── Generation (Phase 3) ──────────────────────────────────────────────────────


class GenerateBody(BaseModel):
    provider_name: str | None = None
    model_name: str | None = None


class ApproveBody(BaseModel):
    notes: str = ""


class RejectBody(BaseModel):
    notes: str = ""


@router.post("/packages/{pkg_id}/generate", status_code=202)
async def start_generation(pkg_id: str, body: GenerateBody) -> dict:
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

    from backend.threat_hunting.agents.runner import start_generation as _start

    record = await _start(
        pkg_id,
        provider_name=body.provider_name,
        model_name=body.model_name,
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
    """Approve the generated hunting package.

    Resumes the LangGraph pipeline through the approval gate and
    marks the hunt package status as 'approved'.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    from backend.threat_hunting.agents.runner import approve_generation as _approve

    try:
        return await _approve(pkg_id, notes=body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/packages/{pkg_id}/reject")
async def reject_generation(pkg_id: str, body: RejectBody) -> dict:
    """Reject the generated hunting package.

    Marks the generation as rejected and resets the hunt package to draft.
    """
    _pkg_or_404(await th_db.get_hunt_package(pkg_id))

    from backend.threat_hunting.agents.runner import reject_generation as _reject

    try:
        return await _reject(pkg_id, notes=body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
