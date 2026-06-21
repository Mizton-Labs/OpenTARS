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

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from backend.threat_hunting import db as th_db
from backend.threat_hunting.extractors.dispatcher import extract_file

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

    # issue-008-2B: IOC extraction moved to intake_classifier (agent pipeline).
    # No add_extracted_iocs call here — IOCs are extracted during analysis.

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
    research_effort: str | None = None  # 'high'|'medium'|'low'; None = use global default


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

    from backend.config.loader import load_th_research_effort
    from backend.threat_hunting.agents.runner import start_generation as _start

    # Resolve research effort: per-request override → global default
    effort = body.research_effort or load_th_research_effort()

    record = await _start(
        pkg_id,
        provider_name=body.provider_name,
        model_name=body.model_name,
        research_effort=effort,
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
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc

    hunt_name = (full_report.get("hunt_name") or pkg_id[:8]).replace(" ", "_")
    filename = f"hunt_report_{hunt_name}_run_{run_id[:8]}.pdf"
    from io import BytesIO

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
