"""Pydantic models for the Threat Hunting API (Phase 1 + 2)."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel


class HuntPackageStatus(str, Enum):
    draft = "draft"
    planning = "planning"
    approved = "approved"
    executing = "executing"
    completed = "completed"
    archived = "archived"


class HuntPackageCreate(BaseModel):
    name: str
    description: str = ""


class HuntPackageUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: HuntPackageStatus | None = None


class HuntPackageOut(BaseModel):
    id: str
    name: str
    description: str
    status: HuntPackageStatus
    created_by: str | None
    created_at: str
    updated_at: str
    evidence_count: int = 0
    # Phase/run data computed by list_hunt_packages (issue-008 root-cause fix).
    # These were previously stripped by FastAPI's response_model serialisation
    # because HuntPackageOut didn't declare them, causing every phase card to
    # render as pending/gray with no status color.
    generation_status: str | None = None
    phases: list[dict[str, Any]] | None = None
    total_elapsed_s: float | None = None
    run_created_at: str | None = None


# ── Evidence ──────────────────────────────────────────────────────────────────


class EvidenceItemOut(BaseModel):
    id: str
    hunt_package_id: str
    item_type: str
    label: str
    source_ref: str
    content_hash: str
    mime_type: str
    fetch_url: str
    final_url: str
    extracted_text: str
    parser_used: str
    parser_version: str
    parse_status: str
    parse_warnings: list[str]
    fetch_metadata: dict[str, Any]
    created_at: str
    provenance_notes: str

    model_config = {"from_attributes": True}


class AddUrlBody(BaseModel):
    url: str
    label: str = ""


class AddManualTextBody(BaseModel):
    text: str
    label: str = ""
    source_ref: str = ""


class AddWatcherBody(BaseModel):
    watcher_id: str
    label: str = ""
    max_events: int = 500


# ── IOCs ──────────────────────────────────────────────────────────────────────


class ExtractedIOCOut(BaseModel):
    id: str
    evidence_item_id: str
    hunt_package_id: str
    run_id: str | None = None
    ioc: str
    ioc_type: str
    ioc_description: str
    noise_score: float
    flagged_noisy: bool
    action: str = "keep"
    created_at: str
