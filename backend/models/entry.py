"""Pydantic models for ingest entries and API responses."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class EntryIn(BaseModel):
    """Payload accepted by the push listener and ingest endpoints."""

    model_config = {"extra": "allow"}  # pass-through unknown fields to normaliser

    indicator: str | None = None
    indicator_type: str | None = None
    threat_type: str | None = None
    severity: str | None = None
    confidence: float | None = None
    source: str | None = None
    source_url: str | None = None
    title: str | None = None
    description: str | None = None
    tags: str | None = None
    tlp: str | None = None
    published_at: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    affected_product: str | None = None
    affected_vendor: str | None = None
    patch_available: bool | None = None
    mitre_attack_id: str | None = None
    malware_family: str | None = None
    campaign: str | None = None
    actor: str | None = None
    country: str | None = None
    autonomous_system: str | None = None
    port: int | None = None
    protocol: str | None = None
    geo_lat: float | None = None
    geo_lon: float | None = None
    ingest_mode: str | None = None
    raw: str | None = None


class EntryOut(BaseModel):
    """Entry as returned by the viewer API."""

    model_config = {"extra": "allow"}

    id: int | None = None
    source: str
    ingested_at: str
    indicator: str | None = None
    indicator_type: str | None = None
    threat_type: str | None = None
    severity: str | None = None
    title: str | None = None
    ingest_mode: str | None = None


class SummaryItem(BaseModel):
    source: str
    count: int


class IngestResponse(BaseModel):
    inserted: int
    skipped: int
    errors: list[str] = Field(default_factory=list)
    # New 4-counter summary fields (back-compat: `skipped` == duplicates + discarded)
    total_read: int = 0
    duplicates: int = 0
    discarded: int = 0


class PreviewResponse(BaseModel):
    preview_id: str
    source_name: str
    format: str
    total: int
    sample: list[dict[str, Any]] = Field(default_factory=list)
    expires_in_seconds: int = 300
