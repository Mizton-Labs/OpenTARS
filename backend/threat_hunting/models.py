"""Pydantic models for the Threat Hunting API (Phase 1 skeleton)."""

from __future__ import annotations

from enum import Enum

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
