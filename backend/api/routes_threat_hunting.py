"""
Threat Hunting API routes (issue-local-002, Phase 1 skeleton).

All routes require authentication when auth is enabled. Admin and
threat-researcher roles have write access; threat-viewer has read-only access
(enforced by the middleware allowlist in main.py).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from backend.threat_hunting import db as th_db
from backend.threat_hunting.models import (
    HuntPackageCreate,
    HuntPackageOut,
    HuntPackageUpdate,
)

router = APIRouter(prefix="/api/threat-hunting", tags=["threat-hunting"])


def _pkg_or_404(pkg: dict | None) -> dict:
    if pkg is None:
        raise HTTPException(status_code=404, detail="Hunt package not found")
    return pkg


# ── Hunt Packages ─────────────────────────────────────────────────────────────


@router.get("/packages", response_model=list[HuntPackageOut])
async def list_packages() -> list[dict]:
    """List all non-archived hunt packages."""
    return await th_db.list_hunt_packages()


@router.post("/packages", response_model=HuntPackageOut, status_code=201)
async def create_package(body: HuntPackageCreate) -> dict:
    """Create a new hunt package in draft status."""
    return await th_db.create_hunt_package(name=body.name, description=body.description)


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
