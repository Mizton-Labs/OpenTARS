"""Durable SQLite storage for Threat Hunting (issue-local-002, Phase 1)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TH_DB_PATH = _PROJECT_ROOT / "data" / "threat_hunting.db"

_TH_SCHEMA_VERSION = 2


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


CREATE_SCHEMA_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS th_schema_version (
    version INTEGER NOT NULL
);
"""

CREATE_HUNT_PACKAGES_TABLE = """
CREATE TABLE IF NOT EXISTS hunt_packages (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'draft',
    created_by  TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""

CREATE_EVIDENCE_ITEMS_TABLE = """
CREATE TABLE IF NOT EXISTS evidence_items (
    id               TEXT PRIMARY KEY,
    hunt_package_id  TEXT NOT NULL REFERENCES hunt_packages(id),
    item_type        TEXT NOT NULL,
    label            TEXT,
    source_ref       TEXT,
    content_hash     TEXT,
    mime_type        TEXT,
    fetch_url        TEXT,
    final_url        TEXT,
    extracted_text   TEXT,
    parser_used      TEXT,
    parser_version   TEXT,
    parse_status     TEXT,
    parse_warnings   TEXT,
    fetch_metadata   TEXT,
    watcher_snapshot TEXT,
    created_at       TEXT NOT NULL,
    provenance_notes TEXT
);
"""

CREATE_EVIDENCE_BLOBS_TABLE = """
CREATE TABLE IF NOT EXISTS evidence_blobs (
    evidence_item_id TEXT PRIMARY KEY REFERENCES evidence_items(id),
    data             BLOB NOT NULL
);
"""

CREATE_EXTRACTED_IOCS_TABLE = """
CREATE TABLE IF NOT EXISTS extracted_iocs (
    id               TEXT PRIMARY KEY,
    evidence_item_id TEXT NOT NULL REFERENCES evidence_items(id),
    hunt_package_id  TEXT NOT NULL REFERENCES hunt_packages(id),
    ioc              TEXT NOT NULL,
    ioc_type         TEXT NOT NULL,
    ioc_description  TEXT,
    noise_score      REAL DEFAULT 0.0,
    flagged_noisy    INTEGER DEFAULT 0,
    created_at       TEXT NOT NULL
);
"""

CREATE_HUNTING_PACKAGES_TABLE = """
CREATE TABLE IF NOT EXISTS hunting_packages (
    id                  TEXT PRIMARY KEY,
    hunt_package_id     TEXT NOT NULL REFERENCES hunt_packages(id),
    threat_context      TEXT,
    hypotheses          TEXT,
    hunting_leads       TEXT,
    deep_retrohunt      TEXT,
    ttp_analysis        TEXT,
    query_drafts        TEXT,
    llm_provider        TEXT,
    llm_model           TEXT,
    generation_status   TEXT,
    generation_errors   TEXT,
    created_at          TEXT NOT NULL
);
"""

CREATE_TASK_RESULTS_TABLE = """
CREATE TABLE IF NOT EXISTS task_results (
    id               TEXT PRIMARY KEY,
    hunt_package_id  TEXT NOT NULL REFERENCES hunt_packages(id),
    task_type        TEXT NOT NULL,
    siem_connector   TEXT,
    query_text       TEXT,
    earliest         TEXT,
    latest           TEXT,
    hunt_id          TEXT,
    status           TEXT NOT NULL,
    raw_result       TEXT,
    interpreted_findings TEXT,
    confidence       REAL,
    created_at       TEXT NOT NULL,
    completed_at     TEXT
);
"""

CREATE_HUNT_REPORTS_TABLE = """
CREATE TABLE IF NOT EXISTS hunt_reports (
    id               TEXT PRIMARY KEY,
    hunt_package_id  TEXT NOT NULL REFERENCES hunt_packages(id),
    executive_summary TEXT,
    full_report      TEXT,
    created_at       TEXT NOT NULL,
    created_by       TEXT
);
"""

CREATE_SIEM_CONNECTORS_TABLE = """
CREATE TABLE IF NOT EXISTS siem_connectors (
    id              TEXT PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    kind            TEXT NOT NULL,
    base_url        TEXT NOT NULL,
    auth_method     TEXT NOT NULL,
    api_token_hash  TEXT,
    config_json     TEXT,
    verified        INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
"""


async def _migrate_db(db: aiosqlite.Connection, current_version: int) -> None:
    """Apply incremental schema migrations from current_version → _TH_SCHEMA_VERSION."""
    if current_version < 2:
        # v2: deep_retrohunt column added to hunting_packages.
        # The CREATE TABLE statement already includes it, so this only applies
        # to existing databases created at v1 that are missing the column.
        try:
            await db.execute("ALTER TABLE hunting_packages ADD COLUMN deep_retrohunt TEXT")
            logger.info("Migrated threat_hunting.db to schema v2 (added deep_retrohunt column)")
        except Exception:
            # Column already exists — safe to ignore
            pass


async def init_threat_hunting_db() -> None:
    """Create the threat hunting schema. Idempotent. Runs incremental migrations."""
    _TH_DB_PATH.parent.mkdir(exist_ok=True)
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(CREATE_SCHEMA_VERSION_TABLE)
        await db.execute(CREATE_HUNT_PACKAGES_TABLE)
        await db.execute(CREATE_EVIDENCE_ITEMS_TABLE)
        await db.execute(CREATE_EVIDENCE_BLOBS_TABLE)
        await db.execute(CREATE_EXTRACTED_IOCS_TABLE)
        await db.execute(CREATE_HUNTING_PACKAGES_TABLE)
        await db.execute(CREATE_TASK_RESULTS_TABLE)
        await db.execute(CREATE_HUNT_REPORTS_TABLE)
        await db.execute(CREATE_SIEM_CONNECTORS_TABLE)
        cur = await db.execute("SELECT version FROM th_schema_version LIMIT 1")
        row = await cur.fetchone()
        await cur.close()
        existing_version = int(row[0]) if row else 0
        if existing_version < _TH_SCHEMA_VERSION:
            await _migrate_db(db, existing_version)
        if row is None:
            await db.execute(
                "INSERT INTO th_schema_version (version) VALUES (?)",
                (_TH_SCHEMA_VERSION,),
            )
        else:
            await db.execute("UPDATE th_schema_version SET version = ?", (_TH_SCHEMA_VERSION,))
        await db.commit()
        logger.info("Threat hunting DB initialized (schema v%d)", _TH_SCHEMA_VERSION)


# ── Hunt Package CRUD ─────────────────────────────────────────────────────────


async def create_hunt_package(
    name: str, description: str = "", created_by: str | None = None
) -> dict[str, Any]:
    pkg_id = _new_id()
    now = _utc_now_iso()
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            "INSERT INTO hunt_packages (id, name, description, status, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, 'draft', ?, ?, ?)",
            (pkg_id, name, description, created_by, now, now),
        )
        await db.commit()
    return await get_hunt_package(pkg_id)


async def get_hunt_package(pkg_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT hp.*, COUNT(ei.id) AS evidence_count "
            "FROM hunt_packages hp "
            "LEFT JOIN evidence_items ei ON ei.hunt_package_id = hp.id "
            "WHERE hp.id = ? GROUP BY hp.id",
            (pkg_id,),
        )
        row = await cur.fetchone()
        await cur.close()
    return dict(row) if row else None


async def list_hunt_packages() -> list[dict[str, Any]]:
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT hp.*, COUNT(ei.id) AS evidence_count "
            "FROM hunt_packages hp "
            "LEFT JOIN evidence_items ei ON ei.hunt_package_id = hp.id "
            "WHERE hp.status != 'archived' "
            "GROUP BY hp.id ORDER BY hp.created_at DESC"
        )
        rows = await cur.fetchall()
        await cur.close()
    return [dict(r) for r in rows]


async def update_hunt_package(
    pkg_id: str, name: str | None = None, description: str | None = None, status: str | None = None
) -> dict[str, Any] | None:
    pkg = await get_hunt_package(pkg_id)
    if not pkg:
        return None
    new_name = name if name is not None else pkg["name"]
    new_desc = description if description is not None else pkg["description"]
    new_status = status if status is not None else pkg["status"]
    now = _utc_now_iso()
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            "UPDATE hunt_packages SET name=?, description=?, status=?, updated_at=? WHERE id=?",
            (new_name, new_desc, new_status, now, pkg_id),
        )
        await db.commit()
    return await get_hunt_package(pkg_id)


# ── Evidence Item CRUD ────────────────────────────────────────────────────────


async def add_evidence_item(
    hunt_package_id: str,
    *,
    item_type: str,
    label: str = "",
    source_ref: str = "",
    content_hash: str = "",
    mime_type: str = "",
    fetch_url: str = "",
    final_url: str = "",
    extracted_text: str = "",
    parser_used: str = "",
    parser_version: str = "",
    parse_status: str = "ok",
    parse_warnings: list[str] | None = None,
    fetch_metadata: dict | None = None,
    watcher_snapshot: dict | None = None,
    provenance_notes: str = "",
    blob_data: bytes | None = None,
) -> dict[str, Any]:
    import json

    item_id = _new_id()
    now = _utc_now_iso()
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO evidence_items
              (id, hunt_package_id, item_type, label, source_ref, content_hash,
               mime_type, fetch_url, final_url, extracted_text, parser_used,
               parser_version, parse_status, parse_warnings, fetch_metadata,
               watcher_snapshot, created_at, provenance_notes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item_id,
                hunt_package_id,
                item_type,
                label,
                source_ref,
                content_hash,
                mime_type,
                fetch_url,
                final_url,
                extracted_text,
                parser_used,
                parser_version,
                parse_status,
                json.dumps(parse_warnings or []),
                json.dumps(fetch_metadata or {}),
                json.dumps(watcher_snapshot or {}),
                now,
                provenance_notes,
            ),
        )
        if blob_data is not None:
            await db.execute(
                "INSERT INTO evidence_blobs (evidence_item_id, data) VALUES (?, ?)",
                (item_id, blob_data),
            )
        await db.commit()
    return await get_evidence_item(item_id)  # type: ignore[return-value]


async def get_evidence_item(item_id: str) -> dict[str, Any] | None:
    import json

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM evidence_items WHERE id = ?", (item_id,))
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    d = dict(row)
    for field in ("parse_warnings", "fetch_metadata", "watcher_snapshot"):
        try:
            d[field] = json.loads(d.get(field) or "null") or (
                [] if field == "parse_warnings" else {}
            )
        except Exception:
            d[field] = [] if field == "parse_warnings" else {}
    return d


async def list_evidence_items(hunt_package_id: str) -> list[dict[str, Any]]:
    import json

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM evidence_items WHERE hunt_package_id = ? ORDER BY created_at",
            (hunt_package_id,),
        )
        rows = await cur.fetchall()
        await cur.close()
    result = []
    for row in rows:
        d = dict(row)
        for field in ("parse_warnings", "fetch_metadata", "watcher_snapshot"):
            try:
                d[field] = json.loads(d.get(field) or "null") or (
                    [] if field == "parse_warnings" else {}
                )
            except Exception:
                d[field] = [] if field == "parse_warnings" else {}
        result.append(d)
    return result


async def delete_evidence_item(item_id: str) -> bool:
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute("DELETE FROM evidence_blobs WHERE evidence_item_id = ?", (item_id,))
        cur = await db.execute("DELETE FROM evidence_items WHERE id = ?", (item_id,))
        await db.commit()
        return cur.rowcount > 0


async def add_extracted_iocs(
    hunt_package_id: str,
    evidence_item_id: str,
    iocs: list[dict[str, Any]],
) -> None:
    now = _utc_now_iso()
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        for ioc in iocs:
            await db.execute(
                """
                INSERT OR IGNORE INTO extracted_iocs
                  (id, evidence_item_id, hunt_package_id, ioc, ioc_type,
                   ioc_description, noise_score, flagged_noisy, created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    _new_id(),
                    evidence_item_id,
                    hunt_package_id,
                    ioc.get("ioc", ""),
                    ioc.get("ioc_type", "other"),
                    ioc.get("ioc_description", ""),
                    float(ioc.get("noise_score", 0.0)),
                    1 if ioc.get("flagged_noisy") else 0,
                    now,
                ),
            )
        await db.commit()


async def list_extracted_iocs(hunt_package_id: str) -> list[dict[str, Any]]:
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM extracted_iocs WHERE hunt_package_id = ? ORDER BY ioc_type, ioc",
            (hunt_package_id,),
        )
        rows = await cur.fetchall()
        await cur.close()
    return [dict(r) for r in rows]
