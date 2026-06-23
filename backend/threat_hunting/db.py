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

_TH_SCHEMA_VERSION = 4


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
    created_at          TEXT NOT NULL,
    current_step        TEXT,
    completed_steps     TEXT,
    step_logs           TEXT,
    research_effort     TEXT
);
"""

CREATE_TASK_RESULTS_TABLE = """
CREATE TABLE IF NOT EXISTS task_results (
    id               TEXT PRIMARY KEY,
    hunt_package_id  TEXT NOT NULL REFERENCES hunt_packages(id),
    run_id           TEXT,
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
    run_id           TEXT,
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
    if current_version < 3:
        # v3: step telemetry + research effort columns added to hunting_packages.
        # These power the live verbosity visualization and per-run effort control.
        for col_def in (
            "ADD COLUMN current_step TEXT",
            "ADD COLUMN completed_steps TEXT",
            "ADD COLUMN step_logs TEXT",
            "ADD COLUMN research_effort TEXT",
        ):
            try:
                await db.execute(f"ALTER TABLE hunting_packages {col_def}")
            except Exception:
                # Column already exists — safe to ignore
                pass
        logger.info(
            "Migrated threat_hunting.db to schema v3 "
            "(added current_step, completed_steps, step_logs, research_effort)"
        )
    if current_version < 4:
        # v4: run_id columns added to hunt_reports and task_results to support
        # independent re-run of hunt packages (issue-local-005).
        # Also backfills existing rows by linking them to the latest
        # hunting_packages row for their hunt_package_id.
        for table, col_def in (
            ("hunt_reports", "ADD COLUMN run_id TEXT"),
            ("task_results", "ADD COLUMN run_id TEXT"),
        ):
            try:
                await db.execute(f"ALTER TABLE {table} {col_def}")  # noqa: S608
            except Exception:
                pass
        # Backfill: for each hunt_package_id find the latest hunting_packages.id
        # and set run_id on existing rows that have NULL run_id.
        try:
            await db.execute(
                """UPDATE hunt_reports
                   SET run_id = (
                       SELECT hp.id FROM hunting_packages hp
                       WHERE hp.hunt_package_id = hunt_reports.hunt_package_id
                       ORDER BY hp.created_at DESC LIMIT 1
                   )
                   WHERE run_id IS NULL"""
            )
            await db.execute(
                """UPDATE task_results
                   SET run_id = (
                       SELECT hp.id FROM hunting_packages hp
                       WHERE hp.hunt_package_id = task_results.hunt_package_id
                       ORDER BY hp.created_at DESC LIMIT 1
                   )
                   WHERE run_id IS NULL"""
            )
        except Exception as exc:
            logger.warning("Schema v4 backfill skipped (non-fatal): %s", exc)
        logger.info(
            "Migrated threat_hunting.db to schema v4 "
            "(added run_id to hunt_reports and task_results)"
        )


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


async def clone_hunt_package(
    src_pkg_id: str,
    new_name: str,
    created_by: str | None = None,
) -> dict[str, Any]:
    """Clone a hunt package's evidence to a new package.

    issue-local-012: creates a new package named *new_name*, copies all
    evidence_items rows (including file blobs from evidence_blobs) and resets
    parse_status to 'pending' so the clone will re-parse on its first run.
    Runs, reports, generation state, and IOCs are NOT copied.

    Returns the newly created package dict.
    """
    import json as _json

    new_pkg_id = _new_id()
    now = _utc_now_iso()

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        # 1. Create the new package
        await db.execute(
            "INSERT INTO hunt_packages (id, name, description, status, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, 'draft', ?, ?, ?)",
            (new_pkg_id, new_name, "", created_by, now, now),
        )

        # 2. Copy all evidence items (reset parse_status to pending, clear extracted_text)
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM evidence_items WHERE hunt_package_id = ? ORDER BY created_at",
            (src_pkg_id,),
        )
        src_items = await cur.fetchall()
        await cur.close()

        for row in src_items:
            row_dict = dict(row)
            new_item_id = _new_id()
            # Keep: item_type, label, source_ref, mime_type, fetch_url, fetch_metadata,
            #        watcher_snapshot, provenance_notes
            # Reset: parse_status='pending', extracted_text='', parser_used='', content_hash='', final_url=''
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
                    new_item_id,
                    new_pkg_id,
                    row_dict.get("item_type", ""),
                    row_dict.get("label", ""),
                    row_dict.get("source_ref", ""),
                    "",  # content_hash reset
                    row_dict.get("mime_type", ""),
                    row_dict.get("fetch_url", ""),
                    "",  # final_url reset
                    "",  # extracted_text reset
                    "",  # parser_used reset
                    "",  # parser_version reset
                    "pending",  # parse_status reset
                    _json.dumps(["Cloned evidence — will be parsed during analysis."]),
                    row_dict.get("fetch_metadata") or "{}",  # keep parser_mode etc.
                    row_dict.get("watcher_snapshot") or "{}",
                    now,
                    row_dict.get("provenance_notes", ""),
                ),
            )

            # 3. Copy blob if it exists (keeps the original file)
            blob_cur = await db.execute(
                "SELECT data FROM evidence_blobs WHERE evidence_item_id = ?",
                (row_dict.get("id"),),
            )
            blob_row = await blob_cur.fetchone()
            await blob_cur.close()
            if blob_row and blob_row[0]:
                await db.execute(
                    "INSERT INTO evidence_blobs (evidence_item_id, data) VALUES (?, ?)",
                    (new_item_id, blob_row[0]),
                )

        await db.commit()

    return await get_hunt_package(new_pkg_id)  # type: ignore[return-value]


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
    """List all non-archived hunt packages with evidence counts and latest run summary.

    issue-006-D: each package dict gains three optional keys:
      - ``phases``         list[{step, status, elapsed_s}] from latest run's step_logs
      - ``total_elapsed_s`` sum of elapsed_s across all completed steps (float|None)
      - ``generation_status`` generation_status of the latest run (str|None)
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        # Base query: packages + evidence count
        cur = await db.execute(
            "SELECT hp.*, COUNT(ei.id) AS evidence_count "
            "FROM hunt_packages hp "
            "LEFT JOIN evidence_items ei ON ei.hunt_package_id = hp.id "
            "WHERE hp.status != 'archived' "
            "GROUP BY hp.id ORDER BY hp.created_at DESC"
        )
        rows = await cur.fetchall()
        await cur.close()

        # Latest run per package (one row per hunt_package_id, newest created_at)
        # issue-008-2A: also fetch created_at for the live timer in the frontend
        cur2 = await db.execute(
            "SELECT hunt_package_id, generation_status, step_logs, created_at "
            "FROM hunting_packages "
            "WHERE id IN ("
            "  SELECT id FROM hunting_packages hp2 "
            "  WHERE hp2.hunt_package_id = hunting_packages.hunt_package_id "
            "  ORDER BY hp2.created_at DESC LIMIT 1"
            ")"
        )
        run_rows = await cur2.fetchall()
        await cur2.close()

    # Build lookup: hunt_package_id → {generation_status, step_logs_json, run_created_at}
    run_by_pkg: dict[str, dict[str, Any]] = {}
    for r in run_rows:
        run_by_pkg[r[0]] = {
            "generation_status": r[1],
            "step_logs_json": r[2],
            "run_created_at": r[3],
        }

    result: list[dict[str, Any]] = []
    for row in rows:
        pkg = dict(row)
        run = run_by_pkg.get(pkg["id"])
        if run:
            pkg["generation_status"] = run["generation_status"]
            # Parse step_logs JSON → phase summary
            phases: list[dict[str, Any]] = []
            total_elapsed: float = 0.0
            try:
                import json as _json

                step_logs: list[dict[str, Any]] = _json.loads(run["step_logs_json"] or "[]")
                for log in step_logs:
                    step_name = log.get("step", "")
                    if step_name:
                        elapsed = log.get("elapsed_s") or 0.0
                        # issue-007: widen projection with richer step-log fields
                        phase_entry: dict[str, Any] = {
                            "step": step_name,
                            "status": log.get("status", "unknown"),
                            "elapsed_s": elapsed,
                        }
                        if log.get("tools_used") is not None:
                            phase_entry["tools_used"] = log["tools_used"]
                        if log.get("decision"):
                            phase_entry["decision"] = log["decision"]
                        if log.get("item_count") is not None:
                            phase_entry["item_count"] = log["item_count"]
                        if log.get("ioc_count") is not None:
                            phase_entry["ioc_count"] = log["ioc_count"]
                        if log.get("noisy_count") is not None:
                            phase_entry["noisy_count"] = log["noisy_count"]
                        phases.append(phase_entry)
                        total_elapsed += float(elapsed)
            except Exception:  # noqa: BLE001
                pass
            pkg["phases"] = phases if phases else None
            pkg["total_elapsed_s"] = round(total_elapsed, 2) if phases else None
            pkg["run_created_at"] = run.get("run_created_at")  # issue-008-2A: live timer
        else:
            pkg["generation_status"] = None
            pkg["phases"] = None
            pkg["total_elapsed_s"] = None
            pkg["run_created_at"] = None
        result.append(pkg)
    return result


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


async def get_evidence_blob(item_id: str) -> bytes | None:
    """Return the raw blob bytes for an evidence item, or None if absent.

    Used by intake_classifier to parse file evidence that was stored with
    parse_status='pending' (issue-local-011: deferred file parsing).
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        cur = await db.execute(
            "SELECT data FROM evidence_blobs WHERE evidence_item_id = ?", (item_id,)
        )
        row = await cur.fetchone()
        await cur.close()
    return bytes(row[0]) if row and row[0] is not None else None


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


async def clear_extracted_iocs(hunt_package_id: str) -> int:
    """Delete all extracted IOCs for *hunt_package_id*.

    issue-008-2B: called by intake_classifier at the start of each pipeline
    run to ensure re-runs produce a fresh, non-duplicated IOC set.

    Returns the number of rows deleted.
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        cur = await db.execute(
            "DELETE FROM extracted_iocs WHERE hunt_package_id = ?",
            (hunt_package_id,),
        )
        deleted = cur.rowcount
        await db.commit()
    return deleted


async def update_evidence_item(
    item_id: str,
    *,
    extracted_text: str | None = None,
    parser_used: str | None = None,
    parser_version: str | None = None,
    parse_status: str | None = None,
    parse_warnings: list[str] | None = None,
    fetch_metadata: dict[str, Any] | None = None,
    final_url: str | None = None,
    content_hash: str | None = None,
    mime_type: str | None = None,
) -> None:
    """Partially update an evidence item.

    issue-008-2B: used by intake_classifier to write fetched URL content
    back to pending evidence items created at upload time.

    Only non-None keyword arguments are written; others are left unchanged.
    """
    import json as _json

    set_clauses: list[str] = []
    params: list[Any] = []

    if extracted_text is not None:
        set_clauses.append("extracted_text = ?")
        params.append(extracted_text)
    if parser_used is not None:
        set_clauses.append("parser_used = ?")
        params.append(parser_used)
    if parser_version is not None:
        set_clauses.append("parser_version = ?")
        params.append(parser_version)
    if parse_status is not None:
        set_clauses.append("parse_status = ?")
        params.append(parse_status)
    if parse_warnings is not None:
        set_clauses.append("parse_warnings = ?")
        params.append(_json.dumps(parse_warnings))
    if fetch_metadata is not None:
        set_clauses.append("fetch_metadata = ?")
        params.append(_json.dumps(fetch_metadata))
    if final_url is not None:
        set_clauses.append("final_url = ?")
        params.append(final_url)
    if content_hash is not None:
        set_clauses.append("content_hash = ?")
        params.append(content_hash)
    if mime_type is not None:
        set_clauses.append("mime_type = ?")
        params.append(mime_type)

    if not set_clauses:
        return  # nothing to update

    params.append(item_id)
    sql = f"UPDATE evidence_items SET {', '.join(set_clauses)} WHERE id = ?"
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(sql, params)
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


# ── SIEM Connector CRUD ───────────────────────────────────────────────────────
#
# Security contract:
#   - api_token is stored in config_json under key "api_token" (plain text,
#     file-access-controlled by the OS).
#   - GET/list responses NEVER return the plain token; they substitute "***".
#   - username/password stored similarly: password returned as "***".
#   - The caller is responsible for not logging config_json.


def _mask_connector(d: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a connector dict with sensitive values masked."""
    import json as _json

    d = dict(d)
    try:
        cfg = _json.loads(d.get("config_json") or "{}")
    except Exception:
        cfg = {}
    if "api_token" in cfg:
        cfg["api_token"] = "***"
    if "password" in cfg:
        cfg["password"] = "***"
    d["config_json"] = _json.dumps(cfg)
    return d


async def create_siem_connector(
    name: str,
    *,
    kind: str = "splunk",
    base_url: str,
    auth_method: str = "token",
    api_token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    verify_tls: bool = True,
    default_index: str = "main",
    retrohunt_macro: str = "threathunt_ioc_search",
) -> dict[str, Any]:
    import json as _json

    conn_id = _new_id()
    now = _utc_now_iso()
    cfg: dict[str, Any] = {
        "verify_tls": verify_tls,
        "default_index": default_index,
        "retrohunt_macro": retrohunt_macro,
    }
    if api_token:
        cfg["api_token"] = api_token
    if username:
        cfg["username"] = username
    if password:
        cfg["password"] = password

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            """INSERT INTO siem_connectors
               (id, name, kind, base_url, auth_method, config_json, verified, created_at, updated_at)
               VALUES (?,?,?,?,?,?,0,?,?)""",
            (conn_id, name, kind, base_url, auth_method, _json.dumps(cfg), now, now),
        )
        await db.commit()
    return _mask_connector(await _get_connector_raw(conn_id))  # type: ignore[arg-type]


async def _get_connector_raw(conn_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM siem_connectors WHERE id = ?", (conn_id,))
        row = await cur.fetchone()
        await cur.close()
    return dict(row) if row else None


async def get_siem_connector(conn_id: str) -> dict[str, Any] | None:
    row = await _get_connector_raw(conn_id)
    return _mask_connector(row) if row else None


async def list_siem_connectors() -> list[dict[str, Any]]:
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM siem_connectors ORDER BY created_at")
        rows = await cur.fetchall()
        await cur.close()
    return [_mask_connector(dict(r)) for r in rows]


async def update_siem_connector(
    conn_id: str,
    *,
    name: str | None = None,
    base_url: str | None = None,
    auth_method: str | None = None,
    api_token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    verify_tls: bool | None = None,
    default_index: str | None = None,
    retrohunt_macro: str | None = None,
    verified: bool | None = None,
) -> dict[str, Any] | None:
    import json as _json

    raw = await _get_connector_raw(conn_id)
    if not raw:
        return None
    try:
        cfg = _json.loads(raw.get("config_json") or "{}")
    except Exception:
        cfg = {}

    # Only update supplied fields
    if api_token is not None:
        cfg["api_token"] = api_token
    if username is not None:
        cfg["username"] = username
    if password is not None:
        cfg["password"] = password
    if verify_tls is not None:
        cfg["verify_tls"] = verify_tls
    if default_index is not None:
        cfg["default_index"] = default_index
    if retrohunt_macro is not None:
        cfg["retrohunt_macro"] = retrohunt_macro

    new_name = name if name is not None else raw["name"]
    new_url = base_url if base_url is not None else raw["base_url"]
    new_auth = auth_method if auth_method is not None else raw["auth_method"]
    new_verified = (1 if verified else 0) if verified is not None else raw["verified"]
    now = _utc_now_iso()

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            """UPDATE siem_connectors
               SET name=?, base_url=?, auth_method=?, config_json=?, verified=?, updated_at=?
               WHERE id=?""",
            (new_name, new_url, new_auth, _json.dumps(cfg), new_verified, now, conn_id),
        )
        await db.commit()
    return _mask_connector(await _get_connector_raw(conn_id))  # type: ignore[arg-type]


async def delete_siem_connector(conn_id: str) -> bool:
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        cur = await db.execute("DELETE FROM siem_connectors WHERE id = ?", (conn_id,))
        await db.commit()
        return cur.rowcount > 0


def _load_connector_for_use(raw: dict[str, Any]) -> dict[str, Any]:
    """Return connector dict with plain credentials for use by the connector class.

    NEVER log or return this to the API layer.
    """
    import json as _json

    d = dict(raw)
    try:
        cfg = _json.loads(d.get("config_json") or "{}")
    except Exception:
        cfg = {}
    d["_cfg"] = cfg
    return d


async def get_connector_for_use(conn_id: str) -> dict[str, Any] | None:
    """Load a connector with plain credentials — for internal use only."""
    raw = await _get_connector_raw(conn_id)
    return _load_connector_for_use(raw) if raw else None


# ── Task Results CRUD ─────────────────────────────────────────────────────────


async def create_task_result(
    hunt_package_id: str,
    *,
    task_type: str,
    siem_connector: str = "",
    query_text: str = "",
    earliest: str = "",
    latest: str = "",
    hunt_id: str = "",
    status: str = "pending",
    run_id: str | None = None,
) -> dict[str, Any]:

    result_id = _new_id()
    now = _utc_now_iso()
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            """INSERT INTO task_results
               (id, hunt_package_id, run_id, task_type, siem_connector, query_text,
                earliest, latest, hunt_id, status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                result_id,
                hunt_package_id,
                run_id,
                task_type,
                siem_connector,
                query_text,
                earliest,
                latest,
                hunt_id,
                status,
                now,
            ),
        )
        await db.commit()
    return await get_task_result(result_id)  # type: ignore[return-value]


async def get_task_result(result_id: str) -> dict[str, Any] | None:
    import json as _json

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM task_results WHERE id = ?", (result_id,))
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    d = dict(row)
    if d.get("raw_result") and isinstance(d["raw_result"], str):
        try:
            d["raw_result"] = _json.loads(d["raw_result"])
        except Exception:
            pass
    return d


async def update_task_result(
    result_id: str,
    *,
    status: str | None = None,
    raw_result: list | dict | None = None,
    interpreted_findings: str | None = None,
    confidence: float | None = None,
    completed_at: str | None = None,
) -> dict[str, Any] | None:
    import json as _json

    existing = await get_task_result(result_id)
    if not existing:
        return None
    updates: dict[str, Any] = {}
    if status is not None:
        updates["status"] = status
    if raw_result is not None:
        updates["raw_result"] = _json.dumps(raw_result, ensure_ascii=False, default=str)
    if interpreted_findings is not None:
        updates["interpreted_findings"] = interpreted_findings
    if confidence is not None:
        updates["confidence"] = confidence
    if completed_at is not None:
        updates["completed_at"] = completed_at
    if not updates:
        return existing
    set_clause = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [result_id]
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            f"UPDATE task_results SET {set_clause} WHERE id=?",  # noqa: S608
            values,
        )
        await db.commit()
    return await get_task_result(result_id)


async def list_task_results(hunt_package_id: str) -> list[dict[str, Any]]:
    import json as _json

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM task_results WHERE hunt_package_id = ? ORDER BY created_at DESC",
            (hunt_package_id,),
        )
        rows = await cur.fetchall()
        await cur.close()
    results = []
    for row in rows:
        d = dict(row)
        if d.get("raw_result") and isinstance(d["raw_result"], str):
            try:
                d["raw_result"] = _json.loads(d["raw_result"])
            except Exception:
                pass
        results.append(d)
    return results


async def list_task_results_by_run(run_id: str) -> list[dict[str, Any]]:
    """Return task results scoped to a specific generation run."""
    import json as _json

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM task_results WHERE run_id = ? ORDER BY created_at DESC",
            (run_id,),
        )
        rows = await cur.fetchall()
        await cur.close()
    results = []
    for row in rows:
        d = dict(row)
        if d.get("raw_result") and isinstance(d["raw_result"], str):
            try:
                d["raw_result"] = _json.loads(d["raw_result"])
            except Exception:
                pass
        results.append(d)
    return results


# ── Generation record (public read-only accessor) ─────────────────────────────


async def get_generation_record_public(
    hunt_package_id: str,
    run_id: str | None = None,
) -> dict[str, Any] | None:
    """Return a generation record for a hunt package.

    When *run_id* is supplied the specific run is returned; otherwise the
    latest run for the package is returned.  JSON-decodes all structured
    fields.  Used by report_writer and the report API to avoid importing
    the runner module.
    """
    if run_id:
        return await get_generation_run(run_id)

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM hunting_packages WHERE hunt_package_id = ? ORDER BY created_at DESC LIMIT 1",
            (hunt_package_id,),
        )
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    return _decode_hunting_package_row(dict(row))


# ── Generation run CRUD (issue-local-005) ────────────────────────────────────


def _decode_hunting_package_row(d: dict) -> dict:
    """JSON-decode structured fields in a hunting_packages row dict."""
    import json as _json

    for field in (
        "hypotheses",
        "hunting_leads",
        "deep_retrohunt",
        "ttp_analysis",
        "query_drafts",
        "generation_errors",
        "completed_steps",
        "step_logs",
    ):
        raw = d.get(field)
        if raw and isinstance(raw, str):
            try:
                d[field] = _json.loads(raw)
            except Exception:
                pass
    if d.get("threat_context") and isinstance(d["threat_context"], str):
        try:
            d["threat_context"] = _json.loads(d["threat_context"])
        except Exception:
            pass
    return d


async def get_generation_run(run_id: str) -> dict[str, Any] | None:
    """Return a single hunting_packages row by its own primary-key id (run_id)."""
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM hunting_packages WHERE id = ?",
            (run_id,),
        )
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    return _decode_hunting_package_row(dict(row))


async def list_generation_runs(hunt_package_id: str) -> list[dict[str, Any]]:
    """Return all generation runs for a hunt package, newest first.

    Returns lightweight summaries: id, hunt_package_id, generation_status,
    llm_provider, llm_model, research_effort, created_at.
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT id, hunt_package_id, generation_status,
                      llm_provider, llm_model, research_effort, created_at
               FROM hunting_packages
               WHERE hunt_package_id = ?
               ORDER BY created_at DESC""",
            (hunt_package_id,),
        )
        rows = await cur.fetchall()
        await cur.close()
    return [dict(row) for row in rows]


# ── Hunt Report CRUD ──────────────────────────────────────────────────────────
#
# The ``full_report`` column stores the complete structured report as JSON.
# Schema:
#   {
#     "executive_summary": str,
#     "hunt_name": str,
#     "hunt_id": str,
#     "generated_at": ISO datetime str,
#     "generated_by": str | null,
#     "package_status": str,
#     "evidence_summary": {total_items, ioc_count, noisy_ioc_count},
#     "threat_context": dict | null,
#     "hypotheses": [...],
#     "hunting_leads": [...],
#     "deep_retrohunt_summary": {total_iocs, noisy_iocs, spl_macro_name} | null,
#     "ttp_analysis": dict | null,
#     "query_drafts_count": int,
#     "execution_results": [...],
#     "recommendations": [str, ...],
#   }


async def create_hunt_report(
    hunt_package_id: str,
    *,
    executive_summary: str,
    full_report: dict,
    created_by: str | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    import json as _json

    report_id = _new_id()
    now = _utc_now_iso()
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            """INSERT INTO hunt_reports
               (id, hunt_package_id, run_id, executive_summary, full_report, created_at, created_by)
               VALUES (?,?,?,?,?,?,?)""",
            (
                report_id,
                hunt_package_id,
                run_id,
                executive_summary,
                _json.dumps(full_report, ensure_ascii=False, default=str),
                now,
                created_by,
            ),
        )
        await db.commit()
    if run_id:
        return await get_hunt_report_by_run(run_id) or {}  # type: ignore[return-value]
    return await get_hunt_report(hunt_package_id)  # type: ignore[return-value]


def _decode_report_row(d: dict) -> dict:
    import json as _json

    if d.get("full_report") and isinstance(d["full_report"], str):
        try:
            d["full_report"] = _json.loads(d["full_report"])
        except Exception:
            pass
    return d


async def get_hunt_report(hunt_package_id: str) -> dict[str, Any] | None:
    """Return the latest report for a hunt package (most recently created)."""
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM hunt_reports WHERE hunt_package_id = ? ORDER BY created_at DESC LIMIT 1",
            (hunt_package_id,),
        )
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    return _decode_report_row(dict(row))


async def get_hunt_report_by_run(run_id: str) -> dict[str, Any] | None:
    """Return the report for a specific generation run."""
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM hunt_reports WHERE run_id = ? ORDER BY created_at DESC LIMIT 1",
            (run_id,),
        )
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    return _decode_report_row(dict(row))


# ── Run-level step_log helpers (issue-local-009) ─────────────────────────────


async def append_run_step_log(run_id: str, entry: dict[str, Any]) -> None:
    """Merge *entry* into the step_logs list of an existing hunting_packages row.

    Uses last-write-wins per ``step`` key (same merge strategy as
    ``state._reduce_step_logs``).  Creates the step if not present; updates in
    place if the step already exists.  No-ops when *run_id* is not found.

    Args:
        run_id: Primary key of the hunting_packages row.
        entry:  A step-log dict; must contain a ``"step"`` key.
    """
    import json as _json

    step_key = entry.get("step")
    if not step_key:
        return

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT step_logs FROM hunting_packages WHERE id = ?", (run_id,)
        )
        row = await cur.fetchone()
        await cur.close()
        if not row:
            return

        try:
            logs: list[dict[str, Any]] = _json.loads(row[0] or "[]")
            if not isinstance(logs, list):
                logs = []
        except Exception:
            logs = []

        # Last-write-wins merge keyed on step name
        idx = next((i for i, lg in enumerate(logs) if lg.get("step") == step_key), None)
        if idx is None:
            logs.append(entry)
        else:
            logs[idx] = {**logs[idx], **entry}

        await db.execute(
            "UPDATE hunting_packages SET step_logs = ? WHERE id = ?",
            (_json.dumps(logs, ensure_ascii=False, default=str), run_id),
        )
        await db.commit()


async def set_run_generation_status(run_id: str, status: str) -> None:
    """Update only the generation_status of an existing hunting_packages run row.

    No-ops when *run_id* is not found.  Used by executor and report_writer to
    surface ``executing`` / ``reporting`` status without touching pipeline state.
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            "UPDATE hunting_packages SET generation_status = ? WHERE id = ?",
            (status, run_id),
        )
        await db.commit()


async def list_hunt_reports(hunt_package_id: str) -> list[dict[str, Any]]:
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM hunt_reports WHERE hunt_package_id = ? ORDER BY created_at DESC",
            (hunt_package_id,),
        )
        rows = await cur.fetchall()
        await cur.close()
    return [_decode_report_row(dict(row)) for row in rows]
