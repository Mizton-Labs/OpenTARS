"""Durable SQLite storage for Threat Hunting (issue-local-002, Phase 1)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from backend.config.loader import load_hunt_id_prefix

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TH_DB_PATH = _PROJECT_ROOT / "data" / "threat_hunting.db"

_TH_SCHEMA_VERSION = 11


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def format_hunt_id(prefix: str, hunt_seq: int | None) -> str:
    """Build a hunt package's human-readable HuntID, e.g. prefix 'TH' + seq 1 -> 'TH01'.

    ``:02d`` is a minimum width, not a cap — seq 100 renders as 'TH100', no
    truncation. Computed dynamically from the *current* prefix setting
    (issue-local-018), not baked into a stored string, so changing the
    prefix relabels every package consistently.
    """
    if hunt_seq is None:
        return ""
    return f"{prefix}{hunt_seq:02d}"


def format_run_id(hunt_id_display: str, run_seq: int | None) -> str:
    """Build a run's human-readable Run ID, e.g. HuntID 'TH01' + seq 1 -> 'TH01-X01'."""
    if run_seq is None or not hunt_id_display:
        return ""
    return f"{hunt_id_display}-X{run_seq:02d}"


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
    updated_at  TEXT NOT NULL,
    hunt_seq    INTEGER,
    excluded_from_correlation INTEGER NOT NULL DEFAULT 0
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
    run_id           TEXT,
    ioc              TEXT NOT NULL,
    ioc_type         TEXT NOT NULL,
    ioc_description  TEXT,
    noise_score      REAL DEFAULT 0.0,
    flagged_noisy    INTEGER DEFAULT 0,
    action           TEXT DEFAULT 'keep',
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
    research_effort     TEXT,
    run_config          TEXT DEFAULT '{}',
    run_seq             INTEGER,
    threat_intel_status TEXT,
    created_by          TEXT
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

CREATE_RUN_COMMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS run_comments (
    id               TEXT PRIMARY KEY,
    hunt_package_id  TEXT NOT NULL REFERENCES hunt_packages(id),
    run_id           TEXT NOT NULL,
    body             TEXT NOT NULL,
    created_by       TEXT,
    created_at       TEXT NOT NULL
);
"""

CREATE_THREAT_INTEL_ANALYSIS_TABLE = """
CREATE TABLE IF NOT EXISTS threat_intel_analysis (
    id                TEXT PRIMARY KEY,
    hunt_package_id   TEXT NOT NULL REFERENCES hunt_packages(id),
    run_id            TEXT,
    threat_actors     TEXT,
    attribution       TEXT,
    malware_families  TEXT,
    campaigns         TEXT,
    related_vendors   TEXT,
    correlated_iocs   TEXT,
    summary           TEXT,
    full_analysis     TEXT,
    created_at        TEXT NOT NULL,
    created_by        TEXT
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
    if current_version < 5:
        # v5: run_id + action columns added to extracted_iocs so each run's
        # IOC set is independent (issue-local-015), and run_config added to
        # hunting_packages for per-run IOC-handling settings.
        for table, col_def in (
            ("extracted_iocs", "ADD COLUMN run_id TEXT"),
            ("extracted_iocs", "ADD COLUMN action TEXT DEFAULT 'keep'"),
            ("hunting_packages", "ADD COLUMN run_config TEXT DEFAULT '{}'"),
        ):
            try:
                await db.execute(f"ALTER TABLE {table} {col_def}")  # noqa: S608
            except Exception:
                pass
        # Backfill: pre-v5 IOC rows predate real run scoping — best-effort
        # link to the latest run for their package, matching the v4 backfill
        # approach for hunt_reports/task_results.
        try:
            await db.execute(
                """UPDATE extracted_iocs
                   SET run_id = (
                       SELECT hp.id FROM hunting_packages hp
                       WHERE hp.hunt_package_id = extracted_iocs.hunt_package_id
                       ORDER BY hp.created_at DESC LIMIT 1
                   )
                   WHERE run_id IS NULL"""
            )
        except Exception as exc:
            logger.warning("Schema v5 backfill skipped (non-fatal): %s", exc)
        logger.info(
            "Migrated threat_hunting.db to schema v5 "
            "(added run_id/action to extracted_iocs, run_config to hunting_packages)"
        )
    if current_version < 6:
        # v6 (issue-local-018): hunt_seq/run_seq columns for human-readable
        # HuntID/Run ID display codes, plus the run_comments table.
        for table, col_def in (
            ("hunt_packages", "ADD COLUMN hunt_seq INTEGER"),
            ("hunting_packages", "ADD COLUMN run_seq INTEGER"),
        ):
            try:
                await db.execute(f"ALTER TABLE {table} {col_def}")  # noqa: S608
            except Exception:
                pass
        # Backfill: assign sequences in creation order (oldest = 1) so every
        # pre-existing package/run gets a HuntID/Run ID too, not just new
        # ones going forward. A plain Python loop (not a SQL window
        # function) to match this file's existing simple-SQL migration
        # style — these tables are small (dozens to low hundreds of rows).
        try:
            cur = await db.execute(
                "SELECT id FROM hunt_packages WHERE hunt_seq IS NULL ORDER BY created_at ASC"
            )
            pkg_rows = await cur.fetchall()
            await cur.close()
            cur = await db.execute("SELECT COALESCE(MAX(hunt_seq), 0) FROM hunt_packages")
            next_seq = (await cur.fetchone())[0] + 1
            await cur.close()
            for row in pkg_rows:
                await db.execute(
                    "UPDATE hunt_packages SET hunt_seq = ? WHERE id = ?", (next_seq, row[0])
                )
                next_seq += 1

            cur = await db.execute(
                "SELECT id, hunt_package_id FROM hunting_packages "
                "WHERE run_seq IS NULL ORDER BY hunt_package_id, created_at ASC"
            )
            run_rows = await cur.fetchall()
            await cur.close()
            run_seq_by_pkg: dict[str, int] = {}
            for run_id, hunt_package_id in run_rows:
                next_run_seq = run_seq_by_pkg.get(hunt_package_id, 0) + 1
                run_seq_by_pkg[hunt_package_id] = next_run_seq
                await db.execute(
                    "UPDATE hunting_packages SET run_seq = ? WHERE id = ?", (next_run_seq, run_id)
                )
        except Exception as exc:
            logger.warning("Schema v6 backfill skipped (non-fatal): %s", exc)
        await db.execute(CREATE_RUN_COMMENTS_TABLE)
        logger.info(
            "Migrated threat_hunting.db to schema v6 "
            "(added hunt_seq/run_seq for HuntID/Run ID, run_comments table)"
        )
    if current_version < 7:
        # v7 (issue-local-020): threat_intel_analysis table (Threat Hunt
        # Intelligence Analyst results) + an index on extracted_iocs.ioc to
        # speed up both the new cross-package correlation query and the new
        # deep-search LIKE filter.
        await db.execute(CREATE_THREAT_INTEL_ANALYSIS_TABLE)
        try:
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_extracted_iocs_ioc ON extracted_iocs(ioc)"
            )
        except Exception as exc:
            logger.warning("Schema v7 index creation skipped (non-fatal): %s", exc)
        logger.info(
            "Migrated threat_hunting.db to schema v7 "
            "(added threat_intel_analysis table, extracted_iocs.ioc index)"
        )
    if current_version < 8:
        # v8 (issue-local-021): excluded_from_correlation flag on
        # hunt_packages for the new Threat Intel Tracking dashboard — a
        # reversible per-hunt opt-out from all cross-hunt aggregation
        # queries (Dashboard tab's Hunts tab "Exclude" action).
        try:
            await db.execute(
                "ALTER TABLE hunt_packages ADD COLUMN excluded_from_correlation "
                "INTEGER NOT NULL DEFAULT 0"
            )
        except Exception:
            pass
        logger.info(
            "Migrated threat_hunting.db to schema v8 "
            "(added hunt_packages.excluded_from_correlation)"
        )
    if current_version < 9:
        # v9 (issue-local-022 item 3): threat_intel_status on hunting_packages
        # (the per-run table) — 'running' while either Threat Intel phase is
        # active for that run, else NULL. Lets the UI gate Re-run/report
        # generation while a Threat Intel analysis is in flight instead of
        # letting them race against it.
        try:
            await db.execute("ALTER TABLE hunting_packages ADD COLUMN threat_intel_status TEXT")
        except Exception:
            pass
        logger.info(
            "Migrated threat_hunting.db to schema v9 (added hunting_packages.threat_intel_status)"
        )
    if current_version < 10:
        # v10 (issue-local-026): created_by on hunting_packages (the per-run
        # table) — the username that triggered this specific run, so the
        # Runs table can show who started it (distinct from
        # hunt_packages.created_by, which is only the package's original
        # creator and doesn't change on re-run by a different user).
        try:
            await db.execute("ALTER TABLE hunting_packages ADD COLUMN created_by TEXT")
        except Exception:
            pass
        logger.info("Migrated threat_hunting.db to schema v10 (added hunting_packages.created_by)")
    if current_version < 11:
        # v11 (issue-local-026 follow-up): extracted_iocs had NO uniqueness
        # constraint on (hunt_package_id, run_id, ioc, ioc_type) — the only
        # real key was `id`, a fresh UUID per row — so add_extracted_iocs's
        # "INSERT OR IGNORE" never actually ignored anything. Every evidence
        # item that mentioned the same IOC inserted its own duplicate row,
        # and every reader of this table (the flat IOC tab, the cross-package
        # Threat Intel correlation query) surfaced the same IOC multiple
        # times. Clean up duplicates already on disk (keep the lowest id per
        # group — SQLite GROUP BY treats NULL run_id as one group too, so
        # this also collapses pre-run_id legacy duplicates), then add the
        # unique index so future inserts actually dedupe as the code already
        # assumed they did.
        try:
            await db.execute(
                """
                DELETE FROM extracted_iocs
                WHERE id NOT IN (
                    SELECT MIN(id) FROM extracted_iocs
                    GROUP BY hunt_package_id, run_id, ioc, ioc_type
                )
                """
            )
            await db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_extracted_iocs_unique "
                "ON extracted_iocs(hunt_package_id, run_id, ioc, ioc_type)"
            )
        except Exception as exc:
            logger.warning("Schema v11 IOC dedup skipped (non-fatal): %s", exc)
        logger.info(
            "Migrated threat_hunting.db to schema v11 (deduped extracted_iocs, added unique index)"
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
        await db.execute(CREATE_RUN_COMMENTS_TABLE)
        await db.execute(CREATE_SIEM_CONNECTORS_TABLE)
        await db.execute(CREATE_THREAT_INTEL_ANALYSIS_TABLE)
        try:
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_extracted_iocs_ioc ON extracted_iocs(ioc)"
            )
        except Exception:
            pass
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
        # issue-local-018: hunt_seq (the HuntID's numeric part) must be
        # assigned atomically — BEGIN IMMEDIATE serializes the read-then-
        # write against other concurrent create_hunt_package calls, same
        # idiom used by backend/normalizer/mappings.py's activate_version.
        await db.execute("BEGIN IMMEDIATE")
        try:
            cur = await db.execute("SELECT COALESCE(MAX(hunt_seq), 0) FROM hunt_packages")
            next_seq = (await cur.fetchone())[0] + 1
            await cur.close()
            await db.execute(
                "INSERT INTO hunt_packages "
                "(id, name, description, status, created_by, created_at, updated_at, hunt_seq) "
                "VALUES (?, ?, ?, 'draft', ?, ?, ?, ?)",
                (pkg_id, name, description, created_by, now, now, next_seq),
            )
            await db.commit()
        except Exception:
            await db.rollback()
            raise
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
        # 1. Create the new package (issue-local-018: hunt_seq assigned
        # atomically under the same BEGIN IMMEDIATE idiom as
        # create_hunt_package — a clone is a brand-new package for HuntID
        # purposes, not a copy of the source's own HuntID).
        await db.execute("BEGIN IMMEDIATE")
        cur = await db.execute("SELECT COALESCE(MAX(hunt_seq), 0) FROM hunt_packages")
        next_seq = (await cur.fetchone())[0] + 1
        await cur.close()
        await db.execute(
            "INSERT INTO hunt_packages (id, name, description, status, created_by, created_at, updated_at, hunt_seq) "
            "VALUES (?, ?, ?, 'draft', ?, ?, ?, ?)",
            (new_pkg_id, new_name, "", created_by, now, now, next_seq),
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
    if not row:
        return None
    pkg = dict(row)
    pkg["hunt_id_display"] = format_hunt_id(load_hunt_id_prefix(), pkg.get("hunt_seq"))
    return pkg


def _parse_step_logs(
    step_logs_json: str | None,
) -> tuple[list[dict[str, Any]] | None, float | None]:
    """Parse a run's ``step_logs`` JSON into a phase summary + total elapsed time.

    Shared by the latest-run merge and the per-run (issue-local-016) bulk pass
    in ``list_hunt_packages`` below — same projection either way.
    """
    import json as _json

    phases: list[dict[str, Any]] = []
    total_elapsed: float = 0.0
    try:
        step_logs: list[dict[str, Any]] = _json.loads(step_logs_json or "[]")
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
    return (phases if phases else None), (round(total_elapsed, 2) if phases else None)


def _parse_deep_retrohunt_counts(
    deep_retrohunt_json: str | None,
) -> tuple[int | None, int | None]:
    """Parse a run's ``deep_retrohunt`` JSON blob into (sanitized_count,
    removed_count) — the post-action-filter kept/removed split of
    ``sanitized_iocs`` (issue-local-017: shown alongside each run's model in
    the compact all-runs status table). Counted directly from each item's
    ``action`` rather than trusting the blob's own ``total_ioc_count`` field,
    so this stays correct even if that field is ever stale.
    """
    import json as _json

    try:
        retro: dict[str, Any] = _json.loads(deep_retrohunt_json or "")
        sanitized_iocs: list[dict[str, Any]] = retro.get("sanitized_iocs") or []
    except Exception:  # noqa: BLE001
        return None, None
    if not sanitized_iocs:
        return None, None
    removed = sum(1 for s in sanitized_iocs if s.get("action") == "remove")
    return len(sanitized_iocs) - removed, removed


def _escape_like(term: str) -> str:
    """Escape LIKE wildcards (%, _) and the escape char itself in *term*,
    so search input containing them is matched literally, not as a pattern.
    Pair with ``LIKE ? ESCAPE '\\'`` in the SQL."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def list_hunt_packages(
    *,
    search: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    """List all non-archived hunt packages with evidence counts and latest run summary.

    issue-006-D: each package dict gains three optional keys:
      - ``phases``         list[{step, status, elapsed_s}] from latest run's step_logs
      - ``total_elapsed_s`` sum of elapsed_s across all completed steps (float|None)
      - ``generation_status`` generation_status of the latest run (str|None)

    issue-local-016: also gains ``runs`` (every generation run for this
    package, newest first, each carrying its own ``phases``/
    ``total_elapsed_s`` — not just the latest one) and ``run_count``, so the
    list view can show per-run state (e.g. a compact status chip per run)
    without an N+1 fetch per package.

    issue-local-020: optional ``search`` (deep search — matches package
    name/description as well as this package's runs' stored
    threat_context/hypotheses/ttp_analysis/deep_retrohunt JSON and its
    extracted IOCs) and ``date_from``/``date_to`` (inclusive bounds on
    ``hunt_packages.created_at``, ISO-8601 strings — compare correctly as
    plain text). All filtering happens in the base query; everything below
    it already keys off the resulting ``pkg_ids``, so it cascades for free.
    """
    where_clauses = ["hp.status != 'archived'"]
    params: list[Any] = []
    if date_from:
        where_clauses.append("hp.created_at >= ?")
        params.append(date_from)
    if date_to:
        where_clauses.append("hp.created_at <= ?")
        params.append(date_to)
    if search:
        like_term = f"%{_escape_like(search)}%"
        where_clauses.append(
            "("
            "hp.name LIKE ? ESCAPE '\\' OR hp.description LIKE ? ESCAPE '\\' "
            "OR EXISTS (SELECT 1 FROM hunting_packages r WHERE r.hunt_package_id = hp.id "
            "AND (r.threat_context LIKE ? ESCAPE '\\' OR r.hypotheses LIKE ? ESCAPE '\\' "
            "OR r.ttp_analysis LIKE ? ESCAPE '\\' OR r.deep_retrohunt LIKE ? ESCAPE '\\')) "
            "OR EXISTS (SELECT 1 FROM extracted_iocs x WHERE x.hunt_package_id = hp.id "
            "AND x.ioc LIKE ? ESCAPE '\\')"
            ")"
        )
        params.extend([like_term] * 7)

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        # Base query: packages + evidence count, filtered by search/date range
        cur = await db.execute(
            "SELECT hp.*, COUNT(ei.id) AS evidence_count "
            "FROM hunt_packages hp "
            "LEFT JOIN evidence_items ei ON ei.hunt_package_id = hp.id "
            f"WHERE {' AND '.join(where_clauses)} "  # noqa: S608
            "GROUP BY hp.id ORDER BY hp.created_at DESC",
            params,
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

        # issue-local-016: EVERY run for these packages (not just the
        # latest), for the list view's per-run chip row. One bulk query for
        # the whole list, not per-package.
        pkg_ids = tuple(row["id"] for row in rows)
        all_run_rows: list[Any] = []
        report_run_ids: set[str] = set()
        if pkg_ids:
            placeholders = ",".join("?" for _ in pkg_ids)
            cur3 = await db.execute(
                "SELECT id, hunt_package_id, generation_status, llm_provider, llm_model, "
                "       research_effort, created_at, step_logs, deep_retrohunt, run_seq, "
                "       created_by "
                f"FROM hunting_packages WHERE hunt_package_id IN ({placeholders}) "
                "ORDER BY hunt_package_id, created_at DESC",
                pkg_ids,
            )
            all_run_rows = await cur3.fetchall()
            await cur3.close()

            # issue-local-017: which of these runs already have a generated
            # report — for the Table density view's report-download links.
            run_ids = tuple(r["id"] for r in all_run_rows)
            if run_ids:
                run_placeholders = ",".join("?" for _ in run_ids)
                cur4 = await db.execute(
                    f"SELECT DISTINCT run_id FROM hunt_reports WHERE run_id IN ({run_placeholders})",
                    run_ids,
                )
                report_run_ids = {r[0] for r in await cur4.fetchall()}
                await cur4.close()

    # Build lookup: hunt_package_id → {generation_status, step_logs_json, run_created_at}
    run_by_pkg: dict[str, dict[str, Any]] = {}
    for r in run_rows:
        run_by_pkg[r[0]] = {
            "generation_status": r[1],
            "step_logs_json": r[2],
            "run_created_at": r[3],
        }

    # issue-local-018: HuntID per package, needed up front so each of its
    # runs' Run ID (derived from the owning package's HuntID) can be
    # computed while building runs_by_pkg below.
    prefix = load_hunt_id_prefix()
    hunt_id_by_pkg: dict[str, str] = {
        row["id"]: format_hunt_id(prefix, row["hunt_seq"]) for row in rows
    }

    # Build lookup: hunt_package_id → [run summary dicts, newest first]
    runs_by_pkg: dict[str, list[dict[str, Any]]] = {}
    for r in all_run_rows:
        phases, total_elapsed_s = _parse_step_logs(r["step_logs"])
        sanitized_count, removed_count = _parse_deep_retrohunt_counts(r["deep_retrohunt"])
        runs_by_pkg.setdefault(r["hunt_package_id"], []).append(
            {
                "id": r["id"],
                "hunt_package_id": r["hunt_package_id"],
                "generation_status": r["generation_status"],
                "llm_provider": r["llm_provider"],
                "llm_model": r["llm_model"],
                "research_effort": r["research_effort"],
                "created_at": r["created_at"],
                "phases": phases,
                "total_elapsed_s": total_elapsed_s,
                "sanitized_ioc_count": sanitized_count,
                "removed_ioc_count": removed_count,
                "has_report": r["id"] in report_run_ids,
                "run_id_display": format_run_id(
                    hunt_id_by_pkg.get(r["hunt_package_id"], ""), r["run_seq"]
                ),
                "created_by": r["created_by"],
            }
        )

    result: list[dict[str, Any]] = []
    for row in rows:
        pkg = dict(row)
        run = run_by_pkg.get(pkg["id"])
        if run:
            pkg["generation_status"] = run["generation_status"]
            phases, total_elapsed_s = _parse_step_logs(run["step_logs_json"])
            pkg["phases"] = phases
            pkg["total_elapsed_s"] = total_elapsed_s
            pkg["run_created_at"] = run.get("run_created_at")  # issue-008-2A: live timer
        else:
            pkg["generation_status"] = None
            pkg["phases"] = None
            pkg["total_elapsed_s"] = None
            pkg["run_created_at"] = None
        pkg["runs"] = runs_by_pkg.get(pkg["id"], [])
        pkg["run_count"] = len(pkg["runs"])
        pkg["hunt_id_display"] = hunt_id_by_pkg.get(pkg["id"], "")
        result.append(pkg)
    return result


def _matching_pkg_where(
    *, search: str | None, date_from: str | None, date_to: str | None
) -> tuple[str, list[Any]]:
    """Build the WHERE clause + params for "which non-archived hunt packages
    match this search/date-range filter" — the same deep-search and
    date-bound rules as ``list_hunt_packages``, shared by
    ``get_hunt_dashboard_stats`` and ``list_explorer_rows`` so the two always
    agree on what counts as "matching"."""
    where_clauses = ["hp.status != 'archived'"]
    params: list[Any] = []
    if date_from:
        where_clauses.append("hp.created_at >= ?")
        params.append(date_from)
    if date_to:
        where_clauses.append("hp.created_at <= ?")
        params.append(date_to)
    if search:
        like_term = f"%{_escape_like(search)}%"
        where_clauses.append(
            "("
            "hp.name LIKE ? ESCAPE '\\' OR hp.description LIKE ? ESCAPE '\\' "
            "OR EXISTS (SELECT 1 FROM hunting_packages r WHERE r.hunt_package_id = hp.id "
            "AND (r.threat_context LIKE ? ESCAPE '\\' OR r.hypotheses LIKE ? ESCAPE '\\' "
            "OR r.ttp_analysis LIKE ? ESCAPE '\\' OR r.deep_retrohunt LIKE ? ESCAPE '\\')) "
            "OR EXISTS (SELECT 1 FROM extracted_iocs x WHERE x.hunt_package_id = hp.id "
            "AND x.ioc LIKE ? ESCAPE '\\')"
            ")"
        )
        params.extend([like_term] * 7)
    return " AND ".join(where_clauses), params


async def _matching_pkg_rows(
    db: aiosqlite.Connection,
    *,
    search: str | None,
    date_from: str | None,
    date_to: str | None,
) -> list[aiosqlite.Row]:
    where_sql, params = _matching_pkg_where(search=search, date_from=date_from, date_to=date_to)
    cur = await db.execute(
        "SELECT hp.id, hp.status, hp.name, hp.hunt_seq, hp.created_at "
        f"FROM hunt_packages hp WHERE {where_sql}",  # noqa: S608
        params,
    )
    rows = await cur.fetchall()
    await cur.close()
    return rows


async def get_hunt_dashboard_stats(
    *,
    search: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, Any]:
    """Aggregate counts for the Threat Hunting Dashboard (issue-local-032).

    *search*/*date_from*/*date_to* filter which hunt packages count toward
    every hunt-scoped figure below (packages, runs, evidence, hypotheses,
    hunting leads, queries, extracted IOCs, SIEM execution activity) —
    exactly the same matching rules as ``list_hunt_packages``'s deep search
    and date-range filter, so the numbers here always describe the same set
    a user would see by applying the same filter to the package list.

    ``hunts_per_day``/``iocs_per_day`` (issue-local-034) are the same
    matching rows bucketed by ``created_at`` day (``[{"date": "YYYY-MM-DD",
    "count": N}]``, sorted ascending) for the Dashboard's two timeline
    charts — no fixed window is applied, so a narrow date range yields a
    short series and no filter yields the whole history.

    The Threat Intel summary (threat actors / campaigns / malware families /
    TTPs / feed sources) is deliberately NOT filtered by search/date — it is
    a cross-hunt aggregate keyed by deduplicated entity name, the same
    global-scope convention already used by the Threat Intel Tracking
    dashboard (``get_tracking_dashboard`` in routes_threat_hunting.py), not a
    per-package figure a date range could meaningfully narrow.
    """
    import json as _json

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        pkg_rows = await _matching_pkg_rows(db, search=search, date_from=date_from, date_to=date_to)
        pkg_ids = tuple(r["id"] for r in pkg_rows)

        packages_by_status: dict[str, int] = {}
        hunts_per_day: dict[str, int] = {}
        for r in pkg_rows:
            packages_by_status[r["status"]] = packages_by_status.get(r["status"], 0) + 1
            day = (r["created_at"] or "")[:10]
            if day:
                hunts_per_day[day] = hunts_per_day.get(day, 0) + 1

        stats: dict[str, Any] = {
            "packages_total": len(pkg_ids),
            "packages_by_status": packages_by_status,
            "hunts_per_day": [{"date": d, "count": c} for d, c in sorted(hunts_per_day.items())],
            "runs_total": 0,
            "runs_by_model": {},
            "hunts_by_model": {},
            "evidence_total": 0,
            "evidence_by_type": {},
            "hypotheses_total": 0,
            "hunting_leads_total": 0,
            "queries_total": 0,
            "iocs_extracted_total": 0,
            "iocs_kept_total": 0,
            "iocs_per_day": [],
            "siem_searches_total": 0,
            "siem_searches_completed": 0,
            "siem_events_total": 0,
        }

        if not pkg_ids:
            return await _add_global_threat_intel_summary(stats)

        placeholders = ",".join("?" for _ in pkg_ids)

        # ── Runs (hunting_packages) — model breakdown + per-run JSON counts ──
        cur = await db.execute(
            "SELECT hunt_package_id, llm_model, hypotheses, hunting_leads, "
            "       query_drafts, step_logs "
            f"FROM hunting_packages WHERE hunt_package_id IN ({placeholders})",
            pkg_ids,
        )
        run_rows = await cur.fetchall()
        await cur.close()

        hunts_by_model: dict[str, set[str]] = {}
        for r in run_rows:
            model = r["llm_model"] or "unknown"
            stats["runs_by_model"][model] = stats["runs_by_model"].get(model, 0) + 1
            hunts_by_model.setdefault(model, set()).add(r["hunt_package_id"])
            for field, key in (
                ("hypotheses", "hypotheses_total"),
                ("hunting_leads", "hunting_leads_total"),
                ("query_drafts", "queries_total"),
            ):
                try:
                    items = _json.loads(r[field] or "[]")
                except Exception:  # noqa: BLE001
                    items = []
                stats[key] += len(items) if isinstance(items, list) else 0

            phases, _elapsed = _parse_step_logs(r["step_logs"])
            for phase in phases or []:
                if phase.get("step") == "siem_fetch" and phase.get("item_count") is not None:
                    stats["siem_events_total"] += int(phase["item_count"])

        stats["runs_total"] = len(run_rows)
        stats["hunts_by_model"] = {m: len(ids) for m, ids in hunts_by_model.items()}

        # ── Evidence, by type ────────────────────────────────────────────────
        cur = await db.execute(
            "SELECT item_type, COUNT(*) AS n FROM evidence_items "
            f"WHERE hunt_package_id IN ({placeholders}) GROUP BY item_type",
            pkg_ids,
        )
        for r in await cur.fetchall():
            stats["evidence_by_type"][r["item_type"]] = r["n"]
            stats["evidence_total"] += r["n"]
        await cur.close()

        # ── Extracted IOCs ───────────────────────────────────────────────────
        cur = await db.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN action = 'remove' THEN 1 ELSE 0 END) AS removed "
            f"FROM extracted_iocs WHERE hunt_package_id IN ({placeholders})",
            pkg_ids,
        )
        row = await cur.fetchone()
        await cur.close()
        total_iocs = row["total"] or 0
        removed_iocs = row["removed"] or 0
        stats["iocs_extracted_total"] = total_iocs
        stats["iocs_kept_total"] = total_iocs - removed_iocs

        cur = await db.execute(
            "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS n "
            f"FROM extracted_iocs WHERE hunt_package_id IN ({placeholders}) "
            "GROUP BY day ORDER BY day",
            pkg_ids,
        )
        stats["iocs_per_day"] = [
            {"date": r["day"], "count": r["n"]} for r in await cur.fetchall() if r["day"]
        ]
        await cur.close()

        # ── SIEM execution activity (task_results) ──────────────────────────
        cur = await db.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed "
            f"FROM task_results WHERE hunt_package_id IN ({placeholders})",
            pkg_ids,
        )
        row = await cur.fetchone()
        await cur.close()
        stats["siem_searches_total"] = row["total"] or 0
        stats["siem_searches_completed"] = row["completed"] or 0

    return await _add_global_threat_intel_summary(stats)


async def _add_global_threat_intel_summary(stats: dict[str, Any]) -> dict[str, Any]:
    """Attach the cross-hunt Threat Intel summary (global, unfiltered) to a
    dashboard stats dict. Split out so the empty-``pkg_ids`` early return in
    ``get_hunt_dashboard_stats`` still gets this section rather than omitting
    it entirely."""
    from backend.db.manager import get_summary

    stats["threat_actors_total"] = len(await aggregate_threat_actors())
    stats["campaigns_total"] = len(await aggregate_campaigns())
    stats["malware_families_total"] = len(await aggregate_malware_families())
    stats["ttps_total"] = len(await aggregate_ttps())
    stats["sources_processed"] = sum(
        1 for row in await get_summary() if row.get("source") != "__total__"
    )
    return stats


#: Valid Data Explorer category ids (issue-local-033) — one per Dashboard
#: panel/stat card. "hunts" and "runs" also back the Dashboard's
#: packages-by-status and runs/hunts-by-model breakdown panels respectively;
#: "siem_searches" also backs the events-retrieved stat (a search IS where
#: those events came from, so there is no separate row-level "events" list).
EXPLORER_CATEGORIES = frozenset(
    {
        "hunts",
        "runs",
        "evidence",
        "hypotheses",
        "hunting_leads",
        "queries",
        "iocs",
        "siem_searches",
        "threat_actors",
        "campaigns",
        "malware_families",
        "ttps",
        "feed_sources",
    }
)

_EXPLORER_GLOBAL_CATEGORIES = frozenset(
    {"threat_actors", "campaigns", "malware_families", "ttps", "feed_sources"}
)


async def list_explorer_rows(
    category: str,
    *,
    search: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    """Row-level data backing one Dashboard panel/stat card, for the Data
    Explorer (issue-local-033).

    Hunt-scoped categories (hunts/runs/evidence/hypotheses/hunting_leads/
    queries/iocs/siem_searches) are filtered by the same search/date-range
    rules ``get_hunt_dashboard_stats`` uses — the row set here always backs
    the same numbers that function reports for the same filter.

    The five Threat Intel categories are global aggregates (see that
    function's docstring for why) — *date_from*/*date_to* are ignored for
    them, and *search* instead matches the entity's own name/title.
    """
    import json as _json

    if category not in EXPLORER_CATEGORIES:
        raise ValueError(f"unknown Data Explorer category: {category!r}")

    if category in _EXPLORER_GLOBAL_CATEGORIES:
        return await _global_explorer_rows(category, search=search)

    prefix = load_hunt_id_prefix()

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        pkg_rows = await _matching_pkg_rows(db, search=search, date_from=date_from, date_to=date_to)
        pkg_ids = tuple(r["id"] for r in pkg_rows)
        if not pkg_ids:
            return []
        placeholders = ",".join("?" for _ in pkg_ids)
        hunt_id_by_pkg = {r["id"]: format_hunt_id(prefix, r["hunt_seq"]) for r in pkg_rows}
        name_by_pkg = {r["id"]: r["name"] for r in pkg_rows}

        if category == "hunts":
            return [
                {
                    "id": r["id"],
                    "hunt_id_display": hunt_id_by_pkg.get(r["id"], ""),
                    "name": r["name"],
                    "status": r["status"],
                }
                for r in pkg_rows
            ]

        if category == "runs":
            cur = await db.execute(
                "SELECT id, hunt_package_id, llm_model, generation_status, research_effort, "
                "       run_seq, created_at "
                f"FROM hunting_packages WHERE hunt_package_id IN ({placeholders}) "
                "ORDER BY created_at DESC",
                pkg_ids,
            )
            rows = await cur.fetchall()
            await cur.close()
            out = []
            for r in rows:
                hunt_id = hunt_id_by_pkg.get(r["hunt_package_id"], "")
                out.append(
                    {
                        "id": r["id"],
                        "hunt_package_id": r["hunt_package_id"],
                        "hunt_id_display": hunt_id,
                        "run_id_display": format_run_id(hunt_id, r["run_seq"]),
                        "hunt_name": name_by_pkg.get(r["hunt_package_id"], ""),
                        "llm_model": r["llm_model"] or "unknown",
                        "generation_status": r["generation_status"],
                        "research_effort": r["research_effort"],
                        "created_at": r["created_at"],
                    }
                )
            return out

        if category == "evidence":
            cur = await db.execute(
                "SELECT id, hunt_package_id, item_type, label, source_ref, created_at "
                f"FROM evidence_items WHERE hunt_package_id IN ({placeholders}) "
                "ORDER BY created_at DESC",
                pkg_ids,
            )
            rows = await cur.fetchall()
            await cur.close()
            return [
                {
                    "id": r["id"],
                    "hunt_package_id": r["hunt_package_id"],
                    "hunt_id_display": hunt_id_by_pkg.get(r["hunt_package_id"], ""),
                    "hunt_name": name_by_pkg.get(r["hunt_package_id"], ""),
                    "item_type": r["item_type"],
                    "label": r["label"] or r["source_ref"] or "",
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

        if category == "iocs":
            cur = await db.execute(
                "SELECT id, hunt_package_id, ioc, ioc_type, action, noise_score, created_at "
                f"FROM extracted_iocs WHERE hunt_package_id IN ({placeholders}) "
                "ORDER BY created_at DESC",
                pkg_ids,
            )
            rows = await cur.fetchall()
            await cur.close()
            return [
                {
                    "id": r["id"],
                    "hunt_package_id": r["hunt_package_id"],
                    "hunt_id_display": hunt_id_by_pkg.get(r["hunt_package_id"], ""),
                    "hunt_name": name_by_pkg.get(r["hunt_package_id"], ""),
                    "ioc": r["ioc"],
                    "ioc_type": r["ioc_type"],
                    "action": r["action"],
                    "noise_score": r["noise_score"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

        if category == "siem_searches":
            cur = await db.execute(
                "SELECT id, hunt_package_id, task_type, siem_connector, status, query_text, "
                "       created_at, completed_at "
                f"FROM task_results WHERE hunt_package_id IN ({placeholders}) "
                "ORDER BY created_at DESC",
                pkg_ids,
            )
            rows = await cur.fetchall()
            await cur.close()
            return [
                {
                    "id": r["id"],
                    "hunt_package_id": r["hunt_package_id"],
                    "hunt_id_display": hunt_id_by_pkg.get(r["hunt_package_id"], ""),
                    "hunt_name": name_by_pkg.get(r["hunt_package_id"], ""),
                    "task_type": r["task_type"],
                    "siem_connector": r["siem_connector"],
                    "status": r["status"],
                    "query_text": r["query_text"],
                    "created_at": r["created_at"],
                    "completed_at": r["completed_at"],
                }
                for r in rows
            ]

        # hypotheses / hunting_leads / queries — flattened out of each
        # matching run's JSON blob.
        field_by_category = {
            "hypotheses": "hypotheses",
            "hunting_leads": "hunting_leads",
            "queries": "query_drafts",
        }
        json_field = field_by_category[category]
        cur = await db.execute(
            f"SELECT hunt_package_id, run_seq, created_at, {json_field} "  # noqa: S608
            f"FROM hunting_packages WHERE hunt_package_id IN ({placeholders}) "
            "ORDER BY created_at DESC",
            pkg_ids,
        )
        rows = await cur.fetchall()
        await cur.close()
        out = []
        for r in rows:
            try:
                items = _json.loads(r[json_field] or "[]")
            except Exception:  # noqa: BLE001
                items = []
            if not isinstance(items, list):
                continue
            hunt_id = hunt_id_by_pkg.get(r["hunt_package_id"], "")
            for item in items:
                if not isinstance(item, dict):
                    continue
                row = {
                    "id": item.get("id", ""),
                    "hunt_package_id": r["hunt_package_id"],
                    "hunt_id_display": hunt_id,
                    "run_id_display": format_run_id(hunt_id, r["run_seq"]),
                    "hunt_name": name_by_pkg.get(r["hunt_package_id"], ""),
                    "title": item.get("title", ""),
                    "created_at": r["created_at"],
                    "discarded": bool(item.get("discarded")),
                }
                if category == "hypotheses":
                    row["relevance"] = item.get("relevance")
                    row["confidence"] = item.get("confidence")
                elif category == "hunting_leads":
                    row["priority"] = item.get("priority")
                elif category == "queries":
                    row["language"] = item.get("language")
                    row["query"] = item.get("query")
                out.append(row)
        return out


async def _global_explorer_rows(category: str, *, search: str | None) -> list[dict[str, Any]]:
    """Row-level data for a Threat Intel Data Explorer category — thin
    wrappers over the same cross-hunt aggregates the Tracking dashboard
    uses, filtered by a plain name substring match rather than the
    hunt-package search rules (there is no single owning hunt package to
    match against — these are deduped entities that can span many)."""

    def _matches(value: str) -> bool:
        return not search or search.lower() in (value or "").lower()

    if category == "threat_actors":
        return [r for r in await aggregate_threat_actors() if _matches(r["name"])]
    if category == "campaigns":
        return [r for r in await aggregate_campaigns() if _matches(r["name"])]
    if category == "malware_families":
        return [r for r in await aggregate_malware_families() if _matches(r["name"])]
    if category == "ttps":
        return [
            r
            for r in await aggregate_ttps()
            if _matches(r["technique_name"]) or _matches(r["technique_id"])
        ]
    if category == "feed_sources":
        from backend.db.manager import get_summary

        return [
            {"source": row.get("source"), "count": row.get("count", 0)}
            for row in await get_summary()
            if row.get("source") != "__total__" and _matches(str(row.get("source") or ""))
        ]
    raise ValueError(f"unknown global Data Explorer category: {category!r}")  # pragma: no cover


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
    *,
    run_id: str | None = None,
) -> None:
    now = _utc_now_iso()
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        for ioc in iocs:
            await db.execute(
                """
                INSERT OR IGNORE INTO extracted_iocs
                  (id, evidence_item_id, hunt_package_id, run_id, ioc, ioc_type,
                   ioc_description, noise_score, flagged_noisy, action, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    _new_id(),
                    evidence_item_id,
                    hunt_package_id,
                    run_id,
                    ioc.get("ioc", ""),
                    ioc.get("ioc_type", "other"),
                    ioc.get("ioc_description", ""),
                    float(ioc.get("noise_score", 0.0)),
                    1 if ioc.get("flagged_noisy") else 0,
                    ioc.get("action", "keep"),
                    now,
                ),
            )
        await db.commit()


async def clear_extracted_iocs(hunt_package_id: str, run_id: str | None = None) -> int:
    """Delete extracted IOCs for *hunt_package_id*, scoped to *run_id* when given.

    issue-008-2B: called by intake_classifier at the start of each pipeline
    run to ensure re-runs produce a fresh, non-duplicated IOC set.

    issue-local-015: scoped to (hunt_package_id, run_id) rather than the
    whole package — run_id is a fresh UUID per run, so this now guards
    against double-processing within the SAME run instead of wiping every
    prior run's IOCs, which is what made each run's IOC set independent.
    When run_id is omitted, falls back to the pre-015 whole-package delete
    (used only by legacy/back-compat callers).

    Returns the number of rows deleted.
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        if run_id is not None:
            cur = await db.execute(
                "DELETE FROM extracted_iocs WHERE hunt_package_id = ? AND run_id = ?",
                (hunt_package_id, run_id),
            )
        else:
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


async def update_ioc_actions(run_id: str, updates: list[tuple[str, str, str]]) -> None:
    """Bulk-update the ``action`` column for extracted IOC rows in one run.

    issue-local-015: called once after intake_classifier finishes noise
    scoring/triage, to persist each IOC's final keep/remove decision so the
    IOC table can show it. *updates* is a list of (ioc, ioc_type, action)
    tuples, matched against the existing (run_id, ioc, ioc_type) row.

    issue-local-016: also called directly from the manual-verdict-override
    route (routes_threat_hunting.update_ioc_verdicts) — the same helper,
    the only difference is who's calling it (the pipeline vs. an analyst).
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        for ioc, ioc_type, action in updates:
            await db.execute(
                "UPDATE extracted_iocs SET action = ? "
                "WHERE run_id = ? AND ioc = ? AND ioc_type = ?",
                (action, run_id, ioc, ioc_type),
            )
        await db.commit()


async def update_deep_retrohunt_ioc_actions(
    run_id: str, updates: list[tuple[str, str, str]]
) -> dict[str, Any] | None:
    """Apply manual keep/remove verdict overrides to a run's stored
    ``deep_retrohunt`` lead (issue-local-016).

    ``sanitized_iocs`` entries (unlike ``extracted_iocs`` rows) have no
    independent id — they're matched by ``(ioc, ioc_type)``, same as
    ``update_ioc_actions`` above. Same load/find/mutate/write-back-whole-
    column pattern as ``set_hypothesis_discarded``, but this also recomputes
    the lead's derived summary fields (``ioc_csv``, ``total_ioc_count``,
    ``noisy_ioc_count``, ``high_noise_ioc_count``) from the updated kept set
    — cheap and deterministic, so a manual verdict change doesn't leave the
    CSV/counts stale without re-running the whole node (which would also
    needlessly re-call the LLM enrichment half of it).

    Returns the updated ``deep_retrohunt`` dict, or None if the run has no
    stored deep_retrohunt lead yet (e.g. the run never extracted any atomic
    IOCs) — callers should treat that as "nothing to update here", not an
    error, since the extracted_iocs half (``update_ioc_actions``) is
    independent and still applies.
    """
    import json as _json

    from backend.threat_hunting.agents.nodes.deep_retrohunt_planner import _build_ioc_csv
    from backend.threat_hunting.iocs import HIGH_NOISE_THRESHOLD, NOISE_THRESHOLD

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT deep_retrohunt FROM hunting_packages WHERE id = ?", (run_id,)
        )
        row = await cur.fetchone()
        await cur.close()
        if not row or not row[0]:
            return None

        try:
            retro: dict[str, Any] = _json.loads(row[0])
            sanitized: list[dict[str, Any]] = retro.get("sanitized_iocs") or []
        except Exception:
            return None
        if not sanitized:
            return None

        update_by_key = {(ioc, ioc_type): action for ioc, ioc_type, action in updates}
        for entry in sanitized:
            key = (entry.get("ioc"), entry.get("ioc_type"))
            if key in update_by_key:
                entry["action"] = update_by_key[key]

        kept = [s for s in sanitized if s.get("action") != "remove"]
        retro["sanitized_iocs"] = sanitized
        retro["ioc_csv"] = _build_ioc_csv(kept)  # type: ignore[arg-type]
        retro["total_ioc_count"] = len(kept)
        retro["noisy_ioc_count"] = sum(1 for s in kept if s["noise_score"] >= NOISE_THRESHOLD)
        retro["high_noise_ioc_count"] = sum(
            1 for s in kept if s["noise_score"] >= HIGH_NOISE_THRESHOLD
        )

        await db.execute(
            "UPDATE hunting_packages SET deep_retrohunt = ? WHERE id = ?",
            (_json.dumps(retro, ensure_ascii=False, default=str), run_id),
        )
        await db.commit()
        return retro


async def list_extracted_iocs(
    hunt_package_id: str, run_id: str | None = None
) -> list[dict[str, Any]]:
    """List extracted IOCs for a package, optionally scoped to one run.

    issue-local-015: pass *run_id* to see exactly that run's IOC set (the
    normal, run-independent path). Omitting it returns every row across all
    runs for the package — kept for back-compat call sites, not used by the
    per-run API route.
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if run_id is not None:
            cur = await db.execute(
                "SELECT * FROM extracted_iocs WHERE hunt_package_id = ? AND run_id = ? "
                "ORDER BY ioc_type, ioc",
                (hunt_package_id, run_id),
            )
        else:
            cur = await db.execute(
                "SELECT * FROM extracted_iocs WHERE hunt_package_id = ? ORDER BY ioc_type, ioc",
                (hunt_package_id,),
            )
        rows = await cur.fetchall()
        await cur.close()
    # issue-local-026 follow-up: defense-in-depth dedup on top of the
    # extracted_iocs unique index (schema v11) — belt-and-suspenders so a
    # pre-migration DB, or any future insert path that bypasses
    # add_extracted_iocs, still can't surface the same IOC twice in a single
    # run's list. Keyed by (ioc_type, ioc, run_id) so the run_id=None
    # "every run for this package" path still shows one row per run, not
    # one row total collapsed across the package's whole history.
    seen: set[tuple[str, str, str | None]] = set()
    deduped: list[dict[str, Any]] = []
    for r in rows:
        row = dict(r)
        key = (row.get("ioc_type", ""), row.get("ioc", ""), row.get("run_id"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


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
        "run_config",
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

    Returns lightweight summaries (id, hunt_package_id, generation_status,
    llm_provider, llm_model, research_effort, created_at) plus, per run
    (issue-local-017, needed for HuntDetail's compact all-runs status
    table — no separate per-run fetch required):
      - ``phases``/``total_elapsed_s``, via the same ``_parse_step_logs``
        helper ``list_hunt_packages`` uses.
      - ``sanitized_ioc_count``/``removed_ioc_count``, via
        ``_parse_deep_retrohunt_counts``.
      - ``has_report``, whether a hunt_reports row exists for this run.
      - ``run_id_display`` (issue-local-018), e.g. "TH01-X02".
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT hunt_seq FROM hunt_packages WHERE id = ?", (hunt_package_id,)
        )
        pkg_row = await cur.fetchone()
        await cur.close()

        cur = await db.execute(
            """SELECT id, hunt_package_id, generation_status,
                      llm_provider, llm_model, research_effort, created_at,
                      step_logs, deep_retrohunt, run_seq, threat_intel_status, created_by
               FROM hunting_packages
               WHERE hunt_package_id = ?
               ORDER BY created_at DESC""",
            (hunt_package_id,),
        )
        rows = await cur.fetchall()
        await cur.close()

        run_ids = tuple(row["id"] for row in rows)
        report_run_ids: set[str] = set()
        if run_ids:
            placeholders = ",".join("?" for _ in run_ids)
            cur2 = await db.execute(
                f"SELECT DISTINCT run_id FROM hunt_reports WHERE run_id IN ({placeholders})",
                run_ids,
            )
            report_run_ids = {r[0] for r in await cur2.fetchall()}
            await cur2.close()

    hunt_id_display = format_hunt_id(
        load_hunt_id_prefix(), pkg_row["hunt_seq"] if pkg_row else None
    )

    result: list[dict[str, Any]] = []
    for row in rows:
        run = dict(row)
        step_logs_json = run.pop("step_logs")
        deep_retrohunt_json = run.pop("deep_retrohunt")
        run_seq = run.pop("run_seq")
        phases, total_elapsed_s = _parse_step_logs(step_logs_json)
        sanitized_count, removed_count = _parse_deep_retrohunt_counts(deep_retrohunt_json)
        run["phases"] = phases
        run["total_elapsed_s"] = total_elapsed_s
        run["sanitized_ioc_count"] = sanitized_count
        run["removed_ioc_count"] = removed_count
        run["has_report"] = run["id"] in report_run_ids
        run["run_id_display"] = format_run_id(hunt_id_display, run_seq)
        result.append(run)
    return result


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
    """Return the latest NORMAL (non-comparison) report for a hunt package.

    issue-local-020: comparison reports (full_report.report_kind ==
    "comparison") share the hunt_reports table but must never surface here —
    every existing caller of this function expects a single-run/package
    report, so a comparison row (run_id=NULL, same as older pre-run-scoping
    package-level reports) would otherwise silently shadow the real one.
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM hunt_reports WHERE hunt_package_id = ? ORDER BY created_at DESC",
            (hunt_package_id,),
        )
        rows = await cur.fetchall()
        await cur.close()
    for row in rows:
        decoded = _decode_report_row(dict(row))
        full_report = decoded.get("full_report")
        if isinstance(full_report, dict) and full_report.get("report_kind") == "comparison":
            continue
        return decoded
    return None


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


# ── Comparison reports (issue-local-020) ─────────────────────────────────────
# Reuses hunt_reports as-is rather than a new table: a comparison report is a
# hunt_reports row with run_id=NULL (it isn't scoped to one run) and a
# "report_kind": "comparison" discriminator inside full_report, alongside the
# compared run ids. get_hunt_report()/get_hunt_report_by_run() are unaffected
# since those either filter by a specific run_id (comparison rows have none)
# or return latest-by-hunt_package_id — see get_latest_comparison_report()'s
# own filtering below for why that one can't just reuse get_hunt_report().


async def create_comparison_report(
    hunt_package_id: str,
    *,
    executive_summary: str,
    full_report: dict[str, Any],
    created_by: str | None = None,
) -> dict[str, Any]:
    full_report = {**full_report, "report_kind": "comparison"}
    await create_hunt_report(
        hunt_package_id,
        executive_summary=executive_summary,
        full_report=full_report,
        created_by=created_by,
        run_id=None,
    )
    result = await get_latest_comparison_report(hunt_package_id)
    return result or {}


async def get_latest_comparison_report(hunt_package_id: str) -> dict[str, Any] | None:
    """Return the most recent comparison report for a package, ignoring
    normal (single-run or package-level) reports — both share the
    hunt_reports table, distinguished only by full_report.report_kind."""
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT * FROM hunt_reports
               WHERE hunt_package_id = ? AND run_id IS NULL
               ORDER BY created_at DESC""",
            (hunt_package_id,),
        )
        rows = await cur.fetchall()
        await cur.close()
    for row in rows:
        decoded = _decode_report_row(dict(row))
        full_report = decoded.get("full_report")
        if isinstance(full_report, dict) and full_report.get("report_kind") == "comparison":
            return decoded
    return None


# ── Threat Intelligence analysis (issue-local-020) ───────────────────────────
# Persists the Threat Hunt Intelligence Analyst's per-run output: threat
# actors, attribution, malware families, campaigns, related vendor
# reporting, and IOCs correlated against OTHER hunt packages.


async def create_threat_intel_analysis(
    hunt_package_id: str,
    *,
    run_id: str | None,
    threat_actors: list[dict[str, Any]],
    attribution: dict[str, Any] | None,
    malware_families: list[str],
    campaigns: list[dict[str, Any]],
    related_vendors: list[dict[str, Any]],
    correlated_iocs: list[dict[str, Any]],
    summary: str,
    full_analysis: dict[str, Any],
    created_by: str | None = None,
) -> dict[str, Any]:
    import json as _json

    analysis_id = _new_id()
    now = _utc_now_iso()

    def _j(val: Any) -> str:
        return _json.dumps(val, ensure_ascii=False, default=str)

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            """INSERT INTO threat_intel_analysis
               (id, hunt_package_id, run_id, threat_actors, attribution,
                malware_families, campaigns, related_vendors, correlated_iocs,
                summary, full_analysis, created_at, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                analysis_id,
                hunt_package_id,
                run_id,
                _j(threat_actors),
                _j(attribution),
                _j(malware_families),
                _j(campaigns),
                _j(related_vendors),
                _j(correlated_iocs),
                summary,
                _j(full_analysis),
                now,
                created_by,
            ),
        )
        await db.commit()
    return await get_threat_intel_analysis_by_run(run_id) if run_id else {}  # type: ignore[return-value]


def _decode_threat_intel_row(d: dict[str, Any]) -> dict[str, Any]:
    import json as _json

    for field in (
        "threat_actors",
        "attribution",
        "malware_families",
        "campaigns",
        "related_vendors",
        "correlated_iocs",
        "full_analysis",
    ):
        raw = d.get(field)
        if raw and isinstance(raw, str):
            try:
                d[field] = _json.loads(raw)
            except Exception:
                pass
    return d


async def get_threat_intel_analysis_by_run(run_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM threat_intel_analysis WHERE run_id = ? ORDER BY created_at DESC LIMIT 1",
            (run_id,),
        )
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    return _decode_threat_intel_row(dict(row))


async def get_latest_threat_intel_analysis(hunt_package_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM threat_intel_analysis WHERE hunt_package_id = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (hunt_package_id,),
        )
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    return _decode_threat_intel_row(dict(row))


async def find_cross_package_ioc_matches(
    hunt_package_id: str, iocs: list[str]
) -> list[dict[str, Any]]:
    """Find *iocs* (this package's kept IOC values) appearing in OTHER hunt
    packages' extracted_iocs rows. All packages share one DB file, so this
    is a plain scoped SELECT — no cross-database complexity.

    issue-local-026 follow-up: GROUP BY collapses to one row per
    (ioc, ioc_type, other package) — an IOC legitimately extracted across
    several runs of that OTHER package (each run is an independent
    extraction, so each can genuinely contain it) previously surfaced as
    one correlation row per run. The Threat Intelligence tab only ever
    displays ioc/ioc_type/hunt_name (never run_id), so those extra rows
    were pure visual duplicates, not distinct information.
    """
    unique_iocs = sorted({i for i in iocs if i})
    if not unique_iocs:
        return []
    placeholders = ",".join("?" for _ in unique_iocs)
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            f"""SELECT ei.ioc, ei.ioc_type, ei.hunt_package_id, MIN(ei.run_id) AS run_id,
                       hp.name AS hunt_name
                FROM extracted_iocs ei
                JOIN hunt_packages hp ON hp.id = ei.hunt_package_id
                WHERE ei.hunt_package_id != ? AND ei.action != 'remove'
                  AND ei.ioc IN ({placeholders})
                GROUP BY ei.ioc, ei.ioc_type, ei.hunt_package_id, hp.name
                ORDER BY ei.ioc_type, ei.ioc""",  # noqa: S608
            (hunt_package_id, *unique_iocs),
        )
        rows = await cur.fetchall()
        await cur.close()
    return [dict(row) for row in rows]


# ── Threat Intel Tracking dashboard (issue-local-021) ─────────────────────────
# Cross-hunt aggregations for the new "Threat Intel Tracking" sidebar
# subsection. All raw material already exists per-hunt (extracted_iocs,
# threat_intel_analysis, hunting_packages.ttp_analysis) — this is purely a
# read/aggregate layer, no new agent runs. Aggregation across hunts is done
# in Python (not SQL json_each), matching this module's existing convention
# (see find_cross_package_ioc_matches, list_hunt_packages's deep search).
# Every aggregation excludes archived and excluded_from_correlation packages.


async def set_hunt_correlation_excluded(hunt_package_id: str, excluded: bool) -> None:
    """Toggle a hunt package's exclusion from every cross-hunt aggregation
    below. Reversible — the hunt package and its data are untouched, just
    filtered out of Dashboard/Hunts-tab aggregation results."""
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            "UPDATE hunt_packages SET excluded_from_correlation = ? WHERE id = ?",
            (1 if excluded else 0, hunt_package_id),
        )
        await db.commit()


async def list_correlated_iocs(
    *, ioc_type: str | None = None, search: str | None = None, limit: int = 200
) -> list[dict[str, Any]]:
    """Aggregate extracted_iocs across all non-excluded, non-archived hunt
    packages, grouped by (ioc, ioc_type), with each group's source hunt
    packages attached (the "relationship of the source of the data" the
    dashboard spec asks for). Powers both the IOC panel and the CVE panel
    (``ioc_type="cve"`` — CVEs are already extracted as a normal IOC type,
    see iocs.py's ``_RE_CVE``) from one shared function.
    """
    where = [
        "ei.action != 'remove'",
        "hp.status != 'archived'",
        "hp.excluded_from_correlation = 0",
    ]
    params: list[Any] = []
    if ioc_type:
        where.append("ei.ioc_type = ?")
        params.append(ioc_type)
    if search:
        where.append("ei.ioc LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(search)}%")

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            f"""SELECT ei.ioc, ei.ioc_type, hp.id AS hunt_package_id, hp.name AS hunt_name,
                       hp.hunt_seq
                FROM extracted_iocs ei
                JOIN hunt_packages hp ON hp.id = ei.hunt_package_id
                WHERE {" AND ".join(where)}""",  # noqa: S608
            params,
        )
        rows = await cur.fetchall()
        await cur.close()

    prefix = load_hunt_id_prefix()
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["ioc"], row["ioc_type"])
        entry = grouped.setdefault(
            key, {"ioc": row["ioc"], "ioc_type": row["ioc_type"], "hunt_packages": {}}
        )
        entry["hunt_packages"][row["hunt_package_id"]] = {
            "id": row["hunt_package_id"],
            "name": row["hunt_name"],
            "hunt_id_display": format_hunt_id(prefix, row["hunt_seq"]),
        }

    result = [
        {
            "ioc": entry["ioc"],
            "ioc_type": entry["ioc_type"],
            "hunt_count": len(entry["hunt_packages"]),
            "hunt_packages": list(entry["hunt_packages"].values()),
        }
        for entry in grouped.values()
    ]
    result.sort(key=lambda r: (-r["hunt_count"], r["ioc"]))
    return result[:limit]


async def _latest_threat_intel_per_package() -> list[dict[str, Any]]:
    """Return the latest threat_intel_analysis row per non-excluded,
    non-archived hunt package — shared source for aggregate_threat_actors/
    campaigns/malware_families below (all three read from the same rows)."""
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT tia.*, hp.name AS hunt_name, hp.hunt_seq
               FROM threat_intel_analysis tia
               JOIN hunt_packages hp ON hp.id = tia.hunt_package_id
               WHERE hp.status != 'archived' AND hp.excluded_from_correlation = 0
               ORDER BY tia.hunt_package_id, tia.created_at DESC"""
        )
        rows = await cur.fetchall()
        await cur.close()

    prefix = load_hunt_id_prefix()
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        pkg_id = row["hunt_package_id"]
        if pkg_id in latest:
            continue  # rows are ORDER BY ... created_at DESC, so first wins
        decoded = _decode_threat_intel_row(dict(row))
        decoded["hunt_name"] = row["hunt_name"]
        decoded["hunt_id_display"] = format_hunt_id(prefix, row["hunt_seq"])
        latest[pkg_id] = decoded
    return list(latest.values())


def _dedupe_by_name(
    records: list[dict[str, Any]], field: str, extra_fields: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    """Shared dedupe helper for aggregate_threat_actors/campaigns/
    malware_families: items are dicts (or plain strings, for
    malware_families) with a "name", deduped case-insensitively, each
    accumulating the set of hunt packages it was seen in."""
    by_name: dict[str, dict[str, Any]] = {}
    for record in records:
        source = {
            "id": record["hunt_package_id"],
            "name": record["hunt_name"],
            "hunt_id_display": record["hunt_id_display"],
        }
        for item in record.get(field) or []:
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
            else:
                name = str(item or "").strip()
            if not name:
                continue
            key = name.lower()
            entry = by_name.setdefault(key, {"name": name, "sources": {}})
            if isinstance(item, dict):
                for extra in extra_fields:
                    if item.get(extra) and not entry.get(extra):
                        entry[extra] = item.get(extra)
            entry["sources"][source["id"]] = source
    out = [{**entry, "sources": list(entry["sources"].values())} for entry in by_name.values()]
    out.sort(key=lambda r: -len(r["sources"]))
    return out


async def aggregate_threat_actors() -> list[dict[str, Any]]:
    """Dedupe threat actors (by normalized name) across every hunt's latest
    Threat Intel analysis, attaching each actor's source hunt package(s)."""
    records = await _latest_threat_intel_per_package()
    return _dedupe_by_name(records, "threat_actors", extra_fields=("confidence", "rationale"))


async def aggregate_campaigns() -> list[dict[str, Any]]:
    """Dedupe campaigns (by normalized name) across every hunt's latest
    Threat Intel analysis, attaching each campaign's source hunt package(s)."""
    records = await _latest_threat_intel_per_package()
    return _dedupe_by_name(records, "campaigns", extra_fields=("description",))


async def aggregate_malware_families() -> list[dict[str, Any]]:
    """Dedupe malware families (by normalized name) across every hunt's
    latest Threat Intel analysis, attaching each family's source hunt
    package(s)."""
    records = await _latest_threat_intel_per_package()
    return _dedupe_by_name(records, "malware_families")


async def aggregate_ttps() -> list[dict[str, Any]]:
    """Dedupe MITRE ATT&CK techniques (by technique_id) across each hunt's
    latest run's ttp_analysis, attaching each technique's source hunt
    package(s)."""
    import json as _json

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT hpk.hunt_package_id, hpk.ttp_analysis, hp.name AS hunt_name, hp.hunt_seq
               FROM hunting_packages hpk
               JOIN hunt_packages hp ON hp.id = hpk.hunt_package_id
               WHERE hp.status != 'archived' AND hp.excluded_from_correlation = 0
               ORDER BY hpk.hunt_package_id, hpk.created_at DESC"""
        )
        rows = await cur.fetchall()
        await cur.close()

    prefix = load_hunt_id_prefix()
    seen_pkg: set[str] = set()
    by_technique: dict[str, dict[str, Any]] = {}
    for row in rows:
        pkg_id = row["hunt_package_id"]
        if pkg_id in seen_pkg:
            continue  # rows are ORDER BY ... created_at DESC, first = latest
        seen_pkg.add(pkg_id)
        raw = row["ttp_analysis"]
        if not raw:
            continue
        try:
            ttp = _json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            continue
        source = {
            "id": pkg_id,
            "name": row["hunt_name"],
            "hunt_id_display": format_hunt_id(prefix, row["hunt_seq"]),
        }
        for tech in (ttp or {}).get("techniques") or []:
            tid = str(tech.get("technique_id") or "").strip()
            if not tid:
                continue
            entry = by_technique.setdefault(
                tid,
                {
                    "technique_id": tid,
                    "technique_name": tech.get("technique_name") or "",
                    "tactic": tech.get("tactic") or "",
                    "sources": {},
                },
            )
            entry["sources"][source["id"]] = source

    out = [{**entry, "sources": list(entry["sources"].values())} for entry in by_technique.values()]
    out.sort(key=lambda r: -len(r["sources"]))
    return out


async def list_tracking_hunts() -> list[dict[str, Any]]:
    """List every non-archived hunt package with its correlation-inclusion
    state and a couple of summary counts, for the Threat Intel Tracking
    dashboard's Hunts tab (include/exclude/delete controls)."""
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT hp.id, hp.name, hp.hunt_seq, hp.status, hp.excluded_from_correlation,
                      COUNT(DISTINCT ei.id) AS ioc_count,
                      COUNT(DISTINCT tia.id) AS threat_intel_count
               FROM hunt_packages hp
               LEFT JOIN extracted_iocs ei
                      ON ei.hunt_package_id = hp.id AND ei.action != 'remove'
               LEFT JOIN threat_intel_analysis tia ON tia.hunt_package_id = hp.id
               WHERE hp.status != 'archived'
               GROUP BY hp.id
               ORDER BY hp.created_at DESC"""
        )
        rows = await cur.fetchall()
        await cur.close()

    prefix = load_hunt_id_prefix()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "hunt_id_display": format_hunt_id(prefix, row["hunt_seq"]),
            "status": row["status"],
            "excluded_from_correlation": bool(row["excluded_from_correlation"]),
            "ioc_count": row["ioc_count"],
            "has_threat_intel": row["threat_intel_count"] > 0,
        }
        for row in rows
    ]


# ── Run Comments CRUD (issue-local-018) ───────────────────────────────────────
# Durable analyst free-text notes tied to a specific run. Mirrors the
# hunt_reports shape (id/hunt_package_id/run_id/created_at/created_by) — the
# closest existing precedent for a simple per-run child record.


async def create_run_comment(
    hunt_package_id: str,
    run_id: str,
    body: str,
    created_by: str | None = None,
) -> dict[str, Any]:
    comment_id = _new_id()
    now = _utc_now_iso()
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            """INSERT INTO run_comments
               (id, hunt_package_id, run_id, body, created_by, created_at)
               VALUES (?,?,?,?,?,?)""",
            (comment_id, hunt_package_id, run_id, body, created_by, now),
        )
        await db.commit()
    return {
        "id": comment_id,
        "hunt_package_id": hunt_package_id,
        "run_id": run_id,
        "body": body,
        "created_by": created_by,
        "created_at": now,
    }


async def list_run_comments(run_id: str) -> list[dict[str, Any]]:
    """Return all comments for a run, oldest first (reads like a conversation)."""
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM run_comments WHERE run_id = ? ORDER BY created_at ASC",
            (run_id,),
        )
        rows = await cur.fetchall()
        await cur.close()
    return [dict(row) for row in rows]


async def delete_run_comment(comment_id: str) -> bool:
    """Delete a comment by id. Returns True if a row was actually deleted."""
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        cur = await db.execute("DELETE FROM run_comments WHERE id = ?", (comment_id,))
        await db.commit()
        return cur.rowcount > 0


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
        cur = await db.execute("SELECT step_logs FROM hunting_packages WHERE id = ?", (run_id,))
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


async def set_run_threat_intel_status(run_id: str, status: str | None) -> None:
    """Set/clear ``hunting_packages.threat_intel_status`` (issue-local-022 item 3).

    ``status='running'`` while either Threat Intel Analyst phase is active for
    this run, ``None`` once it finishes (success or failure) — callers should
    wrap this around ``analyze_threat_intel()`` in a try/finally so it always
    clears. Lets the frontend gate Re-run/report-generation buttons on "is a
    Threat Intel analysis currently running for this run" without a poll of
    the analysis itself. No-ops when *run_id* is not found.
    """
    async with aiosqlite.connect(_TH_DB_PATH) as db:
        await db.execute(
            "UPDATE hunting_packages SET threat_intel_status = ? WHERE id = ?",
            (status, run_id),
        )
        await db.commit()


async def set_hypothesis_discarded(
    run_id: str, hypothesis_id: str, discarded: bool
) -> dict[str, Any] | None:
    """Flip the ``discarded`` flag of one hypothesis within a run's hypotheses list.

    issue-local-015: hypotheses are stored as a JSON blob (the ``hypotheses``
    column), not a table — same load/find/write-back pattern as
    ``append_run_step_log``. Returns the updated hypothesis dict, or None if
    the run or hypothesis id was not found.
    """
    import json as _json

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT hypotheses FROM hunting_packages WHERE id = ?", (run_id,))
        row = await cur.fetchone()
        await cur.close()
        if not row:
            return None

        try:
            hypotheses: list[dict[str, Any]] = _json.loads(row[0] or "[]")
            if not isinstance(hypotheses, list):
                return None
        except Exception:
            return None

        idx = next((i for i, h in enumerate(hypotheses) if h.get("id") == hypothesis_id), None)
        if idx is None:
            return None
        hypotheses[idx]["discarded"] = discarded

        await db.execute(
            "UPDATE hunting_packages SET hypotheses = ? WHERE id = ?",
            (_json.dumps(hypotheses, ensure_ascii=False, default=str), run_id),
        )
        await db.commit()
        return hypotheses[idx]


async def set_hunting_lead_discarded(
    run_id: str, lead_id: str, discarded: bool
) -> dict[str, Any] | None:
    """Flip the ``discarded`` flag of one hunting lead within a run's leads list.

    issue-local-015: same load/find/write-back pattern as
    ``set_hypothesis_discarded``, against the ``hunting_leads`` column.
    Returns the updated lead dict, or None if the run or lead id was not
    found.
    """
    import json as _json

    async with aiosqlite.connect(_TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT hunting_leads FROM hunting_packages WHERE id = ?", (run_id,))
        row = await cur.fetchone()
        await cur.close()
        if not row:
            return None

        try:
            leads: list[dict[str, Any]] = _json.loads(row[0] or "[]")
            if not isinstance(leads, list):
                return None
        except Exception:
            return None

        idx = next((i for i, lead in enumerate(leads) if lead.get("id") == lead_id), None)
        if idx is None:
            return None
        leads[idx]["discarded"] = discarded

        await db.execute(
            "UPDATE hunting_packages SET hunting_leads = ? WHERE id = ?",
            (_json.dumps(leads, ensure_ascii=False, default=str), run_id),
        )
        await db.commit()
        return leads[idx]


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
