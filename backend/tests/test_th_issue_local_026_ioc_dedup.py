"""
Tests for the issue-local-026 follow-up: extracted_iocs had no uniqueness
constraint, so the same IOC extracted from multiple evidence items in one
run produced multiple rows — surfacing as duplicate entries in the flat IOC
tab and, most visibly, in the Threat Intelligence tab's cross-package
"Correlated IOCs" table (the reported symptom).

Covers:
  - Schema v11 migration: cleans up pre-existing duplicate extracted_iocs
    rows and adds a unique index so future INSERT OR IGNORE calls actually
    dedupe.
  - add_extracted_iocs() no longer creates duplicate rows for the same
    (hunt_package_id, run_id, ioc, ioc_type).
  - list_extracted_iocs()'s defense-in-depth Python dedup.
  - find_cross_package_ioc_matches() collapsing an IOC that appears across
    multiple runs of the SAME other package into one correlation row.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", path):
        await th_db.init_threat_hunting_db()
        yield path


async def _insert_raw_ioc_row(
    *, hunt_package_id: str, run_id: str, ioc: str, ioc_type: str, evidence_item_id: str
) -> None:
    """Insert directly via raw SQL, bypassing add_extracted_iocs — mirrors
    what pre-fix duplicate rows on disk actually looked like."""
    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        await db.execute(
            "INSERT INTO extracted_iocs "
            "(id, evidence_item_id, hunt_package_id, run_id, ioc, ioc_type, "
            " ioc_description, noise_score, flagged_noisy, action, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                f"{evidence_item_id}-{ioc}-{ioc_type}",
                evidence_item_id,
                hunt_package_id,
                run_id,
                ioc,
                ioc_type,
                "",
                0.0,
                0,
                "keep",
                "2026-01-01T00:00:00Z",
            ),
        )
        await db.commit()


class TestSchemaV11Migration:
    @pytest.mark.asyncio
    async def test_fresh_db_has_unique_index(self, db_path: Path) -> None:
        async with aiosqlite.connect(db_path) as db:
            cur = await db.execute("PRAGMA index_list(extracted_iocs)")
            indexes = {row[1] for row in await cur.fetchall()}
        assert "idx_extracted_iocs_unique" in indexes

    @pytest.mark.asyncio
    async def test_schema_version_is_current(self, db_path: Path) -> None:
        async with aiosqlite.connect(db_path) as db:
            cur = await db.execute("SELECT version FROM th_schema_version LIMIT 1")
            row = await cur.fetchone()
        assert row[0] == th_db._TH_SCHEMA_VERSION

    @pytest.mark.asyncio
    async def test_migration_cleans_up_preexisting_duplicates(self, tmp_path: Path) -> None:
        """Simulate a pre-v11 DB with duplicate extracted_iocs rows (the
        real-world state before this fix), then re-run init and confirm the
        duplicates are gone and a unique index now exists."""
        path = tmp_path / "old.db"
        with patch.object(th_db, "_TH_DB_PATH", path):
            async with aiosqlite.connect(path) as db:
                await db.execute(th_db.CREATE_SCHEMA_VERSION_TABLE)
                await db.execute(th_db.CREATE_HUNT_PACKAGES_TABLE)
                await db.execute(th_db.CREATE_EXTRACTED_IOCS_TABLE)
                await db.execute("INSERT INTO th_schema_version (version) VALUES (10)")
                await db.execute(
                    "INSERT INTO hunt_packages (id, name, description, status, created_at, updated_at) "
                    "VALUES ('pkg-1','pkg','', 'draft', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
                )
                await db.commit()

            # Three evidence items all mention the same domain -> three
            # duplicate rows for (pkg-1, run-1, evil.example.com, domain),
            # exactly the pre-fix shape.
            for i in range(3):
                await _insert_raw_ioc_row(
                    hunt_package_id="pkg-1",
                    run_id="run-1",
                    ioc="evil.example.com",
                    ioc_type="domain",
                    evidence_item_id=f"evidence-{i}",
                )
            # A genuinely distinct IOC must survive untouched.
            await _insert_raw_ioc_row(
                hunt_package_id="pkg-1",
                run_id="run-1",
                ioc="1.2.3.4",
                ioc_type="ip",
                evidence_item_id="evidence-0",
            )

            async with aiosqlite.connect(path) as db:
                cur = await db.execute("SELECT COUNT(*) FROM extracted_iocs")
                assert (await cur.fetchone())[0] == 4

            # Re-running init_threat_hunting_db triggers the v10->v11 migration.
            await th_db.init_threat_hunting_db()

            async with aiosqlite.connect(path) as db:
                db.row_factory = aiosqlite.Row
                cur = await db.execute("SELECT ioc, ioc_type FROM extracted_iocs ORDER BY ioc")
                rows = [dict(r) for r in await cur.fetchall()]
                cur2 = await db.execute("PRAGMA index_list(extracted_iocs)")
                indexes = {r[1] for r in await cur2.fetchall()}

            assert rows == [
                {"ioc": "1.2.3.4", "ioc_type": "ip"},
                {"ioc": "evil.example.com", "ioc_type": "domain"},
            ]
            assert "idx_extracted_iocs_unique" in indexes


class TestAddExtractedIocsDedup:
    @pytest.mark.asyncio
    async def test_same_ioc_from_two_evidence_items_stores_once(self, db_path: Path) -> None:
        pkg = await th_db.create_hunt_package("pkg", "")

        item = [
            {
                "ioc": "evil.example.com",
                "ioc_type": "domain",
                "ioc_description": "",
                "noise_score": 0.0,
                "flagged_noisy": False,
            }
        ]
        await th_db.add_extracted_iocs(pkg["id"], "evidence-a", item, run_id="run-1")
        await th_db.add_extracted_iocs(pkg["id"], "evidence-b", item, run_id="run-1")

        stored = await th_db.list_extracted_iocs(pkg["id"], "run-1")
        assert len(stored) == 1
        assert stored[0]["ioc"] == "evil.example.com"

    @pytest.mark.asyncio
    async def test_same_ioc_in_different_runs_stores_separately(self, db_path: Path) -> None:
        """Uniqueness is scoped per-run — the same package hunting the same
        IOC again in a later, independent run is not a duplicate."""
        pkg = await th_db.create_hunt_package("pkg", "")

        item = [
            {
                "ioc": "evil.example.com",
                "ioc_type": "domain",
                "ioc_description": "",
                "noise_score": 0.0,
                "flagged_noisy": False,
            }
        ]
        await th_db.add_extracted_iocs(pkg["id"], "evidence-a", item, run_id="run-1")
        await th_db.add_extracted_iocs(pkg["id"], "evidence-a", item, run_id="run-2")

        assert len(await th_db.list_extracted_iocs(pkg["id"], "run-1")) == 1
        assert len(await th_db.list_extracted_iocs(pkg["id"], "run-2")) == 1


class TestFindCrossPackageIocMatchesDedup:
    @pytest.mark.asyncio
    async def test_ioc_across_multiple_runs_of_other_package_collapses_to_one_row(
        self, db_path: Path
    ) -> None:
        pkg_a = await th_db.create_hunt_package("A", "")
        pkg_b = await th_db.create_hunt_package("B", "")

        shared = [
            {
                "ioc": "evil.example.com",
                "ioc_type": "domain",
                "ioc_description": "",
                "noise_score": 0.0,
                "flagged_noisy": False,
            }
        ]
        # pkg_b found the same IOC across three independent runs.
        await th_db.add_extracted_iocs(pkg_b["id"], "ev-1", shared, run_id="run-b1")
        await th_db.add_extracted_iocs(pkg_b["id"], "ev-2", shared, run_id="run-b2")
        await th_db.add_extracted_iocs(pkg_b["id"], "ev-3", shared, run_id="run-b3")

        matches = await th_db.find_cross_package_ioc_matches(pkg_a["id"], ["evil.example.com"])
        assert len(matches) == 1
        assert matches[0]["ioc"] == "evil.example.com"
        assert matches[0]["hunt_name"] == "B"

    @pytest.mark.asyncio
    async def test_distinct_iocs_and_packages_are_not_collapsed(self, db_path: Path) -> None:
        pkg_a = await th_db.create_hunt_package("A", "")
        pkg_b = await th_db.create_hunt_package("B", "")
        pkg_c = await th_db.create_hunt_package("C", "")

        def _row(ioc: str) -> list[dict]:
            return [
                {
                    "ioc": ioc,
                    "ioc_type": "domain",
                    "ioc_description": "",
                    "noise_score": 0.0,
                    "flagged_noisy": False,
                }
            ]

        await th_db.add_extracted_iocs(
            pkg_b["id"], "ev-1", _row("shared.example.com"), run_id="run-b1"
        )
        await th_db.add_extracted_iocs(
            pkg_c["id"], "ev-1", _row("shared.example.com"), run_id="run-c1"
        )
        await th_db.add_extracted_iocs(
            pkg_b["id"], "ev-2", _row("other.example.com"), run_id="run-b1"
        )

        matches = await th_db.find_cross_package_ioc_matches(
            pkg_a["id"], ["shared.example.com", "other.example.com"]
        )
        assert len(matches) == 3
        keys = {(m["ioc"], m["hunt_name"]) for m in matches}
        assert keys == {
            ("shared.example.com", "B"),
            ("shared.example.com", "C"),
            ("other.example.com", "B"),
        }
