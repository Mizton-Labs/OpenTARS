"""
Tests for issue-local-020 Part A: schema v7 migration, threat_intel_analysis
CRUD, cross-package IOC correlation, and comparison-report storage
(reusing hunt_reports with a report_kind discriminator).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.threat_hunting import db as th_db


@pytest.mark.asyncio
async def test_fresh_db_is_schema_v7_with_new_table_and_index(tmp_path: Path) -> None:
    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

    conn = sqlite3.connect(db_path)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    indexes = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    version = conn.execute("SELECT version FROM th_schema_version LIMIT 1").fetchone()[0]
    conn.close()

    assert "threat_intel_analysis" in tables
    assert "idx_extracted_iocs_ioc" in indexes
    assert version == th_db._TH_SCHEMA_VERSION


@pytest.mark.asyncio
async def test_v6_db_migrates_to_v7(tmp_path: Path) -> None:
    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        # Simulate a pre-v7 DB: init fresh, then force the version back to 6
        # and drop the v7 table, mirroring how a real DB would look pre-migration.
        await th_db.init_threat_hunting_db()
        import aiosqlite

        async with aiosqlite.connect(db_path) as db:
            await db.execute("UPDATE th_schema_version SET version = 6")
            await db.execute("DROP TABLE threat_intel_analysis")
            await db.commit()

        await th_db.init_threat_hunting_db()

    conn = sqlite3.connect(db_path)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    version = conn.execute("SELECT version FROM th_schema_version LIMIT 1").fetchone()[0]
    conn.close()
    assert "threat_intel_analysis" in tables
    assert version == th_db._TH_SCHEMA_VERSION


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", path):
        await th_db.init_threat_hunting_db()
        yield path


class TestThreatIntelAnalysisCrud:
    @pytest.mark.asyncio
    async def test_create_and_get_by_run(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id="run-1",
                threat_actors=[{"name": "APT1", "confidence": "medium"}],
                attribution={"assessment": "likely APT1", "confidence": "medium"},
                malware_families=["Emotet"],
                campaigns=[{"name": "Campaign X"}],
                related_vendors=[{"vendor": "Mandiant", "report": "..."}],
                correlated_iocs=[{"ioc": "evil.com", "ioc_type": "domain"}],
                summary="Test summary",
                full_analysis={"raw": True},
            )

            got = await th_db.get_threat_intel_analysis_by_run("run-1")
            assert got is not None
            assert got["threat_actors"] == [{"name": "APT1", "confidence": "medium"}]
            assert got["malware_families"] == ["Emotet"]
            assert got["summary"] == "Test summary"
            assert got["correlated_iocs"][0]["ioc"] == "evil.com"

    @pytest.mark.asyncio
    async def test_get_latest_for_package(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id="run-1",
                threat_actors=[],
                attribution=None,
                malware_families=[],
                campaigns=[],
                related_vendors=[],
                correlated_iocs=[],
                summary="first",
                full_analysis={},
            )
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id="run-2",
                threat_actors=[],
                attribution=None,
                malware_families=[],
                campaigns=[],
                related_vendors=[],
                correlated_iocs=[],
                summary="second",
                full_analysis={},
            )
            latest = await th_db.get_latest_threat_intel_analysis(pkg["id"])
            assert latest is not None
            assert latest["summary"] == "second"

    @pytest.mark.asyncio
    async def test_get_by_run_returns_none_when_absent(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            assert await th_db.get_threat_intel_analysis_by_run("no-such-run") is None


class TestCrossPackageIocCorrelation:
    async def _add_ioc(
        self, pkg_id: str, ioc: str, ioc_type: str = "domain", action: str = "keep"
    ) -> None:
        await th_db.add_extracted_iocs(
            pkg_id,
            "evidence-item-1",
            [
                {
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "ioc_description": "",
                    "noise_score": 0.1,
                    "action": action,
                }
            ],
        )

    @pytest.mark.asyncio
    async def test_finds_shared_ioc_in_other_package(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("A", "")
            pkg_b = await th_db.create_hunt_package("B", "")
            await self._add_ioc(pkg_a["id"], "evil.example")
            await self._add_ioc(pkg_b["id"], "evil.example")

            matches = await th_db.find_cross_package_ioc_matches(pkg_a["id"], ["evil.example"])
            assert len(matches) == 1
            assert matches[0]["hunt_package_id"] == pkg_b["id"]
            assert matches[0]["hunt_name"] == "B"

    @pytest.mark.asyncio
    async def test_excludes_same_package(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("A", "")
            await self._add_ioc(pkg_a["id"], "evil.example")

            matches = await th_db.find_cross_package_ioc_matches(pkg_a["id"], ["evil.example"])
            assert matches == []

    @pytest.mark.asyncio
    async def test_excludes_removed_iocs(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("A", "")
            pkg_b = await th_db.create_hunt_package("B", "")
            await self._add_ioc(pkg_b["id"], "evil.example", action="remove")

            matches = await th_db.find_cross_package_ioc_matches(pkg_a["id"], ["evil.example"])
            assert matches == []

    @pytest.mark.asyncio
    async def test_empty_ioc_list_returns_empty(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("A", "")
            assert await th_db.find_cross_package_ioc_matches(pkg_a["id"], []) == []
            assert await th_db.find_cross_package_ioc_matches(pkg_a["id"], ["", None]) == []  # type: ignore[list-item]


class TestComparisonReportStorage:
    @pytest.mark.asyncio
    async def test_create_and_get_latest_comparison_report(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.create_comparison_report(
                pkg["id"],
                executive_summary="Compared 3 runs",
                full_report={"compared_run_ids": ["r1", "r2", "r3"], "summary": "..."},
            )
            got = await th_db.get_latest_comparison_report(pkg["id"])
            assert got is not None
            assert got["full_report"]["report_kind"] == "comparison"
            assert got["full_report"]["compared_run_ids"] == ["r1", "r2", "r3"]

    @pytest.mark.asyncio
    async def test_comparison_report_does_not_shadow_normal_report(self, db_path: Path) -> None:
        """get_hunt_report() (used by the normal report download routes) must
        never surface a comparison row, even if it's the most recent."""
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.create_hunt_report(
                pkg["id"],
                executive_summary="real report",
                full_report={"hunt_name": "x"},
                run_id="run-1",
            )
            # Comparison report created AFTER, so it's more recent.
            await th_db.create_comparison_report(
                pkg["id"],
                executive_summary="comparison",
                full_report={"compared_run_ids": ["run-1"]},
            )

            normal = await th_db.get_hunt_report(pkg["id"])
            assert normal is not None
            assert normal["executive_summary"] == "real report"

            by_run = await th_db.get_hunt_report_by_run("run-1")
            assert by_run is not None
            assert by_run["executive_summary"] == "real report"

    @pytest.mark.asyncio
    async def test_get_hunt_report_none_when_only_comparison_exists(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.create_comparison_report(
                pkg["id"], executive_summary="comparison", full_report={"compared_run_ids": []}
            )
            assert await th_db.get_hunt_report(pkg["id"]) is None

    @pytest.mark.asyncio
    async def test_get_latest_comparison_report_none_when_absent(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            assert await th_db.get_latest_comparison_report(pkg["id"]) is None
