"""
Tests for issue-local-039's new bulk full-text search functions in
backend.threat_hunting.db: search_hunt_reports, search_threat_intel_analysis,
search_evidence_items, search_run_comments. These back the new AI Assistant /
global search retrieval sources in backend.search.service — this file
exercises the actual SQL against a real (temp) schema, complementing the
mocked shape/wiring tests in backend/tests/test_search.py.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.threat_hunting import db as th_db


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", path):
        await th_db.init_threat_hunting_db()
        yield path


class TestSearchHuntReports:
    @pytest.mark.asyncio
    async def test_matches_executive_summary(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.create_hunt_report(
                pkg["id"],
                executive_summary="Confirmed FIN7 tooling on host X",
                full_report={"findings": []},
            )
            results = await th_db.search_hunt_reports("FIN7")
            assert len(results) == 1
            assert results[0]["hunt_package_id"] == pkg["id"]
            assert results[0]["hunt_id_display"]

    @pytest.mark.asyncio
    async def test_matches_full_report_body_not_just_summary(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.create_hunt_report(
                pkg["id"],
                executive_summary="Unrelated summary",
                full_report={"findings": [{"detail": "Emotet loader observed"}]},
            )
            results = await th_db.search_hunt_reports("Emotet loader")
            assert len(results) == 1

    @pytest.mark.asyncio
    async def test_no_match_returns_empty(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.create_hunt_report(
                pkg["id"], executive_summary="Nothing notable", full_report={}
            )
            assert await th_db.search_hunt_reports("nonexistent-term-xyz") == []


class TestSearchThreatIntelAnalysis:
    @pytest.mark.asyncio
    async def test_matches_summary(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id=None,
                threat_actors=[{"name": "Lazarus Group"}],
                attribution=None,
                malware_families=[],
                campaigns=[],
                related_vendors=[],
                correlated_iocs=[],
                summary="Attributed to Lazarus Group with high confidence",
                full_analysis={},
            )
            results = await th_db.search_threat_intel_analysis("Lazarus Group")
            assert len(results) == 1
            assert results[0]["hunt_package_id"] == pkg["id"]

    @pytest.mark.asyncio
    async def test_matches_malware_families_json(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id=None,
                threat_actors=[],
                attribution=None,
                malware_families=["Chaos ransomware"],
                campaigns=[],
                related_vendors=[],
                correlated_iocs=[],
                summary="unrelated",
                full_analysis={},
            )
            results = await th_db.search_threat_intel_analysis("Chaos ransomware")
            assert len(results) == 1


class TestSearchEvidenceItems:
    @pytest.mark.asyncio
    async def test_matches_extracted_text(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.add_evidence_item(
                pkg["id"],
                item_type="file",
                label="notes.txt",
                extracted_text="The attacker used a Cobalt Strike beacon on port 443",
            )
            results = await th_db.search_evidence_items("Cobalt Strike beacon")
            assert len(results) == 1
            assert results[0]["hunt_package_id"] == pkg["id"]

    @pytest.mark.asyncio
    async def test_matches_label_when_no_extracted_text(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.add_evidence_item(pkg["id"], item_type="file", label="malicious_payload.exe")
            results = await th_db.search_evidence_items("malicious_payload")
            assert len(results) == 1

    @pytest.mark.asyncio
    async def test_no_match_returns_empty(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.add_evidence_item(pkg["id"], item_type="file", label="benign.txt")
            assert await th_db.search_evidence_items("nonexistent-term-xyz") == []


class TestSearchRunComments:
    @pytest.mark.asyncio
    async def test_matches_comment_body(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.create_run_comment(
                pkg["id"], "run-1", "This is definitely APT29 activity", created_by="analyst1"
            )
            results = await th_db.search_run_comments("APT29")
            assert len(results) == 1
            assert results[0]["created_by"] == "analyst1"

    @pytest.mark.asyncio
    async def test_no_match_returns_empty(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.create_run_comment(pkg["id"], "run-1", "Looks benign", created_by="analyst1")
            assert await th_db.search_run_comments("nonexistent-term-xyz") == []
