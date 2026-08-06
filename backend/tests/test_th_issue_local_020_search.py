"""
Tests for issue-local-020 Part B: server-side deep search + date filtering
for the hunt package list (list_hunt_packages() + GET /packages route).
"""

from __future__ import annotations

import json
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


class TestListHuntPackagesSearch:
    @pytest.mark.asyncio
    async def test_no_filters_returns_all(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.create_hunt_package("Alpha", "")
            await th_db.create_hunt_package("Beta", "")
            result = await th_db.list_hunt_packages()
            assert {p["name"] for p in result} == {"Alpha", "Beta"}

    @pytest.mark.asyncio
    async def test_search_matches_name(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.create_hunt_package("Emotet campaign", "")
            await th_db.create_hunt_package("Cobalt Strike hunt", "")
            result = await th_db.list_hunt_packages(search="Emotet")
            assert [p["name"] for p in result] == ["Emotet campaign"]

    @pytest.mark.asyncio
    async def test_search_matches_description(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.create_hunt_package("Package A", "phishing emails targeting finance")
            await th_db.create_hunt_package("Package B", "C2 beacon analysis")
            result = await th_db.list_hunt_packages(search="beacon")
            assert [p["name"] for p in result] == ["Package B"]

    @pytest.mark.asyncio
    async def test_search_matches_run_threat_context_json(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, threat_context, created_at) "
                    "VALUES (?,?,?,?)",
                    (
                        "run-1",
                        pkg["id"],
                        json.dumps({"threat_actor": "FIN7"}),
                        "2026-01-01T00:00:00Z",
                    ),
                )
                await db.commit()
            result = await th_db.list_hunt_packages(search="FIN7")
            assert [p["name"] for p in result] == ["Package A"]

    @pytest.mark.asyncio
    async def test_search_matches_run_hunting_leads_json(self, db_path: Path) -> None:
        """issue-local-039: hunting_leads was missing from the deep-search
        WHERE clause entirely — a package whose only mention of a term was in
        this field was unreachable by any search."""
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, hunting_leads, created_at) "
                    "VALUES (?,?,?,?)",
                    (
                        "run-1",
                        pkg["id"],
                        json.dumps([{"lead": "Pivot on Cobalt Strike beacon interval"}]),
                        "2026-01-01T00:00:00Z",
                    ),
                )
                await db.commit()
            result = await th_db.list_hunt_packages(search="beacon interval")
            assert [p["name"] for p in result] == ["Package A"]

    @pytest.mark.asyncio
    async def test_search_matches_run_query_drafts_json(self, db_path: Path) -> None:
        """issue-local-039: query_drafts was likewise missing from the
        deep-search WHERE clause."""
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, query_drafts, created_at) "
                    "VALUES (?,?,?,?)",
                    (
                        "run-1",
                        pkg["id"],
                        json.dumps([{"spl": "index=proxy dest_domain=evil-domain.example"}]),
                        "2026-01-01T00:00:00Z",
                    ),
                )
                await db.commit()
            result = await th_db.list_hunt_packages(search="evil-domain.example")
            assert [p["name"] for p in result] == ["Package A"]

    @pytest.mark.asyncio
    async def test_search_matches_extracted_ioc(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.add_extracted_iocs(
                pkg["id"],
                "ev1",
                [
                    {
                        "ioc": "malicious-domain.biz",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.1,
                    }
                ],
            )
            result = await th_db.list_hunt_packages(search="malicious-domain")
            assert [p["name"] for p in result] == ["Package A"]

    @pytest.mark.asyncio
    async def test_search_no_match_returns_empty(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.create_hunt_package("Package A", "")
            result = await th_db.list_hunt_packages(search="nonexistent-term-xyz")
            assert result == []

    @pytest.mark.asyncio
    async def test_search_escapes_like_wildcards(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.create_hunt_package("100% Coverage", "")
            await th_db.create_hunt_package("Other", "")
            # A literal "%" in the search term must not act as a wildcard.
            result = await th_db.list_hunt_packages(search="100%")
            assert [p["name"] for p in result] == ["100% Coverage"]
            # An underscore likewise must be literal, not a single-char wildcard.
            result2 = await th_db.list_hunt_packages(search="_nomatch_")
            assert result2 == []

    @pytest.mark.asyncio
    async def test_date_from_filters_out_older_packages(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Old package", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "UPDATE hunt_packages SET created_at = '2020-01-01T00:00:00Z' WHERE id = ?",
                    (pkg["id"],),
                )
                await db.commit()
            await th_db.create_hunt_package("New package", "")

            result = await th_db.list_hunt_packages(date_from="2025-01-01")
            assert [p["name"] for p in result] == ["New package"]

    @pytest.mark.asyncio
    async def test_date_to_filters_out_newer_packages(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.create_hunt_package("New package", "")
            result = await th_db.list_hunt_packages(date_to="2020-01-01")
            assert result == []

    @pytest.mark.asyncio
    async def test_combined_search_and_date_filters(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Emotet campaign", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "UPDATE hunt_packages SET created_at = '2020-01-01T00:00:00Z' WHERE id = ?",
                    (pkg["id"],),
                )
                await db.commit()
            await th_db.create_hunt_package("Emotet followup", "")

            result = await th_db.list_hunt_packages(search="Emotet", date_from="2025-01-01")
            assert [p["name"] for p in result] == ["Emotet followup"]


class TestSearchSnippet:
    """issue-local-039: list_hunt_packages(search=...) attaches a
    `search_snippet` telling the caller which field actually matched, so
    search results stop silently falling back to the package's own
    description or a generic status line for deep-search-only matches."""

    @pytest.mark.asyncio
    async def test_snippet_is_none_when_search_is_unset(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.create_hunt_package("Package A", "")
            result = await th_db.list_hunt_packages()
            assert "search_snippet" not in result[0]

    @pytest.mark.asyncio
    async def test_snippet_is_none_when_only_name_or_description_matched(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.create_hunt_package("Emotet campaign", "phishing lure")
            result = await th_db.list_hunt_packages(search="Emotet")
            assert result[0]["search_snippet"] is None

    @pytest.mark.asyncio
    async def test_snippet_names_the_matched_run_field(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, ttp_analysis, created_at) "
                    "VALUES (?,?,?,?)",
                    ("run-1", pkg["id"], json.dumps({"technique": "T1059 - FIN7 usage"}), "2026-01-01T00:00:00Z"),
                )
                await db.commit()
            result = await th_db.list_hunt_packages(search="FIN7")
            snippet = result[0]["search_snippet"]
            assert snippet is not None
            assert snippet["field"] == "TTP analysis"
            assert "FIN7" in snippet["text"]

    @pytest.mark.asyncio
    async def test_snippet_names_a_matched_extracted_ioc(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Package A", "")
            await th_db.add_extracted_iocs(
                pkg["id"],
                "ev1",
                [{"ioc": "malicious-domain.biz", "ioc_type": "domain", "ioc_description": "", "noise_score": 0.1}],
            )
            result = await th_db.list_hunt_packages(search="malicious-domain")
            snippet = result[0]["search_snippet"]
            assert snippet is not None
            assert snippet["field"] == "extracted IOC"
            assert snippet["text"] == "malicious-domain.biz"


@pytest.mark.asyncio
async def test_route_list_packages_accepts_search_param(db_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.create_hunt_package("Emotet campaign", "")
        await th_db.create_hunt_package("Cobalt Strike hunt", "")

        client = TestClient(app)
        resp = client.get("/api/threat-hunting/packages", params={"search": "Emotet"})
        assert resp.status_code == 200
        names = [p["name"] for p in resp.json()]
        assert names == ["Emotet campaign"]


@pytest.mark.asyncio
async def test_route_list_packages_no_params_returns_all(db_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.create_hunt_package("Alpha", "")
        await th_db.create_hunt_package("Beta", "")

        client = TestClient(app)
        resp = client.get("/api/threat-hunting/packages")
        assert resp.status_code == 200
        assert len(resp.json()) == 2
