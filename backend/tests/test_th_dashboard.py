"""
Tests for the Threat Hunting Dashboard's backend aggregation (issue-local-032):
db.get_hunt_dashboard_stats and the GET /api/threat-hunting/dashboard route.
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


async def _seed_run(
    db_path: Path,
    pkg_id: str,
    *,
    run_id: str,
    llm_model: str | None = "gpt-test",
    hypotheses: list | None = None,
    hunting_leads: list | None = None,
    query_drafts: list | None = None,
    step_logs: list | None = None,
    created_at: str = "2026-01-15T00:00:00Z",
) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO hunting_packages "
            "(id, hunt_package_id, llm_model, hypotheses, hunting_leads, query_drafts, "
            " step_logs, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                run_id,
                pkg_id,
                llm_model,
                json.dumps(hypotheses or []),
                json.dumps(hunting_leads or []),
                json.dumps(query_drafts or []),
                json.dumps(step_logs or []),
                created_at,
            ),
        )
        await db.commit()


class TestEmptyState:
    @pytest.mark.asyncio
    async def test_no_packages_returns_zeros(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            stats = await th_db.get_hunt_dashboard_stats()
        assert stats["packages_total"] == 0
        assert stats["runs_total"] == 0
        assert stats["evidence_total"] == 0
        assert stats["iocs_extracted_total"] == 0
        assert stats["runs_by_model"] == {}
        assert stats["hunts_by_model"] == {}
        # The global Threat Intel summary is still computed (all zero, but present).
        assert stats["threat_actors_total"] == 0
        assert stats["sources_processed"] == 0


class TestCoreCounts:
    @pytest.mark.asyncio
    async def test_packages_runs_and_status_breakdown(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("Hunt A", "")
            pkg_b = await th_db.create_hunt_package("Hunt B", "")
            await th_db.update_hunt_package(pkg_b["id"], status="completed")
            await _seed_run(db_path, pkg_a["id"], run_id="run-1")
            await _seed_run(db_path, pkg_b["id"], run_id="run-2")

            stats = await th_db.get_hunt_dashboard_stats()

        assert stats["packages_total"] == 2
        assert stats["runs_total"] == 2
        assert stats["packages_by_status"] == {"draft": 1, "completed": 1}

    @pytest.mark.asyncio
    async def test_archived_packages_are_excluded(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Archived", "")
            await th_db.update_hunt_package(pkg["id"], status="archived")

            stats = await th_db.get_hunt_dashboard_stats()

        assert stats["packages_total"] == 0

    @pytest.mark.asyncio
    async def test_hypotheses_leads_and_queries_are_summed_across_runs(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(
                db_path,
                pkg["id"],
                run_id="run-1",
                hypotheses=[{"id": "H1"}, {"id": "H2"}],
                hunting_leads=[{"id": "L1"}],
                query_drafts=[{"id": "Q1"}, {"id": "Q2"}, {"id": "Q3"}],
            )
            await _seed_run(
                db_path,
                pkg["id"],
                run_id="run-2",
                hypotheses=[{"id": "H3"}],
                hunting_leads=[],
                query_drafts=[{"id": "Q4"}],
            )

            stats = await th_db.get_hunt_dashboard_stats()

        assert stats["hypotheses_total"] == 3
        assert stats["hunting_leads_total"] == 1
        assert stats["queries_total"] == 4

    @pytest.mark.asyncio
    async def test_malformed_json_blob_does_not_crash_and_counts_as_empty(
        self, db_path: Path
    ) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, hypotheses, created_at) "
                    "VALUES (?,?,?,?)",
                    ("run-bad", pkg["id"], "not-json", "2026-01-01T00:00:00Z"),
                )
                await db.commit()

            stats = await th_db.get_hunt_dashboard_stats()

        assert stats["runs_total"] == 1
        assert stats["hypotheses_total"] == 0

    @pytest.mark.asyncio
    async def test_evidence_counted_by_type(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await th_db.add_evidence_item(pkg["id"], item_type="file")
            await th_db.add_evidence_item(pkg["id"], item_type="file")
            await th_db.add_evidence_item(pkg["id"], item_type="url")

            stats = await th_db.get_hunt_dashboard_stats()

        assert stats["evidence_total"] == 3
        assert stats["evidence_by_type"] == {"file": 2, "url": 1}

    @pytest.mark.asyncio
    async def test_iocs_extracted_vs_kept(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            ev = await th_db.add_evidence_item(pkg["id"], item_type="file")
            await th_db.add_extracted_iocs(
                pkg["id"],
                ev["id"],
                [
                    {"ioc": "1.2.3.4", "ioc_type": "ip", "action": "keep"},
                    {"ioc": "5.6.7.8", "ioc_type": "ip", "action": "keep"},
                    {"ioc": "evil.example", "ioc_type": "domain", "action": "remove"},
                ],
            )

            stats = await th_db.get_hunt_dashboard_stats()

        assert stats["iocs_extracted_total"] == 3
        assert stats["iocs_kept_total"] == 2

    @pytest.mark.asyncio
    async def test_siem_searches_and_events(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await th_db.create_task_result(pkg["id"], task_type="siem_search", status="completed")
            await th_db.create_task_result(pkg["id"], task_type="siem_search", status="pending")
            await _seed_run(
                db_path,
                pkg["id"],
                run_id="run-1",
                step_logs=[
                    {"step": "siem_fetch", "status": "ok", "item_count": 42},
                    {"step": "intake_classifier", "status": "ok", "item_count": 999},
                ],
            )

            stats = await th_db.get_hunt_dashboard_stats()

        assert stats["siem_searches_total"] == 2
        assert stats["siem_searches_completed"] == 1
        # Only siem_fetch's item_count counts toward "events retrieved" — a
        # non-execution step's item_count (e.g. intake_classifier's evidence
        # item count) must not be conflated with SIEM execution results.
        assert stats["siem_events_total"] == 42


class TestModelBreakdown:
    @pytest.mark.asyncio
    async def test_runs_by_model_counts_every_run(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(db_path, pkg["id"], run_id="run-1", llm_model="gpt-a")
            await _seed_run(db_path, pkg["id"], run_id="run-2", llm_model="gpt-a")
            await _seed_run(db_path, pkg["id"], run_id="run-3", llm_model="gpt-b")

            stats = await th_db.get_hunt_dashboard_stats()

        assert stats["runs_by_model"] == {"gpt-a": 2, "gpt-b": 1}

    @pytest.mark.asyncio
    async def test_hunts_by_model_counts_distinct_packages_not_runs(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            # Two runs of the SAME package, same model — must count as 1 hunt.
            await _seed_run(db_path, pkg["id"], run_id="run-1", llm_model="gpt-a")
            await _seed_run(db_path, pkg["id"], run_id="run-2", llm_model="gpt-a")

            stats = await th_db.get_hunt_dashboard_stats()

        assert stats["runs_by_model"] == {"gpt-a": 2}
        assert stats["hunts_by_model"] == {"gpt-a": 1}

    @pytest.mark.asyncio
    async def test_missing_model_buckets_as_unknown(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(db_path, pkg["id"], run_id="run-1", llm_model=None)

            stats = await th_db.get_hunt_dashboard_stats()

        assert stats["runs_by_model"] == {"unknown": 1}


class TestSearchAndDateFilter:
    @pytest.mark.asyncio
    async def test_search_narrows_hunt_scoped_counts(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            lazarus = await th_db.create_hunt_package("Lazarus sweep", "")
            other = await th_db.create_hunt_package("Unrelated", "")
            await _seed_run(db_path, lazarus["id"], run_id="run-1")
            await _seed_run(db_path, other["id"], run_id="run-2")

            stats = await th_db.get_hunt_dashboard_stats(search="lazarus")

        assert stats["packages_total"] == 1
        assert stats["runs_total"] == 1

    @pytest.mark.asyncio
    async def test_date_range_narrows_hunt_scoped_counts(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            old_pkg = await th_db.create_hunt_package("Old Hunt", "")
            recent_pkg = await th_db.create_hunt_package("Recent Hunt", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "UPDATE hunt_packages SET created_at = ? WHERE id = ?",
                    ("2020-01-01T00:00:00Z", old_pkg["id"]),
                )
                await db.execute(
                    "UPDATE hunt_packages SET created_at = ? WHERE id = ?",
                    ("2026-06-01T00:00:00Z", recent_pkg["id"]),
                )
                await db.commit()
            await _seed_run(db_path, old_pkg["id"], run_id="run-old")
            await _seed_run(db_path, recent_pkg["id"], run_id="run-recent")

            unfiltered = await th_db.get_hunt_dashboard_stats()
            from_2026 = await th_db.get_hunt_dashboard_stats(date_from="2026-01-01")

        assert unfiltered["packages_total"] == 2
        assert from_2026["packages_total"] == 1
        assert from_2026["runs_total"] == 1

    @pytest.mark.asyncio
    async def test_threat_intel_summary_is_not_affected_by_search_or_date(
        self, db_path: Path
    ) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id=None,
                threat_actors=[{"name": "APT-Test"}],
                attribution=None,
                malware_families=[],
                campaigns=[],
                related_vendors=[],
                correlated_iocs=[],
                summary="",
                full_analysis={},
            )

            filtered = await th_db.get_hunt_dashboard_stats(search="nonexistent-term")

        # No hunt matches the search, but the global Threat Intel summary is
        # unaffected by the filter — same convention as the Tracking dashboard.
        assert filtered["packages_total"] == 0
        assert filtered["threat_actors_total"] == 1


class TestRoute:
    @pytest.mark.asyncio
    async def test_get_dashboard_route_returns_stats_shape(self, db_path: Path) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(db_path, pkg["id"], run_id="run-1", llm_model="gpt-a")

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/threat-hunting/dashboard")

        assert resp.status_code == 200
        body = resp.json()
        assert body["packages_total"] == 1
        assert body["runs_by_model"] == {"gpt-a": 1}
