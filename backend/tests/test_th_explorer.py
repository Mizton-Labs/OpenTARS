"""
Tests for the Data Explorer's backend (issue-local-033):
db.list_explorer_rows and GET /api/threat-hunting/explorer/{category}.

Reuses the _seed_run helper pattern from test_th_dashboard.py.
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
    run_seq: int = 1,
    created_at: str = "2026-01-15T00:00:00Z",
) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO hunting_packages "
            "(id, hunt_package_id, llm_model, hypotheses, hunting_leads, query_drafts, "
            " step_logs, run_seq, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                pkg_id,
                llm_model,
                json.dumps(hypotheses or []),
                json.dumps(hunting_leads or []),
                json.dumps(query_drafts or []),
                json.dumps(step_logs or []),
                run_seq,
                created_at,
            ),
        )
        await db.commit()


class TestUnknownCategory:
    @pytest.mark.asyncio
    async def test_raises_value_error(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            with pytest.raises(ValueError):
                await th_db.list_explorer_rows("nonsense")


class TestHunts:
    @pytest.mark.asyncio
    async def test_lists_matching_packages_with_hunt_id_display(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Lazarus sweep", "")
            rows = await th_db.list_explorer_rows("hunts")

        assert len(rows) == 1
        assert rows[0]["id"] == pkg["id"]
        assert rows[0]["name"] == "Lazarus sweep"
        assert rows[0]["hunt_id_display"]

    @pytest.mark.asyncio
    async def test_search_narrows_by_name(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.create_hunt_package("Lazarus sweep", "")
            await th_db.create_hunt_package("Unrelated", "")
            rows = await th_db.list_explorer_rows("hunts", search="lazarus")

        assert len(rows) == 1
        assert rows[0]["name"] == "Lazarus sweep"

    @pytest.mark.asyncio
    async def test_archived_included_and_tagged(self, db_path: Path) -> None:
        # issue-local-034: Data Explorer is a "see everything, tagged"
        # surface — unlike the Dashboard/main package list, it no longer
        # excludes archived packages, it tags them via the status field.
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Archived", "")
            await th_db.update_hunt_package(pkg["id"], status="archived")
            rows = await th_db.list_explorer_rows("hunts")

        assert len(rows) == 1
        assert rows[0]["id"] == pkg["id"]
        assert rows[0]["status"] == "archived"


class TestRuns:
    @pytest.mark.asyncio
    async def test_lists_runs_with_hunt_linkage(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(db_path, pkg["id"], run_id="run-1", llm_model="gpt-a")
            rows = await th_db.list_explorer_rows("runs")

        assert len(rows) == 1
        assert rows[0]["id"] == "run-1"
        assert rows[0]["hunt_name"] == "Hunt"
        assert rows[0]["llm_model"] == "gpt-a"
        assert rows[0]["hunt_id_display"]
        assert rows[0]["run_id_display"]

    @pytest.mark.asyncio
    async def test_missing_model_reported_as_unknown(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(db_path, pkg["id"], run_id="run-1", llm_model=None)
            rows = await th_db.list_explorer_rows("runs")

        assert rows[0]["llm_model"] == "unknown"

    @pytest.mark.asyncio
    async def test_archived_run_included_and_flagged(self, db_path: Path) -> None:
        # issue-local-034: Explorer includes archived runs too (tagged via
        # the new per-run `archived` flag), unlike the Dashboard.
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(db_path, pkg["id"], run_id="run-1")
            ok = await th_db.set_run_archived("run-1", True)
            rows = await th_db.list_explorer_rows("runs")

        assert ok is True
        assert rows[0]["archived"] is True

    @pytest.mark.asyncio
    async def test_search_matches_own_model_not_sibling_package(self, db_path: Path) -> None:
        # issue-local-034 regression: a run's own llm_model/generation_status
        # /research_effort were never matched — only coarse package-level
        # fields were, so "all runs of a matching package" leaked in.
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("Alpha", "")
            pkg_b = await th_db.create_hunt_package("Beta", "")
            await _seed_run(db_path, pkg_a["id"], run_id="run-a", llm_model="claude-opus-5")
            await _seed_run(db_path, pkg_b["id"], run_id="run-b", llm_model="gpt-5.5")
            rows = await th_db.list_explorer_rows("runs", search="claude")

        assert len(rows) == 1
        assert rows[0]["llm_model"] == "claude-opus-5"


class TestEvidence:
    @pytest.mark.asyncio
    async def test_lists_evidence_items(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await th_db.add_evidence_item(pkg["id"], item_type="file", label="report.pdf")
            rows = await th_db.list_explorer_rows("evidence")

        assert len(rows) == 1
        assert rows[0]["item_type"] == "file"
        assert rows[0]["label"] == "report.pdf"
        assert rows[0]["hunt_name"] == "Hunt"

    @pytest.mark.asyncio
    async def test_search_matches_own_label_not_sibling_package(self, db_path: Path) -> None:
        # issue-local-034 regression: evidence's own label/source_ref/
        # item_type were never referenced by the package-level match — a
        # complete no-op beyond incidental package name/description matches.
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("Alpha", "")
            pkg_b = await th_db.create_hunt_package("Beta", "")
            await th_db.add_evidence_item(
                pkg_a["id"], item_type="file", label="incident-report.pdf"
            )
            await th_db.add_evidence_item(pkg_b["id"], item_type="file", label="unrelated.pdf")
            rows = await th_db.list_explorer_rows("evidence", search="incident")

        assert len(rows) == 1
        assert rows[0]["label"] == "incident-report.pdf"


class TestFeedSources:
    """issue-local-034: feed_sources was rebuilt from unrelated ingestion-
    pipeline stats into evidence-source aggregation — hunt-scoped now, not
    global, grouped by evidence_items.source_entity."""

    @pytest.mark.asyncio
    async def test_groups_by_source_entity(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await th_db.add_evidence_item(
                pkg["id"], item_type="url", label="a", source_entity="evil-example.com"
            )
            await th_db.add_evidence_item(
                pkg["id"], item_type="url", label="b", source_entity="evil-example.com"
            )
            await th_db.add_evidence_item(
                pkg["id"], item_type="manual_text", label="c", source_entity="Acme Corp"
            )
            rows = await th_db.list_explorer_rows("feed_sources")

        by_name = {r["name"]: r for r in rows}
        assert by_name["evil-example.com"]["count"] == 2
        assert by_name["Acme Corp"]["count"] == 1
        assert by_name["evil-example.com"]["sources"][0]["id"] == pkg["id"]

    @pytest.mark.asyncio
    async def test_unresolved_source_entity_falls_back_to_type_bucket(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await th_db.add_evidence_item(pkg["id"], item_type="file", label="unresolved.pdf")
            rows = await th_db.list_explorer_rows("feed_sources")

        assert len(rows) == 1
        assert "unidentified source" in rows[0]["name"].lower()
        assert rows[0]["count"] == 1

    @pytest.mark.asyncio
    async def test_search_matches_entity_name(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await th_db.add_evidence_item(
                pkg["id"], item_type="url", label="a", source_entity="evil-example.com"
            )
            await th_db.add_evidence_item(
                pkg["id"], item_type="manual_text", label="b", source_entity="Acme Corp"
            )
            matched = await th_db.list_explorer_rows("feed_sources", search="acme")

        assert len(matched) == 1
        assert matched[0]["name"] == "Acme Corp"


class TestIocs:
    @pytest.mark.asyncio
    async def test_lists_extracted_iocs(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            ev = await th_db.add_evidence_item(pkg["id"], item_type="file")
            await th_db.add_extracted_iocs(
                pkg["id"], ev["id"], [{"ioc": "1.2.3.4", "ioc_type": "ip", "action": "keep"}]
            )
            rows = await th_db.list_explorer_rows("iocs")

        assert len(rows) == 1
        assert rows[0]["ioc"] == "1.2.3.4"
        assert rows[0]["ioc_type"] == "ip"
        assert rows[0]["action"] == "keep"

    @pytest.mark.asyncio
    async def test_run_id_and_display_exposed(self, db_path: Path) -> None:
        # issue-local-034: run_id existed on extracted_iocs but was dropped
        # before reaching the frontend — needed for the Data Explorer Run
        # column's deep link.
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(db_path, pkg["id"], run_id="run-1")
            ev = await th_db.add_evidence_item(pkg["id"], item_type="file")
            await th_db.add_extracted_iocs(
                pkg["id"],
                ev["id"],
                [{"ioc": "1.2.3.4", "ioc_type": "ip", "action": "keep"}],
                run_id="run-1",
            )
            rows = await th_db.list_explorer_rows("iocs")

        assert rows[0]["run_id"] == "run-1"
        assert rows[0]["run_id_display"]

    @pytest.mark.asyncio
    async def test_search_matches_own_ioc_not_sibling_package(self, db_path: Path) -> None:
        # issue-local-034 regression: previously an IOC search only worked
        # via the PARENT PACKAGE's own broad match — a package with no
        # name/description/blob match but a genuinely-matching IOC value
        # would return nothing.
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("Alpha", "")
            pkg_b = await th_db.create_hunt_package("Beta", "")
            ev_a = await th_db.add_evidence_item(pkg_a["id"], item_type="file")
            ev_b = await th_db.add_evidence_item(pkg_b["id"], item_type="file")
            await th_db.add_extracted_iocs(
                pkg_a["id"],
                ev_a["id"],
                [{"ioc": "evil.com", "ioc_type": "domain", "action": "keep"}],
            )
            await th_db.add_extracted_iocs(
                pkg_b["id"],
                ev_b["id"],
                [{"ioc": "benign.com", "ioc_type": "domain", "action": "keep"}],
            )
            rows = await th_db.list_explorer_rows("iocs", search="evil")

        assert len(rows) == 1
        assert rows[0]["ioc"] == "evil.com"


class TestSiemSearches:
    @pytest.mark.asyncio
    async def test_lists_task_results(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await th_db.create_task_result(pkg["id"], task_type="siem_search", status="completed")
            rows = await th_db.list_explorer_rows("siem_searches")

        assert len(rows) == 1
        assert rows[0]["status"] == "completed"
        assert rows[0]["hunt_name"] == "Hunt"

    @pytest.mark.asyncio
    async def test_search_matches_own_fields_not_sibling_package(self, db_path: Path) -> None:
        # issue-local-034 regression: siem_searches had NO fields referenced
        # by the package-level match at all — search was a complete no-op.
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("Alpha", "")
            pkg_b = await th_db.create_hunt_package("Beta", "")
            await th_db.create_task_result(
                pkg_a["id"],
                task_type="siem_search",
                status="completed",
                siem_connector="splunk-prod",
            )
            await th_db.create_task_result(
                pkg_b["id"], task_type="siem_search", status="completed", siem_connector="other"
            )
            rows = await th_db.list_explorer_rows("siem_searches", search="splunk-prod")

        assert len(rows) == 1
        assert rows[0]["siem_connector"] == "splunk-prod"


class TestHypotheses:
    @pytest.mark.asyncio
    async def test_flattens_hypotheses_across_runs(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(
                db_path,
                pkg["id"],
                run_id="run-1",
                hypotheses=[
                    {"id": "H1", "title": "Phishing", "relevance": "high", "confidence": 80},
                    {
                        "id": "H2",
                        "title": "Lateral movement",
                        "relevance": "low",
                        "discarded": True,
                    },
                ],
            )
            rows = await th_db.list_explorer_rows("hypotheses")

        assert len(rows) == 2
        titles = {r["title"] for r in rows}
        assert titles == {"Phishing", "Lateral movement"}
        phishing = next(r for r in rows if r["title"] == "Phishing")
        assert phishing["relevance"] == "high"
        assert phishing["confidence"] == 80
        assert phishing["discarded"] is False
        lateral = next(r for r in rows if r["title"] == "Lateral movement")
        assert lateral["discarded"] is True

    @pytest.mark.asyncio
    async def test_malformed_json_is_skipped_not_raised(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, hypotheses, created_at) "
                    "VALUES (?,?,?,?)",
                    ("run-bad", pkg["id"], "not-json", "2026-01-01T00:00:00Z"),
                )
                await db.commit()
            rows = await th_db.list_explorer_rows("hypotheses")

        assert rows == []


class TestHuntingLeadsAndQueries:
    @pytest.mark.asyncio
    async def test_hunting_leads_include_priority(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(
                db_path,
                pkg["id"],
                run_id="run-1",
                hunting_leads=[{"id": "L1", "title": "Check DNS logs", "priority": "high"}],
            )
            rows = await th_db.list_explorer_rows("hunting_leads")

        assert len(rows) == 1
        assert rows[0]["title"] == "Check DNS logs"
        assert rows[0]["priority"] == "high"
        assert rows[0]["run_id"] == "run-1"
        assert rows[0]["run_id_display"]

    @pytest.mark.asyncio
    async def test_hunting_leads_search_matches_own_title_not_sibling_package(
        self, db_path: Path
    ) -> None:
        # issue-local-034 regression: hunting_leads (r.hunting_leads) was
        # never referenced by the package-level match at all — a complete
        # no-op beyond incidental package name/description matches.
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("Alpha", "")
            pkg_b = await th_db.create_hunt_package("Beta", "")
            await _seed_run(
                db_path,
                pkg_a["id"],
                run_id="run-a",
                hunting_leads=[{"id": "L1", "title": "Check DNS logs", "priority": "high"}],
            )
            await _seed_run(
                db_path,
                pkg_b["id"],
                run_id="run-b",
                hunting_leads=[{"id": "L2", "title": "Review firewall rules", "priority": "low"}],
            )
            rows = await th_db.list_explorer_rows("hunting_leads", search="DNS")

        assert len(rows) == 1
        assert rows[0]["title"] == "Check DNS logs"

    @pytest.mark.asyncio
    async def test_queries_include_language_and_text(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await _seed_run(
                db_path,
                pkg["id"],
                run_id="run-1",
                query_drafts=[
                    {"id": "Q1", "title": "Find beacons", "language": "spl", "query": "index=main"}
                ],
            )
            rows = await th_db.list_explorer_rows("queries")

        assert len(rows) == 1
        assert rows[0]["language"] == "spl"
        assert rows[0]["query"] == "index=main"


class TestThreatIntelCategories:
    @pytest.mark.asyncio
    async def test_threat_actors_filtered_by_name_not_date(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("Hunt", "")
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id=None,
                threat_actors=[{"name": "APT-Test"}],
                attribution=None,
                malware_families=["msaRAT"],
                campaigns=[{"name": "Operation X"}],
                related_vendors=[],
                correlated_iocs=[],
                summary="",
                full_analysis={},
            )

            actors = await th_db.list_explorer_rows("threat_actors")
            families = await th_db.list_explorer_rows("malware_families", search="msa")
            campaigns_no_match = await th_db.list_explorer_rows("campaigns", search="nonexistent")

        assert len(actors) == 1 and actors[0]["name"] == "APT-Test"
        assert len(families) == 1 and families[0]["name"] == "msaRAT"
        assert campaigns_no_match == []


class TestRoute:
    @pytest.mark.asyncio
    async def test_route_returns_rows(self, db_path: Path) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.create_hunt_package("Hunt", "")
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/threat-hunting/explorer/hunts")

        assert resp.status_code == 200
        assert len(resp.json()) == 1

    @pytest.mark.asyncio
    async def test_unknown_category_404s(self, db_path: Path) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/threat-hunting/explorer/nonsense")

        assert resp.status_code == 404
