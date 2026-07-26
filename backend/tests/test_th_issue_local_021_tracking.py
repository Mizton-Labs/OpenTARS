"""
Tests for issue-local-021 Part B: the Threat Intel Tracking dashboard's
backend — migration v8 (excluded_from_correlation), the cross-hunt
aggregation functions (list_correlated_iocs, aggregate_threat_actors/
campaigns/malware_families/ttps, list_tracking_hunts), and the new
/tracking/* API routes.
"""

from __future__ import annotations

import json
import sqlite3
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


async def _add_iocs(
    pkg_id: str, evidence_id: str, iocs: list[dict], run_id: str | None = None
) -> None:
    await th_db.add_extracted_iocs(pkg_id, evidence_id, iocs, run_id=run_id)


class TestSchemaV8Migration:
    @pytest.mark.asyncio
    async def test_fresh_db_has_excluded_column_default_zero(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            assert pkg["excluded_from_correlation"] == 0

        conn = sqlite3.connect(db_path)
        version = conn.execute("SELECT version FROM th_schema_version LIMIT 1").fetchone()[0]
        conn.close()
        assert version == th_db._TH_SCHEMA_VERSION

    @pytest.mark.asyncio
    async def test_v7_db_migrates_to_v8_with_column(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            async with aiosqlite.connect(db_path) as db:
                await db.execute("UPDATE th_schema_version SET version = 7")
                await db.commit()

            await th_db.init_threat_hunting_db()

            pkg = await th_db.create_hunt_package("pkg", "")
            assert pkg["excluded_from_correlation"] == 0

        conn = sqlite3.connect(db_path)
        version = conn.execute("SELECT version FROM th_schema_version LIMIT 1").fetchone()[0]
        conn.close()
        assert version == th_db._TH_SCHEMA_VERSION


class TestSetHuntCorrelationExcluded:
    @pytest.mark.asyncio
    async def test_toggle_excluded_flag(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.set_hunt_correlation_excluded(pkg["id"], True)
            updated = await th_db.get_hunt_package(pkg["id"])
            assert updated["excluded_from_correlation"] == 1

            await th_db.set_hunt_correlation_excluded(pkg["id"], False)
            updated = await th_db.get_hunt_package(pkg["id"])
            assert updated["excluded_from_correlation"] == 0


class TestListCorrelatedIocs:
    @pytest.mark.asyncio
    async def test_groups_ioc_across_hunts_with_provenance(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("Hunt A", "")
            pkg_b = await th_db.create_hunt_package("Hunt B", "")
            await _add_iocs(
                pkg_a["id"],
                "ev1",
                [
                    {
                        "ioc": "evil.example",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.1,
                    }
                ],
            )
            await _add_iocs(
                pkg_b["id"],
                "ev2",
                [
                    {
                        "ioc": "evil.example",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.1,
                    }
                ],
            )

            result = await th_db.list_correlated_iocs()

            assert len(result) == 1
            assert result[0]["ioc"] == "evil.example"
            assert result[0]["hunt_count"] == 2
            names = {h["name"] for h in result[0]["hunt_packages"]}
            assert names == {"Hunt A", "Hunt B"}

    @pytest.mark.asyncio
    async def test_excludes_removed_action_iocs(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _add_iocs(
                pkg["id"],
                "ev1",
                [
                    {
                        "ioc": "gone.example",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.9,
                    }
                ],
                run_id="run-1",
            )
            await th_db.update_ioc_actions("run-1", [("gone.example", "domain", "remove")])

            result = await th_db.list_correlated_iocs()
            assert result == []

    @pytest.mark.asyncio
    async def test_excludes_flagged_hunt_packages(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _add_iocs(
                pkg["id"],
                "ev1",
                [
                    {
                        "ioc": "excluded.example",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.1,
                    }
                ],
            )
            await th_db.set_hunt_correlation_excluded(pkg["id"], True)

            result = await th_db.list_correlated_iocs()
            assert result == []

    @pytest.mark.asyncio
    async def test_ioc_type_filter_isolates_cves(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _add_iocs(
                pkg["id"],
                "ev1",
                [
                    {
                        "ioc": "CVE-2023-12345",
                        "ioc_type": "cve",
                        "ioc_description": "",
                        "noise_score": 0.0,
                    },
                    {
                        "ioc": "evil.example",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.0,
                    },
                ],
            )

            cves = await th_db.list_correlated_iocs(ioc_type="cve")
            assert [c["ioc"] for c in cves] == ["CVE-2023-12345"]

    @pytest.mark.asyncio
    async def test_search_filters_by_substring(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _add_iocs(
                pkg["id"],
                "ev1",
                [
                    {
                        "ioc": "malicious-domain.biz",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.0,
                    },
                    {
                        "ioc": "other.example",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.0,
                    },
                ],
            )
            result = await th_db.list_correlated_iocs(search="malicious")
            assert [r["ioc"] for r in result] == ["malicious-domain.biz"]


class TestAggregateThreatActorsCampaignsMalware:
    @pytest.mark.asyncio
    async def test_dedupes_actor_across_hunts_case_insensitive(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("Hunt A", "")
            pkg_b = await th_db.create_hunt_package("Hunt B", "")
            await th_db.create_threat_intel_analysis(
                pkg_a["id"],
                run_id="run-a",
                threat_actors=[{"name": "FIN7", "confidence": "high"}],
                attribution=None,
                malware_families=["Carbanak"],
                campaigns=[{"name": "RetailHeist"}],
                related_vendors=[],
                correlated_iocs=[],
                summary="",
                full_analysis={},
            )
            await th_db.create_threat_intel_analysis(
                pkg_b["id"],
                run_id="run-b",
                threat_actors=[{"name": "fin7", "confidence": "medium"}],
                attribution=None,
                malware_families=["Carbanak"],
                campaigns=[],
                related_vendors=[],
                correlated_iocs=[],
                summary="",
                full_analysis={},
            )

            actors = await th_db.aggregate_threat_actors()
            assert len(actors) == 1
            assert actors[0]["name"] in ("FIN7", "fin7")
            assert len(actors[0]["sources"]) == 2

            families = await th_db.aggregate_malware_families()
            assert len(families) == 1
            assert len(families[0]["sources"]) == 2

            campaigns = await th_db.aggregate_campaigns()
            assert len(campaigns) == 1
            assert len(campaigns[0]["sources"]) == 1

    @pytest.mark.asyncio
    async def test_uses_latest_analysis_per_package(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id="run-1",
                threat_actors=[{"name": "OldActor"}],
                attribution=None,
                malware_families=[],
                campaigns=[],
                related_vendors=[],
                correlated_iocs=[],
                summary="",
                full_analysis={},
            )
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id="run-2",
                threat_actors=[{"name": "NewActor"}],
                attribution=None,
                malware_families=[],
                campaigns=[],
                related_vendors=[],
                correlated_iocs=[],
                summary="",
                full_analysis={},
            )

            actors = await th_db.aggregate_threat_actors()
            names = {a["name"] for a in actors}
            assert names == {"NewActor"}

    @pytest.mark.asyncio
    async def test_excludes_flagged_hunt_packages(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id="run-1",
                threat_actors=[{"name": "Actor"}],
                attribution=None,
                malware_families=[],
                campaigns=[],
                related_vendors=[],
                correlated_iocs=[],
                summary="",
                full_analysis={},
            )
            await th_db.set_hunt_correlation_excluded(pkg["id"], True)

            assert await th_db.aggregate_threat_actors() == []


class TestAggregateTtps:
    @pytest.mark.asyncio
    async def test_dedupes_technique_across_hunts(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("Hunt A", "")
            pkg_b = await th_db.create_hunt_package("Hunt B", "")
            async with aiosqlite.connect(db_path) as db:
                for pkg, run_id in ((pkg_a, "run-a"), (pkg_b, "run-b")):
                    await db.execute(
                        "INSERT INTO hunting_packages (id, hunt_package_id, ttp_analysis, created_at) "
                        "VALUES (?,?,?,?)",
                        (
                            run_id,
                            pkg["id"],
                            json.dumps(
                                {
                                    "techniques": [
                                        {
                                            "technique_id": "T1059",
                                            "technique_name": "CLI",
                                            "tactic": "Execution",
                                        }
                                    ]
                                }
                            ),
                            "2026-01-01T00:00:00Z",
                        ),
                    )
                await db.commit()

            ttps = await th_db.aggregate_ttps()
            assert len(ttps) == 1
            assert ttps[0]["technique_id"] == "T1059"
            assert len(ttps[0]["sources"]) == 2


class TestListTrackingHunts:
    @pytest.mark.asyncio
    async def test_lists_hunts_with_counts_and_excluded_flag(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _add_iocs(
                pkg["id"],
                "ev1",
                [
                    {
                        "ioc": "x.example",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.0,
                    }
                ],
            )

            hunts = await th_db.list_tracking_hunts()
            assert len(hunts) == 1
            assert hunts[0]["ioc_count"] == 1
            assert hunts[0]["excluded_from_correlation"] is False
            assert hunts[0]["has_threat_intel"] is False

    @pytest.mark.asyncio
    async def test_excludes_archived_hunts(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.update_hunt_package(pkg["id"], status="archived")
            assert await th_db.list_tracking_hunts() == []


class TestTrackingRoutes:
    @pytest.mark.asyncio
    async def test_dashboard_route_returns_all_panels(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            client = TestClient(app)
            resp = client.get("/api/threat-hunting/tracking/dashboard")
            assert resp.status_code == 200
            body = resp.json()
            for key in ("iocs", "cves", "threat_actors", "campaigns", "malware_families", "ttps"):
                assert key in body

    @pytest.mark.asyncio
    async def test_hunts_route_and_exclude_toggle(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)

            resp = client.get("/api/threat-hunting/tracking/hunts")
            assert resp.status_code == 200
            assert len(resp.json()) == 1

            resp = client.post(
                f"/api/threat-hunting/tracking/hunts/{pkg['id']}/exclude", json={"excluded": True}
            )
            assert resp.status_code == 200
            assert resp.json()["excluded_from_correlation"] == 1

    @pytest.mark.asyncio
    async def test_delete_hunt_route_archives_package(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)

            resp = client.delete(f"/api/threat-hunting/tracking/hunts/{pkg['id']}")
            assert resp.status_code == 204

            updated = await th_db.get_hunt_package(pkg["id"])
            assert updated["status"] == "archived"

    @pytest.mark.asyncio
    async def test_hunt_routes_404_for_unknown_package(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            client = TestClient(app)
            resp = client.post(
                "/api/threat-hunting/tracking/hunts/no-such-pkg/exclude", json={"excluded": True}
            )
            assert resp.status_code == 404
