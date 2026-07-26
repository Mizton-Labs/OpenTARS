"""
Tests for issue-local-020 Part C: the Threat Hunt Intelligence Analyst
(backend.threat_hunting.agents.nodes.threat_intel_analyst), its executor.py
call site, and the new threat-intel API routes.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents.nodes import threat_intel_analyst


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", path):
        await th_db.init_threat_hunting_db()
        yield path


async def _seed_run(
    pkg_id: str,
    run_id: str,
    *,
    threat_context: dict | None = None,
    hypotheses: list | None = None,
    ttp_analysis: dict | None = None,
) -> None:
    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        await db.execute(
            "INSERT INTO hunting_packages (id, hunt_package_id, threat_context, hypotheses, "
            "ttp_analysis, created_at) VALUES (?,?,?,?,?,?)",
            (
                run_id,
                pkg_id,
                json.dumps(threat_context) if threat_context is not None else None,
                json.dumps(hypotheses) if hypotheses is not None else None,
                json.dumps(ttp_analysis) if ttp_analysis is not None else None,
                "2026-01-01T00:00:00Z",
            ),
        )
        await db.commit()


LLM_RESPONSE = json.dumps(
    {
        "threat_actors": [{"name": "FIN7", "confidence": "high", "rationale": "matches TTPs"}],
        "attribution": {"assessment": "FIN7", "confidence": "high", "rationale": "x"},
        "malware_families": ["Carbanak"],
        "campaigns": [{"name": "RetailHeist", "description": "..."}],
        "related_vendors": [],
        "correlated_ioc_notes": "shared IOC found",
        "summary": "LLM summary",
    }
)


class TestAnalyzeThreatIntel:
    @pytest.mark.asyncio
    async def test_llm_enriched_result_persisted(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(
                pkg["id"],
                "run-1",
                threat_context={
                    "threat_actor": "FIN7",
                    "campaign_name": "RetailHeist",
                    "malware_families": ["Carbanak"],
                    "summary": "targeted retail POS",
                    "confidence": "medium",
                },
                hypotheses=[{"title": "H1"}],
                ttp_analysis={"techniques": []},
            )

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                result = await threat_intel_analyst.analyze_threat_intel(pkg["id"], run_id="run-1")

            assert result is not None
            assert result["threat_actors"][0]["name"] == "FIN7"
            assert result["malware_families"] == ["Carbanak"]
            assert result["summary"] == "LLM summary"

            persisted = await th_db.get_threat_intel_analysis_by_run("run-1")
            assert persisted is not None
            assert persisted["summary"] == "LLM summary"

    @pytest.mark.asyncio
    async def test_llm_failure_falls_back_to_deterministic_fields(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(
                pkg["id"],
                "run-1",
                threat_context={
                    "threat_actor": "APT28",
                    "malware_families": ["X-Agent"],
                    "confidence": "low",
                },
            )

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(side_effect=Exception("LLM unavailable")),
            ):
                result = await threat_intel_analyst.analyze_threat_intel(pkg["id"], run_id="run-1")

            assert result is not None
            assert result["threat_actors"][0]["name"] == "APT28"
            assert result["malware_families"] == ["X-Agent"]

    @pytest.mark.asyncio
    async def test_returns_none_for_missing_run(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            result = await threat_intel_analyst.analyze_threat_intel(
                pkg["id"], run_id="no-such-run"
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_correlated_iocs_come_from_db_not_llm(self, db_path: Path) -> None:
        """The LLM's output must never override the DB-derived correlated_iocs
        list — even if an (implausible) LLM response tried to include one."""
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg_a = await th_db.create_hunt_package("A", "")
            pkg_b = await th_db.create_hunt_package("B", "")
            await _seed_run(pkg_a["id"], "run-a", threat_context={})
            await th_db.add_extracted_iocs(
                pkg_a["id"],
                "ev1",
                [
                    {
                        "ioc": "shared.example",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.1,
                    }
                ],
                run_id="run-a",
            )
            await th_db.add_extracted_iocs(
                pkg_b["id"],
                "ev2",
                [
                    {
                        "ioc": "shared.example",
                        "ioc_type": "domain",
                        "ioc_description": "",
                        "noise_score": 0.1,
                    }
                ],
            )

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(return_value=LLM_RESPONSE),
            ):
                result = await threat_intel_analyst.analyze_threat_intel(
                    pkg_a["id"], run_id="run-a"
                )

            assert result is not None
            assert len(result["correlated_iocs"]) == 1
            assert result["correlated_iocs"][0]["hunt_package_id"] == pkg_b["id"]

    @pytest.mark.asyncio
    async def test_no_threat_actor_gives_empty_threat_actors_list(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={})

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(side_effect=Exception("down")),
            ):
                result = await threat_intel_analyst.analyze_threat_intel(pkg["id"], run_id="run-1")

            assert result is not None
            assert result["threat_actors"] == []
            assert result["attribution"] is None

    @pytest.mark.asyncio
    async def test_step_log_appended(self, db_path: Path) -> None:
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"threat_actor": "X"})

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(side_effect=Exception("down")),
            ):
                await threat_intel_analyst.analyze_threat_intel(pkg["id"], run_id="run-1")

            run = await th_db.get_generation_run("run-1")
            steps = {s.get("step") for s in (run.get("step_logs") or [])}
            # issue-local-022: step id now includes the phase (default "final").
            assert "threat_intel_final" in steps


def test_executor_calls_threat_intel_after_completed_before_report() -> None:
    """_run_execution's source must call analyze_threat_intel(...) — after
    marking the package 'completed' and before write_report(...) — matching
    the "after execution, before the report" placement from the spec."""
    import inspect

    from backend.threat_hunting.siem.executor import _run_execution

    source = inspect.getsource(_run_execution)
    assert "analyze_threat_intel" in source

    completed_idx = source.index('status="completed"')
    intel_idx = source.index("analyze_threat_intel")
    report_idx = source.index("write_report(")
    assert completed_idx < intel_idx < report_idx


class TestThreatIntelRoutes:
    @pytest.mark.asyncio
    async def test_get_run_threat_intel_404_when_absent(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)
            resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/runs/run-1/threat-intel")
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_run_threat_intel_200_when_present(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await th_db.create_threat_intel_analysis(
                pkg["id"],
                run_id="run-1",
                threat_actors=[{"name": "X"}],
                attribution=None,
                malware_families=[],
                campaigns=[],
                related_vendors=[],
                correlated_iocs=[],
                summary="s",
                full_analysis={},
            )
            client = TestClient(app)
            resp = client.get(f"/api/threat-hunting/packages/{pkg['id']}/runs/run-1/threat-intel")
            assert resp.status_code == 200
            assert resp.json()["summary"] == "s"

    @pytest.mark.asyncio
    async def test_post_trigger_route_runs_analysis(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            await _seed_run(pkg["id"], "run-1", threat_context={"threat_actor": "APT1"})

            with patch(
                "backend.threat_hunting.agents.nodes.threat_intel_analyst.call_llm",
                new=AsyncMock(side_effect=Exception("no llm in test")),
            ):
                client = TestClient(app)
                resp = client.post(
                    f"/api/threat-hunting/packages/{pkg['id']}/runs/run-1/threat-intel"
                )
            assert resp.status_code == 201, resp.text
            assert resp.json()["threat_actors"][0]["name"] == "APT1"

    @pytest.mark.asyncio
    async def test_post_trigger_route_404_for_unknown_run(self, db_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        with patch.object(th_db, "_TH_DB_PATH", db_path):
            pkg = await th_db.create_hunt_package("pkg", "")
            client = TestClient(app)
            resp = client.post(
                f"/api/threat-hunting/packages/{pkg['id']}/runs/no-such-run/threat-intel"
            )
            assert resp.status_code == 404
