"""
Tests for issue-local-004 features:
  - loader.py: four new settings (agent_verbosity, agent_visualization,
    th_research_effort, th_report_formats)
  - routes_app.py: GET/PUT /api/app/agent-verbosity etc.
  - effort_profile.py: correct knobs per effort level
  - DB schema v3 migration: new columns present
  - report_writer.py: render_report_markdown / render_report_pdf
  - TH routes: /report/markdown and /report/pdf endpoints
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# ── loader.py — new settings ──────────────────────────────────────────────────


class TestLoaderAgentVerbosity:
    def test_load_default(self, tmp_path: Path) -> None:
        from backend.config.loader import load_agent_verbosity

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            assert load_agent_verbosity() == "info"

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        from backend.config.loader import load_agent_verbosity, save_agent_verbosity

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            save_agent_verbosity("verbose")
            assert load_agent_verbosity() == "verbose"
            save_agent_verbosity("debug")
            assert load_agent_verbosity() == "debug"

    def test_invalid_raises(self, tmp_path: Path) -> None:
        from backend.config.loader import save_agent_verbosity

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            with pytest.raises(ValueError, match="agent_workflow_verbosity"):
                save_agent_verbosity("extreme")

    def test_bad_yaml_falls_back_to_default(self, tmp_path: Path) -> None:
        from backend.config.loader import load_agent_verbosity

        p = tmp_path / "app.yaml"
        p.write_text("agent_workflow_verbosity: nonsense\n")
        with patch("backend.config.loader.APP_CONFIG_PATH", p):
            assert load_agent_verbosity() == "info"


class TestLoaderAgentVisualization:
    def test_load_default(self, tmp_path: Path) -> None:
        from backend.config.loader import load_agent_visualization

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            assert load_agent_visualization() == "timeline"

    def test_save_and_load(self, tmp_path: Path) -> None:
        from backend.config.loader import load_agent_visualization, save_agent_visualization

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            save_agent_visualization("mermaid")
            assert load_agent_visualization() == "mermaid"
            save_agent_visualization("reactflow")
            assert load_agent_visualization() == "reactflow"

    def test_invalid_raises(self, tmp_path: Path) -> None:
        from backend.config.loader import save_agent_visualization

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            with pytest.raises(ValueError):
                save_agent_visualization("d3")


class TestLoaderTHResearchEffort:
    def test_default(self, tmp_path: Path) -> None:
        from backend.config.loader import load_th_research_effort

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            assert load_th_research_effort() == "medium"

    def test_high_and_low(self, tmp_path: Path) -> None:
        from backend.config.loader import load_th_research_effort, save_th_research_effort

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            save_th_research_effort("high")
            assert load_th_research_effort() == "high"
            save_th_research_effort("low")
            assert load_th_research_effort() == "low"

    def test_invalid_raises(self, tmp_path: Path) -> None:
        from backend.config.loader import save_th_research_effort

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            with pytest.raises(ValueError):
                save_th_research_effort("ultra")


class TestLoaderTHReportFormats:
    def test_default_both_true(self, tmp_path: Path) -> None:
        from backend.config.loader import load_th_report_formats

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            result = load_th_report_formats()
            assert result == {"pdf": True, "markdown": True}

    def test_save_and_load(self, tmp_path: Path) -> None:
        from backend.config.loader import load_th_report_formats, save_th_report_formats

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            save_th_report_formats({"pdf": False, "markdown": True})
            result = load_th_report_formats()
            assert result["pdf"] is False
            assert result["markdown"] is True

    def test_unknown_key_raises(self, tmp_path: Path) -> None:
        from backend.config.loader import save_th_report_formats

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            with pytest.raises(ValueError, match="Unknown report format key"):
                save_th_report_formats({"pdf": True, "xml": True})  # type: ignore[arg-type]

    def test_non_bool_raises(self, tmp_path: Path) -> None:
        from backend.config.loader import save_th_report_formats

        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            with pytest.raises(ValueError):
                save_th_report_formats({"pdf": 1, "markdown": True})  # type: ignore[arg-type]


# ── routes_app.py — new endpoints ────────────────────────────────────────────


def _test_client():
    from fastapi.testclient import TestClient

    from backend.main import app

    return TestClient(app)


class TestRoutesAgentVerbosity:
    def test_get_returns_default(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.get("/api/app/agent-verbosity")
        assert r.status_code == 200
        assert r.json()["agent_workflow_verbosity"] == "info"

    def test_put_valid(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.put(
                "/api/app/agent-verbosity",
                json={"agent_workflow_verbosity": "verbose"},
            )
        assert r.status_code == 200
        assert r.json()["agent_workflow_verbosity"] == "verbose"

    def test_put_invalid_400(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.put(
                "/api/app/agent-verbosity",
                json={"agent_workflow_verbosity": "extreme"},
            )
        assert r.status_code == 400

    def test_put_non_string_400(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.put(
                "/api/app/agent-verbosity",
                json={"agent_workflow_verbosity": 3},
            )
        assert r.status_code == 400


class TestRoutesAgentVisualization:
    def test_get_returns_default(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.get("/api/app/agent-visualization")
        assert r.status_code == 200
        assert r.json()["agent_workflow_visualization"] == "timeline"

    def test_put_mermaid(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.put(
                "/api/app/agent-visualization",
                json={"agent_workflow_visualization": "mermaid"},
            )
        assert r.status_code == 200
        assert r.json()["agent_workflow_visualization"] == "mermaid"


class TestRoutesThResearchEffort:
    def test_get_default(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.get("/api/app/th-research-effort")
        assert r.status_code == 200
        assert r.json()["th_research_effort"] == "medium"

    def test_put_high(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.put(
                "/api/app/th-research-effort",
                json={"th_research_effort": "high"},
            )
        assert r.status_code == 200

    def test_put_invalid_400(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.put(
                "/api/app/th-research-effort",
                json={"th_research_effort": "ultra"},
            )
        assert r.status_code == 400


class TestRoutesThReportFormats:
    def test_get_default(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.get("/api/app/th-report-formats")
        assert r.status_code == 200
        assert r.json()["th_report_formats"] == {"pdf": True, "markdown": True}

    def test_put_valid(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.put(
                "/api/app/th-report-formats",
                json={"th_report_formats": {"pdf": False, "markdown": True}},
            )
        assert r.status_code == 200

    def test_put_non_dict_400(self, tmp_path: Path) -> None:
        client = _test_client()
        with patch("backend.config.loader.APP_CONFIG_PATH", tmp_path / "app.yaml"):
            r = client.put(
                "/api/app/th-report-formats",
                json={"th_report_formats": "all"},
            )
        assert r.status_code == 400


# ── effort_profile.py — knobs per level ──────────────────────────────────────


class TestEffortProfile:
    def test_medium_defaults(self) -> None:
        from backend.threat_hunting.agents.effort_profile import get_effort_profile

        p = get_effort_profile("medium")
        assert p["hypotheses_range"] == (3, 6)
        assert p["leads_range"] == (2, 4)
        assert p["ioc_sample_limit"] == 20

    def test_high_more_than_medium(self) -> None:
        from backend.threat_hunting.agents.effort_profile import get_effort_profile

        h = get_effort_profile("high")
        m = get_effort_profile("medium")
        assert h["hypothesis_tokens"] > m["hypothesis_tokens"]
        assert h["ioc_sample_limit"] > m["ioc_sample_limit"]
        assert h["retrohunt_ioc_cap"] > m["retrohunt_ioc_cap"]
        h_min, h_max = h["hypotheses_range"]
        m_min, m_max = m["hypotheses_range"]
        assert h_min >= m_min
        assert h_max >= m_max

    def test_low_less_than_medium(self) -> None:
        from backend.threat_hunting.agents.effort_profile import get_effort_profile

        lo = get_effort_profile("low")
        m = get_effort_profile("medium")
        assert lo["hypothesis_tokens"] < m["hypothesis_tokens"]
        assert lo["ioc_sample_limit"] < m["ioc_sample_limit"]

    def test_unknown_falls_back_to_medium(self) -> None:
        from backend.threat_hunting.agents.effort_profile import get_effort_profile

        assert get_effort_profile("ultra") == get_effort_profile("medium")
        assert get_effort_profile(None) == get_effort_profile("medium")


# ── DB schema v3 migration ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_db_schema_v3_fresh_init(tmp_path: Path) -> None:
    """Fresh DB initialisation must include the v3 columns."""
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "test_th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hunting_packages)")}
    conn.close()

    assert "current_step" in cols
    assert "completed_steps" in cols
    assert "step_logs" in cols
    assert "research_effort" in cols


@pytest.mark.asyncio
async def test_db_schema_v3_migration_from_v2(tmp_path: Path) -> None:
    """A v2 schema must gain the v3 columns after migration."""
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "test_th_v2.db"

    # Create a v2 schema manually
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE th_schema_version (version INTEGER NOT NULL)""")
    conn.execute("INSERT INTO th_schema_version VALUES (2)")
    conn.execute(
        """CREATE TABLE hunting_packages (
            id TEXT PRIMARY KEY,
            hunt_package_id TEXT NOT NULL,
            threat_context TEXT, hypotheses TEXT, hunting_leads TEXT,
            deep_retrohunt TEXT, ttp_analysis TEXT, query_drafts TEXT,
            llm_provider TEXT, llm_model TEXT,
            generation_status TEXT, generation_errors TEXT, created_at TEXT NOT NULL
        )"""
    )
    conn.commit()
    conn.close()

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(hunting_packages)")}
    version = conn.execute("SELECT version FROM th_schema_version LIMIT 1").fetchone()[0]
    conn.close()

    assert "current_step" in cols
    assert "completed_steps" in cols
    assert "step_logs" in cols
    assert "research_effort" in cols
    # Schema has since been bumped to v4 (issue-local-005 adds run_id columns)
    assert version >= 3


# ── report_writer — render_report_markdown / render_report_pdf ───────────────


def _sample_full_report() -> dict[str, Any]:
    return {
        "executive_summary": "Test executive summary.",
        "hunt_name": "Test Hunt",
        "hunt_id": "abc-123",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "generated_by": None,
        "package_status": "completed",
        "evidence_summary": {"total_items": 2, "ioc_count": 5, "item_types": ["file", "url"]},
        "threat_context": {
            "summary": "APT28 targeting energy sector.",
            "threat_actor": "APT28",
            "campaign_name": "Energetic Bear",
            "attack_vector": "spearphishing",
            "confidence": "high",
            "malware_families": ["BlackEnergy"],
            "key_observations": ["Lateral movement observed"],
        },
        "hypotheses": [
            {
                "id": "H1",
                "title": "Credential harvesting via spearphishing",
                "description": "...",
                "justification": "IOC overlap with known campaign.",
                "relevance": "high",
                "ioc_basis": [],
            }
        ],
        "hunting_leads": [
            {
                "id": "L1",
                "hypothesis_id": "H1",
                "title": "Email analysis lead",
                "description": "Analyse inbound email headers.",
                "priority": "high",
                "tasks": [
                    {
                        "id": "T1.1",
                        "title": "Check email headers",
                        "description": "...",
                        "datasource": "email",
                        "query_hint": "...",
                    }
                ],
            }
        ],
        "deep_retrohunt_summary": {
            "total_iocs": 10,
            "noisy_iocs": 2,
            "high_noise_iocs": 0,
            "spl_macro_name": "threathunt_ioc_abc123",
            "search_hint": "Search for the IOCs across all log sources.",
        },
        "ttp_analysis": {
            "summary": "Execution via PowerShell.",
            "techniques": [
                {
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                    "tactic": "Execution",
                    "description": "...",
                    "evidence_basis": "...",
                }
            ],
            "detection_opportunities": ["Monitor PowerShell execution"],
        },
        "query_drafts_count": 2,
        "execution_results": [
            {
                "id": "R1",
                "status": "completed",
                "earliest": "-24h",
                "latest": "now",
                "event_count": 3,
                "interpreted_findings": "3 events matched.",
                "completed_at": "2026-01-01T01:00:00+00:00",
            }
        ],
        "recommendations": ["Investigate H1 further.", "Review 3 SIEM events."],
    }


def test_render_report_markdown_contains_key_sections() -> None:
    from backend.threat_hunting.agents.nodes.report_writer import render_report_markdown

    report = _sample_full_report()
    md = render_report_markdown(report)

    assert "# Threat Hunt Report: Test Hunt" in md
    assert "Executive Summary" in md
    assert "Test executive summary" in md
    assert "Hypotheses" in md
    assert "APT28" in md
    assert "PowerShell" in md
    assert "Recommendations" in md
    assert len(md) > 500


def test_render_report_pdf_produces_valid_pdf() -> None:
    pytest.importorskip("reportlab")
    from backend.threat_hunting.agents.nodes.report_writer import render_report_pdf

    report = _sample_full_report()
    pdf_bytes = render_report_pdf(report)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    # PDF magic bytes
    assert pdf_bytes[:4] == b"%PDF"


def test_render_report_pdf_handles_empty_report() -> None:
    pytest.importorskip("reportlab")
    from backend.threat_hunting.agents.nodes.report_writer import render_report_pdf

    pdf_bytes = render_report_pdf({})
    assert pdf_bytes[:4] == b"%PDF"
