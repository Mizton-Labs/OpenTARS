"""Tests for issue-local-015 Part 1: IOC run-scoping, active-cleaning config,
hypothesis confidence/discard, and the /generate run_config passthrough."""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from backend.threat_hunting.iocs import compute_ioc_action

# ── compute_ioc_action ───────────────────────────────────────────────────────


class TestComputeIocAction:
    def test_tagging_only_always_keeps(self):
        ioc = {"ioc": "evil.com", "ioc_type": "domain", "flagged_noisy": True}
        action, reason = compute_ioc_action(
            ioc,
            ioc_mode="tagging_only",
            cleaning_options={"remove_noisy": True, "remove_legit_domains": True},
        )
        assert action == "keep"
        assert reason is None

    def test_active_cleaning_no_toggles_keeps(self):
        ioc = {"ioc": "evil.com", "ioc_type": "domain", "flagged_noisy": True}
        action, reason = compute_ioc_action(ioc, ioc_mode="active_cleaning", cleaning_options={})
        assert action == "keep"
        assert reason is None

    def test_remove_noisy(self):
        ioc = {"ioc": "10.0.0.5", "ioc_type": "ip", "flagged_noisy": True}
        action, reason = compute_ioc_action(
            ioc, ioc_mode="active_cleaning", cleaning_options={"remove_noisy": True}
        )
        assert action == "remove"
        assert reason and "remove_noisy" in reason

    def test_remove_noisy_does_not_affect_clean_ioc(self):
        ioc = {"ioc": "203.0.113.5", "ioc_type": "ip", "flagged_noisy": False}
        action, reason = compute_ioc_action(
            ioc, ioc_mode="active_cleaning", cleaning_options={"remove_noisy": True}
        )
        assert action == "keep"
        assert reason is None

    def test_remove_legit_domains(self):
        ioc = {"ioc": "google.com", "ioc_type": "domain", "flagged_noisy": False}
        action, reason = compute_ioc_action(
            ioc, ioc_mode="active_cleaning", cleaning_options={"remove_legit_domains": True}
        )
        assert action == "remove"
        assert reason and "remove_legit_domains" in reason

    def test_remove_legit_domains_does_not_catch_cdn(self):
        ioc = {"ioc": "cloudflare.com", "ioc_type": "domain", "flagged_noisy": False}
        action, reason = compute_ioc_action(
            ioc, ioc_mode="active_cleaning", cleaning_options={"remove_legit_domains": True}
        )
        assert action == "keep"
        assert reason is None

    def test_remove_cdn_ranges(self):
        ioc = {"ioc": "cloudflare.com", "ioc_type": "domain", "flagged_noisy": False}
        action, reason = compute_ioc_action(
            ioc, ioc_mode="active_cleaning", cleaning_options={"remove_cdn_ranges": True}
        )
        assert action == "remove"
        assert reason and "remove_cdn_ranges" in reason

    def test_remove_legit_services(self):
        ioc = {"ioc": "C:\\Windows\\System32\\cmd.exe", "ioc_type": "filepath"}
        action, reason = compute_ioc_action(
            ioc, ioc_mode="active_cleaning", cleaning_options={"remove_legit_services": True}
        )
        assert action == "remove"
        assert reason and "remove_legit_services" in reason

    def test_unrelated_ioc_kept_even_with_all_toggles_on(self):
        ioc = {"ioc": "malicious-c2.example", "ioc_type": "domain", "flagged_noisy": False}
        action, reason = compute_ioc_action(
            ioc,
            ioc_mode="active_cleaning",
            cleaning_options={
                "remove_noisy": True,
                "remove_legit_domains": True,
                "remove_cdn_ranges": True,
                "remove_legit_services": True,
            },
        )
        assert action == "keep"
        assert reason is None

    def test_none_cleaning_options_treated_as_all_off(self):
        ioc = {"ioc": "google.com", "ioc_type": "domain", "flagged_noisy": True}
        action, reason = compute_ioc_action(ioc, ioc_mode="active_cleaning", cleaning_options=None)
        assert action == "keep"
        assert reason is None


# ── DB layer: v5 migration, run-scoped IOCs, hypothesis discard ─────────────


@pytest.mark.asyncio
async def test_schema_v5_fresh_db_has_new_columns(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

    conn = sqlite3.connect(db_path)
    ioc_cols = {row[1] for row in conn.execute("PRAGMA table_info(extracted_iocs)")}
    run_cols = {row[1] for row in conn.execute("PRAGMA table_info(hunting_packages)")}
    version = conn.execute("SELECT version FROM th_schema_version LIMIT 1").fetchone()[0]
    conn.close()

    assert "run_id" in ioc_cols
    assert "action" in ioc_cols
    assert "run_config" in run_cols
    assert version == 5


@pytest.mark.asyncio
async def test_schema_v4_migrates_to_v5_and_backfills_run_id(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"

    # Build a v4 DB by hand (no run_id/action on extracted_iocs, no run_config).
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE th_schema_version (version INTEGER NOT NULL)")
    conn.execute("INSERT INTO th_schema_version (version) VALUES (4)")
    conn.execute(
        """CREATE TABLE hunt_packages (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'draft', created_by TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE evidence_items (
            id TEXT PRIMARY KEY, hunt_package_id TEXT NOT NULL, item_type TEXT NOT NULL,
            label TEXT, source_ref TEXT, content_hash TEXT, mime_type TEXT, fetch_url TEXT,
            final_url TEXT, extracted_text TEXT, parser_used TEXT, parser_version TEXT,
            parse_status TEXT, parse_warnings TEXT, fetch_metadata TEXT,
            watcher_snapshot TEXT, created_at TEXT NOT NULL, provenance_notes TEXT)"""
    )
    conn.execute(
        """CREATE TABLE extracted_iocs (
            id TEXT PRIMARY KEY, evidence_item_id TEXT NOT NULL, hunt_package_id TEXT NOT NULL,
            ioc TEXT NOT NULL, ioc_type TEXT NOT NULL, ioc_description TEXT,
            noise_score REAL DEFAULT 0.0, flagged_noisy INTEGER DEFAULT 0,
            created_at TEXT NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE hunting_packages (
            id TEXT PRIMARY KEY, hunt_package_id TEXT NOT NULL, threat_context TEXT,
            hypotheses TEXT, hunting_leads TEXT, deep_retrohunt TEXT, ttp_analysis TEXT,
            query_drafts TEXT, llm_provider TEXT, llm_model TEXT, generation_status TEXT,
            generation_errors TEXT, created_at TEXT NOT NULL, current_step TEXT,
            completed_steps TEXT, step_logs TEXT, research_effort TEXT)"""
    )
    conn.execute(
        """CREATE TABLE task_results (
            id TEXT PRIMARY KEY, hunt_package_id TEXT NOT NULL, run_id TEXT,
            task_type TEXT NOT NULL, siem_connector TEXT, query_text TEXT, earliest TEXT,
            latest TEXT, hunt_id TEXT, status TEXT NOT NULL, raw_result TEXT,
            interpreted_findings TEXT, confidence REAL, created_at TEXT NOT NULL,
            completed_at TEXT)"""
    )
    conn.execute(
        """CREATE TABLE hunt_reports (
            id TEXT PRIMARY KEY, hunt_package_id TEXT NOT NULL, run_id TEXT,
            executive_summary TEXT, full_report TEXT, created_at TEXT NOT NULL,
            created_by TEXT)"""
    )

    pkg_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())
    ioc_id = str(uuid.uuid4())
    now = "2026-01-01T00:00:00+00:00"
    conn.execute(
        "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) "
        "VALUES (?,?,?,?,?,?)",
        (pkg_id, "test", "", "draft", now, now),
    )
    conn.execute(
        "INSERT INTO hunting_packages (id,hunt_package_id,created_at) VALUES (?,?,?)",
        (run_id, pkg_id, now),
    )
    conn.execute(
        "INSERT INTO evidence_items (id,hunt_package_id,item_type,created_at) VALUES (?,?,?,?)",
        (evidence_id, pkg_id, "file", now),
    )
    conn.execute(
        "INSERT INTO extracted_iocs "
        "(id,evidence_item_id,hunt_package_id,ioc,ioc_type,created_at) VALUES (?,?,?,?,?,?)",
        (ioc_id, evidence_id, pkg_id, "evil.com", "domain", now),
    )
    conn.commit()
    conn.close()

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

    conn = sqlite3.connect(db_path)
    version = conn.execute("SELECT version FROM th_schema_version LIMIT 1").fetchone()[0]
    row = conn.execute(
        "SELECT run_id, action FROM extracted_iocs WHERE id = ?", (ioc_id,)
    ).fetchone()
    conn.close()

    assert version == 5
    assert row[0] == run_id, "pre-v5 IOC row must be backfilled to the latest run for its package"
    assert row[1] == "keep"


@pytest.mark.asyncio
async def test_extracted_iocs_are_independent_per_run(tmp_path: Path) -> None:
    """issue-local-015 anchor fix: two runs of the same package keep separate IOC sets."""
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

        pkg_id = str(uuid.uuid4())
        run_1 = str(uuid.uuid4())
        run_2 = str(uuid.uuid4())
        evidence_id = str(uuid.uuid4())

        await th_db.add_extracted_iocs(
            pkg_id,
            evidence_id,
            [{"ioc": "run1-only.com", "ioc_type": "domain", "noise_score": 0.0}],
            run_id=run_1,
        )
        await th_db.add_extracted_iocs(
            pkg_id,
            evidence_id,
            [{"ioc": "run2-only.com", "ioc_type": "domain", "noise_score": 0.0}],
            run_id=run_2,
        )

        run_1_iocs = await th_db.list_extracted_iocs(pkg_id, run_1)
        run_2_iocs = await th_db.list_extracted_iocs(pkg_id, run_2)

    assert [i["ioc"] for i in run_1_iocs] == ["run1-only.com"]
    assert [i["ioc"] for i in run_2_iocs] == ["run2-only.com"]


@pytest.mark.asyncio
async def test_clear_extracted_iocs_scoped_to_run_does_not_touch_other_runs(
    tmp_path: Path,
) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

        pkg_id = str(uuid.uuid4())
        run_1 = str(uuid.uuid4())
        run_2 = str(uuid.uuid4())
        evidence_id = str(uuid.uuid4())

        await th_db.add_extracted_iocs(
            pkg_id, evidence_id, [{"ioc": "a.com", "ioc_type": "domain"}], run_id=run_1
        )
        await th_db.add_extracted_iocs(
            pkg_id, evidence_id, [{"ioc": "b.com", "ioc_type": "domain"}], run_id=run_2
        )

        deleted = await th_db.clear_extracted_iocs(pkg_id, run_1)
        run_1_iocs = await th_db.list_extracted_iocs(pkg_id, run_1)
        run_2_iocs = await th_db.list_extracted_iocs(pkg_id, run_2)

    assert deleted == 1
    assert run_1_iocs == []
    assert [i["ioc"] for i in run_2_iocs] == ["b.com"]


@pytest.mark.asyncio
async def test_update_ioc_actions(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

        pkg_id = str(uuid.uuid4())
        run_id = str(uuid.uuid4())
        evidence_id = str(uuid.uuid4())

        await th_db.add_extracted_iocs(
            pkg_id,
            evidence_id,
            [
                {"ioc": "keep-me.com", "ioc_type": "domain"},
                {"ioc": "remove-me.com", "ioc_type": "domain"},
            ],
            run_id=run_id,
        )
        await th_db.update_ioc_actions(run_id, [("remove-me.com", "domain", "remove")])

        iocs = await th_db.list_extracted_iocs(pkg_id, run_id)

    by_ioc = {i["ioc"]: i["action"] for i in iocs}
    assert by_ioc["keep-me.com"] == "keep"
    assert by_ioc["remove-me.com"] == "remove"


@pytest.mark.asyncio
async def test_set_hypothesis_discarded_round_trip(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

        pkg_id = str(uuid.uuid4())
        run_id = str(uuid.uuid4())
        now = "2026-01-01T00:00:00+00:00"

        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (pkg_id, "test", "", "draft", now, now),
        )
        import json as _json

        conn.execute(
            "INSERT INTO hunting_packages (id,hunt_package_id,hypotheses,created_at) "
            "VALUES (?,?,?,?)",
            (
                run_id,
                pkg_id,
                _json.dumps([{"id": "H1", "title": "x", "discarded": False}]),
                now,
            ),
        )
        conn.commit()
        conn.close()

        updated = await th_db.set_hypothesis_discarded(run_id, "H1", True)
        assert updated["discarded"] is True

        record = await th_db.get_generation_run(run_id)

    # get_generation_run already parses JSON columns into Python objects.
    assert record["hypotheses"][0]["discarded"] is True


@pytest.mark.asyncio
async def test_set_hypothesis_discarded_unknown_run_returns_none(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        result = await th_db.set_hypothesis_discarded("no-such-run", "H1", True)

    assert result is None


@pytest.mark.asyncio
async def test_set_hunting_lead_discarded_round_trip(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

        pkg_id = str(uuid.uuid4())
        run_id = str(uuid.uuid4())
        now = "2026-01-01T00:00:00+00:00"

        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (pkg_id, "test", "", "draft", now, now),
        )
        import json as _json

        conn.execute(
            "INSERT INTO hunting_packages (id,hunt_package_id,hunting_leads,created_at) "
            "VALUES (?,?,?,?)",
            (
                run_id,
                pkg_id,
                _json.dumps(
                    [{"id": "L1", "hypothesis_id": "H1", "title": "x", "discarded": False}]
                ),
                now,
            ),
        )
        conn.commit()
        conn.close()

        updated = await th_db.set_hunting_lead_discarded(run_id, "L1", True)
        assert updated["discarded"] is True

        record = await th_db.get_generation_run(run_id)

    assert record["hunting_leads"][0]["discarded"] is True


@pytest.mark.asyncio
async def test_set_hunting_lead_discarded_unknown_run_returns_none(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        result = await th_db.set_hunting_lead_discarded("no-such-run", "L1", True)

    assert result is None


class TestHuntingLeadDiscardedDefault:
    @pytest.mark.asyncio
    async def test_llm_discarded_field_is_overridden_to_false(self):
        from backend.threat_hunting.agents.nodes.hunting_lead_planner import hunting_lead_planner

        response = (
            '[{"id":"L1","hypothesis_id":"H1","title":"t","description":"d",'
            '"priority":"high","tasks":[],"discarded":true}]'
        )
        with patch(
            "backend.threat_hunting.agents.nodes.hunting_lead_planner.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await hunting_lead_planner({"research_effort": "medium"})

        assert result["hunting_leads"][0]["discarded"] is False


# ── hypothesis_generator: confidence normalization ──────────────────────────


class TestHypothesisConfidenceNormalization:
    @pytest.mark.asyncio
    async def test_valid_confidence_preserved(self):
        from backend.threat_hunting.agents.nodes.hypothesis_generator import (
            hypothesis_generator,
        )

        response = (
            '[{"id":"H1","title":"t","description":"d","justification":"j",'
            '"relevance":"high","confidence":80,"ioc_basis":[],"suggested_actions":[]}]'
        )
        with patch(
            "backend.threat_hunting.agents.nodes.hypothesis_generator.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await hypothesis_generator({"research_effort": "medium"})

        assert result["hypotheses"][0]["confidence"] == 80
        assert result["hypotheses"][0]["discarded"] is False

    @pytest.mark.asyncio
    async def test_out_of_range_confidence_clamped(self):
        from backend.threat_hunting.agents.nodes.hypothesis_generator import (
            hypothesis_generator,
        )

        response = (
            '[{"id":"H1","title":"t","description":"d","justification":"j",'
            '"relevance":"high","confidence":150,"ioc_basis":[],"suggested_actions":[]}]'
        )
        with patch(
            "backend.threat_hunting.agents.nodes.hypothesis_generator.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await hypothesis_generator({"research_effort": "medium"})

        assert result["hypotheses"][0]["confidence"] == 100

    @pytest.mark.asyncio
    async def test_missing_confidence_defaults(self):
        from backend.threat_hunting.agents.nodes.hypothesis_generator import (
            hypothesis_generator,
        )

        response = (
            '[{"id":"H1","title":"t","description":"d","justification":"j",'
            '"relevance":"high","ioc_basis":[],"suggested_actions":[]}]'
        )
        with patch(
            "backend.threat_hunting.agents.nodes.hypothesis_generator.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await hypothesis_generator({"research_effort": "medium"})

        assert result["hypotheses"][0]["confidence"] == 50

    @pytest.mark.asyncio
    async def test_non_numeric_confidence_defaults(self):
        from backend.threat_hunting.agents.nodes.hypothesis_generator import (
            hypothesis_generator,
        )

        response = (
            '[{"id":"H1","title":"t","description":"d","justification":"j",'
            '"relevance":"high","confidence":"very high","ioc_basis":[],"suggested_actions":[]}]'
        )
        with patch(
            "backend.threat_hunting.agents.nodes.hypothesis_generator.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await hypothesis_generator({"research_effort": "medium"})

        assert result["hypotheses"][0]["confidence"] == 50

    @pytest.mark.asyncio
    async def test_llm_discarded_field_is_overridden_to_false(self):
        """discarded must always be app-set, never trusted from the LLM."""
        from backend.threat_hunting.agents.nodes.hypothesis_generator import (
            hypothesis_generator,
        )

        response = (
            '[{"id":"H1","title":"t","description":"d","justification":"j",'
            '"relevance":"high","confidence":90,"discarded":true,'
            '"ioc_basis":[],"suggested_actions":[]}]'
        )
        with patch(
            "backend.threat_hunting.agents.nodes.hypothesis_generator.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await hypothesis_generator({"research_effort": "medium"})

        assert result["hypotheses"][0]["discarded"] is False


# ── /generate route: run_config validation ──────────────────────────────────


class TestGenerateRunConfigValidation:
    @pytest.mark.asyncio
    async def test_invalid_ioc_mode_rejected(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app
        from backend.threat_hunting import db as th_db

        db_path = tmp_path / "th_generate.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("test-015-validate", "")
            await th_db.add_evidence_item(pkg["id"], item_type="text", label="x", source_ref="x")

            client = TestClient(app)
            resp = client.post(
                f"/api/threat-hunting/packages/{pkg['id']}/generate",
                json={"run_config": {"ioc_mode": "not_a_real_mode"}},
            )

        assert resp.status_code == 400
        assert "ioc_mode" in resp.json()["detail"]
