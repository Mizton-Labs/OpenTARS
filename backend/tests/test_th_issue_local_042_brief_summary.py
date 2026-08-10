"""Tests for issue-local-042 (item 9): a one-sentence subtitle for the Hunt
Packages list, derived from the newest run's threat_context.summary — no
dedicated LLM call, no stored/stale copy, just a first-sentence extraction
computed at list_hunt_packages() read time.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db


async def _insert_run(
    pkg_id: str,
    run_id: str,
    *,
    created_at: str,
    threat_context: dict | None,
) -> None:
    async with aiosqlite.connect(th_db._TH_DB_PATH) as conn:
        await conn.execute(
            "INSERT INTO hunting_packages "
            "(id, hunt_package_id, threat_context, generation_status, created_at, run_seq) "
            "VALUES (?, ?, ?, 'completed', ?, 1)",
            (run_id, pkg_id, json.dumps(threat_context) if threat_context is not None else None, created_at),
        )
        await conn.commit()


class TestBriefSummaryFromThreatContext:
    def test_extracts_only_the_first_sentence(self) -> None:
        ctx = json.dumps({"summary": "APT42 targets defense contractors. It uses spear phishing."})
        assert th_db._brief_summary_from_threat_context(ctx) == "APT42 targets defense contractors."

    def test_truncates_an_unusually_long_first_sentence_at_a_word_boundary(self) -> None:
        long_sentence = "A " + "very " * 60 + "long sentence with no period anywhere in it at all"
        ctx = json.dumps({"summary": long_sentence})
        result = th_db._brief_summary_from_threat_context(ctx)
        assert result is not None
        assert result.endswith("…")
        assert len(result) <= th_db._BRIEF_SUMMARY_MAX_LEN + 1

    def test_returns_none_for_missing_or_blank_summary(self) -> None:
        assert th_db._brief_summary_from_threat_context(json.dumps({})) is None
        assert th_db._brief_summary_from_threat_context(json.dumps({"summary": "  "})) is None

    def test_returns_none_for_invalid_json(self) -> None:
        assert th_db._brief_summary_from_threat_context(None) is None
        assert th_db._brief_summary_from_threat_context("not json") is None


class TestListHuntPackagesBriefSummary:
    @pytest.mark.asyncio
    async def test_uses_the_newest_runs_summary(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            await _insert_run(
                pkg["id"], "run-old",
                created_at="2026-01-01T00:00:00Z",
                threat_context={"summary": "Old, stale context from an earlier run."},
            )
            await _insert_run(
                pkg["id"], "run-new",
                created_at="2026-01-02T00:00:00Z",
                threat_context={"summary": "Fresh context from the newest run."},
            )
            packages = await th_db.list_hunt_packages()

        found = next(p for p in packages if p["id"] == pkg["id"])
        assert found["brief_summary"] == "Fresh context from the newest run."

    @pytest.mark.asyncio
    async def test_none_when_no_run_has_a_threat_context_yet(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            packages = await th_db.list_hunt_packages()

        found = next(p for p in packages if p["id"] == pkg["id"])
        assert found["brief_summary"] is None

    @pytest.mark.asyncio
    async def test_falls_back_to_an_older_run_when_the_newest_has_no_summary_yet(
        self, tmp_path: Path
    ) -> None:
        """A brand-new re-run (still 'running', threat_context not written
        yet) shouldn't blank out a subtitle a prior run already produced —
        list_hunt_packages() only skips a run in the newest-first scan when
        it has nothing usable, it doesn't stop at the first (newest) run."""
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            await _insert_run(
                pkg["id"], "run-old",
                created_at="2026-01-01T00:00:00Z",
                threat_context={"summary": "Context from the completed run."},
            )
            await _insert_run(
                pkg["id"], "run-new",
                created_at="2026-01-02T00:00:00Z",
                threat_context=None,
            )
            packages = await th_db.list_hunt_packages()

        found = next(p for p in packages if p["id"] == pkg["id"])
        assert found["brief_summary"] == "Context from the completed run."
