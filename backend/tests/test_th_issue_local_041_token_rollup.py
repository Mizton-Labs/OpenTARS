"""
Tests for issue-local-041: per-run/per-package token usage rollups.

_parse_step_logs (db.py) now returns a 3-tuple (phases, total_elapsed_s,
token_usage_total) — the third summed across every step's "tokens" block.
list_hunt_packages/list_generation_runs surface it as
THuntPackageRun.token_usage_total; a package-wide total is just summed
client-side over the already-fetched runs list.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db


class TestSumTokenUsage:
    def test_sums_across_multiple_steps(self):
        step_logs = [
            {"step": "a", "tokens": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}},
            {"step": "b", "tokens": {"input_tokens": 20, "output_tokens": 8, "total_tokens": 28}},
        ]
        assert th_db._sum_token_usage(step_logs) == {
            "input_tokens": 30,
            "output_tokens": 13,
            "total_tokens": 43,
        }

    def test_none_when_no_step_reports_usage(self):
        step_logs = [{"step": "a", "status": "ok"}, {"step": "b", "status": "ok", "tokens": None}]
        assert th_db._sum_token_usage(step_logs) is None

    def test_partial_reporting_still_sums_what_exists(self):
        """One step reports only input/output, another only total — each
        field is summed independently across whichever steps carried it."""
        step_logs = [
            {"step": "a", "tokens": {"input_tokens": 10, "output_tokens": 5}},
            {"step": "b", "tokens": {"total_tokens": 99}},
        ]
        assert th_db._sum_token_usage(step_logs) == {
            "input_tokens": 10,
            "output_tokens": 5,
            "total_tokens": 99,
        }

    def test_ignores_non_dict_tokens_field(self):
        step_logs = [{"step": "a", "tokens": "not-a-dict"}]
        assert th_db._sum_token_usage(step_logs) is None


class TestParseStepLogsReturnsTokenTotals:
    def test_returns_three_tuple_with_token_totals(self):
        import json

        step_logs_json = json.dumps(
            [
                {"step": "a", "status": "ok", "elapsed_s": 1.0, "tokens": {"total_tokens": 10}},
                {"step": "b", "status": "ok", "elapsed_s": 2.0, "tokens": {"total_tokens": 20}},
            ]
        )
        phases, total_elapsed, token_totals = th_db._parse_step_logs(step_logs_json)
        assert len(phases) == 2
        assert total_elapsed == 3.0
        assert token_totals == {"total_tokens": 30}
        # Each phase entry also carries its own step's tokens for the
        # per-task breakdown (F24's debug console).
        assert phases[0]["tokens"] == {"total_tokens": 10}

    def test_none_step_logs_returns_all_none(self):
        assert th_db._parse_step_logs(None) == (None, None, None)

    def test_malformed_json_returns_all_none_not_a_crash(self):
        assert th_db._parse_step_logs("{not valid json") == (None, None, None)

    def test_steps_without_tokens_field_yield_none_total(self):
        import json

        step_logs_json = json.dumps([{"step": "a", "status": "ok", "elapsed_s": 1.0}])
        _phases, _elapsed, token_totals = th_db._parse_step_logs(step_logs_json)
        assert token_totals is None


class TestTokenUsageRollupIntegration:
    @pytest.mark.asyncio
    async def test_list_generation_runs_surfaces_token_usage_total(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            run_id = "run-1"
            async with aiosqlite.connect(db_path) as conn:
                await conn.execute(
                    "INSERT INTO hunting_packages "
                    "(id, hunt_package_id, generation_status, created_at) VALUES (?,?,?,?)",
                    (run_id, pkg["id"], "completed", "2026-01-01T00:00:00Z"),
                )
                await conn.commit()

            await th_db.append_run_step_log(
                run_id,
                {"step": "hypothesis_generator", "status": "ok", "tokens": {"total_tokens": 100}},
            )
            await th_db.append_run_step_log(
                run_id,
                {"step": "ttp_analyst", "status": "ok", "tokens": {"total_tokens": 50}},
            )

            runs = await th_db.list_generation_runs(pkg["id"])
            assert len(runs) == 1
            assert runs[0]["token_usage_total"] == {"total_tokens": 150}

    @pytest.mark.asyncio
    async def test_list_hunt_packages_surfaces_token_usage_total_per_run(
        self, tmp_path: Path
    ) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            run_id = "run-1"
            async with aiosqlite.connect(db_path) as conn:
                await conn.execute(
                    "INSERT INTO hunting_packages "
                    "(id, hunt_package_id, generation_status, created_at) VALUES (?,?,?,?)",
                    (run_id, pkg["id"], "completed", "2026-01-01T00:00:00Z"),
                )
                await conn.commit()
            await th_db.append_run_step_log(
                run_id, {"step": "hypothesis_generator", "status": "ok", "tokens": {"total_tokens": 42}}
            )

            packages = await th_db.list_hunt_packages()
            found = next(p for p in packages if p["id"] == pkg["id"])
            assert found["runs"][0]["token_usage_total"] == {"total_tokens": 42}
