"""Tests for issue-local-016: list_hunt_packages() bulk-fetches every run
(not just the latest) so the hunt-package list view can show a per-run
compact state indicator without an N+1 fetch per package."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.mark.asyncio
async def test_package_with_no_runs_has_empty_runs_list(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        await th_db.create_hunt_package("no-runs-yet", "")

        packages = await th_db.list_hunt_packages()

    assert len(packages) == 1
    assert packages[0]["runs"] == []
    assert packages[0]["run_count"] == 0


@pytest.mark.asyncio
async def test_package_with_one_run_has_run_count_one(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("one-run", "")
        await _insert_run(
            db_path,
            pkg["id"],
            run_id="run-1",
            generation_status="completed",
            created_at="2026-01-01T00:00:00+00:00",
            llm_model="gpt-oss",
        )

        packages = await th_db.list_hunt_packages()

    assert packages[0]["run_count"] == 1
    assert len(packages[0]["runs"]) == 1
    assert packages[0]["runs"][0]["id"] == "run-1"
    assert packages[0]["runs"][0]["llm_model"] == "gpt-oss"


@pytest.mark.asyncio
async def test_multiple_runs_returned_newest_first_each_with_own_phases(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("multi-run", "")
        await _insert_run(
            db_path,
            pkg["id"],
            run_id="run-old",
            generation_status="error",
            created_at="2026-01-01T00:00:00+00:00",
            llm_model="model-a",
            step_logs=[{"step": "intake_classifier", "status": "error", "elapsed_s": 1.0}],
        )
        await _insert_run(
            db_path,
            pkg["id"],
            run_id="run-new",
            generation_status="completed",
            created_at="2026-01-02T00:00:00+00:00",
            llm_model="model-b",
            step_logs=[{"step": "intake_classifier", "status": "ok", "elapsed_s": 2.5}],
        )

        packages = await th_db.list_hunt_packages()

    pkg_out = packages[0]
    assert pkg_out["run_count"] == 2
    run_ids = [r["id"] for r in pkg_out["runs"]]
    assert run_ids == ["run-new", "run-old"], "runs must be newest-first"

    newest, oldest = pkg_out["runs"]
    assert newest["generation_status"] == "completed"
    assert newest["llm_model"] == "model-b"
    assert newest["phases"][0]["status"] == "ok"
    assert newest["total_elapsed_s"] == 2.5

    assert oldest["generation_status"] == "error"
    assert oldest["llm_model"] == "model-a"
    assert oldest["phases"][0]["status"] == "error"
    assert oldest["total_elapsed_s"] == 1.0

    # The top-level (latest-run-merge) fields are unaffected by this change —
    # still driven by the single latest run, same as before issue-local-016.
    assert pkg_out["generation_status"] == "completed"


@pytest.mark.asyncio
async def test_runs_scoped_to_their_own_package(tmp_path: Path) -> None:
    """Two packages, each with their own run(s) — no cross-contamination."""
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg_a = await th_db.create_hunt_package("pkg-a", "")
        pkg_b = await th_db.create_hunt_package("pkg-b", "")
        await _insert_run(
            db_path, pkg_a["id"], run_id="a-run-1", created_at="2026-01-01T00:00:00+00:00"
        )
        await _insert_run(
            db_path, pkg_a["id"], run_id="a-run-2", created_at="2026-01-02T00:00:00+00:00"
        )
        await _insert_run(
            db_path, pkg_b["id"], run_id="b-run-1", created_at="2026-01-01T00:00:00+00:00"
        )

        packages = await th_db.list_hunt_packages()

    by_id = {p["id"]: p for p in packages}
    assert by_id[pkg_a["id"]]["run_count"] == 2
    assert {r["id"] for r in by_id[pkg_a["id"]]["runs"]} == {"a-run-1", "a-run-2"}
    assert by_id[pkg_b["id"]]["run_count"] == 1
    assert {r["id"] for r in by_id[pkg_b["id"]]["runs"]} == {"b-run-1"}


# ── issue-local-017: list_generation_runs() phase enrichment ────────────────
# (needed for HuntDetail's compact all-runs status table, which shows each
# run's model + status + workflow progress without a per-run extra fetch)


@pytest.mark.asyncio
async def test_list_generation_runs_includes_phases_and_elapsed(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("phase-enrichment", "")
        await _insert_run(
            db_path,
            pkg["id"],
            run_id="run-1",
            created_at="2026-01-01T00:00:00+00:00",
            llm_model="gpt-oss",
            step_logs=[
                {"step": "intake_classifier", "status": "ok", "elapsed_s": 1.5},
                {"step": "threat_context_builder", "status": "error", "elapsed_s": 0.5},
            ],
        )

        runs = await th_db.list_generation_runs(pkg["id"])

    assert len(runs) == 1
    assert runs[0]["llm_model"] == "gpt-oss"
    assert runs[0]["total_elapsed_s"] == 2.0
    steps = {p["step"]: p["status"] for p in runs[0]["phases"]}
    assert steps == {"intake_classifier": "ok", "threat_context_builder": "error"}


@pytest.mark.asyncio
async def test_list_generation_runs_no_step_logs_yields_none_phases(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("no-step-logs", "")
        await _insert_run(
            db_path, pkg["id"], run_id="run-1", created_at="2026-01-01T00:00:00+00:00"
        )

        runs = await th_db.list_generation_runs(pkg["id"])

    assert runs[0]["phases"] is None
    assert runs[0]["total_elapsed_s"] is None


async def _insert_run(
    db_path: Path,
    hunt_package_id: str,
    *,
    run_id: str,
    created_at: str,
    generation_status: str = "completed",
    llm_provider: str = "alt-provider",
    llm_model: str = "gpt-oss",
    research_effort: str = "medium",
    step_logs: list[dict] | None = None,
) -> None:
    """Directly INSERT a run row (bypassing the full agent pipeline) —
    mirrors the raw-sqlite3-insert pattern already used by
    test_th_issue_local_015.py for schema/migration tests."""
    import aiosqlite

    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(
            "INSERT INTO hunting_packages "
            "(id, hunt_package_id, generation_status, llm_provider, llm_model, "
            " research_effort, created_at, step_logs) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                hunt_package_id,
                generation_status,
                llm_provider,
                llm_model,
                research_effort,
                created_at,
                json.dumps(step_logs or []),
            ),
        )
        await conn.commit()
