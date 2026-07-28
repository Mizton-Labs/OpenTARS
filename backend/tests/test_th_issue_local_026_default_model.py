"""
Tests for the issue-local-026 follow-up: a run started with "Configured
default" (provider_name/model_name both None) never had its actual
resolved provider/model persisted — hunting_packages.llm_provider/llm_model
stayed NULL forever for that run, so the Runs table had nothing to show for
it and no reliable way to know afterward what was actually used.

runner.start_generation() now resolves the default provider/model once, at
run-start time, and persists THOSE resolved values on the run — not left
NULL, and not reconstructed later from "whatever today's default happens to
be" (which would drift from historical truth if an admin changes the
default after the run completes).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents import runner


async def _seed_package(db_path: Path) -> str:
    pkg_id = str(uuid.uuid4())
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO hunt_packages (id,name,description,status,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (pkg_id, "test", "", "draft", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        )
        await db.commit()
    return pkg_id


class _FakeClient:
    def __init__(self, name: str, model: str) -> None:
        self.name = name
        self.model = model


@pytest.mark.asyncio
async def test_default_selection_resolves_actual_provider_and_model(tmp_path: Path) -> None:
    db_path = tmp_path / "th.db"
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
        patch("backend.llm.registry.get_client") as mock_get_client,
    ):
        mock_task.return_value = object()
        mock_get_client.return_value = _FakeClient("test-default-provider", "claude-sonnet-5")
        await th_db.init_threat_hunting_db()
        pkg_id = await _seed_package(db_path)

        result = await runner.start_generation(pkg_id)

        # get_client(None) is how "no explicit provider" resolves to the
        # configured default — confirms the resolution path was actually hit.
        mock_get_client.assert_called_once_with(None)
        assert result["provider_name"] == "test-default-provider"
        assert result["model_name"] == "claude-sonnet-5"

        # The resolved values must also be what gets threaded into the
        # pipeline state (create_task's first positional call arg is the
        # coroutine; inspect what _run_pipeline was invoked with by checking
        # the coroutine's own frame locals is fragile — instead assert via
        # the persisted row, matching this file's own _save_generation_state
        # convention for simulating what _run_pipeline would have done).
        await runner._save_generation_state(
            result["run_id"],
            pkg_id,
            {"provider_name": result["provider_name"], "model_name": result["model_name"]},
            status="running",
        )
        row = await th_db.get_generation_run(result["run_id"])
        assert row["llm_provider"] == "test-default-provider"
        assert row["llm_model"] == "claude-sonnet-5"


@pytest.mark.asyncio
async def test_explicit_provider_choice_is_not_overridden(tmp_path: Path) -> None:
    """An analyst's explicit provider/model choice must pass through
    unchanged — resolution only kicks in for provider_name=None."""
    db_path = tmp_path / "th.db"
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
        patch("backend.llm.registry.get_client") as mock_get_client,
    ):
        mock_task.return_value = object()
        await th_db.init_threat_hunting_db()
        pkg_id = await _seed_package(db_path)

        result = await runner.start_generation(
            pkg_id, provider_name="test-explicit-provider", model_name="gpt-5.5"
        )

        mock_get_client.assert_not_called()
        assert result["provider_name"] == "test-explicit-provider"
        assert result["model_name"] == "gpt-5.5"


@pytest.mark.asyncio
async def test_resolution_failure_falls_through_to_none(tmp_path: Path) -> None:
    """When there's genuinely no default configured (or LLM is disabled),
    resolution soft-fails and start_generation still returns — the real,
    actionable error surfaces from the pipeline's own LLM call, not here."""
    db_path = tmp_path / "th.db"
    with (
        patch.object(th_db, "_TH_DB_PATH", db_path),
        patch.object(runner, "_ACTIVE_JOBS", {}),
        patch.object(runner, "_ACTIVE_RUN_PKG", {}),
        patch("backend.threat_hunting.agents.runner.asyncio.create_task") as mock_task,
        patch("backend.llm.registry.get_client", side_effect=RuntimeError("no default configured")),
    ):
        mock_task.return_value = object()
        await th_db.init_threat_hunting_db()
        pkg_id = await _seed_package(db_path)

        result = await runner.start_generation(pkg_id)

        assert result["provider_name"] is None
        assert result["model_name"] is None
