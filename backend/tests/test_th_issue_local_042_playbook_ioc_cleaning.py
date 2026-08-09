"""Tests for issue-local-042 (item 20): a Hunt Playbook can now configure
IOC cleaning for its own fired runs — previously every playbook run always
used run_config={}, silently ignoring the configured default with no way
for a playbook to say otherwise.

Also covers a real regression this surfaced: PlaybookModelEntry (the
request-body Pydantic model backing POST/PUT /playbooks) never declared
`effort`, even though playbook_runner.py already read entry.get("effort")
and the frontend already sent it — Pydantic's default behavior is to
silently drop undeclared input fields, so a per-model effort chosen through
the real HTTP API was discarded before it ever reached the database. Only
db.py-level tests (which call create_playbook() directly, bypassing
Pydantic validation) existed before, so this never surfaced.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents.playbook_runner import _resolve_playbook_run_config


class TestPydanticEffortRegression:
    @pytest.mark.asyncio
    async def test_per_model_effort_survives_the_real_http_route(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            client = TestClient(app)

            resp = client.post(
                "/api/threat-hunting/playbooks",
                json={
                    "name": "PB1",
                    "models": [{"model_name": "m1", "effort": "high"}],
                },
            )
            assert resp.status_code == 201, resp.text
            assert resp.json()["models"][0]["effort"] == "high"

            # Round-trips through GET too, not just the create response.
            get_resp = client.get(f"/api/threat-hunting/playbooks/{resp.json()['id']}")
            assert get_resp.json()["models"][0]["effort"] == "high"


class TestResolvePlaybookRunConfig:
    def test_returns_empty_dict_when_ioc_cleaning_disabled(self) -> None:
        playbook = {"ioc_cleaning_enabled": False}
        assert _resolve_playbook_run_config(playbook, {}) == {}

    def test_general_scope_uses_the_playbook_level_config_for_every_entry(self) -> None:
        playbook = {
            "ioc_cleaning_enabled": True,
            "ioc_cleaning_scope": "general",
            "ioc_mode": "active_cleaning",
            "ioc_cleaning_options": {"remove_noisy": True, "remove_legit_domains": False},
        }
        cfg1 = _resolve_playbook_run_config(playbook, {"model_name": "m1"})
        cfg2 = _resolve_playbook_run_config(playbook, {"model_name": "m2", "ioc_mode": "tagging_only"})
        assert cfg1 == cfg2 == {
            "ioc_mode": "active_cleaning",
            "ioc_cleaning_options": {"remove_noisy": True, "remove_legit_domains": False},
        }

    def test_per_model_scope_uses_each_entrys_own_config(self) -> None:
        playbook = {"ioc_cleaning_enabled": True, "ioc_cleaning_scope": "per_model"}
        entry1 = {"model_name": "m1", "ioc_mode": "tagging_only"}
        entry2 = {
            "model_name": "m2",
            "ioc_mode": "active_cleaning",
            "ioc_cleaning_options": {"remove_noisy": False},
        }
        assert _resolve_playbook_run_config(playbook, entry1) == {"ioc_mode": "tagging_only"}
        assert _resolve_playbook_run_config(playbook, entry2) == {
            "ioc_mode": "active_cleaning",
            "ioc_cleaning_options": {"remove_noisy": False},
        }

    def test_per_model_scope_falls_through_to_empty_when_entry_has_no_override(self) -> None:
        playbook = {"ioc_cleaning_enabled": True, "ioc_cleaning_scope": "per_model"}
        assert _resolve_playbook_run_config(playbook, {"model_name": "m1"}) == {}

    def test_tagging_only_never_carries_cleaning_options_even_if_present(self) -> None:
        playbook = {
            "ioc_cleaning_enabled": True,
            "ioc_cleaning_scope": "general",
            "ioc_mode": "tagging_only",
            "ioc_cleaning_options": {"remove_noisy": True},
        }
        assert _resolve_playbook_run_config(playbook, {}) == {"ioc_mode": "tagging_only"}


class TestRunPlaybookJobAppliesIocCleaning:
    @pytest.mark.asyncio
    async def test_general_scope_config_is_passed_to_start_generation(self, tmp_path: Path) -> None:
        from backend.threat_hunting.agents import playbook_runner

        db_path = tmp_path / "th.db"
        calls: list[dict] = []

        async def _fake_start_generation(pkg_id, **kwargs):
            calls.append(kwargs)
            return {"run_id": f"run-{len(calls)}", "hunt_package_id": pkg_id}

        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(playbook_runner, "start_generation", _fake_start_generation),
        ):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            pb = await th_db.create_playbook(
                "PB1",
                models=[{"model_name": "m1"}],
                auto_approve_analysis=False,
                ioc_cleaning_enabled=True,
                ioc_cleaning_scope="general",
                ioc_mode="active_cleaning",
                ioc_cleaning_options={"remove_noisy": True, "remove_cdn_ranges": False},
            )
            job = await th_db.create_playbook_job(
                pkg["id"], playbook_id=pb["id"], playbook_name=pb["name"]
            )
            await playbook_runner._run_playbook_job(job["id"], pkg["id"], pb, created_by=None)

        assert calls[0]["run_config"] == {
            "ioc_mode": "active_cleaning",
            "ioc_cleaning_options": {"remove_noisy": True, "remove_cdn_ranges": False},
        }

    @pytest.mark.asyncio
    async def test_disabled_playbook_still_passes_empty_run_config(self, tmp_path: Path) -> None:
        """Every pre-existing playbook (ioc_cleaning_enabled defaults to
        False) must keep behaving exactly as before this feature existed."""
        from backend.threat_hunting.agents import playbook_runner

        db_path = tmp_path / "th.db"
        calls: list[dict] = []

        async def _fake_start_generation(pkg_id, **kwargs):
            calls.append(kwargs)
            return {"run_id": f"run-{len(calls)}", "hunt_package_id": pkg_id}

        with (
            patch.object(th_db, "_TH_DB_PATH", db_path),
            patch.object(playbook_runner, "start_generation", _fake_start_generation),
        ):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package("pkg", "")
            pb = await th_db.create_playbook("PB1", models=[{"model_name": "m1"}])
            job = await th_db.create_playbook_job(
                pkg["id"], playbook_id=pb["id"], playbook_name=pb["name"]
            )
            await playbook_runner._run_playbook_job(job["id"], pkg["id"], pb, created_by=None)

        assert calls[0]["run_config"] == {}


class TestPlaybookIocCleaningCrud:
    @pytest.mark.asyncio
    async def test_create_and_update_persist_ioc_cleaning_config(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pb = await th_db.create_playbook(
                "PB1",
                models=[{"model_name": "m1"}],
                ioc_cleaning_enabled=True,
                ioc_cleaning_scope="general",
                ioc_mode="active_cleaning",
                ioc_cleaning_options={"remove_noisy": True},
            )
            assert pb["ioc_cleaning_enabled"] is True
            assert pb["ioc_cleaning_scope"] == "general"
            assert pb["ioc_mode"] == "active_cleaning"
            assert pb["ioc_cleaning_options"] == {"remove_noisy": True}

            updated = await th_db.update_playbook(pb["id"], ioc_cleaning_enabled=False)
            assert updated["ioc_cleaning_enabled"] is False
            # Disabling clears the now-meaningless scope/mode/options in storage
            # (re-enabling later starts from a clean slate, not stale values).
            assert updated["ioc_cleaning_scope"] is None
            assert updated["ioc_mode"] is None
            assert updated["ioc_cleaning_options"] is None

    @pytest.mark.asyncio
    async def test_defaults_to_disabled_for_a_playbook_that_never_set_it(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pb = await th_db.create_playbook("PB1", models=[{"model_name": "m1"}])
            assert pb["ioc_cleaning_enabled"] is False
            assert pb["ioc_cleaning_scope"] is None

    @pytest.mark.asyncio
    async def test_enabling_without_a_valid_scope_is_rejected(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            with pytest.raises(ValueError, match="ioc_cleaning_scope"):
                await th_db.create_playbook(
                    "PB1", models=[{"model_name": "m1"}], ioc_cleaning_enabled=True
                )

    @pytest.mark.asyncio
    async def test_clone_copies_ioc_cleaning_config(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pb = await th_db.create_playbook(
                "PB1",
                models=[{"model_name": "m1"}],
                ioc_cleaning_enabled=True,
                ioc_cleaning_scope="per_model",
            )
            cloned = await th_db.clone_playbook(pb["id"], "PB1 copy")
            assert cloned["ioc_cleaning_enabled"] is True
            assert cloned["ioc_cleaning_scope"] == "per_model"
