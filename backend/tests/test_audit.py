"""
Tests for the Audit module (issue-local-033): backend.audit.db storage,
GET /api/audit/events permission scoping, and the two integration points
that feed it without per-call-site instrumentation — the generic
audit_activity middleware's login instrumentation (routes_auth.py) and
threat_hunting.db.append_run_step_log's "agent" category hook.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import aiosqlite
import pytest
from fastapi.testclient import TestClient

from backend.audit import db as audit_db
from backend.auth import db as auth_db
from backend.auth import service
from backend.main import app
from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents import runner as th_runner


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "audit.db"
    with patch.object(audit_db, "_DB_PATH", path):
        await audit_db.init_audit_db()
        yield path


class TestRecordEvent:
    @pytest.mark.asyncio
    async def test_records_and_lists_event(self, db_path: Path) -> None:
        with patch.object(audit_db, "_DB_PATH", db_path):
            await audit_db.record_event(
                "user",
                "POST /api/foo",
                username="alice",
                role="threat-viewer",
                summary="alice did a thing",
                detail={"k": "v"},
            )
            events, total = await audit_db.list_events(category="user")

        assert total == 1
        assert events[0]["action"] == "POST /api/foo"
        assert events[0]["username"] == "alice"
        assert events[0]["role"] == "threat-viewer"
        assert events[0]["summary"] == "alice did a thing"
        assert events[0]["detail"] == {"k": "v"}
        assert events[0]["created_at"]

    @pytest.mark.asyncio
    async def test_unknown_category_is_dropped(self, db_path: Path) -> None:
        with patch.object(audit_db, "_DB_PATH", db_path):
            await audit_db.record_event("bogus", "x", summary="should not persist")
            # "bogus" is not a valid category, so no row was ever inserted under
            # it — note this may itself emit a "system" event via the root
            # WARNING+ logging bridge, which is expected and checked elsewhere.
            events, total = await audit_db.list_events(category="bogus")

        assert total == 0
        assert events == []

    @pytest.mark.asyncio
    async def test_summary_and_detail_are_truncated(self, db_path: Path) -> None:
        with patch.object(audit_db, "_DB_PATH", db_path):
            await audit_db.record_event(
                "system",
                "x",
                summary="s" * 1000,
                detail={"blob": "d" * 10_000},
            )
            events, _ = await audit_db.list_events(category="system")

        assert len(events[0]["summary"]) == audit_db.MAX_SUMMARY_CHARS
        # detail is JSON-encoded then truncated at the byte level, so it may
        # no longer be valid JSON; list_events falls back to None in that case.
        assert (
            events[0]["detail"] is None
            or len(str(events[0]["detail"])) <= audit_db.MAX_DETAIL_CHARS
        )


class TestListEventsFiltering:
    @pytest.mark.asyncio
    async def test_filters_by_category(self, db_path: Path) -> None:
        with patch.object(audit_db, "_DB_PATH", db_path):
            await audit_db.record_event("user", "a", summary="u1")
            await audit_db.record_event("agent", "b", summary="a1")

            user_events, user_total = await audit_db.list_events(category="user")
            agent_events, agent_total = await audit_db.list_events(category="agent")

        assert user_total == 1 and user_events[0]["category"] == "user"
        assert agent_total == 1 and agent_events[0]["category"] == "agent"

    @pytest.mark.asyncio
    async def test_filters_by_username(self, db_path: Path) -> None:
        with patch.object(audit_db, "_DB_PATH", db_path):
            await audit_db.record_event("user", "a", username="alice", summary="a1")
            await audit_db.record_event("user", "a", username="bob", summary="b1")

            alice_events, alice_total = await audit_db.list_events(username="alice")

        assert alice_total == 1
        assert alice_events[0]["username"] == "alice"

    @pytest.mark.asyncio
    async def test_search_matches_summary_and_action(self, db_path: Path) -> None:
        with patch.object(audit_db, "_DB_PATH", db_path):
            await audit_db.record_event("user", "login.success", summary="'alice' logged in")
            await audit_db.record_event("user", "logout", summary="'bob' logged out")

            by_summary, total_summary = await audit_db.list_events(search="alice")
            by_action, total_action = await audit_db.list_events(search="login.success")

        assert total_summary == 1 and by_summary[0]["summary"] == "'alice' logged in"
        assert total_action == 1 and by_action[0]["action"] == "login.success"

    @pytest.mark.asyncio
    async def test_search_escapes_like_wildcards(self, db_path: Path) -> None:
        with patch.object(audit_db, "_DB_PATH", db_path):
            await audit_db.record_event("user", "a", summary="100% done")
            await audit_db.record_event("user", "a", summary="totally unrelated text")

            events, total = await audit_db.list_events(search="100%")

        # A literal "%" in the search term must not act as a wildcard.
        assert total == 1
        assert events[0]["summary"] == "100% done"

    @pytest.mark.asyncio
    async def test_pagination_and_total_count(self, db_path: Path) -> None:
        with patch.object(audit_db, "_DB_PATH", db_path):
            for i in range(5):
                await audit_db.record_event("system", "x", summary=f"event-{i}")

            page1, total = await audit_db.list_events(category="system", limit=2, offset=0)
            page2, _ = await audit_db.list_events(category="system", limit=2, offset=2)

        assert total == 5
        assert len(page1) == 2
        assert len(page2) == 2
        assert {e["id"] for e in page1}.isdisjoint({e["id"] for e in page2})

    @pytest.mark.asyncio
    async def test_newest_first_ordering(self, db_path: Path) -> None:
        with patch.object(audit_db, "_DB_PATH", db_path):
            async with aiosqlite.connect(db_path) as db:
                await db.execute(
                    "INSERT INTO audit_events (id, category, action, username, role, summary, "
                    "detail, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    ("e1", "system", "a", None, None, "older", None, "2026-01-01T00:00:00+00:00"),
                )
                await db.execute(
                    "INSERT INTO audit_events (id, category, action, username, role, summary, "
                    "detail, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    ("e2", "system", "a", None, None, "newer", None, "2026-01-02T00:00:00+00:00"),
                )
                await db.commit()

            events, _ = await audit_db.list_events(category="system")

        assert [e["id"] for e in events] == ["e2", "e1"]


class TestRetentionTrim:
    @pytest.mark.asyncio
    async def test_trims_down_to_target_once_cap_exceeded(self, db_path: Path) -> None:
        with (
            patch.object(audit_db, "_DB_PATH", db_path),
            patch.object(audit_db, "MAX_EVENTS", 5),
            patch.object(audit_db, "_TRIM_CHECK_EVERY", 3),
            patch.object(audit_db, "_TRIM_TARGET", 2),
            patch.object(audit_db, "_insert_count", 0),
        ):
            for i in range(6):
                await audit_db.record_event("system", "x", summary=f"e{i}")

            _, total = await audit_db.list_events(category="system")

        # The 6th insert is a multiple of _TRIM_CHECK_EVERY(3); count(6) > MAX_EVENTS(5)
        # triggers a trim back down to _TRIM_TARGET(2).
        assert total == 2


class TestRoutesAudit:
    @pytest.fixture
    def audit_env(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        monkeypatch.setattr(audit_db, "_DB_PATH", tmp_path / "audit.db")
        monkeypatch.setenv("OPENTARS_ENABLE_AUTH", "1")
        service._failures.clear()

        async def _seed():
            await auth_db.init_users_db()
            await audit_db.init_audit_db()
            await auth_db.create_user("admin", service.hash_password("Adminpass1"), role="admin")
            await auth_db.create_user(
                "alice", service.hash_password("Alicepass1"), role="threat-viewer"
            )
            await auth_db.create_user(
                "bob", service.hash_password("Bobpass123"), role="threat-viewer"
            )
            await audit_db.record_event(
                "user", "a", username="alice", role="threat-viewer", summary="alice user event"
            )
            await audit_db.record_event(
                "user", "a", username="bob", role="threat-viewer", summary="bob user event"
            )
            await audit_db.record_event("agent", "a", username="alice", summary="alice agent event")
            await audit_db.record_event("application", "a", summary="unattributed app event")
            await audit_db.record_event(
                "application", "a", username="alice", summary="alice application event"
            )
            await audit_db.record_event("system", "a", summary="system event")

        asyncio.run(_seed())
        yield
        service._failures.clear()

    def _login(self, username: str, password: str) -> TestClient:
        c = TestClient(app)
        r = c.post("/api/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return c

    def test_requires_category(self, audit_env) -> None:
        c = self._login("admin", "Adminpass1")
        r = c.get("/api/audit/events")
        assert r.status_code == 422

    def test_unknown_category_is_404(self, audit_env) -> None:
        c = self._login("admin", "Adminpass1")
        r = c.get("/api/audit/events", params={"category": "bogus"})
        assert r.status_code == 404

    def test_admin_sees_every_actor(self, audit_env) -> None:
        c = self._login("admin", "Adminpass1")
        r = c.get("/api/audit/events", params={"category": "user"})
        assert r.status_code == 200
        usernames = {e["username"] for e in r.json()["events"]}
        # admin's own login.success is itself a "user" event and is expected
        # to be visible to admin — admin sees every actor, including itself.
        assert {"alice", "bob"} <= usernames

    def test_admin_can_see_application_and_system(self, audit_env) -> None:
        c = self._login("admin", "Adminpass1")
        r = c.get("/api/audit/events", params={"category": "application"})
        assert r.status_code == 200
        assert r.json()["total"] == 2  # unattributed + alice's, admin sees every actor
        r = c.get("/api/audit/events", params={"category": "system"})
        assert r.status_code == 200
        assert r.json()["total"] == 1

    def test_non_admin_scoped_to_own_username(self, audit_env) -> None:
        c = self._login("alice", "Alicepass1")
        r = c.get("/api/audit/events", params={"category": "user"})
        assert r.status_code == 200
        body = r.json()
        # The seeded "alice user event" plus alice's own login.success from
        # the _login() call above — both attributed to alice.
        assert body["total"] == 2
        assert all(e["username"] == "alice" for e in body["events"])

    def test_non_admin_cannot_override_username(self, audit_env) -> None:
        # No client-supplied username param exists on this route at all, but
        # confirm bob's events are never visible to alice regardless.
        c = self._login("alice", "Alicepass1")
        r = c.get("/api/audit/events", params={"category": "user"})
        usernames = {e["username"] for e in r.json()["events"]}
        assert "bob" not in usernames

    def test_non_admin_agent_category_scoped_to_self(self, audit_env) -> None:
        c = self._login("alice", "Alicepass1")
        r = c.get("/api/audit/events", params={"category": "agent"})
        assert r.status_code == 200
        assert r.json()["total"] == 1

    def test_non_admin_sees_application_scoped_to_self(self, audit_env) -> None:
        # issue-local-033 (follow-up): "application" now covers a non-admin's
        # own everyday activity (hunt packages, evidence, IOC verdicts, ...),
        # so it moved from admin-only into _USER_VISIBLE_CATEGORIES, scoped
        # to the caller's own username like "user"/"agent" already were.
        c = self._login("alice", "Alicepass1")
        r = c.get("/api/audit/events", params={"category": "application"})
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["events"][0]["username"] == "alice"

    def test_non_admin_forbidden_from_system(self, audit_env) -> None:
        c = self._login("alice", "Alicepass1")
        r = c.get("/api/audit/events", params={"category": "system"})
        assert r.status_code == 403

    def test_unauthenticated_is_401(self, audit_env) -> None:
        c = TestClient(app)
        r = c.get("/api/audit/events", params={"category": "user"})
        assert r.status_code == 401


class TestLoginAudit:
    @pytest.fixture
    def audit_env(self, tmp_path, monkeypatch):
        monkeypatch.setattr(auth_db, "_USERS_DB_PATH", tmp_path / "users.db")
        monkeypatch.setattr(audit_db, "_DB_PATH", tmp_path / "audit.db")
        monkeypatch.setenv("OPENTARS_ENABLE_AUTH", "1")
        service._failures.clear()

        async def _seed():
            await auth_db.init_users_db()
            await audit_db.init_audit_db()
            await auth_db.create_user("admin", service.hash_password("Adminpass1"), role="admin")

        asyncio.run(_seed())
        yield
        service._failures.clear()

    def test_successful_login_is_recorded(self, audit_env) -> None:
        c = TestClient(app)
        r = c.post("/api/auth/login", json={"username": "admin", "password": "Adminpass1"})
        assert r.status_code == 200

        events, total = asyncio.run(audit_db.list_events(category="user"))
        actions = [e["action"] for e in events]
        assert "Signed in" in actions
        assert total >= 1

    def test_failed_login_is_recorded_without_password(self, audit_env) -> None:
        c = TestClient(app)
        r = c.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401

        events, _ = asyncio.run(audit_db.list_events(category="user"))
        failed = [e for e in events if e["action"] == "Failed sign-in attempt"]
        assert len(failed) == 1
        assert failed[0]["username"] == "admin"
        assert "wrong" not in str(failed[0])


class TestAgentAuditIntegration:
    @pytest.fixture
    async def th_db_path(self, tmp_path: Path):
        path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", path):
            await th_db.init_threat_hunting_db()
            yield path

    @pytest.mark.asyncio
    async def test_append_run_step_log_records_agent_event(
        self, th_db_path: Path, db_path: Path
    ) -> None:
        with patch.object(th_db, "_TH_DB_PATH", th_db_path):
            pkg = await th_db.create_hunt_package("Hunt", "", created_by="carol")
            async with aiosqlite.connect(th_db_path) as db:
                await db.execute(
                    "INSERT INTO hunting_packages (id, hunt_package_id, step_logs, created_at, "
                    "created_by) VALUES (?,?,?,?,?)",
                    ("run-1", pkg["id"], "[]", "2026-01-01T00:00:00Z", "carol"),
                )
                await db.commit()

            with patch.object(audit_db, "_DB_PATH", db_path):
                await th_db.append_run_step_log(
                    "run-1", {"step": "hypothesis_generator", "status": "completed"}
                )
                events, total = await audit_db.list_events(category="agent")

        assert total == 1
        assert events[0]["action"] == "Generated hunting hypotheses"
        assert events[0]["summary"] == "hypothesis_generator: completed"
        assert events[0]["username"] == "carol"
        assert events[0]["detail"]["run_id"] == "run-1"
        assert events[0]["detail"]["hunt_package_id"] == pkg["id"]
        assert events[0]["detail"]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_append_run_step_log_noop_for_unknown_run(
        self, th_db_path: Path, db_path: Path
    ) -> None:
        with (
            patch.object(th_db, "_TH_DB_PATH", th_db_path),
            patch.object(audit_db, "_DB_PATH", db_path),
        ):
            await th_db.append_run_step_log("nonexistent", {"step": "x", "status": "completed"})
            _, total = await audit_db.list_events(category="agent")

        assert total == 0


class TestSaveGenerationStateAgentAudit:
    """issue-local-033 (follow-up): _save_generation_state — the actual
    per-node choke point for LangGraph pipeline persistence — is the fix for
    the Agent category not populating. append_run_step_log (tested above) is
    only called from the 3 steps that run OUTSIDE the graph; the 7 graph
    nodes (hypothesis_generator, ttp_analyst, ...) persist through
    _save_generation_state instead, once per node, with the FULL accumulated
    step_logs list each time — so the fix must diff against what was already
    audited for that run_id, not blindly record the whole list every call.
    """

    @pytest.fixture
    async def th_db_path(self, tmp_path: Path):
        path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", path):
            await th_db.init_threat_hunting_db()
            yield path

    @pytest.fixture(autouse=True)
    def _clear_tracked_steps(self):
        th_runner._AUDITED_AGENT_STEPS.clear()
        yield
        th_runner._AUDITED_AGENT_STEPS.clear()

    @pytest.mark.asyncio
    async def test_records_one_event_per_new_step_no_duplicates_on_repeat_save(
        self, th_db_path: Path, db_path: Path
    ) -> None:
        with (
            patch.object(th_db, "_TH_DB_PATH", th_db_path),
            patch.object(audit_db, "_DB_PATH", db_path),
        ):
            pkg = await th_db.create_hunt_package("Hunt", "", created_by="dave")
            run_id = "run-graph-1"
            state = {
                "created_by": "dave",
                "step_logs": [{"step": "intake_classifier", "status": "ok"}],
            }

            # First node completes — one "agent" event, correctly interpreted.
            await th_runner._save_generation_state(run_id, pkg["id"], state, status="running")
            events, total = await audit_db.list_events(category="agent")
            assert total == 1
            assert events[0]["action"] == "Classified evidence intake"
            assert events[0]["username"] == "dave"

            # LangGraph's streaming loop calls _save_generation_state again on
            # the NEXT node with the reducer's full accumulated list — the
            # SAME first entry must not be re-recorded.
            await th_runner._save_generation_state(run_id, pkg["id"], state, status="running")
            _, total = await audit_db.list_events(category="agent")
            assert total == 1

            # A second, genuinely new step appears in the accumulated list —
            # exactly one more event, for that step only. Terminal status
            # ("completed") also exercises the tracking-dict cleanup path.
            state["step_logs"].append({"step": "hypothesis_generator", "status": "ok"})
            await th_runner._save_generation_state(run_id, pkg["id"], state, status="completed")
            events, total = await audit_db.list_events(category="agent")
            assert total == 2
            actions = {e["action"] for e in events}
            assert actions == {"Classified evidence intake", "Generated hunting hypotheses"}

        assert run_id not in th_runner._AUDITED_AGENT_STEPS

    @pytest.mark.asyncio
    async def test_error_status_step_gets_error_label(
        self, th_db_path: Path, db_path: Path
    ) -> None:
        with (
            patch.object(th_db, "_TH_DB_PATH", th_db_path),
            patch.object(audit_db, "_DB_PATH", db_path),
        ):
            pkg = await th_db.create_hunt_package("Hunt", "", created_by="dave")
            run_id = "run-graph-2"
            state = {
                "created_by": "dave",
                "step_logs": [{"step": "ttp_analyst", "status": "error"}],
            }
            await th_runner._save_generation_state(run_id, pkg["id"], state, status="error")
            events, total = await audit_db.list_events(category="agent")

        assert total == 1
        assert events[0]["action"] == "MITRE ATT&CK TTP analysis failed"

    @pytest.mark.asyncio
    async def test_no_step_logs_records_nothing(self, th_db_path: Path, db_path: Path) -> None:
        with (
            patch.object(th_db, "_TH_DB_PATH", th_db_path),
            patch.object(audit_db, "_DB_PATH", db_path),
        ):
            pkg = await th_db.create_hunt_package("Hunt", "", created_by="dave")
            await th_runner._save_generation_state(
                "run-graph-3", pkg["id"], {"created_by": "dave"}, status="running"
            )
            _, total = await audit_db.list_events(category="agent")

        assert total == 0
