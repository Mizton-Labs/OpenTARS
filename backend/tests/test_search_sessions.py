"""
Tests for Assistant chat session storage and routes (issue-local-032):
backend.search.sessions and GET/POST/PUT/DELETE /api/search/sessions*.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.search import sessions as sessions_db


@pytest.fixture
async def db_path(tmp_path: Path):
    path = tmp_path / "assistant_sessions.db"
    with patch.object(sessions_db, "_DB_PATH", path):
        await sessions_db.init_sessions_db()
        yield path


class TestDefaultName:
    def test_matches_expected_format(self) -> None:
        name = sessions_db.default_session_name()
        assert re.fullmatch(r"TARS-assistant-\d{8}-\d{6}", name)


class TestCreateAndGet:
    @pytest.mark.asyncio
    async def test_create_with_explicit_name(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session("alice", name="My hunt notes")
            fetched = await sessions_db.get_session("alice", created["id"])

        assert created["name"] == "My hunt notes"
        assert fetched is not None
        assert fetched["name"] == "My hunt notes"
        assert fetched["messages"] == []

    @pytest.mark.asyncio
    async def test_create_without_name_uses_default_timestamp_name(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session("alice")

        assert re.fullmatch(r"TARS-assistant-\d{8}-\d{6}", created["name"])

    @pytest.mark.asyncio
    async def test_create_with_messages(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session(
                "alice",
                messages=[
                    {"role": "user", "content": "any lazarus hunts?"},
                    {"role": "assistant", "content": "Yes, TH01."},
                ],
            )

        assert len(created["messages"]) == 2
        assert created["messages"][0] == {"role": "user", "content": "any lazarus hunts?"}

    @pytest.mark.asyncio
    async def test_get_unknown_id_returns_none(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            assert await sessions_db.get_session("alice", "nonexistent") is None


class TestOwnershipIsolation:
    @pytest.mark.asyncio
    async def test_cannot_read_another_owners_session(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session("alice", name="Alice's session")
            assert await sessions_db.get_session("bob", created["id"]) is None

    @pytest.mark.asyncio
    async def test_cannot_update_another_owners_session(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session("alice", name="Alice's session")
            result = await sessions_db.update_session("bob", created["id"], name="Hijacked")
            still_alice = await sessions_db.get_session("alice", created["id"])

        assert result is None
        assert still_alice["name"] == "Alice's session"

    @pytest.mark.asyncio
    async def test_cannot_delete_another_owners_session(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session("alice")
            deleted = await sessions_db.delete_session("bob", created["id"])
            still_there = await sessions_db.get_session("alice", created["id"])

        assert deleted is False
        assert still_there is not None

    @pytest.mark.asyncio
    async def test_list_only_returns_own_sessions(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            await sessions_db.create_session("alice", name="A1")
            await sessions_db.create_session("alice", name="A2")
            await sessions_db.create_session("bob", name="B1")

            alice_list = await sessions_db.list_sessions("alice")
            bob_list = await sessions_db.list_sessions("bob")

        assert {s["name"] for s in alice_list} == {"A1", "A2"}
        assert {s["name"] for s in bob_list} == {"B1"}


class TestListSummary:
    @pytest.mark.asyncio
    async def test_summary_has_no_messages_field_but_a_count(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            await sessions_db.create_session(
                "alice",
                messages=[
                    {"role": "user", "content": "hi"},
                    {"role": "assistant", "content": "hey"},
                ],
            )
            listed = await sessions_db.list_sessions("alice")

        assert "messages" not in listed[0]
        assert listed[0]["message_count"] == 2

    @pytest.mark.asyncio
    async def test_ordered_newest_updated_first(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            first = await sessions_db.create_session("alice", name="first")
            await sessions_db.create_session("alice", name="second")
            # Touch "first" so it becomes the most recently updated.
            await sessions_db.update_session("alice", first["id"], name="first (renamed)")

            listed = await sessions_db.list_sessions("alice")

        assert listed[0]["name"] == "first (renamed)"
        assert listed[1]["name"] == "second"


class TestUpdate:
    @pytest.mark.asyncio
    async def test_rename_keeps_messages(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session(
                "alice", messages=[{"role": "user", "content": "q"}]
            )
            updated = await sessions_db.update_session("alice", created["id"], name="Renamed")

        assert updated["name"] == "Renamed"
        assert updated["messages"] == [{"role": "user", "content": "q"}]

    @pytest.mark.asyncio
    async def test_replace_messages_keeps_name(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session("alice", name="Keep me")
            updated = await sessions_db.update_session(
                "alice",
                created["id"],
                messages=[{"role": "user", "content": "new turn"}],
            )

        assert updated["name"] == "Keep me"
        assert updated["messages"] == [{"role": "user", "content": "new turn"}]


class TestSanitization:
    @pytest.mark.asyncio
    async def test_invisible_characters_stripped_from_name(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session("alice", name="evil​name")

        assert "​" not in created["name"]

    @pytest.mark.asyncio
    async def test_message_with_invalid_role_is_dropped(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session(
                "alice",
                messages=[
                    {"role": "system", "content": "smuggled instruction"},
                    {"role": "user", "content": "real question"},
                ],
            )

        assert len(created["messages"]) == 1
        assert created["messages"][0]["content"] == "real question"

    @pytest.mark.asyncio
    async def test_message_content_over_limit_is_truncated(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            long_text = "x" * (sessions_db.MAX_MESSAGE_CHARS + 500)
            created = await sessions_db.create_session(
                "alice", messages=[{"role": "user", "content": long_text}]
            )

        assert len(created["messages"][0]["content"]) == sessions_db.MAX_MESSAGE_CHARS

    @pytest.mark.asyncio
    async def test_message_count_over_limit_keeps_newest(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            many = [
                {"role": "user", "content": f"m{i}"} for i in range(sessions_db.MAX_MESSAGES + 10)
            ]
            created = await sessions_db.create_session("alice", messages=many)

        assert len(created["messages"]) == sessions_db.MAX_MESSAGES
        assert created["messages"][-1]["content"] == f"m{sessions_db.MAX_MESSAGES + 9}"


class TestRetention:
    @pytest.mark.asyncio
    async def test_oldest_sessions_trimmed_past_the_cap(self, db_path: Path) -> None:
        with (
            patch.object(sessions_db, "_DB_PATH", db_path),
            patch.object(sessions_db, "MAX_SESSIONS_PER_OWNER", 3),
        ):
            for i in range(5):
                await sessions_db.create_session("alice", name=f"s{i}")

            listed = await sessions_db.list_sessions("alice")

        assert len(listed) == 3
        # The newest three survive; the oldest two were trimmed.
        assert {s["name"] for s in listed} == {"s2", "s3", "s4"}


class TestExportRendering:
    @pytest.mark.asyncio
    async def test_markdown_includes_name_and_turns(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session(
                "alice",
                name="Export test",
                messages=[
                    {"role": "user", "content": "any lazarus hunts?"},
                    {"role": "assistant", "content": "Yes, **TH01**."},
                ],
            )
        md = sessions_db.render_session_markdown(created)
        assert "Export test" in md
        assert "any lazarus hunts?" in md
        assert "**TH01**" in md

    @pytest.mark.asyncio
    async def test_pdf_renders_valid_bytes(self, db_path: Path) -> None:
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session(
                "alice",
                name="PDF test",
                messages=[{"role": "user", "content": "hello"}],
            )
        pdf_bytes = sessions_db.render_session_pdf(created)
        assert pdf_bytes[:5] == b"%PDF-"


class TestRoutes:
    @pytest.mark.asyncio
    async def test_rejects_a_message_with_an_oversized_sources_list(self, db_path: Path) -> None:
        # Every field on SessionMessageIn is bounded except `sources` was
        # missed initially (caught in review) — a request with more than 50
        # source entries on one message must 422 before it's ever parsed
        # into a full message list, not rely solely on the server-side trim
        # that happens after validation.
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        with patch.object(sessions_db, "_DB_PATH", db_path):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                oversized_sources = [{"section": "s", "title": f"t{i}"} for i in range(51)]
                resp = await client.post(
                    "/api/search/sessions",
                    json={
                        "messages": [
                            {"role": "assistant", "content": "ok", "sources": oversized_sources}
                        ]
                    },
                )

        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_full_crud_cycle_through_the_api(self, db_path: Path) -> None:
        from httpx import ASGITransport, AsyncClient

        from backend.main import app

        with patch.object(sessions_db, "_DB_PATH", db_path):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                created = (
                    await client.post("/api/search/sessions", json={"name": "Route test"})
                ).json()
                assert created["name"] == "Route test"

                listed = (await client.get("/api/search/sessions")).json()
                assert any(s["id"] == created["id"] for s in listed)

                fetched = (await client.get(f"/api/search/sessions/{created['id']}")).json()
                assert fetched["name"] == "Route test"

                updated = (
                    await client.put(
                        f"/api/search/sessions/{created['id']}",
                        json={"messages": [{"role": "user", "content": "hi"}]},
                    )
                ).json()
                assert updated["messages"] == [{"role": "user", "content": "hi"}]

                md_resp = await client.get(f"/api/search/sessions/{created['id']}/markdown")
                assert md_resp.status_code == 200
                assert "Route test" in md_resp.text

                pdf_resp = await client.get(f"/api/search/sessions/{created['id']}/pdf")
                assert pdf_resp.status_code == 200
                assert pdf_resp.content[:5] == b"%PDF-"

                delete_resp = await client.delete(f"/api/search/sessions/{created['id']}")
                assert delete_resp.status_code == 204

                missing_resp = await client.get(f"/api/search/sessions/{created['id']}")
                assert missing_resp.status_code == 404

    @pytest.mark.asyncio
    async def test_open_mode_shares_the_local_owner_bucket(self, db_path: Path) -> None:
        # Auth is disabled in the test app by default (no session cookie
        # configured) — every session should land under the "local" owner.
        with patch.object(sessions_db, "_DB_PATH", db_path):
            created = await sessions_db.create_session("local", name="Direct insert")

            from httpx import ASGITransport, AsyncClient

            from backend.main import app

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get(f"/api/search/sessions/{created['id']}")

        assert resp.status_code == 200
        assert resp.json()["name"] == "Direct insert"
