"""
Tests for issue-local-041: Hunt Playbook ownership enforcement.

"Only Threat researcher role is able to read/edit/delete (own) playbooks."
Decided scope (user-confirmed): any researcher or admin may create/read/run/
clone a playbook; editing/deleting an EXISTING playbook is scoped to its
owner (created_by) for researchers, while admins bypass that check entirely
(unrestricted, same as before this change). A playbook with no recorded
owner (created_by NULL) has no owner to enforce and stays editable/deletable
by any researcher.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from backend.api.routes_threat_hunting import _require_playbook_owner_or_admin
from backend.threat_hunting import db as th_db


def _fake_request(user=None):
    return SimpleNamespace(state=SimpleNamespace(user=user))


class TestRequirePlaybookOwnerOrAdmin:
    def test_auth_disabled_is_unrestricted(self):
        """No request.state.user at all (auth disabled) — no identity to check."""
        _require_playbook_owner_or_admin({"created_by": "alice"}, _fake_request(None))

    def test_owner_may_edit_own_playbook(self):
        _require_playbook_owner_or_admin(
            {"created_by": "alice"}, _fake_request({"username": "alice", "role": "threat-researcher"})
        )

    def test_non_owner_researcher_is_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            _require_playbook_owner_or_admin(
                {"created_by": "alice"}, _fake_request({"username": "bob", "role": "threat-researcher"})
            )
        assert exc_info.value.status_code == 403

    def test_admin_bypasses_ownership_entirely(self):
        """Admin can edit/delete ANY playbook, matching the pre-existing
        unrestricted admin behavior everywhere else in this app."""
        _require_playbook_owner_or_admin(
            {"created_by": "alice"}, _fake_request({"username": "someone-else", "role": "admin"})
        )

    def test_no_recorded_owner_is_editable_by_any_researcher(self):
        """created_by NULL — pre-issue-local-041 playbook, or created while
        auth was disabled — has no owner to enforce."""
        _require_playbook_owner_or_admin(
            {"created_by": None}, _fake_request({"username": "bob", "role": "threat-researcher"})
        )


class TestPlaybookOwnershipRoutesHttp:
    """End-to-end via the real routes — auth middleware is bypassed (auth
    disabled by default in tests), so these exercise the route logic itself
    by calling _require_playbook_owner_or_admin's dependency indirectly
    through a monkeypatched current-user is not applicable here since the
    real middleware never runs under TestClient without auth configured;
    the unit tests above cover the enforcement logic, this covers that the
    routes actually call get_playbook + the check before mutating."""

    @pytest.mark.asyncio
    async def test_update_404s_before_ownership_check_for_unknown_playbook(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            client = TestClient(app)
            resp = client.put("/api/threat-hunting/playbooks/does-not-exist", json={"name": "X"})
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_404s_before_ownership_check_for_unknown_playbook(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            client = TestClient(app)
            resp = client.delete("/api/threat-hunting/playbooks/does-not-exist")
            assert resp.status_code == 404
