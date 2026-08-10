"""Tests for issue-local-042 (item 23): evidence items can now be renamed
(label edited) in place — previously the only mutations were add/delete,
with no way to fix a bad/auto-generated label without deleting and
re-adding the item.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.threat_hunting import db as th_db


class TestUpdateEvidenceItemDb:
    @pytest.mark.asyncio
    async def test_update_evidence_item_renames_label(self, tmp_path: Path) -> None:
        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            pkg = await th_db.create_hunt_package(name="Pkg", description="")
            item = await th_db.add_evidence_item(
                pkg["id"], item_type="text", label="old label", source_ref="note"
            )

            await th_db.update_evidence_item(item["id"], label="new label")

            refetched = await th_db.get_evidence_item(item["id"])
            assert refetched["label"] == "new label"


class TestUpdateEvidenceRoute:
    @pytest.mark.asyncio
    async def test_patch_evidence_route_renames_and_round_trips(self, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            client = TestClient(app)

            pkg_resp = client.post("/api/threat-hunting/packages", json={"name": "Pkg"})
            pkg_id = pkg_resp.json()["id"]
            item_resp = client.post(
                f"/api/threat-hunting/packages/{pkg_id}/evidence/text",
                json={"text": "some content", "label": "old label"},
            )
            item_id = item_resp.json()["id"]

            patch_resp = client.patch(
                f"/api/threat-hunting/packages/{pkg_id}/evidence/{item_id}",
                json={"label": "renamed"},
            )
            assert patch_resp.status_code == 200, patch_resp.text
            assert patch_resp.json()["label"] == "renamed"

            list_resp = client.get(f"/api/threat-hunting/packages/{pkg_id}/evidence")
            assert list_resp.json()[0]["label"] == "renamed"

    @pytest.mark.asyncio
    async def test_patch_evidence_route_404s_for_item_in_another_package(
        self, tmp_path: Path
    ) -> None:
        from fastapi.testclient import TestClient

        from backend.main import app

        db_path = tmp_path / "th.db"
        with patch.object(th_db, "_TH_DB_PATH", db_path):
            await th_db.init_threat_hunting_db()
            client = TestClient(app)

            pkg1 = client.post("/api/threat-hunting/packages", json={"name": "Pkg1"}).json()
            pkg2 = client.post("/api/threat-hunting/packages", json={"name": "Pkg2"}).json()
            item = client.post(
                f"/api/threat-hunting/packages/{pkg1['id']}/evidence/text",
                json={"text": "x", "label": "l"},
            ).json()

            resp = client.patch(
                f"/api/threat-hunting/packages/{pkg2['id']}/evidence/{item['id']}",
                json={"label": "renamed"},
            )
            assert resp.status_code == 404
