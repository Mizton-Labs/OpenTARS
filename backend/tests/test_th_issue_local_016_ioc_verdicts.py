"""Tests for issue-local-016: manual per-IOC keep/remove verdict overrides.

Covers both DB-layer helpers (update_ioc_actions — pre-existing, and the new
update_deep_retrohunt_ioc_actions) and the new HTTP route
PATCH /packages/{pkg_id}/runs/{run_id}/iocs, which updates both IOC data
stores (extracted_iocs table + deep_retrohunt JSON blob's sanitized_iocs) in
one call."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


def _sanitized_ioc(ioc: str, ioc_type: str, action: str, noise_score: float = 0.0) -> dict:
    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "ioc_description": "",
        "noise_score": noise_score,
        "noise_reasons": [],
        "search_token": ioc,
        "action": action,
    }


async def _seed_run_with_deep_retrohunt(
    db_path: Path, sanitized_iocs: list[dict]
) -> tuple[str, str]:
    """Create a hunt package + one run with a stored deep_retrohunt blob.
    Returns (pkg_id, run_id)."""
    from backend.threat_hunting import db as th_db

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("ioc-verdict-test", "")
        kept = [s for s in sanitized_iocs if s["action"] != "remove"]
        deep_retrohunt = {
            "sanitized_iocs": sanitized_iocs,
            "ioc_csv": "ioc,ioc_type,ioc_description\n",
            "total_ioc_count": len(kept),
            "noisy_ioc_count": 0,
            "high_noise_ioc_count": 0,
            "spl_draft": "",
            "spl_macro_name": "",
            "search_hint": "",
            "analyst_notes": "",
            "llm_parse_error": False,
        }

        import aiosqlite

        run_id = "run-1"
        async with aiosqlite.connect(db_path) as conn:
            await conn.execute(
                "INSERT INTO hunting_packages (id, hunt_package_id, deep_retrohunt, created_at) "
                "VALUES (?, ?, ?, ?)",
                (run_id, pkg["id"], json.dumps(deep_retrohunt), "2026-01-01T00:00:00+00:00"),
            )
            await conn.commit()

    return pkg["id"], run_id


# ── DB layer: update_deep_retrohunt_ioc_actions ─────────────────────────────


@pytest.mark.asyncio
async def test_update_deep_retrohunt_ioc_actions_flips_verdict_and_recomputes_counts(
    tmp_path: Path,
) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    sanitized = [
        _sanitized_ioc("evil.com", "domain", "keep"),
        _sanitized_ioc("google.com", "domain", "keep"),
    ]
    pkg_id, run_id = await _seed_run_with_deep_retrohunt(db_path, sanitized)
    del pkg_id

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        updated = await th_db.update_deep_retrohunt_ioc_actions(
            run_id, [("google.com", "domain", "remove")]
        )

    assert updated is not None
    by_ioc = {s["ioc"]: s for s in updated["sanitized_iocs"]}
    assert by_ioc["google.com"]["action"] == "remove"
    assert by_ioc["evil.com"]["action"] == "keep"
    # Counts/CSV recomputed from the kept set only.
    assert updated["total_ioc_count"] == 1
    assert "google.com" not in updated["ioc_csv"]
    assert "evil.com" in updated["ioc_csv"]


@pytest.mark.asyncio
async def test_update_deep_retrohunt_ioc_actions_can_restore_a_removed_ioc(tmp_path: Path) -> None:
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    sanitized = [
        _sanitized_ioc("evil.com", "domain", "keep"),
        _sanitized_ioc("google.com", "domain", "remove"),
    ]
    pkg_id, run_id = await _seed_run_with_deep_retrohunt(db_path, sanitized)
    del pkg_id

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        updated = await th_db.update_deep_retrohunt_ioc_actions(
            run_id, [("google.com", "domain", "keep")]
        )

    assert updated is not None
    assert updated["total_ioc_count"] == 2
    assert "google.com" in updated["ioc_csv"]


@pytest.mark.asyncio
async def test_update_deep_retrohunt_ioc_actions_returns_none_when_no_deep_retrohunt(
    tmp_path: Path,
) -> None:
    """A run with no deep_retrohunt lead (no atomic IOCs extracted) is a
    legitimate 'nothing to update here' case, not an error."""
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("no-retrohunt", "")

        import aiosqlite

        async with aiosqlite.connect(db_path) as conn:
            await conn.execute(
                "INSERT INTO hunting_packages (id, hunt_package_id, created_at) VALUES (?, ?, ?)",
                ("run-1", pkg["id"], "2026-01-01T00:00:00+00:00"),
            )
            await conn.commit()

        result = await th_db.update_deep_retrohunt_ioc_actions(
            "run-1", [("evil.com", "domain", "remove")]
        )

    assert result is None


# ── HTTP route: PATCH /packages/{pkg_id}/runs/{run_id}/iocs ────────────────


@pytest.mark.asyncio
async def test_route_updates_both_extracted_iocs_and_deep_retrohunt(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th_route.db"
    sanitized = [
        _sanitized_ioc("evil.com", "domain", "keep"),
        _sanitized_ioc("google.com", "domain", "keep"),
    ]

    with patch.object(th_db, "_TH_DB_PATH", db_path):
        pkg_id, run_id = await _seed_run_with_deep_retrohunt(db_path, sanitized)
        evidence = await th_db.add_evidence_item(
            pkg_id, item_type="text", label="x", source_ref="x"
        )
        await th_db.add_extracted_iocs(
            pkg_id,
            evidence["id"],
            [
                {"ioc": "evil.com", "ioc_type": "domain", "action": "keep"},
                {"ioc": "google.com", "ioc_type": "domain", "action": "keep"},
            ],
            run_id=run_id,
        )

        client = TestClient(app)
        resp = client.patch(
            f"/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/iocs",
            json={"updates": [{"ioc": "google.com", "ioc_type": "domain", "action": "remove"}]},
        )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["updated_count"] == 1
        assert body["deep_retrohunt"]["total_ioc_count"] == 1

        # extracted_iocs (the real table) reflects the change too.
        rows = await th_db.list_extracted_iocs(pkg_id, run_id)
        by_ioc = {r["ioc"]: r for r in rows}
        assert by_ioc["google.com"]["action"] == "remove"
        assert by_ioc["evil.com"]["action"] == "keep"


@pytest.mark.asyncio
async def test_route_rejects_invalid_action(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th_route2.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("bad-action", "")

        client = TestClient(app)
        resp = client.patch(
            f"/api/threat-hunting/packages/{pkg['id']}/runs/run-x/iocs",
            json={"updates": [{"ioc": "evil.com", "ioc_type": "domain", "action": "discard"}]},
        )

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_route_404s_for_unknown_package(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th_route3.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()

        client = TestClient(app)
        resp = client.patch(
            "/api/threat-hunting/packages/does-not-exist/runs/run-x/iocs",
            json={"updates": [{"ioc": "evil.com", "ioc_type": "domain", "action": "keep"}]},
        )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_route_scoped_to_single_run_does_not_affect_other_runs(tmp_path: Path) -> None:
    """A manual verdict change on run A must not touch run B's IOCs."""
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.threat_hunting import db as th_db

    db_path = tmp_path / "th_route4.db"
    with patch.object(th_db, "_TH_DB_PATH", db_path):
        await th_db.init_threat_hunting_db()
        pkg = await th_db.create_hunt_package("multi-run-scope", "")
        pkg_id = pkg["id"]
        evidence = await th_db.add_evidence_item(
            pkg_id, item_type="text", label="x", source_ref="x"
        )
        await th_db.add_extracted_iocs(
            pkg_id,
            evidence["id"],
            [{"ioc": "evil.com", "ioc_type": "domain", "action": "keep"}],
            run_id="run-a",
        )
        await th_db.add_extracted_iocs(
            pkg_id,
            evidence["id"],
            [{"ioc": "evil.com", "ioc_type": "domain", "action": "keep"}],
            run_id="run-b",
        )

        client = TestClient(app)
        resp = client.patch(
            f"/api/threat-hunting/packages/{pkg_id}/runs/run-a/iocs",
            json={"updates": [{"ioc": "evil.com", "ioc_type": "domain", "action": "remove"}]},
        )
        assert resp.status_code == 200

        run_a_iocs = await th_db.list_extracted_iocs(pkg_id, "run-a")
        run_b_iocs = await th_db.list_extracted_iocs(pkg_id, "run-b")

    assert run_a_iocs[0]["action"] == "remove"
    assert run_b_iocs[0]["action"] == "keep"
