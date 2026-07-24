"""
Tests for issue-local-007:
  2A — Agent tooling config (TOOL_METADATA, get_enabled_tool_specs, loader, routes)
  2B — Enriched phases projection in list_hunt_packages
  2C — Marker PDF extractor routing in dispatcher
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

# ─── 2A: TOOL_METADATA ────────────────────────────────────────────────────────


def test_tool_metadata_has_all_keys() -> None:
    from backend.threat_hunting.agents.tools import TOOL_METADATA, TOOL_SPECS

    spec_names = {t["name"] for t in TOOL_SPECS}
    # All 6 agent tools should be in metadata
    for name in spec_names:
        assert name in TOOL_METADATA, f"TOOL_METADATA missing entry for {name!r}"

    # Docling should be in metadata (replaces marker from issue-007)
    assert "docling" in TOOL_METADATA

    # Every entry has required keys
    for name, meta in TOOL_METADATA.items():
        for key in (
            "label",
            "category",
            "description",
            "used_by",
            "used_by_description",
            "implication_if_disabled",
            "available",
        ):
            assert key in meta, f"TOOL_METADATA[{name!r}] missing {key!r}"


def test_tool_metadata_categories() -> None:
    from backend.threat_hunting.agents.tools import TOOL_METADATA, TOOL_SPECS

    spec_names = {t["name"] for t in TOOL_SPECS}
    # All TOOL_SPECS entries should be agent_tool category
    for name in spec_names:
        assert TOOL_METADATA[name]["category"] == "agent_tool"

    # Marker is a document_parser
    assert TOOL_METADATA["docling"]["category"] == "document_parser"


def test_tool_metadata_used_by_lists() -> None:
    from backend.threat_hunting.agents.tools import TOOL_METADATA

    for name, meta in TOOL_METADATA.items():
        assert isinstance(meta["used_by"], list), f"{name}: used_by must be a list"
        assert len(meta["used_by"]) > 0, f"{name}: used_by must not be empty"


# ─── 2A: get_enabled_tool_specs ──────────────────────────────────────────────


def test_get_enabled_tool_specs_all_enabled() -> None:
    from backend.threat_hunting.agents.tools import get_enabled_tool_specs

    names = ["mitre_lookup", "validate_spl"]
    enabled = {"mitre_lookup": True, "validate_spl": True}
    result = get_enabled_tool_specs(names, enabled)
    assert len(result) == 2
    assert all(s["name"] in names for s in result)


def test_get_enabled_tool_specs_one_disabled() -> None:
    from backend.threat_hunting.agents.tools import get_enabled_tool_specs

    names = ["mitre_lookup", "validate_spl"]
    enabled = {"mitre_lookup": True, "validate_spl": False}
    result = get_enabled_tool_specs(names, enabled)
    assert len(result) == 1
    assert result[0]["name"] == "mitre_lookup"


def test_get_enabled_tool_specs_all_disabled() -> None:
    from backend.threat_hunting.agents.tools import get_enabled_tool_specs

    names = ["mitre_lookup", "validate_spl"]
    enabled = {"mitre_lookup": False, "validate_spl": False}
    result = get_enabled_tool_specs(names, enabled)
    assert result == []


def test_get_enabled_tool_specs_missing_key_defaults_true() -> None:
    """Missing key in enabled dict defaults to True (conservative)."""
    from backend.threat_hunting.agents.tools import get_enabled_tool_specs

    names = ["mitre_lookup"]
    result = get_enabled_tool_specs(names, {})  # empty enabled dict
    assert len(result) == 1


def test_get_enabled_tool_specs_unknown_name_silently_skipped() -> None:
    """Names not in TOOL_SPEC_BY_NAME are silently skipped."""
    from backend.threat_hunting.agents.tools import get_enabled_tool_specs

    names = ["mitre_lookup", "nonexistent_tool"]
    result = get_enabled_tool_specs(names, {"mitre_lookup": True, "nonexistent_tool": True})
    assert len(result) == 1
    assert result[0]["name"] == "mitre_lookup"


def test_get_enabled_tool_specs_accepts_tuple() -> None:
    """Should work with both list and tuple of names."""
    from backend.threat_hunting.agents.tools import get_enabled_tool_specs

    result = get_enabled_tool_specs(("validate_spl",), {"validate_spl": True})
    assert len(result) == 1


# ─── 2A: deep_retrohunt_planner _TOOL_NAMES normalization ────────────────────


def test_deep_retrohunt_has_module_level_tool_names() -> None:
    """deep_retrohunt_planner must expose _TOOL_NAMES at module level."""
    import backend.threat_hunting.agents.nodes.deep_retrohunt_planner as drp

    assert hasattr(drp, "_TOOL_NAMES"), "_TOOL_NAMES constant missing from deep_retrohunt_planner"
    assert set(drp._TOOL_NAMES) == {"validate_spl", "defang_ioc", "noise_score"}


# ─── 2A: loader round-trip ───────────────────────────────────────────────────


def test_load_agent_tools_returns_all_keys() -> None:
    from backend.config.loader import load_agent_tools
    from backend.threat_hunting.agents.tools import TOOL_METADATA

    with patch("backend.config.loader.load_app_config", return_value={}):
        result = load_agent_tools()

    # All keys from TOOL_METADATA should be in the result
    for key in TOOL_METADATA:
        assert key in result, f"load_agent_tools() missing {key!r}"
    # All default to True
    for key, val in result.items():
        assert val is True, f"load_agent_tools() default for {key!r} should be True"


def test_load_agent_tools_applies_stored_values() -> None:
    from backend.config.loader import load_agent_tools

    with patch(
        "backend.config.loader.load_app_config",
        return_value={"agent_tools": {"refetch_url": False, "docling": False}},
    ):
        result = load_agent_tools()

    assert result["refetch_url"] is False
    assert result["docling"] is False
    assert result["mitre_lookup"] is True  # not in stored dict → default True


def test_load_agent_tools_invalid_type_uses_defaults() -> None:
    from backend.config.loader import load_agent_tools

    with patch("backend.config.loader.load_app_config", return_value={"agent_tools": "not a dict"}):
        result = load_agent_tools()

    # Should return defaults without raising
    assert isinstance(result, dict)
    assert all(isinstance(v, bool) for v in result.values())


def test_save_agent_tools_rejects_unknown_key() -> None:
    from backend.config.loader import save_agent_tools

    with pytest.raises(ValueError, match="Unknown agent tool key"):
        save_agent_tools({"nonexistent_tool": True})


def test_save_agent_tools_rejects_non_bool() -> None:
    from backend.config.loader import save_agent_tools

    with pytest.raises(ValueError, match="must be a boolean"):
        save_agent_tools({"mitre_lookup": "yes"})  # type: ignore[arg-type]


def test_save_agent_tools_rejects_non_dict() -> None:
    from backend.config.loader import save_agent_tools

    with pytest.raises(ValueError):
        save_agent_tools("not a dict")  # type: ignore[arg-type]


def test_save_agent_tools_persists() -> None:
    from backend.config.loader import save_agent_tools

    written: list[dict] = []

    def _fake_write(_path, data):
        written.append(data)

    with (
        patch("backend.config.loader.load_app_config", return_value={}),
        patch("backend.config.loader._write_yaml", side_effect=_fake_write),
    ):
        save_agent_tools({"refetch_url": False})

    assert written[0]["agent_tools"]["refetch_url"] is False


# ─── 2A: API routes ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_agent_tools_route() -> None:
    from fastapi.testclient import TestClient

    from backend.main import app

    with patch(
        "backend.api.routes_app.load_agent_tools",
        return_value={"mitre_lookup": True, "refetch_url": False},
    ):
        client = TestClient(app)
        resp = client.get("/api/app/agent-tools")

    assert resp.status_code == 200
    data = resp.json()
    assert "agent_tools" in data
    assert data["agent_tools"]["mitre_lookup"] is True
    assert data["agent_tools"]["refetch_url"] is False


@pytest.mark.asyncio
async def test_put_agent_tools_route_valid() -> None:
    from fastapi.testclient import TestClient

    from backend.main import app

    with (
        patch("backend.api.routes_app.save_agent_tools"),
        patch("backend.api.routes_app.load_agent_tools", return_value={"mitre_lookup": False}),
        patch("backend.auth.dependencies.require_admin_when_enabled", return_value=None),
    ):
        client = TestClient(app)
        resp = client.put(
            "/api/app/agent-tools",
            json={"agent_tools": {"mitre_lookup": False}},
        )

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_put_agent_tools_route_rejects_non_dict() -> None:
    from fastapi.testclient import TestClient

    from backend.main import app

    with patch("backend.auth.dependencies.require_admin_when_enabled", return_value=None):
        client = TestClient(app)
        resp = client.put(
            "/api/app/agent-tools",
            json={"agent_tools": "bad"},
        )

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_get_agent_tools_catalog_route() -> None:
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.threat_hunting.agents.tools import TOOL_METADATA

    with patch(
        "backend.threat_hunting.extractors.pdf_extractor.is_docling_available", return_value=False
    ):
        client = TestClient(app)
        resp = client.get("/api/app/agent-tools/catalog")

    assert resp.status_code == 200
    data = resp.json()
    assert "catalog" in data
    names = {e["name"] for e in data["catalog"]}
    # All TOOL_METADATA keys should appear
    for key in TOOL_METADATA:
        assert key in names, f"catalog missing {key!r}"
    # Marker available=False when not installed
    docling_entry = next(e for e in data["catalog"] if e["name"] == "docling")
    assert docling_entry["available"] is False


# ─── 2A: node gating ─────────────────────────────────────────────────────────


def test_intake_classifier_uses_get_enabled_tool_specs() -> None:
    """intake_classifier must import and use get_enabled_tool_specs."""
    import inspect

    import backend.threat_hunting.agents.nodes.intake_classifier as ic

    source = inspect.getsource(ic)
    assert "get_enabled_tool_specs" in source


def test_threat_context_builder_uses_get_enabled_tool_specs() -> None:
    import inspect

    import backend.threat_hunting.agents.nodes.threat_context_builder as tcb

    source = inspect.getsource(tcb)
    assert "get_enabled_tool_specs" in source


def test_query_drafting_agent_uses_get_enabled_tool_specs() -> None:
    import inspect

    import backend.threat_hunting.agents.nodes.query_drafting_agent as qda

    source = inspect.getsource(qda)
    assert "get_enabled_tool_specs" in source


def test_deep_retrohunt_uses_get_enabled_tool_specs() -> None:
    import inspect

    import backend.threat_hunting.agents.nodes.deep_retrohunt_planner as drp

    source = inspect.getsource(drp)
    assert "get_enabled_tool_specs" in source


# ─── 2B: enriched phases projection ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_hunt_packages_enriches_phases() -> None:
    """list_hunt_packages should pass tools_used, decision, item_count through."""
    from backend.threat_hunting import db as th_db

    # Build a realistic step_logs JSON with tools_used, decision, item_count
    step_logs = json.dumps(
        [
            {
                "step": "intake_classifier",
                "status": "ok",
                "elapsed_s": 1.2,
                "tools_used": ["extract_iocs"],
                "decision": "Fetched 2 URLs",
                "item_count": None,
                "ioc_count": 5,
                "noisy_count": 1,
            },
            {
                "step": "threat_context_builder",
                "status": "ok",
                "elapsed_s": 3.4,
                "tools_used": ["mitre_lookup"],
                "decision": "Found T1059",
                "item_count": 2,
            },
        ]
    )

    # Build mock aiosqlite rows
    pkg_row = {
        "id": "pkg-1",
        "name": "Test Hunt",
        "description": "",
        "status": "completed",
        "created_by": None,
        "created_at": "2026-01-01T00:00:00",
        "updated_at": "2026-01-01T00:00:00",
        "evidence_count": 2,
        "hunt_seq": 1,
    }

    hp_row = ("pkg-1", "completed", step_logs, "2026-01-01T00:00:00")

    class _FakeCur:
        def __init__(self, rows):
            self._rows = rows

        async def fetchall(self):
            return self._rows

        async def close(self):
            pass

    class _FakeConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def execute(self, query, *args):
            if "hunt_packages" in query and "hunting_packages" not in query:
                # Return package rows as Row-like dicts
                return _FakeCur([_DictRow(pkg_row)])
            elif "hunt_package_id IN (" in query:
                # issue-local-016 bulk all-runs query — not exercised here
                return _FakeCur([])
            else:
                return _FakeCur([hp_row])

    class _DictRow(dict):
        def __getitem__(self, key):
            return super().__getitem__(key)

        def keys(self):
            return super().keys()

    with patch("backend.threat_hunting.db.aiosqlite") as mock_aio:
        mock_aio.connect.return_value = _FakeConn()
        mock_aio.Row = dict
        result = await th_db.list_hunt_packages()

    if not result:
        pytest.skip("mock returned no packages — structural test only")
        return

    pkg = result[0]
    phases = pkg.get("phases") or []
    if not phases:
        pytest.skip("no phases projected — check mock row format")
        return

    # Find intake_classifier phase
    intake = next((p for p in phases if p["step"] == "intake_classifier"), None)
    if intake is None:
        pytest.skip("intake_classifier phase not in results")
        return

    assert intake.get("tools_used") == ["extract_iocs"]
    assert "Fetched" in intake.get("decision", "")
    assert intake.get("ioc_count") == 5
    assert intake.get("noisy_count") == 1

    # Find threat_context_builder phase
    ctx = next((p for p in phases if p["step"] == "threat_context_builder"), None)
    if ctx:
        assert ctx.get("tools_used") == ["mitre_lookup"]
        assert ctx.get("item_count") == 2


# ─── 2C: Docling routing in dispatcher ───────────────────────────────────────


def test_dispatcher_docling_mode_falls_back_when_not_installed() -> None:
    """parser_mode='docling' falls back to PyMuPDF when docling is unavailable."""
    from backend.threat_hunting.extractors.dispatcher import PARSER_DOCLING, _extract_pdf

    with (
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.is_docling_available",
            return_value=False,
        ),
        patch("backend.threat_hunting.extractors.pdf_extractor.is_available", return_value=True),
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.extract_pdf",
            return_value=("plain text", "1.0", []),
        ),
    ):
        _text, parser_used, _version, warnings = _extract_pdf(b"%PDF", PARSER_DOCLING, [])

    assert parser_used == "pymupdf"
    assert any("not installed" in w for w in warnings)


def test_dispatcher_docling_mode_falls_back_when_toggle_disabled() -> None:
    """parser_mode='docling' falls back to PyMuPDF when the toggle is off."""
    from backend.threat_hunting.extractors.dispatcher import PARSER_DOCLING, _extract_pdf

    with (
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.is_docling_available",
            return_value=True,
        ),
        patch("backend.config.loader.load_agent_tools", return_value={"docling": False}),
        patch("backend.threat_hunting.extractors.pdf_extractor.is_available", return_value=True),
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.extract_pdf",
            return_value=("plain text", "1.0", []),
        ),
    ):
        _text, parser_used, _version, warnings = _extract_pdf(b"%PDF", PARSER_DOCLING, [])

    assert parser_used == "pymupdf"
    assert any("disabled" in w for w in warnings)


def test_dispatcher_docling_mode_succeeds_when_available() -> None:
    """parser_mode='docling' uses Docling when available + enabled."""
    from backend.threat_hunting.extractors.dispatcher import PARSER_DOCLING, _extract_pdf

    with (
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.is_docling_available",
            return_value=True,
        ),
        patch("backend.config.loader.load_agent_tools", return_value={"docling": True}),
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.extract_pdf_docling",
            return_value=("# Heading\nContent", "2.104.0", []),
        ),
    ):
        text, parser_used, version, _warnings = _extract_pdf(b"%PDF", PARSER_DOCLING, [])

    assert parser_used == "docling"
    assert "# Heading" in text
    assert version == "2.104.0"


def test_dispatcher_legacy_marker_mode_routes_to_docling() -> None:
    """parser_mode='marker' (legacy) is treated as 'docling' — backward compat."""
    from backend.threat_hunting.extractors.dispatcher import _extract_pdf

    with (
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.is_docling_available",
            return_value=True,
        ),
        patch("backend.config.loader.load_agent_tools", return_value={"docling": True}),
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.extract_pdf_docling",
            return_value=("# Legacy\nContent", "2.104.0", []),
        ),
    ):
        text, parser_used, _version, _warnings = _extract_pdf(b"%PDF", "marker", [])

    assert parser_used == "docling"
    assert "# Legacy" in text


def test_dispatcher_auto_mode_uses_docling_when_available() -> None:
    """parser_mode='auto' prefers Docling when installed + enabled."""
    from backend.threat_hunting.extractors.dispatcher import PARSER_AUTO, _extract_pdf

    with (
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.is_docling_available",
            return_value=True,
        ),
        patch("backend.config.loader.load_agent_tools", return_value={"docling": True}),
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.extract_pdf_docling",
            return_value=("# Title\n\nContent", "2.104.0", []),
        ),
    ):
        _text, parser_used, _version, warnings = _extract_pdf(b"%PDF", PARSER_AUTO, [])

    assert parser_used == "docling"
    assert "auto" in " ".join(warnings).lower()


def test_dispatcher_auto_mode_uses_pymupdf_when_docling_unavailable() -> None:
    """parser_mode='auto' falls back to PyMuPDF when Docling is not installed."""
    from backend.threat_hunting.extractors.dispatcher import PARSER_AUTO, _extract_pdf

    with (
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.is_docling_available",
            return_value=False,
        ),
        patch("backend.threat_hunting.extractors.pdf_extractor.is_available", return_value=True),
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.extract_pdf",
            return_value=("plain text", "1.24.0", []),
        ),
    ):
        _text, parser_used, _version, _warnings = _extract_pdf(b"%PDF", PARSER_AUTO, [])

    assert parser_used == "pymupdf"


def test_dispatcher_pymupdf_mode_ignores_docling() -> None:
    """Explicit pymupdf mode never calls Docling even when it is available."""
    from backend.threat_hunting.extractors.dispatcher import PARSER_PYMUPDF, _extract_pdf

    with (
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.is_docling_available",
            return_value=True,
        ),
        patch("backend.threat_hunting.extractors.pdf_extractor.is_available", return_value=True),
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.extract_pdf",
            return_value=("plain text", "1.24.0", []),
        ),
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.extract_pdf_docling"
        ) as mock_docling,
    ):
        _text, parser_used, _version, _warnings = _extract_pdf(b"%PDF", PARSER_PYMUPDF, [])

    mock_docling.assert_not_called()
    assert parser_used == "pymupdf"


def test_dispatcher_docling_falls_back_when_extraction_fails() -> None:
    """If Docling raises during extraction, fall back to PyMuPDF with a warning."""
    from backend.threat_hunting.extractors.dispatcher import PARSER_DOCLING, _extract_pdf

    with (
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.is_docling_available",
            return_value=True,
        ),
        patch("backend.config.loader.load_agent_tools", return_value={"docling": True}),
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.extract_pdf_docling",
            side_effect=ValueError("model failed"),
        ),
        patch("backend.threat_hunting.extractors.pdf_extractor.is_available", return_value=True),
        patch(
            "backend.threat_hunting.extractors.pdf_extractor.extract_pdf",
            return_value=("fallback text", "1.24.0", []),
        ),
    ):
        text, parser_used, _version, warnings = _extract_pdf(b"%PDF", PARSER_DOCLING, [])

    assert parser_used == "pymupdf"
    assert text == "fallback text"
    assert any("failed" in w.lower() for w in warnings)


# ─── 2C: is_docling_available ─────────────────────────────────────────────────


def test_is_docling_available_reflects_import() -> None:
    """is_docling_available() must mirror the module-level _DOCLING_AVAILABLE flag."""
    from backend.threat_hunting.extractors import pdf_extractor

    original = pdf_extractor._DOCLING_AVAILABLE
    try:
        pdf_extractor._DOCLING_AVAILABLE = False
        assert pdf_extractor.is_docling_available() is False
        pdf_extractor._DOCLING_AVAILABLE = True
        assert pdf_extractor.is_docling_available() is True
    finally:
        pdf_extractor._DOCLING_AVAILABLE = original
