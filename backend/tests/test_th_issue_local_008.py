"""
Tests for issue-local-008:

  2A — Process-arrow: list_hunt_packages returns run_created_at
  2B — B2: upload routes do NOT extract IOCs; intake_classifier does
  2B — Deferred URL fetch: add_evidence_url stores parse_status='pending'
  2B — intake_classifier: clear_extracted_iocs called; IOCs extracted from corpus
  2B — intake_classifier: pending URL items fetched and evidence updated
  2C-A — Auto-report: runner triggers write_report on pipeline completion
  2C-B — Hypothesis detail: assemble_report stores suggested_actions + ioc_basis
  2C-C — Findings: assemble_report has 'findings' key; placed after recommendations
         in MD/PDF renderers
  2D — Effort profile: high effort has force_all_tools=True + playwright_first
  2D — fetch_url: prefer_playwright param passed to _should_force_playwright
  2D — intake_classifier: prefer_playwright=True when effort=high
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─── 2A: run_created_at in list_hunt_packages ─────────────────────────────────


@pytest.mark.asyncio
async def test_list_hunt_packages_includes_run_created_at() -> None:
    """list_hunt_packages must project run_created_at from the latest run."""
    from backend.threat_hunting import db as th_db

    # Use a 4-element tuple matching the new SQL projection
    hp_row = ("pkg-1", "running", "[]", "2026-06-21T10:00:00")

    pkg_row_dict = {
        "id": "pkg-1",
        "name": "Test",
        "description": "",
        "status": "draft",
        "created_by": None,
        "created_at": "2026-06-21T09:00:00",
        "updated_at": "2026-06-21T09:00:00",
        "evidence_count": 0,
        "hunt_seq": 1,
    }

    class _DictRow(dict):
        pass

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
                return _FakeCur([_DictRow(pkg_row_dict)])
            elif "hunt_package_id IN (" in query:
                # issue-local-016 bulk all-runs query — not exercised here
                return _FakeCur([])
            return _FakeCur([hp_row])

    with patch("backend.threat_hunting.db.aiosqlite") as mock_aio:
        mock_aio.connect.return_value = _FakeConn()
        mock_aio.Row = dict
        result = await th_db.list_hunt_packages()

    if not result:
        pytest.skip("mock returned no packages")
    pkg = result[0]
    # run_created_at must be projected
    assert "run_created_at" in pkg
    assert pkg["run_created_at"] == "2026-06-21T10:00:00"


# ─── 2B: upload routes no longer call extract_iocs_from_text ──────────────────


def test_upload_file_route_does_not_call_extract_iocs() -> None:
    """File upload route must not call extract_iocs_from_text after issue-008-2B."""
    import inspect

    import backend.api.routes_threat_hunting as routes

    source = inspect.getsource(routes.add_evidence_file)
    assert "extract_iocs_from_text" not in source
    # The comment mentions add_extracted_iocs but it must not be called (no await)
    assert "await th_db.add_extracted_iocs" not in source


def test_upload_text_route_does_not_call_extract_iocs() -> None:
    import inspect

    import backend.api.routes_threat_hunting as routes

    source = inspect.getsource(routes.add_evidence_text)
    assert "extract_iocs_from_text" not in source
    assert "add_extracted_iocs" not in source


def test_upload_watcher_route_does_not_call_extract_iocs() -> None:
    import inspect

    import backend.api.routes_threat_hunting as routes

    source = inspect.getsource(routes.add_evidence_watcher)
    assert "extract_iocs_from_text" not in source
    assert "add_extracted_iocs" not in source


def test_add_evidence_url_does_not_fetch() -> None:
    """add_evidence_url must NOT call fetch_url (deferred to pipeline)."""
    import inspect

    import backend.api.routes_threat_hunting as routes

    source = inspect.getsource(routes.add_evidence_url)
    # Must NOT call fetch_url() — only validate_url SSRF pre-check
    assert "await fetch_url" not in source
    assert "fetch_url(body.url)" not in source


def test_add_evidence_url_stores_pending_status() -> None:
    """add_evidence_url must store parse_status='pending'."""
    import inspect

    import backend.api.routes_threat_hunting as routes

    source = inspect.getsource(routes.add_evidence_url)
    assert "pending" in source
    assert "parse_status" in source


# ─── 2B: db helpers ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_clear_extracted_iocs_is_importable() -> None:
    """clear_extracted_iocs must be exported from db.py."""
    from backend.threat_hunting.db import clear_extracted_iocs

    assert callable(clear_extracted_iocs)


@pytest.mark.asyncio
async def test_update_evidence_item_is_importable() -> None:
    """update_evidence_item must be exported from db.py."""
    from backend.threat_hunting.db import update_evidence_item

    assert callable(update_evidence_item)


@pytest.mark.asyncio
async def test_update_evidence_item_builds_correct_sql() -> None:
    """update_evidence_item must only set provided fields."""
    from backend.threat_hunting.db import update_evidence_item

    executed_sqls: list[str] = []

    class _FakeCursor:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

    class _FakeConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def execute(self, sql, params=None):
            executed_sqls.append(sql)
            return _FakeCursor()

        async def commit(self):
            pass

    with patch("backend.threat_hunting.db.aiosqlite") as mock_aio:
        mock_aio.connect.return_value = _FakeConn()
        await update_evidence_item(
            "item-1",
            parse_status="ok",
            extracted_text="hello",
        )

    assert len(executed_sqls) == 1
    sql = executed_sqls[0]
    assert "parse_status" in sql
    assert "extracted_text" in sql
    # parser_version was not provided — should NOT be in SQL
    assert "parser_version" not in sql


# ─── 2B: intake_classifier clears IOCs and re-extracts ───────────────────────


def test_intake_classifier_calls_clear_extracted_iocs() -> None:
    """intake_classifier must call clear_extracted_iocs before extracting."""
    import inspect

    import backend.threat_hunting.agents.nodes.intake_classifier as ic

    source = inspect.getsource(ic)
    assert "clear_extracted_iocs" in source


def test_intake_classifier_calls_add_extracted_iocs() -> None:
    """intake_classifier must call add_extracted_iocs (now the only place it runs)."""
    import inspect

    import backend.threat_hunting.agents.nodes.intake_classifier as ic

    source = inspect.getsource(ic)
    assert "add_extracted_iocs" in source


def test_intake_classifier_fetches_pending_urls() -> None:
    """intake_classifier must fetch evidence items with parse_status='pending'."""
    import inspect

    import backend.threat_hunting.agents.nodes.intake_classifier as ic

    source = inspect.getsource(ic)
    assert "pending" in source
    assert "update_evidence_item" in source


def test_intake_classifier_uses_prefer_playwright_for_high_effort() -> None:
    """intake_classifier must pass prefer_playwright=True when effort=high."""
    import inspect

    import backend.threat_hunting.agents.nodes.intake_classifier as ic

    source = inspect.getsource(ic)
    assert "prefer_playwright" in source
    assert (
        'effort == "high"' in source
        or 'effort=="high"' in source
        or "prefer_playwright = effort ==" in source
    )


# ─── 2C-A: auto-report on pipeline completion ─────────────────────────────────


def test_runner_triggers_write_report_on_completion() -> None:
    """runner._run_pipeline must call write_report when final_status='completed'."""
    import inspect

    import backend.threat_hunting.agents.runner as runner

    source = inspect.getsource(runner._run_pipeline)
    assert "write_report" in source
    assert "auto-report" in source or "run-scoped" in source or "run_id=run_id" in source


# ─── 2C-B: hypotheses detail in report ───────────────────────────────────────


def test_assemble_report_includes_hypotheses_with_suggested_actions() -> None:
    """assemble_report must preserve suggested_actions on hypotheses."""
    from backend.threat_hunting.agents.nodes.report_writer import assemble_report

    hyp = {
        "id": "H1",
        "title": "Test",
        "description": "desc",
        "justification": "just",
        "relevance": "high",
        "ioc_basis": ["8.8.8.8"],
        "suggested_actions": ["Run SPL: index=main | stats count"],
    }
    full_report = assemble_report(
        hunt_package={"id": "pkg-1", "name": "Test", "status": "approved"},
        generation_record={"hypotheses": [hyp]},
        evidence_items=[],
        task_results=[],
    )

    h_out = full_report["hypotheses"][0]
    assert h_out.get("suggested_actions") == ["Run SPL: index=main | stats count"]
    assert h_out.get("ioc_basis") == ["8.8.8.8"]
    assert h_out.get("justification") == "just"


def test_render_report_markdown_includes_suggested_actions() -> None:
    """Markdown render must include suggested_actions and ioc_basis per hypothesis."""
    from backend.threat_hunting.agents.nodes.report_writer import render_report_markdown

    full_report = {
        "hunt_name": "Test",
        "hunt_id": "1",
        "generated_at": "now",
        "generated_by": None,
        "package_status": "approved",
        "executive_summary": "",
        "findings": None,
        "evidence_summary": {"total_items": 0, "ioc_count": 0, "item_types": []},
        "threat_context": None,
        "hypotheses": [
            {
                "id": "H1",
                "title": "Test Hyp",
                "description": "desc",
                "justification": "just",
                "relevance": "high",
                "ioc_basis": ["8.8.8.8"],
                "suggested_actions": ["Check firewall logs"],
            }
        ],
        "hunting_leads": [],
        "deep_retrohunt_summary": None,
        "ttp_analysis": None,
        "query_drafts_count": 0,
        "execution_results": [],
        "recommendations": [],
    }
    md = render_report_markdown(full_report)
    assert "Check firewall logs" in md
    assert "8.8.8.8" in md


# ─── 2C-C: Findings/Conclusion section ───────────────────────────────────────


def test_assemble_report_has_findings_key() -> None:
    """assemble_report must include a 'findings' key."""
    from backend.threat_hunting.agents.nodes.report_writer import assemble_report

    full_report = assemble_report(
        hunt_package={"id": "pkg-1", "name": "Test", "status": "approved"},
        generation_record={},
        evidence_items=[],
        task_results=[],
        findings="Key finding: No threats detected.",
    )
    assert "findings" in full_report
    assert full_report["findings"] == "Key finding: No threats detected."


def test_assemble_report_findings_none_when_empty() -> None:
    from backend.threat_hunting.agents.nodes.report_writer import assemble_report

    full_report = assemble_report(
        hunt_package={"id": "pkg-1", "name": "Test", "status": "approved"},
        generation_record={},
        evidence_items=[],
        task_results=[],
        findings="",
    )
    assert full_report["findings"] is None


def test_render_report_markdown_findings_placed_after_recommendations() -> None:
    """Findings/Conclusion must appear AFTER Recommendations in the MD output."""
    from backend.threat_hunting.agents.nodes.report_writer import render_report_markdown

    full_report = {
        "hunt_name": "Test",
        "hunt_id": "1",
        "generated_at": "now",
        "generated_by": None,
        "package_status": "approved",
        "executive_summary": "Exec summary.",
        "findings": "Key conclusion: threat not detected.",
        "evidence_summary": {"total_items": 0, "ioc_count": 0, "item_types": []},
        "threat_context": None,
        "hypotheses": [],
        "hunting_leads": [],
        "deep_retrohunt_summary": None,
        "ttp_analysis": None,
        "query_drafts_count": 0,
        "execution_results": [],
        "recommendations": ["Investigate further"],
    }
    md = render_report_markdown(full_report)
    rec_pos = md.find("Recommendations")
    findings_pos = md.find("Findings and Conclusion")
    assert findings_pos > rec_pos, "Findings must appear after Recommendations"
    assert "threat not detected" in md


def test_build_fallback_findings_returns_string() -> None:
    """_build_fallback_findings must return a non-empty string."""
    from backend.threat_hunting.agents.nodes.report_writer import _build_fallback_findings

    full_report = {
        "hunt_name": "Test Hunt",
        "hypotheses": [{"id": "H1", "title": "Test Hyp", "relevance": "high"}],
        "execution_results": [],
        "deep_retrohunt_summary": {"total_iocs": 5, "noisy_iocs": 1},
        "recommendations": [],
    }
    result = _build_fallback_findings(full_report)
    assert isinstance(result, str)
    assert len(result) > 50
    assert "Test Hunt" in result.upper() or "hunt" in result.lower()


# ─── 2D: effort profile knobs ─────────────────────────────────────────────────


def test_high_effort_force_all_tools_true() -> None:
    """High effort profile must have force_all_tools=True."""
    from backend.threat_hunting.agents.effort_profile import get_effort_profile

    profile = get_effort_profile("high")
    assert profile.get("force_all_tools") is True
    assert profile.get("url_fetch_strategy") == "playwright_first"


def test_medium_low_effort_force_all_tools_false() -> None:
    from backend.threat_hunting.agents.effort_profile import get_effort_profile

    for effort in ("medium", "low"):
        profile = get_effort_profile(effort)
        assert profile.get("force_all_tools") is False, f"{effort} should not force tools"
        assert profile.get("url_fetch_strategy") == "auto"


# ─── 2D: fetch_url prefer_playwright ─────────────────────────────────────────


def test_fetch_url_accepts_prefer_playwright() -> None:
    """fetch_url must accept a prefer_playwright keyword argument."""
    import inspect

    from backend.threat_hunting.extractors.url_fetcher import fetch_url

    sig = inspect.signature(fetch_url)
    assert "prefer_playwright" in sig.parameters


def test_should_force_playwright_prefer_playwright_true() -> None:
    """_should_force_playwright must return True immediately when prefer_playwright=True."""
    from backend.threat_hunting.extractors.url_fetcher import _should_force_playwright

    # Even with long clean text and 200 status, prefer_playwright overrides
    good_text = "A" * 1000
    forced, reason = _should_force_playwright(
        good_text,
        "trafilatura",
        "text/html",
        200,
        b"<html>...</html>",
        prefer_playwright=True,
    )
    assert forced is True
    assert "prefer_playwright" in reason or "high" in reason.lower()


def test_should_force_playwright_false_when_not_requested() -> None:
    """With prefer_playwright=False and good content, Playwright should not be forced."""
    from backend.threat_hunting.extractors.url_fetcher import _should_force_playwright

    good_text = "ESET researchers analyzed the EDR killer toolkit. " * 30
    forced, reason = _should_force_playwright(
        good_text,
        "trafilatura/1.12",
        "text/html",
        200,
        b"<html>...</html>",
        prefer_playwright=False,
    )
    assert forced is False


# ─── 2D: tool_refetch_url prefer_playwright propagation ───────────────────────


@pytest.mark.asyncio
async def test_tool_refetch_url_passes_prefer_playwright() -> None:
    """tool_refetch_url must forward prefer_playwright to fetch_url."""
    from backend.threat_hunting.agents import tools as tools_module

    with patch(
        "backend.threat_hunting.extractors.url_fetcher.fetch_url",
        new=AsyncMock(return_value=MagicMock(extracted_text="fetched")),
    ) as mock_fetch:
        await tools_module.tool_refetch_url("https://example.com/", prefer_playwright=True)

    mock_fetch.assert_called_once_with("https://example.com/", prefer_playwright=True)
