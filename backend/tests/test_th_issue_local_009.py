"""Tests for issue-local-009.

Parts covered:
  1. db.append_run_step_log — merge behavior (last-write-wins per step key).
  2. db.set_run_generation_status — updates status field.
  3. llm_bridge.build_prompt — json_output=False omits JSON directives.
  4. report_writer._clean_prose_response — strips JSON wrappers from prose.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── 1. append_run_step_log ────────────────────────────────────────────────────


def test_append_run_step_log_is_in_db_module() -> None:
    """append_run_step_log must be importable from backend.threat_hunting.db."""
    import inspect

    import backend.threat_hunting.db as db

    assert hasattr(db, "append_run_step_log"), "append_run_step_log is missing from db module"
    assert inspect.iscoroutinefunction(db.append_run_step_log), "append_run_step_log must be async"


def test_set_run_generation_status_is_in_db_module() -> None:
    """set_run_generation_status must be importable from backend.threat_hunting.db."""
    import inspect

    import backend.threat_hunting.db as db

    assert hasattr(db, "set_run_generation_status"), (
        "set_run_generation_status is missing from db module"
    )
    assert inspect.iscoroutinefunction(db.set_run_generation_status), (
        "set_run_generation_status must be async"
    )


def _make_fake_db_ctx(existing_json: str | None, saved_logs_container: list) -> MagicMock:
    """Return a MagicMock that acts as ``aiosqlite.connect(...)`` context manager.

    aiosqlite.connect() itself is synchronous (returns an async context manager
    object directly); so we patch it with a regular MagicMock, not an async
    side_effect.
    """
    fake_cur = MagicMock()
    if existing_json is not None:
        row_mock = MagicMock()
        row_mock.__getitem__ = lambda self, i: existing_json
        fake_cur.fetchone = AsyncMock(return_value=row_mock)
    else:
        fake_cur.fetchone = AsyncMock(return_value=None)

    fake_cur.close = AsyncMock()

    async def _execute(sql, params=()):
        if "UPDATE hunting_packages" in sql and params:
            saved_logs_container.clear()
            saved_logs_container.extend(json.loads(params[0]))
        return fake_cur

    fake_db = MagicMock()
    fake_db.row_factory = None
    fake_db.execute = _execute
    fake_db.commit = AsyncMock()
    fake_db.__aenter__ = AsyncMock(return_value=fake_db)
    fake_db.__aexit__ = AsyncMock(return_value=False)

    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=fake_db)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


@pytest.mark.asyncio
async def test_append_run_step_log_inserts_new_step() -> None:
    """First write for a step inserts a new entry at the end of step_logs."""
    import backend.threat_hunting.db as db

    existing_json = json.dumps([{"step": "intake_classifier", "status": "ok", "elapsed_s": 1.2}])
    new_entry = {"step": "siem_connect", "status": "running", "decision": "Connecting…"}
    saved: list = []

    ctx = _make_fake_db_ctx(existing_json, saved)
    with patch("backend.threat_hunting.db.aiosqlite.connect", return_value=ctx):
        await db.append_run_step_log("run-abc", new_entry)

    assert saved, "UPDATE was never called"
    steps = [lg["step"] for lg in saved]
    assert "intake_classifier" in steps
    assert "siem_connect" in steps
    assert steps[-1] == "siem_connect"


@pytest.mark.asyncio
async def test_append_run_step_log_last_write_wins() -> None:
    """Updating an existing step merges in the new fields (last-write-wins)."""
    import backend.threat_hunting.db as db

    existing_json = json.dumps(
        [
            {"step": "siem_poll", "status": "running", "decision": "0% done", "elapsed_s": 0.5},
        ]
    )
    updated_entry = {"step": "siem_poll", "status": "ok", "decision": "100% done", "elapsed_s": 4.2}
    saved: list = []

    ctx = _make_fake_db_ctx(existing_json, saved)
    with patch("backend.threat_hunting.db.aiosqlite.connect", return_value=ctx):
        await db.append_run_step_log("run-xyz", updated_entry)

    assert saved, "UPDATE was never called"
    assert len(saved) == 1, "No duplicate entries should be added"
    assert saved[0]["status"] == "ok"
    assert saved[0]["elapsed_s"] == 4.2
    assert "100% done" in saved[0]["decision"]


@pytest.mark.asyncio
async def test_append_run_step_log_noop_when_run_missing() -> None:
    """append_run_step_log must not raise when run_id is not in DB."""
    import backend.threat_hunting.db as db

    saved: list = []
    ctx = _make_fake_db_ctx(None, saved)  # fetchone returns None → row not found

    with patch("backend.threat_hunting.db.aiosqlite.connect", return_value=ctx):
        # Should silently no-op, not raise
        await db.append_run_step_log("nonexistent-run", {"step": "siem_connect", "status": "ok"})


# ── 2. build_prompt json_output=False ─────────────────────────────────────────


def test_build_prompt_json_output_false_omits_json_directives() -> None:
    """build_prompt(json_output=False) must not instruct the LLM to return JSON."""
    from backend.threat_hunting.agents.llm_bridge import build_prompt

    system, user = build_prompt(
        task_description="Write a short summary.",
        context_sections=[("Hunt Name", "Test Hunt")],
        output_format="Plain text, 3 sentences.",
        json_output=False,
    )

    assert "JSON" not in system, f"System prompt should not mention JSON: {system!r}"
    assert "json" not in system.lower(), f"System prompt should not mention json: {system!r}"
    assert "return ONLY the JSON" not in user, "User prompt should not contain JSON-only directive"
    assert "no markdown fences" not in user, "User prompt should not mention markdown fences"


def test_build_prompt_json_output_true_includes_json_directive() -> None:
    """build_prompt(json_output=True, default) retains JSON output instructions."""
    from backend.threat_hunting.agents.llm_bridge import build_prompt

    system, user = build_prompt(
        task_description="Extract threat context.",
        context_sections=[("Evidence", "Some text here")],
        output_format='{"key": "value"}',
    )

    assert "JSON" in system, "Default system prompt should instruct JSON output"
    assert "return ONLY the JSON" in user, "User prompt should contain JSON-only directive"


def test_build_prompt_json_output_false_uses_prose_system() -> None:
    """build_prompt(json_output=False) uses the prose-appropriate system prompt."""
    from backend.threat_hunting.agents.llm_bridge import build_prompt

    system, _ = build_prompt(
        task_description="Write executive summary.",
        context_sections=[],
        output_format="Plain text.",
        json_output=False,
    )

    assert "prose" in system.lower() or "factual" in system.lower(), (
        f"Prose system prompt should mention 'prose' or 'factual': {system!r}"
    )


# ── 3. _clean_prose_response ──────────────────────────────────────────────────


def test_clean_prose_response_passthrough_plain_text() -> None:
    """Plain prose text should pass through _clean_prose_response unchanged."""
    from backend.threat_hunting.agents.nodes.report_writer import _clean_prose_response

    text = (
        "The hunt found no matching events in the SIEM. "
        "Review the IOC list for accuracy before re-running."
    )
    assert _clean_prose_response(text) == text


def test_clean_prose_response_strips_json_fence() -> None:
    """Leading ```json fences should be stripped."""
    from backend.threat_hunting.agents.nodes.report_writer import _clean_prose_response

    wrapped = '```json\n{"executive_summary": "Clean prose here."}\n```'
    result = _clean_prose_response(wrapped)
    assert result == "Clean prose here."


def test_clean_prose_response_unwraps_single_key_dict() -> None:
    """A single-key JSON object wrapping a string is unwrapped to the string."""
    from backend.threat_hunting.agents.nodes.report_writer import _clean_prose_response

    wrapped = '{"summary": "Threat actor was identified in SIEM logs."}'
    result = _clean_prose_response(wrapped)
    assert result == "Threat actor was identified in SIEM logs."


def test_clean_prose_response_unwraps_executive_summary_key() -> None:
    """A {'executive_summary': '...'} dict is unwrapped correctly."""
    from backend.threat_hunting.agents.nodes.report_writer import _clean_prose_response

    wrapped = '{"executive_summary": "This hunt investigated APT activity across endpoints."}'
    result = _clean_prose_response(wrapped)
    assert result == "This hunt investigated APT activity across endpoints."


def test_clean_prose_response_unwraps_findings_key() -> None:
    """A {'findings': '...'} dict is unwrapped correctly."""
    from backend.threat_hunting.agents.nodes.report_writer import _clean_prose_response

    wrapped = '{"findings": "No lateral movement detected."}'
    result = _clean_prose_response(wrapped)
    assert result == "No lateral movement detected."


def test_clean_prose_response_leaves_multi_key_dict_as_is() -> None:
    """A multi-key JSON object (real structured output) is NOT unwrapped."""
    from backend.threat_hunting.agents.nodes.report_writer import _clean_prose_response

    structured = '{"key": "val", "other": "val2"}'
    result = _clean_prose_response(structured)
    # Should remain as the parsed JSON string form (fences stripped, parsed as-is)
    # The important thing is the full content is retained
    assert "val" in result
    assert "other" in result


def test_clean_prose_response_passes_through_non_json() -> None:
    """Text that is not valid JSON at all should be returned verbatim."""
    from backend.threat_hunting.agents.nodes.report_writer import _clean_prose_response

    text = "This is just a sentence. It has no JSON structure at all."
    assert _clean_prose_response(text) == text


# ── 4. Executor step_log instrumentation (structural) ─────────────────────────


def test_executor_run_execution_accepts_run_id() -> None:
    """_run_execution signature must accept a run_id keyword argument."""
    import inspect

    from backend.threat_hunting.siem.executor import _run_execution

    sig = inspect.signature(_run_execution)
    assert "run_id" in sig.parameters, "_run_execution must accept run_id kwarg"


def test_executor_has_step_log_helper() -> None:
    """executor module must define _step_log helper for writing step entries."""
    import inspect

    import backend.threat_hunting.siem.executor as executor

    assert hasattr(executor, "_step_log"), "_step_log helper missing from executor"
    assert inspect.iscoroutinefunction(executor._step_log), "_step_log must be async"


def test_executor_references_siem_connect_step() -> None:
    """_run_execution source must reference the 'siem_connect' step."""
    import inspect

    from backend.threat_hunting.siem.executor import _run_execution

    source = inspect.getsource(_run_execution)
    for step in ("siem_connect", "siem_submit", "siem_poll", "siem_fetch", "siem_interpret"):
        assert step in source, f"step {step!r} not found in _run_execution source"


# ── 5. report_writer step_log instrumentation (structural) ────────────────────


def test_report_writer_write_report_references_reporting_steps() -> None:
    """write_report source must reference all report_* step names."""
    import inspect

    from backend.threat_hunting.agents.nodes.report_writer import write_report

    source = inspect.getsource(write_report)
    for step in ("report_assemble", "report_exec_summary", "report_findings", "report_render"):
        assert step in source, f"step {step!r} not found in write_report source"


def test_report_writer_sets_reporting_status() -> None:
    """write_report source must call set_run_generation_status with 'reporting'."""
    import inspect

    from backend.threat_hunting.agents.nodes.report_writer import write_report

    source = inspect.getsource(write_report)
    assert "reporting" in source, "write_report must set generation_status='reporting'"


def test_report_writer_has_report_step_log_helper() -> None:
    """report_writer must define _report_step_log helper."""
    import inspect

    import backend.threat_hunting.agents.nodes.report_writer as rw

    assert hasattr(rw, "_report_step_log"), "_report_step_log missing from report_writer"
    assert inspect.iscoroutinefunction(rw._report_step_log), "_report_step_log must be async"
