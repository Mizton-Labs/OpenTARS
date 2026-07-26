"""
Regression tests for issue-local-022 Part A: render_report_pdf() crashed
(inconsistently, depending on a given run's LLM output shape) whenever a
hypothesis/hunting-lead/TTP-technique field was explicitly `None` rather than
merely absent — dict.get(key, default) only substitutes the default when the
key is *missing*, not when its value is None. Also covers the Findings
section's double-escape bug.
"""

from __future__ import annotations

from backend.threat_hunting.agents.nodes.report_writer import (
    _generate_findings,
    assemble_report,
    render_report_pdf,
)


def _base_report(**overrides: object) -> dict:
    report = assemble_report(
        hunt_package={"name": "Test Hunt", "id": "pkg-1", "status": "completed"},
        generation_record={},
        evidence_items=[],
        task_results=[],
        executive_summary="Executive summary text.",
    )
    report.update(overrides)
    return report


class TestNullHypothesisFields:
    def test_none_relevance_does_not_crash(self) -> None:
        report = _base_report(
            hypotheses=[
                {
                    "id": "H1",
                    "title": "Test hypothesis",
                    "description": "desc",
                    "relevance": None,
                    "justification": None,
                    "ioc_basis": None,
                    "suggested_actions": None,
                }
            ]
        )
        pdf_bytes = render_report_pdf(report)
        assert pdf_bytes[:4] == b"%PDF"

    def test_none_description_does_not_crash(self) -> None:
        report = _base_report(
            hypotheses=[{"id": "H1", "title": "t", "description": None, "relevance": "high"}]
        )
        pdf_bytes = render_report_pdf(report)
        assert pdf_bytes[:4] == b"%PDF"


class TestNullHuntingLeadFields:
    def test_none_priority_and_hypothesis_id_do_not_crash(self) -> None:
        report = _base_report(
            hunting_leads=[
                {
                    "id": "L1",
                    "title": "Lead",
                    "priority": None,
                    "hypothesis_id": None,
                    "description": None,
                    "tasks": [{"id": "T1.1", "title": None, "description": None}],
                }
            ]
        )
        pdf_bytes = render_report_pdf(report)
        assert pdf_bytes[:4] == b"%PDF"


class TestNullTtpFields:
    def test_none_technique_fields_do_not_crash(self) -> None:
        report = _base_report(
            ttp_analysis={
                "summary": "s",
                "techniques": [
                    {
                        "technique_id": "T1059",
                        "technique_name": None,
                        "tactic": None,
                        "description": None,
                    }
                ],
                "detection_opportunities": [None, "a real one"],
            }
        )
        pdf_bytes = render_report_pdf(report)
        assert pdf_bytes[:4] == b"%PDF"


class TestFindingsNotDoubleEscaped:
    def test_ampersand_in_findings_renders_without_raising(self) -> None:
        report = _base_report(findings="Confirmed C2 traffic to A & B.\n\nSecond paragraph.")
        pdf_bytes = render_report_pdf(report)
        assert pdf_bytes[:4] == b"%PDF"
        # The double-escape itself (& -> &amp; -> &amp;amp;) is a silent
        # visual corruption, not a crash — see TestSourceLevelDoubleEscapeGuard
        # below for the actual regression guard on the fix.


class TestGenerateFindingsPromptDoesNotCrashOnNoneDescription:
    async def test_none_hypothesis_description_in_prompt_builder(self) -> None:
        report = _base_report(
            hypotheses=[{"id": "H1", "title": "t", "relevance": "high", "description": None}]
        )
        # _generate_findings builds an LLM prompt string from full_report —
        # the bug was a crash while building hyp_lines, before any LLM call
        # happens, so this must not raise even without a working LLM backend.
        try:
            await _generate_findings(report, provider_name=None, model_name=None)
        except Exception as exc:  # noqa: BLE001
            # Only acceptable exception is a genuine LLM-unavailable error
            # (soft-failed internally to a template — see report_writer.py);
            # a TypeError from `None[:200]` must never occur.
            assert not isinstance(exc, TypeError), f"hyp_lines slicing crashed: {exc}"


class TestSourceLevelDoubleEscapeGuard:
    def test_findings_render_no_longer_calls_esc_before_p(self) -> None:
        import inspect

        from backend.threat_hunting.agents.nodes import report_writer

        source = inspect.getsource(report_writer.render_report_pdf)
        # The old bug: `_p(_esc(para))` inside the Findings loop. Guard
        # against reintroducing it.
        assert "_p(_esc(para))" not in source
