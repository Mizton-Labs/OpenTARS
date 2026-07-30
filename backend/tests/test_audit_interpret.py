"""
Tests for backend.audit.interpret (issue-local-033 follow-up): route-driven
category classification, curated action labels + algorithmic fallback,
agent step-key interpretation, and log-message interpretation for the
Application/System log-bridge categories.
"""

from __future__ import annotations

from backend.audit import interpret


class TestClassifyAndInterpret:
    def test_auth_routes_are_user_category(self) -> None:
        category, action = interpret.classify_and_interpret("POST", "/api/auth/login")
        assert category == "user"
        assert action == "Signed in"

    def test_non_auth_routes_are_application_category(self) -> None:
        category, action = interpret.classify_and_interpret("POST", "/api/threat-hunting/packages")
        assert category == "application"
        assert action == "Created hunt package"

    def test_curated_table_matches_path_with_id_segments(self) -> None:
        category, action = interpret.classify_and_interpret(
            "PATCH", "/api/threat-hunting/packages/pkg-123/runs/run-456/iocs"
        )
        assert category == "application"
        assert action == "Updated IOC verdicts"

    def test_delete_user_is_user_category(self) -> None:
        category, action = interpret.classify_and_interpret("DELETE", "/api/auth/users/5")
        assert category == "user"
        assert action == "Deleted user account"

    def test_unmapped_route_falls_back_to_humanized_label(self) -> None:
        category, action = interpret.classify_and_interpret(
            "POST", "/api/threat-hunting/packages/pkg-1/runs/run-1/comments"
        )
        # This one IS in the curated table — confirm it resolves via the
        # table, not the fallback (the fallback test below uses a route that
        # genuinely isn't mapped).
        assert category == "application"
        assert action == "Added a comment"

    def test_truly_unmapped_route_uses_algorithmic_fallback(self) -> None:
        category, action = interpret.classify_and_interpret(
            "POST", "/api/some-future-router/widgets/abc-123-def/spin"
        )
        assert category == "application"
        assert action == "Created Spin"

    def test_fallback_strips_id_like_segments(self) -> None:
        # A bare numeric id and a long opaque token both get dropped, leaving
        # the last real resource-name segment.
        action = interpret._fallback_action("DELETE", "/api/foo/123/bar/abcdef0123456789")
        assert action == "Deleted Bar"


class TestInterpretAgentStep:
    def test_graph_node_ok(self) -> None:
        assert interpret.interpret_agent_step("hypothesis_generator", "ok") == (
            "Generated hunting hypotheses"
        )

    def test_graph_node_error(self) -> None:
        assert interpret.interpret_agent_step("hypothesis_generator", "error") == (
            "Hypothesis generation failed"
        )

    def test_siem_step_running_ok_error(self) -> None:
        assert interpret.interpret_agent_step("siem_connect", "running") == (
            "Connecting to SIEM connector"
        )
        assert interpret.interpret_agent_step("siem_connect", "ok") == (
            "Connected to SIEM connector"
        )
        assert interpret.interpret_agent_step("siem_connect", "error") == (
            "Failed to connect to SIEM connector"
        )

    def test_report_writer(self) -> None:
        assert interpret.interpret_agent_step("report_writer", "ok") == "Generated hunt report"
        assert interpret.interpret_agent_step("report_writer", "error") == (
            "Report generation failed"
        )

    def test_threat_intel_phases(self) -> None:
        assert interpret.interpret_agent_step("threat_intel_preliminary", "ok") == (
            "Ran preliminary threat intel analysis"
        )
        assert interpret.interpret_agent_step("threat_intel_final", "ok") == (
            "Ran threat intel analysis"
        )

    def test_unknown_step_key_falls_back_to_humanized_key(self) -> None:
        assert interpret.interpret_agent_step("some_future_node", "ok") == "Some Future Node"


class TestInterpretLogMessage:
    def test_ingest_message_with_known_mode(self) -> None:
        action = interpret.interpret_log_message(
            "api_pull",
            "ingest source=feed1 mode=api_pull total_read=10 inserted=5 duplicates=2 discarded=3 errors=0",
        )
        assert action == "Ingested via API pull"

    def test_ingest_message_with_unknown_mode_uses_raw_mode(self) -> None:
        action = interpret.interpret_log_message("some.module", "ingest source=x mode=weird_mode")
        assert action == "Ingested via weird_mode"

    def test_known_event_labels(self) -> None:
        assert (
            interpret.interpret_log_message(
                "push_listener", "listener_receive source=x events=1 bytes=2"
            )
            == "Received listener push"
        )
        assert (
            interpret.interpret_log_message(
                "source_preview", "source_preview_confirmed kind=x name=y"
            )
            == "Confirmed source preview"
        )

    def test_unrecognized_message_falls_back_to_logger_name(self) -> None:
        action = interpret.interpret_log_message(
            "backend.ingestion.custom_thing", "totally free text"
        )
        assert action == "Custom Thing activity"


class TestInterpretSystemLog:
    def test_lifecycle_startup(self) -> None:
        action = interpret.interpret_system_log(
            "backend.system", "INFO", "OpenTARS startup complete (version 0.1.0)"
        )
        assert action == "Application startup"

    def test_lifecycle_shutdown(self) -> None:
        action = interpret.interpret_system_log("backend.system", "INFO", "OpenTARS shutting down")
        assert action == "Application shutdown"

    def test_warning_from_arbitrary_module(self) -> None:
        action = interpret.interpret_system_log(
            "backend.threat_hunting.siem.executor", "WARNING", "something went wrong"
        )
        assert action == "Warning in Executor"

    def test_error_level_label(self) -> None:
        action = interpret.interpret_system_log("backend.llm.client", "ERROR", "boom")
        assert action == "Error in Client"
