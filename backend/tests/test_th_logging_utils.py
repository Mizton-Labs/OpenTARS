"""
Tests for issue-local-019's pipeline logging helper
(backend/threat_hunting/agents/logging_utils.py) — every log line emitted
while processing a hunt package/run should be traceable back to that
specific hunt_package_id/run_id.
"""

from __future__ import annotations

import logging

from backend.threat_hunting.agents.logging_utils import get_run_logger


def test_prefixes_message_with_truncated_hunt_and_run_ids() -> None:
    log = get_run_logger(
        __name__, "4a36e1ef-24ae-48f2-910f-eb3a14545774", "da08f463-677a-445b-9e81-86a4f3b1e76a"
    )
    msg, _ = log.process("hello", {})
    assert msg == "[hunt=4a36e1ef run=da08f463] hello"


def test_falls_back_to_placeholder_when_ids_are_missing() -> None:
    log = get_run_logger(__name__, None, None)
    msg, _ = log.process("hello", {})
    assert msg == "[hunt=? run=?] hello"


def test_handles_one_id_present_and_the_other_missing() -> None:
    log = get_run_logger(__name__, "4a36e1ef-24ae-48f2-910f-eb3a14545774", None)
    msg, _ = log.process("hello", {})
    assert msg == "[hunt=4a36e1ef run=?] hello"


def test_returned_object_is_a_working_logger_adapter(caplog) -> None:  # type: ignore[no-untyped-def]
    log = get_run_logger("th.test.logger", "hunt-1234", "run-5678")
    with caplog.at_level(logging.INFO, logger="th.test.logger"):
        log.info("run started")
    assert any("[hunt=hunt-123 run=run-5678] run started" in r.message for r in caplog.records)
