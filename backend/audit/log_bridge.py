"""
Logging → audit_events bridge (issue-local-033).

Feeds the "Application" and "System" Audit tabs from the logging channels
that already exist rather than adding new call sites throughout the
codebase — see backend/audit/db.py's module docstring for the full picture.
"""

from __future__ import annotations

import asyncio
import logging
import sys


class AuditLogHandler(logging.Handler):
    """Persists matching log records as ``audit_events`` rows.

    Never raises and never itself logs through the ``logging`` module — a
    handler attached to (or, via propagation, downstream of) the very
    logger it is listening to must not report its own failures back through
    that same channel, so failures here go to stderr directly.

    Best-effort: if there is no running event loop yet (log lines emitted
    before uvicorn's loop starts), the record is silently dropped rather
    than blocking or erroring — the same acceptable-loss tradeoff every
    other soft-fail audit path in this module makes.
    """

    def __init__(self, category: str, level: int = logging.NOTSET) -> None:
        super().__init__(level=level)
        self._category = category

    def emit(self, record: logging.LogRecord) -> None:
        # Local import: avoids a module-load-order dependency between
        # logging_config.py (imported very early, before backend.audit.db's
        # own imports — notably aiosqlite — are necessarily ready) and this
        # handler, which is only ever exercised once logging is live.
        from backend.audit.db import record_event
        from backend.audit.interpret import interpret_log_message, interpret_system_log

        try:
            message = record.getMessage()
        except Exception:
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        try:
            # issue-local-033 (follow-up): action is a short interpretation,
            # not the raw logger name — summary keeps the actual message.
            if self._category == "system":
                action = interpret_system_log(record.name, record.levelname, message)
            else:
                action = interpret_log_message(record.name, message)
            loop.create_task(
                record_event(
                    self._category,
                    action,
                    summary=message,
                    detail={"level": record.levelname, "logger": record.name},
                )
            )
        except Exception as exc:  # pragma: no cover — defensive
            print(f"AuditLogHandler: failed to schedule record_event: {exc}", file=sys.stderr)
