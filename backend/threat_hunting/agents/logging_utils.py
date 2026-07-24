"""Shared logging helper for the Threat Hunting pipeline (issue-local-019).

Every log line emitted while processing a hunt package/run should be
traceable back to that specific hunt_package_id/run_id — previously this was
done ad hoc (some call sites embedded a truncated pkg_id, most embedded
nothing, none embedded run_id), making it hard to `grep` all activity for one
hunt package or run out of the shared app.log.

``get_run_logger()`` returns a stdlib ``LoggerAdapter`` that prefixes every
message with ``[hunt=<id> run=<id>]`` automatically, so call sites only need
to acquire the adapter once (from data already in scope — every node
function already receives ``state["hunt_package_id"]``/``state.get("run_id")``)
and use it exactly like a normal logger.
"""

from __future__ import annotations

import logging
from typing import Any


class RunLoggerAdapter(logging.LoggerAdapter):
    """Prefixes every message with the bound hunt_package_id/run_id."""

    def process(self, msg: Any, kwargs: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        return f"{self.extra['prefix']} {msg}", kwargs


def get_run_logger(name: str, hunt_package_id: str | None, run_id: str | None) -> RunLoggerAdapter:
    """Return a logger for *name* whose every message is prefixed with the
    owning hunt_package_id/run_id (each shown truncated to 8 chars, matching
    this codebase's existing short-ID convention elsewhere in the pipeline).

    ``grep 'run=1a2b3c4d' logs/app.log`` then finds every log line for one
    specific run across runner.py and every node file in one shot.
    """
    base = logging.getLogger(name)
    hunt_part = f"hunt={hunt_package_id[:8]}" if hunt_package_id else "hunt=?"
    run_part = f"run={run_id[:8]}" if run_id else "run=?"
    return RunLoggerAdapter(base, {"prefix": f"[{hunt_part} {run_part}]"})
