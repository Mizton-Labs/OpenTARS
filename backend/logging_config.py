"""
Logging configuration for OpenTARS.

Sets up two output channels:
  - stdout StreamHandler  (all levels, same as before)
  - logs/app.log          (RotatingFileHandler, all levels)
  - logs/audit.log        (RotatingFileHandler, INFO+, backend.audit logger only)
  - logs/system.log       (RotatingFileHandler, INFO+, backend.system logger only)

Also attaches AuditLogHandler (backend/audit/log_bridge.py, issue-local-033)
so the "Application" and "System" Audit tabs are fed from these same
channels: backend.audit → category "application"; backend.system (explicit
lifecycle milestones) and the root logger at WARNING+ (real problems,
anywhere) → category "system".

Call setup_logging() once at application startup (main.py).
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from backend.audit.log_bridge import AuditLogHandler

_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FMT = "%Y-%m-%dT%H:%M:%S"
_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
_BACKUP_COUNT = 5


def setup_logging(log_dir: Path) -> None:
    """
    Configure root logger and the backend.audit named logger.

    Args:
        log_dir: Directory where log files are written.  Created if absent.
    """
    log_dir.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(_FMT, datefmt=_DATE_FMT)

    # ── Root logger ──────────────────────────────────────────────────────────
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Remove any handlers already attached (e.g. from a previous basicConfig call)
    root.handlers.clear()

    # stdout
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    # app.log — all INFO+ messages
    app_handler = logging.handlers.RotatingFileHandler(
        log_dir / "app.log",
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    app_handler.setFormatter(formatter)
    root.addHandler(app_handler)

    # ── Audit logger ─────────────────────────────────────────────────────────
    audit_logger = logging.getLogger("backend.audit")
    audit_logger.setLevel(logging.DEBUG)  # DEBUG emitted only if root allows it
    audit_logger.propagate = True  # flows through root handlers above

    # audit.log — dedicated file for structured ingestion events (INFO+)
    audit_handler = logging.handlers.RotatingFileHandler(
        log_dir / "audit.log",
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    audit_handler.setLevel(logging.INFO)
    audit_handler.setFormatter(formatter)
    audit_logger.addHandler(audit_handler)

    # issue-local-033: feed the Audit section's "Application" tab from this
    # same logger — a queryable, filterable, per-actor home for the same
    # events audit.log already captured as flat text.
    audit_logger.addHandler(AuditLogHandler("application", level=logging.INFO))

    # ── System logger (issue-local-033) ─────────────────────────────────────
    # Dedicated channel for informational lifecycle milestones (startup,
    # schema migrations, ...) — explicit log calls at those points, not a
    # blanket capture (most INFO-level app logging is normal operation, not
    # "system log" material).
    system_logger = logging.getLogger("backend.system")
    system_logger.setLevel(logging.DEBUG)
    system_logger.propagate = True

    system_handler = logging.handlers.RotatingFileHandler(
        log_dir / "system.log",
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    system_handler.setLevel(logging.INFO)
    system_handler.setFormatter(formatter)
    system_logger.addHandler(system_handler)
    system_logger.addHandler(AuditLogHandler("system", level=logging.INFO))

    # Also feed "System" from any WARNING+ record anywhere in the app (real
    # problems — failed DB inits, unhandled exceptions, degraded providers —
    # are genuine system-log material regardless of which module logged
    # them). Attached to root, so this does not depend on every such call
    # site using the backend.system logger specifically.
    root.addHandler(AuditLogHandler("system", level=logging.WARNING))

    # ── Watchers logger ──────────────────────────────────────────────────────
    # Dedicated channel for watcher evaluation / trigger / error events
    # (issue_local_006). Propagates through the root handlers above and also
    # writes its own file so operators can audit watcher activity in isolation.
    watchers_logger = logging.getLogger("backend.watchers")
    watchers_logger.setLevel(logging.DEBUG)
    watchers_logger.propagate = True

    watchers_handler = logging.handlers.RotatingFileHandler(
        log_dir / "watchers.log",
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    watchers_handler.setLevel(logging.INFO)
    watchers_handler.setFormatter(formatter)
    watchers_logger.addHandler(watchers_handler)
