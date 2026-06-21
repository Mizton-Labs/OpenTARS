"""Abstract base for SIEM connectors (Phase 5).

All connectors must implement:
  - test_connection() → ConnectorTestResult
  - submit_search(spl, earliest, latest, hunt_id) → str (job sid)
  - poll_job(sid) → JobStatus
  - fetch_results(sid, *, offset, count) → list[dict]
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ConnectorTestResult:
    ok: bool
    message: str
    server_info: dict[str, Any] | None = None


@dataclass
class JobStatus:
    sid: str
    done: bool
    failed: bool
    progress: float  # 0.0–1.0
    event_count: int
    message: str = ""


class SIEMConnectorBase:
    """Abstract base — all connectors must subclass this."""

    kind: str = "base"

    async def test_connection(self) -> ConnectorTestResult:  # pragma: no cover
        raise NotImplementedError

    async def submit_search(
        self,
        spl: str,
        *,
        earliest: str = "-24h",
        latest: str = "now",
        hunt_id: str = "",
    ) -> str:  # pragma: no cover
        """Submit a search job. Returns the job SID."""
        raise NotImplementedError

    async def poll_job(self, sid: str) -> JobStatus:  # pragma: no cover
        raise NotImplementedError

    async def fetch_results(
        self, sid: str, *, offset: int = 0, count: int = 100
    ) -> list[dict[str, Any]]:  # pragma: no cover
        raise NotImplementedError
