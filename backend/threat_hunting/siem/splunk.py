"""Splunk REST API connector for Threat Hunting execution (Phase 5).

Implements the Splunk REST API v2 search flow:
  1. GET /services/server/info         — connection test
  2. POST /services/search/jobs        — submit search, receive SID
  3. GET /services/search/jobs/{sid}   — poll job status
  4. GET /services/search/jobs/{sid}/results — fetch results (paginated)

Authentication:
  - Bearer token (Splunk token auth, recommended)
  - Basic auth (username + password)

Security:
  - API tokens stored as write-only; plain value kept in memory only during
    the request that provides it.
  - TLS verification on by default; disabling emits a WARNING log.
  - All HTTP calls use httpx with explicit timeouts.
  - No raw Splunk responses are executed — they are treated as data only.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any

import httpx

from backend.threat_hunting.siem.base import (
    ConnectorTestResult,
    JobStatus,
    SIEMConnectorBase,
)

logger = logging.getLogger(__name__)

# How long to wait on each Splunk REST call (seconds)
_CONNECT_TIMEOUT = 10.0
_READ_TIMEOUT = 30.0
_POLL_TIMEOUT = 15.0


def _build_client(
    base_url: str,
    *,
    auth_method: str,
    api_token: str | None,
    username: str | None,
    password: str | None,
    verify_tls: bool,
) -> httpx.AsyncClient:
    """Build an authenticated httpx.AsyncClient for Splunk REST API."""
    if not verify_tls:
        logger.warning(
            "Splunk connector: TLS verification is DISABLED for %s — "
            "this is insecure and should only be used in development",
            base_url,
        )

    headers: dict[str, str] = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    auth: tuple[str, str] | None = None

    if auth_method == "token" and api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    elif auth_method == "username_password" and username and password:
        auth = (username, password)

    return httpx.AsyncClient(
        base_url=base_url,
        headers=headers,
        auth=auth,
        verify=verify_tls,
        follow_redirects=True,
        timeout=httpx.Timeout(
            connect=_CONNECT_TIMEOUT,
            read=_READ_TIMEOUT,
            write=_READ_TIMEOUT,
            pool=5.0,
        ),
    )


def _splunk_params(**kwargs: Any) -> str:
    """URL-encode parameters for Splunk form-data posts."""
    return urllib.parse.urlencode({k: v for k, v in kwargs.items() if v is not None})


class SplunkConnector(SIEMConnectorBase):
    """Splunk REST API connector.

    Instantiated with the decrypted connection parameters (never stored).
    """

    kind = "splunk"

    def __init__(
        self,
        *,
        base_url: str,
        auth_method: str = "token",
        api_token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_tls: bool = True,
        default_index: str = "main",
        retrohunt_macro: str = "threathunt_ioc_search",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_method = auth_method
        self._api_token = api_token
        self._username = username
        self._password = password
        self._verify_tls = verify_tls
        self.default_index = default_index
        self.retrohunt_macro = retrohunt_macro

    def _client(self) -> httpx.AsyncClient:
        return _build_client(
            self._base_url,
            auth_method=self._auth_method,
            api_token=self._api_token,
            username=self._username,
            password=self._password,
            verify_tls=self._verify_tls,
        )

    # ── Connection test ───────────────────────────────────────────────────────

    async def test_connection(self) -> ConnectorTestResult:
        """GET /services/server/info — verify credentials and reachability."""
        try:
            async with self._client() as client:
                resp = await client.get(
                    "/services/server/info",
                    params={"output_mode": "json"},
                    timeout=httpx.Timeout(connect=_CONNECT_TIMEOUT, read=_POLL_TIMEOUT),
                )
            if resp.status_code == 401:
                return ConnectorTestResult(ok=False, message="Authentication failed (401)")
            if resp.status_code == 403:
                return ConnectorTestResult(
                    ok=False, message="Access forbidden (403) — check token permissions"
                )
            if not resp.is_success:
                return ConnectorTestResult(
                    ok=False,
                    message=f"Unexpected HTTP {resp.status_code}: {resp.text[:200]}",
                )
            data = resp.json()
            entry = (data.get("entry") or [{}])[0]
            content = entry.get("content", {})
            server_info = {
                "version": content.get("version", "unknown"),
                "build": content.get("build", ""),
                "server_name": content.get("serverName", ""),
                "os_name": content.get("os_name", ""),
            }
            return ConnectorTestResult(
                ok=True,
                message=f"Connected to Splunk {server_info['version']} ({server_info['server_name']})",
                server_info=server_info,
            )
        except httpx.ConnectError as exc:
            return ConnectorTestResult(ok=False, message=f"Connection refused: {exc}")
        except httpx.TimeoutException:
            return ConnectorTestResult(ok=False, message="Connection timed out")
        except Exception as exc:
            logger.exception("Splunk connection test failed: %s", exc)
            return ConnectorTestResult(ok=False, message=f"Error: {exc}")

    # ── Submit search ─────────────────────────────────────────────────────────

    async def submit_search(
        self,
        spl: str,
        *,
        earliest: str = "-24h",
        latest: str = "now",
        hunt_id: str = "",
    ) -> str:
        """POST /services/search/jobs — submit search, return SID."""
        # Ensure the search starts with 'search' keyword if it doesn't
        search_str = spl.strip()
        if not search_str.lower().startswith("search ") and not search_str.startswith("|"):
            search_str = f"search {search_str}"

        payload = _splunk_params(
            search=search_str,
            earliest_time=earliest,
            latest_time=latest,
            output_mode="json",
            exec_mode="normal",
            # Attach hunt_id as a custom field for traceability
            custom_fields=f"hunt_id={hunt_id}" if hunt_id else None,
        )

        async with self._client() as client:
            resp = await client.post(
                "/services/search/jobs",
                content=payload,
            )

        if not resp.is_success:
            raise RuntimeError(
                f"Splunk submit_search failed with HTTP {resp.status_code}: {resp.text[:400]}"
            )

        data = resp.json()
        sid = data.get("sid") or (data.get("entry", [{}])[0].get("content", {}).get("sid", ""))
        if not sid:
            raise RuntimeError(f"Splunk did not return a SID. Response: {resp.text[:400]}")

        logger.info("Splunk search submitted: sid=%s hunt_id=%s", sid, hunt_id)
        return str(sid)

    # ── Poll job status ───────────────────────────────────────────────────────

    async def poll_job(self, sid: str) -> JobStatus:
        """GET /services/search/jobs/{sid} — poll job status."""
        async with self._client() as client:
            resp = await client.get(
                f"/services/search/jobs/{sid}",
                params={"output_mode": "json"},
                timeout=httpx.Timeout(connect=_CONNECT_TIMEOUT, read=_POLL_TIMEOUT),
            )

        if resp.status_code == 404:
            return JobStatus(
                sid=sid,
                done=True,
                failed=True,
                progress=0.0,
                event_count=0,
                message="Job not found",
            )
        if not resp.is_success:
            raise RuntimeError(f"poll_job HTTP {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        entry = (data.get("entry") or [{}])[0]
        content = entry.get("content", {})

        dispatch_state = str(content.get("dispatchState", "")).upper()
        done = dispatch_state in ("DONE", "FAILED", "FINALIZED")
        failed = dispatch_state == "FAILED"
        progress = float(content.get("doneProgress", 0.0))
        event_count = int(content.get("resultCount", 0))
        message = (
            content.get("messages", [{}])[0].get("text", "") if content.get("messages") else ""
        )

        return JobStatus(
            sid=sid,
            done=done,
            failed=failed,
            progress=progress,
            event_count=event_count,
            message=message,
        )

    # ── Fetch results ─────────────────────────────────────────────────────────

    async def fetch_results(
        self, sid: str, *, offset: int = 0, count: int = 100
    ) -> list[dict[str, Any]]:
        """GET /services/search/jobs/{sid}/results — paginated result fetch."""
        async with self._client() as client:
            resp = await client.get(
                f"/services/search/jobs/{sid}/results",
                params={
                    "output_mode": "json",
                    "offset": offset,
                    "count": count,
                },
            )

        if not resp.is_success:
            raise RuntimeError(f"fetch_results HTTP {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        return list(data.get("results", []))
