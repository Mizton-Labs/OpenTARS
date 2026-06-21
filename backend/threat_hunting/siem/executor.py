"""Execution runner for approved hunt packages (Phase 5).

Orchestrates:
  1. Load the approved hunt package's deep_retrohunt SPL draft (or a custom
     SPL query) and the selected SIEM connector profile.
  2. Instantiate the appropriate connector (Splunk only in Phase 5).
  3. Submit the search and track the job SID in a TaskResult DB record.
  4. Poll the job until done (max _MAX_POLL_ROUNDS × _POLL_INTERVAL_S seconds).
  5. Fetch the results (up to _MAX_RESULTS rows).
  6. Call the LLM results_interpreter to produce a plain-text findings summary.
  7. Update the TaskResult with all findings and mark it complete.
  8. Update the hunt package status to 'completed'.

Security:
  - Plain connector credentials are loaded immediately before use and never
    stored in memory beyond the scope of execute_hunt().
  - Raw SIEM results are stored as JSON but never executed as code.
  - LLM interpretation is soft-fail — results are still stored if LLM fails.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from backend.threat_hunting import db as th_db
from backend.threat_hunting.siem.splunk import SplunkConnector

logger = logging.getLogger(__name__)

_MAX_POLL_ROUNDS = 120  # 120 × 3 s = 6 minutes max
_POLL_INTERVAL_S = 3.0
_MAX_RESULTS = 500

# In-memory registry of running execution tasks {task_result_id: asyncio.Task}
_ACTIVE_EXECUTIONS: dict[str, asyncio.Task] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Connector factory ─────────────────────────────────────────────────────────


def _build_connector(conn_raw: dict[str, Any]):
    """Instantiate a SIEM connector from a raw DB record (with _cfg populated)."""
    cfg = conn_raw.get("_cfg", {})
    kind = conn_raw.get("kind", "splunk")
    if kind == "splunk":
        return SplunkConnector(
            base_url=conn_raw["base_url"],
            auth_method=conn_raw.get("auth_method", "token"),
            api_token=cfg.get("api_token"),
            username=cfg.get("username"),
            password=cfg.get("password"),
            verify_tls=bool(cfg.get("verify_tls", True)),
            default_index=cfg.get("default_index", "main"),
            retrohunt_macro=cfg.get("retrohunt_macro", "threathunt_ioc_search"),
        )
    raise ValueError(f"Unsupported SIEM connector kind: {kind!r}")


# ── LLM interpretation ────────────────────────────────────────────────────────


async def _interpret_results(
    results: list[dict[str, Any]],
    hunt_package_id: str,
    spl: str,
    *,
    provider_name: str | None = None,
    model_name: str | None = None,
) -> str:
    """Ask the LLM to interpret SIEM search results. Soft-fail."""
    try:
        from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm

        sample = results[:20]  # cap prompt size
        import json as _json

        sample_text = _json.dumps(sample, indent=2, ensure_ascii=False)[:4000]

        system, user = build_prompt(
            task_description=(
                "You are a Threat Hunter interpreting SIEM search results. "
                "Summarize the findings from a retrohunt search in plain language. "
                "Identify whether any results indicate malicious activity, "
                "and explain the significance of the top matches."
            ),
            context_sections=[
                ("Hunt Package ID", hunt_package_id),
                ("SPL Query Used", spl[:500]),
                (f"Result Sample (first {len(sample)} of {len(results)})", sample_text),
            ],
            output_format="Plain text — 2-5 sentences maximum.",
            additional_instructions=(
                "If the results appear to be benign or the result set is empty, "
                "say so clearly. Do not invent details not present in the data."
            ),
        )
        return await call_llm(
            user,
            system=system,
            provider_name=provider_name,
            model=model_name,
            max_tokens=512,
        )
    except Exception as exc:
        logger.warning("results_interpreter failed (non-fatal): %s", exc)
        return f"(LLM interpretation unavailable: {exc})"


# ── Core execution ────────────────────────────────────────────────────────────


async def _run_execution(
    task_result_id: str,
    hunt_package_id: str,
    connector_raw: dict[str, Any],
    spl: str,
    earliest: str,
    latest: str,
    *,
    provider_name: str | None = None,
    model_name: str | None = None,
) -> None:
    """Background task: run the SIEM search and record results."""
    try:
        connector = _build_connector(connector_raw)

        # 1. Submit search
        sid = await connector.submit_search(
            spl, earliest=earliest, latest=latest, hunt_id=hunt_package_id[:8]
        )
        logger.info("Execution [%s]: sid=%s submitted", task_result_id[:8], sid)
        await th_db.update_task_result(task_result_id, status="running")

        # 2. Poll until done
        for _ in range(_MAX_POLL_ROUNDS):
            await asyncio.sleep(_POLL_INTERVAL_S)
            job = await connector.poll_job(sid)
            logger.debug(
                "Execution [%s]: sid=%s done=%s progress=%.0f%% events=%d",
                task_result_id[:8],
                sid,
                job.done,
                job.progress * 100,
                job.event_count,
            )
            if job.done:
                if job.failed:
                    await th_db.update_task_result(
                        task_result_id,
                        status="failed",
                        interpreted_findings=f"Search job failed: {job.message}",
                        completed_at=_utc_now(),
                    )
                    return
                break
        else:
            await th_db.update_task_result(
                task_result_id,
                status="failed",
                interpreted_findings="Search timed out after 6 minutes",
                completed_at=_utc_now(),
            )
            return

        # 3. Fetch results
        raw_results = await connector.fetch_results(sid, offset=0, count=_MAX_RESULTS)
        logger.info(
            "Execution [%s]: %d results fetched for sid=%s",
            task_result_id[:8],
            len(raw_results),
            sid,
        )

        # 4. Interpret with LLM
        findings = await _interpret_results(
            raw_results,
            hunt_package_id,
            spl,
            provider_name=provider_name,
            model_name=model_name,
        )

        # 5. Persist results
        await th_db.update_task_result(
            task_result_id,
            status="completed",
            raw_result=raw_results,
            interpreted_findings=findings,
            confidence=min(1.0, len(raw_results) / max(1, _MAX_RESULTS)),
            completed_at=_utc_now(),
        )

        # 6. Update hunt package status
        await th_db.update_hunt_package(hunt_package_id, status="completed")
        logger.info("Execution [%s]: completed", task_result_id[:8])

    except Exception as exc:
        logger.exception("Execution [%s] error: %s", task_result_id[:8], exc)
        await th_db.update_task_result(
            task_result_id,
            status="failed",
            interpreted_findings=f"Execution error: {exc}",
            completed_at=_utc_now(),
        )
    finally:
        _ACTIVE_EXECUTIONS.pop(task_result_id, None)


# ── Public API ────────────────────────────────────────────────────────────────


async def start_execution(
    hunt_package_id: str,
    connector_id: str,
    *,
    spl: str,
    earliest: str = "-24h",
    latest: str = "now",
    provider_name: str | None = None,
    model_name: str | None = None,
) -> dict[str, Any]:
    """Start a background SIEM execution for an approved hunt package.

    Returns the TaskResult record immediately; execution runs in the background.

    Raises ValueError if the connector is not found or package already has a
    running execution.
    """
    # Check no execution is already running for this package
    existing_results = await th_db.list_task_results(hunt_package_id)
    for r in existing_results:
        if r.get("status") == "running" and r["id"] in _ACTIVE_EXECUTIONS:
            return r  # idempotent

    # Load connector with plain credentials
    connector_raw = await th_db.get_connector_for_use(connector_id)
    if not connector_raw:
        raise ValueError(f"SIEM connector {connector_id!r} not found")

    # Create task result record
    task_result = await th_db.create_task_result(
        hunt_package_id,
        task_type="retrohunt",
        siem_connector=connector_id,
        query_text=spl,
        earliest=earliest,
        latest=latest,
        hunt_id=hunt_package_id[:8],
        status="pending",
    )
    result_id = task_result["id"]

    task = asyncio.create_task(
        _run_execution(
            result_id,
            hunt_package_id,
            connector_raw,
            spl,
            earliest,
            latest,
            provider_name=provider_name,
            model_name=model_name,
        )
    )
    _ACTIVE_EXECUTIONS[result_id] = task

    task_result["is_running"] = True
    return task_result


async def get_execution_status(task_result_id: str) -> dict[str, Any] | None:
    """Return the current state of a task result."""
    record = await th_db.get_task_result(task_result_id)
    if record:
        record["is_running"] = task_result_id in _ACTIVE_EXECUTIONS
    return record
