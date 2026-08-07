"""
Hunt Playbook orchestrator (issue-local-040).

A playbook is a named automation config (backend/threat_hunting/db.py's
hunt_playbooks table): a list of models to run, and which of the normally-
manual gates proceed automatically. Firing a playbook against a hunt
package:

  1. Starts one generation run per enabled model, CONCURRENTLY (the runner
     already supports N independent concurrent runs of the same package —
     issue-local-014 — so this needs no new execution primitive).
  2. If auto_approve_analysis is off, stops there — the rest of the chain
     below requires every fired run to actually finish analysis, and that
     can't happen without a human approving each one first. The playbook job
     is marked 'completed' at this point; the runs themselves proceed
     normally and can still be approved and compared manually.
  3. If auto_approve_analysis is on, each run auto-resumes past the approval
     gate (see runner._run_pipeline's auto_approve hook) — this step polls
     until every fired run reaches a terminal status, then:
       a. If auto_run_comparison is on, fires the enabled comparison
          phase(s) (auto_compare_preliminary / auto_compare_full) across the
          successfully-completed runs, named "<playbook-name>_<timestamp>".
       b. If auto_create_run_from_recommendations is on (and a preliminary
          comparison was produced), synthesizes a consolidated run from it
          (see recommendation_synthesizer) — this is what backs the
          "Consolidated Runs" sub-tab.
       c. If auto_generate_full_report is on (and a full comparison was
          produced), snapshots it as a consolidated report — the existing
          "Use as Consolidated Report" action (issue-local-035).

Progress is tracked in a playbook_jobs row (mirrors comparison_jobs' "survive
the triggering request" background-task pattern) so the frontend can poll
regardless of whether the triggering tab/dialog stays open.

Explicitly OUT OF SCOPE (per issue-local-040 planning): SIEM execution is
never automatic. A playbook run reaching 'completed' (approved analysis) is
as far as unattended automation goes — a human still picks a connector and
SPL to actually execute against a SIEM, same as any other run.
"""

from __future__ import annotations

import asyncio
from typing import Any

from backend.threat_hunting import db as th_db
from backend.threat_hunting.agents.logging_utils import get_run_logger
from backend.threat_hunting.agents.runner import start_generation

_TERMINAL_RUN_STATUSES = frozenset({"completed", "rejected", "cancelled", "error"})
#: Polling cadence + safety ceiling while waiting for fired runs to finish —
#: there is no push/callback signal across the N independent run tasks, so
#: this is a plain poll loop, same idiom the rest of this codebase uses for
#: job status (comparison_jobs, generation_status) rather than a new one.
_POLL_INTERVAL_SECONDS = 3
_MAX_WAIT_SECONDS = 3600


async def run_playbook(
    hunt_package_id: str,
    playbook_id: str,
    *,
    created_by: str | None = None,
) -> dict[str, Any]:
    """Fire *playbook* against *hunt_package_id* and return the tracking job
    immediately (status='running') — the chain itself runs as a detached
    background task. Raises ValueError if the playbook or package doesn't
    exist."""
    playbook = await th_db.get_playbook(playbook_id)
    if not playbook:
        raise ValueError(f"Playbook {playbook_id!r} not found")
    if not await th_db.get_hunt_package(hunt_package_id):
        raise ValueError(f"Hunt package {hunt_package_id!r} not found")

    job = await th_db.create_playbook_job(
        hunt_package_id,
        playbook_id=playbook_id,
        playbook_name=playbook["name"],
        created_by=created_by,
    )
    asyncio.create_task(
        _run_playbook_job(job["id"], hunt_package_id, playbook, created_by=created_by)
    )
    return job


async def _wait_for_terminal(run_ids: list[str]) -> list[str]:
    """Poll until every run in *run_ids* reaches a terminal generation
    status, then return the ones that reached 'completed' — the only status
    usable as comparison input. rejected/cancelled/error runs are dropped,
    not retried; the chain proceeds with whatever succeeded (if at least 2
    completed — comparison needs multiple runs to be meaningful)."""
    pending = set(run_ids)
    waited = 0
    while pending and waited < _MAX_WAIT_SECONDS:
        for run_id in list(pending):
            record = await th_db.get_generation_run(run_id)
            if (record or {}).get("generation_status") in _TERMINAL_RUN_STATUSES:
                pending.discard(run_id)
        if pending:
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
            waited += _POLL_INTERVAL_SECONDS

    completed: list[str] = []
    for run_id in run_ids:
        record = await th_db.get_generation_run(run_id)
        if (record or {}).get("generation_status") == "completed":
            completed.append(run_id)
    return completed


async def _run_playbook_job(
    job_id: str,
    hunt_package_id: str,
    playbook: dict[str, Any],
    *,
    created_by: str | None,
) -> None:
    from backend.threat_hunting.agents.nodes.comparison_analyst import compare_runs
    from backend.threat_hunting.agents.nodes.recommendation_synthesizer import (
        synthesize_recommendation_run,
    )

    log = get_run_logger(__name__, hunt_package_id, None)
    playbook_id = playbook["id"]
    playbook_name = playbook["name"]

    try:
        run_ids: list[str] = []
        for entry in playbook["models"]:
            record = await start_generation(
                hunt_package_id,
                provider_name=entry.get("provider_name"),
                model_name=entry.get("model_name"),
                run_config={},
                created_by=created_by,
                playbook_id=playbook_id,
                playbook_name=playbook_name,
                run_origin="playbook",
                auto_approve=bool(playbook["auto_approve_analysis"]),
            )
            run_ids.append(record["run_id"])
        await th_db.update_playbook_job(job_id, run_ids=run_ids, current_step="running_analysis")
        log.info("playbook_runner: fired %d run(s) for playbook %r", len(run_ids), playbook_name)

        if not playbook["auto_approve_analysis"]:
            # Nothing further can proceed unattended — each run is parked at
            # awaiting_approval until a human approves it. The playbook's job
            # is done; the runs themselves are not (that's expected).
            await th_db.update_playbook_job(
                job_id, status="completed", current_step="awaiting_manual_approval"
            )
            return

        await th_db.update_playbook_job(job_id, current_step="waiting_for_analysis")
        completed_run_ids = await _wait_for_terminal(run_ids)
        await th_db.update_playbook_job(job_id, current_step="analysis_complete")

        if not playbook["auto_run_comparison"] or len(completed_run_ids) < 2:
            await th_db.update_playbook_job(job_id, status="completed")
            return

        prelim_report_id: str | None = None
        full_report_id: str | None = None

        if playbook["auto_compare_preliminary"]:
            await th_db.update_playbook_job(job_id, current_step="comparing_preliminary")
            try:
                report = await compare_runs(
                    hunt_package_id,
                    run_ids=completed_run_ids,
                    phase="preliminary",
                    created_by=created_by,
                    name_prefix=playbook_name,
                )
                prelim_report_id = report.get("id")
                await th_db.update_playbook_job(
                    job_id, comparison_preliminary_report_id=prelim_report_id
                )
            except Exception as exc:  # noqa: BLE001 — soft-fail, chain continues
                log.warning("playbook_runner: preliminary comparison failed (non-fatal): %s", exc)

        if playbook["auto_compare_full"]:
            await th_db.update_playbook_job(job_id, current_step="comparing_full")
            try:
                report = await compare_runs(
                    hunt_package_id,
                    run_ids=completed_run_ids,
                    phase="full",
                    created_by=created_by,
                    name_prefix=playbook_name,
                )
                full_report_id = report.get("id")
                await th_db.update_playbook_job(job_id, comparison_full_report_id=full_report_id)
            except Exception as exc:  # noqa: BLE001
                log.warning("playbook_runner: full comparison failed (non-fatal): %s", exc)

        if playbook["auto_create_run_from_recommendations"]:
            if prelim_report_id is None:
                log.info(
                    "playbook_runner: auto_create_run_from_recommendations is on but no "
                    "preliminary comparison was produced (auto_compare_preliminary off or it "
                    "failed) — skipping, nothing to synthesize from"
                )
            else:
                await th_db.update_playbook_job(job_id, current_step="synthesizing_recommendation_run")
                try:
                    rec_run = await synthesize_recommendation_run(
                        hunt_package_id,
                        phase="preliminary",
                        run_ids=completed_run_ids,
                        created_by=created_by,
                        playbook_id=playbook_id,
                        playbook_name=playbook_name,
                        auto_approve=bool(playbook["auto_approve_analysis"]),
                    )
                    await th_db.update_playbook_job(
                        job_id, recommendation_run_id=rec_run.get("run_id")
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "playbook_runner: recommendation-run synthesis failed (non-fatal): %s", exc
                    )

        if playbook["auto_generate_full_report"]:
            if full_report_id is None:
                log.info(
                    "playbook_runner: auto_generate_full_report is on but no full comparison "
                    "was produced (auto_compare_full off or it failed) — skipping"
                )
            else:
                await th_db.update_playbook_job(job_id, current_step="consolidating_full_report")
                try:
                    consolidated = await th_db.create_consolidated_report(
                        hunt_package_id, phase="full", created_by=created_by
                    )
                    await th_db.update_playbook_job(
                        job_id, consolidated_report_id=consolidated.get("id")
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "playbook_runner: full-assessment consolidation failed (non-fatal): %s", exc
                    )

        await th_db.update_playbook_job(job_id, status="completed", current_step="finished")
        log.info("playbook_runner: playbook %r finished for %s", playbook_name, hunt_package_id[:8])
    except Exception as exc:  # noqa: BLE001
        log.exception("playbook_runner: job %s failed: %s", job_id[:8], exc)
        await th_db.update_playbook_job(job_id, status="error", error_message=str(exc))
