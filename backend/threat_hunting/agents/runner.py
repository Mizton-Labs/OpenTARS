"""
Pipeline runner — executes the LangGraph Threat Hunting workflow and
persists the state to ``data/threat_hunting.db`` between steps.

Run model (issue-local-005):
  Each call to ``start_generation`` creates a NEW ``hunting_packages`` row
  with its own UUID (the *run_id*).  State updates during execution always
  UPDATE by ``id = run_id``, never by ``hunt_package_id``.  This means
  re-running the same hunt package produces fully independent records —
  the prior run is never overwritten.

  ``_ACTIVE_JOBS`` is keyed by ``run_id`` so concurrent runs are tracked
  independently — including multiple concurrent runs of the *same* hunt
  package (issue-local-014: re-run is available at any time, so a user can
  kick off a second run with a different model/effort while an earlier one
  is still executing). ``_ACTIVE_RUN_PKG`` maps run_id -> pkg_id purely for
  bookkeeping (``is_running`` lookups); it no longer gates whether a new run
  is allowed to start.

Lifecycle:
  1. ``start_generation(pkg_id, ...)``
     - Creates a NEW generation row (run_id = new UUID).
     - Returns the run_id immediately; API polls /runs/{run_id}/status.

  2. LangGraph pipeline runs node-by-node.
     - After each node the runner persists the partial state (UPDATE by run_id).
     - When the graph reaches ``awaiting_approval``, status = awaiting_approval.

  3. ``approve_generation(run_id)`` / ``reject_generation(run_id)``
     - Loads persisted state for that run, sets approved/rejected flag,
       and re-fires the background task to resume.

  4. On completion, the hunt package status is updated to ``approved``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# In-memory job registry — maps run_id → generation task handle
_ACTIVE_JOBS: dict[str, asyncio.Task] = {}

# issue-local-019: run_ids whose active job was cancelled via the explicit
# cancel_generation() API — distinguishes an operator-requested cancel from
# approve_generation()'s internal "supersede the old task to resume" cancel,
# so _run_pipeline's CancelledError handler only persists status='cancelled'
# for the former (the latter is immediately followed by a new task writing
# status='running' for the same run_id, which a naive handler would race).
_CANCEL_REQUESTED: set[str] = set()


# issue-local-019: wall-clock ceiling for a single LangGraph node (covers
# every hang scenario uniformly — an unresponsive LLM backend, a stuck
# Playwright/URL fetch, a hung tool call — rather than threading a timeout
# into each individual call site.
#
# issue-local-034: configurable (default 900s, was a hardcoded 600s) —
# loaded fresh at the point of use rather than cached at import time, same
# convention llm_bridge.py already uses for th_llm_max_retries/
# th_llm_retry_backoff_seconds, so an admin's change takes effect on the
# very next run without a restart.
def _node_timeout_seconds() -> int:
    from backend.config.loader import load_th_node_timeout_seconds

    return load_th_node_timeout_seconds()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# issue-local-033 (follow-up): per-run_id set of step_logs entries (keyed by
# 'step') already audited as "agent" events — see _audit_new_agent_steps.
# Same bookkeeping-dict pattern as _ACTIVE_JOBS/_ACTIVE_RUN_PKG above. Cleared
# on terminal status so it never grows unbounded across the process lifetime.
_AUDITED_AGENT_STEPS: dict[str, set[str]] = {}
_TERMINAL_STATUSES = frozenset({"completed", "cancelled", "error", "rejected"})


async def _audit_new_agent_steps(run_id: str, state: dict[str, Any], status: str) -> None:
    """Record an 'agent' audit event for any step_logs entry not yet seen for
    this run.

    Root cause this fixes: `append_run_step_log` (threat_hunting/db.py) —
    the function originally instrumented for the "agent" audit category —
    is only called from siem/executor.py, report_writer.py, and
    threat_intel_analyst.py, all of which run OUTSIDE the LangGraph graph.
    The actual graph nodes (hypothesis_generator, ttp_analyst, ...) persist
    through THIS function instead, called once per node from
    _run_pipeline's streaming loop with the full accumulated step_logs list
    (state.py::_reduce_step_logs: last entry wins per step, each node writes
    its own step exactly once per run — no interim "running" state here,
    unlike the SIEM steps). Diffing against a per-run tracked set is what
    turns "the whole accumulated list, every call" into "one event per step".
    """
    seen = _AUDITED_AGENT_STEPS.setdefault(run_id, set())
    for entry in state.get("step_logs") or []:
        step_key = entry.get("step")
        if not step_key or step_key in seen:
            continue
        seen.add(step_key)
        try:
            from backend.audit.db import record_event
            from backend.audit.interpret import interpret_agent_step

            entry_status = entry.get("status", "unknown")
            await record_event(
                "agent",
                interpret_agent_step(step_key, entry_status),
                username=state.get("created_by"),
                summary=f"{step_key}: {entry_status}",
                detail={
                    "run_id": run_id,
                    "step": step_key,
                    "status": entry_status,
                    "elapsed_s": entry.get("elapsed_s"),
                    "item_count": entry.get("item_count"),
                },
            )
        except Exception as exc:  # noqa: BLE001 — best-effort, never break the pipeline
            logger.warning(
                "_audit_new_agent_steps: record_event failed for run %s step %s: %s",
                run_id,
                step_key,
                exc,
            )
    if status in _TERMINAL_STATUSES:
        _AUDITED_AGENT_STEPS.pop(run_id, None)


# ── DB helpers ────────────────────────────────────────────────────────────────


async def _save_generation_state(
    run_id: str,
    pkg_id: str,
    state: dict[str, Any],
    *,
    status: str,
) -> None:
    """Persist the current pipeline state to hunting_packages table.

    Always operates on the specific run row identified by *run_id* (the row's
    primary key).  NEVER updates by hunt_package_id — each run is independent.
    """
    from backend.threat_hunting import db as th_db

    now = _utc_now()

    def _to_json(val: Any) -> str | None:
        if val is None:
            return None
        if isinstance(val, str):
            return val
        return json.dumps(val, ensure_ascii=False, default=str)

    async with __import__("aiosqlite").connect(th_db._TH_DB_PATH) as db:
        # Check if this specific run row already exists
        cur = await db.execute("SELECT id FROM hunting_packages WHERE id = ?", (run_id,))
        row = await cur.fetchone()
        await cur.close()

        if row:
            await db.execute(
                """UPDATE hunting_packages SET
                   threat_context=?, hypotheses=?, hunting_leads=?,
                   deep_retrohunt=?, ttp_analysis=?, query_drafts=?,
                   llm_provider=?, llm_model=?,
                   generation_status=?, generation_errors=?,
                   current_step=?, completed_steps=?, step_logs=?, research_effort=?,
                   run_config=?
                   WHERE id=?""",
                (
                    _to_json(state.get("threat_context")),
                    _to_json(state.get("hypotheses")),
                    _to_json(state.get("hunting_leads")),
                    _to_json(state.get("deep_retrohunt")),
                    _to_json(state.get("ttp_analysis")),
                    _to_json(state.get("query_drafts")),
                    state.get("provider_name"),
                    state.get("model_name"),
                    status,
                    _to_json(state.get("errors")),
                    state.get("current_step", ""),
                    _to_json(state.get("completed_steps") or []),
                    _to_json(state.get("step_logs") or []),
                    state.get("research_effort", "medium"),
                    _to_json(state.get("run_config") or {}),
                    run_id,
                ),
            )
        else:
            # issue-local-018: run_seq (the Run ID's numeric part, scoped to
            # this package) must be assigned atomically — BEGIN IMMEDIATE
            # serializes the read-then-write against other concurrent runs
            # of the same package (issue-local-014 explicitly allows
            # multiple concurrent runs per package), same idiom used by
            # backend/threat_hunting/db.py's create_hunt_package.
            await db.execute("BEGIN IMMEDIATE")
            cur = await db.execute(
                "SELECT COALESCE(MAX(run_seq), 0) FROM hunting_packages WHERE hunt_package_id = ?",
                (pkg_id,),
            )
            next_run_seq = (await cur.fetchone())[0] + 1
            await cur.close()
            await db.execute(
                """INSERT INTO hunting_packages
                   (id, hunt_package_id, threat_context, hypotheses,
                    hunting_leads, deep_retrohunt, ttp_analysis, query_drafts,
                    llm_provider, llm_model,
                    generation_status, generation_errors, created_at,
                    current_step, completed_steps, step_logs, research_effort,
                    run_config, run_seq, created_by)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    pkg_id,
                    _to_json(state.get("threat_context")),
                    _to_json(state.get("hypotheses")),
                    _to_json(state.get("hunting_leads")),
                    _to_json(state.get("deep_retrohunt")),
                    _to_json(state.get("ttp_analysis")),
                    _to_json(state.get("query_drafts")),
                    state.get("provider_name"),
                    state.get("model_name"),
                    status,
                    _to_json(state.get("errors")),
                    now,
                    state.get("current_step", ""),
                    _to_json(state.get("completed_steps") or []),
                    _to_json(state.get("step_logs") or []),
                    state.get("research_effort", "medium"),
                    _to_json(state.get("run_config") or {}),
                    next_run_seq,
                    state.get("created_by"),
                ),
            )
        await db.commit()

    await _audit_new_agent_steps(run_id, state, status)


async def _get_run_record(run_id: str) -> dict[str, Any] | None:
    """Load a specific generation run by run_id."""
    import aiosqlite

    from backend.threat_hunting import db as th_db

    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM hunting_packages WHERE id = ?",
            (run_id,),
        )
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    d = dict(row)
    for field in (
        "hypotheses",
        "hunting_leads",
        "deep_retrohunt",
        "ttp_analysis",
        "query_drafts",
        "generation_errors",
        "completed_steps",
        "step_logs",
        "run_config",
    ):
        raw = d.get(field)
        if raw and isinstance(raw, str):
            try:
                d[field] = json.loads(raw)
            except Exception:
                pass
    if d.get("threat_context") and isinstance(d["threat_context"], str):
        try:
            d["threat_context"] = json.loads(d["threat_context"])
        except Exception:
            pass
    return d


async def _get_latest_run_record(pkg_id: str) -> dict[str, Any] | None:
    """Load the most recent generation run for a hunt package (back-compat)."""
    import aiosqlite

    from backend.threat_hunting import db as th_db

    async with aiosqlite.connect(th_db._TH_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM hunting_packages WHERE hunt_package_id = ? ORDER BY created_at DESC LIMIT 1",
            (pkg_id,),
        )
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    d = dict(row)
    for field in (
        "hypotheses",
        "hunting_leads",
        "deep_retrohunt",
        "ttp_analysis",
        "query_drafts",
        "generation_errors",
        "completed_steps",
        "step_logs",
        "run_config",
    ):
        raw = d.get(field)
        if raw and isinstance(raw, str):
            try:
                d[field] = json.loads(raw)
            except Exception:
                pass
    if d.get("threat_context") and isinstance(d["threat_context"], str):
        try:
            d["threat_context"] = json.loads(d["threat_context"])
        except Exception:
            pass
    return d


async def _load_pipeline_state(run_id: str) -> dict[str, Any] | None:
    """Reconstruct a HuntPipelineState from the DB record for a given run."""
    record = await _get_run_record(run_id)
    if not record:
        return None
    pkg_id = record.get("hunt_package_id", "")
    return {
        "hunt_package_id": pkg_id,
        "provider_name": record.get("llm_provider"),
        "model_name": record.get("llm_model"),
        "research_effort": record.get("research_effort") or "medium",
        "threat_context": record.get("threat_context"),
        "hypotheses": record.get("hypotheses") or [],
        "hunting_leads": record.get("hunting_leads") or [],
        "deep_retrohunt": record.get("deep_retrohunt"),
        "ttp_analysis": record.get("ttp_analysis"),
        "query_drafts": record.get("query_drafts") or [],
        "errors": record.get("generation_errors") or [],
        "step_logs": record.get("step_logs") or [],
        "completed_steps": record.get("completed_steps") or [],
        "current_step": record.get("current_step") or "",
        "approved": False,
        "rejected": False,
        "approval_notes": "",
        "generation_status": record.get("generation_status", "running"),
    }


# Maps run_id → hunt_package_id for active jobs (mirrors _ACTIVE_JOBS).
# Bookkeeping only — issue-local-014 removed the "one active run per
# package" gate that used to be built on top of this map.
_ACTIVE_RUN_PKG: dict[str, str] = {}


# ── Pipeline execution ────────────────────────────────────────────────────────


async def _run_pipeline(
    run_id: str,
    pkg_id: str,
    initial_state: dict[str, Any],
    *,
    resume: bool = False,
) -> None:
    """Background task: run the LangGraph pipeline and persist results."""
    from backend.threat_hunting.agents.logging_utils import get_run_logger
    from backend.threat_hunting.agents.pipeline import (
        get_compiled_graph,
        get_post_approval_graph,
    )

    log = get_run_logger(__name__, pkg_id, run_id)

    # issue-local-015: nodes (e.g. intake_classifier) need run_id to scope
    # extracted_iocs rows per-run — inject it into the graph state itself,
    # since node functions only ever see HuntPipelineState, not this
    # function's own run_id parameter.
    initial_state = {**initial_state, "run_id": run_id}
    final_state = dict(initial_state)

    try:
        await _save_generation_state(run_id, pkg_id, initial_state, status="running")

        if resume:
            graph = get_post_approval_graph()
        else:
            graph = get_compiled_graph()

        # Stream execution so we can persist after each step. Each iteration
        # is bounded by the configured per-node timeout (issue-local-019,
        # made configurable in issue-local-034) — without this, a single
        # hung node (unresponsive LLM backend, a stuck Playwright/URL fetch,
        # ...) leaves the run at 'running' forever, with no error ever
        # recorded (nothing raises, it just never returns). Resolved once at
        # the start of this run, not re-read per node — a config change
        # takes effect on the next run, not retroactively mid-run.
        node_timeout = _node_timeout_seconds()
        graph_iter = graph.astream(initial_state).__aiter__()
        while True:
            try:
                chunk = await asyncio.wait_for(graph_iter.__anext__(), timeout=node_timeout)
            except StopAsyncIteration:
                break
            for node_name, updates in chunk.items():
                if isinstance(updates, dict):
                    final_state.update(updates)
                    status = final_state.get("generation_status", "running")
                    await _save_generation_state(run_id, pkg_id, final_state, status=status)
                    log.info("TH pipeline node=%s status=%s", node_name, status)

        final_status = final_state.get("generation_status", "completed")
        await _save_generation_state(run_id, pkg_id, final_state, status=final_status)

        # Update hunt package status
        from backend.threat_hunting import db as th_db

        if final_status == "completed":
            await th_db.update_hunt_package(pkg_id, status="approved")
        elif final_status == "awaiting_approval":
            await th_db.update_hunt_package(pkg_id, status="planning")

        # issue-local-021/023: preliminary-phase Threat Intel analysis — runs
        # here, at the point the pipeline first reaches the approval gate
        # (status='awaiting_approval'), BEFORE a human approves it — not
        # after approval. issue-local-023 fix: this used to gate on
        # final_status == "completed", but that status only occurs on the
        # RESUMED run once approve_generation() re-fires the pipeline past
        # the gate — i.e. it was firing after approval, not before it,
        # contradicting both this analyst's "preliminary" naming and the
        # pipeline diagrams (WorkflowVisualizer.tsx etc.), which already
        # depict threat_intel_preliminary positioned before approval_gate.
        # Gated on the run's include_threat_intel config flag (default on).
        # Soft-fail, same convention as the auto-report block below.
        if final_status == "awaiting_approval" and (final_state.get("run_config") or {}).get(
            "include_threat_intel", True
        ):
            try:
                from backend.threat_hunting.agents.nodes.threat_intel_analyst import (
                    analyze_threat_intel,
                )

                # issue-local-022 (item 3): mark this run's Threat Intel
                # analysis as in-flight so the frontend can gate Re-run/report
                # generation for it — always cleared in `finally`, even on
                # failure.
                await th_db.set_run_threat_intel_status(run_id, "running")
                try:
                    await analyze_threat_intel(
                        pkg_id,
                        run_id=run_id,
                        phase="preliminary",
                        provider_name=final_state.get("provider_name"),
                        model_name=final_state.get("model_name"),
                    )
                finally:
                    await th_db.set_run_threat_intel_status(run_id, None)
                log.info("TH pipeline: preliminary threat intel analysis complete")
            except Exception as intel_exc:  # noqa: BLE001
                log.warning(
                    "TH pipeline: preliminary threat intel analysis failed (non-fatal): %s",
                    intel_exc,
                )

        # issue-008-2C-A: auto-generate a run-scoped report when the pipeline
        # completes (status 'completed' = approved, awaiting SIEM execution).
        # Soft-fail — report failure never blocks the hunt workflow.
        if final_status == "completed":
            try:
                from backend.threat_hunting.agents.nodes.report_writer import write_report

                provider = final_state.get("provider_name")
                model = final_state.get("model_name")
                await write_report(
                    pkg_id,
                    run_id=run_id,
                    provider_name=provider,
                    model_name=model,
                )
                log.info("TH pipeline: auto-report generated (run-scoped)")
            except Exception as report_exc:  # noqa: BLE001
                log.warning(
                    "TH pipeline: auto-report generation failed (non-fatal): %s", report_exc
                )

    except asyncio.CancelledError:
        # issue-local-019: only persist status='cancelled' for an operator-
        # requested cancel (see _CANCEL_REQUESTED's docstring above) — a
        # supersede-cancel from approve_generation() is immediately followed
        # by a new task writing status='running' for the same run_id, and
        # writing 'cancelled' here would race it.
        if run_id in _CANCEL_REQUESTED:
            _CANCEL_REQUESTED.discard(run_id)
            log.warning("TH pipeline cancelled by operator")
            await _save_generation_state(
                run_id,
                pkg_id,
                {
                    **final_state,
                    "errors": [*(final_state.get("errors") or []), "Cancelled by operator"],
                },
                status="cancelled",
            )
        else:
            log.info("TH pipeline task cancelled (superseded by resume)")
        raise
    except TimeoutError:
        msg = (
            f"Pipeline step timed out after {node_timeout}s — the LLM backend or a "
            "fetch may be unresponsive"
        )
        log.error("TH pipeline: %s", msg)
        await _save_generation_state(
            run_id,
            pkg_id,
            {**final_state, "errors": [*(final_state.get("errors") or []), msg]},
            status="error",
        )
    except Exception as exc:
        log.exception("TH pipeline error: %s", exc)
        await _save_generation_state(
            run_id,
            pkg_id,
            {**final_state, "errors": [*(final_state.get("errors") or []), str(exc)]},
            status="error",
        )
    finally:
        _ACTIVE_JOBS.pop(run_id, None)
        _ACTIVE_RUN_PKG.pop(run_id, None)


# ── Public API ────────────────────────────────────────────────────────────────


async def start_generation(
    pkg_id: str,
    *,
    provider_name: str | None = None,
    model_name: str | None = None,
    research_effort: str = "medium",
    run_config: dict[str, Any] | None = None,
    created_by: str | None = None,
) -> dict[str, Any]:
    """Start a new generation run for a hunt package.

    Always creates a NEW run (new hunting_packages row), even if another run
    for the same package is still active — issue-local-014: re-run is
    available at any time, so multiple runs (e.g. different models/effort)
    can execute concurrently. The prior run(s) are left untouched. Returns a
    dict containing the new run_id and initial status.

    *run_config* (issue-local-015) carries this run's IOC-handling settings
    (ioc_mode + cleaning toggles) — see HuntPipelineState.run_config.

    *created_by* (issue-local-026) is the username that triggered this run
    (None when auth is disabled), persisted to hunting_packages.created_by.
    """
    from backend.threat_hunting.agents.pipeline import build_initial_state

    # issue-local-026 follow-up: when the analyst picks "Configured default"
    # (provider_name/model_name both None), resolve the ACTUAL provider and
    # model that will be used right now, once, and persist those resolved
    # values on this run's row instead of leaving them NULL. Previously a
    # "Default" run's llm_provider/llm_model columns stayed NULL forever, so
    # the Runs table had nothing to show — and the only workaround (re-derive
    # "whatever the current default is" at display time) would silently
    # drift out of sync with what a given historical run actually used if an
    # admin changed the default afterward. Soft-fail: if resolution fails
    # here (e.g. LLM disabled, no default configured), fall through with
    # provider_name/model_name still None — the pipeline's own LLM calls
    # will raise the real, actionable error at the point they need a client.
    if provider_name is None:
        try:
            from backend.llm.registry import get_client

            default_client = get_client(None)
            provider_name = default_client.name
            model_name = model_name or default_client.model
        except Exception:  # noqa: BLE001
            pass

    run_id = str(uuid.uuid4())
    initial_state = build_initial_state(
        pkg_id,
        provider_name=provider_name,
        model_name=model_name,
        research_effort=research_effort,
        run_config=run_config,
        created_by=created_by,
    )
    # Pre-register so sequential guard works before the task begins
    _ACTIVE_RUN_PKG[run_id] = pkg_id

    task = asyncio.create_task(_run_pipeline(run_id, pkg_id, dict(initial_state)))
    _ACTIVE_JOBS[run_id] = task

    return {
        "id": run_id,
        "run_id": run_id,
        "hunt_package_id": pkg_id,
        "generation_status": "running",
        "provider_name": provider_name,
        "model_name": model_name,
        "research_effort": research_effort,
        "run_config": run_config or {},
        "created_by": created_by,
    }


async def get_generation_status(
    pkg_id: str,
    run_id: str | None = None,
) -> dict[str, Any] | None:
    """Return the generation record for a run.

    When *run_id* is supplied, returns that specific run.
    Otherwise returns the latest run for the package (back-compat).
    """
    if run_id:
        record = await _get_run_record(run_id)
    else:
        record = await _get_latest_run_record(pkg_id)
    if not record:
        return None
    effective_run_id = record.get("id", run_id or "")
    record["is_running"] = effective_run_id in _ACTIVE_JOBS
    record["run_id"] = effective_run_id
    return record


async def cancel_generation(run_id: str) -> dict[str, Any]:
    """Cancel a currently-running generation run (issue-local-019).

    If the run's LangGraph pipeline task is still alive in this process,
    requests cooperative cancellation — since every await point (an LLM
    call, a tool call, a URL/Playwright fetch) is inside that one task,
    `.cancel()` interrupts whatever subtask is currently in flight too, no
    separate subtask bookkeeping needed. `_run_pipeline`'s own
    CancelledError handler then persists status='cancelled' once the task
    actually unwinds.

    If no in-process task is tracked for this run_id (`_ACTIVE_JOBS` is an
    in-memory registry — it doesn't survive an app restart, so a run left at
    'running' from before the last restart has no live task to stop), there
    is nothing left to actually cancel; the stale DB status is corrected
    directly instead.
    """
    state = await _load_pipeline_state(run_id)
    if not state:
        raise ValueError(f"No generation run found for run_id {run_id!r}")

    status = state.get("generation_status")
    if status != "running":
        raise ValueError(f"Run {run_id!r} is not currently running (status={status!r})")

    pkg_id = state.get("hunt_package_id", "")

    task = _ACTIVE_JOBS.get(run_id)
    if task is not None and not task.done():
        _CANCEL_REQUESTED.add(run_id)
        task.cancel()
        return {"run_id": run_id, "hunt_package_id": pkg_id, "generation_status": "cancelling"}

    state["errors"] = [
        *(state.get("errors") or []),
        "Cancelled by operator (no active worker found — likely orphaned by a server restart)",
    ]
    await _save_generation_state(run_id, pkg_id, state, status="cancelled")
    return {"run_id": run_id, "hunt_package_id": pkg_id, "generation_status": "cancelled"}


async def approve_generation(run_id: str, notes: str = "") -> dict[str, Any]:
    """Approve the generated hunting package and resume the pipeline."""
    state = await _load_pipeline_state(run_id)
    if not state:
        raise ValueError(f"No generation run found for run_id {run_id!r}")

    current_status = state.get("generation_status")
    if current_status not in ("awaiting_approval", "running", "error"):
        raise ValueError(f"Run {run_id!r} is not awaiting approval (status={current_status!r})")

    pkg_id = state.get("hunt_package_id", "")

    # Mark approved and resume
    state["approved"] = True
    state["rejected"] = False
    state["approval_notes"] = notes

    if run_id in _ACTIVE_JOBS:
        _ACTIVE_JOBS[run_id].cancel()
        _ACTIVE_RUN_PKG.pop(run_id, None)

    _ACTIVE_RUN_PKG[run_id] = pkg_id
    task = asyncio.create_task(_run_pipeline(run_id, pkg_id, state, resume=True))
    _ACTIVE_JOBS[run_id] = task

    return {
        "run_id": run_id,
        "hunt_package_id": pkg_id,
        "generation_status": "running",
        "approved": True,
    }


async def reject_generation(run_id: str, notes: str = "") -> dict[str, Any]:
    """Reject the generated hunting package."""
    state = await _load_pipeline_state(run_id)
    if not state:
        raise ValueError(f"No generation run found for run_id {run_id!r}")

    pkg_id = state.get("hunt_package_id", "")
    state["rejected"] = True
    state["approved"] = False
    state["approval_notes"] = notes

    await _save_generation_state(run_id, pkg_id, state, status="rejected")

    from backend.threat_hunting import db as th_db

    await th_db.update_hunt_package(pkg_id, status="draft")

    return {"run_id": run_id, "hunt_package_id": pkg_id, "generation_status": "rejected"}
