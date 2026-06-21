"""
Pipeline runner — executes the LangGraph Threat Hunting workflow and
persists the state to ``data/threat_hunting.db`` between steps.

Run model (issue-local-005):
  Each call to ``start_generation`` creates a NEW ``hunting_packages`` row
  with its own UUID (the *run_id*).  State updates during execution always
  UPDATE by ``id = run_id``, never by ``hunt_package_id``.  This means
  re-running the same hunt package produces fully independent records —
  the prior run is never overwritten.

  ``_ACTIVE_JOBS`` is keyed by ``run_id`` so concurrent runs of different
  packages are tracked independently.  A sequential guard prevents starting
  a new run while any run for the same *hunt package* is still active.

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


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
                   current_step=?, completed_steps=?, step_logs=?, research_effort=?
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
                    run_id,
                ),
            )
        else:
            await db.execute(
                """INSERT INTO hunting_packages
                   (id, hunt_package_id, threat_context, hypotheses,
                    hunting_leads, deep_retrohunt, ttp_analysis, query_drafts,
                    llm_provider, llm_model,
                    generation_status, generation_errors, created_at,
                    current_step, completed_steps, step_logs, research_effort)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                ),
            )
        await db.commit()


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


def _is_pkg_active(pkg_id: str) -> bool:
    """Return True when any run for this hunt package is currently executing."""
    # We must look up all active run_ids and check their pkg_id
    # The state dict kept alive in asyncio tasks is not inspectable, so we rely
    # on _ACTIVE_RUN_PKG to map run_id → pkg_id.
    return any(v == pkg_id for v in _ACTIVE_RUN_PKG.values())


# Maps run_id → hunt_package_id for active jobs (mirrors _ACTIVE_JOBS)
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
    from backend.threat_hunting.agents.pipeline import (
        get_compiled_graph,
        get_post_approval_graph,
    )

    try:
        await _save_generation_state(run_id, pkg_id, initial_state, status="running")

        if resume:
            graph = get_post_approval_graph()
        else:
            graph = get_compiled_graph()

        # Stream execution so we can persist after each step
        final_state = dict(initial_state)
        async for chunk in graph.astream(initial_state):
            for node_name, updates in chunk.items():
                if isinstance(updates, dict):
                    final_state.update(updates)
                    status = final_state.get("generation_status", "running")
                    await _save_generation_state(run_id, pkg_id, final_state, status=status)
                    logger.info(
                        "TH pipeline run=%s [%s] node=%s status=%s",
                        run_id[:8],
                        pkg_id[:8],
                        node_name,
                        status,
                    )

        final_status = final_state.get("generation_status", "completed")
        await _save_generation_state(run_id, pkg_id, final_state, status=final_status)

        # Update hunt package status
        from backend.threat_hunting import db as th_db

        if final_status == "completed":
            await th_db.update_hunt_package(pkg_id, status="approved")
        elif final_status == "awaiting_approval":
            await th_db.update_hunt_package(pkg_id, status="planning")

    except Exception as exc:
        logger.exception("TH pipeline error run=%s pkg=%s: %s", run_id[:8], pkg_id[:8], exc)
        await _save_generation_state(
            run_id,
            pkg_id,
            {**initial_state, "errors": [str(exc)]},
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
) -> dict[str, Any]:
    """Start a new generation run for a hunt package.

    Always creates a NEW run (new hunting_packages row).  The prior run —
    if any — is left untouched.  Returns a dict containing the new run_id
    and initial status.  Raises ValueError if another run for this package
    is currently active (sequential guard).
    """
    if _is_pkg_active(pkg_id):
        # Return the active run record so the caller can poll it
        active_run_id = next(k for k, v in _ACTIVE_RUN_PKG.items() if v == pkg_id)
        record = await _get_run_record(active_run_id)
        if record:
            record["is_running"] = True
            return record
        return {"generation_status": "running", "hunt_package_id": pkg_id, "run_id": active_run_id}

    from backend.threat_hunting.agents.pipeline import build_initial_state

    run_id = str(uuid.uuid4())
    initial_state = build_initial_state(
        pkg_id,
        provider_name=provider_name,
        model_name=model_name,
        research_effort=research_effort,
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
