"""
Pipeline runner — executes the LangGraph Threat Hunting workflow and
persists the state to ``data/threat_hunting.db`` between steps.

Lifecycle:
  1. ``start_generation(pkg_id, ...)``
     - Creates a generation record in the DB (status=running)
     - Fires ``asyncio.create_task`` to run the LangGraph pipeline in the background
     - Returns the generation record immediately for API polling

  2. LangGraph pipeline runs node-by-node.
     - After each node the runner's ``_step_callback`` persists the partial state.
     - When the graph reaches ``awaiting_approval``, the pipeline saves state
       and exits.  Status becomes ``awaiting_approval``.

  3. ``approve_generation(pkg_id)`` / ``reject_generation(pkg_id)``
     - Loads persisted state, sets ``approved=True`` (or ``rejected=True``),
       and re-fires the background task to resume.
     - On the resume run, the graph re-enters after the gate (already-completed
       nodes are skipped because their outputs are in the state).

  4. On completion, the final state is written to the ``hunting_packages``
     table and the hunt package status is updated to ``approved``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# In-memory job registry — maps pkg_id → generation task handle
# (not persistent; cleared on process restart; sufficient for Phase 3)
_ACTIVE_JOBS: dict[str, asyncio.Task] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── DB helpers ────────────────────────────────────────────────────────────────


async def _save_generation_state(
    pkg_id: str,
    state: dict[str, Any],
    *,
    status: str,
) -> None:
    """Persist the current pipeline state to hunting_packages table."""
    from backend.threat_hunting import db as th_db

    # Check if a hunting_package row already exists for this pkg_id
    existing = await _get_generation_record(pkg_id)
    now = _utc_now()

    async def _to_json(val: Any) -> str | None:
        if val is None:
            return None
        if isinstance(val, str):
            return val
        return json.dumps(val, ensure_ascii=False, default=str)

    async with __import__("aiosqlite").connect(th_db._TH_DB_PATH) as db:
        if existing:
            await db.execute(
                """UPDATE hunting_packages SET
                   threat_context=?, hypotheses=?, hunting_leads=?,
                   deep_retrohunt=?, ttp_analysis=?, query_drafts=?,
                   llm_provider=?, llm_model=?,
                   generation_status=?, generation_errors=?
                   WHERE hunt_package_id=?""",
                (
                    await _to_json(state.get("threat_context")),
                    await _to_json(state.get("hypotheses")),
                    await _to_json(state.get("hunting_leads")),
                    await _to_json(state.get("deep_retrohunt")),
                    await _to_json(state.get("ttp_analysis")),
                    await _to_json(state.get("query_drafts")),
                    state.get("provider_name"),
                    state.get("model_name"),
                    status,
                    await _to_json(state.get("errors")),
                    pkg_id,
                ),
            )
        else:
            row_id = str(uuid.uuid4())
            await db.execute(
                """INSERT INTO hunting_packages
                   (id, hunt_package_id, threat_context, hypotheses,
                    hunting_leads, deep_retrohunt, ttp_analysis, query_drafts,
                    llm_provider, llm_model,
                    generation_status, generation_errors, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row_id,
                    pkg_id,
                    await _to_json(state.get("threat_context")),
                    await _to_json(state.get("hypotheses")),
                    await _to_json(state.get("hunting_leads")),
                    await _to_json(state.get("deep_retrohunt")),
                    await _to_json(state.get("ttp_analysis")),
                    await _to_json(state.get("query_drafts")),
                    state.get("provider_name"),
                    state.get("model_name"),
                    status,
                    await _to_json(state.get("errors")),
                    now,
                ),
            )
        await db.commit()


async def _get_generation_record(pkg_id: str) -> dict[str, Any] | None:
    """Load the generation record for a hunt package."""
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


async def _load_pipeline_state(pkg_id: str) -> dict[str, Any] | None:
    """Reconstruct a HuntPipelineState from the DB record."""
    record = await _get_generation_record(pkg_id)
    if not record:
        return None
    return {
        "hunt_package_id": pkg_id,
        "provider_name": record.get("llm_provider"),
        "model_name": record.get("llm_model"),
        "threat_context": record.get("threat_context"),
        "hypotheses": record.get("hypotheses") or [],
        "hunting_leads": record.get("hunting_leads") or [],
        "deep_retrohunt": record.get("deep_retrohunt"),
        "ttp_analysis": record.get("ttp_analysis"),
        "query_drafts": record.get("query_drafts") or [],
        "errors": record.get("generation_errors") or [],
        "step_logs": [],
        "completed_steps": [],
        "current_step": "",
        "approved": False,
        "rejected": False,
        "approval_notes": "",
        "generation_status": record.get("generation_status", "running"),
    }


# ── Pipeline execution ────────────────────────────────────────────────────────


async def _run_pipeline(
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
        await _save_generation_state(pkg_id, initial_state, status="running")

        if resume:
            graph = get_post_approval_graph()
        else:
            graph = get_compiled_graph()

        # Stream execution so we can persist after each step
        final_state = dict(initial_state)
        async for chunk in graph.astream(initial_state):
            # chunk is a dict of {node_name: state_updates}
            for node_name, updates in chunk.items():
                if isinstance(updates, dict):
                    final_state.update(updates)
                    status = final_state.get("generation_status", "running")
                    await _save_generation_state(pkg_id, final_state, status=status)
                    logger.info(
                        "TH pipeline [%s] node=%s status=%s",
                        pkg_id[:8],
                        node_name,
                        status,
                    )

        final_status = final_state.get("generation_status", "completed")
        await _save_generation_state(pkg_id, final_state, status=final_status)

        # Update hunt package status
        from backend.threat_hunting import db as th_db

        if final_status == "completed":
            await th_db.update_hunt_package(pkg_id, status="approved")
        elif final_status == "awaiting_approval":
            await th_db.update_hunt_package(pkg_id, status="planning")

    except Exception as exc:
        logger.exception("TH pipeline error for %s: %s", pkg_id, exc)
        await _save_generation_state(
            pkg_id,
            {**initial_state, "errors": [str(exc)]},
            status="error",
        )
    finally:
        _ACTIVE_JOBS.pop(pkg_id, None)


# ── Public API ────────────────────────────────────────────────────────────────


async def start_generation(
    pkg_id: str,
    *,
    provider_name: str | None = None,
    model_name: str | None = None,
) -> dict[str, Any]:
    """Start the generation pipeline for a hunt package.

    Returns the initial generation record immediately.
    The actual pipeline runs in a background task.
    """
    from backend.threat_hunting.agents.pipeline import build_initial_state

    if pkg_id in _ACTIVE_JOBS:
        existing = await _get_generation_record(pkg_id)
        return existing or {"generation_status": "running", "hunt_package_id": pkg_id}

    initial_state = build_initial_state(pkg_id, provider_name=provider_name, model_name=model_name)
    task = asyncio.create_task(_run_pipeline(pkg_id, dict(initial_state)))
    _ACTIVE_JOBS[pkg_id] = task

    return {
        "hunt_package_id": pkg_id,
        "generation_status": "running",
        "provider_name": provider_name,
        "model_name": model_name,
    }


async def get_generation_status(pkg_id: str) -> dict[str, Any] | None:
    """Return the current generation record for a hunt package."""
    record = await _get_generation_record(pkg_id)
    if not record:
        return None
    record["is_running"] = pkg_id in _ACTIVE_JOBS
    return record


async def approve_generation(pkg_id: str, notes: str = "") -> dict[str, Any]:
    """Approve the generated hunting package and resume the pipeline."""
    state = await _load_pipeline_state(pkg_id)
    if not state:
        raise ValueError(f"No generation record found for package {pkg_id!r}")

    current_status = state.get("generation_status")
    if current_status not in ("awaiting_approval", "running", "error"):
        raise ValueError(f"Package {pkg_id!r} is not awaiting approval (status={current_status!r})")

    # Mark approved and resume
    state["approved"] = True
    state["rejected"] = False
    state["approval_notes"] = notes

    if pkg_id in _ACTIVE_JOBS:
        _ACTIVE_JOBS[pkg_id].cancel()

    task = asyncio.create_task(_run_pipeline(pkg_id, state, resume=True))
    _ACTIVE_JOBS[pkg_id] = task

    return {"hunt_package_id": pkg_id, "generation_status": "running", "approved": True}


async def reject_generation(pkg_id: str, notes: str = "") -> dict[str, Any]:
    """Reject the generated hunting package."""
    state = await _load_pipeline_state(pkg_id)
    if not state:
        raise ValueError(f"No generation record found for package {pkg_id!r}")

    state["rejected"] = True
    state["approved"] = False
    state["approval_notes"] = notes

    await _save_generation_state(pkg_id, state, status="rejected")

    from backend.threat_hunting import db as th_db

    await th_db.update_hunt_package(pkg_id, status="draft")

    return {"hunt_package_id": pkg_id, "generation_status": "rejected"}
