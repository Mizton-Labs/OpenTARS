"""LangGraph node: intake_classifier

Loads all evidence items and extracted IOCs for the hunt package from the DB,
builds the evidence text corpus, IOC summary, and raw IOC list that downstream
nodes consume.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from backend.threat_hunting.agents.state import HuntPipelineState

logger = logging.getLogger(__name__)


async def intake_classifier(state: HuntPipelineState) -> dict:
    start = time.monotonic()
    step = "intake_classifier"
    logs = list(state.get("step_logs") or [])
    errors = list(state.get("errors") or [])
    completed = list(state.get("completed_steps") or [])
    try:
        from backend.threat_hunting import db as th_db

        pkg_id = state["hunt_package_id"]

        # Load evidence items
        evidence_items = await th_db.list_evidence_items(pkg_id)

        # Build text corpus
        texts: list[str] = []
        for item in evidence_items:
            label = item.get("label") or item.get("source_ref") or item.get("item_type", "")
            text = item.get("extracted_text") or ""
            if text.strip():
                texts.append(f"=== {label} ===\n{text.strip()}")
        evidence_text_corpus = "\n\n".join(texts) if texts else ""

        # Load IOCs
        all_iocs: list[dict[str, Any]] = await th_db.list_extracted_iocs(pkg_id)

        # Summarize by type
        by_type: dict[str, int] = {}
        for ioc in all_iocs:
            t = ioc.get("ioc_type", "other")
            by_type[t] = by_type.get(t, 0) + 1
        noisy = sum(1 for i in all_iocs if i.get("flagged_noisy"))

        ioc_summary: dict[str, Any] = {
            "total": len(all_iocs),
            "by_type": by_type,
            "noisy_count": noisy,
            "sample": [
                {
                    "ioc": i.get("ioc"),
                    "ioc_type": i.get("ioc_type"),
                    "description": i.get("ioc_description"),
                }
                for i in all_iocs[:50]  # first 50 for prompt context
            ],
        }

        logger.info(
            "intake_classifier: pkg=%s evidence=%d iocs=%d",
            pkg_id,
            len(evidence_items),
            len(all_iocs),
        )

        elapsed = time.monotonic() - start
        logs.append({"step": step, "status": "ok", "elapsed_s": round(elapsed, 2)})
        completed.append(step)
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
            "evidence_text_corpus": evidence_text_corpus,
            "ioc_summary": ioc_summary,
            "raw_ioc_list": all_iocs,
        }
    except Exception as exc:
        logger.exception("Node %s failed: %s", step, exc)
        errors.append(f"{step}: {exc}")
        elapsed = time.monotonic() - start
        logs.append(
            {"step": step, "status": "error", "elapsed_s": round(elapsed, 2), "error": str(exc)}
        )
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
        }
