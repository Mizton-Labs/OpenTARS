"""
Research effort profiles for the Threat Hunting agent pipeline.

Each profile maps a research effort level (high / medium / low) to a set of
LLM call and prompt knobs. Nodes import ``get_effort_profile`` and read the
knobs they need via ``state.get("research_effort", "medium")``.

Knob reference
--------------
hypotheses_range    (min, max)  — range passed to the LLM prompt
leads_range         (min, max)  — range passed to the LLM prompt
hypothesis_tokens   int         — max_tokens for hypothesis_generator
leads_tokens        int         — max_tokens for hunting_lead_planner
ttp_tokens          int         — max_tokens for ttp_analyst
query_tokens        int         — max_tokens for query_drafting_agent
retrohunt_tokens    int         — max_tokens for deep_retrohunt_planner LLM call
ioc_sample_limit    int         — cap on IOC count sent in query_drafting prompt
retrohunt_ioc_cap   int         — cap on IOCs passed to retrohunt LLM ([:N])
retrohunt_csv_cap   int         — cap on IOC CSV chars sent to retrohunt LLM ([:N])
"""

from __future__ import annotations

from typing import Any

_PROFILES: dict[str, dict[str, Any]] = {
    "high": {
        # More hypotheses, larger budgets, wider IOC context
        "hypotheses_range": (5, 8),
        "leads_range": (4, 6),
        "hypothesis_tokens": 3000,
        "leads_tokens": 3500,
        "ttp_tokens": 2500,
        "query_tokens": 4000,
        "retrohunt_tokens": 4000,
        "ioc_sample_limit": 40,
        "retrohunt_ioc_cap": 100,
        "retrohunt_csv_cap": 6000,
    },
    "medium": {
        # Current defaults — balanced
        "hypotheses_range": (3, 6),
        "leads_range": (2, 4),
        "hypothesis_tokens": 2000,
        "leads_tokens": 2500,
        "ttp_tokens": 2000,
        "query_tokens": 3000,
        "retrohunt_tokens": 3000,
        "ioc_sample_limit": 20,
        "retrohunt_ioc_cap": 50,
        "retrohunt_csv_cap": 3000,
    },
    "low": {
        # Minimal output: basic IOC extraction + deep retrohunt always run;
        # hypothesis/lead/query generation produces only the bare minimum.
        "hypotheses_range": (1, 3),
        "leads_range": (1, 2),
        "hypothesis_tokens": 1200,
        "leads_tokens": 1500,
        "ttp_tokens": 1200,
        "query_tokens": 1500,
        "retrohunt_tokens": 2000,
        "ioc_sample_limit": 10,
        "retrohunt_ioc_cap": 25,
        "retrohunt_csv_cap": 1500,
    },
}

_DEFAULT_EFFORT = "medium"


def get_effort_profile(effort: str | None) -> dict[str, Any]:
    """Return the knob dict for *effort*, falling back to 'medium' for unknown values."""
    key = effort if effort in _PROFILES else _DEFAULT_EFFORT
    return _PROFILES[key]
