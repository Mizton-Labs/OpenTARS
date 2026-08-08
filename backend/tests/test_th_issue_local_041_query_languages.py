"""
Tests for issue-local-041: configurable SIEM query-language generation.

query_drafting_agent previously hardcoded SPL/KQL/ES DSL in the prompt with
no config, and CQL (CrowdStrike Query Language / LogScale) didn't exist
anywhere. It now reads the global default (config.loader.th_query_languages)
or a per-run override (run_config.query_languages), and drafts only the
enabled languages.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from backend.threat_hunting.agents.nodes.query_drafting_agent import (
    _resolve_query_languages,
    query_drafting_agent,
)

_DEFAULT_LANGUAGES = {"spl": True, "kql": True, "cql": False, "elasticsearch": True}


class TestResolveQueryLanguages:
    def test_uses_global_default_when_no_run_config_override(self):
        with patch(
            "backend.config.loader.load_th_query_languages",
            return_value=_DEFAULT_LANGUAGES,
        ):
            assert _resolve_query_languages({}) == ["spl", "kql", "elasticsearch"]

    def test_run_config_override_merges_over_the_default(self):
        with patch(
            "backend.config.loader.load_th_query_languages",
            return_value=_DEFAULT_LANGUAGES,
        ):
            state = {"run_config": {"query_languages": {"spl": False, "cql": True}}}
            # kql/elasticsearch keep the global default (True); spl turned
            # off, cql turned on by the per-run override.
            assert _resolve_query_languages(state) == ["kql", "cql", "elasticsearch"]

    def test_falls_back_to_spl_when_every_language_disabled(self):
        with patch(
            "backend.config.loader.load_th_query_languages",
            return_value={"spl": False, "kql": False, "cql": False, "elasticsearch": False},
        ):
            assert _resolve_query_languages({}) == ["spl"]

    def test_ignores_unknown_keys_in_the_override(self):
        with patch(
            "backend.config.loader.load_th_query_languages",
            return_value=_DEFAULT_LANGUAGES,
        ):
            state = {"run_config": {"query_languages": {"not_a_real_language": True}}}
            assert _resolve_query_languages(state) == ["spl", "kql", "elasticsearch"]


class TestQueryDraftingAgentLanguageSelection:
    @pytest.mark.asyncio
    async def test_prompt_mentions_only_enabled_languages_incl_cql(self):
        captured_prompts: list[str] = []

        async def _fake_call_llm(user, **_kw):
            captured_prompts.append(user)
            return json.dumps([{"id": "Q1", "language": "cql", "query": "x"}])

        with (
            patch(
                "backend.config.loader.load_th_query_languages",
                return_value={"spl": False, "kql": False, "cql": True, "elasticsearch": False},
            ),
            patch(
                "backend.threat_hunting.agents.nodes.query_drafting_agent.call_llm",
                new=AsyncMock(side_effect=_fake_call_llm),
            ),
        ):
            result = await query_drafting_agent({"research_effort": "medium"})

        assert result["query_drafts"][0]["language"] == "cql"
        prompt_text = captured_prompts[0]
        assert "CrowdStrike Query Language" in prompt_text
        assert "'cql'" in prompt_text
        # SPL/KQL/ES DSL must not be requested when disabled.
        assert "Splunk Search Processing Language" not in prompt_text

    @pytest.mark.asyncio
    async def test_skips_spl_tool_validation_when_spl_disabled(self):
        response = json.dumps([{"id": "Q1", "language": "kql", "query": "x"}])
        with (
            patch(
                "backend.config.loader.load_th_query_languages",
                return_value={"spl": False, "kql": True, "cql": False, "elasticsearch": False},
            ),
            patch(
                "backend.threat_hunting.agents.nodes.query_drafting_agent.call_llm",
                new=AsyncMock(return_value=response),
            ),
            patch(
                "backend.threat_hunting.agents.nodes.query_drafting_agent.call_llm_with_tools",
                new=AsyncMock(side_effect=AssertionError("should not be called when SPL is disabled")),
            ),
            patch("backend.config.loader.load_agent_tools", return_value={"validate_spl": True}),
        ):
            result = await query_drafting_agent({"research_effort": "medium"})

        assert result["query_drafts"][0]["language"] == "kql"

    @pytest.mark.asyncio
    async def test_per_run_override_disables_spl_validation_even_if_globally_enabled(self):
        response = json.dumps([{"id": "Q1", "language": "cql", "query": "x"}])
        with (
            patch(
                "backend.config.loader.load_th_query_languages",
                return_value=_DEFAULT_LANGUAGES,
            ),
            patch(
                "backend.threat_hunting.agents.nodes.query_drafting_agent.call_llm",
                new=AsyncMock(return_value=response),
            ),
            patch(
                "backend.threat_hunting.agents.nodes.query_drafting_agent.call_llm_with_tools",
                new=AsyncMock(side_effect=AssertionError("should not be called when SPL is disabled")),
            ),
            patch("backend.config.loader.load_agent_tools", return_value={"validate_spl": True}),
        ):
            state = {
                "research_effort": "medium",
                "run_config": {"query_languages": {"spl": False, "cql": True}},
            }
            result = await query_drafting_agent(state)

        assert result["query_drafts"][0]["language"] == "cql"
