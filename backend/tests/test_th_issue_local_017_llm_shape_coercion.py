"""Tests for issue-local-017: defensive coercion of LLM-generated array
fields that are supposed to be list[str] but occasionally come back as a
richer per-item object (observed live: Mistral returning
{"observation": ..., "confidence": ..., "evidence": ...} entries for
threat_context.key_observations, and {"hypothesis_id": ..., "technique_id":
..., "description": ..., ...} entries for ttp_analysis.detection_opportunities).
Rendering such an object directly as a React child crashes the page
(minified error #31) — these nodes normalize to plain strings at the source
so every consumer (including already-broken historical runs, once
re-generated) gets clean data."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from backend.threat_hunting.agents.llm_bridge import coerce_string_list

# ── coerce_string_list ───────────────────────────────────────────────────────


class TestCoerceStringList:
    def test_passes_through_plain_strings(self):
        assert coerce_string_list(["a", "b"]) == ["a", "b"]

    def test_non_list_input_returns_empty(self):
        assert coerce_string_list(None) == []
        assert coerce_string_list("not a list") == []
        assert coerce_string_list({"a": 1}) == []

    def test_extracts_preferred_key_from_dict_items(self):
        value = [{"observation": "evil thing happened", "confidence": "high", "evidence": "x"}]
        assert coerce_string_list(value, preferred_keys=("observation", "text")) == [
            "evil thing happened"
        ]

    def test_falls_back_to_second_preferred_key(self):
        value = [{"text": "fallback text", "other": "x"}]
        assert coerce_string_list(value, preferred_keys=("observation", "text")) == [
            "fallback text"
        ]

    def test_falls_back_to_json_dump_when_no_preferred_key_matches(self):
        value = [{"foo": "bar"}]
        result = coerce_string_list(value, preferred_keys=("observation", "text"))
        assert len(result) == 1
        assert "foo" in result[0] and "bar" in result[0]

    def test_skips_none_items(self):
        assert coerce_string_list(["a", None, "b"]) == ["a", "b"]

    def test_coerces_non_string_non_dict_items(self):
        assert coerce_string_list([1, 2.5, True]) == ["1", "2.5", "True"]

    def test_empty_list_stays_empty(self):
        assert coerce_string_list([]) == []


# ── hypothesis_generator: suggested_actions coercion ─────────────────────────


class TestHypothesisSuggestedActionsCoercion:
    @pytest.mark.asyncio
    async def test_object_shaped_actions_coerced_to_strings(self):
        from backend.threat_hunting.agents.nodes.hypothesis_generator import (
            hypothesis_generator,
        )

        response = (
            '[{"id":"H1","title":"t","description":"d","justification":"j",'
            '"relevance":"high","confidence":80,"ioc_basis":[],'
            '"suggested_actions":[{"action":"Run SPL query","tool":"splunk"},'
            '"Check EDR logs"]}]'
        )
        with patch(
            "backend.threat_hunting.agents.nodes.hypothesis_generator.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await hypothesis_generator({"research_effort": "medium"})

        actions = result["hypotheses"][0]["suggested_actions"]
        assert actions == ["Run SPL query", "Check EDR logs"]
        assert all(isinstance(a, str) for a in actions)

    @pytest.mark.asyncio
    async def test_missing_suggested_actions_defaults_to_empty_list(self):
        from backend.threat_hunting.agents.nodes.hypothesis_generator import (
            hypothesis_generator,
        )

        response = (
            '[{"id":"H1","title":"t","description":"d","justification":"j",'
            '"relevance":"high","confidence":80,"ioc_basis":[]}]'
        )
        with patch(
            "backend.threat_hunting.agents.nodes.hypothesis_generator.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await hypothesis_generator({"research_effort": "medium"})

        assert result["hypotheses"][0]["suggested_actions"] == []


# ── threat_context_builder: key_observations coercion ────────────────────────


class TestThreatContextKeyObservationsCoercion:
    @pytest.mark.asyncio
    async def test_object_shaped_observations_coerced_to_strings(self):
        from backend.threat_hunting.agents.nodes.threat_context_builder import (
            threat_context_builder,
        )

        response = (
            '{"threat_actor":"","campaign_name":"","summary":"s","confidence":"high",'
            '"key_observations":[{"observation":"npm worm campaign",'
            '"confidence":"high","evidence":"corpus"},"a plain string too"]}'
        )
        with (
            patch(
                "backend.threat_hunting.agents.nodes.threat_context_builder.call_llm",
                new=AsyncMock(return_value=response),
            ),
            patch(
                "backend.threat_hunting.agents.nodes.threat_context_builder.call_llm_with_tools",
                new=AsyncMock(return_value=("", [])),
            ),
        ):
            result = await threat_context_builder(
                {"evidence_text_corpus": "corpus", "ioc_summary": {}}
            )

        observations = result["threat_context"]["key_observations"]
        assert observations == ["npm worm campaign", "a plain string too"]
        assert all(isinstance(o, str) for o in observations)


# ── ttp_analyst: detection_opportunities coercion ────────────────────────────


class TestTtpDetectionOpportunitiesCoercion:
    @pytest.mark.asyncio
    async def test_object_shaped_opportunities_coerced_to_strings(self):
        from backend.threat_hunting.agents.nodes.ttp_analyst import ttp_analyst

        response = (
            '{"summary":"s","techniques":[],'
            '"detection_opportunities":[{"hypothesis_id":"H1","technique_id":"T1059",'
            '"description":"Search process creation logs","log_source":"EDR",'
            '"query":"..."} ,"a plain string too"]}'
        )
        with patch(
            "backend.threat_hunting.agents.nodes.ttp_analyst.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await ttp_analyst({"threat_context": {}, "hypotheses": []})

        opportunities = result["ttp_analysis"]["detection_opportunities"]
        assert opportunities == ["Search process creation logs", "a plain string too"]
        assert all(isinstance(o, str) for o in opportunities)
