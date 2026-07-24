"""Tests for query_drafting_agent's defensive 'query' field normalization.

Some LLMs (observed with Kimi-K2.6 drafting an ES DSL query) return `query`
as a nested JSON object instead of the string the schema requires — the
frontend renders it directly as a React child, and an object throws
"Objects are not valid as a React child" and blanks the page. The node must
always store `query` as a string."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from backend.threat_hunting.agents.nodes.query_drafting_agent import query_drafting_agent


class TestQueryFieldNormalization:
    @pytest.mark.asyncio
    async def test_object_query_is_stringified(self):
        es_dsl_object = {"bool": {"must": [{"terms": {"event.category": ["network"]}}]}}
        response = json.dumps(
            [
                {
                    "id": "Q1",
                    "language": "es_dsl",
                    "title": "t",
                    "description": "d",
                    "query": es_dsl_object,
                    "data_sources": ["network"],
                    "lead_id": "L1",
                }
            ]
        )
        with patch(
            "backend.threat_hunting.agents.nodes.query_drafting_agent.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await query_drafting_agent({"research_effort": "medium"})

        draft = result["query_drafts"][0]
        assert isinstance(draft["query"], str)
        # Must round-trip to the same structure, just serialized.
        assert json.loads(draft["query"]) == es_dsl_object

    @pytest.mark.asyncio
    async def test_string_query_untouched(self):
        response = json.dumps(
            [
                {
                    "id": "Q1",
                    "language": "spl",
                    "title": "t",
                    "description": "d",
                    "query": "index=* | stats count",
                    "data_sources": ["network"],
                    "lead_id": "L1",
                }
            ]
        )
        with patch(
            "backend.threat_hunting.agents.nodes.query_drafting_agent.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await query_drafting_agent({"research_effort": "medium"})

        assert result["query_drafts"][0]["query"] == "index=* | stats count"

    @pytest.mark.asyncio
    async def test_non_dict_draft_items_are_dropped(self):
        response = json.dumps(["not a dict", {"id": "Q1", "query": "x"}])
        with patch(
            "backend.threat_hunting.agents.nodes.query_drafting_agent.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await query_drafting_agent({"research_effort": "medium"})

        assert len(result["query_drafts"]) == 1
        assert result["query_drafts"][0]["id"] == "Q1"

    @pytest.mark.asyncio
    async def test_null_query_normalized_to_empty_string(self):
        """A None query must not crash the SPL-preview join in tool
        validation (str.join() rejects None items) — normalize to ''."""
        response = json.dumps([{"id": "Q1", "language": "spl", "query": None}])
        with patch(
            "backend.threat_hunting.agents.nodes.query_drafting_agent.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await query_drafting_agent({"research_effort": "medium"})

        assert "query_drafts" in result, f"step crashed entirely: {result}"
        assert result["query_drafts"][0]["query"] == ""
