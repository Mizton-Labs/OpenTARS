"""
Tests for backend.threat_hunting.evidence_source (issue-local-034) — the
source-entity resolution backing the Data Explorer "Feed sources" tab.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from backend.threat_hunting import evidence_source


class TestDomainFromUrl:
    def test_extracts_domain(self) -> None:
        assert (
            evidence_source.domain_from_url("https://evil-example.com/page?x=1")
            == "evil-example.com"
        )

    def test_strips_www_prefix(self) -> None:
        assert evidence_source.domain_from_url("https://www.example.com/") == "example.com"

    def test_strips_port_and_credentials(self) -> None:
        assert (
            evidence_source.domain_from_url("https://user:pass@example.com:8443/x") == "example.com"
        )

    def test_invalid_url_returns_none(self) -> None:
        assert evidence_source.domain_from_url("not a url") is None

    def test_empty_string_returns_none(self) -> None:
        assert evidence_source.domain_from_url("") is None


class TestResolveSourceEntityFromText:
    @pytest.mark.asyncio
    async def test_empty_text_returns_none_without_calling_llm(self) -> None:
        with patch("backend.threat_hunting.agents.llm_bridge.call_llm") as mock_call:
            result = await evidence_source.resolve_source_entity_from_text("")
        assert result is None
        mock_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_returns_identified_entity(self) -> None:
        with patch(
            "backend.threat_hunting.agents.llm_bridge.call_llm",
            new=AsyncMock(return_value="Acme Threat Intel"),
        ):
            result = await evidence_source.resolve_source_entity_from_text("Published by Acme...")
        assert result == "Acme Threat Intel"

    @pytest.mark.asyncio
    async def test_unknown_response_returns_none(self) -> None:
        with patch(
            "backend.threat_hunting.agents.llm_bridge.call_llm",
            new=AsyncMock(return_value="unknown"),
        ):
            result = await evidence_source.resolve_source_entity_from_text("some text")
        assert result is None

    @pytest.mark.asyncio
    async def test_overlong_response_treated_as_non_compliant_returns_none(self) -> None:
        with patch(
            "backend.threat_hunting.agents.llm_bridge.call_llm",
            new=AsyncMock(return_value="x" * 200),
        ):
            result = await evidence_source.resolve_source_entity_from_text("some text")
        assert result is None

    @pytest.mark.asyncio
    async def test_llm_failure_is_soft_fail_never_raises(self) -> None:
        with patch(
            "backend.threat_hunting.agents.llm_bridge.call_llm",
            new=AsyncMock(side_effect=RuntimeError("provider down")),
        ):
            result = await evidence_source.resolve_source_entity_from_text("some text")
        assert result is None
