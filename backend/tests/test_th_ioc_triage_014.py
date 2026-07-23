"""Tests for issue-local-014 LLM IOC triage (intake_classifier step 5b)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from backend.threat_hunting.agents.nodes.intake_classifier import _llm_triage_iocs


class TestLlmTriageIocs:
    @pytest.mark.asyncio
    async def test_returns_empty_when_no_unflagged_candidates(self):
        all_iocs = [
            {"ioc": "evil.com", "ioc_type": "domain", "flagged_noisy": True},
        ]
        result = await _llm_triage_iocs(all_iocs, provider_name=None, model_name=None)
        assert result == []

    @pytest.mark.asyncio
    async def test_parses_llm_flags(self):
        all_iocs = [
            {"ioc": "example.com", "ioc_type": "domain", "flagged_noisy": False},
        ]
        response = (
            '[{"ioc": "example.com", "ioc_type": "domain", "reason": "documentation domain"}]'
        )
        with patch(
            "backend.threat_hunting.agents.llm_bridge.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await _llm_triage_iocs(all_iocs, provider_name=None, model_name=None)
        assert result == [
            {"ioc": "example.com", "ioc_type": "domain", "reason": "documentation domain"}
        ]

    @pytest.mark.asyncio
    async def test_non_list_response_returns_empty(self):
        all_iocs = [{"ioc": "example.com", "ioc_type": "domain", "flagged_noisy": False}]
        with patch(
            "backend.threat_hunting.agents.llm_bridge.call_llm",
            new=AsyncMock(return_value="not json at all"),
        ):
            result = await _llm_triage_iocs(all_iocs, provider_name=None, model_name=None)
        assert result == []

    @pytest.mark.asyncio
    async def test_malformed_items_are_dropped(self):
        all_iocs = [{"ioc": "example.com", "ioc_type": "domain", "flagged_noisy": False}]
        response = '[{"ioc": "example.com"}, {"not_ioc": "x"}, "junk"]'
        with patch(
            "backend.threat_hunting.agents.llm_bridge.call_llm",
            new=AsyncMock(return_value=response),
        ):
            result = await _llm_triage_iocs(all_iocs, provider_name=None, model_name=None)
        # First item missing ioc_type, second missing ioc, third not a dict.
        assert result == []


class TestTriageMergeIntoAllIocs:
    """Behavioral test of the merge logic inlined in intake_classifier — exercised
    directly here since it isn't its own function (keeps it close to the node body,
    matching house style), so we replicate the exact merge loop for verification."""

    def _apply(self, all_iocs, flags):
        triaged = 0
        for flag in flags:
            for ioc_item in all_iocs:
                if (
                    ioc_item.get("ioc") == flag["ioc"]
                    and ioc_item.get("ioc_type") == flag["ioc_type"]
                    and not ioc_item.get("flagged_noisy")
                ):
                    ioc_item["flagged_noisy"] = True
                    ioc_item["noise_score"] = max(float(ioc_item.get("noise_score") or 0.0), 0.75)
                    reason = flag.get("reason", "").strip()
                    if reason:
                        existing_desc = ioc_item.get("ioc_description") or ""
                        ioc_item["ioc_description"] = (
                            f"{existing_desc} [LLM triage: {reason}]".strip()
                        )
                    triaged += 1
                    break
        return triaged

    def test_flags_matching_ioc(self):
        all_iocs = [
            {"ioc": "example.com", "ioc_type": "domain", "flagged_noisy": False, "noise_score": 0.0}
        ]
        flags = [{"ioc": "example.com", "ioc_type": "domain", "reason": "doc domain"}]
        count = self._apply(all_iocs, flags)
        assert count == 1
        assert all_iocs[0]["flagged_noisy"] is True
        assert all_iocs[0]["noise_score"] == 0.75
        assert "LLM triage: doc domain" in all_iocs[0]["ioc_description"]

    def test_does_not_lower_an_existing_higher_score(self):
        all_iocs = [
            {"ioc": "x.com", "ioc_type": "domain", "flagged_noisy": False, "noise_score": 0.9}
        ]
        flags = [{"ioc": "x.com", "ioc_type": "domain", "reason": "r"}]
        self._apply(all_iocs, flags)
        assert all_iocs[0]["noise_score"] == 0.9

    def test_type_mismatch_does_not_flag(self):
        all_iocs = [
            {"ioc": "1.2.3.4", "ioc_type": "ip", "flagged_noisy": False, "noise_score": 0.0}
        ]
        flags = [{"ioc": "1.2.3.4", "ioc_type": "domain", "reason": "r"}]
        count = self._apply(all_iocs, flags)
        assert count == 0
        assert all_iocs[0]["flagged_noisy"] is False

    def test_already_flagged_is_not_double_counted(self):
        all_iocs = [
            {"ioc": "x.com", "ioc_type": "domain", "flagged_noisy": True, "noise_score": 0.95}
        ]
        flags = [{"ioc": "x.com", "ioc_type": "domain", "reason": "r"}]
        count = self._apply(all_iocs, flags)
        assert count == 0
