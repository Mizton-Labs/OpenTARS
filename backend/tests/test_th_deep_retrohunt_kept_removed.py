"""Tests for issue-local-015: deep_retrohunt_planner's "Sanitized IOCs"
table must show BOTH kept and removed IOCs (action-tagged), while the
actual SPL/CSV/LLM-context it builds uses kept IOCs only.

Before this fix, deep_retrohunt_planner read `raw_ioc_list` — which
intake_classifier already filters to exclude action=='remove' items in
active_cleaning mode — so removed IOCs were invisible to this node
entirely; there was no way to review them from the Sanitized IOCs panel."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from backend.threat_hunting.agents.nodes.deep_retrohunt_planner import deep_retrohunt_planner

_LLM_ENRICHMENT_RESPONSE = json.dumps(
    {
        "spl_draft": "[threathunt_ioc_test]\n| makeresults",
        "spl_macro_name": "threathunt_ioc_test",
        "search_hint": "hunt for iocs",
        "analyst_notes": "notes",
    }
)


def _ioc(ioc: str, ioc_type: str, action: str) -> dict:
    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "ioc_description": "",
        "noise_score": 0.0,
        "flagged_noisy": False,
        "action": action,
    }


class TestKeptAndRemovedIocsBothVisible:
    @pytest.mark.asyncio
    async def test_sanitized_iocs_includes_both_keep_and_remove(self):
        all_iocs = [
            _ioc("evil.com", "domain", "keep"),
            _ioc("google.com", "domain", "remove"),
        ]
        with patch(
            "backend.threat_hunting.agents.nodes.deep_retrohunt_planner.call_llm",
            new=AsyncMock(return_value=_LLM_ENRICHMENT_RESPONSE),
        ):
            result = await deep_retrohunt_planner(
                {
                    "hunt_package_id": "pkg1",
                    "research_effort": "medium",
                    "all_extracted_iocs": all_iocs,
                }
            )

        retro = result["deep_retrohunt"]
        assert len(retro["sanitized_iocs"]) == 2
        actions = {s["ioc"]: s["action"] for s in retro["sanitized_iocs"]}
        assert actions["evil.com"] == "keep"
        assert actions["google.com"] == "remove"

    @pytest.mark.asyncio
    async def test_counts_and_csv_reflect_kept_only(self):
        all_iocs = [
            _ioc("evil.com", "domain", "keep"),
            _ioc("google.com", "domain", "remove"),
            _ioc("also-evil.com", "domain", "keep"),
        ]
        with patch(
            "backend.threat_hunting.agents.nodes.deep_retrohunt_planner.call_llm",
            new=AsyncMock(return_value=_LLM_ENRICHMENT_RESPONSE),
        ):
            result = await deep_retrohunt_planner(
                {
                    "hunt_package_id": "pkg1",
                    "research_effort": "medium",
                    "all_extracted_iocs": all_iocs,
                }
            )

        retro = result["deep_retrohunt"]
        assert retro["total_ioc_count"] == 2  # kept only
        assert "google.com" not in retro["ioc_csv"]
        assert "evil.com" in retro["ioc_csv"]
        assert "also-evil.com" in retro["ioc_csv"]

    @pytest.mark.asyncio
    async def test_falls_back_to_raw_ioc_list_when_all_extracted_iocs_absent(self):
        """Older/resumed pipeline state without all_extracted_iocs must still work."""
        all_iocs = [_ioc("evil.com", "domain", "keep")]
        with patch(
            "backend.threat_hunting.agents.nodes.deep_retrohunt_planner.call_llm",
            new=AsyncMock(return_value=_LLM_ENRICHMENT_RESPONSE),
        ):
            result = await deep_retrohunt_planner(
                {"hunt_package_id": "pkg1", "research_effort": "medium", "raw_ioc_list": all_iocs}
            )

        assert result["deep_retrohunt"] is not None
        assert len(result["deep_retrohunt"]["sanitized_iocs"]) == 1

    @pytest.mark.asyncio
    async def test_removal_reason_leads_noise_reasons_for_removed_iocs(self):
        """issue-local-015 feedback: the 'Removed' section must show WHY an
        IOC was excluded. intake_classifier stashes this on 'removal_reason'
        (see iocs.compute_ioc_action) — deep_retrohunt_planner must surface
        it, since _noise_reasons() alone doesn't know about active-cleaning
        allowlist matches (e.g. remove_legit_domains has nothing to do with
        noise scoring)."""
        all_iocs = [
            {
                **_ioc("google.com", "domain", "remove"),
                "removal_reason": "Known legitimate/brand domain — excluded by active cleaning (remove_legit_domains)",
            },
            _ioc("evil.com", "domain", "keep"),
        ]
        with patch(
            "backend.threat_hunting.agents.nodes.deep_retrohunt_planner.call_llm",
            new=AsyncMock(return_value=_LLM_ENRICHMENT_RESPONSE),
        ):
            result = await deep_retrohunt_planner(
                {
                    "hunt_package_id": "pkg1",
                    "research_effort": "medium",
                    "all_extracted_iocs": all_iocs,
                }
            )

        retro = result["deep_retrohunt"]
        by_ioc = {s["ioc"]: s for s in retro["sanitized_iocs"]}
        assert by_ioc["google.com"]["noise_reasons"][0] == (
            "Known legitimate/brand domain — excluded by active cleaning (remove_legit_domains)"
        )
        # Kept IOCs are untouched — no removal_reason to surface.
        assert by_ioc["evil.com"]["action"] == "keep"

    @pytest.mark.asyncio
    async def test_missing_action_defaults_to_keep(self):
        """Rows with no 'action' key at all (pre-issue-015 data) must not be
        silently dropped from the hunt — default to 'keep'."""
        all_iocs = [
            {
                "ioc": "evil.com",
                "ioc_type": "domain",
                "ioc_description": "",
                "noise_score": 0.0,
                "flagged_noisy": False,
                # no "action" key
            }
        ]
        with patch(
            "backend.threat_hunting.agents.nodes.deep_retrohunt_planner.call_llm",
            new=AsyncMock(return_value=_LLM_ENRICHMENT_RESPONSE),
        ):
            result = await deep_retrohunt_planner(
                {
                    "hunt_package_id": "pkg1",
                    "research_effort": "medium",
                    "all_extracted_iocs": all_iocs,
                }
            )

        retro = result["deep_retrohunt"]
        assert retro["sanitized_iocs"][0]["action"] == "keep"
        assert retro["total_ioc_count"] == 1
