"""Tests for issue-local-014 LLM call retry/backoff resilience."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from backend.llm.errors import LLMEmptyContentError, LLMProviderError, LLMTransportError
from backend.threat_hunting.agents import llm_bridge


def _patch_retry_config(max_retries: int = 3, backoff: float = 0.0):
    return (
        patch(
            "backend.config.loader.load_th_llm_max_retries",
            return_value=max_retries,
        ),
        patch(
            "backend.config.loader.load_th_llm_retry_backoff_seconds",
            return_value=backoff,
        ),
    )


class TestIsRetryable:
    def test_empty_content_is_retryable(self):
        assert llm_bridge._is_retryable(LLMEmptyContentError("x", finish_reason="length"))

    def test_transport_error_is_retryable(self):
        assert llm_bridge._is_retryable(LLMTransportError("timed out"))

    def test_provider_5xx_is_retryable(self):
        assert llm_bridge._is_retryable(LLMProviderError("x", status=502))

    def test_provider_4xx_is_not_retryable(self):
        assert not llm_bridge._is_retryable(LLMProviderError("bad request", status=400))

    def test_provider_unknown_status_is_retryable(self):
        assert llm_bridge._is_retryable(LLMProviderError("x", status=None))

    def test_unrelated_exception_is_not_retryable(self):
        assert not llm_bridge._is_retryable(ValueError("nope"))


class TestCallWithRetry:
    @pytest.mark.asyncio
    async def test_succeeds_first_try_without_retry(self):
        calls = []

        async def attempt(mt: int) -> str:
            calls.append(mt)
            return "ok"

        p1, p2 = _patch_retry_config()
        with p1, p2:
            result = await llm_bridge._call_with_retry(attempt, max_tokens=2048, retry_label="test")
        assert result == "ok"
        assert calls == [2048]

    @pytest.mark.asyncio
    async def test_retries_on_transport_error_then_succeeds(self):
        calls = []

        async def attempt(mt: int) -> str:
            calls.append(mt)
            if len(calls) < 3:
                raise LLMTransportError("timed out")
            return "ok"

        p1, p2 = _patch_retry_config(max_retries=3, backoff=0.0)
        with p1, p2:
            result = await llm_bridge._call_with_retry(attempt, max_tokens=1024, retry_label="test")
        assert result == "ok"
        # Transport errors don't change max_tokens across attempts.
        assert calls == [1024, 1024, 1024]

    @pytest.mark.asyncio
    async def test_escalates_max_tokens_on_empty_content_error(self):
        calls = []

        async def attempt(mt: int) -> str:
            calls.append(mt)
            if len(calls) < 3:
                raise LLMEmptyContentError("empty", finish_reason="length")
            return "ok"

        p1, p2 = _patch_retry_config(max_retries=3, backoff=0.0)
        with p1, p2:
            result = await llm_bridge._call_with_retry(attempt, max_tokens=1000, retry_label="test")
        assert result == "ok"
        assert calls == [1000, 2000, 4000]

    @pytest.mark.asyncio
    async def test_max_tokens_escalation_is_capped(self):
        calls = []

        async def attempt(mt: int) -> str:
            calls.append(mt)
            raise LLMEmptyContentError("empty", finish_reason="length")

        p1, p2 = _patch_retry_config(max_retries=6, backoff=0.0)
        with p1, p2, pytest.raises(LLMEmptyContentError):
            await llm_bridge._call_with_retry(attempt, max_tokens=10000, retry_label="test")
        assert all(mt <= llm_bridge._EMPTY_CONTENT_MAX_TOKENS_CEILING for mt in calls)
        assert calls[-1] == llm_bridge._EMPTY_CONTENT_MAX_TOKENS_CEILING

    @pytest.mark.asyncio
    async def test_does_not_retry_permanent_4xx_error(self):
        calls = []

        async def attempt(mt: int) -> str:
            calls.append(mt)
            raise LLMProviderError("bad request", status=400)

        p1, p2 = _patch_retry_config(max_retries=3, backoff=0.0)
        with p1, p2, pytest.raises(LLMProviderError):
            await llm_bridge._call_with_retry(attempt, max_tokens=1024, retry_label="test")
        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_gives_up_after_max_retries_exhausted(self):
        calls = []

        async def attempt(mt: int) -> str:
            calls.append(mt)
            raise LLMTransportError("timed out")

        p1, p2 = _patch_retry_config(max_retries=2, backoff=0.0)
        with p1, p2, pytest.raises(LLMTransportError):
            await llm_bridge._call_with_retry(attempt, max_tokens=1024, retry_label="test")
        # Initial attempt + 2 retries = 3 calls total.
        assert len(calls) == 3

    @pytest.mark.asyncio
    async def test_zero_max_retries_means_single_attempt(self):
        calls = []

        async def attempt(mt: int) -> str:
            calls.append(mt)
            raise LLMTransportError("timed out")

        p1, p2 = _patch_retry_config(max_retries=0, backoff=0.0)
        with p1, p2, pytest.raises(LLMTransportError):
            await llm_bridge._call_with_retry(attempt, max_tokens=1024, retry_label="test")
        assert len(calls) == 1


class TestCallLlmIntegration:
    @pytest.mark.asyncio
    async def test_call_llm_retries_via_client_complete(self):
        mock_client = MagicMock()
        mock_client.complete.side_effect = [
            LLMTransportError("timed out"),
            "final answer",
        ]

        p1, p2 = _patch_retry_config(max_retries=2, backoff=0.0)
        with (
            patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client),
            p1,
            p2,
        ):
            result = await llm_bridge.call_llm("prompt text")
        assert result == "final answer"
        assert mock_client.complete.call_count == 2

    @pytest.mark.asyncio
    async def test_call_llm_raises_after_exhausting_retries(self):
        mock_client = MagicMock()
        mock_client.complete.side_effect = LLMTransportError("timed out")

        p1, p2 = _patch_retry_config(max_retries=1, backoff=0.0)
        with (
            patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client),
            p1,
            p2,
            pytest.raises(LLMTransportError),
        ):
            await llm_bridge.call_llm("prompt text")
        assert mock_client.complete.call_count == 2
