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


class TestCallLlmUsageOut:
    """issue-local-041: usage_out is an optional, additive out-param — the
    dict is populated with the client's last_usage() once the call
    completes, or left untouched entirely when omitted or when the
    provider reported no usage."""

    @pytest.mark.asyncio
    async def test_call_llm_populates_usage_out_when_given(self):
        mock_client = MagicMock()
        mock_client.complete.return_value = "answer"
        mock_client.last_usage.return_value = {
            "input_tokens": 10,
            "output_tokens": 5,
            "cache_read_tokens": None,
            "cache_creation_tokens": None,
            "total_tokens": 15,
        }
        with patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client):
            usage: dict = {}
            result = await llm_bridge.call_llm("prompt text", usage_out=usage)
        assert result == "answer"
        assert usage["total_tokens"] == 15

    @pytest.mark.asyncio
    async def test_call_llm_leaves_usage_out_untouched_when_provider_reports_none(self):
        mock_client = MagicMock()
        mock_client.complete.return_value = "answer"
        mock_client.last_usage.return_value = None
        with patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client):
            usage: dict = {}
            await llm_bridge.call_llm("prompt text", usage_out=usage)
        assert usage == {}

    @pytest.mark.asyncio
    async def test_call_llm_omitted_usage_out_is_a_no_op(self):
        mock_client = MagicMock()
        mock_client.complete.return_value = "answer"
        mock_client.last_usage.return_value = {"total_tokens": 99}
        with patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client):
            result = await llm_bridge.call_llm("prompt text")
        assert result == "answer"

    @pytest.mark.asyncio
    async def test_call_llm_with_tools_no_tools_fallback_populates_usage_out(self):
        mock_client = MagicMock()
        mock_client.supports_tools = False
        mock_client.complete.return_value = "answer"
        mock_client.last_usage.return_value = {"total_tokens": 42}
        with patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client):
            usage: dict = {}
            text, tool_calls = await llm_bridge.call_llm_with_tools("prompt", [], usage_out=usage)
        assert text == "answer"
        assert tool_calls == []
        assert usage["total_tokens"] == 42

    @pytest.mark.asyncio
    async def test_call_llm_with_tools_populates_usage_out(self):
        mock_client = MagicMock()
        mock_client.supports_tools = True
        mock_client.complete_with_tools.return_value = ("answer", [{"name": "t", "arguments": {}}])
        mock_client.last_usage.return_value = {"total_tokens": 77}
        with patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client):
            usage: dict = {}
            text, tool_calls = await llm_bridge.call_llm_with_tools(
                "prompt", [{"name": "t"}], usage_out=usage
            )
        assert text == "answer"
        assert len(tool_calls) == 1
        assert usage["total_tokens"] == 77


class TestCallLlmPromptLogOut:
    """issue-local-041: prompt_log_out is populated ONLY at 'debug'
    verbosity (prompts can be large, unlike token counts which are always
    captured) — and only when the caller actually passes a list."""

    @pytest.mark.asyncio
    async def test_call_llm_populates_prompt_log_out_at_debug_verbosity(self):
        mock_client = MagicMock()
        mock_client.complete.return_value = "the answer"
        mock_client.last_usage.return_value = None
        with (
            patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client),
            patch("backend.config.loader.load_agent_verbosity", return_value="debug"),
        ):
            prompts: list = []
            await llm_bridge.call_llm(
                "the user prompt", system="the system prompt", prompt_log_out=prompts
            )
        assert prompts == [
            {"type": "system", "content": "the system prompt"},
            {"type": "user", "content": "the user prompt"},
            {"type": "agent", "content": "the answer"},
        ]

    @pytest.mark.asyncio
    async def test_call_llm_leaves_prompt_log_out_empty_below_debug_verbosity(self):
        mock_client = MagicMock()
        mock_client.complete.return_value = "the answer"
        mock_client.last_usage.return_value = None
        with (
            patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client),
            patch("backend.config.loader.load_agent_verbosity", return_value="verbose"),
        ):
            prompts: list = []
            await llm_bridge.call_llm("prompt", prompt_log_out=prompts)
        assert prompts == []

    @pytest.mark.asyncio
    async def test_call_llm_omitted_prompt_log_out_is_a_no_op(self):
        mock_client = MagicMock()
        mock_client.complete.return_value = "the answer"
        mock_client.last_usage.return_value = None
        with (
            patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client),
            patch("backend.config.loader.load_agent_verbosity", return_value="debug"),
        ):
            result = await llm_bridge.call_llm("prompt")
        assert result == "the answer"

    @pytest.mark.asyncio
    async def test_call_llm_with_tools_populates_prompt_log_out_at_debug(self):
        mock_client = MagicMock()
        mock_client.supports_tools = True
        mock_client.complete_with_tools.return_value = ("answer", [])
        mock_client.last_usage.return_value = None
        with (
            patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client),
            patch("backend.config.loader.load_agent_verbosity", return_value="debug"),
        ):
            prompts: list = []
            await llm_bridge.call_llm_with_tools(
                "user prompt", [{"name": "t"}], system="sys prompt", prompt_log_out=prompts
            )
        assert {"type": "system", "content": "sys prompt"} in prompts
        assert {"type": "user", "content": "user prompt"} in prompts
        assert {"type": "agent", "content": "answer"} in prompts
