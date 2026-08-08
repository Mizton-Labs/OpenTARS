"""
Tests for issue-local-041: per-client token usage capture.

Each LLMClient concrete implementation stores the most recent call's token
usage on ``self._last_usage`` (read via ``.last_usage()``), extracted from
whatever usage envelope that provider's response actually contains — no
shared/global state, since registry.get_client() constructs a brand-new
client instance per call (see llm_bridge.call_llm), so concurrent playbook
runs never share one instance to race on.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from backend.llm.client import (
    AnthropicClient,
    AzureAIFoundryClient,
    OllamaClient,
    OpenAIClient,
    OpenAICompatibleClient,
)


class _FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def __call__(self, method, url, *, headers, body, timeout, skip_tls_verify, max_retries, provider_name):
        self.calls.append({"method": method, "url": url, "body": body})
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class TestOpenAIUsage:
    def test_complete_captures_usage(self):
        body = json.dumps(
            {
                "choices": [{"message": {"content": "hi"}}],
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 20,
                    "total_tokens": 120,
                    "prompt_tokens_details": {"cached_tokens": 30},
                },
            }
        ).encode()
        c = OpenAIClient(
            name="openai-test", base_url="https://api.openai.com/v1", api_key="sk-test",
            model="gpt-4o-mini", transport=_FakeTransport([(200, {}, body)]),
        )
        assert c.last_usage() is None
        c.complete("hello")
        usage = c.last_usage()
        assert usage == {
            "input_tokens": 100,
            "output_tokens": 20,
            "cache_read_tokens": 30,
            "cache_creation_tokens": None,
            "total_tokens": 120,
        }

    def test_complete_with_tools_captures_usage(self):
        body = json.dumps(
            {
                "choices": [{"message": {"content": "hi", "tool_calls": []}}],
                "usage": {"prompt_tokens": 50, "completion_tokens": 5, "total_tokens": 55},
            }
        ).encode()
        c = OpenAIClient(
            name="openai-test", base_url="https://api.openai.com/v1", api_key="sk-test",
            model="gpt-4o-mini", transport=_FakeTransport([(200, {}, body)]),
        )
        c.complete_with_tools("hello", [])
        assert c.last_usage() == {
            "input_tokens": 50,
            "output_tokens": 5,
            "cache_read_tokens": None,
            "cache_creation_tokens": None,
            "total_tokens": 55,
        }

    def test_missing_usage_block_is_none(self):
        body = json.dumps({"choices": [{"message": {"content": "hi"}}]}).encode()
        c = OpenAIClient(
            name="openai-test", base_url="https://api.openai.com/v1", api_key="sk-test",
            model="gpt-4o-mini", transport=_FakeTransport([(200, {}, body)]),
        )
        c.complete("hello")
        assert c.last_usage() is None

    def test_openai_compatible_client_captures_usage(self):
        body = json.dumps(
            {
                "choices": [{"message": {"content": "hi"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
            }
        ).encode()
        c = OpenAICompatibleClient(
            name="vllm-local", base_url="http://localhost:8000/v1", api_key="",
            model="local-model", transport=_FakeTransport([(200, {}, body)]),
        )
        c.complete("hello")
        assert c.last_usage()["total_tokens"] == 12

    def test_azure_unified_client_captures_usage(self):
        body = json.dumps(
            {
                "choices": [{"message": {"content": "hi"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
            }
        ).encode()
        c = AzureAIFoundryClient(
            name="foundry", base_url="https://my-resource.services.ai.azure.com", api_key="az-key",
            model="gpt-4o", transport=_FakeTransport([(200, {}, body)]),
        )
        c.complete("hello")
        assert c.last_usage()["total_tokens"] == 12


class TestAnthropicUsage:
    def test_complete_captures_usage(self):
        body = json.dumps(
            {
                "content": [{"type": "text", "text": "ok"}],
                "usage": {
                    "input_tokens": 200,
                    "output_tokens": 40,
                    "cache_creation_input_tokens": 15,
                    "cache_read_input_tokens": 5,
                },
            }
        ).encode()
        c = AnthropicClient(
            name="claude", base_url="https://api.anthropic.com", api_key="sk-ant",
            model="claude-3-5-sonnet-latest", transport=_FakeTransport([(200, {}, body)]),
        )
        c.complete("hello")
        usage = c.last_usage()
        assert usage == {
            "input_tokens": 200,
            "output_tokens": 40,
            "cache_read_tokens": 5,
            "cache_creation_tokens": 15,
            # No total_tokens field from Anthropic — summed by the extractor.
            "total_tokens": 240,
        }

    def test_azure_anthropic_style_client_captures_usage(self):
        body = json.dumps(
            {
                "content": [{"type": "text", "text": "ok"}],
                "usage": {"input_tokens": 30, "output_tokens": 10},
            }
        ).encode()
        c = AzureAIFoundryClient(
            name="foundry-anthropic", base_url="https://my-resource.services.ai.azure.com",
            api_key="az-key", model="claude-sonnet-5", api_style="anthropic",
            transport=_FakeTransport([(200, {}, body)]),
        )
        c.complete("hello")
        assert c.last_usage() == {
            "input_tokens": 30,
            "output_tokens": 10,
            "cache_read_tokens": None,
            "cache_creation_tokens": None,
            "total_tokens": 40,
        }


class TestOllamaUsage:
    def test_complete_captures_usage(self):
        body = json.dumps(
            {"message": {"content": "hi"}, "prompt_eval_count": 12, "eval_count": 3}
        ).encode()
        c = OllamaClient(
            name="ollama-local", base_url="http://localhost:11434", api_key="",
            model="llama3", transport=_FakeTransport([(200, {}, body)]),
        )
        c.complete("hello")
        assert c.last_usage() == {
            "input_tokens": 12,
            "output_tokens": 3,
            "cache_read_tokens": None,
            "cache_creation_tokens": None,
            "total_tokens": 15,
        }

    def test_missing_counts_is_none(self):
        body = json.dumps({"message": {"content": "hi"}}).encode()
        c = OllamaClient(
            name="ollama-local", base_url="http://localhost:11434", api_key="",
            model="llama3", transport=_FakeTransport([(200, {}, body)]),
        )
        c.complete("hello")
        assert c.last_usage() is None


class TestPromptCaptureIntegration:
    """issue-local-041: end-to-end through a real pipeline node — call_llm
    is NOT mocked, only get_client (registry boundary) — verifying the
    node's own step_logs entry actually carries typed prompts at 'debug'
    verbosity and doesn't at lower levels."""

    @pytest.mark.asyncio
    async def test_hypothesis_generator_captures_prompts_at_debug_verbosity(self):
        import json

        from backend.threat_hunting.agents.nodes import hypothesis_generator as hg_mod

        fake_client = MagicMock()
        fake_client.complete.return_value = json.dumps(
            [{"id": "H1", "title": "t", "description": "d", "relevance": "high"}]
        )
        fake_client.last_usage.return_value = None

        with (
            patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=fake_client),
            patch("backend.config.loader.load_agent_verbosity", return_value="debug"),
        ):
            result = await hg_mod.hypothesis_generator({"research_effort": "medium"})

        step_log = result["step_logs"][0]
        assert step_log["step"] == "hypothesis_generator"
        assert step_log["prompts"], "expected prompts to be captured at debug verbosity"
        types = [p["type"] for p in step_log["prompts"]]
        assert "system" in types
        assert "user" in types
        assert "agent" in types

    @pytest.mark.asyncio
    async def test_hypothesis_generator_omits_prompts_below_debug_verbosity(self):
        import json

        from backend.threat_hunting.agents.nodes import hypothesis_generator as hg_mod

        fake_client = MagicMock()
        fake_client.complete.return_value = json.dumps(
            [{"id": "H1", "title": "t", "description": "d", "relevance": "high"}]
        )
        fake_client.last_usage.return_value = None

        with (
            patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=fake_client),
            patch("backend.config.loader.load_agent_verbosity", return_value="verbose"),
        ):
            result = await hg_mod.hypothesis_generator({"research_effort": "medium"})

        step_log = result["step_logs"][0]
        assert step_log.get("prompts") is None


class TestUsageInstanceIsolation:
    def test_each_client_instance_has_its_own_usage_no_shared_state(self):
        """issue-local-041: the whole point — get_client() constructs a fresh
        instance per call, so two 'concurrent' clients never see each
        other's usage even though they're the same provider kind."""
        body_a = json.dumps(
            {"choices": [{"message": {"content": "a"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
        ).encode()
        body_b = json.dumps(
            {"choices": [{"message": {"content": "b"}}], "usage": {"prompt_tokens": 9, "completion_tokens": 9, "total_tokens": 18}}
        ).encode()
        client_a = OpenAIClient(
            name="a", base_url="https://api.openai.com/v1", api_key="k",
            model="gpt-4o-mini", transport=_FakeTransport([(200, {}, body_a)]),
        )
        client_b = OpenAIClient(
            name="b", base_url="https://api.openai.com/v1", api_key="k",
            model="gpt-4o-mini", transport=_FakeTransport([(200, {}, body_b)]),
        )
        client_a.complete("x")
        client_b.complete("y")
        assert client_a.last_usage()["total_tokens"] == 2
        assert client_b.last_usage()["total_tokens"] == 18
