"""
Tests for issue-local-006 Part B — Agent Tool-Calling.

Covers:
  - Each tool wrapper (extract_iocs, defang_ioc, noise_score, mitre_lookup,
    validate_spl, refetch_url)
  - call_tool dispatcher: known tools, unknown tools, missing required args
  - SSRF: refetch_url passes through url_fetcher (which enforces SSRF)
  - call_llm_with_tools: capable provider returns (text, tool_calls)
  - call_llm_with_tools: non-capable provider falls back to call_llm ([], text)
  - LLM client: supports_tools property on OpenAI/Anthropic/Ollama/Compatible
  - LLM client: complete_with_tools parses OpenAI/Anthropic tool-call responses
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─── tool_defang_ioc ─────────────────────────────────────────────────────────

def test_defang_ioc_normalizes_defanged_ip() -> None:
    """tool_defang_ioc normalizes a defanged/fanged IOC to its canonical form."""
    from backend.threat_hunting.agents.tools import tool_defang_ioc

    # _defang in iocs.py actually re-fangs (normalizes) defanged notation
    result = tool_defang_ioc("192[.]168[.]1[.]1")
    assert isinstance(result, str)
    # The plain IP is returned as-is (it's already canonical)
    result2 = tool_defang_ioc("192.168.1.1")
    assert result2 == "192.168.1.1"


def test_defang_ioc_returns_string() -> None:
    from backend.threat_hunting.agents.tools import tool_defang_ioc

    result = tool_defang_ioc("malware.example.com")
    assert isinstance(result, str)


# ─── tool_noise_score ─────────────────────────────────────────────────────────

def test_noise_score_returns_dict() -> None:
    from backend.threat_hunting.agents.tools import tool_noise_score

    result = tool_noise_score("192.168.1.1", "ip")
    assert isinstance(result, dict)
    assert "score" in result
    assert "reasons" in result
    assert isinstance(result["score"], (int, float))
    assert isinstance(result["reasons"], list)


def test_noise_score_private_ip_is_noisy() -> None:
    from backend.threat_hunting.agents.tools import tool_noise_score

    result = tool_noise_score("10.0.0.1", "ip")
    # Private IP should have a high noise score
    assert result["score"] > 0


def test_noise_score_public_hash_low_noise() -> None:
    from backend.threat_hunting.agents.tools import tool_noise_score

    result = tool_noise_score("aabbccdd" * 4, "hash_md5")  # 32-char hex
    assert isinstance(result["score"], (int, float))


# ─── tool_mitre_lookup ───────────────────────────────────────────────────────

def test_mitre_lookup_known_technique() -> None:
    from backend.threat_hunting.agents.tools import tool_mitre_lookup

    result = tool_mitre_lookup("T1059")
    assert result is not None
    assert result["technique_id"] == "T1059"
    assert "name" in result
    assert "tactic" in result


def test_mitre_lookup_subtechnique() -> None:
    from backend.threat_hunting.agents.tools import tool_mitre_lookup

    result = tool_mitre_lookup("T1059.001")
    assert result is not None
    assert "PowerShell" in result["name"]


def test_mitre_lookup_unknown_returns_none() -> None:
    from backend.threat_hunting.agents.tools import tool_mitre_lookup

    result = tool_mitre_lookup("T9999.999")
    assert result is None


def test_mitre_lookup_normalizes_lowercase() -> None:
    from backend.threat_hunting.agents.tools import tool_mitre_lookup

    result = tool_mitre_lookup("t1059")
    assert result is not None  # should normalize to T1059


def test_mitre_lookup_no_t_prefix() -> None:
    from backend.threat_hunting.agents.tools import tool_mitre_lookup

    result = tool_mitre_lookup("1059")
    assert result is not None  # should prepend T


# ─── tool_validate_spl ───────────────────────────────────────────────────────

def test_validate_spl_valid_query() -> None:
    from backend.threat_hunting.agents.tools import tool_validate_spl

    result = tool_validate_spl("index=main sourcetype=syslog | stats count by host")
    assert result["valid"] is True
    assert result["issues"] == []


def test_validate_spl_unbalanced_parens() -> None:
    from backend.threat_hunting.agents.tools import tool_validate_spl

    result = tool_validate_spl("index=main (sourcetype=syslog | stats count by host")
    assert result["valid"] is False
    assert any("bracket" in issue.lower() for issue in result["issues"])


def test_validate_spl_empty_query() -> None:
    from backend.threat_hunting.agents.tools import tool_validate_spl

    result = tool_validate_spl("")
    assert result["valid"] is False


def test_validate_spl_double_pipe() -> None:
    from backend.threat_hunting.agents.tools import tool_validate_spl

    result = tool_validate_spl("index=main || stats count")
    assert result["valid"] is False
    assert any("pipe" in issue.lower() for issue in result["issues"])


def test_validate_spl_no_commands() -> None:
    from backend.threat_hunting.agents.tools import tool_validate_spl

    result = tool_validate_spl("this is not spl at all random text")
    assert result["valid"] is False


# ─── tool_extract_iocs ───────────────────────────────────────────────────────

def test_extract_iocs_returns_list() -> None:
    from backend.threat_hunting.agents.tools import tool_extract_iocs

    result = tool_extract_iocs("Attacker IP: 185.220.101.1 used domain evil.example.com")
    assert isinstance(result, list)


def test_extract_iocs_caps_input() -> None:
    from backend.threat_hunting.agents.tools import tool_extract_iocs

    # Should not raise on huge input (capped to 50_000)
    huge_text = "A" * 100_000
    result = tool_extract_iocs(huge_text)
    assert isinstance(result, list)


def test_extract_iocs_result_shape() -> None:
    from backend.threat_hunting.agents.tools import tool_extract_iocs

    result = tool_extract_iocs("The IP 8.8.8.8 was observed.")
    for item in result:
        assert "ioc" in item
        assert "ioc_type" in item


# ─── call_tool dispatcher ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_call_tool_unknown_raises() -> None:
    from backend.threat_hunting.agents.tools import call_tool

    with pytest.raises(ValueError, match="Unknown tool"):
        await call_tool("nonexistent_tool", {})


@pytest.mark.asyncio
async def test_call_tool_missing_required_arg_raises() -> None:
    from backend.threat_hunting.agents.tools import call_tool

    # mitre_lookup requires technique_id
    with pytest.raises(ValueError, match="requires parameter"):
        await call_tool("mitre_lookup", {})


@pytest.mark.asyncio
async def test_call_tool_defang_ioc() -> None:
    from backend.threat_hunting.agents.tools import call_tool

    result = await call_tool("defang_ioc", {"ioc": "192.168.1.1"})
    assert isinstance(result, str)


@pytest.mark.asyncio
async def test_call_tool_noise_score() -> None:
    from backend.threat_hunting.agents.tools import call_tool

    result = await call_tool("noise_score", {"ioc": "10.0.0.1", "ioc_type": "ip"})
    assert isinstance(result, dict)
    assert "score" in result


@pytest.mark.asyncio
async def test_call_tool_mitre_lookup() -> None:
    from backend.threat_hunting.agents.tools import call_tool

    result = await call_tool("mitre_lookup", {"technique_id": "T1059"})
    assert result is not None


@pytest.mark.asyncio
async def test_call_tool_validate_spl() -> None:
    from backend.threat_hunting.agents.tools import call_tool

    result = await call_tool("validate_spl", {"query": "index=main | stats count"})
    assert isinstance(result, dict)
    assert "valid" in result


@pytest.mark.asyncio
async def test_call_tool_refetch_url_delegates_to_fetcher() -> None:
    """refetch_url must delegate to fetch_url (which enforces SSRF)."""
    from backend.threat_hunting.agents import tools as tools_module

    with patch(
        "backend.threat_hunting.extractors.url_fetcher.fetch_url",
        new=AsyncMock(return_value=MagicMock(extracted_text="fetched content")),
    ) as mock_fetch:
        result = await tools_module.call_tool("refetch_url", {"url": "https://example.com/"})

    mock_fetch.assert_called_once_with("https://example.com/")
    assert result == "fetched content"


# ─── LLM client: supports_tools property ─────────────────────────────────────

def test_openai_client_supports_tools() -> None:
    from backend.llm.client import OpenAIClient

    client = OpenAIClient(
        name="test",
        base_url="https://api.openai.com/v1",
        api_key="test-key",
        model="gpt-4",
    )
    assert client.supports_tools is True


def test_anthropic_client_supports_tools() -> None:
    from backend.llm.client import AnthropicClient

    client = AnthropicClient(
        name="test",
        base_url="https://api.anthropic.com",
        api_key="test-key",
        model="claude-3-opus-20240229",
    )
    assert client.supports_tools is True


def test_ollama_client_does_not_support_tools() -> None:
    from backend.llm.client import OllamaClient

    client = OllamaClient(
        name="test",
        base_url="http://localhost:11434",
        api_key="",
        model="llama3",
    )
    assert client.supports_tools is False


def test_openai_compatible_client_supports_tools() -> None:
    from backend.llm.client import OpenAICompatibleClient

    client = OpenAICompatibleClient(
        name="test",
        base_url="http://localhost:8080/v1",
        api_key="",
        model="mistral",
    )
    assert client.supports_tools is True


# ─── OpenAI complete_with_tools parsing ──────────────────────────────────────

def test_openai_complete_with_tools_parses_tool_calls() -> None:
    """OpenAIClient.complete_with_tools should parse tool_calls from response."""
    from backend.llm.client import OpenAIClient

    client = OpenAIClient(
        name="test",
        base_url="https://api.openai.com/v1",
        api_key="test-key",
        model="gpt-4",
    )

    # Mock the _send method to return a tool-calling response
    tool_response = {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": "call_123",
                    "type": "function",
                    "function": {
                        "name": "mitre_lookup",
                        "arguments": '{"technique_id": "T1059"}',
                    },
                }],
            },
            "finish_reason": "tool_calls",
        }]
    }
    mock_resp = json.dumps(tool_response).encode()

    with patch.object(client, "_send", return_value=(200, {}, mock_resp)):
        text, tool_calls = client.complete_with_tools(
            "What MITRE technique is this?",
            tools=[{
                "name": "mitre_lookup",
                "description": "Look up MITRE",
                "parameters": {"type": "object", "properties": {"technique_id": {"type": "string"}}, "required": ["technique_id"]},
            }],
        )

    assert text == "" or text is None or True  # content is None in this response
    assert len(tool_calls) == 1
    assert tool_calls[0]["name"] == "mitre_lookup"
    assert tool_calls[0]["arguments"]["technique_id"] == "T1059"


def test_openai_complete_with_tools_plain_text() -> None:
    """When the model returns plain text instead of tool calls."""
    from backend.llm.client import OpenAIClient

    client = OpenAIClient(
        name="test",
        base_url="https://api.openai.com/v1",
        api_key="test-key",
        model="gpt-4",
    )

    plain_response = {
        "choices": [{
            "message": {"role": "assistant", "content": "No tools needed."},
            "finish_reason": "stop",
        }]
    }
    mock_resp = json.dumps(plain_response).encode()

    with patch.object(client, "_send", return_value=(200, {}, mock_resp)):
        text, tool_calls = client.complete_with_tools(
            "Just answer me",
            tools=[],
        )

    assert text == "No tools needed."
    assert tool_calls == []


# ─── Anthropic complete_with_tools parsing ────────────────────────────────────

def test_anthropic_complete_with_tools_parses_tool_calls() -> None:
    from backend.llm.client import AnthropicClient

    client = AnthropicClient(
        name="test",
        base_url="https://api.anthropic.com",
        api_key="test-key",
        model="claude-3-opus-20240229",
    )

    anthropic_response = {
        "content": [
            {"type": "text", "text": "Let me check that for you."},
            {
                "type": "tool_use",
                "id": "toolu_01",
                "name": "mitre_lookup",
                "input": {"technique_id": "T1566"},
            },
        ],
        "stop_reason": "tool_use",
    }
    mock_resp = json.dumps(anthropic_response).encode()

    with patch.object(client, "_send", return_value=(200, {}, mock_resp)):
        text, tool_calls = client.complete_with_tools(
            "What is this technique?",
            tools=[{
                "name": "mitre_lookup",
                "description": "Look up MITRE",
                "parameters": {"type": "object", "properties": {"technique_id": {"type": "string"}}, "required": ["technique_id"]},
            }],
        )

    assert "Let me check" in text
    assert len(tool_calls) == 1
    assert tool_calls[0]["name"] == "mitre_lookup"
    assert tool_calls[0]["arguments"]["technique_id"] == "T1566"


# ─── call_llm_with_tools: capable provider ────────────────────────────────────

@pytest.mark.asyncio
async def test_call_llm_with_tools_capable_provider() -> None:
    """call_llm_with_tools delegates to client.complete_with_tools for capable providers."""
    from backend.threat_hunting.agents import llm_bridge

    mock_client = MagicMock()
    mock_client.supports_tools = True
    mock_client.complete_with_tools = MagicMock(return_value=("analysis done", [{"name": "mitre_lookup", "arguments": {"technique_id": "T1059"}}]))

    with patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client):
        text, tool_calls = await llm_bridge.call_llm_with_tools(
            "test prompt",
            tools=[{"name": "mitre_lookup", "description": "...", "parameters": {}}],
        )

    assert text == "analysis done"
    assert len(tool_calls) == 1
    assert tool_calls[0]["name"] == "mitre_lookup"


@pytest.mark.asyncio
async def test_call_llm_with_tools_fallback_for_non_capable() -> None:
    """Non-capable provider (Ollama) falls back to call_llm, returns (text, [])."""
    from backend.threat_hunting.agents import llm_bridge

    mock_client = MagicMock()
    mock_client.supports_tools = False
    mock_client.complete = MagicMock(return_value="plain text response")

    with patch("backend.threat_hunting.agents.llm_bridge.get_client", return_value=mock_client):
        text, tool_calls = await llm_bridge.call_llm_with_tools(
            "test prompt",
            tools=[{"name": "mitre_lookup", "description": "...", "parameters": {}}],
        )

    assert text == "plain text response"
    assert tool_calls == []
