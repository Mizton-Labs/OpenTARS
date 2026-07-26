"""
LangChain bridge for the existing OpenTARS LLM registry.

Wraps the existing ``backend.llm.registry.get_client()`` / ``LLMClient``
interface as a callable that the LangGraph agent nodes can use without
pulling in the full LangChain chat-model hierarchy.

Design rationale
----------------
The existing LLMClient already handles:
  - OpenAI, Anthropic, Ollama, OpenAI-compatible providers
  - API-key security (write-only, never logged)
  - Retry / backoff / timeout
  - Structured logging
  - Reasoning-model output recovery (prompts-035/037)

We do NOT want to re-implement all of that via LangChain's own chat model
classes (which would need duplicate credentials and bypass our security
wrappers).  Instead, we expose a thin async ``call_llm()`` helper that:
  1. Resolves the provider through the existing registry.
  2. Runs the synchronous ``complete()`` call in a thread pool
     (``asyncio.to_thread``) so it is safe to ``await`` inside LangGraph
     async nodes.
  3. Returns the raw string response that nodes then parse.

LangChain types (``HumanMessage``, ``SystemMessage``) are used only for
prompt building helpers; the actual HTTP transport uses our own client.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from backend.llm.errors import LLMEmptyContentError, LLMProviderError, LLMTransportError

logger = logging.getLogger(__name__)

# Registry import at module level so tests can patch it via
# 'backend.threat_hunting.agents.llm_bridge.get_client'.
# Uses a lazy wrapper to avoid import cycles at module load time.
try:
    from backend.llm.registry import get_client  # noqa: F401 (imported for test patching)
except ImportError:  # pragma: no cover
    get_client = None  # type: ignore[assignment]

# issue-local-014: a single LLM call, retried with backoff on transient
# failures before the caller (a pipeline node) records a permanent error.
# Covers three distinct failure shapes seen in production runs:
#   - LLMTransportError            — network/timeout, always worth retrying.
#   - LLMProviderError (status>=500 or unknown) — upstream hiccup, retry.
#   - LLMProviderError (status<500)             — permanent (bad request),
#     never retried — retrying an HTTP 400 wastes attempts and quota.
#   - LLMEmptyContentError          — HTTP 200 but the output-token budget
#     was exhausted (finish_reason=length); the *same* max_tokens tends to
#     fail again, so each retry raises the ceiling instead of repeating
#     verbatim. This is why a plain "retry the same call" decorator isn't
#     enough here and the loop is hand-rolled rather than using tenacity.
_EMPTY_CONTENT_TOKEN_MULTIPLIER = 2.0
_EMPTY_CONTENT_MAX_TOKENS_CEILING = 16384


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, LLMEmptyContentError):
        return True
    if isinstance(exc, LLMProviderError):
        # LLMEmptyContentError subclasses LLMProviderError — already handled
        # above. A plain LLMProviderError with a 4xx status is permanent.
        return exc.status is None or exc.status >= 500
    if isinstance(exc, LLMTransportError):
        return True
    return False


async def _call_with_retry(attempt_fn, *, max_tokens: int, retry_label: str):
    """Call ``await attempt_fn(max_tokens)`` with retry/backoff on transient errors.

    Shared by ``call_llm`` and ``call_llm_with_tools`` — ``attempt_fn`` wraps
    whichever ``LLMClient`` method the caller needs (already bound to the
    fixed args; only ``max_tokens`` varies across attempts).
    """
    from backend.config.loader import (
        load_th_llm_max_retries,
        load_th_llm_retry_backoff_seconds,
    )

    max_retries = load_th_llm_max_retries()
    backoff_base = load_th_llm_retry_backoff_seconds()
    current_max_tokens = max_tokens

    attempt = 0
    while True:
        try:
            return await attempt_fn(current_max_tokens)
        except (LLMEmptyContentError, LLMProviderError, LLMTransportError) as exc:
            if not _is_retryable(exc) or attempt >= max_retries:
                raise
            if isinstance(exc, LLMEmptyContentError):
                current_max_tokens = min(
                    int(current_max_tokens * _EMPTY_CONTENT_TOKEN_MULTIPLIER),
                    _EMPTY_CONTENT_MAX_TOKENS_CEILING,
                )
            attempt += 1
            delay = backoff_base * (2 ** (attempt - 1))
            logger.warning(
                "%s: retrying after %s (attempt %d/%d, backoff %.1fs%s)",
                retry_label,
                exc,
                attempt,
                max_retries,
                delay,
                f", max_tokens→{current_max_tokens}"
                if isinstance(exc, LLMEmptyContentError)
                else "",
            )
            await asyncio.sleep(delay)


# LangChain message helpers (used for prompt assembly only)
try:
    from langchain_core.messages import HumanMessage, SystemMessage

    _LANGCHAIN_AVAILABLE = True
except ImportError:  # pragma: no cover
    _LANGCHAIN_AVAILABLE = False
    HumanMessage = None  # type: ignore[assignment,misc]
    SystemMessage = None  # type: ignore[assignment,misc]


async def call_llm_with_tools(
    prompt: str,
    tools: list[dict],
    *,
    system: str | None = None,
    provider_name: str | None = None,
    model: str | None = None,
    max_tokens: int = 2048,
    temperature: float = 0.0,
    timeout: float | None = 120.0,
) -> tuple[str, list[dict]]:
    """Call the configured LLM with tool definitions.

    Returns (text_response, tool_calls_list) where ``tool_calls`` is a list of
    ``{name: str, arguments: dict}`` dicts.

    When the provider does not support tool-calling (e.g. Ollama), falls back
    to ``call_llm()`` and returns (text, []).

    Args:
        tools: List of tool spec dicts in OpenAI function-calling format
               (name, description, parameters fields).
    """
    # Use the module-level get_client (patched in tests via
    # 'backend.threat_hunting.agents.llm_bridge.get_client').
    client = get_client(provider_name)

    if not client.supports_tools:
        # Fallback: prompt-only path — no tools available
        async def _attempt(mt: int) -> str:
            return await asyncio.to_thread(
                client.complete,
                prompt,
                system=system,
                max_tokens=mt,
                temperature=temperature,
                timeout=timeout,
                model=model,
            )

        text = await _call_with_retry(
            _attempt, max_tokens=max_tokens, retry_label="call_llm_with_tools(no-tools fallback)"
        )
        return text, []

    async def _attempt_with_tools(mt: int) -> tuple[str, list[dict]]:
        return await asyncio.to_thread(
            client.complete_with_tools,
            prompt,
            tools,
            system=system,
            max_tokens=mt,
            temperature=temperature,
            timeout=timeout,
            model=model,
        )

    text, tool_calls = await _call_with_retry(
        _attempt_with_tools, max_tokens=max_tokens, retry_label="call_llm_with_tools"
    )
    return text, tool_calls


async def call_llm(
    prompt: str,
    *,
    system: str | None = None,
    provider_name: str | None = None,
    model: str | None = None,
    max_tokens: int = 2048,
    temperature: float = 0.0,
    timeout: float | None = 120.0,
) -> str:
    """Call the configured LLM and return the text response.

    All parameters are optional — when omitted, the default provider and
    model from ``config/llm-providers.yaml`` are used.

    Raises:
        LLMDisabledError  — when LLM is disabled in config.
        LLMConfigError    — when provider is misconfigured.
        LLMProviderError  — on upstream HTTP errors.
        LLMTransportError — on network failures.
    """
    client = get_client(provider_name)

    async def _attempt(mt: int) -> str:
        return await asyncio.to_thread(
            client.complete,
            prompt,
            system=system,
            max_tokens=mt,
            temperature=temperature,
            timeout=timeout,
            model=model,
        )

    return await _call_with_retry(_attempt, max_tokens=max_tokens, retry_label="call_llm")


def build_prompt(
    *,
    task_description: str,
    context_sections: list[tuple[str, str]],
    output_format: str,
    additional_instructions: str = "",
    json_output: bool = True,
    system: str | None = None,
) -> tuple[str, str]:
    """Build a (system_prompt, user_prompt) pair for a hunting agent node.

    Args:
        task_description: One-sentence description of what this agent does.
        context_sections: List of (section_title, content) tuples.
        output_format: Description of the expected output structure.
        additional_instructions: Optional extra constraints for the LLM.
        json_output: When True (default) the system prompt instructs the model
            to return valid JSON only.  Set to False for prose outputs such as
            executive summaries and findings sections where JSON framing causes
            the LLM to wrap its answer in a JSON object.
        system: Optional override for the system prompt / agent persona.
            When omitted (the default for every existing node), falls back to
            the generic Threat Intelligence analyst persona below. Pass a
            node-specific persona (issue-local-014) when a step needs a
            narrower, more reliable "skill" than the generic one — e.g. an
            IOC triage specialist rather than a general analyst.

    Returns:
        (system_prompt, user_prompt) strings.
    """
    if system is not None:
        pass
    elif json_output:
        system = (
            "You are an expert Threat Intelligence and Threat Hunting analyst. "
            "You produce structured, actionable analysis in JSON format. "
            "Be precise, specific, and base all conclusions on the provided evidence. "
            "Do not fabricate indicators, campaigns, or techniques not present in the evidence. "
            "Always output valid JSON as instructed — no prose before or after the JSON block."
        )
    else:
        system = (
            "You are an expert Threat Intelligence and Threat Hunting analyst. "
            "You produce clear, precise, factual prose. "
            "Be specific and base all conclusions on the provided evidence. "
            "Do not fabricate indicators, campaigns, or techniques not present in the evidence."
        )

    context_parts: list[str] = []
    for title, content in context_sections:
        if content and content.strip():
            context_parts.append(f"## {title}\n\n{content.strip()}")

    user = f"Task: {task_description}\n\n"
    if context_parts:
        user += "\n\n".join(context_parts) + "\n\n"
    if additional_instructions:
        user += f"Additional instructions: {additional_instructions}\n\n"
    if json_output:
        user += f"Output format (return ONLY the JSON, no markdown fences):\n{output_format}"
    else:
        user += f"Output format:\n{output_format}"

    return system, user


def parse_json_response(response: str, context: str = "") -> Any:
    """Parse a JSON response from an LLM, tolerating common formatting issues.

    Tries:
      1. Direct json.loads
      2. Extract first {...} block (after stripping markdown fences)
      3. Strip trailing commas, control chars, ast.literal_eval
    """
    import ast
    import json
    import re

    text = response.strip()

    # Strip markdown fences
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```\s*$", "", text, flags=re.MULTILINE)
    text = text.strip()

    # 1. Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Find first top-level { ... } or [ ... ]
    m = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
    if m:
        candidate = m.group(1)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
        # 3. Trailing comma strip
        cleaned = re.sub(r",\s*([}\]])", r"\1", candidate)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
        try:
            return ast.literal_eval(cleaned)
        except Exception:
            pass

    logger.warning(
        "LLM JSON parse failed%s — returning raw string",
        f" ({context})" if context else "",
    )
    return response  # Return raw string as fallback; nodes handle gracefully


def coerce_string_list(value: Any, *, preferred_keys: tuple[str, ...] = ()) -> list[str]:
    """Coerce a parsed LLM field to ``list[str]``, defensively.

    Several node output schemas ask for a plain array of strings (e.g.
    ``key_observations``, ``suggested_actions``, ``detection_opportunities``)
    but models occasionally return a richer per-item object instead —
    observed live with Mistral returning ``{"observation": ..., "confidence":
    ..., "evidence": ...}`` entries for ``key_observations`` where a bare
    string was asked for. Rendering such an object directly as a React child
    crashes the whole page (minified error #31), and it can't be fixed
    retroactively for already-persisted runs from the frontend alone since
    the stored data itself has the wrong shape — so nodes call this right
    after parsing to normalize at the source.
    """
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            text = None
            for key in preferred_keys:
                candidate = item.get(key)
                if isinstance(candidate, str) and candidate:
                    text = candidate
                    break
            if text is None:
                import json

                text = json.dumps(item, default=str)
            result.append(text)
        elif item is not None:
            result.append(str(item))
    return result
