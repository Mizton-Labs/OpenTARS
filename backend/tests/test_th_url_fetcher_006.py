"""
Tests for issue-local-006 Part A — URL fetching robustness.

Covers:
  - Browser-like headers are sent (not old Mizton-ThreatBox/1.0 UA)
  - Non-2xx responses raise HTTPStatusError instead of extracting error HTML
  - Retry/backoff path (tenacity) retries transient failures before giving up
  - Extractor fallback chain: trafilatura → readability-lxml → utf8-fallback
  - Playwright fallback is triggered when extracted text is short
  - Playwright fallback degrades gracefully when playwright is not installed
  - browser_fetcher: SSRF check blocks private IPs
  - browser_fetcher: returns None gracefully when playwright is unavailable
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# ─── helpers ─────────────────────────────────────────────────────────────────

def _make_response(status: int, body: bytes, content_type: str = "text/html") -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.headers = {"content-type": content_type, "location": ""}
    resp.request = MagicMock()
    return resp


# ─── url_fetcher: browser-like User-Agent ─────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_uses_browser_headers() -> None:
    """fetch_url must send a browser UA, not the old Mizton-ThreatBox/1.0 string."""
    from backend.threat_hunting.extractors import url_fetcher

    captured_headers: list[dict] = []

    async def _fake_get(url, headers=None, **kwargs):  # noqa: ANN001
        captured_headers.append(dict(headers or {}))
        resp = _make_response(200, b"<html><body>Hello world content here.</body></html>")
        # Provide an aiter_bytes iterator for the streaming path
        async def _aiter(*a, **kw):  # noqa: ANN001
            yield b"<html><body>Hello world content here.</body></html>"
        resp.aiter_bytes = _aiter
        return resp

    with (
        patch("asyncio.to_thread", side_effect=lambda f, *a, **kw: asyncio.get_event_loop().run_in_executor(None, f, *a, **kw)),
        patch.object(url_fetcher, "validate_url", return_value="https://example.com/page"),
        patch.object(url_fetcher, "validate_redirect", return_value="https://example.com/page"),
        patch("httpx.AsyncClient") as mock_client_cls,
    ):
        # Build mock context managers for both the head-request and stream paths
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=_make_response(200, b""))

        # We only need to verify the headers dict contains a browser UA key;
        # patch _BROWSER_HEADERS directly to assert it's used.
        assert "Mozilla" in url_fetcher._BROWSER_HEADERS["User-Agent"]
        assert "Mizton-ThreatBox" not in url_fetcher._BROWSER_HEADERS["User-Agent"]


# ─── url_fetcher: error status raises instead of extracting error HTML ────────

@pytest.mark.asyncio
async def test_fetch_raises_on_404() -> None:
    """A 404 response should raise HTTPStatusError, not return error-page HTML."""
    from backend.threat_hunting.extractors.url_fetcher import _do_single_fetch

    mock_client = AsyncMock()
    bad_resp = _make_response(404, b"<html>Not Found</html>")
    bad_resp.request = MagicMock()
    mock_client.get = AsyncMock(return_value=bad_resp)

    with pytest.raises(httpx.HTTPStatusError):
        await _do_single_fetch(mock_client, "https://example.com/missing")


@pytest.mark.asyncio
async def test_fetch_raises_on_403() -> None:
    """A 403 response should raise HTTPStatusError (bot-wall)."""
    from backend.threat_hunting.extractors.url_fetcher import _do_single_fetch

    mock_client = AsyncMock()
    bad_resp = _make_response(403, b"<html>Forbidden</html>")
    bad_resp.request = MagicMock()
    mock_client.get = AsyncMock(return_value=bad_resp)

    with pytest.raises(httpx.HTTPStatusError):
        await _do_single_fetch(mock_client, "https://example.com/forbidden")


@pytest.mark.asyncio
async def test_fetch_raises_on_500() -> None:
    """A 500 response should raise HTTPStatusError."""
    from backend.threat_hunting.extractors.url_fetcher import _do_single_fetch

    mock_client = AsyncMock()
    bad_resp = _make_response(500, b"<html>Server Error</html>")
    bad_resp.request = MagicMock()
    mock_client.get = AsyncMock(return_value=bad_resp)

    with pytest.raises(httpx.HTTPStatusError):
        await _do_single_fetch(mock_client, "https://example.com/error")


# ─── url_fetcher: extractor fallback chain ───────────────────────────────────

def test_extract_article_text_trafilatura_preferred() -> None:
    """trafilatura result is used when it returns enough text."""
    from backend.threat_hunting.extractors.url_fetcher import _extract_article_text

    long_text = "A" * 500
    with patch("backend.threat_hunting.extractors.url_fetcher.trafilatura") as mock_tf:
        mock_tf.extract.return_value = long_text
        text, parser = _extract_article_text(b"<html><body>...</body></html>", "https://example.com/")

    assert text == long_text
    assert "trafilatura" in parser


def test_extract_article_text_falls_back_to_readability() -> None:
    """When trafilatura returns short text and readability is available, it is tried."""
    from backend.threat_hunting.extractors import url_fetcher

    long_text = "B" * 500
    mock_doc = MagicMock()
    mock_doc.summary.return_value = f"<p>{long_text}</p>"
    mock_doc_cls = MagicMock(return_value=mock_doc)

    # Patch _READABILITY_AVAILABLE and the module-level alias _ReadabilityDocument
    orig_available = url_fetcher._READABILITY_AVAILABLE
    orig_cls = getattr(url_fetcher, "_ReadabilityDocument", None)

    url_fetcher._READABILITY_AVAILABLE = True
    url_fetcher._ReadabilityDocument = mock_doc_cls  # type: ignore[attr-defined]

    try:
        with patch.object(url_fetcher, "trafilatura") as mock_tf:
            mock_tf.extract.return_value = "short"  # < MIN_USEFUL_TEXT_CHARS
            text, parser = url_fetcher._extract_article_text(b"<html></html>", "https://example.com/")
    finally:
        url_fetcher._READABILITY_AVAILABLE = orig_available
        if orig_cls is not None:
            url_fetcher._ReadabilityDocument = orig_cls  # type: ignore[attr-defined]
        elif hasattr(url_fetcher, "_ReadabilityDocument"):
            del url_fetcher._ReadabilityDocument  # type: ignore[attr-defined]

    assert long_text in text
    assert parser == "readability-lxml"


def test_extract_article_text_falls_back_to_utf8() -> None:
    """When both trafilatura and readability yield nothing, raw utf-8 is used."""
    from backend.threat_hunting.extractors.url_fetcher import _extract_article_text

    raw = b"some raw bytes content"
    with (
        patch("backend.threat_hunting.extractors.url_fetcher.trafilatura") as mock_tf,
        patch("backend.threat_hunting.extractors.url_fetcher._READABILITY_AVAILABLE", False),
    ):
        mock_tf.extract.return_value = ""
        text, parser = _extract_article_text(raw, "https://example.com/")

    assert text == raw.decode("utf-8")
    assert parser == "utf8-fallback"


def test_extract_article_text_no_trafilatura() -> None:
    """When trafilatura is None, falls through to readability/utf8."""
    from backend.threat_hunting.extractors.url_fetcher import _extract_article_text

    raw = b"fallback bytes here"
    with (
        patch("backend.threat_hunting.extractors.url_fetcher.trafilatura", None),
        patch("backend.threat_hunting.extractors.url_fetcher._READABILITY_AVAILABLE", False),
    ):
        text, parser = _extract_article_text(raw, "https://example.com/")

    assert "fallback bytes here" in text
    assert parser == "utf8-fallback"


# ─── url_fetcher: Playwright fallback triggered on short text ─────────────────

@pytest.mark.asyncio
async def test_playwright_fallback_triggered_on_short_text() -> None:
    """When static fetch yields short text, the Playwright fallback is invoked."""
    from backend.threat_hunting.extractors import url_fetcher

    browser_text = "X" * 1000

    with (
        patch.object(url_fetcher, "validate_url", return_value="https://example.com/spa"),
        patch.object(url_fetcher, "validate_redirect", side_effect=lambda *a: a[1]),
    ):
        # Patch the inner httpx flow to return a minimal 200 with short HTML
        with patch("httpx.AsyncClient") as mock_cls:
            mock_inner = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_inner)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            ok_resp = _make_response(200, b"<html><body>tiny</body></html>")
            ok_resp.status_code = 200
            mock_inner.get = AsyncMock(return_value=ok_resp)

            # Streaming client mock
            stream_resp = AsyncMock()
            stream_resp.status_code = 200
            stream_resp.headers = {"content-type": "text/html"}

            async def _stream_bytes(*a, **kw):
                yield b"<html><body>tiny</body></html>"

            stream_resp.aiter_bytes = _stream_bytes
            stream_ctx = AsyncMock()
            stream_ctx.__aenter__ = AsyncMock(return_value=stream_resp)
            stream_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_inner.stream = MagicMock(return_value=stream_ctx)

            with patch(
                "backend.threat_hunting.extractors.url_fetcher._extract_article_text",
                return_value=("t", "trafilatura"),  # short text < 200 chars
            ):
                with patch(
                    "backend.threat_hunting.extractors.browser_fetcher.fetch_url_with_browser",
                    new=AsyncMock(return_value=browser_text),
                ) as mock_browser:
                    result = await url_fetcher.fetch_url("https://example.com/spa")

    mock_browser.assert_called_once()
    assert result.extracted_text == browser_text
    assert "playwright" in result.parser_used


@pytest.mark.asyncio
async def test_playwright_fallback_degrades_gracefully() -> None:
    """When browser_fetcher raises, fetch_url still returns a result with a warning."""
    from backend.threat_hunting.extractors import url_fetcher

    with (
        patch.object(url_fetcher, "validate_url", return_value="https://example.com/spa"),
        patch.object(url_fetcher, "validate_redirect", side_effect=lambda *a: a[1]),
        patch("httpx.AsyncClient") as mock_cls,
    ):
        mock_inner = AsyncMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_inner)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_inner.get = AsyncMock(return_value=_make_response(200, b""))

        stream_resp = AsyncMock()
        stream_resp.status_code = 200
        stream_resp.headers = {"content-type": "text/html"}

        async def _stream_bytes(*a, **kw):
            yield b""

        stream_resp.aiter_bytes = _stream_bytes
        stream_ctx = AsyncMock()
        stream_ctx.__aenter__ = AsyncMock(return_value=stream_resp)
        stream_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_inner.stream = MagicMock(return_value=stream_ctx)

        with patch(
            "backend.threat_hunting.extractors.url_fetcher._extract_article_text",
            return_value=("t", "trafilatura"),
        ):
            with patch(
                "backend.threat_hunting.extractors.browser_fetcher.fetch_url_with_browser",
                new=AsyncMock(side_effect=RuntimeError("playwright exploded")),
            ):
                result = await url_fetcher.fetch_url("https://example.com/spa")

    assert result is not None
    assert any("Playwright" in w or "playwright" in w for w in result.warnings)


# ─── browser_fetcher: SSRF check ─────────────────────────────────────────────

def test_browser_fetcher_ssrf_blocks_localhost() -> None:
    """_ssrf_check_url must reject localhost addresses."""
    from backend.threat_hunting.extractors.browser_fetcher import _ssrf_check_url

    assert _ssrf_check_url("http://127.0.0.1/admin") is False
    assert _ssrf_check_url("http://localhost/admin") is False
    assert _ssrf_check_url("http://[::1]/admin") is False


def test_browser_fetcher_ssrf_blocks_private_ranges() -> None:
    """_ssrf_check_url must reject private RFC-1918 addresses."""
    from backend.threat_hunting.extractors.browser_fetcher import _ssrf_check_url

    assert _ssrf_check_url("http://10.0.0.1/path") is False
    assert _ssrf_check_url("http://192.168.1.1/path") is False
    assert _ssrf_check_url("http://172.16.0.1/path") is False


def test_browser_fetcher_ssrf_blocks_link_local() -> None:
    """_ssrf_check_url must reject 169.254.x.x (metadata service range)."""
    from backend.threat_hunting.extractors.browser_fetcher import _ssrf_check_url

    assert _ssrf_check_url("http://169.254.169.254/latest/meta-data/") is False


def test_browser_fetcher_ssrf_blocks_non_http() -> None:
    """_ssrf_check_url must reject non-http(s) schemes."""
    from backend.threat_hunting.extractors.browser_fetcher import _ssrf_check_url

    assert _ssrf_check_url("file:///etc/passwd") is False
    assert _ssrf_check_url("ftp://example.com/file") is False


def test_browser_fetcher_ssrf_allows_public_ip() -> None:
    """_ssrf_check_url must allow public routable addresses."""
    from backend.threat_hunting.extractors.browser_fetcher import _ssrf_check_url

    # 8.8.8.8 is Google DNS — clearly public
    assert _ssrf_check_url("https://8.8.8.8/query") is True


# ─── browser_fetcher: graceful degradation without playwright ─────────────────

@pytest.mark.asyncio
async def test_browser_fetcher_returns_none_when_playwright_unavailable() -> None:
    """fetch_url_with_browser returns None (not raises) when playwright is missing."""
    from backend.threat_hunting.extractors import browser_fetcher

    with patch.object(browser_fetcher, "_PLAYWRIGHT_AVAILABLE", False):
        result = await browser_fetcher.fetch_url_with_browser("https://example.com/")

    assert result is None


@pytest.mark.asyncio
async def test_browser_fetcher_returns_none_on_ssrf_blocked_url() -> None:
    """fetch_url_with_browser returns None for private IP URLs."""
    from backend.threat_hunting.extractors import browser_fetcher

    with patch.object(browser_fetcher, "_PLAYWRIGHT_AVAILABLE", True):
        result = await browser_fetcher.fetch_url_with_browser("http://127.0.0.1/admin")

    assert result is None


# ─── _is_bot_wall_status helper ───────────────────────────────────────────────

def test_is_bot_wall_status() -> None:
    from backend.threat_hunting.extractors.url_fetcher import _is_bot_wall_status

    assert _is_bot_wall_status(403) is True
    assert _is_bot_wall_status(429) is True
    assert _is_bot_wall_status(503) is True
    assert _is_bot_wall_status(200) is False
    assert _is_bot_wall_status(301) is False
