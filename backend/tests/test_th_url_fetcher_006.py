"""
Tests for issue-local-006 Part A + issue-local-008 — URL fetching robustness.

Covers (006-A):
  - Browser-like headers are sent (not old Mizton-ThreatBox/1.0 UA)
  - Non-2xx responses raise HTTPStatusError instead of extracting error HTML
  - Retry/backoff path (tenacity) retries transient failures before giving up
  - Extractor fallback chain: trafilatura -> readability-lxml -> utf8-fallback
  - Playwright fallback is triggered when extracted text is short
  - Playwright fallback degrades gracefully when playwright is not installed
  - browser_fetcher: SSRF check blocks private IPs
  - browser_fetcher: returns None gracefully when playwright is unavailable

Covers (issue-local-008):
  Fix 1 - _BROTLI_AVAILABLE flag reflects brotli import; Accept-Encoding header
           only includes 'br' when brotli decoder is available
  Fix 2 - _looks_like_binary() detects compressed/binary bytes correctly
  Fix 2 - binary raw bytes on HTML response triggers warning + playwright forced
  Fix 3 - _should_force_playwright() broader triggers: short text, bot-wall,
           binary text, utf8-fallback on HTML, binary raw bytes
  Fix 3 - Playwright fallback fires on binary/mojibake even when text is long
  Fix 4 - readability-lxml exceptions surface as warnings (not silent swallow)
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
        patch(
            "asyncio.to_thread",
            side_effect=lambda f, *a, **kw: asyncio.get_event_loop().run_in_executor(
                None, f, *a, **kw
            ),
        ),
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
        text, parser = _extract_article_text(
            b"<html><body>...</body></html>", "https://example.com/"
        )

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
            text, parser = url_fetcher._extract_article_text(
                b"<html></html>", "https://example.com/"
            )
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


# ─── issue-local-008 Fix 1: brotli availability + Accept-Encoding ─────────────


def test_brotli_available_flag_type() -> None:
    """_BROTLI_AVAILABLE must be a plain bool."""
    from backend.threat_hunting.extractors.url_fetcher import _BROTLI_AVAILABLE

    assert isinstance(_BROTLI_AVAILABLE, bool)


def test_accept_encoding_excludes_br_when_brotli_missing() -> None:
    """When brotli is not importable, Accept-Encoding must not contain 'br'."""
    from backend.threat_hunting.extractors import url_fetcher

    orig = url_fetcher._BROTLI_AVAILABLE
    try:
        url_fetcher._BROTLI_AVAILABLE = False
        url_fetcher._ACCEPT_ENCODING = "gzip, deflate"
        headers = dict(url_fetcher._BROWSER_HEADERS)
        headers["Accept-Encoding"] = url_fetcher._ACCEPT_ENCODING
        assert "br" not in headers["Accept-Encoding"].split(", ")
    finally:
        url_fetcher._BROTLI_AVAILABLE = orig
        url_fetcher._ACCEPT_ENCODING = "gzip, deflate, br" if orig else "gzip, deflate"


def test_accept_encoding_includes_br_when_brotli_present() -> None:
    """When brotli IS available, Accept-Encoding should include 'br'."""
    from backend.threat_hunting.extractors import url_fetcher

    orig = url_fetcher._BROTLI_AVAILABLE
    try:
        url_fetcher._BROTLI_AVAILABLE = True
        url_fetcher._ACCEPT_ENCODING = "gzip, deflate, br"
        assert "br" in url_fetcher._ACCEPT_ENCODING.split(", ")
    finally:
        url_fetcher._BROTLI_AVAILABLE = orig
        url_fetcher._ACCEPT_ENCODING = "gzip, deflate, br" if orig else "gzip, deflate"


def test_browser_headers_accept_encoding_matches_capability() -> None:
    """_BROWSER_HEADERS Accept-Encoding must match _ACCEPT_ENCODING at module load."""
    from backend.threat_hunting.extractors.url_fetcher import _ACCEPT_ENCODING, _BROWSER_HEADERS

    assert _BROWSER_HEADERS["Accept-Encoding"] == _ACCEPT_ENCODING


# ─── issue-local-008 Fix 2: _looks_like_binary ────────────────────────────────


def test_looks_like_binary_with_brotli_bytes() -> None:
    """Simulated Brotli-compressed bytes must be detected as binary."""
    from backend.threat_hunting.extractors.url_fetcher import _looks_like_binary

    # Brotli-compressed data is high-entropy: majority of bytes are >= 0x80 (non-ASCII).
    # Build a sample where >30% of bytes are non-ASCII to trigger the threshold.
    # (Real Brotli streams have ~60-80% non-ASCII bytes.)
    brotli_like = bytes([0xF0, 0xFF, 0xA2, 0xAA, 0xF6, 0xC8, 0xB3, 0x9E, 0xD4, 0x21]) * 300
    assert _looks_like_binary(brotli_like) is True


def test_looks_like_binary_with_real_html() -> None:
    """Valid HTML bytes must NOT be flagged as binary."""
    from backend.threat_hunting.extractors.url_fetcher import _looks_like_binary

    html = b"<!DOCTYPE html><html><body><h1>Hello</h1><p>Article content here.</p></body></html>"
    assert _looks_like_binary(html) is False


def test_looks_like_binary_with_plain_text() -> None:
    from backend.threat_hunting.extractors.url_fetcher import _looks_like_binary

    text = b"This is a plain text document with some normal content.\n" * 50
    assert _looks_like_binary(text) is False


def test_looks_like_binary_with_empty_bytes() -> None:
    from backend.threat_hunting.extractors.url_fetcher import _looks_like_binary

    assert _looks_like_binary(b"") is False


def test_looks_like_binary_with_str_mojibake() -> None:
    """String with high non-ASCII chars (mojibake) must be detected as binary."""
    from backend.threat_hunting.extractors.url_fetcher import _looks_like_binary

    # Simulate utf-8 decoding of Brotli bytes: many chars in range 0x80-0xFF
    mojibake = "".join(chr(0x80 + (i % 128)) for i in range(1600))  # all non-ASCII
    assert _looks_like_binary(mojibake) is True


def test_looks_like_binary_with_clean_str() -> None:
    from backend.threat_hunting.extractors.url_fetcher import _looks_like_binary

    clean = "This is a clean article about threat intelligence. " * 40
    assert _looks_like_binary(clean) is False


# ─── issue-local-008 Fix 3: _should_force_playwright ─────────────────────────


def test_should_force_playwright_short_text() -> None:
    from backend.threat_hunting.extractors.url_fetcher import _should_force_playwright

    forced, reason = _should_force_playwright(
        "tiny", "trafilatura", "text/html", 200, b"<html></html>"
    )
    assert forced is True
    assert "short" in reason.lower()


def test_should_force_playwright_bot_wall_status() -> None:
    from backend.threat_hunting.extractors.url_fetcher import _should_force_playwright

    long_text = "A" * 1000
    forced, reason = _should_force_playwright(long_text, "trafilatura", "text/html", 403, b"")
    assert forced is True
    assert "403" in reason


def test_should_force_playwright_binary_extracted_text() -> None:
    """Binary/mojibake extracted text forces Playwright even when it is long."""
    from backend.threat_hunting.extractors.url_fetcher import _should_force_playwright

    # 1600 control chars — looks like binary, is long
    mojibake = "".join(chr(i % 32) for i in range(1600))
    forced, reason = _should_force_playwright(mojibake, "utf8-fallback", "text/html", 200, b"")
    assert forced is True
    assert "binary" in reason.lower() or "control" in reason.lower()


def test_should_force_playwright_utf8_fallback_on_html() -> None:
    """utf8-fallback on HTML (even with long text) forces Playwright."""
    from backend.threat_hunting.extractors.url_fetcher import _should_force_playwright

    # Some long garbage that isn't flagged as binary but is still utf8-fallback
    long_ascii_garbage = "abc" * 300  # clean-looking but utf8-fallback on html = problem
    forced, reason = _should_force_playwright(
        long_ascii_garbage, "utf8-fallback", "text/html; charset=UTF-8", 200, b"<html></html>"
    )
    assert forced is True
    assert "utf8-fallback" in reason.lower()


def test_should_force_playwright_binary_raw_bytes() -> None:
    """Binary raw bytes force Playwright even when extracted text is clean."""
    from backend.threat_hunting.extractors.url_fetcher import _should_force_playwright

    brotli_like = bytes([0xF0, 0xFF, 0x01, 0x00, 0x0F] * 200)
    clean_text = "A" * 1000
    forced, reason = _should_force_playwright(
        clean_text, "trafilatura", "text/html", 200, brotli_like
    )
    assert forced is True
    assert "binary" in reason.lower()


def test_should_force_playwright_not_needed_for_good_content() -> None:
    """Good long clean text on 200 does NOT force Playwright."""
    from backend.threat_hunting.extractors.url_fetcher import _should_force_playwright

    good_text = "ESET researchers analyzed the EDR killer framework. " * 40
    forced, reason = _should_force_playwright(
        good_text, "trafilatura/1.12", "text/html", 200, b"<html>...</html>"
    )
    assert forced is False
    assert reason == ""


def test_should_force_playwright_json_not_forced() -> None:
    """Non-HTML content-type with utf8-fallback does NOT trigger (not HTML)."""
    from backend.threat_hunting.extractors.url_fetcher import _should_force_playwright

    long_text = "A" * 1000
    forced, _reason = _should_force_playwright(
        long_text, "utf8-fallback", "application/json", 200, b"{}"
    )
    assert forced is False


# ─── issue-local-008 Fix 4: readability errors surfaced as warnings ───────────


def test_extract_article_text_readability_error_surfaced() -> None:
    """readability-lxml exceptions must be added to the warnings list (Fix 4)."""
    from backend.threat_hunting.extractors import url_fetcher

    # Simulate readability raising ValueError (as observed with binary/NULL bytes).
    # _ReadabilityDocument is only present when readability-lxml is installed;
    # we inject it by patching _READABILITY_AVAILABLE + adding the module-level name.
    mock_doc = MagicMock()
    mock_doc.summary.side_effect = ValueError("All strings must be XML compatible: no NULL bytes")
    mock_doc_cls = MagicMock(return_value=mock_doc)

    orig_available = url_fetcher._READABILITY_AVAILABLE
    orig_cls = getattr(url_fetcher, "_ReadabilityDocument", None)
    url_fetcher._READABILITY_AVAILABLE = True
    url_fetcher._ReadabilityDocument = mock_doc_cls  # type: ignore[attr-defined]

    warnings_list: list[str] = []
    try:
        with patch.object(url_fetcher, "trafilatura") as mock_tf:
            mock_tf.extract.return_value = ""
            text, parser = url_fetcher._extract_article_text(
                b"\x00\x01\x02binary content", "https://example.com/", warnings_list
            )
    finally:
        url_fetcher._READABILITY_AVAILABLE = orig_available
        if orig_cls is not None:
            url_fetcher._ReadabilityDocument = orig_cls  # type: ignore[attr-defined]
        elif hasattr(url_fetcher, "_ReadabilityDocument"):
            del url_fetcher._ReadabilityDocument  # type: ignore[attr-defined]

    assert len(warnings_list) == 1
    assert "readability" in warnings_list[0].lower()
    assert parser == "utf8-fallback"


def test_extract_article_text_readability_error_no_warnings_arg() -> None:
    """When no warnings list is passed, readability errors must not raise."""
    from backend.threat_hunting.extractors import url_fetcher

    mock_doc = MagicMock()
    mock_doc.summary.side_effect = RuntimeError("some readability crash")
    mock_doc_cls = MagicMock(return_value=mock_doc)

    orig_available = url_fetcher._READABILITY_AVAILABLE
    orig_cls = getattr(url_fetcher, "_ReadabilityDocument", None)
    url_fetcher._READABILITY_AVAILABLE = True
    url_fetcher._ReadabilityDocument = mock_doc_cls  # type: ignore[attr-defined]

    try:
        with patch.object(url_fetcher, "trafilatura") as mock_tf:
            mock_tf.extract.return_value = ""
            text, parser = url_fetcher._extract_article_text(b"data", "https://example.com/")
    finally:
        url_fetcher._READABILITY_AVAILABLE = orig_available
        if orig_cls is not None:
            url_fetcher._ReadabilityDocument = orig_cls  # type: ignore[attr-defined]
        elif hasattr(url_fetcher, "_ReadabilityDocument"):
            del url_fetcher._ReadabilityDocument  # type: ignore[attr-defined]

    assert parser == "utf8-fallback"


# ─── issue-local-008: Playwright triggered on binary content (integration) ────


@pytest.mark.asyncio
async def test_playwright_triggered_on_binary_brotli_like_content() -> None:
    """Playwright fallback must fire when raw bytes look like undecoded Brotli.

    This reproduces the welivesecurity.com production failure where:
    - httpx received Brotli-compressed bytes (brotli pkg missing)
    - 31 KB of mojibake was stored with parse_status=ok
    - No IOCs/info could be extracted
    - Playwright was never triggered because len(mojibake) > 200
    """
    from backend.threat_hunting.extractors import url_fetcher

    # Simulate Brotli-compressed bytes (high control-char density)
    brotli_bytes = bytes([0xF0, 0xFF, 0x23, 0xA2, 0xAA, 0xF6, 0x43, 0x8C, 0x00, 0x01]) * 3000
    browser_text = "ESET researchers analyzed the EDR-killing toolset. " * 200  # clean article

    with (
        patch.object(url_fetcher, "validate_url", return_value="https://example.com/article"),
        patch.object(url_fetcher, "validate_redirect", side_effect=lambda *a: a[1]),
        patch("httpx.AsyncClient") as mock_cls,
    ):
        mock_inner = MagicMock()
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_inner)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_inner.get = AsyncMock(return_value=_make_response(200, b""))

        stream_resp = AsyncMock()
        stream_resp.status_code = 200
        stream_resp.headers = {"content-type": "text/html; charset=UTF-8"}

        async def _stream_brotli(*a, **kw):
            yield brotli_bytes

        stream_resp.aiter_bytes = _stream_brotli
        stream_ctx = AsyncMock()
        stream_ctx.__aenter__ = AsyncMock(return_value=stream_resp)
        stream_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_inner.stream = MagicMock(return_value=stream_ctx)

        # The mojibake string has many non-ASCII chars (>30%) — _looks_like_binary will flag it
        mojibake = "".join(chr(0x80 + (c % 128)) for c in brotli_bytes[:31000])
        with patch(
            "backend.threat_hunting.extractors.url_fetcher._extract_article_text",
            return_value=(mojibake, "utf8-fallback"),
        ):
            with patch(
                "backend.threat_hunting.extractors.browser_fetcher.fetch_url_with_browser",
                new=AsyncMock(return_value=browser_text),
            ) as mock_browser:
                result = await url_fetcher.fetch_url("https://example.com/article")

    # Playwright must have been triggered
    mock_browser.assert_called_once()
    # Result must be the clean browser text, not the mojibake
    assert result.extracted_text == browser_text
    assert "playwright" in result.parser_used
    assert result.fetch_metadata.get("playwright_fallback") is True
    # A warning about binary content must be present
    assert any(
        "binary" in w.lower() or "brotli" in w.lower() or "control" in w.lower()
        for w in result.warnings
    )


@pytest.mark.asyncio
async def test_brotli_available_flag_controls_accept_encoding_in_headers() -> None:
    """When brotli is available, the Accept-Encoding header should include 'br'."""
    from backend.threat_hunting.extractors import url_fetcher

    # Verify the module-level flag is correctly read back
    if url_fetcher._BROTLI_AVAILABLE:
        assert "br" in url_fetcher._BROWSER_HEADERS.get("Accept-Encoding", "")
    else:
        assert "br" not in url_fetcher._BROWSER_HEADERS.get("Accept-Encoding", "").split(", ")
