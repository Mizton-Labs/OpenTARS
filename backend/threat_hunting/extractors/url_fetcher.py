"""URL fetching with SSRF policy enforcement and article text extraction.

Uses httpx for the HTTP transport with retry/backoff (tenacity) and a
multi-extractor fallback chain (trafilatura → readability-lxml → raw utf-8).
For JS-heavy pages that return little usable text, an optional Playwright
headless-Chromium path is used as a last resort.

All DNS resolution and redirect validation go through
backend.threat_hunting.ssrf before any network call is issued.

NOTE ON USER-AGENT SPOOFING:
  Using a browser-like User-Agent string in a server-side scraper may violate
  the Terms of Service of some websites. Operators are responsible for ensuring
  that their use of this feature complies with applicable ToS and local law.
  The UA string is used here solely to avoid bot-blocking that would prevent
  legitimate threat-intelligence research; it does not bypass any
  authentication or access controls.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from backend.threat_hunting.ssrf import validate_redirect, validate_url

logger = logging.getLogger(__name__)

# Default limits — operators may override via config in a later phase.
_DEFAULT_TIMEOUT_S = 30
_DEFAULT_MAX_BYTES = 20 * 1024 * 1024  # 20 MiB
_DEFAULT_MAX_REDIRECTS = 5

# Minimum extracted-text length to consider static fetch sufficient.
# If the static fetch yields fewer chars we attempt the Playwright fallback.
_MIN_USEFUL_TEXT_CHARS = 200

_ALLOWED_CONTENT_TYPE_PREFIXES = (
    "text/",
    "application/pdf",
    "application/json",
    "application/xml",
    "application/xhtml",
    "application/atom",
    "application/rss",
    "application/ld+json",
    "application/msword",
    "application/vnd.openxmlformats",
)

# HTTP status codes that should be treated as permanent failures rather than
# silently returning the error HTML as content.
_ERROR_STATUS_CODES = frozenset(range(400, 600)) - frozenset({429})  # 429 is handled by retry

# Realistic browser-like headers to reduce bot-blocking.
_BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

_TRAFILATURA_VERSION: str | None = None
try:
    import trafilatura  # type: ignore[import-untyped]

    _TRAFILATURA_VERSION = getattr(trafilatura, "__version__", "unknown")
except ImportError:  # pragma: no cover
    trafilatura = None  # type: ignore[assignment]

try:
    from readability import Document as _ReadabilityDocument  # type: ignore[import-untyped]

    _READABILITY_AVAILABLE = True
except ImportError:
    _READABILITY_AVAILABLE = False

try:
    from tenacity import (  # type: ignore[import-untyped]
        retry,
        retry_if_exception_type,
        stop_after_attempt,
        wait_exponential,
    )

    _TENACITY_AVAILABLE = True
except ImportError:
    _TENACITY_AVAILABLE = False


class FetchResult:
    """Result of a URL fetch operation."""

    def __init__(
        self,
        *,
        original_url: str,
        final_url: str,
        status_code: int,
        content_type: str,
        content_length: int,
        raw_bytes: bytes,
        extracted_text: str,
        parser_used: str,
        warnings: list[str],
        fetch_metadata: dict[str, Any],
    ) -> None:
        self.original_url = original_url
        self.final_url = final_url
        self.status_code = status_code
        self.content_type = content_type
        self.content_length = content_length
        self.raw_bytes = raw_bytes
        self.extracted_text = extracted_text
        self.parser_used = parser_used
        self.warnings = warnings
        self.fetch_metadata = fetch_metadata


def _check_content_type(content_type: str) -> bool:
    ct = content_type.lower().split(";")[0].strip()
    return any(ct.startswith(p) for p in _ALLOWED_CONTENT_TYPE_PREFIXES)


def _extract_article_text(raw_bytes: bytes, final_url: str) -> tuple[str, str]:
    """Extract article/page text using a fallback chain.

    Chain: trafilatura → readability-lxml → raw utf-8.
    Returns (text, parser_name).
    """
    # 1. trafilatura
    if trafilatura is not None:
        result = trafilatura.extract(
            raw_bytes,
            url=final_url,
            include_comments=False,
            include_tables=True,
            no_fallback=False,
            favor_recall=True,
        )
        if result and len(result.strip()) >= _MIN_USEFUL_TEXT_CHARS:
            return result, f"trafilatura/{_TRAFILATURA_VERSION}"

    # 2. readability-lxml
    if _READABILITY_AVAILABLE:
        try:
            html_str = raw_bytes.decode("utf-8", errors="replace")
            doc = _ReadabilityDocument(html_str)
            summary = doc.summary()
            # Strip basic HTML tags from the summary
            import re

            clean = re.sub(r"<[^>]+>", " ", summary)
            clean = re.sub(r"\s+", " ", clean).strip()
            if clean and len(clean) >= _MIN_USEFUL_TEXT_CHARS:
                return clean, "readability-lxml"
        except Exception:  # noqa: BLE001 — readability can raise on malformed HTML
            pass

    # 3. Raw utf-8 fallback
    return raw_bytes.decode("utf-8", errors="replace"), "utf8-fallback"


def _is_bot_wall_status(status_code: int) -> bool:
    """Return True for status codes commonly used by bot-protection systems."""
    return status_code in (403, 429, 503)


async def _do_single_fetch(
    client: httpx.AsyncClient,
    url: str,
) -> httpx.Response:
    """Issue a single GET, raising httpx.HTTPStatusError on error statuses."""
    response = await client.get(url, headers=_BROWSER_HEADERS)
    # Raise on 4xx/5xx except 429 (tenacity handles that via retry)
    if response.status_code in _ERROR_STATUS_CODES:
        raise httpx.HTTPStatusError(
            f"HTTP {response.status_code} for URL: {url}",
            request=response.request,
            response=response,
        )
    return response


async def fetch_url(
    url: str,
    *,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    max_redirects: int = _DEFAULT_MAX_REDIRECTS,
) -> FetchResult:
    """Fetch *url* with SSRF policy enforcement.

    Validates the URL and every redirect hop before issuing the request.
    Applies retry with exponential backoff for transient failures (requires
    tenacity; degrades gracefully without it).

    Raises SSRFError on policy violations, httpx.HTTPError on transport
    failures, and ValueError on content-type or size violations.
    """
    warnings: list[str] = []
    fetch_metadata: dict[str, Any] = {"redirects": []}

    # Pre-flight SSRF check (DNS resolution happens here)
    validated_url = await asyncio.to_thread(validate_url, url)

    current_url = validated_url
    redirect_count = 0
    raw_bytes = b""
    status_code = 0
    content_type = ""
    final_url = current_url

    async with httpx.AsyncClient(
        follow_redirects=False,  # We handle redirects manually to validate each hop
        timeout=httpx.Timeout(timeout_s),
        limits=httpx.Limits(max_connections=1),
        verify=True,
    ) as client:
        # Build a retry-wrapped fetch function if tenacity is available
        if _TENACITY_AVAILABLE:

            @retry(
                retry=retry_if_exception_type(
                    (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError)
                ),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                stop=stop_after_attempt(3),
                reraise=True,
            )
            async def _fetch_with_retry(u: str) -> httpx.Response:
                return await _do_single_fetch(client, u)

        else:

            async def _fetch_with_retry(u: str) -> httpx.Response:  # type: ignore[misc]
                return await _do_single_fetch(client, u)

        while True:
            logger.info("TH fetch: %s", current_url)
            response = await _fetch_with_retry(current_url)

            fetch_metadata["redirects"].append({"url": current_url, "status": response.status_code})

            if response.status_code in (301, 302, 303, 307, 308):
                if redirect_count >= max_redirects:
                    raise ValueError(f"Too many redirects (max {max_redirects})")
                location = response.headers.get("location", "")
                # Validate the redirect target before following
                next_url = await asyncio.to_thread(validate_redirect, current_url, location)
                current_url = next_url
                redirect_count += 1
                continue

            # Non-redirect response
            status_code = response.status_code
            content_type = response.headers.get("content-type", "")
            final_url = current_url
            break

    if not _check_content_type(content_type):
        warnings.append(
            f"Content-Type {content_type!r} is not in the allowed list; "
            "text extraction may be limited"
        )

    # Stream content with size cap (re-open a client for streaming)
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(timeout_s),
        verify=True,
    ) as stream_client:
        async with stream_client.stream("GET", final_url, headers=_BROWSER_HEADERS) as stream_resp:
            chunks: list[bytes] = []
            total = 0
            async for chunk in stream_resp.aiter_bytes(chunk_size=65536):
                total += len(chunk)
                if total > max_bytes:
                    warnings.append(f"Response truncated at {max_bytes // (1024 * 1024)} MiB limit")
                    chunks.append(chunk[: max_bytes - (total - len(chunk))])
                    break
                chunks.append(chunk)
            raw_bytes = b"".join(chunks)

    content_length = len(raw_bytes)

    fetch_metadata.update(
        {
            "final_url": final_url,
            "status_code": status_code,
            "content_type": content_type,
            "content_length": content_length,
            "redirect_count": redirect_count,
        }
    )

    # Extract text using the appropriate extractor
    ct_lower = content_type.lower()
    if "pdf" in ct_lower:
        from backend.threat_hunting.extractors.pdf_extractor import extract_pdf

        extracted_text, parser_version, parse_warnings = extract_pdf(raw_bytes)
        parser_used = f"pymupdf/{parser_version}"
        warnings.extend(parse_warnings)
    elif "json" in ct_lower:
        from backend.threat_hunting.extractors.text_extractor import extract_json_text

        extracted_text, parse_warnings = extract_json_text(raw_bytes)
        parser_used = "json"
        warnings.extend(parse_warnings)
    elif any(t in ct_lower for t in ("html", "xhtml", "xml", "rss", "atom")):
        extracted_text, parser_used = _extract_article_text(raw_bytes, final_url)
    else:
        from backend.threat_hunting.extractors.text_extractor import extract_text

        extracted_text, parse_warnings = extract_text(raw_bytes, content_type)
        parser_used = "text"
        warnings.extend(parse_warnings)

    # Playwright fallback: if static fetch yielded little text or a bot-wall
    # status was encountered (retries exhausted with 403/503).
    if len(extracted_text.strip()) < _MIN_USEFUL_TEXT_CHARS or _is_bot_wall_status(status_code):
        try:
            from backend.threat_hunting.extractors.browser_fetcher import fetch_url_with_browser

            browser_text = await fetch_url_with_browser(url)
            if browser_text and len(browser_text.strip()) > len(extracted_text.strip()):
                logger.info(
                    "TH fetch: Playwright fallback used for %s (gained %d chars)",
                    url,
                    len(browser_text) - len(extracted_text),
                )
                extracted_text = browser_text
                parser_used = f"{parser_used}+playwright"
                fetch_metadata["playwright_fallback"] = True
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Playwright fallback unavailable: {exc}")
            fetch_metadata["playwright_fallback"] = False

    return FetchResult(
        original_url=url,
        final_url=final_url,
        status_code=status_code,
        content_type=content_type,
        content_length=content_length,
        raw_bytes=raw_bytes,
        extracted_text=extracted_text,
        parser_used=parser_used,
        warnings=warnings,
        fetch_metadata=fetch_metadata,
    )
