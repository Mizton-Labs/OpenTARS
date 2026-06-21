"""URL fetching with SSRF policy enforcement and article text extraction.

Uses httpx for the HTTP transport with retry/backoff (tenacity) and a
multi-extractor fallback chain (trafilatura -> readability-lxml -> raw utf-8).
For JS-heavy pages or pages that return binary/garbled content, a Playwright
headless-Chromium path is used as a fallback.

All DNS resolution and redirect validation go through
backend.threat_hunting.ssrf before any network call is issued.

issue-local-008 fixes applied here:
  Fix 1 - Brotli: brotli package in requirements.txt so httpx auto-decodes br
           responses; Accept-Encoding header is built dynamically and only
           advertises 'br' when a brotli decoder is actually importable.
  Fix 2 - Binary detection: raw bytes are validated after streaming; binary or
           undecoded-compression content forces the Playwright fallback and
           records a parse_warning rather than silently storing mojibake.
  Fix 3 - Broader Playwright trigger: the fallback also fires when the
           extracted text looks like binary (high control-char ratio) or when
           utf8-fallback was used on an HTML content-type, even if the length
           exceeds the 200-char minimum.
  Fix 4 - readability errors surfaced: exceptions from readability-lxml are
           captured and added to warnings instead of silently swallowed.

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

# issue-local-008 Fix 1: only advertise 'br' (Brotli) in Accept-Encoding when
# a brotli decoder is actually importable.  Without this, httpx sends 'br' to
# servers (triggering Brotli compression) but cannot decompress the response
# because the brotli/brotlicffi package is missing — resulting in compressed
# binary bytes being passed to extractors, which yield mojibake and zero IOCs.
_BROTLI_AVAILABLE: bool = False
try:
    import brotli as _brotli_check  # noqa: F401

    _BROTLI_AVAILABLE = True
except ImportError:
    try:
        import brotlicffi as _brotlicffi_check  # noqa: F401

        _BROTLI_AVAILABLE = True
    except ImportError:
        pass

_ACCEPT_ENCODING = "gzip, deflate, br" if _BROTLI_AVAILABLE else "gzip, deflate"

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
    "Accept-Encoding": _ACCEPT_ENCODING,  # Only 'br' when brotli decoder is present
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


def _extract_article_text(
    raw_bytes: bytes,
    final_url: str,
    warnings: list[str] | None = None,
) -> tuple[str, str]:
    """Extract article/page text using a fallback chain.

    Chain: trafilatura -> readability-lxml -> raw utf-8.
    Returns (text, parser_name).

    issue-local-008 Fix 4: exceptions from readability-lxml are now captured
    and appended to *warnings* (when provided) instead of being silently
    swallowed.  This makes extraction failures visible in evidence parse_warnings.
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
        except Exception as exc:  # noqa: BLE001
            # issue-local-008 Fix 4: surface the error instead of silently dropping it
            msg = f"readability-lxml extraction failed: {exc}"
            logger.debug("_extract_article_text: %s", msg)
            if warnings is not None:
                warnings.append(msg)

    # 3. Raw utf-8 fallback
    return raw_bytes.decode("utf-8", errors="replace"), "utf8-fallback"


def _is_bot_wall_status(status_code: int) -> bool:
    """Return True for status codes commonly used by bot-protection systems."""
    return status_code in (403, 429, 503)


# ── issue-local-008 Fix 2 + Fix 3 helpers ─────────────────────────────────────

# Thresholds for binary content detection.
# Brotli/gzip-compressed bytes contain a high ratio of non-ASCII bytes (>60%).
# Valid UTF-8 HTML/text has very few non-ASCII bytes (<15% for English,
# <40% for double-byte scripts).  We use two checks:
#   1. Non-ASCII ratio > threshold (catches undecoded Brotli/gzip which are
#      high-entropy byte streams with many bytes >= 0x80).
#   2. Control-char ratio > threshold (catches NULL/control bytes from binary
#      content that happen to be decoded as utf-8).
_BINARY_NON_ASCII_RATIO_THRESHOLD = 0.30  # >30% non-ASCII bytes → binary
_BINARY_CONTROL_RATIO_THRESHOLD = 0.05  # >5% control chars → binary


def _looks_like_binary(data: bytes | str) -> bool:
    """Return True when *data* appears to be binary rather than text.

    Uses two checks on the first 4096 bytes/chars:
    1. High non-ASCII ratio (>30%) — catches undecoded Brotli/gzip/zstd, which
       are high-entropy byte streams with many bytes >= 0x80.
    2. High control-char ratio (>5%) — catches NULL/control bytes from binary
       data decoded as UTF-8.

    Works on both bytes and str (str is encoded back to bytes for uniform check).
    """
    if isinstance(data, str):
        sample = data[:4096].encode("utf-8", errors="replace")
    else:
        sample = data[:4096]
    if not sample:
        return False
    n = len(sample)
    non_ascii = sum(1 for b in sample if b > 127)
    control = sum(1 for b in sample if b < 9 or (14 <= b <= 31) or b == 0)
    return (non_ascii / n) > _BINARY_NON_ASCII_RATIO_THRESHOLD or (
        control / n
    ) > _BINARY_CONTROL_RATIO_THRESHOLD


def _should_force_playwright(
    extracted_text: str,
    parser_used: str,
    content_type: str,
    status_code: int,
    raw_bytes: bytes,
) -> tuple[bool, str]:
    """Return (should_use_playwright, reason) for the Playwright fallback decision.

    issue-local-008 Fix 3: broadens the original length-only trigger to also
    catch binary/mojibake content that happens to be long (e.g. 31 KB of
    undecompressed Brotli that was decoded as utf-8 garbage).

    Triggers when ANY of:
    1. Extracted text is shorter than _MIN_USEFUL_TEXT_CHARS (original trigger).
    2. HTTP status is a bot-wall code (original trigger).
    3. Extracted text looks like binary (high control-char ratio) — catches
       undecoded Brotli/gzip/zstd where the garbage exceeds 200 chars.
    4. utf8-fallback was used on an HTML content-type — signals that both
       trafilatura and readability failed, meaning the bytes are almost
       certainly not valid HTML text.
    5. Raw bytes look like binary (defense-in-depth: catches the case where
       the extractor wasn't even tried on binary).
    """
    is_html = any(t in content_type.lower() for t in ("html", "xhtml"))

    if len(extracted_text.strip()) < _MIN_USEFUL_TEXT_CHARS:
        return True, f"extracted text too short ({len(extracted_text.strip())} chars)"

    if _is_bot_wall_status(status_code):
        return True, f"bot-wall HTTP status {status_code}"

    if _looks_like_binary(extracted_text):
        return True, "extracted text contains binary/control chars (likely undecoded compression)"

    if parser_used == "utf8-fallback" and is_html:
        return True, "utf8-fallback on HTML content — trafilatura and readability both failed"

    if _looks_like_binary(raw_bytes):
        return True, "raw response bytes look binary (undecoded Content-Encoding?)"

    return False, ""


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
            "brotli_available": _BROTLI_AVAILABLE,  # diagnostic: helps ops debug future encoding issues
        }
    )

    # issue-local-008 Fix 2: detect binary/undecoded content immediately after
    # streaming, before attempting extraction.  If the raw bytes look like
    # compressed/binary data (e.g. Brotli that httpx couldn't decode), record
    # a warning so it is visible in parse_warnings and the Playwright fallback
    # will be forced regardless of extracted-text length (Fix 3).
    ct_lower = content_type.lower()
    is_html_ct = any(t in ct_lower for t in ("html", "xhtml", "xml", "rss", "atom"))
    if _looks_like_binary(raw_bytes) and is_html_ct:
        warnings.append(
            "Raw response bytes appear binary/undecoded (possible undecoded Brotli or "
            "other Content-Encoding). brotli decoder available: "
            f"{_BROTLI_AVAILABLE}. "
            "Install the 'brotli' package to fix Brotli-encoded responses. "
            "Playwright fallback will be attempted."
        )
        fetch_metadata["binary_content_detected"] = True
        logger.warning(
            "TH fetch: binary content detected for %s (brotli_available=%s)",
            url,
            _BROTLI_AVAILABLE,
        )

    # Extract text using the appropriate extractor
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
    elif is_html_ct:
        # Pass warnings so readability errors are surfaced (Fix 4)
        extracted_text, parser_used = _extract_article_text(raw_bytes, final_url, warnings)
    else:
        from backend.threat_hunting.extractors.text_extractor import extract_text

        extracted_text, parse_warnings = extract_text(raw_bytes, content_type)
        parser_used = "text"
        warnings.extend(parse_warnings)

    # issue-local-008 Fix 3: broadened Playwright fallback trigger.
    # Replaces the original length-only check with _should_force_playwright(),
    # which also catches binary/mojibake text that happens to be >200 chars
    # (e.g. 31 KB of undecompressed Brotli decoded as utf-8 garbage).
    playwright_needed, playwright_reason = _should_force_playwright(
        extracted_text, parser_used, content_type, status_code, raw_bytes
    )
    if playwright_needed:
        try:
            from backend.threat_hunting.extractors.browser_fetcher import fetch_url_with_browser

            logger.info(
                "TH fetch: attempting Playwright fallback for %s (reason: %s)",
                url,
                playwright_reason,
            )
            browser_text = await fetch_url_with_browser(url)
            # Accept Playwright result when:
            #   a) the existing text looks binary/garbage → prefer any clean Playwright output
            #   b) OR Playwright yielded more text than the static path
            # This prevents rejecting Playwright when binary mojibake is "long" (Fix 2+3).
            static_is_binary = _looks_like_binary(extracted_text)
            browser_is_useful = bool(
                browser_text
                and len(browser_text.strip()) >= _MIN_USEFUL_TEXT_CHARS
                and not _looks_like_binary(browser_text)
            )
            prefer_browser = browser_is_useful and (
                static_is_binary or len(browser_text.strip()) > len(extracted_text.strip())
            )
            if prefer_browser:
                logger.info(
                    "TH fetch: Playwright fallback succeeded for %s "
                    "(browser=%d chars, static_binary=%s, reason: %s)",
                    url,
                    len(browser_text),
                    static_is_binary,
                    playwright_reason,
                )
                extracted_text = browser_text
                parser_used = f"{parser_used}+playwright"
                fetch_metadata["playwright_fallback"] = True
                fetch_metadata["playwright_reason"] = playwright_reason
            else:
                logger.info(
                    "TH fetch: Playwright did not improve on static fetch for %s "
                    "(browser=%d chars, static=%d chars, static_binary=%s)",
                    url,
                    len(browser_text.strip()) if browser_text else 0,
                    len(extracted_text.strip()),
                    static_is_binary,
                )
                fetch_metadata["playwright_fallback"] = False
                fetch_metadata["playwright_reason"] = playwright_reason
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Playwright fallback unavailable: {exc}")
            fetch_metadata["playwright_fallback"] = False
            fetch_metadata["playwright_reason"] = playwright_reason

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
