"""URL fetching with SSRF policy enforcement and article text extraction.

Uses httpx for the HTTP transport and trafilatura for article content
extraction. All DNS resolution and redirect validation go through
backend.threat_hunting.ssrf before any network call is issued.
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

_TRAFILATURA_VERSION: str | None = None
try:
    import trafilatura  # type: ignore[import-untyped]

    _TRAFILATURA_VERSION = getattr(trafilatura, "__version__", "unknown")
except ImportError:  # pragma: no cover
    trafilatura = None  # type: ignore[assignment]


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
    """Extract article/page text from HTML bytes using trafilatura.

    Returns (text, parser_name).
    """
    if trafilatura is None:
        # Fallback: return raw bytes decoded as utf-8
        return raw_bytes.decode("utf-8", errors="replace"), "utf8-fallback"

    result = trafilatura.extract(
        raw_bytes,
        url=final_url,
        include_comments=False,
        include_tables=True,
        no_fallback=False,
        favor_recall=True,
    )
    if result:
        return result, f"trafilatura/{_TRAFILATURA_VERSION}"
    # Trafilatura gave nothing — fall back to raw decode
    return raw_bytes.decode("utf-8", errors="replace"), "utf8-fallback"


async def fetch_url(
    url: str,
    *,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    max_redirects: int = _DEFAULT_MAX_REDIRECTS,
) -> FetchResult:
    """Fetch *url* with SSRF policy enforcement.

    Validates the URL and every redirect hop before issuing the request.
    Raises SSRFError on policy violations, httpx.HTTPError on transport
    failures, and ValueError on content-type or size violations.
    """
    warnings: list[str] = []
    fetch_metadata: dict[str, Any] = {"redirects": []}

    # Pre-flight SSRF check (DNS resolution happens here)
    validated_url = await asyncio.to_thread(validate_url, url)

    current_url = validated_url
    redirect_count = 0

    async with httpx.AsyncClient(
        follow_redirects=False,  # We handle redirects manually to validate each hop
        timeout=httpx.Timeout(timeout_s),
        limits=httpx.Limits(max_connections=1),
        verify=True,
    ) as client:
        while True:
            logger.info("TH fetch: %s", current_url)
            response = await client.get(
                current_url, headers={"User-Agent": "Mizton-ThreatBox/1.0 ThreatHunting"}
            )

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

            if not _check_content_type(content_type):
                warnings.append(
                    f"Content-Type {content_type!r} is not in the allowed list; "
                    "text extraction may be limited"
                )

            # Stream content with size cap
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes(chunk_size=65536):
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

            # Extract text
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
