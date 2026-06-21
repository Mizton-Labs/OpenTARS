"""Playwright headless-Chromium fallback fetcher.

Used by url_fetcher when static HTTP fetch yields little usable text (e.g.
JavaScript single-page applications) or when the server returns a bot-wall
status code (403 / 503).

Security notes:
- Every URL is SSRF-validated via backend.threat_hunting.ssrf before navigation.
- All route interceptions block navigation to private-IP ranges (127.x, 10.x,
  192.168.x, 169.254.x, ::1, fc00::/7) that could arise from open-redirect
  tricks in the page's JavaScript.
- Playwright runs with its default sandbox (--no-sandbox is NOT set). Operators
  running in restricted container environments (e.g. rootless Docker without
  user namespaces) may need to adjust kernel.unprivileged_userns_clone or run
  with --ipc=host; see https://playwright.dev/python/docs/docker.
- Content is extracted with the same trafilatura → readability-lxml → utf-8
  fallback chain used by url_fetcher; the raw rendered HTML is never stored.
"""

from __future__ import annotations

import asyncio
import logging
import re

logger = logging.getLogger(__name__)

# Minimum text length we consider worth returning from the browser path.
_MIN_BROWSER_TEXT_CHARS = 200

# Hard timeout for Playwright page navigation + rendering (seconds).
_BROWSER_TIMEOUT_MS = 30_000

try:
    from playwright.async_api import async_playwright  # type: ignore[import-untyped]

    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


def _ssrf_check_url(url: str) -> bool:
    """Synchronous SSRF check for use inside Playwright route callbacks.

    Delegates to the authoritative ``backend.threat_hunting.ssrf.validate_url``
    via a synchronous call. Returns True (safe) / False (blocked).

    This replaces the previous independent implementation that diverged from the
    authoritative blocklist (e.g., lacked CGNAT 100.64.0.0/10).
    """
    try:
        # validate_url is synchronous under the hood (uses socket.getaddrinfo)
        # but is an async def for consistent API with url_fetcher. We call the
        # underlying synchronous validation directly.
        from urllib.parse import urlparse as _urlparse

        from backend.threat_hunting.ssrf import _is_blocked_ip, _resolve_hostname

        parsed = _urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname or ""
        if not hostname:
            return False
        resolved = _resolve_hostname(hostname)
        if not resolved:
            return False  # Unresolvable → block
        for ip_str in resolved:
            if _is_blocked_ip(ip_str):
                return False
        return True
    except Exception:  # noqa: BLE001
        return False


async def fetch_url_with_browser(url: str) -> str | None:
    """Fetch *url* with headless Chromium and return extracted text.

    Returns None if Playwright is not installed or if the page yields no
    usable text. Never raises — all errors are caught and logged so the
    caller (url_fetcher) can degrade gracefully.

    The URL must already have passed validate_url() before this function is
    called; this function does a secondary lightweight SSRF check for safety
    but relies on the caller for the primary DNS-based validation.
    """
    if not _PLAYWRIGHT_AVAILABLE:
        logger.debug("browser_fetcher: playwright not installed — skipping browser fallback")
        return None

    # Secondary SSRF guard before we let the browser make a network request.
    if not _ssrf_check_url(url):
        logger.warning("browser_fetcher: SSRF check blocked URL before browser navigation: %s", url)
        return None

    try:
        return await asyncio.wait_for(
            _run_browser_fetch(url),
            timeout=_BROWSER_TIMEOUT_MS / 1000 + 5,  # +5 s grace over page timeout
        )
    except asyncio.TimeoutError:
        logger.warning("browser_fetcher: browser fetch timed out for %s", url)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("browser_fetcher: browser fetch failed for %s: %s", url, exc)
        return None


async def _run_browser_fetch(url: str) -> str | None:
    """Internal: launch browser, navigate, extract text, close."""
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-gpu",
                "--no-first-run",
            ],
        )
        try:
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                },
                java_script_enabled=True,
                service_workers="block",  # Prevent service worker fetch bypass
            )
            page = await context.new_page()

            # Route interception on context (covers all frames + workers, not just main page).
            # Blocks any in-page navigation to private/internal IP ranges.
            async def _intercept_route(route, request):  # type: ignore[no-untyped-def]
                req_url = request.url
                if not _ssrf_check_url(req_url):
                    logger.warning(
                        "browser_fetcher: blocking in-page navigation to private URL: %s",
                        req_url,
                    )
                    await route.abort("blockedbyclient")
                    return
                await route.continue_()

            # Use context.route instead of page.route — applies to all frames and workers.
            await context.route("**/*", _intercept_route)

            try:
                await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=_BROWSER_TIMEOUT_MS,
                )
                # Brief wait for dynamic content to render
                await page.wait_for_timeout(2000)
            except Exception as nav_exc:  # noqa: BLE001
                logger.warning("browser_fetcher: navigation error for %s: %s", url, nav_exc)
                # Still try to extract whatever loaded
            finally:
                html = await page.content()

            await context.close()
        finally:
            await browser.close()

    # Extract text from the rendered HTML using the same chain as url_fetcher
    return _extract_from_html(html.encode("utf-8"), url)


def _extract_from_html(raw_bytes: bytes, url: str) -> str | None:
    """Extract readable text from rendered HTML bytes."""
    # 1. trafilatura
    try:
        import trafilatura  # type: ignore[import-untyped]

        result = trafilatura.extract(
            raw_bytes,
            url=url,
            include_comments=False,
            include_tables=True,
            no_fallback=False,
            favor_recall=True,
        )
        if result and len(result.strip()) >= _MIN_BROWSER_TEXT_CHARS:
            return result
    except Exception:  # noqa: BLE001
        pass

    # 2. readability-lxml
    try:
        from readability import Document  # type: ignore[import-untyped]

        doc = Document(raw_bytes.decode("utf-8", errors="replace"))
        summary = doc.summary()
        clean = re.sub(r"<[^>]+>", " ", summary)
        clean = re.sub(r"\s+", " ", clean).strip()
        if clean and len(clean) >= _MIN_BROWSER_TEXT_CHARS:
            return clean
    except Exception:  # noqa: BLE001
        pass

    # 3. Plain text decode
    decoded = raw_bytes.decode("utf-8", errors="replace")
    if len(decoded.strip()) >= _MIN_BROWSER_TEXT_CHARS:
        return decoded

    return None
