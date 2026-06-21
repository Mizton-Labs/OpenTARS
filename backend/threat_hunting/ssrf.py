"""
SSRF (Server-Side Request Forgery) baseline policy for the Threat Hunting
URL fetching pipeline (issue-local-002, Phase 2).

Enforcement steps applied on every URL before a request is issued, and again
after every redirect hop:

1. Scheme check — only http / https allowed.
2. Hostname extraction and DNS resolution of all A/AAAA records.
3. Each resolved IP is checked against the blocked ranges.
4. Redirects are re-validated (call validate_url on every Location hop).
5. Response size and timeout caps are applied by the caller (url_fetcher.py).

Blocked by default:
    - Loopback         127.0.0.0/8, ::1/128
    - Link-local       169.254.0.0/16, fe80::/10
    - Private RFC1918  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    - Cloud metadata   169.254.169.254 / fd00:ec2::254
    - Multicast        224.0.0.0/4, ff00::/8
    - Reserved         0.0.0.0/8, 240.0.0.0/4

Design: all validation is synchronous so it can be called in both sync and
async contexts. DNS resolution is done with socket.getaddrinfo (blocking),
which must be called from a thread when used in async code (see url_fetcher).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Blocked IP networks
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Link-local / APIPA / cloud metadata
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # RFC1918 private
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # AWS/GCP/Azure metadata (IPv6 equivalent is fe80:: caught above)
    ipaddress.ip_network("fd00:ec2::254/128"),
    # Multicast
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    # Reserved / "this" network
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("240.0.0.0/4"),
    # Unique local (IPv6 ULA — covers fd00:ec2:: broadly)
    ipaddress.ip_network("fc00::/7"),
]

_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Maximum hostname length (RFC 1035)
_MAX_HOSTNAME_LEN = 253


class SSRFError(ValueError):
    """Raised when a URL or resolved IP violates the SSRF policy."""


def _is_blocked_ip(addr: str) -> bool:
    """Return True when *addr* falls in a blocked network."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # Cannot parse → block
    return any(ip in net for net in _BLOCKED_NETWORKS)


def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve *hostname* to a list of IP address strings.

    Uses socket.getaddrinfo so both A and AAAA records are returned.
    Raises SSRFError on resolution failure.
    """
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for {hostname!r}: {exc}") from exc
    return [r[4][0] for r in results]


def validate_url(url: str) -> str:
    """Validate *url* against the SSRF policy.

    Returns the normalised URL string on success.
    Raises SSRFError with a descriptive message on any violation.

    This function is intentionally synchronous — call it from
    ``asyncio.to_thread(validate_url, url)`` in async contexts.
    """
    if not url or not isinstance(url, str):
        raise SSRFError("URL must be a non-empty string")

    url = url.strip()
    parsed = urlparse(url)

    # 1. Scheme
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise SSRFError(
            f"URL scheme {parsed.scheme!r} is not allowed; only http/https are permitted"
        )

    # 2. Hostname presence
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("URL has no hostname")
    if len(hostname) > _MAX_HOSTNAME_LEN:
        raise SSRFError(f"Hostname exceeds maximum length ({_MAX_HOSTNAME_LEN} chars)")

    # 3. Reject bare IPs that are in blocked ranges before DNS (fast path)
    try:
        ip_literal = ipaddress.ip_address(hostname)
        if _is_blocked_ip(str(ip_literal)):
            raise SSRFError(f"IP address {hostname!r} is in a blocked range")
        # Valid public IP literal — no DNS needed
        return url
    except ValueError:
        pass  # Not an IP literal — fall through to DNS resolution

    # 4. DNS resolution + IP block check
    resolved = _resolve_hostname(hostname)
    if not resolved:
        raise SSRFError(f"DNS resolution returned no addresses for {hostname!r}")
    for addr in resolved:
        if _is_blocked_ip(addr):
            raise SSRFError(f"Hostname {hostname!r} resolves to blocked IP {addr!r}")

    return url


def validate_redirect(original_url: str, location: str) -> str:
    """Validate a redirect Location header value.

    Resolves relative Location values against *original_url* and then
    applies the full SSRF policy to the result.  Returns the validated
    absolute redirect URL.
    """
    from urllib.parse import urljoin

    if not location:
        raise SSRFError("Empty redirect Location header")

    # urljoin handles relative and absolute Location values correctly
    absolute = urljoin(original_url, location)
    return validate_url(absolute)
