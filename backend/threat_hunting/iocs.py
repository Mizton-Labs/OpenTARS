"""
IOC extraction, normalization, deduplication, and noise scoring.

Pipeline:
1. Extract IOC candidates from text using regex patterns per type.
2. Normalize:
   - strip protocol prefixes (http://, https://, ftp://) from URL-type IOCs
   - lowercase domains
   - uppercase hex digests (MD5/SHA1/SHA256)
   - strip defanging (dots, brackets): evil[.]com, hxxp://
3. Deduplicate by (ioc_type, normalized_ioc).
4. Score noise (0.0 = clean, 1.0 = very noisy).

The result is a list of ExtractedIOC dicts ready for DB insertion.
"""

from __future__ import annotations

import re
from typing import TypedDict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# IPv4 addresses
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# MD5 (32 hex), SHA-1 (40 hex), SHA-256 (64 hex)
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Domain names (simplified; excludes common TLDs that appear in prose)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|gov|edu|mil|int|info|biz|co|uk|de|fr|ru|cn|jp|br|"
    r"xyz|top|online|site|tech|store|shop|app|dev|cloud|ai)\b",
    re.IGNORECASE,
)

# CVE identifiers
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# URLs (http/https)
_RE_URL = re.compile(
    r"(?:https?://|hxxp[s]?://|h\[t\]tp[s]?://)"
    r"[^\s\"'<>(){}\[\]\\]+",
    re.IGNORECASE,
)

# Email addresses
_RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

# Windows registry keys
_RE_REGISTRY = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKU|HKCR|HKCC)"
    r"(?:\\[^\s\\/:*?\"<>|]+)+\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Noise patterns — IOCs that are likely to generate excessive SIEM matches
# ---------------------------------------------------------------------------

_NOISY_PROCESSES = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "svchost.exe",
        "explorer.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
        "notepad.exe",
        "calc.exe",
        "regedit.exe",
        "taskmgr.exe",
    }
)

_NOISY_DOMAINS = frozenset(
    {
        "google.com",
        "microsoft.com",
        "windows.com",
        "cloudflare.com",
        "amazonaws.com",
        "akamai.net",
        "fastly.net",
        "azure.com",
        "office.com",
        "live.com",
        "outlook.com",
        "apple.com",
        "icloud.com",
        "github.com",
        "githubusercontent.com",
        "gstatic.com",
        "googleapis.com",
    }
)

# Known benign MD5/SHA hashes (empty file, etc.)
_NOISY_HASHES = frozenset(
    {
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5 empty
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 empty
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 empty
    }
)


# ---------------------------------------------------------------------------
# TypedDict for extracted IOC
# ---------------------------------------------------------------------------


class ExtractedIOC(TypedDict):
    ioc: str
    ioc_type: str
    ioc_description: str
    noise_score: float
    flagged_noisy: bool


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

_DEFANG_DOT = re.compile(r"\[\.\]|\(\.\)")
_DEFANG_PROTO = re.compile(r"hxxp(s?)://", re.IGNORECASE)
_STRIP_PROTO = re.compile(r"^https?://", re.IGNORECASE)


def _defang(text: str) -> str:
    """Remove common defanging patterns."""
    text = _DEFANG_DOT.sub(".", text)
    text = _DEFANG_PROTO.sub(r"http\1://", text)
    return text


def _normalize_ioc(ioc: str, ioc_type: str) -> str:
    ioc = _defang(ioc).strip()
    if ioc_type in ("domain",):
        return ioc.lower()
    if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        return ioc.lower()
    if ioc_type == "url":
        # Remove protocol for search-ready token
        return _STRIP_PROTO.sub("", ioc).rstrip("/")
    if ioc_type == "cve":
        return ioc.upper()
    return ioc


def _noise_score(ioc: str, ioc_type: str) -> float:
    """Return a noise score in [0.0, 1.0]. Higher = noisier / less actionable."""
    lower = ioc.lower()

    # Very short tokens
    if len(ioc) < 4:
        return 0.9

    if ioc_type == "ip":
        # Private/loopback
        import ipaddress

        try:
            ip = ipaddress.ip_address(ioc)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return 0.95
        except ValueError:
            pass

    if ioc_type == "domain" and lower in _NOISY_DOMAINS:
        return 0.95

    if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256") and lower in _NOISY_HASHES:
        return 0.99

    if ioc_type == "filepath" and any(p in lower for p in _NOISY_PROCESSES):
        return 0.85

    return 0.0


# ---------------------------------------------------------------------------
# Main extraction function
# ---------------------------------------------------------------------------


def extract_iocs_from_text(text: str) -> list[ExtractedIOC]:
    """Extract, normalize, deduplicate, and score IOCs from *text*.

    Returns a list of ExtractedIOC dicts ordered by type then ioc value.
    """
    seen: set[tuple[str, str]] = set()
    results: list[ExtractedIOC] = []

    def _add(ioc_raw: str, ioc_type: str, description: str = "") -> None:
        normalized = _normalize_ioc(ioc_raw, ioc_type)
        key = (ioc_type, normalized)
        if key in seen:
            return
        seen.add(key)
        score = _noise_score(normalized, ioc_type)
        results.append(
            ExtractedIOC(
                ioc=normalized,
                ioc_type=ioc_type,
                ioc_description=description,
                noise_score=score,
                flagged_noisy=score >= 0.7,
            )
        )

    # SHA-256 first (64 hex — must precede MD5/SHA1 to avoid prefix collisions)
    for m in _RE_SHA256.finditer(text):
        _add(m.group(), "hash_sha256")

    # SHA-1 (40 hex)
    for m in _RE_SHA1.finditer(text):
        # Skip if already captured as SHA-256 prefix
        val = m.group()
        if ("hash_sha256", val.lower()) not in seen:
            _add(val, "hash_sha1")

    # MD5 (32 hex)
    for m in _RE_MD5.finditer(text):
        val = m.group()
        if ("hash_sha256", val.lower()) not in seen and ("hash_sha1", val.lower()) not in seen:
            _add(val, "hash_md5")

    # CVEs
    for m in _RE_CVE.finditer(text):
        _add(m.group(), "cve")

    # IPs
    for m in _RE_IPV4.finditer(text):
        _add(m.group(), "ip")

    # URLs (before domains so domains within URLs are not double-counted)
    for m in _RE_URL.finditer(text):
        _add(m.group(), "url")

    # Domains (skip if already seen as part of a URL)
    for m in _RE_DOMAIN.finditer(text):
        val = m.group().lower()
        # Only add if not already captured inside a URL IOC
        already_in_url = any(val in r["ioc"] for r in results if r["ioc_type"] == "url")
        if not already_in_url:
            _add(val, "domain")

    # Emails
    for m in _RE_EMAIL.finditer(text):
        _add(m.group(), "email")

    # Registry keys
    for m in _RE_REGISTRY.finditer(text):
        _add(m.group(), "registry_key")

    return sorted(results, key=lambda r: (r["ioc_type"], r["ioc"]))


def normalize_ioc_csv(rows: list[dict]) -> list[ExtractedIOC]:
    """Normalize and score a pre-parsed IOC CSV (list of dicts with ioc/ioc_type/ioc_description).

    Used by the Deep Retrohunt pipeline and manual CSV uploads.
    """
    seen: set[tuple[str, str]] = set()
    results: list[ExtractedIOC] = []

    for row in rows:
        raw_ioc = str(row.get("ioc", "")).strip()
        ioc_type = str(row.get("ioc_type", "other")).strip().lower()
        description = str(row.get("ioc_description", "")).strip()
        if not raw_ioc:
            continue
        normalized = _normalize_ioc(raw_ioc, ioc_type)
        key = (ioc_type, normalized)
        if key in seen:
            continue
        seen.add(key)
        score = _noise_score(normalized, ioc_type)
        results.append(
            ExtractedIOC(
                ioc=normalized,
                ioc_type=ioc_type,
                ioc_description=description,
                noise_score=score,
                flagged_noisy=score >= 0.7,
            )
        )

    return results
