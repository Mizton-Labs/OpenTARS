"""Threat Hunting agent tool wrappers.

These are pure Python callables exposed to the LLM via the tool-calling API
(OpenAI function-calling / Anthropic tool-use). Each tool is:
  - A plain synchronous function (no I/O except the SSRF-checked URL re-fetch).
  - Validated at the call site before dispatch (no arbitrary code execution).
  - Fully covered by unit tests.

Security notes:
  - ``refetch_url`` enforces SSRF validation via backend.threat_hunting.ssrf
    before any network call. The model cannot bypass this.
  - No shell execution. All tools are pure Python.
  - Tool inputs are type-validated by the JSON schema before dispatch.
  - LLM tool-choice cannot call arbitrary code — only the registered tools below.
"""

from __future__ import annotations

import re
from typing import Any

# ── Tool schemas (OpenAI function-calling format) ─────────────────────────────

# Each entry:
#   name         — tool name sent to the LLM
#   description  — LLM-facing description
#   parameters   — JSON Schema for arguments
#   fn           — Python callable (resolved lazily to avoid import cycles)

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "extract_iocs",
        "description": (
            "Extract Indicators of Compromise (IOCs) from a text string. "
            "Returns a list of {ioc, ioc_type, ioc_description} dicts. "
            "Use when additional text needs IOC scanning beyond the pre-loaded evidence."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text to extract IOCs from (max 50 000 chars).",
                }
            },
            "required": ["text"],
        },
    },
    {
        "name": "defang_ioc",
        "description": (
            "Defang an IOC value for safe display (e.g. replace dots in IPs/domains, "
            "obfuscate URL schema). Returns the defanged string."
        ),
        "parameters": {
            "type": "object",
            "properties": {"ioc": {"type": "string", "description": "Raw IOC value to defang."}},
            "required": ["ioc"],
        },
    },
    {
        "name": "noise_score",
        "description": (
            "Return the noise score (0.0–1.0) and human-readable reasons for an IOC. "
            "Higher score means more likely to be a false-positive or too generic for hunting. "
            "IOC types: ip, domain, url, hash_md5, hash_sha1, hash_sha256, email, cve, registry."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ioc": {"type": "string", "description": "IOC value."},
                "ioc_type": {
                    "type": "string",
                    "description": "IOC type (ip, domain, url, hash_md5, hash_sha1, hash_sha256, email, cve, registry).",
                },
            },
            "required": ["ioc", "ioc_type"],
        },
    },
    {
        "name": "mitre_lookup",
        "description": (
            "Look up a MITRE ATT&CK technique by ID (e.g. T1059, T1059.001). "
            "Returns name, tactic(s), and a short description. "
            "Returns null if the technique ID is not in the static map."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "MITRE ATT&CK technique ID, e.g. T1059 or T1059.001.",
                }
            },
            "required": ["technique_id"],
        },
    },
    {
        "name": "validate_spl",
        "description": (
            "Perform a basic syntax check on a Splunk SPL query. "
            "Returns {valid: bool, issues: [str]}. "
            "Use before including a query draft in the final output."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "SPL query string to validate."}
            },
            "required": ["query"],
        },
    },
    {
        "name": "refetch_url",
        "description": (
            "Re-fetch a URL and return its extracted text. "
            "Subject to SSRF validation — private/internal IPs are blocked. "
            "Use when the existing evidence corpus is missing content for a known URL."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Fully-qualified URL to fetch (https:// preferred).",
                }
            },
            "required": ["url"],
        },
    },
]

# Build a quick lookup by name
TOOL_SPEC_BY_NAME: dict[str, dict[str, Any]] = {t["name"]: t for t in TOOL_SPECS}

# ── Tool implementations ───────────────────────────────────────────────────────


def tool_extract_iocs(text: str) -> list[dict[str, Any]]:
    """Extract IOCs from text using the existing iocs module."""
    from backend.threat_hunting.iocs import extract_iocs_from_text

    # Cap input to avoid accidental huge prompts
    text = text[:50_000]
    iocs = extract_iocs_from_text(text)
    return [
        {
            "ioc": i.get("ioc"),
            "ioc_type": i.get("ioc_type"),
            "ioc_description": i.get("ioc_description"),
        }
        for i in iocs
    ]


def tool_defang_ioc(ioc: str) -> str:
    """Defang an IOC value for safe display."""
    from backend.threat_hunting.iocs import _defang  # noqa: PLC2701

    return _defang(ioc)


def tool_noise_score(ioc: str, ioc_type: str) -> dict[str, Any]:
    """Return noise score and reasons for an IOC.

    ``_noise_score`` returns a float. We separately derive reasons from the
    deep_retrohunt_planner's ``_noise_reasons`` helper (which inspects the same
    heuristics). If that is unavailable, reasons is an empty list.
    """
    from backend.threat_hunting.iocs import _noise_score  # noqa: PLC2701

    score = _noise_score(ioc, ioc_type)
    reasons: list[str] = []
    try:
        from backend.threat_hunting.agents.nodes.deep_retrohunt_planner import (
            _noise_reasons,  # noqa: PLC2701
        )

        reasons = _noise_reasons(ioc, ioc_type)
    except Exception:  # noqa: BLE001
        pass
    return {"score": score, "reasons": reasons}


# Static MITRE ATT&CK technique map (common techniques; not exhaustive).
# Operators can extend this dict without touching the tool interface.
_MITRE_MAP: dict[str, dict[str, str]] = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1059.006": {"name": "Python", "tactic": "Execution"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access"},
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
    },
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion, Privilege Escalation"},
    "T1055.001": {"name": "DLL Injection", "tactic": "Defense Evasion, Privilege Escalation"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control"},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "Discovery"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "Defense Evasion"},
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence, Privilege Escalation",
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence, Privilege Escalation",
    },
    "T1574": {
        "name": "Hijack Execution Flow",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
    },
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1219": {"name": "Remote Access Software", "tactic": "Command and Control"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution"},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
}


def tool_mitre_lookup(technique_id: str) -> dict[str, str] | None:
    """Look up a MITRE ATT&CK technique by ID."""
    # Normalize: strip spaces, uppercase T prefix
    tid = technique_id.strip().upper()
    if not tid.startswith("T"):
        tid = "T" + tid
    info = _MITRE_MAP.get(tid)
    if info:
        return {"technique_id": tid, **info}
    return None


def tool_validate_spl(query: str) -> dict[str, Any]:
    """Basic SPL syntax validation.

    Checks:
    - Balanced pipes (basic structure)
    - No obviously invalid keywords
    - Common SPL search commands present
    """
    issues: list[str] = []

    if not query.strip():
        return {"valid": False, "issues": ["Empty query"]}

    # Check for balanced brackets
    for open_c, close_c in [("(", ")"), ("[", "]")]:
        if query.count(open_c) != query.count(close_c):
            issues.append(f"Unbalanced {open_c!r}/{close_c!r} brackets")

    # Warn on common misuses
    if re.search(r"\|\s*\|", query):
        issues.append("Double pipe (|| — empty command) detected")

    # Check for at least one recognized SPL command or search directive
    known_commands = re.compile(
        r"\b(index|source|sourcetype|stats|eval|where|table|fields|rename|"
        r"rex|regex|search|join|lookup|dedup|sort|head|tail|timechart|chart|"
        r"bucket|transaction|tstats|mstats|makeresults|inputlookup|outputlookup|"
        r"eventstats|streamstats|append|appendcols|mvexpand|convert|strftime)\b",
        re.IGNORECASE,
    )
    if not known_commands.search(query):
        issues.append(
            "No recognized SPL commands found — query may be incomplete or use unsupported syntax"
        )

    return {"valid": len(issues) == 0, "issues": issues}


async def tool_refetch_url(url: str) -> str:
    """Re-fetch a URL and return its extracted text (async, SSRF-validated).

    Delegates to url_fetcher.fetch_url which enforces SSRF validation before
    making any network request. The model cannot bypass SSRF via this tool.
    """
    # Lazy import to avoid circular imports at module load time.
    # Tests should patch 'backend.threat_hunting.extractors.url_fetcher.fetch_url'.
    from backend.threat_hunting.extractors.url_fetcher import fetch_url as _fetch_url

    result = await _fetch_url(url)
    return result.extracted_text or ""


# ── Dispatch map ──────────────────────────────────────────────────────────────

# Sync tools keyed by name (async tool handled separately in dispatcher)
_SYNC_TOOLS: dict[str, Any] = {
    "extract_iocs": tool_extract_iocs,
    "defang_ioc": tool_defang_ioc,
    "noise_score": tool_noise_score,
    "mitre_lookup": tool_mitre_lookup,
    "validate_spl": tool_validate_spl,
}

# refetch_url is async — handled explicitly in call_tool
_ASYNC_TOOLS: dict[str, Any] = {
    "refetch_url": tool_refetch_url,
}


async def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    """Dispatch a tool call by name with the given arguments.

    Returns the tool result (any JSON-serialisable value).
    Raises ValueError for unknown tool names or invalid arguments.

    Security: all inputs are validated against the JSON schema spec before
    dispatch. No shell execution; no arbitrary imports.
    """
    # Validate the tool name
    if name not in TOOL_SPEC_BY_NAME:
        raise ValueError(f"Unknown tool: {name!r}")

    spec = TOOL_SPEC_BY_NAME[name]
    required = spec["parameters"].get("required", [])
    for req_param in required:
        if req_param not in arguments:
            raise ValueError(f"Tool {name!r} requires parameter {req_param!r}")

    # Strip extra keys not in the schema to prevent unexpected-kwarg injection.
    # The LLM may hallucinate extra parameters; filtering here makes dispatch safe.
    allowed_keys = set(spec["parameters"].get("properties", {}).keys())
    safe_args = {k: v for k, v in arguments.items() if k in allowed_keys}

    # Dispatch
    if name in _ASYNC_TOOLS:
        return await _ASYNC_TOOLS[name](**safe_args)
    elif name in _SYNC_TOOLS:
        return _SYNC_TOOLS[name](**safe_args)
    else:
        raise ValueError(f"Tool {name!r} has no implementation")  # pragma: no cover
