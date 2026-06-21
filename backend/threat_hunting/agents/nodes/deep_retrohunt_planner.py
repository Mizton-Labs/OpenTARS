"""LangGraph node: deep_retrohunt_planner (with tool-calling, issue-006-B)

Produces the Deep Retrohunt lead for a hunt package.

Always runs when the extracted IOC set contains at least one atomic IOC
(IP, domain, hash, CVE, email, registry key, or URL).  Skips gracefully
when the package has no IOCs.

Two-stage processing:
  1. Deterministic sanitization — uses the existing ``iocs.py`` helpers to:
       - Defang and normalize all IOCs.
       - Deduplicate by (type, value).
       - Noise-score every IOC.
       - Derive the shortest search-ready token for each IOC.
       - Build the canonical CSV (ioc,ioc_type,ioc_description).

  2. LLM enrichment — calls the LLM to:
       - Generate analyst notes on sanitization decisions and noise flags.
       - Draft a Splunk SPL macro for the retrohunt.
       - Write a plain-language search hint for non-Splunk SIEMs.

If the LLM call fails, the node returns the deterministic output unchanged
with ``llm_parse_error=True``.  The pipeline continues — the deterministic
CSV and noise scores are always present.
"""

from __future__ import annotations

import csv
import io
import logging
import re
import time
from typing import Any

from backend.threat_hunting.agents.effort_profile import get_effort_profile
from backend.threat_hunting.agents.llm_bridge import build_prompt, call_llm, parse_json_response
from backend.threat_hunting.agents.state import DeepRetrohuntLead, HuntPipelineState, SanitizedIOC
from backend.threat_hunting.iocs import _defang, _noise_score, _normalize_ioc  # noqa: PLC2701

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Noise-reason catalogue — human-readable explanations
# ---------------------------------------------------------------------------

_PRIVATE_RANGES = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
    "169.254.",
)

_NOISY_DOMAINS_SET = frozenset(
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

_NOISY_PROCESSES_SET = frozenset(
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

_EMPTY_HASHES = frozenset(
    {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
)

_STRIP_PROTO = re.compile(r"^https?://", re.IGNORECASE)


def _noise_reasons(ioc: str, ioc_type: str) -> list[str]:
    """Return a list of human-readable noise reason strings for this IOC."""
    reasons: list[str] = []
    lower = ioc.lower()

    if len(ioc) < 4:
        reasons.append("Very short token — likely to generate excessive SIEM hits")

    if ioc_type == "ip":
        if any(ioc.startswith(p) for p in _PRIVATE_RANGES):
            reasons.append("Private/RFC1918/loopback IP — not routable on the internet")

    if ioc_type == "domain":
        if lower in _NOISY_DOMAINS_SET:
            reasons.append("Known benign CDN/infrastructure domain")
        if lower.endswith(".local") or lower.endswith(".internal"):
            reasons.append("Internal/non-public domain suffix")

    if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        if lower in _EMPTY_HASHES:
            reasons.append("Hash of empty file — not indicative of malicious activity")

    if ioc_type in ("filepath", "other"):
        if any(p in lower for p in _NOISY_PROCESSES_SET):
            reasons.append("Common Windows system process — high base-rate in SIEM")

    return reasons


def _search_token(ioc: str, ioc_type: str) -> str:
    """Derive the shortest search-ready token for SIEM queries."""
    if ioc_type == "url":
        # Strip protocol and trailing slash
        return _STRIP_PROTO.sub("", ioc).rstrip("/")
    if ioc_type == "domain":
        # Use as-is (already lowercase after normalization)
        return ioc
    if ioc_type == "ip":
        return ioc
    if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        return ioc.lower()
    if ioc_type == "cve":
        return ioc.upper()
    if ioc_type == "email":
        return ioc.lower()
    return ioc


# ---------------------------------------------------------------------------
# Deterministic sanitization
# ---------------------------------------------------------------------------

_ATOMIC_TYPES = frozenset(
    {
        "ip",
        "domain",
        "url",
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
        "email",
        "cve",
        "registry_key",
        "filepath",
        "mutex",
        "asn",
        "other",
    }
)


def _sanitize_ioc_list(raw_iocs: list[dict[str, Any]]) -> list[SanitizedIOC]:
    """Deterministically sanitize and noise-score a list of raw IOC dicts.

    Each dict must have at least ``ioc`` and ``ioc_type`` keys.
    Performs defanging, normalization, deduplication, noise scoring,
    and search-token derivation.
    """
    seen: set[tuple[str, str]] = set()
    results: list[SanitizedIOC] = []

    for row in raw_iocs:
        raw_val = str(row.get("ioc", "")).strip()
        ioc_type = str(row.get("ioc_type", "other")).strip().lower()
        description = str(row.get("ioc_description", "") or row.get("description", "")).strip()

        if not raw_val or ioc_type not in _ATOMIC_TYPES:
            continue

        # Defang then normalize
        defanged = _defang(raw_val)
        normalized = _normalize_ioc(defanged, ioc_type)
        if not normalized:
            continue

        key = (ioc_type, normalized)
        if key in seen:
            continue
        seen.add(key)

        score = _noise_score(normalized, ioc_type)
        reasons = _noise_reasons(normalized, ioc_type)
        token = _search_token(normalized, ioc_type)

        results.append(
            SanitizedIOC(
                ioc=normalized,
                ioc_type=ioc_type,
                ioc_description=description,
                noise_score=score,
                noise_reasons=reasons,
                search_token=token,
            )
        )

    # Stable sort: clean IOCs first, then by type, then by value
    return sorted(results, key=lambda r: (r["noise_score"], r["ioc_type"], r["ioc"]))


def _build_ioc_csv(sanitized: list[SanitizedIOC]) -> str:
    """Render the canonical IOC CSV string from sanitized IOCs."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ioc", "ioc_type", "ioc_description"])
    for s in sanitized:
        writer.writerow([s["ioc"], s["ioc_type"], s["ioc_description"]])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# LLM prompt
# ---------------------------------------------------------------------------

_LLM_OUTPUT_FORMAT = """{
  "spl_draft": "| makeresults ... | eval ioc=... | ... (full Splunk SPL macro body)",
  "spl_macro_name": "threathunt_ioc_<hunt_id_short>",
  "search_hint": "Plain-language description of what to hunt for across all IOC types",
  "analyst_notes": "Summary of sanitization decisions, noise flags, and recommendations for the operator"
}"""


async def _enrich_with_llm(
    sanitized: list[SanitizedIOC],
    ioc_csv: str,
    hunt_package_id: str,
    *,
    provider_name: str | None,
    model_name: str | None,
    retrohunt_ioc_cap: int = 50,
    retrohunt_csv_cap: int = 3000,
    retrohunt_tokens: int = 3000,
) -> dict[str, str]:
    """Call the LLM to generate SPL draft, search hint, and analyst notes.

    Returns a dict with keys: spl_draft, spl_macro_name, search_hint, analyst_notes.
    Raises on LLM error — caller handles.
    """
    noisy = [s for s in sanitized if s["noise_score"] >= 0.5]
    clean = [s for s in sanitized if s["noise_score"] < 0.5]
    hunt_id_short = hunt_package_id[:8]

    ioc_summary_lines = []
    for s in sanitized[:retrohunt_ioc_cap]:  # cap prompt size
        flag = " [NOISY]" if s["noise_score"] >= 0.5 else ""
        ioc_summary_lines.append(
            f"  {s['ioc_type']}: {s['ioc']} (noise={s['noise_score']:.2f}{flag})"
        )
    ioc_summary_text = "\n".join(ioc_summary_lines)

    system, user = build_prompt(
        task_description=(
            "You are a Threat Hunting expert generating a Deep Retrohunt lead for a Splunk environment. "
            "Given a sanitized IOC list, produce:\n"
            "1. A Splunk SPL macro draft that searches all log sources for any of the clean IOCs.\n"
            "2. A suggested macro name.\n"
            "3. A plain-language search hint (1-2 sentences) for analysts using non-Splunk SIEMs.\n"
            "4. Analyst notes summarizing sanitization decisions and flagging noisy IOCs for operator review."
        ),
        context_sections=[
            ("Hunt Package ID", hunt_package_id),
            (
                "IOC Statistics",
                f"Total: {len(sanitized)} | Clean (<0.5 noise): {len(clean)} | Noisy (≥0.5 noise): {len(noisy)}",
            ),
            (f"IOC Summary (first {retrohunt_ioc_cap})", ioc_summary_text),
            ("IOC CSV (canonical)", ioc_csv[:retrohunt_csv_cap]),  # cap to avoid token overflow
        ],
        output_format=_LLM_OUTPUT_FORMAT,
        additional_instructions=(
            "For the SPL draft:\n"
            "  - Use 'index=* earliest=-24h@h latest=now' as the time range placeholder.\n"
            "  - Include a comment block at the top listing the IOC types covered.\n"
            "  - Build a `| where` clause using `cidrmatch` for IPs, `like` for domains/URLs, "
            "and `=` for hashes, CVEs.\n"
            "  - Do NOT include IOCs with noise_score >= 0.8 in the SPL query.\n"
            "  - Wrap the query in a macro definition: `[threathunt_ioc_<hunt_id_short>]`.\n"
            f"  - Use hunt ID short: {hunt_id_short}\n"
            "For analyst_notes:\n"
            "  - List each noisy IOC with the reason it was flagged.\n"
            "  - Recommend whether operator should exclude high-noise IOCs from execution.\n"
            "Return ONLY the JSON object."
        ),
    )

    response = await call_llm(
        user,
        system=system,
        provider_name=provider_name,
        model=model_name,
        max_tokens=retrohunt_tokens,
    )

    parsed = parse_json_response(response, context="deep_retrohunt_planner")
    if not isinstance(parsed, dict):
        raise ValueError(f"Expected dict from LLM, got {type(parsed).__name__}")

    return {
        "spl_draft": str(parsed.get("spl_draft", "")),
        "spl_macro_name": str(parsed.get("spl_macro_name", f"threathunt_ioc_{hunt_id_short}")),
        "search_hint": str(parsed.get("search_hint", "")),
        "analyst_notes": str(parsed.get("analyst_notes", "")),
    }


# ---------------------------------------------------------------------------
# Node entry point
# ---------------------------------------------------------------------------


async def deep_retrohunt_planner(state: HuntPipelineState) -> dict:
    """LangGraph node: Deep Retrohunt Planner.

    Sanitizes the raw IOC list deterministically, then enriches with LLM-generated
    SPL draft, search hint, and analyst notes.

    Returns ``deep_retrohunt=None`` when no atomic IOCs are available.
    """
    start = time.monotonic()
    step = "deep_retrohunt_planner"
    logs = list(state.get("step_logs") or [])
    errors = list(state.get("errors") or [])
    completed = list(state.get("completed_steps") or [])

    profile = get_effort_profile(state.get("research_effort"))

    raw_iocs: list[dict[str, Any]] = list(state.get("raw_ioc_list") or [])

    # Filter to atomic IOC types only
    atomic_iocs = [r for r in raw_iocs if str(r.get("ioc_type", "other")).lower() in _ATOMIC_TYPES]

    if not atomic_iocs:
        logger.info("deep_retrohunt_planner: no atomic IOCs found — skipping")
        elapsed = time.monotonic() - start
        logs.append(
            {
                "step": step,
                "status": "skipped",
                "elapsed_s": round(elapsed, 2),
                "tools_used": [],
                "decision": "No atomic IOCs — skipped.",
                "debug_lines": [],
            }
        )
        completed.append(step)
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
            "deep_retrohunt": None,
        }

    # ── Stage 1: deterministic sanitization ──────────────────────────────────
    try:
        sanitized = _sanitize_ioc_list(atomic_iocs)
        ioc_csv = _build_ioc_csv(sanitized)
        noisy_count = sum(1 for s in sanitized if s["noise_score"] >= 0.5)
        high_noise_count = sum(1 for s in sanitized if s["noise_score"] >= 0.8)
        logger.info(
            "deep_retrohunt_planner: sanitized %d IOCs (%d noisy, %d high-noise)",
            len(sanitized),
            noisy_count,
            high_noise_count,
        )
    except Exception as exc:
        logger.exception("deep_retrohunt_planner: deterministic stage failed: %s", exc)
        errors.append(f"{step} (sanitization): {exc}")
        elapsed = time.monotonic() - start
        logs.append(
            {
                "step": step,
                "status": "error",
                "elapsed_s": round(elapsed, 2),
                "error": str(exc),
                "tools_used": [],
                "debug_lines": [],
            }
        )
        return {
            "current_step": step,
            "completed_steps": completed,
            "step_logs": logs,
            "errors": errors,
            "deep_retrohunt": None,
        }

    # ── Stage 2: LLM enrichment ───────────────────────────────────────────────
    llm_parse_error = False
    spl_draft = ""
    spl_macro_name = f"threathunt_ioc_{state.get('hunt_package_id', 'unknown')[:8]}"
    search_hint = ""
    analyst_notes = ""

    try:
        from backend.llm.errors import LLMDisabledError

        enrichment = await _enrich_with_llm(
            sanitized,
            ioc_csv,
            state.get("hunt_package_id", "unknown"),
            provider_name=state.get("provider_name"),
            model_name=state.get("model_name"),
            retrohunt_ioc_cap=profile["retrohunt_ioc_cap"],
            retrohunt_csv_cap=profile["retrohunt_csv_cap"],
            retrohunt_tokens=profile["retrohunt_tokens"],
        )
        spl_draft = enrichment["spl_draft"]
        spl_macro_name = enrichment["spl_macro_name"] or spl_macro_name
        search_hint = enrichment["search_hint"]
        analyst_notes = enrichment["analyst_notes"]
    except Exception as exc:
        from backend.llm.errors import LLMDisabledError

        if isinstance(exc, LLMDisabledError):
            logger.warning("deep_retrohunt_planner: LLM disabled — using deterministic output only")
        else:
            logger.exception("deep_retrohunt_planner: LLM enrichment failed: %s", exc)
            errors.append(f"{step} (LLM): {exc}")
        llm_parse_error = True

    # ── Build output ──────────────────────────────────────────────────────────
    result: DeepRetrohuntLead = DeepRetrohuntLead(
        sanitized_iocs=sanitized,
        ioc_csv=ioc_csv,
        total_ioc_count=len(sanitized),
        noisy_ioc_count=noisy_count,
        high_noise_ioc_count=high_noise_count,
        spl_draft=spl_draft,
        spl_macro_name=spl_macro_name,
        search_hint=search_hint,
        analyst_notes=analyst_notes,
        llm_parse_error=llm_parse_error,
    )

    # ── Tool-calling: validate SPL draft if LLM supports tools ──────────────
    tools_used: list[str] = []
    debug_lines: list[str] = []
    decision = ""
    if spl_draft and not llm_parse_error:
        try:
            from backend.threat_hunting.agents.llm_bridge import call_llm_with_tools
            from backend.threat_hunting.agents.tools import TOOL_SPEC_BY_NAME, call_tool

            _validate_tools = [
                TOOL_SPEC_BY_NAME[n]
                for n in ("validate_spl", "defang_ioc", "noise_score")
                if n in TOOL_SPEC_BY_NAME
            ]
            if _validate_tools:
                spl_validate_prompt = (
                    f"Validate the following SPL query for syntax issues:\n{spl_draft[:2000]}\n"
                    f"Also check the top 5 IOCs for noise score. "
                    "Respond with a brief assessment."
                )
                _text, tool_calls = await call_llm_with_tools(
                    spl_validate_prompt,
                    _validate_tools,
                    provider_name=state.get("provider_name"),
                    model=state.get("model_name"),
                    max_tokens=400,
                )
                decision = _text or "SPL validation complete."
                for tc in tool_calls:
                    tool_name = tc.get("name", "")
                    tool_args = tc.get("arguments", {})
                    debug_lines.append(f"TOOL_CALL: {tool_name}({tool_args})")
                    try:
                        result_val = await call_tool(tool_name, tool_args)
                        tools_used.append(tool_name)
                        debug_lines.append(f"TOOL_RESULT: {str(result_val)[:300]}")
                    except Exception as tool_exc:  # noqa: BLE001
                        debug_lines.append(f"TOOL_ERROR: {tool_exc}")
        except Exception as llm_exc:  # noqa: BLE001
            debug_lines.append(f"TOOL_LLM_ERROR: {llm_exc}")

    elapsed = time.monotonic() - start
    logs.append(
        {
            "step": step,
            "status": "ok" if not llm_parse_error else "partial",
            "elapsed_s": round(elapsed, 2),
            "ioc_count": len(sanitized),
            "noisy_count": noisy_count,
            "effort": state.get("research_effort", "medium"),
            "tools_used": tools_used,
            "decision": decision,
            "debug_lines": debug_lines,
        }
    )
    completed.append(step)
    return {
        "current_step": step,
        "completed_steps": completed,
        "step_logs": logs,
        "errors": errors,
        "deep_retrohunt": result,
    }
