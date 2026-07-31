"""
Human-readable interpretation for audit events (issue-local-033 follow-up).

The Audit UI's ``action`` field must read as an interpretation ("Created hunt
package"), not a raw HTTP method+path or step key — ``summary`` is where the
concrete specifics belong. Two entry points:

  - ``classify_and_interpret(method, path)`` — used by ``main.py``'s
    ``audit_activity`` middleware. Category is a pure function of the route:
    ``/api/auth/*`` is "user" activity (authentication + account
    self-service), everything else mutating is "application" activity (the
    app's own state changing, whoever/whatever triggered it). ``action``
    comes from a curated per-route table with an algorithmic fallback, so a
    route added later and not yet in the table still gets *something*
    readable rather than a raw dump.
  - ``interpret_agent_step(step_key, status)`` — used by
    ``threat_hunting/agents/runner.py``'s per-node audit hook and by
    ``threat_hunting/db.py``'s ``append_run_step_log`` (SIEM/report/
    threat-intel steps, which run outside the LangGraph graph).
  - ``interpret_log_message(logger_name, message)`` /
    ``interpret_system_log(logger_name, level, message)`` — used by
    ``audit/log_bridge.py``'s ``AuditLogHandler`` for the "application"
    (ingestion/watcher) and "system" (lifecycle + WARNING+ catch-all)
    categories respectively. Free-text log lines can't be perfectly parsed;
    both fall back to something readable rather than raw when they don't
    recognise the shape.
"""

from __future__ import annotations

import re

_ID_SEGMENT_RE = re.compile(
    r"^(\{[^}]+\}|[0-9a-fA-F-]{8,}|\d+)$"  # {param}, uuid-ish/hex, or all-digits
)

_METHOD_VERB = {
    "POST": "Created",
    "PUT": "Updated",
    "PATCH": "Updated",
    "DELETE": "Deleted",
}


def _humanize_segment(segment: str) -> str:
    return segment.replace("-", " ").replace("_", " ").strip().title()


def _fallback_action(method: str, path: str) -> str:
    """Best-effort label for a route not in the curated table below."""
    segments = [s for s in path.removeprefix("/api/").split("/") if s]
    meaningful = [s for s in segments if not _ID_SEGMENT_RE.match(s)]
    resource = _humanize_segment(meaningful[-1]) if meaningful else "resource"
    verb = _METHOD_VERB.get(method, method.title())
    return f"{verb} {resource}"


def _to_regex(path_template: str) -> re.Pattern[str]:
    """Convert a ``{param}``-style path template into a compiled matcher."""
    escaped = re.escape(path_template)
    pattern = re.sub(r"\\\{[^}]+\\\}", r"[^/]+", escaped)
    return re.compile(f"^{pattern}$")


# (method, path template, action label) — matched in order, first match wins.
# Path templates use the same ``{param}`` shape FastAPI route decorators do;
# ``_to_regex`` turns each into a matcher once at import time.
_ROUTE_TABLE_RAW: list[tuple[str, str, str]] = [
    # ── Threat Hunting: packages ─────────────────────────────────────────
    ("POST", "/api/threat-hunting/packages", "Created hunt package"),
    ("PUT", "/api/threat-hunting/packages/{pkg_id}", "Updated hunt package"),
    ("DELETE", "/api/threat-hunting/packages/{pkg_id}", "Archived hunt package"),
    ("POST", "/api/threat-hunting/packages/{pkg_id}/clone", "Cloned hunt package"),
    # ── Threat Hunting: evidence ─────────────────────────────────────────
    ("POST", "/api/threat-hunting/packages/{pkg_id}/evidence/file", "Added file evidence"),
    ("POST", "/api/threat-hunting/packages/{pkg_id}/evidence/url", "Added URL evidence"),
    ("POST", "/api/threat-hunting/packages/{pkg_id}/evidence/text", "Added text evidence"),
    (
        "POST",
        "/api/threat-hunting/packages/{pkg_id}/evidence/watcher",
        "Added watcher-feed evidence",
    ),
    ("DELETE", "/api/threat-hunting/packages/{pkg_id}/evidence/{item_id}", "Removed evidence"),
    # ── Threat Hunting: generation / approval ────────────────────────────
    ("POST", "/api/threat-hunting/packages/{pkg_id}/generate", "Started hunt generation"),
    ("POST", "/api/threat-hunting/packages/{pkg_id}/approve", "Approved hunt generation"),
    ("POST", "/api/threat-hunting/packages/{pkg_id}/reject", "Rejected hunt generation"),
    ("POST", "/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/approve", "Approved hunt run"),
    ("POST", "/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/reject", "Rejected hunt run"),
    ("POST", "/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/cancel", "Cancelled hunt run"),
    (
        "PATCH",
        "/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/hypotheses/{hypothesis_id}",
        "Edited hypothesis",
    ),
    (
        "PATCH",
        "/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/hunting-leads/{lead_id}",
        "Edited hunting lead",
    ),
    (
        "PATCH",
        "/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/iocs",
        "Updated IOC verdicts",
    ),
    # ── Threat Hunting: SIEM connectors / execution ──────────────────────
    ("POST", "/api/threat-hunting/connectors", "Added SIEM connector"),
    ("PUT", "/api/threat-hunting/connectors/{conn_id}", "Updated SIEM connector"),
    ("DELETE", "/api/threat-hunting/connectors/{conn_id}", "Removed SIEM connector"),
    ("POST", "/api/threat-hunting/connectors/{conn_id}/test", "Tested SIEM connector"),
    ("POST", "/api/threat-hunting/packages/{pkg_id}/execute", "Started SIEM execution"),
    # ── Threat Hunting: reports / threat intel / comparison ──────────────
    ("POST", "/api/threat-hunting/packages/{pkg_id}/report", "Generated hunt report"),
    (
        "POST",
        "/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/report",
        "Generated hunt report",
    ),
    (
        "POST",
        "/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/threat-intel",
        "Triggered threat intel analysis",
    ),
    ("POST", "/api/threat-hunting/packages/{pkg_id}/compare", "Ran run comparison"),
    (
        "POST",
        "/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/comments",
        "Added a comment",
    ),
    (
        "DELETE",
        "/api/threat-hunting/packages/{pkg_id}/runs/{run_id}/comments/{comment_id}",
        "Deleted a comment",
    ),
    # ── Threat Hunting: Threat Intel Tracking ────────────────────────────
    (
        "POST",
        "/api/threat-hunting/tracking/hunts/{pkg_id}/exclude",
        "Changed hunt tracking visibility",
    ),
    (
        "DELETE",
        "/api/threat-hunting/tracking/hunts/{pkg_id}",
        "Removed hunt from tracking",
    ),
    # ── Smart Mappings ────────────────────────────────────────────────────
    ("POST", "/api/smart-mappings/dry-run", "Ran a smart-mapping dry run"),
    ("POST", "/api/smart-mappings/jobs", "Started a smart-mapping job"),
    ("POST", "/api/smart-mappings/proposals/{proposal_id}/approve", "Approved a mapping proposal"),
    ("POST", "/api/smart-mappings/proposals/{proposal_id}/reject", "Rejected a mapping proposal"),
    ("POST", "/api/smart-mappings/proposals/{proposal_id}/archive", "Archived a mapping proposal"),
    (
        "POST",
        "/api/smart-mappings/proposals/{proposal_id}/reenable",
        "Re-enabled a mapping proposal",
    ),
    ("POST", "/api/smart-mappings/active/run", "Ran active consolidated mapping"),
    # ── Field configuration ──────────────────────────────────────────────
    ("PUT", "/api/fields/ingest-all", "Changed ingest-all-fields setting"),
    ("PUT", "/api/fields/flatten-depth", "Changed field flatten-depth setting"),
    ("PUT", "/api/fields/core/{field_name}/enabled", "Toggled a core field"),
    ("POST", "/api/fields/custom", "Added a custom field"),
    ("PUT", "/api/fields/custom/{field_name}", "Updated a custom field"),
    ("DELETE", "/api/fields/custom/{field_name}", "Deleted a custom field"),
    # ── Normalizer ────────────────────────────────────────────────────────
    ("PUT", "/api/normalizer/config", "Updated normalizer configuration"),
    ("POST", "/api/normalizer/run", "Ran the normalizer"),
    (
        "POST",
        "/api/normalizer/mappings/versions/{version_id}/activate",
        "Activated a mapping version",
    ),
    # ── Watchers ──────────────────────────────────────────────────────────
    ("POST", "/api/watchers", "Created a watcher"),
    ("PUT", "/api/watchers/{watcher_id}", "Updated a watcher"),
    ("PUT", "/api/watchers/{watcher_id}/enabled", "Enabled/disabled a watcher"),
    ("DELETE", "/api/watchers/{watcher_id}", "Deleted a watcher"),
    ("POST", "/api/watchers/{watcher_id}/trigger", "Manually triggered a watcher"),
    # ── LLM providers ─────────────────────────────────────────────────────
    ("PUT", "/api/llm/config", "Updated LLM configuration"),
    ("POST", "/api/llm/providers", "Added an LLM provider"),
    ("PUT", "/api/llm/providers/{name}", "Updated an LLM provider"),
    ("DELETE", "/api/llm/providers/{name}", "Deleted an LLM provider"),
    ("POST", "/api/llm/providers/test", "Tested a draft LLM provider"),
    ("POST", "/api/llm/providers/discover", "Discovered models for a draft LLM provider"),
    ("POST", "/api/llm/providers/{name}/discover", "Discovered models for an LLM provider"),
    ("POST", "/api/llm/providers/{name}/test", "Tested an LLM provider"),
    # ── Natural-language query ───────────────────────────────────────────
    ("POST", "/api/query/nl", "Ran a natural-language query"),
    # ── Application settings ─────────────────────────────────────────────
    ("PUT", "/api/app/base-prefix", "Changed application base-prefix setting"),
    ("PUT", "/api/app/title", "Changed application title"),
    ("PUT", "/api/app/theme", "Changed default UI theme"),
    ("PUT", "/api/app/pagination-max", "Changed pagination-limit setting"),
    ("PUT", "/api/app/watcher-max-events", "Changed watcher max-events setting"),
    ("PUT", "/api/app/th-llm-max-retries", "Changed LLM max-retries setting"),
    ("PUT", "/api/app/th-llm-retry-backoff-seconds", "Changed LLM retry-backoff setting"),
    ("PUT", "/api/app/agent-verbosity", "Changed agent verbosity setting"),
    ("PUT", "/api/app/agent-visualization", "Changed agent visualization setting"),
    ("PUT", "/api/app/agent-show-subtasks", "Changed agent subtasks-display setting"),
    ("PUT", "/api/app/th-research-effort", "Changed default research-effort setting"),
    ("PUT", "/api/app/hunt-id-prefix", "Changed hunt ID prefix setting"),
    ("PUT", "/api/app/th-report-formats", "Changed report-formats setting"),
    ("PUT", "/api/app/agent-tools", "Changed agent tools setting"),
    ("POST", "/api/app/logo", "Uploaded application logo"),
    ("DELETE", "/api/app/logo", "Removed application logo"),
    ("POST", "/api/app/config-drift/apply", "Applied a configuration-drift fix"),
    # ── Global search / Assistant sessions ───────────────────────────────
    ("POST", "/api/search/smart", "Asked the Assistant a question"),
    ("POST", "/api/search/sessions", "Saved an Assistant session"),
    ("PUT", "/api/search/sessions/{session_id}", "Updated an Assistant session"),
    ("DELETE", "/api/search/sessions/{session_id}", "Deleted an Assistant session"),
    # ── Control (destructive DB / manual refresh) ────────────────────────
    ("POST", "/api/control/reset-db", "Reset all databases"),
    ("POST", "/api/control/reset-source/{source_name}", "Reset a source database"),
    ("POST", "/api/control/refresh/api-pull/{name}", "Manually refreshed an API-pull source"),
    ("POST", "/api/control/refresh/rss-pull/{name}", "Manually refreshed an RSS-pull source"),
    (
        "POST",
        "/api/control/refresh/remote-json-pull/{name}",
        "Manually refreshed a remote-JSON source",
    ),
    ("POST", "/api/control/refresh/api-pull", "Manually refreshed all API-pull sources"),
    ("POST", "/api/control/refresh/rss-pull", "Manually refreshed all RSS-pull sources"),
    (
        "POST",
        "/api/control/refresh/remote-json-pull",
        "Manually refreshed all remote-JSON sources",
    ),
    # ── Sources ───────────────────────────────────────────────────────────
    ("PUT", "/api/sources/listener", "Updated the listener source"),
    ("POST", "/api/sources/api-pull", "Added an API-pull source"),
    ("PUT", "/api/sources/api-pull/{name}", "Updated an API-pull source"),
    ("DELETE", "/api/sources/api-pull/{name}", "Deleted an API-pull source"),
    ("POST", "/api/sources/rss-pull", "Added an RSS-pull source"),
    ("PUT", "/api/sources/rss-pull/{name}", "Updated an RSS-pull source"),
    ("DELETE", "/api/sources/rss-pull/{name}", "Deleted an RSS-pull source"),
    ("POST", "/api/sources/remote-json-pull", "Added a remote-JSON source"),
    ("PUT", "/api/sources/remote-json-pull/{name}", "Updated a remote-JSON source"),
    ("DELETE", "/api/sources/remote-json-pull/{name}", "Deleted a remote-JSON source"),
    ("PUT", "/api/sources/threat-intel", "Updated threat intel source settings"),
    ("PUT", "/api/sources/listener/fields", "Updated listener source field mapping"),
    ("PUT", "/api/sources/{source_type}/{name}/fields", "Updated a source's field mapping"),
    ("POST", "/api/sources/preview/{source_type}", "Previewed a source"),
    ("POST", "/api/sources/preview/confirm/{preview_id}", "Confirmed a previewed source"),
    ("POST", "/api/sources/preview/cancel/{preview_id}", "Cancelled a previewed source"),
    # ── Ingest ────────────────────────────────────────────────────────────
    ("POST", "/api/ingest/listener", "Ingested pushed data (listener)"),
    ("POST", "/api/ingest/push/{source_name}", "Ingested pushed data"),
    ("POST", "/api/ingest/push-batch/{source_name}", "Ingested a pushed data batch"),
    ("POST", "/api/ingest/local/{source_name}", "Ingested a local feed upload"),
    ("POST", "/api/ingest/preview/local/{source_name}", "Previewed a local feed upload"),
    ("POST", "/api/ingest/preview/confirm/{preview_id}", "Confirmed a previewed local upload"),
    ("POST", "/api/ingest/remote/{source_name}", "Ingested a remote feed"),
]

_ROUTE_TABLE: list[tuple[str, re.Pattern[str], str]] = [
    (method, _to_regex(template), label) for method, template, label in _ROUTE_TABLE_RAW
]


def application_action(method: str, path: str) -> str:
    """Interpret a non-auth mutating request as a short human action label."""
    for table_method, pattern, label in _ROUTE_TABLE:
        if method == table_method and pattern.match(path):
            return label
    return _fallback_action(method, path)


# (path template relative to /api/auth, method) -> label. Small, closed set —
# every /api/auth/* mutating route is enumerated (no fallback needed, but
# _fallback_action still backstops a future route added here and forgotten).
_AUTH_ROUTE_TABLE_RAW: list[tuple[str, str, str]] = [
    ("PUT", "/api/auth/sso/config", "Updated SSO configuration"),
    ("POST", "/api/auth/login", "Signed in"),
    ("POST", "/api/auth/logout", "Signed out"),
    ("PUT", "/api/auth/password", "Changed own password"),
    ("PUT", "/api/auth/me/theme", "Changed UI theme"),
    ("POST", "/api/auth/users", "Created user account"),
    ("PUT", "/api/auth/users/{user_id}/role", "Changed user role"),
    ("PUT", "/api/auth/users/{user_id}/enabled", "Changed user account status"),
    ("PUT", "/api/auth/users/{user_id}/password", "Reset user password"),
    ("DELETE", "/api/auth/users/{user_id}", "Deleted user account"),
    ("PUT", "/api/auth/api-keys/config", "Updated API key settings"),
    ("POST", "/api/auth/api-keys", "Created API access key"),
    ("PUT", "/api/auth/api-keys/{client_id}", "Updated API access key"),
    ("DELETE", "/api/auth/api-keys/{client_id}", "Revoked API access key"),
    ("POST", "/api/auth/api-keys/{client_id}/test", "Tested API access key"),
]

_AUTH_ROUTE_TABLE: list[tuple[str, re.Pattern[str], str]] = [
    (method, _to_regex(template), label) for method, template, label in _AUTH_ROUTE_TABLE_RAW
]


def user_action(method: str, path: str) -> str:
    """Interpret an /api/auth/* mutating request as a short human action label."""
    for table_method, pattern, label in _AUTH_ROUTE_TABLE:
        if method == table_method and pattern.match(path):
            return label
    return _fallback_action(method, path)


def classify_and_interpret(method: str, path: str) -> tuple[str, str]:
    """Return (category, action) for a mutating /api/ request.

    Category is purely route-driven: /api/auth/* is "user" activity
    (authentication + account self-service), everything else mutating is
    "application" activity.
    """
    if path.startswith("/api/auth/"):
        return "user", user_action(method, path)
    return "application", application_action(method, path)


# ── Agent step interpretation ────────────────────────────────────────────────

#: LangGraph pipeline nodes — one final log entry per run, status in {"ok", "error"}.
#: (ok label, error label) per step.
_GRAPH_NODE_LABELS: dict[str, tuple[str, str]] = {
    "intake_classifier": ("Classified evidence intake", "Evidence intake classification failed"),
    "threat_context_builder": ("Built threat context", "Threat context building failed"),
    "deep_retrohunt_planner": (
        "Planned retrohunt IOC sanitization",
        "Retrohunt IOC sanitization planning failed",
    ),
    "hypothesis_generator": ("Generated hunting hypotheses", "Hypothesis generation failed"),
    "hunting_lead_planner": ("Planned hunting leads", "Hunting lead planning failed"),
    "ttp_analyst": ("Analyzed MITRE ATT&CK TTPs", "MITRE ATT&CK TTP analysis failed"),
    "query_drafting_agent": ("Drafted SIEM queries", "SIEM query drafting failed"),
}

#: SIEM execution steps — status in {"running", "ok", "error"} (append_run_step_log).
#: (running label, ok label, error label) per step.
_SIEM_STEP_LABELS: dict[str, tuple[str, str, str]] = {
    "siem_connect": (
        "Connecting to SIEM connector",
        "Connected to SIEM connector",
        "Failed to connect to SIEM connector",
    ),
    "siem_submit": (
        "Submitting SIEM search",
        "Submitted SIEM search",
        "Failed to submit SIEM search",
    ),
    "siem_poll": (
        "Waiting on SIEM search",
        "SIEM search finished",
        "SIEM search failed",
    ),
    "siem_fetch": (
        "Fetching SIEM results",
        "Fetched SIEM results",
        "Failed to fetch SIEM results",
    ),
    "siem_interpret": (
        "Interpreting SIEM results",
        "Interpreted SIEM results",
        "Failed to interpret SIEM results",
    ),
}


def interpret_agent_step(step_key: str, status: str) -> str:
    """Interpret an agent step_key + status pair as a short human action label."""
    if step_key in _GRAPH_NODE_LABELS:
        ok_label, error_label = _GRAPH_NODE_LABELS[step_key]
        return error_label if status == "error" else ok_label
    if step_key in _SIEM_STEP_LABELS:
        running_label, ok_label, error_label = _SIEM_STEP_LABELS[step_key]
        if status == "ok":
            return ok_label
        if status == "error":
            return error_label
        return running_label
    if step_key == "report_writer":
        return "Generated hunt report" if status != "error" else "Report generation failed"
    if step_key == "threat_intel_preliminary":
        return (
            "Ran preliminary threat intel analysis"
            if status != "error"
            else "Preliminary threat intel analysis failed"
        )
    if step_key == "threat_intel_final":
        return "Ran threat intel analysis" if status != "error" else "Threat intel analysis failed"
    return _humanize_segment(step_key)


# ── "Application" log-bridge interpretation (ingestion / watcher events) ────

# Every backend/ingestion/*.py `audit.info(...)` call uses the same shape:
# a leading identifier token followed by "key=value" pairs (confirmed across
# all 6 emitters: api_pull, local_feed, push_listener, remote_feed,
# remote_json, rss_pull, plus source_preview's 3 events). "mode=" identifies
# *how* ingestion happened; humanized here rather than left as a raw code.
_INGEST_MODE_LABELS = {
    "api_pull": "API pull",
    "local_feed": "local feed upload",
    "remote_feed": "remote feed pull",
    "remote_json": "remote JSON pull",
    "rss_pull": "RSS pull",
    "push": "push",
}

_LOG_EVENT_LABELS = {
    "listener_receive": "Received listener push",
    "source_preview_built": "Previewed a source",
    "source_added_via_preview": "Added source from preview",
    "source_preview_confirmed": "Confirmed source preview",
}

_KV_RE = re.compile(r"(\w+)=(\S+)")


def interpret_log_message(logger_name: str, message: str) -> str:
    """Interpret an ingestion/watcher log-bridge message as an action label.

    Falls back to a logger-name-derived label for any message shape not
    recognised — never surfaces nothing.
    """
    first_token, _, rest = message.partition(" ")
    if first_token == "ingest":
        kv = dict(_KV_RE.findall(rest))
        mode_label = _INGEST_MODE_LABELS.get(kv.get("mode", ""), kv.get("mode") or "ingestion")
        return f"Ingested via {mode_label}"
    if first_token in _LOG_EVENT_LABELS:
        return _LOG_EVENT_LABELS[first_token]
    return f"{_humanize_segment(logger_name.rsplit('.', 1)[-1])} activity"


# ── "System" log-bridge interpretation (lifecycle + WARNING+ catch-all) ─────

_LIFECYCLE_PREFIXES = {
    "OpenTARS startup": "Application startup",
    "OpenTARS shutting down": "Application shutdown",
}

_LEVEL_LABEL = {
    "WARNING": "Warning",
    "ERROR": "Error",
    "CRITICAL": "Critical error",
}


def interpret_system_log(logger_name: str, level: str, message: str) -> str:
    """Interpret a system-category log record (lifecycle or WARNING+) as an
    action label.

    Free-text messages from anywhere in the app can't be reliably parsed for
    *what* happened — this gives a coarse, consistent "<level> in <module>"
    classification instead, except for the dedicated lifecycle logger's own
    exact startup/shutdown messages, which get precise labels.
    """
    for prefix, label in _LIFECYCLE_PREFIXES.items():
        if message.startswith(prefix):
            return label
    module = _humanize_segment(logger_name.rsplit(".", 1)[-1]) or "application"
    level_label = _LEVEL_LABEL.get(level, level.title())
    return f"{level_label} in {module}"
