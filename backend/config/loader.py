"""
Config loader — reads feed-fields.yaml and sources.yaml.
All other modules import from here; never read YAML files directly.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


def env_with_legacy_fallback(name: str, legacy_name: str) -> str | None:
    """Read an env var by its current name, falling back to a deprecated
    legacy name with a warning (issue-local-024 rebrand: every
    ``MIZTON_THREATBOX_*`` env var was renamed to ``OPENTARS_*``). Keeps an
    already-configured deployment's override working instead of it silently
    reverting to the default the moment the env var name changed underneath
    it — see docs/rebranding-risk-analysis.md's Tier 2 discussion.
    """
    val = os.environ.get(name)
    if val is not None:
        return val
    val = os.environ.get(legacy_name)
    if val is not None:
        logger.warning(
            "%s is deprecated and will stop being read in a future release; rename it to %s",
            legacy_name,
            name,
        )
        return val
    return None


# Resolve config directory relative to project root (two levels up from this file)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIELDS_PATH = _PROJECT_ROOT / "config" / "feed-fields.yaml"
SOURCES_PATH = _PROJECT_ROOT / "config" / "sources.yaml"
DEFAULT_SOURCES_PATH = _PROJECT_ROOT / "config" / "default-sources.yaml"
APP_CONFIG_PATH = _PROJECT_ROOT / "config" / "application.yaml"


def _bootstrap_from_example(path: Path) -> None:
    """Seed *path* from a sibling ``<name>.example`` file on first read.

    application.yaml / sources.yaml / feed-fields.yaml hold live,
    operator-editable instance state (branding, ingestion sources, custom
    fields) and are gitignored so a site's edits never risk landing in a
    commit — that previously caused a deployment's git HEAD to permanently
    diverge from upstream just because someone toggled a setting. Each real
    file is seeded from its committed ``.example`` template so a fresh
    clone/deploy still starts with working defaults instead of an empty file.

    ``example`` is derived from ``path`` itself (not a separate hardcoded
    constant) so tests that monkeypatch the module-level ``*_PATH`` constants
    to an isolated ``tmp_path`` automatically get an isolated, normally-absent
    example path too — no bootstrap occurs unless a test deliberately places
    one there.
    """
    if path.exists():
        return
    example = path.with_name(path.name + ".example")
    if not example.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    logger.info("Bootstrapped %s from %s (first run)", path, example)


def _read_yaml(path: Path, *, bootstrap: bool = False) -> dict[str, Any]:
    if bootstrap:
        _bootstrap_from_example(path)
    if not path.exists():
        logger.warning("Config file missing at %s; returning empty dict", path)
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.dump(data, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)


# ── Fields ──────────────────────────────────────────────────────────────────


def load_fields() -> dict[str, Any]:
    """Return parsed feed-fields.yaml (bootstrapped from .example on first run)."""
    return _read_yaml(FIELDS_PATH, bootstrap=True)


def get_enabled_core_field_names() -> list[str]:
    """Return names of all enabled core fields."""
    data = load_fields()
    return [f["name"] for f in data.get("core_fields", []) if f.get("enabled", True)]


def get_all_field_names() -> list[str]:
    """Return names of all core + custom fields (regardless of enabled state)."""
    data = load_fields()
    core = [f["name"] for f in data.get("core_fields", [])]
    custom = [f["name"] for f in data.get("custom_fields", [])]
    return core + custom


def get_configured_field_names() -> list[str]:
    """Return names of all ENABLED core + custom fields (core first, then custom).

    prompts-032 Phase E: the "configured" canonical set offered to the LLM for
    a consolidated smart-mapping proposal when ``field_scope == 'configured'``.
    Both core and custom fields default ``enabled=True`` when the flag is
    absent. Order mirrors :func:`get_all_field_names` (core then custom) and
    duplicate names are de-duplicated, first occurrence wins.
    """
    data = load_fields()
    names: list[str] = []
    seen: set[str] = set()
    for group in ("core_fields", "custom_fields"):
        for field in data.get(group, []) or []:
            name = (field or {}).get("name")
            if not name or name in seen:
                continue
            if not (field or {}).get("enabled", True):
                continue
            names.append(name)
            seen.add(name)
    return names


def save_fields(data: dict[str, Any]) -> None:
    _write_yaml(FIELDS_PATH, data)


def load_ingest_all_fields() -> bool:
    """Return the ingest_all_fields flag from feed-fields.yaml (default True)."""
    return bool(load_fields().get("ingest_all_fields", True))


def save_ingest_all_fields(value: bool) -> None:
    """Persist the ingest_all_fields flag to feed-fields.yaml."""
    data = load_fields()
    data["ingest_all_fields"] = value
    save_fields(data)


# ── Flatten depth (prompts-015) ────────────────────────────────────────────

_FLATTEN_DEFAULT = 5
_FLATTEN_MIN = 1
_FLATTEN_MAX = 10


def load_flatten_max_depth() -> int:
    """Return the configured flatten depth for nested JSON entries.

    Default 5. Clamped to [1, 10]. Used by ingestion.parsers.flatten_entry.
    """
    raw = load_fields().get("flatten_max_depth", _FLATTEN_DEFAULT)
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return _FLATTEN_DEFAULT
    if n < _FLATTEN_MIN:
        return _FLATTEN_MIN
    if n > _FLATTEN_MAX:
        return _FLATTEN_MAX
    return n


def save_flatten_max_depth(value: int) -> None:
    """Persist the flatten_max_depth setting to feed-fields.yaml."""
    if not isinstance(value, int) or value < _FLATTEN_MIN or value > _FLATTEN_MAX:
        raise ValueError(
            f"flatten_max_depth must be an integer in [{_FLATTEN_MIN}, {_FLATTEN_MAX}]"
        )
    data = load_fields()
    data["flatten_max_depth"] = value
    save_fields(data)


# ── Sources ──────────────────────────────────────────────────────────────────


def load_sources() -> dict[str, Any]:
    """Return parsed sources.yaml (bootstrapped from .example on first run)."""
    return _read_yaml(SOURCES_PATH, bootstrap=True)


def save_sources(data: dict[str, Any]) -> None:
    _write_yaml(SOURCES_PATH, data)


# ── Default threat-intel source catalogue (prompts-042) ───────────────────────


def load_default_sources() -> list[dict[str, Any]]:
    """Return the curated default threat-intel source catalogue.

    Reads the ``threat_intel_sources`` list from config/default-sources.yaml.
    This is a read-only catalogue maintainers edit between releases; the UI
    re-reads it on each request. Returns an empty list when the file is missing
    or malformed so the catalogue card degrades gracefully.
    """
    data = _read_yaml(DEFAULT_SOURCES_PATH)
    items = data.get("threat_intel_sources", [])
    if not isinstance(items, list):
        logger.warning("threat_intel_sources in %s is not a list; ignoring", DEFAULT_SOURCES_PATH)
        return []
    return [item for item in items if isinstance(item, dict)]


# ── Application (prompts-017) ────────────────────────────────────────────────

_APP_PREFIX_DEFAULT = ""
_APP_PREFIX_MAX_LEN = 200
# Allowed: empty string OR a leading slash followed by one or more URL-safe chars,
# never ending in '/' and never containing two consecutive slashes.
# Anchored full-match.
_APP_PREFIX_RE = re.compile(r"^$|^/[A-Za-z0-9._\-/]*[A-Za-z0-9._\-]$")

# Env-var override (prompts-018). Set by opentars --base-prefix
# at uvicorn invocation time. Takes precedence over application.yaml on read.
# - absent     → read application.yaml (existing behaviour)
# - ""         → explicit root mount (yaml ignored)
# - valid val  → use as-is, log info, yaml ignored
# - invalid    → log warning, fall back to yaml
_APP_PREFIX_ENV = "OPENTARS_BASE_PREFIX"
_APP_PREFIX_ENV_LEGACY = "MIZTON_THREATBOX_BASE_PREFIX"


def _is_valid_app_prefix(value: str) -> bool:
    """Return True if value is a valid app_base_prefix per the format rules."""
    return (
        _APP_PREFIX_RE.match(value) is not None
        and "//" not in value
        and len(value) <= _APP_PREFIX_MAX_LEN
    )


def load_app_config() -> dict[str, Any]:
    """Return parsed application.yaml (bootstrapped from .example on first run)."""
    return _read_yaml(APP_CONFIG_PATH, bootstrap=True)


def load_app_base_prefix() -> str:
    """Return the active base-URL prefix (default empty string).

    Precedence:
      1. OPENTARS_BASE_PREFIX environment variable (if set; the deprecated
         MIZTON_THREATBOX_BASE_PREFIX name still works as a fallback)
      2. app_base_prefix in config/application.yaml
      3. "" (mount at root)

    The env-var path is set by the opentars runner script via
    ``--base-prefix``. When set to an empty string it explicitly means
    "mount at root" and yaml is bypassed. When set to an invalid value it
    is ignored with a warning and yaml is consulted instead.
    """
    env_raw = env_with_legacy_fallback(_APP_PREFIX_ENV, _APP_PREFIX_ENV_LEGACY)
    if env_raw is not None:
        if env_raw == "":
            logger.info(
                "app_base_prefix overridden by %s (empty string → mount at root)",
                _APP_PREFIX_ENV,
            )
            return ""
        if _is_valid_app_prefix(env_raw):
            logger.info(
                "app_base_prefix overridden by %s=%r",
                _APP_PREFIX_ENV,
                env_raw,
            )
            return env_raw
        logger.warning(
            "%s=%r is invalid; falling back to %s",
            _APP_PREFIX_ENV,
            env_raw,
            APP_CONFIG_PATH,
        )

    raw = load_app_config().get("app_base_prefix", _APP_PREFIX_DEFAULT)
    if not isinstance(raw, str):
        return _APP_PREFIX_DEFAULT
    # Be tolerant on read: silently coerce unexpected non-conforming values to "".
    # Strict validation only happens on save.
    if not _is_valid_app_prefix(raw):
        logger.warning(
            "app_base_prefix in %s is invalid (%r); ignoring and using empty prefix",
            APP_CONFIG_PATH,
            raw,
        )
        return _APP_PREFIX_DEFAULT
    return raw


def save_app_base_prefix(value: str) -> None:
    """Persist the app_base_prefix to application.yaml.

    Raises ValueError if the value is not a valid prefix per the format rules
    documented in application.yaml.
    """
    if not isinstance(value, str):
        raise ValueError("app_base_prefix must be a string")
    if len(value) > _APP_PREFIX_MAX_LEN:
        raise ValueError(f"app_base_prefix exceeds maximum length of {_APP_PREFIX_MAX_LEN}")
    if "//" in value:
        raise ValueError("app_base_prefix must not contain '//'")
    if not _APP_PREFIX_RE.match(value):
        raise ValueError(
            "app_base_prefix must be empty or start with '/', "
            "not end with '/', and use only [A-Za-z0-9._-/]"
        )
    data = load_app_config()
    data["app_base_prefix"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Operator-configurable app display title (issue-local-001-rev1) ───────────

_APP_TITLE_MAX_LEN = 80


def load_app_title() -> str:
    """Return the configured display title (empty string when unset).

    An empty string means "use the default 'OpenTARS'". The value is
    branding-only; the About page always shows the static product name.
    """
    raw = load_app_config().get("app_title", "")
    if not isinstance(raw, str):
        return ""
    return raw.strip()


def save_app_title(value: str) -> None:
    """Persist app_title to application.yaml.

    Raises ValueError when the value is too long or contains newlines.
    An empty string is valid (means "use the default").
    """
    if not isinstance(value, str):
        raise ValueError("app_title must be a string")
    value = value.strip()
    if "\n" in value or "\r" in value:
        raise ValueError("app_title must not contain newlines")
    if len(value) > _APP_TITLE_MAX_LEN:
        raise ValueError(f"app_title exceeds the maximum length of {_APP_TITLE_MAX_LEN} characters")
    data = load_app_config()
    data["app_title"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Instance-wide default UI theme (issue-local-016) ─────────────────────────

_VALID_THEMES = {"classic", "energy", "light", "ocean"}


def load_default_theme() -> str:
    """Return the instance-wide default theme (falls back to 'classic').

    This is what unauthenticated visitors (e.g. the login screen) see, and
    what a signed-in user sees when they haven't set a personal override
    (users.theme is NULL — see backend/auth/db.py).
    """
    raw = load_app_config().get("theme", "classic")
    if raw not in _VALID_THEMES:
        return "classic"
    return raw


def save_default_theme(value: str) -> None:
    """Persist the instance-wide default theme to application.yaml."""
    if value not in _VALID_THEMES:
        raise ValueError(f"theme must be one of {sorted(_VALID_THEMES)}")
    data = load_app_config()
    data["theme"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Normalized viewer pagination cap (prompts-043) ───────────────────────────

# Ceiling on rows the Normalized Feeds viewer pulls in a single request. The
# viewer paginates/filters/searches client-side over this window, so this caps
# the working set rather than a per-page size. Default 1000, bounded.
_PAGINATION_MAX_DEFAULT = 1000
_PAGINATION_MAX_MIN = 50
_PAGINATION_MAX_MAX = 100_000


def load_app_pagination_max() -> int:
    """Return the configured Normalized-viewer pagination cap (default 1000).

    Non-integer or out-of-range values on disk fall back to the default with a
    warning, so a malformed config never breaks the viewer.
    """
    raw = load_app_config().get("pagination_max", _PAGINATION_MAX_DEFAULT)
    try:
        n = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "pagination_max in %s is not an integer (%r); using default %d",
            APP_CONFIG_PATH,
            raw,
            _PAGINATION_MAX_DEFAULT,
        )
        return _PAGINATION_MAX_DEFAULT
    if n < _PAGINATION_MAX_MIN or n > _PAGINATION_MAX_MAX:
        logger.warning(
            "pagination_max=%d is out of range [%d, %d]; using default %d",
            n,
            _PAGINATION_MAX_MIN,
            _PAGINATION_MAX_MAX,
            _PAGINATION_MAX_DEFAULT,
        )
        return _PAGINATION_MAX_DEFAULT
    return n


def save_app_pagination_max(value: int) -> None:
    """Persist the Normalized-viewer pagination cap to application.yaml.

    Raises ValueError when the value is not an integer in the supported range.
    Booleans are rejected explicitly (bool is a subclass of int).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("pagination_max must be an integer")
    if value < _PAGINATION_MAX_MIN or value > _PAGINATION_MAX_MAX:
        raise ValueError(
            f"pagination_max must be between {_PAGINATION_MAX_MIN} and {_PAGINATION_MAX_MAX}"
        )
    data = load_app_config()
    data["pagination_max"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Watcher event retention cap (issue_local_006) ────────────────────────────

# Global ceiling on how many triggered events each watcher retains, and the
# hard limit for the Watcher Details full-list view. Default 1000, bounded.
_WATCHER_MAX_EVENTS_DEFAULT = 1000
_WATCHER_MAX_EVENTS_MIN = 10
_WATCHER_MAX_EVENTS_MAX = 100_000


def load_watcher_max_events() -> int:
    """Return the configured per-watcher event retention cap (default 1000).

    Non-integer or out-of-range values on disk fall back to the default with a
    warning, so a malformed config never breaks watcher evaluation.
    """
    raw = load_app_config().get("watcher_max_events", _WATCHER_MAX_EVENTS_DEFAULT)
    try:
        n = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "watcher_max_events in %s is not an integer (%r); using default %d",
            APP_CONFIG_PATH,
            raw,
            _WATCHER_MAX_EVENTS_DEFAULT,
        )
        return _WATCHER_MAX_EVENTS_DEFAULT
    if n < _WATCHER_MAX_EVENTS_MIN or n > _WATCHER_MAX_EVENTS_MAX:
        logger.warning(
            "watcher_max_events=%d is out of range [%d, %d]; using default %d",
            n,
            _WATCHER_MAX_EVENTS_MIN,
            _WATCHER_MAX_EVENTS_MAX,
            _WATCHER_MAX_EVENTS_DEFAULT,
        )
        return _WATCHER_MAX_EVENTS_DEFAULT
    return n


def save_watcher_max_events(value: int) -> None:
    """Persist the per-watcher event retention cap to application.yaml.

    Raises ValueError when the value is not an integer in the supported range.
    Booleans are rejected explicitly (bool is a subclass of int).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("watcher_max_events must be an integer")
    if value < _WATCHER_MAX_EVENTS_MIN or value > _WATCHER_MAX_EVENTS_MAX:
        raise ValueError(
            f"watcher_max_events must be between {_WATCHER_MAX_EVENTS_MIN} "
            f"and {_WATCHER_MAX_EVENTS_MAX}"
        )
    data = load_app_config()
    data["watcher_max_events"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Threat Hunting LLM call retry/backoff (issue-local-014) ─────────────────

# How many times a threat-hunting agent node retries a single LLM call before
# giving up and recording the error (in addition to the first attempt), and
# the base delay for the exponential backoff between attempts. Covers
# transient transport/5xx failures AND "empty content" responses caused by
# the output-token budget being exhausted (finish_reason=length) — neither
# of which the low-level HTTP client's own retry (backend/llm/client.py)
# fully absorbs on its own, since the latter is a successful-response
# condition, not a transport failure.
_TH_LLM_MAX_RETRIES_DEFAULT = 3
_TH_LLM_MAX_RETRIES_MIN = 0
_TH_LLM_MAX_RETRIES_MAX = 10

_TH_LLM_RETRY_BACKOFF_SECONDS_DEFAULT = 2.0
_TH_LLM_RETRY_BACKOFF_SECONDS_MIN = 0.1
_TH_LLM_RETRY_BACKOFF_SECONDS_MAX = 60.0


def load_th_llm_max_retries() -> int:
    """Return the configured max retry count for a single TH agent LLM call."""
    raw = load_app_config().get("th_llm_max_retries", _TH_LLM_MAX_RETRIES_DEFAULT)
    try:
        n = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "th_llm_max_retries in %s is not an integer (%r); using default %d",
            APP_CONFIG_PATH,
            raw,
            _TH_LLM_MAX_RETRIES_DEFAULT,
        )
        return _TH_LLM_MAX_RETRIES_DEFAULT
    if n < _TH_LLM_MAX_RETRIES_MIN or n > _TH_LLM_MAX_RETRIES_MAX:
        logger.warning(
            "th_llm_max_retries=%d is out of range [%d, %d]; using default %d",
            n,
            _TH_LLM_MAX_RETRIES_MIN,
            _TH_LLM_MAX_RETRIES_MAX,
            _TH_LLM_MAX_RETRIES_DEFAULT,
        )
        return _TH_LLM_MAX_RETRIES_DEFAULT
    return n


def save_th_llm_max_retries(value: int) -> None:
    """Persist the TH agent LLM-call max-retry count to application.yaml."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("th_llm_max_retries must be an integer")
    if value < _TH_LLM_MAX_RETRIES_MIN or value > _TH_LLM_MAX_RETRIES_MAX:
        raise ValueError(
            f"th_llm_max_retries must be between {_TH_LLM_MAX_RETRIES_MIN} "
            f"and {_TH_LLM_MAX_RETRIES_MAX}"
        )
    data = load_app_config()
    data["th_llm_max_retries"] = value
    _write_yaml(APP_CONFIG_PATH, data)


def load_th_llm_retry_backoff_seconds() -> float:
    """Return the configured base backoff (seconds) between TH LLM-call retries."""
    raw = load_app_config().get(
        "th_llm_retry_backoff_seconds", _TH_LLM_RETRY_BACKOFF_SECONDS_DEFAULT
    )
    try:
        n = float(raw)
    except (TypeError, ValueError):
        logger.warning(
            "th_llm_retry_backoff_seconds in %s is not a number (%r); using default %s",
            APP_CONFIG_PATH,
            raw,
            _TH_LLM_RETRY_BACKOFF_SECONDS_DEFAULT,
        )
        return _TH_LLM_RETRY_BACKOFF_SECONDS_DEFAULT
    if n < _TH_LLM_RETRY_BACKOFF_SECONDS_MIN or n > _TH_LLM_RETRY_BACKOFF_SECONDS_MAX:
        logger.warning(
            "th_llm_retry_backoff_seconds=%s is out of range [%s, %s]; using default %s",
            n,
            _TH_LLM_RETRY_BACKOFF_SECONDS_MIN,
            _TH_LLM_RETRY_BACKOFF_SECONDS_MAX,
            _TH_LLM_RETRY_BACKOFF_SECONDS_DEFAULT,
        )
        return _TH_LLM_RETRY_BACKOFF_SECONDS_DEFAULT
    return n


def save_th_llm_retry_backoff_seconds(value: float) -> None:
    """Persist the TH agent LLM-call retry backoff base (seconds) to application.yaml."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("th_llm_retry_backoff_seconds must be a number")
    n = float(value)
    if n < _TH_LLM_RETRY_BACKOFF_SECONDS_MIN or n > _TH_LLM_RETRY_BACKOFF_SECONDS_MAX:
        raise ValueError(
            "th_llm_retry_backoff_seconds must be between "
            f"{_TH_LLM_RETRY_BACKOFF_SECONDS_MIN} and {_TH_LLM_RETRY_BACKOFF_SECONDS_MAX}"
        )
    data = load_app_config()
    data["th_llm_retry_backoff_seconds"] = n
    _write_yaml(APP_CONFIG_PATH, data)


# ── Threat Hunting pipeline per-node timeout (issue-local-034) ──────────────

# Wall-clock ceiling for a single LangGraph node to yield (runner.py wraps
# each graph.astream() step in asyncio.wait_for with this value) — covers an
# unresponsive LLM backend, a stuck fetch, or a hung tool call uniformly.
# Diagnosed against a real failure (TH67, 4 runs): genuine query_drafting_agent
# LLM slowness/retries (transport timeouts on both configured providers)
# pushed past the previous hardcoded 600s. Raised to 900s by default and made
# configurable rather than raised again blindly next time.
_TH_NODE_TIMEOUT_SECONDS_DEFAULT = 900
_TH_NODE_TIMEOUT_SECONDS_MIN = 60
_TH_NODE_TIMEOUT_SECONDS_MAX = 3600


def load_th_node_timeout_seconds() -> int:
    """Return the configured per-node timeout (seconds) for the TH pipeline."""
    raw = load_app_config().get("th_node_timeout_seconds", _TH_NODE_TIMEOUT_SECONDS_DEFAULT)
    try:
        n = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "th_node_timeout_seconds in %s is not an integer (%r); using default %d",
            APP_CONFIG_PATH,
            raw,
            _TH_NODE_TIMEOUT_SECONDS_DEFAULT,
        )
        return _TH_NODE_TIMEOUT_SECONDS_DEFAULT
    if n < _TH_NODE_TIMEOUT_SECONDS_MIN or n > _TH_NODE_TIMEOUT_SECONDS_MAX:
        logger.warning(
            "th_node_timeout_seconds=%d is out of range [%d, %d]; using default %d",
            n,
            _TH_NODE_TIMEOUT_SECONDS_MIN,
            _TH_NODE_TIMEOUT_SECONDS_MAX,
            _TH_NODE_TIMEOUT_SECONDS_DEFAULT,
        )
        return _TH_NODE_TIMEOUT_SECONDS_DEFAULT
    return n


def save_th_node_timeout_seconds(value: int) -> None:
    """Persist the TH pipeline per-node timeout (seconds) to application.yaml."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("th_node_timeout_seconds must be an integer")
    if value < _TH_NODE_TIMEOUT_SECONDS_MIN or value > _TH_NODE_TIMEOUT_SECONDS_MAX:
        raise ValueError(
            f"th_node_timeout_seconds must be between {_TH_NODE_TIMEOUT_SECONDS_MIN} "
            f"and {_TH_NODE_TIMEOUT_SECONDS_MAX}"
        )
    data = load_app_config()
    data["th_node_timeout_seconds"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Agent workflow verbosity (issue-local-004) ───────────────────────────────
# Controls how much live pipeline telemetry is surfaced in the UI.
#   info    — clean summary; show current step only
#   verbose — animated pipeline card: per-step status, tools, timing, item counts
#   debug   — verbose + scoped backend log buffer in a bottom textbox

_AGENT_VERBOSITY_DEFAULT = "debug"  # issue-local-012: changed from "info"
_AGENT_VERBOSITY_VALUES = frozenset({"info", "verbose", "debug"})


def load_agent_verbosity() -> str:
    """Return the configured agentic workflow verbosity level (default 'info')."""
    raw = load_app_config().get("agent_workflow_verbosity", _AGENT_VERBOSITY_DEFAULT)
    if raw not in _AGENT_VERBOSITY_VALUES:
        logger.warning(
            "agent_workflow_verbosity %r is not valid; using default %r",
            raw,
            _AGENT_VERBOSITY_DEFAULT,
        )
        return _AGENT_VERBOSITY_DEFAULT
    return str(raw)


def save_agent_verbosity(value: str) -> None:
    """Persist the agentic workflow verbosity level to application.yaml."""
    if not isinstance(value, str) or value not in _AGENT_VERBOSITY_VALUES:
        raise ValueError(
            f"agent_workflow_verbosity must be one of: {sorted(_AGENT_VERBOSITY_VALUES)}"
        )
    data = load_app_config()
    data["agent_workflow_verbosity"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Agent workflow visualization style (issue-local-004) ─────────────────────
# Controls which rendering mode is used for Verbose / Debug views.
#   timeline  — animated vertical node list (no extra deps, default)
#   mermaid   — live Mermaid flowchart diagram (lazy-loaded)
#   reactflow — interactive ReactFlow node/edge graph (lazy-loaded)

_AGENT_VISUALIZATION_DEFAULT = "reactflow"  # issue-local-012: changed from "timeline"
_AGENT_VISUALIZATION_VALUES = frozenset({"timeline", "mermaid", "reactflow"})


def load_agent_visualization() -> str:
    """Return the configured workflow visualization style (default 'timeline')."""
    raw = load_app_config().get("agent_workflow_visualization", _AGENT_VISUALIZATION_DEFAULT)
    if raw not in _AGENT_VISUALIZATION_VALUES:
        logger.warning(
            "agent_workflow_visualization %r is not valid; using default %r",
            raw,
            _AGENT_VISUALIZATION_DEFAULT,
        )
        return _AGENT_VISUALIZATION_DEFAULT
    return str(raw)


def save_agent_visualization(value: str) -> None:
    """Persist the workflow visualization style to application.yaml."""
    if not isinstance(value, str) or value not in _AGENT_VISUALIZATION_VALUES:
        raise ValueError(
            f"agent_workflow_visualization must be one of: {sorted(_AGENT_VISUALIZATION_VALUES)}"
        )
    data = load_app_config()
    data["agent_workflow_visualization"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Threat Hunting research effort (issue-local-004) ─────────────────────────
# Controls how deeply agents analyse evidence.
#   high   — more hypotheses/leads, larger token budgets, bigger IOC caps
#   medium — current defaults (balanced)
#   low    — minimal output; always runs IOC extraction + deep retrohunt

_TH_RESEARCH_EFFORT_DEFAULT = "high"  # issue-local-012: changed from "medium"
_TH_RESEARCH_EFFORT_VALUES = frozenset({"high", "medium", "low"})


def load_th_research_effort() -> str:
    """Return the configured TH research effort level (default 'medium')."""
    raw = load_app_config().get("th_research_effort", _TH_RESEARCH_EFFORT_DEFAULT)
    if raw not in _TH_RESEARCH_EFFORT_VALUES:
        logger.warning(
            "th_research_effort %r is not valid; using default %r",
            raw,
            _TH_RESEARCH_EFFORT_DEFAULT,
        )
        return _TH_RESEARCH_EFFORT_DEFAULT
    return str(raw)


def save_th_research_effort(value: str) -> None:
    """Persist the TH research effort level to application.yaml."""
    if not isinstance(value, str) or value not in _TH_RESEARCH_EFFORT_VALUES:
        raise ValueError(f"th_research_effort must be one of: {sorted(_TH_RESEARCH_EFFORT_VALUES)}")
    data = load_app_config()
    data["th_research_effort"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Threat Hunting report formats (issue-local-004) ──────────────────────────
# Which formats to generate when a hunt report is created.
# Both default to True.

_TH_REPORT_FORMATS_DEFAULT: dict[str, bool] = {"pdf": True, "markdown": True}
_TH_REPORT_FORMAT_KEYS = frozenset({"pdf", "markdown"})


def load_th_report_formats() -> dict[str, bool]:
    """Return the configured report-format toggles (both default True)."""
    raw = load_app_config().get("th_report_formats", {})
    if not isinstance(raw, dict):
        logger.warning("th_report_formats in %s is not a dict; using defaults", APP_CONFIG_PATH)
        return dict(_TH_REPORT_FORMATS_DEFAULT)
    result = dict(_TH_REPORT_FORMATS_DEFAULT)
    for key in _TH_REPORT_FORMAT_KEYS:
        if key in raw:
            result[key] = bool(raw[key])
    return result


def save_th_report_formats(value: dict[str, bool]) -> None:
    """Persist the report-format toggles to application.yaml."""
    if not isinstance(value, dict):
        raise ValueError("th_report_formats must be a dict with keys: pdf, markdown")
    for key in value:
        if key not in _TH_REPORT_FORMAT_KEYS:
            raise ValueError(f"Unknown report format key: {key!r}. Allowed: pdf, markdown")
        if not isinstance(value[key], bool):
            raise ValueError(f"th_report_formats[{key!r}] must be a boolean")
    data = load_app_config()
    data["th_report_formats"] = dict(value)
    _write_yaml(APP_CONFIG_PATH, data)


# ── Threat Hunting HuntID prefix (issue-local-018) ────────────────────────────
# The human-readable prefix used to build each hunt package's HuntID
# (f"{prefix}{hunt_seq:02d}", e.g. "TH01") and, transitively, each of its
# runs' Run ID (f"{hunt_id}-X{run_seq:02d}", e.g. "TH01-X01"). Computed
# dynamically from this setting at read time (not baked into a stored
# string), so changing the prefix relabels every package/run consistently.

_TH_HUNT_ID_PREFIX_DEFAULT = "TH"
_TH_HUNT_ID_PREFIX_MAX_LEN = 8


def load_hunt_id_prefix() -> str:
    """Return the configured HuntID prefix (default 'TH')."""
    raw = load_app_config().get("hunt_id_prefix", _TH_HUNT_ID_PREFIX_DEFAULT)
    if (
        not isinstance(raw, str)
        or not raw.isalnum()
        or not (1 <= len(raw) <= _TH_HUNT_ID_PREFIX_MAX_LEN)
    ):
        logger.warning(
            "hunt_id_prefix %r is not valid; using default %r", raw, _TH_HUNT_ID_PREFIX_DEFAULT
        )
        return _TH_HUNT_ID_PREFIX_DEFAULT
    return raw


def save_hunt_id_prefix(value: str) -> None:
    """Persist the HuntID prefix to application.yaml."""
    if (
        not isinstance(value, str)
        or not value.isalnum()
        or not (1 <= len(value) <= _TH_HUNT_ID_PREFIX_MAX_LEN)
    ):
        raise ValueError(
            f"hunt_id_prefix must be an alphanumeric string of 1-{_TH_HUNT_ID_PREFIX_MAX_LEN} characters"
        )
    data = load_app_config()
    data["hunt_id_prefix"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Agent tools + document parsers toggle (issue-007) ────────────────────────
# Controls which LLM-callable tools and document parsers are offered to agents.
# All default to True (fully enabled). The 7 keys are kept in sync with
# TOOL_METADATA in backend/threat_hunting/agents/tools.py.

_AGENT_TOOLS_DEFAULT: dict[str, bool] = {
    "extract_iocs": True,
    "defang_ioc": True,
    "noise_score": True,
    "mitre_lookup": True,
    "validate_spl": True,
    "refetch_url": True,
    "docling": True,  # PDF document parser; only takes effect when docling is installed
}
_AGENT_TOOLS_KEYS = frozenset(_AGENT_TOOLS_DEFAULT.keys())


def load_agent_tools() -> dict[str, bool]:
    """Return the enabled/disabled toggle map for agent tools + document parsers.

    All 7 tools default to True.  Missing keys in application.yaml are filled
    from the defaults so that new tools added in future releases are enabled
    automatically without requiring a config migration.
    """
    raw = load_app_config().get("agent_tools", {})
    if not isinstance(raw, dict):
        logger.warning("agent_tools in %s is not a dict; using defaults", APP_CONFIG_PATH)
        return dict(_AGENT_TOOLS_DEFAULT)
    result = dict(_AGENT_TOOLS_DEFAULT)
    for key in _AGENT_TOOLS_KEYS:
        if key in raw:
            result[key] = bool(raw[key])
    return result


def save_agent_tools(value: dict[str, bool]) -> None:
    """Persist the agent-tools toggle map to application.yaml.

    Raises:
        ValueError: if *value* contains unknown keys or non-bool values.
    """
    if not isinstance(value, dict):
        raise ValueError("agent_tools must be a dict mapping tool names to booleans")
    for key in value:
        if key not in _AGENT_TOOLS_KEYS:
            raise ValueError(
                f"Unknown agent tool key: {key!r}. Allowed: {sorted(_AGENT_TOOLS_KEYS)}"
            )
        if not isinstance(value[key], bool):
            raise ValueError(f"agent_tools[{key!r}] must be a boolean")
    data = load_app_config()
    # Merge: keep existing keys not in value (future-proof against partial saves)
    existing = data.get("agent_tools", {})
    if isinstance(existing, dict):
        merged = {**existing, **value}
    else:
        merged = dict(value)
    data["agent_tools"] = merged
    _write_yaml(APP_CONFIG_PATH, data)


# ── Authentication toggle (prompts-045) ──────────────────────────────────────
# Env-var override set by opentars --enable-auth at uvicorn
# invocation time. Takes precedence over application.yaml on read.
#   - absent              → read application.yaml (default false)
#   - "1"/"true"/"yes"/"on" (case-insensitive) → auth ON
#   - anything else       → auth OFF
# When auth is OFF the app is fully open, exactly as before prompts-045.
_AUTH_ENABLED_ENV = "OPENTARS_ENABLE_AUTH"
_AUTH_ENABLED_ENV_LEGACY = "MIZTON_THREATBOX_ENABLE_AUTH"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def load_auth_enabled() -> bool:
    """Return whether authentication enforcement is enabled (default False).

    Precedence:
      1. OPENTARS_ENABLE_AUTH environment variable (if set; the deprecated
         MIZTON_THREATBOX_ENABLE_AUTH name still works as a fallback)
      2. auth_enabled in config/application.yaml
      3. False (app fully open)
    """
    env_raw = env_with_legacy_fallback(_AUTH_ENABLED_ENV, _AUTH_ENABLED_ENV_LEGACY)
    if env_raw is not None:
        enabled = env_raw.strip().lower() in _TRUTHY
        logger.info(
            "auth_enabled overridden by %s=%r → %s",
            _AUTH_ENABLED_ENV,
            env_raw,
            enabled,
        )
        return enabled
    return bool(load_app_config().get("auth_enabled", False))


def save_auth_enabled(value: bool) -> None:
    """Persist the auth_enabled flag to application.yaml."""
    if not isinstance(value, bool):
        raise ValueError("auth_enabled must be a boolean")
    data = load_app_config()
    data["auth_enabled"] = value
    _write_yaml(APP_CONFIG_PATH, data)


# ── Programmatic API access toggle (issue-local-029) ──────────────────────────
# Deliberately separate from auth_enabled: this only controls whether an
# Authorization: Bearer <client_id>.<secret> API key is ALSO accepted as a
# credential alongside the session cookie — it never widens access when
# auth_enabled=False, since that already means "app fully open" and the
# auth_enforcement middleware short-circuits before ever inspecting either
# credential type.


def load_api_access_enabled() -> bool:
    """Return whether API-key authentication is enabled (default False)."""
    return bool(load_app_config().get("api_access_enabled", False))


def save_api_access_enabled(value: bool) -> None:
    """Persist the api_access_enabled flag to application.yaml."""
    if not isinstance(value, bool):
        raise ValueError("api_access_enabled must be a boolean")
    data = load_app_config()
    data["api_access_enabled"] = value
    _write_yaml(APP_CONFIG_PATH, data)


_COOKIE_SECURE_ENV = "OPENTARS_COOKIE_SECURE"
_COOKIE_SECURE_ENV_LEGACY = "MIZTON_THREATBOX_COOKIE_SECURE"
_FALSEY = frozenset({"0", "false", "no", "off"})


def load_cookie_secure() -> bool | None:
    """Return the session-cookie ``Secure`` override, or None for auto-detect.

    Behind a TLS-terminating proxy the request scheme is plain HTTP and the only
    signal is the spoofable ``X-Forwarded-Proto`` header. Operators who serve
    over HTTPS in production can force the ``Secure`` flag instead of trusting
    that header.

    Precedence:
      1. OPENTARS_COOKIE_SECURE env (true/false, or "auto"; the deprecated
         MIZTON_THREATBOX_COOKIE_SECURE name still works as a fallback)
      2. cookie_secure in application.yaml (bool, or "auto")
      3. None → auto-detect from the request scheme / X-Forwarded-Proto
    """
    env_raw = env_with_legacy_fallback(_COOKIE_SECURE_ENV, _COOKIE_SECURE_ENV_LEGACY)
    if env_raw is not None:
        val = env_raw.strip().lower()
        if val in _TRUTHY:
            return True
        if val in _FALSEY:
            return False
        return None  # "auto" or anything else
    raw = load_app_config().get("cookie_secure", "auto")
    if isinstance(raw, bool):
        return raw
    return None


# ── Branding logo (prompts-045) ──────────────────────────────────────────────

# Path (relative to project root) of the uploaded branding logo, or "" when
# none is configured and the default icon is used. Stored in application.yaml;
# the image bytes live under data/branding/.
_LOGO_PATH_DEFAULT = ""
_LOGO_PATH_MAX_LEN = 500


def load_logo_path() -> str:
    """Return the configured branding logo path (relative), or "" if unset."""
    raw = load_app_config().get("logo_path", _LOGO_PATH_DEFAULT)
    if not isinstance(raw, str):
        return _LOGO_PATH_DEFAULT
    return raw


def save_logo_path(value: str) -> None:
    """Persist the branding logo path to application.yaml.

    Accepts "" (no logo) or a project-relative path under data/branding/.
    Rejects absolute paths and parent-directory traversal.
    """
    if not isinstance(value, str):
        raise ValueError("logo_path must be a string")
    if len(value) > _LOGO_PATH_MAX_LEN:
        raise ValueError(f"logo_path exceeds maximum length of {_LOGO_PATH_MAX_LEN}")
    if value:
        norm = value.replace("\\", "/")
        if norm.startswith("/") or ".." in norm.split("/"):
            raise ValueError("logo_path must be a relative path without '..'")
        if not norm.startswith("data/branding/"):
            raise ValueError("logo_path must be under data/branding/")
    data = load_app_config()
    data["logo_path"] = value
    _write_yaml(APP_CONFIG_PATH, data)


_BRANDING_DIR = _PROJECT_ROOT / "data" / "branding"


def resolve_logo_file() -> Path | None:
    """Return the on-disk branding logo Path if configured and present, else None.

    Shared by the /api/app/logo route and PDF report generation. Defends
    against a tampered application.yaml: the stored path must resolve to a
    real file inside data/branding/ (no traversal escape).
    """
    rel = load_logo_path()
    if not rel:
        return None
    fp = (_PROJECT_ROOT / rel).resolve()
    try:
        fp.relative_to(_BRANDING_DIR.resolve())
    except ValueError:
        return None
    return fp if fp.is_file() else None


# ── Password policy (prompts-046) ────────────────────────────────────────────
#
# The password strength rules are operator-configurable. Two knobs:
#   password_min_length        minimum length in characters (clamped [8, 64])
#   password_required_classes  how many of the four character classes
#                              {lowercase, uppercase, digit, symbol} a password
#                              must contain (clamped [1, 4])
# The 72-byte bcrypt ceiling is a hard limit and is NOT configurable. The
# minimum is measured in *characters* but the maximum is enforced in *bytes*
# (72). The min-length ceiling is therefore 64 (not 72) so a password meeting
# the minimum always has byte headroom for some multi-byte characters and the
# policy can never become effectively unsatisfiable for non-ASCII input.
_PASSWORD_MIN_LEN_DEFAULT = 8
_PASSWORD_MIN_LEN_FLOOR = 8  # never allow a weaker minimum than 8
_PASSWORD_MIN_LEN_CEIL = 64  # leaves byte headroom under the 72-byte cap
_PASSWORD_CLASSES_DEFAULT = 3
_PASSWORD_CLASSES_MIN = 1
_PASSWORD_CLASSES_MAX = 4
_PASSWORD_MAX_BYTES = 72  # bcrypt hard limit (fixed)


def _clamp_int(raw: Any, default: int, lo: int, hi: int, label: str) -> int:
    try:
        n = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "%s in %s is not an integer (%r); using default %d",
            label,
            APP_CONFIG_PATH,
            raw,
            default,
        )
        return default
    if n < lo or n > hi:
        clamped = min(max(n, lo), hi)
        logger.warning(
            "%s=%d is out of range [%d, %d]; clamping to %d",
            label,
            n,
            lo,
            hi,
            clamped,
        )
        return clamped
    return n


def load_password_policy() -> dict[str, int]:
    """Return the configured password policy (with safe, clamped defaults).

    Shape: ``{"min_length": int, "required_classes": int, "max_bytes": 72}``.
    A malformed or out-of-range value never weakens security below the floor
    (min length >= 8, classes in [1, 4]); it is clamped with a warning.

    This runs on the unauthenticated ``GET /api/auth/status`` endpoint, so a
    corrupt ``application.yaml`` (invalid YAML, or a non-mapping top level) must
    not surface as a 500. On any read failure we fall back to defaults.
    """
    try:
        cfg = load_app_config()
        if not isinstance(cfg, dict):
            raise TypeError(f"application.yaml top level is {type(cfg).__name__}, not a mapping")
    except (yaml.YAMLError, OSError, TypeError) as exc:
        logger.warning(
            "Could not read password policy from %s (%s); using defaults",
            APP_CONFIG_PATH,
            exc,
        )
        cfg = {}
    min_length = _clamp_int(
        cfg.get("password_min_length", _PASSWORD_MIN_LEN_DEFAULT),
        _PASSWORD_MIN_LEN_DEFAULT,
        _PASSWORD_MIN_LEN_FLOOR,
        _PASSWORD_MIN_LEN_CEIL,
        "password_min_length",
    )
    required_classes = _clamp_int(
        cfg.get("password_required_classes", _PASSWORD_CLASSES_DEFAULT),
        _PASSWORD_CLASSES_DEFAULT,
        _PASSWORD_CLASSES_MIN,
        _PASSWORD_CLASSES_MAX,
        "password_required_classes",
    )
    return {
        "min_length": min_length,
        "required_classes": required_classes,
        "max_bytes": _PASSWORD_MAX_BYTES,
    }


# ── Decompression size cap (prompts-021B) ────────────────────────────────────

_MAX_DECOMPRESSED_DEFAULT = 100 * 1024 * 1024  # 100 MiB
_MAX_DECOMPRESSED_MIN = 1024  # 1 KiB lower bound (sanity)


# ── Agent workflow granular subtasks toggle (issue-local-012) ────────────────
# Controls whether the workflow diagram shows derived granular subtask nodes
# (evidence items per intake step, tool-call nodes per agent step) in addition
# to the main pipeline and evidence nodes.
#   false — show main nodes only (default)
#   true  — also show granular subtask nodes (derived from tools_used/intake_sources)

_AGENT_SHOW_SUBTASKS_DEFAULT = False


def load_agent_show_subtasks() -> bool:
    """Return whether granular subtask nodes are shown in the workflow diagram."""
    raw = load_app_config().get("agent_workflow_show_subtasks", _AGENT_SHOW_SUBTASKS_DEFAULT)
    return bool(raw)


def save_agent_show_subtasks(value: bool) -> None:
    """Persist the agent workflow show_subtasks flag to application.yaml."""
    if not isinstance(value, bool):
        raise ValueError("agent_workflow_show_subtasks must be a boolean")
    data = load_app_config()
    data["agent_workflow_show_subtasks"] = value
    _write_yaml(APP_CONFIG_PATH, data)


def load_max_decompressed_bytes() -> int:
    """Return the configured cap (bytes) for decompressed feed payloads.

    Default 100 MiB. Values below ``_MAX_DECOMPRESSED_MIN`` are coerced
    up to that floor with a warning. Non-integer values fall back to
    the default with a warning. Used by
    ``backend.ingestion.decompression.decompress_if_needed`` via the
    callers in ``local_feed``, ``remote_feed`` and ``preview``.
    """
    raw = load_app_config().get("max_decompressed_bytes", _MAX_DECOMPRESSED_DEFAULT)
    try:
        n = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "max_decompressed_bytes in %s is not an integer (%r); using default %d",
            APP_CONFIG_PATH,
            raw,
            _MAX_DECOMPRESSED_DEFAULT,
        )
        return _MAX_DECOMPRESSED_DEFAULT
    if n < _MAX_DECOMPRESSED_MIN:
        logger.warning(
            "max_decompressed_bytes=%d is below floor %d; coercing up",
            n,
            _MAX_DECOMPRESSED_MIN,
        )
        return _MAX_DECOMPRESSED_MIN
    return n
