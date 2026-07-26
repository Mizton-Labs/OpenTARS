"""Config-drift detection (issue-local-024 follow-up).

application.yaml / sources.yaml / feed-fields.yaml / normalizer-config.yaml
are gitignored and bootstrapped from a committed ``.example`` template on
first run (see loader.py / normalizer/config.py's ``_bootstrap_from_example``)
so an operator's live edits never conflict with an upgrade. Every individual
*scalar* setting already self-heals when a new one is introduced in code — each
``load_*()`` function merges the live file over a coded-in default dict, so a
missing key silently defaults with no admin action needed.

The one place that does NOT self-heal is list-shaped shipped content:
``feed-fields.yaml``'s ``core_fields`` has no coded default to merge missing
entries against, so a deployment bootstrapped before a new built-in field was
added has no way to notice or receive it. This module detects that gap (and,
generically, any brand-new top-level key a future ``.example`` introduces) by
comparing each live file against its own shipped ``.example`` — so an admin
can be notified and choose to add exactly the missing pieces, never anything
they've deliberately customized or removed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

import backend.config.loader as loader
import backend.normalizer.config as normalizer_config

# (display name, live-path accessor) — accessors are read live via module
# attribute access at call time, not imported as bound names, so tests that
# monkeypatch e.g. ``loader.FIELDS_PATH`` to an isolated tmp_path are honored.
_TRACKED_FILES: tuple[tuple[str, str, str], ...] = (
    ("application.yaml", "loader", "APP_CONFIG_PATH"),
    ("sources.yaml", "loader", "SOURCES_PATH"),
    ("feed-fields.yaml", "loader", "FIELDS_PATH"),
    ("normalizer-config.yaml", "normalizer_config", "_NORMALIZER_CONFIG_PATH"),
)

_MODULES: dict[str, Any] = {"loader": loader, "normalizer_config": normalizer_config}


def _live_path(file: str) -> Path | None:
    for name, module_key, attr in _TRACKED_FILES:
        if name == file:
            return getattr(_MODULES[module_key], attr)
    return None


def _example_path(path: Path) -> Path:
    return path.with_name(path.name + ".example")


def _load_yaml_safe(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.dump(data, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)


def _diff_scalar_keys(live: dict[str, Any], example: dict[str, Any]) -> list[str]:
    """Top-level keys shipped in *example* but absent from *live*.

    Informational for files whose settings already self-heal via per-setting
    coded defaults — surfaced so an admin can see a new setting exists (and
    what it currently defaults to), not because the app would malfunction
    without this notice.
    """
    return sorted(k for k in example if k not in live)


def _diff_core_fields(live: dict[str, Any], example: dict[str, Any]) -> list[dict[str, str]]:
    """core_fields entries shipped in *example* but missing (by name) from
    *live* — matched by name, not list equality, so a field the operator
    merely disabled (still present, ``enabled: false``) is never flagged."""
    live_names = {f.get("name") for f in live.get("core_fields", []) if isinstance(f, dict)}
    missing: list[dict[str, str]] = []
    for field in example.get("core_fields", []):
        if not isinstance(field, dict):
            continue
        name = field.get("name")
        if name and name not in live_names:
            missing.append({"name": name, "description": field.get("description", "")})
    return missing


def compute_config_drift() -> list[dict[str, Any]]:
    """Return a drift report for every tracked file that has any.

    Each report: ``{"file": str, "missing_keys": list[str],
    "missing_core_fields": [{"name", "description"}]}``. A file with no
    drift is omitted entirely — an empty return means everything is current.
    """
    reports: list[dict[str, Any]] = []
    for name, module_key, attr in _TRACKED_FILES:
        path = getattr(_MODULES[module_key], attr)
        example = _load_yaml_safe(_example_path(path))
        if not example:
            continue  # no shipped template to compare against (shouldn't happen)
        live = _load_yaml_safe(path)

        missing_keys = _diff_scalar_keys(live, example)
        missing_core_fields = _diff_core_fields(live, example) if name == "feed-fields.yaml" else []
        if missing_keys or missing_core_fields:
            reports.append(
                {
                    "file": name,
                    "missing_keys": missing_keys,
                    "missing_core_fields": missing_core_fields,
                }
            )
    return reports


def apply_config_drift_fix(
    file: str,
    *,
    keys: list[str] | None = None,
    core_field_names: list[str] | None = None,
) -> None:
    """Merge selected missing example content into the live file.

    Only ever ADDS the named keys/fields — every other key and every existing
    ``core_fields`` entry in the live file is left untouched. Raises
    ValueError for an unknown file or a key/name that isn't actually part of
    the current drift (defends against a stale client re-applying a fix that
    no longer exists, e.g. two admins racing each other).
    """
    path = _live_path(file)
    if path is None:
        raise ValueError(f"unknown config file: {file!r}")

    example = _load_yaml_safe(_example_path(path))
    live = _load_yaml_safe(path)

    for key in keys or []:
        if key not in example:
            raise ValueError(f"{file}: {key!r} is not a key in the shipped example")
        live[key] = example[key]

    if core_field_names:
        if file != "feed-fields.yaml":
            raise ValueError(f"{file}: core_field_names only applies to feed-fields.yaml")
        example_by_name = {
            field.get("name"): field
            for field in example.get("core_fields", [])
            if isinstance(field, dict)
        }
        live_core = list(live.get("core_fields", []))
        live_names = {field.get("name") for field in live_core if isinstance(field, dict)}
        for name in core_field_names:
            field = example_by_name.get(name)
            if field is None:
                raise ValueError(
                    f"feed-fields.yaml: {name!r} is not a core field in the shipped example"
                )
            if name not in live_names:
                live_core.append(field)
        live["core_fields"] = live_core

    _write_yaml(path, live)
