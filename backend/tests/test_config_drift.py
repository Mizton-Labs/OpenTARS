"""Tests for backend.config.drift (issue-local-024 follow-up).

Covers: no drift when live == example; missing scalar top-level keys;
missing core_fields matched by name (not list equality, so a merely-
disabled field is never flagged); apply only adds the selected items and
never touches anything else; unknown file/key/name raise ValueError.
"""

from __future__ import annotations

import yaml

from backend.config import drift as drift_mod


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config):
    """Point every tracked file at an isolated tmp dir with no .example
    present by default, so only files a test explicitly seeds participate."""
    monkeypatch.setattr(loader, "APP_CONFIG_PATH", tmp_path / "application.yaml")
    monkeypatch.setattr(loader, "SOURCES_PATH", tmp_path / "sources.yaml")
    monkeypatch.setattr(loader, "FIELDS_PATH", tmp_path / "feed-fields.yaml")
    monkeypatch.setattr(
        normalizer_config, "_NORMALIZER_CONFIG_PATH", tmp_path / "normalizer-config.yaml"
    )


def test_no_drift_when_live_matches_example(tmp_path, monkeypatch):
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    live = tmp_path / "application.yaml"
    _write(live, {"app_title": "", "theme": "classic"})
    _write(tmp_path / "application.yaml.example", {"app_title": "", "theme": "classic"})

    assert drift_mod.compute_config_drift() == []


def test_detects_missing_scalar_key(tmp_path, monkeypatch):
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    _write(tmp_path / "application.yaml", {"app_title": ""})
    _write(
        tmp_path / "application.yaml.example",
        {"app_title": "", "new_setting_from_upgrade": "default-value"},
    )

    reports = drift_mod.compute_config_drift()
    assert len(reports) == 1
    assert reports[0]["file"] == "application.yaml"
    assert reports[0]["missing_keys"] == ["new_setting_from_upgrade"]
    assert reports[0]["missing_core_fields"] == []


def test_detects_missing_core_field_by_name(tmp_path, monkeypatch):
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    _write(
        tmp_path / "feed-fields.yaml",
        {"core_fields": [{"name": "indicator", "description": "Raw indicator", "enabled": True}]},
    )
    _write(
        tmp_path / "feed-fields.yaml.example",
        {
            "core_fields": [
                {"name": "indicator", "description": "Raw indicator", "enabled": True},
                {"name": "new_field", "description": "A brand-new built-in field", "enabled": True},
            ]
        },
    )

    reports = drift_mod.compute_config_drift()
    assert len(reports) == 1
    assert reports[0]["file"] == "feed-fields.yaml"
    assert reports[0]["missing_keys"] == []
    assert reports[0]["missing_core_fields"] == [
        {"name": "new_field", "description": "A brand-new built-in field"}
    ]


def test_disabled_core_field_is_not_flagged_as_missing(tmp_path, monkeypatch):
    """A field the operator merely disabled (still present in the live list)
    must never be reported as missing — matching is by name, not by full
    dict equality (which would differ once enabled flips)."""
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    _write(
        tmp_path / "feed-fields.yaml",
        {"core_fields": [{"name": "indicator", "description": "Raw indicator", "enabled": False}]},
    )
    _write(
        tmp_path / "feed-fields.yaml.example",
        {"core_fields": [{"name": "indicator", "description": "Raw indicator", "enabled": True}]},
    )

    assert drift_mod.compute_config_drift() == []


def test_file_with_no_example_is_skipped(tmp_path, monkeypatch):
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    _write(tmp_path / "application.yaml", {"app_title": ""})
    # No .example written for any file.

    assert drift_mod.compute_config_drift() == []


def test_apply_adds_only_selected_key_and_preserves_the_rest(tmp_path, monkeypatch):
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    live_path = tmp_path / "application.yaml"
    _write(live_path, {"app_title": "My Custom Title"})
    _write(
        tmp_path / "application.yaml.example",
        {"app_title": "", "new_setting": "shipped-default", "another_new_one": 42},
    )

    drift_mod.apply_config_drift_fix("application.yaml", keys=["new_setting"])

    live = yaml.safe_load(live_path.read_text(encoding="utf-8"))
    assert live["app_title"] == "My Custom Title"  # untouched
    assert live["new_setting"] == "shipped-default"  # added
    assert "another_new_one" not in live  # NOT selected, NOT added

    # Drift for the applied key is gone; the unselected key still shows.
    reports = drift_mod.compute_config_drift()
    assert reports == [
        {
            "file": "application.yaml",
            "missing_keys": ["another_new_one"],
            "missing_core_fields": [],
        }
    ]


def test_apply_adds_only_selected_core_field_and_preserves_the_rest(tmp_path, monkeypatch):
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    live_path = tmp_path / "feed-fields.yaml"
    _write(
        live_path,
        {
            "core_fields": [
                {"name": "indicator", "description": "Raw indicator", "enabled": True},
            ],
            "custom_fields": [{"name": "vendor_score", "description": "x", "enabled": True}],
        },
    )
    _write(
        tmp_path / "feed-fields.yaml.example",
        {
            "core_fields": [
                {"name": "indicator", "description": "Raw indicator", "enabled": True},
                {"name": "field_a", "description": "A", "enabled": True},
                {"name": "field_b", "description": "B", "enabled": True},
            ]
        },
    )

    drift_mod.apply_config_drift_fix("feed-fields.yaml", core_field_names=["field_a"])

    live = yaml.safe_load(live_path.read_text(encoding="utf-8"))
    names = [f["name"] for f in live["core_fields"]]
    assert names == ["indicator", "field_a"]  # field_b NOT added
    # Untouched, unrelated top-level key survives.
    assert live["custom_fields"] == [{"name": "vendor_score", "description": "x", "enabled": True}]


def test_apply_is_idempotent_when_field_already_present(tmp_path, monkeypatch):
    """Re-applying a fix that already landed (e.g. a racing second admin)
    must not duplicate the entry."""
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    _write(
        tmp_path / "feed-fields.yaml",
        {"core_fields": [{"name": "field_a", "description": "A", "enabled": True}]},
    )
    _write(
        tmp_path / "feed-fields.yaml.example",
        {"core_fields": [{"name": "field_a", "description": "A", "enabled": True}]},
    )

    drift_mod.apply_config_drift_fix("feed-fields.yaml", core_field_names=["field_a"])

    live = yaml.safe_load((tmp_path / "feed-fields.yaml").read_text(encoding="utf-8"))
    assert len(live["core_fields"]) == 1


def test_apply_rejects_unknown_file(tmp_path, monkeypatch):
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    try:
        drift_mod.apply_config_drift_fix("not-a-real-file.yaml", keys=["x"])
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "unknown config file" in str(exc)


def test_apply_rejects_key_not_in_example(tmp_path, monkeypatch):
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    _write(tmp_path / "application.yaml", {})
    _write(tmp_path / "application.yaml.example", {"app_title": ""})

    try:
        drift_mod.apply_config_drift_fix("application.yaml", keys=["nonexistent_key"])
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "nonexistent_key" in str(exc)


def test_apply_rejects_core_field_names_on_non_feed_fields_file(tmp_path, monkeypatch):
    from backend.config import loader
    from backend.normalizer import config as normalizer_config

    _patch_all_paths(monkeypatch, tmp_path, loader, normalizer_config)
    _write(tmp_path / "application.yaml", {})
    _write(tmp_path / "application.yaml.example", {"app_title": ""})

    try:
        drift_mod.apply_config_drift_fix("application.yaml", core_field_names=["indicator"])
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "only applies to feed-fields.yaml" in str(exc)
