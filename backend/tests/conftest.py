"""Shared pytest fixtures for the backend test suite.

prompts-039: ``run_normalizer`` now records every run into
``data/run_history.db``. Many tests exercise ``run_normalizer`` (engine,
scheduler, routes) without caring about history. This autouse fixture
redirects the run-history DB to a per-test temp file so those tests never
touch the real ``data/`` directory. Tests that assert on history (e.g.
``test_run_history.py``) override ``_RUN_DB_PATH`` themselves — applied last,
their fixture wins.

issue-local-001: authentication is now ON by default in ``config/application.yaml``
(``auth_enabled: true``). Route-level integration tests that do not explicitly
test the auth layer must run in open mode so they don't receive unexpected 401s.
This autouse fixture sets ``OPENTARS_ENABLE_AUTH=0`` for every test.
Tests in ``test_routes_auth.py`` and other auth-specific files override this with
``monkeypatch.setenv("OPENTARS_ENABLE_AUTH", "1")`` in their own
fixtures — that runs within the same monkeypatch scope and takes precedence.
Tests in ``test_loader.py`` use their own ``_clear_auth_env`` autouse to
unset the variable entirely so they can read the yaml value directly.
"""

from __future__ import annotations

import pytest

from backend.normalizer import run_history as run_history_mod


@pytest.fixture(autouse=True)
def _isolate_run_history_db(tmp_path, monkeypatch):
    monkeypatch.setattr(run_history_mod, "_RUN_DB_PATH", tmp_path / "run_history.db")
    yield


@pytest.fixture(autouse=True)
def _default_auth_off(monkeypatch):
    """Keep tests isolated from the yaml auth_enabled=true default.

    Authentication is on by default in config/application.yaml. Route tests
    that do not exercise the auth layer set OPENTARS_ENABLE_AUTH=0 via
    this fixture so they receive 200s instead of 401s.  Auth-specific tests
    override with their own monkeypatch.setenv("OPENTARS_ENABLE_AUTH",
    "1") call, which takes precedence within the same monkeypatch scope.
    test_loader.py's _clear_auth_env autouse deletes the variable entirely so
    loader tests read the yaml directly.
    """
    monkeypatch.setenv("OPENTARS_ENABLE_AUTH", "0")
    yield
