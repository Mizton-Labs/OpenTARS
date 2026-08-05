"""Tests for issue-local-038: backend learns/logs its own git commit.

The `opentars` launcher now exports GIT_COMMIT to the backend process (it
previously only exported it to the frontend build subprocess) — the backend
side of that is `backend.get_git_commit()`, read from the environment.
"""

from __future__ import annotations

from backend import get_git_commit


def test_get_git_commit_reads_env_var(monkeypatch):
    monkeypatch.setenv("GIT_COMMIT", "abc1234")
    assert get_git_commit() == "abc1234"


def test_get_git_commit_falls_back_to_unknown(monkeypatch):
    monkeypatch.delenv("GIT_COMMIT", raising=False)
    assert get_git_commit() == "unknown"


def test_startup_log_includes_commit():
    import inspect

    import backend.main as main_module

    src = inspect.getsource(main_module.lifespan)
    assert "get_git_commit" in src, "startup log must include the git commit"
