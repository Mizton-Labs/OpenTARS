import os

# Single source of truth for the backend package version.
# All other version strings (frontend/package.json, frontend/vite.config.ts,
# pyproject.toml) must be updated in sync when this changes.
__version__ = "0.1.0"


def get_git_commit() -> str:
    """Return the short git commit hash this backend process was launched
    with. The `opentars` launcher script computes it and exports GIT_COMMIT
    before starting uvicorn (both --dev and production mode); running
    uvicorn directly (no launcher) leaves it unset, hence the fallback.
    """
    return os.environ.get("GIT_COMMIT", "unknown")
