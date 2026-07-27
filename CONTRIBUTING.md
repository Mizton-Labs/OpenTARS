# Contributing to OpenTARS

Thank you for your interest in contributing. This document covers the
essentials for getting started, running tests, and submitting changes.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Versioning](#versioning)

---

## Getting Started

**Prerequisites:** Python 3.10+, Node.js 18+, npm 9+, and optionally
[uv](https://github.com/astral-sh/uv) for faster Python dependency management.

```bash
# 1. Clone the repository
git clone https://github.com/Mizton-Labs/OpenTARS.git
cd OpenTARS

# 2. Start the application (installs all deps automatically on first run)
./mizton-threatbox start --dev
```

The `--dev` flag runs uvicorn in the foreground with live logs and also starts
the Vite dev server for hot-reload frontend development.

> **Authentication is on by default.** On first start, a default `admin` account
> is provisioned and its password is printed to the terminal. For local
> development without authentication, use `--disable-auth`:
> ```bash
> ./mizton-threatbox start --dev --disable-auth
> ```

**Commit hooks (one-time, recommended):**
```bash
git config core.hooksPath .githooks
```
This enables `.githooks/commit-msg`, which enforces this repository's
commit-authorship guideline. Commit authorship in this repo is the human
contributor only.

---

## Development Workflow

| Service | URL |
|---|---|
| Frontend (Vite HMR) | http://localhost:5173 |
| Backend API | http://localhost:8000/api |
| Swagger UI | http://localhost:8000/docs |

Use `./mizton-threatbox stop` to stop all background processes.

---

## Running Tests

```bash
# Run backend (pytest) + frontend (vitest) in one command
./scripts/test.sh

# Backend only
PYTHONPATH=. .venv/bin/pytest backend/tests -v --tb=short

# Frontend only
npm --prefix frontend test
```

Additional helper scripts:

```bash
./scripts/check.sh           # linting / static checks
./scripts/security-check.sh  # dependency + secret scanning
```

---

## Code Style

**Python** — [Ruff](https://docs.astral.sh/ruff/) is configured in
`pyproject.toml`. Run `ruff check .` and `ruff format .` before committing.

**TypeScript/React** — ESLint via `npm --prefix frontend run lint`.

**Shell scripts** — `shellcheck` on any `.sh` file you modify.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, `test:`, `ci:`.

---

## Submitting Changes

1. Fork the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Make your changes and ensure all tests pass (`./scripts/test.sh`).
3. Push your branch and open a Pull Request against `main`.
4. Fill in the PR template, referencing any related issues.
5. A maintainer will review and merge.

---

## Versioning

OpenTARS uses [Semantic Versioning](https://semver.org/).

The version string lives in **four places** that must all be updated together:

| File | Field |
|---|---|
| `pyproject.toml` | `[project] version` |
| `backend/__init__.py` | `__version__` |
| `frontend/package.json` | `"version"` |
| `frontend/vite.config.ts` | `__APP_VERSION__` define |

Update all four, then add a `CHANGELOG.md` entry and tag the release:

```bash
git tag -a v<version> -m "Release v<version>"
git push origin v<version>
```
