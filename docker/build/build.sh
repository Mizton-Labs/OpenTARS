#!/usr/bin/env bash
# Build the local OpenTARS image: opentars/local
#
# The image is STANDALONE: the application source is fetched from GitHub at build
# time, so no repository build context is required. By default it pulls the
# latest main branch; override with MTB_REF (branch, tag, or commit-ish) for a
# reproducible build.
#
# Usage:
#   docker/build/build.sh [extra docker build args...]
#
# Environment overrides:
#   IMAGE_TAG   image tag to produce         (default: opentars/local)
#   MTB_REF     git ref to build from GitHub  (default: main)
#   MTB_REPO    source repository URL         (default: project GitHub repo)
#
# Examples:
#   docker/build/build.sh
#   MTB_REF=v1.0.0 docker/build/build.sh
#   docker/build/build.sh --no-cache
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE_TAG="${IMAGE_TAG:-opentars/local}"
MTB_REF="${MTB_REF:-main}"
MTB_REPO="${MTB_REPO:-https://github.com/Mizton-Labs/OpenTARS.git}"

echo "[build] Building ${IMAGE_TAG} from ${MTB_REPO} @ ${MTB_REF}"

# The Dockerfile uses no local context (source is cloned from GitHub), so the
# build context is just this directory — kept tiny on purpose.
exec docker build \
    -f "${SCRIPT_DIR}/Dockerfile" \
    -t "${IMAGE_TAG}" \
    --build-arg "MTB_REF=${MTB_REF}" \
    --build-arg "MTB_REPO=${MTB_REPO}" \
    "$@" \
    "${SCRIPT_DIR}"
