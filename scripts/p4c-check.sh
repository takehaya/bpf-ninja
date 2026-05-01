#!/usr/bin/env bash
# Build the local p4c-check Docker image and run it against the repo.
#
# The Dockerfile lives at docker/p4c-check/Dockerfile and pins p4c to
# a specific upstream tag. The image bakes in a libboost-iostreams
# workaround and copies in the wrapper script that iterates each
# .p4 vocab file with `#include <core.p4>` prepended. See
# docs/ja/dsl-followups.md P0-4 for context.
#
# Usage:    ./scripts/p4c-check.sh
# Env:      P4C_CHECK_IMAGE  (default: xdp-ninja-p4c-check:local)
# Requires: docker

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
IMG="${P4C_CHECK_IMAGE:-xdp-ninja-p4c-check:local}"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker not found in PATH" >&2
    exit 1
fi

# `docker build` reuses cached layers when nothing changed, so the
# repeat invocation is cheap (~1s on a warm cache). The base layers
# (libboost install) are invalidated only when the Dockerfile
# changes; the final layer is invalidated only when check.sh
# changes.
docker build -t "$IMG" "$REPO/docker/p4c-check"

docker run --rm -v "$REPO:/work" "$IMG"
