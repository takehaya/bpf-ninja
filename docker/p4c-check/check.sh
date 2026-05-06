#!/usr/bin/env bash
# Iterate /work/pkg/kunai/protocols/*.p4 and run p4test in
# --parse-only mode against each one. Prepends `#include <core.p4>`
# to a tmp copy first so p4test can resolve the built-in `packet_in`
# type (vocab files don't carry the include themselves so p4lite
# stays minimal).
#
# Per-file content-hash caching: a passed file leaves an empty
# marker at /work/.p4c-cache/<sha256>.<CACHE_VERSION>.ok. Subsequent
# runs with the same content skip p4test entirely. Bump
# CACHE_VERSION here whenever the parse logic (this script or the
# Dockerfile's apt layer) changes meaning, so existing markers
# invalidate without manual cache wipe.
#
# Caller mounts the repo at /work and runs the image with no args.

set -euo pipefail

# Bump when parse semantics or core.p4-prepend logic changes.
CACHE_VERSION=v1
CACHE_DIR=/work/.p4c-cache
mkdir -p "$CACHE_DIR"

failed=0
for f in /work/pkg/kunai/protocols/*.p4; do
    h=$(sha256sum "$f" | awk '{print $1}')
    marker="$CACHE_DIR/${h}.${CACHE_VERSION}.ok"
    if [ -f "$marker" ]; then
        echo "=== $f (cached) ==="
        continue
    fi
    echo "=== $f ==="
    tmp=$(mktemp --suffix=.p4)
    { echo "#include <core.p4>"; cat "$f"; } > "$tmp"
    if p4test --parse-only --Werror "$tmp"; then
        touch "$marker"
    else
        echo "FAIL: $f"
        failed=$((failed + 1))
    fi
    rm -f "$tmp"
done

if [ "$failed" -ne 0 ]; then
    echo "$failed file(s) failed p4c parse-check"
    exit 1
fi
echo "All vocab files passed p4c --parse-only"
