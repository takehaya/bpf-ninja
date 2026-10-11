#!/usr/bin/env bash
# Diff the canonical text of every bytecode golden filter between a base
# revision and the working tree. The manifest under
# pkg/kunai/dsltest/testdata/golden keeps most filters only as a hash;
# this script dumps the full text on both sides (TestGolden -golden-dump)
# and runs `diff -ruN` over the two dumps.
#
# Instruction indexes are removed before the diff, so a few inserted
# instructions show up as those lines instead of renumbering the rest
# of the program. Jumps name their target label, so no information the
# reader needs goes away.
#
# Usage:    ./scripts/golden-diff.sh [BASE]   (BASE defaults to main)
# Env:      GOLDEN_DIFF_INDEX  keep the instruction indexes when set
#                              to anything but empty or 0
# Exit:     0  no filter moved
#           1  some filter moved, was added, or was removed (an added
#              or removed filter is shown as a diff against nothing)
#           2  error (BASE cannot be checked out, has no golden test,
#              or a dump failed)

set -euo pipefail

fail() {
    echo "golden-diff: $*" >&2
    exit 2
}
trap 'fail "command failed at line $LINENO"' ERR

REPO=$(cd "$(dirname "$0")/.." && pwd) || fail "cannot find the repository"
BASE="${1:-main}"

tmp=$(mktemp -d)
cleanup() {
    git -C "$REPO" worktree remove --force "$tmp/base" >/dev/null 2>&1 || true
    rm -rf "$tmp"
    git -C "$REPO" worktree prune >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

git -C "$REPO" worktree add --quiet --detach "$tmp/base" "$BASE" ||
    fail "cannot check out $BASE"
[ -f "$tmp/base/pkg/kunai/dsltest/golden_test.go" ] ||
    fail "$BASE has no bytecode golden test"

dump() {
    (cd "$1/pkg/kunai/dsltest" && go test -run '^TestGolden$' -golden-dump="$2" >&2) ||
        fail "dumping the golden of $3 failed"
}
dump "$tmp/base" "$tmp/old" "$BASE"
dump "$REPO" "$tmp/new" "the working tree"

# Main and Callbacks lines read "\t 29: MovReg ..."; Funcs lines read
# "176: name", where 176 is the index into Main followed by Callbacks.
# Labels stay, and every Funcs name is also a label line, so a moved
# function still shows.
case "${GOLDEN_DIFF_INDEX:-}" in
"" | 0) strip=1 ;;
*) strip=0 ;;
esac
if [ "$strip" = 1 ]; then
    find "$tmp/old" "$tmp/new" -type f -name '*.asm' -print0 |
        while IFS= read -r -d '' f; do
            awk '/^== / { funcs = ($0 == "== Funcs") }
                 { if (funcs) sub(/^[0-9]+: /, ""); else sub(/^\t *[0-9]+: /, "\t"); print }' \
                "$f" >"$f.tmp"
            mv "$f.tmp" "$f"
        done
fi

status=0
(cd "$tmp" && diff -ruN old new) || status=$?
[ "$status" -le 1 ] || fail "diff failed"
exit "$status"
