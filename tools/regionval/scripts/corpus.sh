#!/bin/sh
# Check every capture file under DIR and summarise the results.
# Usage: scripts/corpus.sh DIR [OUT]
# OUT (default regionval-corpus.jsonl) receives one JSON result per load.
# Exits 1 if any load is not validated, 2 on a usage or build error.
set -eu
dir=${1:-}
out=${2:-regionval-corpus.jsonl}
if [ -z "$dir" ] || [ ! -d "$dir" ]; then
	echo "usage: $0 DIR [OUT]" >&2
	exit 2
fi
here=$(cd "$(dirname "$0")/.." && pwd)
bin=$(mktemp)
trap 'rm -f "$bin"' EXIT
(cd "$here" && CGO_ENABLED=0 go build -o "$bin" ./cmd/regionval) || exit 2
find "$dir" -name '*.json' -type f | sort | tr '\n' '\0' | xargs -0 "$bin" > "$out"
jq -rs '
  "loads: \(length)  validated: \(map(select(.validated)) | length)",
  (map(select(.validated | not)
       | if .structure.ok then (.windows[] | select(.validated | not) | "rule:\(.rule)")
         else "structure:\(.structure.failed_stage)" end)
   | group_by(.) | map("  \(.[0]): \(length)") | .[])
' "$out"
jq -se 'all(.validated)' "$out" > /dev/null
