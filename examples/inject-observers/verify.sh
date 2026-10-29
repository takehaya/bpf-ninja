#!/bin/sh
# Run as root inside a VM, after build.sh and the root bpf-ninja build.
set -eu
window=7
load_only=false
case "${1:-}" in
  "") ;;
  --load-only) window=2; load_only=true ;;
  *) echo "usage: $0 [--load-only]" >&2; exit 2 ;;
esac
cd "$(dirname "$0")"
results="build/$(uname -r)"
mkdir -p "$results"
launcher=
cleanup() {
  if [ -n "$launcher" ]; then
    kill -INT "$launcher" 2>/dev/null || true
    wait "$launcher" 2>/dev/null || true
    launcher=
  fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM
uname -r
for name in count conditional latency; do
  rules=../inject-walkthrough/rules.json
  if [ "$name" = latency ]; then rules=latency-rules.json; fi
  # A unique, initially absent file also permits repeated runs without stale readiness.
  ready=$(mktemp -d "$results/$name.ready.XXXXXX")/start
  idfile="$results/$name.id"
  : > "$idfile"
  ../../bpf-ninja inject-run --config "$rules" --hooks-json "$results/$name.hooks.json" \
    -- ./build/loader-bin build/prog.o "$ready" > "$idfile" 2> "$results/$name.loader.log" &
  launcher=$!
  for _ in $(seq 90); do
    if [ -s "$idfile" ]; then break; fi
    if ! kill -0 "$launcher" 2>/dev/null; then
      cat "$results/$name.loader.log"
      exit 1
    fi
    sleep 1
  done
  test -s "$idfile"
  rc=0
  INJECT_OBSERVER_READY="$ready" timeout -s INT "$window" ./build/observer-bin "$name" "build/$name.o" "$(cat "$idfile")" \
    > "$results/$name.log" 2>&1 || rc=$?
  cat "$results/$name.log"
  test "$rc" -eq 124
  grep -q "^attached $name$" "$results/$name.log"
  if [ "$load_only" = true ]; then
    cleanup
    echo "$name: load PASS"
    continue
  fi
  case "$name" in
    count)
      grep -Eq '^hook=ninja_recent_push .* calls=[1-9][0-9]* failures=[1-9][0-9]*$' "$results/$name.log"
      grep -Eq '^hook=ninja_recent_pop .* calls=[1-9][0-9]* failures=0$' "$results/$name.log"
      ;;
    conditional)
      grep -Eq '^hook=ninja_recent_push .* ret=-7 cpu=[0-9]+$' "$results/$name.log"
      if grep -q ' ret=0 ' "$results/$name.log"; then exit 1; fi
      ;;
    latency)
      grep -Eq '^hook=ninja_seen_push site=[0-9]+ ret=-?[0-9]+ ns=[1-9][0-9]*$' "$results/$name.log"
      grep -Eq '^hook=ninja_recent_push site=[0-9]+ ret=-?[0-9]+ ns=[1-9][0-9]*$' "$results/$name.log"
      ;;
  esac
  grep -q 'action=2 err=<nil>' "$results/$name.loader.log"
  if grep '^run ' "$results/$name.loader.log" | grep -v 'action=2 err=<nil>$'; then exit 1; fi
  cleanup
  echo "$name: PASS"
done
