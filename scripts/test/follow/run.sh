#!/usr/bin/env bash
# Run as root inside a disposable VM. Uses only BPF_PROG_TEST_RUN.
set -euo pipefail
work=$(mktemp -d "$PWD/follow-results.XXXXXX")
pids=()
cleanup() {
  local rc=$?
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  echo "Artifacts retained in $work (exit=$rc)"
  return "$rc"
}
trap cleanup EXIT
echo "kernel=$(uname -r)"
rules='[{"program":"entry","auto":true,"ops":["lookup:any"],"hook":"ninja"}]'
# run_case NAME GEN2_OBJECT CAPTURE_PREFIX... -- CAPTURE_ARGS...
# Starts the loader under inject-run, captures at generation 1's hook, lets
# the loader send its packets and replace the program, then stops the
# capture and checks the result.
run_case() {
  local name=$1 gen2=$2
  shift 2
  local prefix=()
  while [[ $1 != -- ]]; do prefix+=("$1"); shift; done
  shift
  local dir=$work/$name
  mkdir -p "$dir"
  printf '%s\n' "$rules" > "$dir/rules.json"
  ./bpf-ninja inject-run --fail-closed --config "$dir/rules.json" -- \
    ./loader "$dir" policies.o "$gen2" 400 100 > "$dir/id" 2> "$dir/inject.err" &
  local inject=$!
  pids+=("$inject")
  for ((i=0;i<100;i++)); do
    [[ -s "$dir/id" ]] && break
    kill -0 "$inject" 2>/dev/null || { cat "$dir/inject.err"; return 1; }
    sleep 0.1
  done
  local id
  id=$(cat "$dir/id")
  [[ "$id" =~ ^[0-9]+$ ]]
  "${prefix[@]}" ./bpf-ninja -p "$id" --func ninja_policies -v -w "$dir/cap.pcap" "$@" > /dev/null 2> "$dir/cap.err" &
  local cap=$!
  pids+=("$cap")
  for ((i=0;i<100;i++)); do
    grep -q 'capturing (' "$dir/cap.err" && break
    kill -0 "$cap" 2>/dev/null || { cat "$dir/cap.err"; return 1; }
    sleep 0.1
  done
  touch "$dir/go"
  for ((i=0;i<300;i++)); do
    [[ -s "$dir/done" ]] && break
    kill -0 "$inject" 2>/dev/null || { cat "$dir/inject.err"; return 1; }
    sleep 0.1
  done
  [[ -s "$dir/done" ]]
  # Give the capture a final polling pass after the swap, then stop it.
  sleep 3
  # The capture may run under a wrapper; signal the capture itself.
  pkill -INT -f "bpf-ninja -p $id --func ninja_policies" || true
  wait "$cap" || { cat "$dir/cap.err"; return 1; }
  kill "$inject" 2>/dev/null || true
  wait "$inject" 2>/dev/null || true
  python3 check.py "$name" "$dir"
}
# The capture reaches inject-run, which holds generation 2's load for it.
run_case held policies.o -- --arg-filter 'value->port!=0'
# The capture runs in its own network namespace, where it cannot reach
# inject-run and finds new programs only by polling program IDs.
run_case polling policies.o unshare -n -- --arg-filter 'value->port!=0'
run_case unresolved policies_noport.o -- --arg-filter 'value->port!=0'

# Two captures may both observe the named generation 1, but only one may
# attach to generation 2. The other reports that another observer won.
run_contended() {
  local dir=$work/contended
  mkdir -p "$dir"
  printf '%s\n' "$rules" > "$dir/rules.json"
  ./bpf-ninja inject-run --fail-closed --config "$dir/rules.json" -- \
    ./loader "$dir" policies.o policies.o 400 100 > "$dir/id" 2> "$dir/inject.err" &
  local inject=$!
  pids+=("$inject")
  for ((i=0;i<100;i++)); do
    [[ -s "$dir/id" ]] && break
    kill -0 "$inject" 2>/dev/null || { cat "$dir/inject.err"; return 1; }
    sleep 0.1
  done
  local id
  id=$(cat "$dir/id")
  [[ "$id" =~ ^[0-9]+$ ]]
  local captures=()
  for label in a b; do
    ./bpf-ninja -p "$id" --func ninja_policies -v -w "$dir/cap-$label.pcap" \
      > /dev/null 2> "$dir/cap-$label.err" &
    captures+=("$!")
    pids+=("$!")
  done
  for label in a b; do
    for ((i=0;i<100;i++)); do
      grep -q 'capturing (' "$dir/cap-$label.err" && \
        grep -q 'subscribed to 1 inject-run process' "$dir/cap-$label.err" && break
      sleep 0.1
    done
    grep -q 'capturing (' "$dir/cap-$label.err"
    grep -q 'subscribed to 1 inject-run process' "$dir/cap-$label.err"
  done
  touch "$dir/go"
  for ((i=0;i<300;i++)); do
    [[ -s "$dir/done" ]] && break
    kill -0 "$inject" 2>/dev/null || { cat "$dir/inject.err"; return 1; }
    sleep 0.1
  done
  [[ -s "$dir/done" ]]
  sleep 3
  kill -INT "${captures[@]}" 2>/dev/null || true
  for cap in "${captures[@]}"; do
    wait "$cap" || { cat "$dir"/cap-*.err; return 1; }
  done
  kill "$inject" 2>/dev/null || true
  wait "$inject" 2>/dev/null || true
  python3 check.py contended "$dir"
}

run_contended
echo "PASS cases=4"
