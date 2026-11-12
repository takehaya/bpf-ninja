#!/usr/bin/env bash
# Build on the development host, then copy only DIR into a disposable VM.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$repo"
CGO_ENABLED=0 go build -o "$out/bpf-ninja" ./cmd/bpf-ninja
CGO_ENABLED=0 go build -o "$out/loader" ./scripts/test/follow/loader
clang -O2 -g -target bpf -c scripts/test/follow/bpf/policies.c -o "$out/policies.o"
clang -O2 -g -target bpf -DNO_PORT -c scripts/test/follow/bpf/policies.c -o "$out/policies_noport.o"
cp scripts/test/follow/run.sh scripts/test/follow/check.py scripts/test/assert_pcap.py "$out/"
