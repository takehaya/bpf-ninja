#!/usr/bin/env bash
# Build on the development host, then copy only DIR into a disposable VM.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
out=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$repo"
CGO_ENABLED=0 go build -o "$out/bpf-ninja" ./cmd/bpf-ninja
CGO_ENABLED=0 go build -o "$out/loader" ./scripts/test/argmember/loader
clang -O2 -g -target bpf -c scripts/test/argmember/bpf/policies.c -o "$out/policies.o"
clang -O2 -g -target bpf -c examples/inject-walkthrough/bpf/prog.c -o "$out/walkthrough.o"
cp scripts/test/argmember/run.sh "$out/run.sh"
