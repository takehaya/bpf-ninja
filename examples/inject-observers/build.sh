#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build
for name in count conditional latency; do
  "${CLANG:-clang}" -O2 -g -target bpf -Wall -Werror -c "bpf/$name.c" -o "build/$name.o"
done
"${CLANG:-clang}" -O2 -g -target bpf -c ../inject-walkthrough/bpf/prog.c -o build/prog.o
go build -o build/loader-bin ../inject-walkthrough/loader
go build -o build/observer-bin ./observer
