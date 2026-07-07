#!/bin/bash
# Sets up an XDP program with a __noinline capture point on va0, for testing
# xdp-ninja --func + --arg-filter. Traffic sent to 10.99.0.1 runs the program,
# which calls capture_point(pkt_len).
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OBJ="$SCRIPT_DIR/xdp_argcap.o"

# Compile (needs sudo because the test dir may be root-owned). -I so the
# program's #include "keep_args.h" resolves; -g so BTF carries the
# capture_point func_info and its pkt_len parameter name.
clang -O2 -g -target bpf -I "$SCRIPT_DIR" -c "$SCRIPT_DIR/xdp_argcap.c" -o "$OBJ" 2>/dev/null || \
    sudo clang -O2 -g -target bpf -I "$SCRIPT_DIR" -c "$SCRIPT_DIR/xdp_argcap.c" -o "$OBJ"

# Create netns + veth
sudo ip netns add xdpargtest
sudo ip link add va0 type veth peer name va1
sudo ip link set va1 netns xdpargtest
sudo ip addr add 10.99.0.1/24 dev va0
sudo ip netns exec xdpargtest ip addr add 10.99.0.2/24 dev va1
sudo ip link set va0 up
sudo ip netns exec xdpargtest ip link set va1 up

# Attach the program to va0 so it runs on ingress traffic.
sudo ip link set dev va0 xdp obj "$OBJ" sec xdp

echo "argcap loaded on va0 (capture_point subfunction)" >&2
