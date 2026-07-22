#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Compile dummy XDP and TC classifier programs.
clang -O2 -g -target bpf -c "$SCRIPT_DIR/xdp_pass.c" -o "$SCRIPT_DIR/xdp_pass.o"
clang -O2 -g -target bpf -c "$SCRIPT_DIR/tc_pass.c" -o "$SCRIPT_DIR/tc_pass.o"

# Create netns + veth pair
sudo ip netns add xdptest
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns xdptest
sudo ip addr add 10.0.0.1/24 dev veth0
sudo ip netns exec xdptest ip addr add 10.0.0.2/24 dev veth1
sudo ip link set veth0 up
sudo ip netns exec xdptest ip link set veth1 up
sudo ip netns exec xdptest ip link set lo up

# Attach dummy XDP program
sudo ip link set dev veth0 xdp obj "$SCRIPT_DIR/xdp_pass.o" sec xdp

# Attach dummy TC clsact classifier so --mode tc-{entry,exit} has a
# fentry/fexit target. tc qdisc + filter is per-direction (ingress);
# bpf-ninja attaches as a tracing observer, not a forwarder.
sudo tc qdisc add dev veth0 clsact
sudo tc filter add dev veth0 ingress bpf direct-action obj "$SCRIPT_DIR/tc_pass.o" sec classifier

echo "setup complete: veth0 (10.0.0.1 + XDP + tc clsact) <-> xdptest:veth1 (10.0.0.2)"
bpftool prog show name xdp_pass 2>/dev/null || true
bpftool prog show name tc_pass 2>/dev/null || true
