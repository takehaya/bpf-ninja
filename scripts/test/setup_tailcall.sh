#!/bin/bash
# Sets up a tail call chain: dispatcher → prog_a on vtc0
# Prints the dispatcher program ID on stdout.
#
# fentry/fexit trampolines only fire for the directly-attached XDP program
# (the dispatcher), not for tail call targets. So bpf-ninja -p should
# target the dispatcher ID to capture packets.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OBJ="$SCRIPT_DIR/xdp_tailcall.o"

# Compile (needs sudo because test dir may be root-owned)
clang -O2 -g -target bpf -c "$SCRIPT_DIR/xdp_tailcall.c" -o "$OBJ" 2>/dev/null || \
    sudo clang -O2 -g -target bpf -c "$SCRIPT_DIR/xdp_tailcall.c" -o "$OBJ"

# Create netns + veth
sudo ip netns add xdptctest
sudo ip link add vtc0 type veth peer name vtc1
sudo ip link set vtc1 netns xdptctest
sudo ip addr add 10.98.0.1/24 dev vtc0
sudo ip netns exec xdptctest ip addr add 10.98.0.2/24 dev vtc1
sudo ip link set vtc0 up
sudo ip netns exec xdptctest ip link set vtc1 up

# Load all programs (shares prog_array map)
sudo rm -rf /sys/fs/bpf/xdp_tailcall_test
sudo mkdir -p /sys/fs/bpf/xdp_tailcall_test
sudo bpftool prog loadall "$OBJ" /sys/fs/bpf/xdp_tailcall_test

# Get IDs
DISP_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/xdp_tailcall_test/xdp_dispatcher | head -1 | awk '{print $1}' | tr -d ':')
PROG_A_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/xdp_tailcall_test/xdp_prog_a | head -1 | awk '{print $1}' | tr -d ':')

# Attach dispatcher to interface
sudo bpftool net attach xdp id "$DISP_ID" dev vtc0

# Insert prog_a into prog_array at index 0
MAP_ID=$(sudo bpftool prog show id "$DISP_ID" | grep map_ids | grep -oP '\d+' | tail -1)
sudo bpftool map update id "$MAP_ID" key 0 0 0 0 value id "$PROG_A_ID" 2>/dev/null

echo "dispatcher=$DISP_ID prog_a=$PROG_A_ID" >&2
echo "$DISP_ID"
