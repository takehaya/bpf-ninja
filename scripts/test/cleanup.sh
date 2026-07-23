#!/bin/bash
sudo ip link delete veth0 2>/dev/null || true
sudo ip netns delete xdptest 2>/dev/null || true
sudo bpftool cgroup detach /sys/fs/cgroup/bpfninja-test ingress pinned /sys/fs/bpf/bpfninja_cgroup_pass 2>/dev/null || true
sudo rm -f /sys/fs/bpf/bpfninja_cgroup_pass 2>/dev/null || true
sudo rmdir /sys/fs/cgroup/bpfninja-test 2>/dev/null || true
echo "cleanup done"
