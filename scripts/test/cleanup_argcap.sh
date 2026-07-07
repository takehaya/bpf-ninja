#!/bin/bash
sudo ip link delete va0 2>/dev/null || true
sudo ip netns delete xdpargtest 2>/dev/null || true
