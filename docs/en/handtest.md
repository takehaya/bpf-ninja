# Manual Test: xdp-ninja Packet Capture

Step-by-step manual verification of xdp-ninja features.
Starting from basic fentry/fexit on entry functions,
progressing through `--func` subfunction probing, and tail call environments.

## Prerequisites

- Linux kernel 6.x or later (bpf2bpf call + tail call coexistence support)
- Root privileges
- clang, bpftool, tcpdump

## 0. Build

```bash
cd /path/to/xdp-ninja
go build -o xdp-ninja ./cmd/xdp-ninja/
```

---

## Part 1: fentry/fexit on Entry Functions

The simplest case. Attach to the XDP program's entry function and capture packets.

### 1.1 Create Test Program

```bash
cat > /tmp/xdp_simple.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return 2; /* XDP_PASS */
}

char _license[] SEC("license") = "GPL";
EOF
clang -O2 -g -target bpf -c /tmp/xdp_simple.c -o /tmp/xdp_simple.o
```

### 1.2 Set Up Environment

```bash
sudo ip netns add nstest
sudo ip link add vtest0 type veth peer name vtest1
sudo ip link set vtest1 netns nstest
sudo ip addr add 10.77.0.1/24 dev vtest0
sudo ip netns exec nstest ip addr add 10.77.0.2/24 dev vtest1
sudo ip link set vtest0 up
sudo ip netns exec nstest ip link set vtest1 up
sudo ip netns exec nstest ip link set lo up

# Attach XDP program
sudo ip link set dev vtest0 xdp obj /tmp/xdp_simple.o sec xdp
```

Verify connectivity:

```bash
sudo ip netns exec nstest ping -c 3 10.77.0.1
```

### 1.3 fentry (Capture Before XDP Processing)

Terminal 1:

```bash
sudo ./xdp-ninja -i vtest0 -v | tcpdump -n -r -
```

Terminal 2:

```bash
sudo ip netns exec nstest ping -c 5 10.77.0.1
```

Expected: ICMP packets are captured.

### 1.4 fexit (Capture After XDP Processing)

```bash
sudo ./xdp-ninja -i vtest0 --mode exit -v | tcpdump -n -r -
```

Expected: ICMP packets are captured.

### 1.5 With Filters

```bash
# Matching filter
sudo ./xdp-ninja -i vtest0 "icmp" -v | tcpdump -n -r -

# Non-matching filter
sudo ./xdp-ninja -i vtest0 "tcp port 80" -v -c 3 | tcpdump -n -r -
```

Expected: The icmp filter captures packets; tcp port 80 results in `0 packets captured`.

### 1.6 Pcap File Output

```bash
sudo ./xdp-ninja -i vtest0 -w /tmp/capture.pcap -c 5 &
sudo ip netns exec nstest ping -c 5 10.77.0.1
wait
tcpdump -n -r /tmp/capture.pcap
```

Expected: A pcap file is generated and readable by tcpdump.

### 1.7 Cleanup

```bash
sudo ip link set dev vtest0 xdp off
sudo ip link delete vtest0 2>/dev/null
sudo ip netns delete nstest 2>/dev/null
```

---

## Part 2: Subfunction Probing with `--func`

Attach to `__noinline` subfunctions and capture packets.
The test program includes both global and static subfunctions.

### 2.1 Create Test Program

```
xdp_main
  └─ classify_packet  [global __noinline]
      └─ parse_headers  [static __noinline]
```

```bash
cat > /tmp/xdp_subfunc.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP     0x0800
#define IPPROTO_ICMP 1

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16        h_proto;
} __attribute__((packed));

struct iphdr {
    __u8   ihl_ver;
    __u8   tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8   ttl;
    __u8   protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

/* static __noinline: verified in the caller's context */
static __attribute__((noinline))
int parse_headers(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    return ip->protocol;
}

/* global __noinline: verified independently by the verifier */
__attribute__((noinline))
int classify_packet(struct xdp_md *ctx) {
    int proto = parse_headers(ctx);
    if (proto == IPPROTO_ICMP)
        return 2; /* XDP_PASS */
    return 2; /* XDP_PASS */
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
    return classify_packet(ctx);
}

char _license[] SEC("license") = "GPL";
EOF
clang -O2 -g -target bpf -c /tmp/xdp_subfunc.c -o /tmp/xdp_subfunc.o
```

> **Note:** The subfunction body must be non-trivial (e.g., access `ctx->data`).
> A trivial body like `return 2;` will be constant-folded by `clang -O2`,
> eliminating the bpf2bpf call entirely.

### 2.2 Set Up Environment

```bash
sudo ip netns add nstest
sudo ip link add vtest0 type veth peer name vtest1
sudo ip link set vtest1 netns nstest
sudo ip addr add 10.77.0.1/24 dev vtest0
sudo ip netns exec nstest ip addr add 10.77.0.2/24 dev vtest1
sudo ip link set vtest0 up
sudo ip netns exec nstest ip link set vtest1 up
sudo ip netns exec nstest ip link set lo up

sudo ip link set dev vtest0 xdp obj /tmp/xdp_subfunc.o sec xdp
```

Verify connectivity:

```bash
sudo ip netns exec nstest ping -c 3 10.77.0.1
```

### 2.3 List Functions with `--list-funcs`

```bash
sudo ./xdp-ninja -i vtest0 --list-funcs
```

Expected output:

```
BTF functions in program (id=XXXX):
  parse_headers                              [static]
  classify_packet                            [global]
  xdp_main                                   [global]
```

### 2.4 fentry on `classify_packet` (global)

```bash
sudo ./xdp-ninja -i vtest0 --func classify_packet -v | tcpdump -n -r -
```

Expected: ICMP packets are captured.

### 2.5 fentry on `parse_headers` (static)

```bash
sudo ./xdp-ninja -i vtest0 --func parse_headers -v | tcpdump -n -r -
```

Expected: Packets are captured as well.

### 2.6 fexit on Subfunction

```bash
sudo ./xdp-ninja -i vtest0 --func classify_packet --mode exit -v | tcpdump -n -r -
```

Expected: Packets are captured.

### 2.7 Non-existent Function Name (Error)

```bash
sudo ./xdp-ninja -i vtest0 --func no_such_func
```

Expected: Error message listing available functions.

### 2.8 Cleanup

```bash
sudo ip link set dev vtest0 xdp off
sudo ip link delete vtest0 2>/dev/null
sudo ip netns delete nstest 2>/dev/null
```

---

## Part 3: Subfunction Probing in a Tail Call Environment

Verify that fentry/fexit on subfunctions works when the parent program
is reached via tail call from a dispatcher.

### 3.1 Create Test Program

```
xdp_dispatcher
  └─ tail call ─→ xdp_leaf
                    └─ classify_packet  [global]
                        └─ parse_headers  [static]
```

```bash
cat > /tmp/xdp_tc_subfunc.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP     0x0800
#define IPPROTO_ICMP 1

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16        h_proto;
} __attribute__((packed));

struct iphdr {
    __u8   ihl_ver;
    __u8   tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8   ttl;
    __u8   protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} prog_array SEC(".maps");

/* static __noinline */
static __attribute__((noinline))
int parse_headers(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    return ip->protocol;
}

/* global __noinline */
__attribute__((noinline))
int classify_packet(struct xdp_md *ctx) {
    int proto = parse_headers(ctx);
    if (proto == IPPROTO_ICMP)
        return 2;
    return 2;
}

SEC("xdp")
int xdp_leaf(struct xdp_md *ctx) {
    return classify_packet(ctx);
}

SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx) {
    bpf_tail_call(ctx, &prog_array, 0);
    return 2;
}

char _license[] SEC("license") = "GPL";
EOF
clang -O2 -g -target bpf -c /tmp/xdp_tc_subfunc.c -o /tmp/xdp_tc_subfunc.o
```

### 3.2 Set Up Environment

```bash
sudo ip netns add nstest
sudo ip link add vtest0 type veth peer name vtest1
sudo ip link set vtest1 netns nstest
sudo ip addr add 10.77.0.1/24 dev vtest0
sudo ip netns exec nstest ip addr add 10.77.0.2/24 dev vtest1
sudo ip link set vtest0 up
sudo ip netns exec nstest ip link set vtest1 up
sudo ip netns exec nstest ip link set lo up

# Load with bpftool (dispatcher and leaf as separate programs)
sudo rm -rf /sys/fs/bpf/tctest
sudo mkdir -p /sys/fs/bpf/tctest
sudo bpftool prog loadall /tmp/xdp_tc_subfunc.o /sys/fs/bpf/tctest

# Get program IDs
DISP_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/tctest/xdp_dispatcher | head -1 | awk '{print $1}' | tr -d ':')
LEAF_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/tctest/xdp_leaf | head -1 | awk '{print $1}' | tr -d ':')
echo "DISP_ID=$DISP_ID LEAF_ID=$LEAF_ID"

# Attach dispatcher to interface
sudo bpftool net attach xdp id "$DISP_ID" dev vtest0

# Pin prog_array and set up the tail call
MAP_ID=$(sudo bpftool prog show id "$DISP_ID" | grep -oP 'map_ids \K\d+')
sudo bpftool map pin id "$MAP_ID" /sys/fs/bpf/tctest/prog_array
sudo bpftool map update pinned /sys/fs/bpf/tctest/prog_array key 0 0 0 0 value id "$LEAF_ID"
```

Verify connectivity:

```bash
sudo ip netns exec nstest ping -c 3 10.77.0.1
```

### 3.3 Discover Tail Call Targets with `--list-progs`

```bash
sudo ./xdp-ninja -i vtest0 --list-progs
```

Expected output:

```
id=XXXX   xdp_dispatcher
id=YYYY   xdp_leaf (tailcall[0])
```

### 3.4 List Leaf's Subfunctions

```bash
sudo ./xdp-ninja -p $LEAF_ID --list-funcs
```

### 3.5 fentry on Subfunction (Via Tail Call)

```bash
sudo ./xdp-ninja -p $LEAF_ID --func classify_packet -v | tcpdump -n -r -
```

Expected: ICMP packets are captured.
The bpf2bpf call inside the tail-called program goes through its trampoline normally.

### 3.6 fexit on Subfunction

```bash
sudo ./xdp-ninja -p $LEAF_ID --func classify_packet --mode exit -v | tcpdump -n -r -
```

Expected: Packets are captured.

### 3.7 Direct Attach to Tail Call Target Entry (Does Not Fire)

```bash
sudo ./xdp-ninja -p $LEAF_ID -v -c 3 | tcpdump -n -r -
```

Expected: `0 packets captured`.
Tail calls use `jmp` to bypass the entry function's trampoline,
so fentry on the entry function does not fire.
However, internal bpf2bpf calls are regular function calls
and their trampolines work correctly.

### 3.8 Cleanup

```bash
sudo bpftool net detach xdp dev vtest0
sudo rm -rf /sys/fs/bpf/tctest
sudo ip link delete vtest0 2>/dev/null
sudo ip netns delete nstest 2>/dev/null
```
