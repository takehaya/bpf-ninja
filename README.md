# xdp-ninja

xdp-ninja captures packets at XDP-time. `tcpdump` runs below XDP and can't show what XDP did to the packet, and cBPF filters can't walk into VXLAN / GTP / MPLS / SRv6 inner headers. Attach via fentry/fexit to a running XDP without modifying it, or `--mode xdp` for standalone capture on a netdev. Filters use the built-in DSL by default — chains like `eth/ipv4/udp/vxlan/eth/ipv4/tcp`. Plain tcpdump syntax via [cbpfc](https://github.com/cloudflare/cbpfc) is still accepted via `--cbpf`, kept for backwards compatibility and planned to retire once the DSL surface stabilises. Output is pcap (pcapng) to stdout.🥷

## Install

```bash
# One-liner (downloads pre-built binary from GitHub Releases, requires jq)
curl -fsSL https://raw.githubusercontent.com/takehaya/xdp-ninja/main/scripts/install.sh | sudo bash

# Specific version
curl -fsSL https://raw.githubusercontent.com/takehaya/xdp-ninja/main/scripts/install.sh | sudo bash -s -- --version v0.1.0

# Or via go install (requires Go + libpcap-dev)
go install github.com/takehaya/xdp-ninja/cmd/xdp-ninja@latest

# Or build from source
git clone https://github.com/takehaya/xdp-ninja.git
cd xdp-ninja
make build
```

## Modes

xdp-ninja supports five attach modes via `--mode`:

| Mode | Attach via | Existing program needed | Sees return action | Typical use |
|---|---|---|---|---|
| `entry` (default) | fentry on the target XDP | yes (with BTF) | no — packet only | observe what reaches the production XDP |
| `exit` | fexit on the target XDP | yes (with BTF) | yes (`XDP_PASS`/`DROP`/...) | observe what the XDP decided; filter on action |
| `xdp` | attach as the primary XDP on the netdev | no — fails if one is attached | n/a (xdp-ninja decides; always returns `XDP_PASS`) | capture on a netdev with no XDP, no BTF needed |
| `tc-entry` | fentry on a TC clsact filter program | yes (a tc-bpf program with BTF) | no — skb only | observe what reaches a TC ingress/egress filter |
| `tc-exit` | fexit on a TC clsact filter program | yes (same) | yes (`TC_ACT_OK`/`SHOT`/...) | observe the TC verdict; filter on `action == TC_ACT_SHOT` etc. |

`entry`/`exit` and `tc-entry`/`tc-exit` are non-invasive: the target program is unmodified, attach is via BPF trampoline. `xdp` is the standalone path for "I just want to capture, there's nothing else here". The `tc-*` modes today expect the target by `-p <progID>` only (interface lookup for TC clsact is not yet wired).

## Usage

```bash
# Default: observe via fentry on whatever XDP is attached to eth0
sudo xdp-ninja -i eth0 | tcpdump -n -r -

# Filter (DSL is the default — no flag needed)
sudo xdp-ninja -i eth0 "eth/ipv4/tcp[dport==80]" | tcpdump -n -r -

# fexit — filter on the XDP return action
sudo xdp-ninja -i eth0 --mode exit "eth/ipv4/tcp where action == XDP_DROP"

# Standalone XDP attach (no existing XDP needed)
sudo xdp-ninja --mode xdp -i eth0 "eth/ipv4/tcp[dport==443]" | tcpdump -n -r -

# Legacy tcpdump/cBPF syntax (--cbpf opt-in, prints a deprecation notice)
sudo xdp-ninja --cbpf -i eth0 "host 10.0.0.1 and tcp port 80" | tcpdump -n -r -

# Write to pcap file, stop after 100 packets
# (output is sharded across per-CPU files; see "Sharded output" below)
sudo xdp-ninja -i eth0 -w capture.pcap -c 100

# Attach by BPF program ID (for multi-prog / libxdp setups)
sudo xdp-ninja -p 42 | tcpdump -n -r -

# List BTF functions in the target program
sudo xdp-ninja -i eth0 --list-funcs

# Attach to a specific __noinline subfunction (entry/exit only)
sudo xdp-ninja -i eth0 --func process_packet | tcpdump -n -r -

# Attach several (program, func) pairs in one run: -p and --func are
# repeatable, and each func attaches in every listed program whose BTF
# has it. All attach points share one ringbuf and merge into one pcap.
# (e.g. UL + DL capture points living in separate per-direction programs)
sudo xdp-ninja -p 1610 -p 1611 -p 1614 \
  --func pgwu_capture_point_ul --func pgwu_capture_point_dl -w all.pcap

# Match against a runtime-updatable set (pinned BPF hash map): the map
# key IS the value to match; entries added/removed while capturing take
# effect immediately, no re-attach. Manage entries by field name via
# `xdp-ninja set` (schema comes from the map's BTF).
sudo xdp-ninja set create /sys/fs/bpf/subs --key "imsi:u64"
sudo xdp-ninja set add /sys/fs/bpf/subs imsi=901040010000005
sudo xdp-ninja -p 1661 --func pgwu_capture_point_ul \
  --set "subs=/sys/fs/bpf/subs" --arg-filter "@subs" -w subs.pcap
```

### Filter syntax

The filter expression is interpreted as the built-in DSL by default. Write it as a protocol stack chain — it covers everything tcpdump's cBPF can express and adds the multi-encapsulation cases cBPF can't (MPLS label stacks, VXLAN inner Ethernet, GTP-U inner IP, SRv6, …):

```bash
# IPv4/TCP, dport 443
sudo xdp-ninja -i eth0 "eth/ipv4/tcp[dport==443]"

# Up to 3 VLAN tags before IPv4
sudo xdp-ninja -i eth0 "eth/vlan{1,3}/ipv4/tcp"

# MPLS label stack (terminates at the s-bit)
sudo xdp-ninja -i eth0 "eth/mpls+/ipv4/tcp"

# VXLAN inner IPv4/TCP
sudo xdp-ninja -i eth0 "eth/ipv4/udp/vxlan/eth/ipv4/tcp"

# Capture only headers + 64 bytes when the inner TCP dport > 1024
sudo xdp-ninja -i eth0 \
  "eth/ipv4/tcp capture headers+64 where tcp.dport > 1024"

# fexit: filter on the XDP return action
sudo xdp-ninja -i eth0 --mode exit \
  "eth/ipv4/tcp where action == XDP_DROP"
```

Run `xdp-ninja --dsl-help` for the grammar + bundled protocol catalogue, or `xdp-ninja --dsl-help <proto>` (e.g. `--dsl-help ipv4`) to see a protocol's field list, dispatch parents/children, and any variable-layout note.

User-facing CLI guide: [docs/ja/dsl-usage.md](./docs/ja/dsl-usage.md). Internal architecture, codegen ABI, vocab authoring, and P4-16 conformance: [docs/ja/dsl-internals.md](./docs/ja/dsl-internals.md). Formal grammar (EBNF): [docs/ja/dsl-grammar.md](./docs/ja/dsl-grammar.md). Index: [docs/ja/dsl-overview.md](./docs/ja/dsl-overview.md).

xdp-ninja's `.p4` vocab files are a strict subset of P4-16 (see internals §5). They are NOT a full p4c-compatible program: the bundled fragments declare only `header` / `const` / `parser` blocks (no `action` / `table` / `control` / `apply` / `extern`).

#### Legacy: tcpdump syntax (`--cbpf`)

Pass `--cbpf` to interpret the filter expression as tcpdump syntax and compile it to eBPF via [cbpfc](https://github.com/cloudflare/cbpfc). Kept for backwards compatibility. Each invocation prints a deprecation notice on stderr; the flag is expected to retire once the DSL surface stabilises.

```bash
sudo xdp-ninja --cbpf -i eth0 "host 10.0.0.1 and tcp port 80"
```

### Sharded output

For high-rate captures, xdp-ninja uses a per-CPU sharded ringbuf and each CPU writes its own pcap-ng file with no lock. With `-w capture.pcap`:

```
capture.pcap          # all shards merged, time-ordered (ready to use)
capture.pcap.cpu0     # CPU 0 packets (kept)
capture.pcap.cpu1     # CPU 1 packets (kept)
...
```

When capture stops (Ctrl-C or `-c`), xdp-ninja merges the per-CPU shards into `capture.pcap` as a single time-ordered pcap-ng, so the base path is ready to open directly (`tcpdump -r capture.pcap`). The `.cpuN` shards are left in place; you can also read one with `tcpdump -r capture.pcap.cpu0` or merge them yourself with `mergecap -w merged.pcap capture.pcap.cpu*`. `xdp-ninja convert` handles `--raw-dump` `.raw` shards, not pcap-ng shards.

Without `-w` (streaming to stdout), all CPUs are merged into a single pcap-ng stream (serialized), so `sudo xdp-ninja ... | tcpdump -r -` shows every core's packets. Use `-w` for high-rate captures — stdout serialization is for the interactive path.

### Performance flags (high-rate captures)

| Flag | Purpose |
|------|---------|
| `--snaplen N` | Cap per-packet capture bytes (CLI override). Default = full packet (1500 B), libpcap-equivalent |
| `--fast-reader` | mmap+atomic ringbuf reader (lower CPU than cilium/ebpf generic) |
| `--no-wakeup` | Suppress eventfd wake per submit. Trades p50 latency for throughput. **Requires `--fast-reader`** |
| `--ringbuf-size MB` | Per-CPU ringbuf size (default 16 MB) |
| `--raw-dump` | Raw bytes path; convert offline with `xdp-ninja convert` |
| `--rx-cores N` | Split-core: pin ringbuf consumers to cores `N..2N-1`, off the RX softirqs (set the NIC to `N` queues yourself via `ethtool -L combined N`). +30% on `-w` output. **Requires `--fast-reader`**; pair with `--busy-poll --no-wakeup` |
| `--busy-poll` | Spin the fast-reader shards instead of sleeping in `epoll_wait`. Burns a core per shard. **Requires `--fast-reader`** |
| `--null-output` | Drop output entirely (bench only) |

Detailed flag reference + DSL `capture` clause's snaplen trade-off: [docs/ja/dsl-usage.md](./docs/ja/dsl-usage.md#performance-flags).

High-rate tuning — which lever in which order, and what doesn't work: [docs/ja/tuning.md](./docs/ja/tuning.md).

### Hand-test: `--dump-asm`

`--dump-asm` compiles a filter and prints the resulting eBPF asm without loading. No `-i`/`-p` needed:

```bash
# Just the filter body (kunai/cbpfc Main + Callbacks + CaptureInfo)
xdp-ninja --dump-asm filter "eth/ipv4/tcp where tcp.dport == 443"
xdp-ninja --dump-asm filter --cbpf "tcp port 443"     # legacy tcpdump syntax

# Wrapped program with prologue/epilogue (mode-aware)
xdp-ninja --dump-asm full --mode entry "eth/ipv4/tcp[dport==443]"
xdp-ninja --dump-asm full --mode exit  "eth/ipv4/tcp where action == XDP_DROP"
xdp-ninja --dump-asm full --mode xdp --cbpf "tcp port 443"
```

Use this to sanity-check DSL parse/type errors, inspect codegen output, or verify the wrapped program shape per mode.

### Attaching to subfunctions (entry/exit only)

You can use `--func` to attach fentry/fexit to a `__noinline` subfunction inside the target XDP program, instead of the entry function. The subfunction must take `struct xdp_md *ctx` as its first argument.

Use `--list-funcs` to discover available functions:

```bash
sudo xdp-ninja -i eth0 --list-funcs
```

Both global and static `__noinline` subfunctions work:

```c
/* Global — always survives in BTF */
__attribute__((noinline))
int classify_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end) return 1;
    return 2;
}

/* Static — also works, but the body must be non-trivial */
static __attribute__((noinline))
int parse_headers(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end) return -1;
    return 2;
}
```

> **Note:** The subfunction must have a non-trivial body (e.g. access `ctx->data`). A trivial body like `return 2;` will be constant-folded by `clang -O2`, eliminating the bpf2bpf call entirely.

`--func`, `--list-funcs`, `--list-progs`, `--list-params`, and `--arg-filter` only apply to `entry`/`exit` modes (xdp-native has no tracing args or BTF subfunction concept).

## Options

| Option | Description | Modes |
|---|---|---|
| `-i, --interface` | Network interface to capture on | entry, exit, xdp |
| `-p, --prog-id` | BPF program ID to attach to (alternative to `-i`) | entry, exit, tc-entry, tc-exit |
| `--mode` | `entry` (default), `exit`, `xdp`, `tc-entry`, `tc-exit` | — |
| `-w, --write` | Write to pcap file instead of stdout | all |
| `-c, --count` | Stop after N packets (0 = unlimited) | all |
| `-v, --verbose` | Verbose output to stderr | all |
| `--cbpf` | Use the legacy tcpdump/cBPF syntax (compiled via cbpfc); default is the built-in DSL. Prints a deprecation notice when used. | all |
| `--dsl-help` | Print the DSL grammar + bundled protocol catalogue and exit (no `-i`/`-p` required) | — |
| `--dump-asm` | Print compiled eBPF asm and exit. Values: `filter` (kunai/cbpfc body only) \| `full` (wrapped program). No `-i`/`-p` required | — |
| `--func` | Attach to a specific `__noinline` subfunction by BTF name | entry, exit, tc-entry, tc-exit |
| `--list-funcs` | List available BTF functions in the target program and exit | entry, exit, tc-entry, tc-exit |
| `--list-progs` | List tail call targets reachable from the target program and exit | entry, exit, tc-entry, tc-exit |
| `--list-params` | List filterable parameters for `--func` (requires `--func`) | entry, exit, tc-entry, tc-exit |
| `--arg-filter` | Filter by function argument value (requires `--func`); format: `param=value`, `param>=val`, `param<=val`, `param=min..max` | entry, exit, tc-entry, tc-exit |

Specify either `-i` or `-p`, not both.

## Prerequisites

Common:

- Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- Root privileges (or `CAP_BPF` + `CAP_NET_ADMIN`)
- Go 1.25+ (build only — pre-built binaries don't need Go)
- libpcap-dev (runtime + tcpdump-syntax filter compilation)

Mode-specific:

- **`--mode entry` / `exit`**: an XDP program already attached to the target interface, with BTF.
- **`--mode xdp`**: no XDP attached to the interface (xdp-ninja becomes the XDP program).
- **`--mode tc-entry` / `tc-exit`**: a tc clsact filter program already loaded with BTF; target by `-p <progID>`.
- **DSL with chain quantifier (`+`, `*`, `{n,m>4}`), parser-machine self-loop (variable-length headers like IPv6 ext / GTP options / SRv6 segments), or alternation (`(a|b)`)**: kernel 5.17+ (uses `bpf_loop` + bpf2bpf subprograms). Plain DSL chains and `--cbpf` filters work on 5.8+.

```bash
# Debian/Ubuntu
sudo apt install libpcap-dev clang

# Fedora/RHEL
sudo dnf install libpcap-devel clang
```

`clang` is only needed for running BPF load tests locally; not required for using xdp-ninja itself.

## Development

### Build

```bash
make build
```

### Test

```bash
# Unit tests (no root required)
make test

# BPF verifier load tests (root required, needs clang)
make test-bpf

# Integration tests with veth pair (root required, needs clang + tcpdump)
make test-integration

# All tests
make test-all
```

#### Unit tests

Pure Go logic tests. No BPF or root privileges needed.

```bash
make test
# or: go test ./...
```

#### BPF load tests

Verifies that the dynamically generated fentry/fexit/xdp programs pass the kernel's BPF verifier. Tests both with and without filters. Requires root and clang.

```bash
make test-bpf
```

#### Integration tests

End-to-end tests using a veth pair and a dummy XDP program. Requires root, clang, and tcpdump.

```bash
make test-integration
```

This runs `scripts/test/run_tests.sh` which:
1. Creates a veth pair with a dummy XDP program
2. Tests entry/exit capture, filters, pcap output, graceful shutdown
3. Cleans up the veth pair

#### Multi-kernel testing (vimto + QEMU)

BPF load tests and integration tests run on kernel 6.1, 6.6, 6.12, 6.18 via [vimto](https://github.com/lmb/vimto) + QEMU in GitHub Actions.

To run locally:

```bash
# Install vimto and QEMU
CGO_ENABLED=0 go install lmb.io/vimto@v0.4.0
sudo apt install qemu-system-x86

# BPF verifier load tests on a specific kernel
vimto -kernel :6.6 exec -- go test -v -count 1 -timeout 5m ./internal/program/ -run TestBpf
```

## Acknowledgements

xdp-ninja's design was inspired by the following projects:

- [xdp-dump](https://github.com/xdp-project/xdp-tools/blob/main/xdp-dump/README.org) (xdp-tools) — fentry/fexit trampoline approach for tracing XDP programs
- [xdpcap](https://github.com/cloudflare/xdpcap) (Cloudflare) — tcpdump filter compilation via cBPF→eBPF ([cbpfc](https://github.com/cloudflare/cbpfc)), and the overall architecture of capturing XDP packets to pcap
