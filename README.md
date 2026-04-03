# xdp-ninja

xdp-ninja is a tool that captures packets before or after XDP processing, without modifying the existing XDP program🥷

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

It uses BPF trampoline (fentry/fexit) to non-invasively trace the target XDP program. Optionally, a tcpdump-style filter is compiled to eBPF via cbpfc and executed in the kernel, so only matching packets are sent to userspace.

Outputs pcap (pcapng) to stdout. Pipe to `tcpdump`, `wireshark`, etc.

## Usage

```bash
# Capture before XDP, pipe to tcpdump
sudo xdp-ninja -i eth0 | tcpdump -n -r -

# With filter
sudo xdp-ninja -i eth0 "host 10.0.0.1 and tcp port 80" | tcpdump -n -r -

# Capture after XDP (see XDP action in verbose mode)
sudo xdp-ninja -i eth0 --mode exit | tcpdump -n -r -

# Write to pcap file
sudo xdp-ninja -i eth0 -w capture.pcap -c 100

# Attach by BPF program ID (for multi-prog / libxdp setups)
sudo xdp-ninja -p 42 | tcpdump -n -r -

# List available BTF functions in the target program
sudo xdp-ninja -i eth0 --list-funcs

# Attach to a specific __noinline subfunction
sudo xdp-ninja -i eth0 --func process_packet | tcpdump -n -r -

# Capture both before and after (run two instances)
sudo xdp-ninja -i eth0 | tcpdump -n -r -
sudo xdp-ninja -i eth0 --mode exit | tcpdump -n -r -
```

### Options

| Option | Description |
|--------|-------------|
| `-i, --interface` | Network interface to capture on |
| `-p, --prog-id` | BPF program ID to attach to (alternative to `-i`) |
| `--mode` | `entry` (before XDP, default) or `exit` (after XDP) |
| `--func` | Attach to a specific `__noinline` subfunction by BTF name |
| `--list-funcs` | List available BTF functions in the target program and exit |
| `-w, --write` | Write to pcap file instead of stdout |
| `-c, --count` | Stop after N packets (0 = unlimited) |
| `-v, --verbose` | Verbose output to stderr |

Specify either `-i` or `-p`, not both.

### Attaching to subfunctions

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

## Prerequisites

- Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- An existing XDP program attached to the target interface (with BTF)
- Root privileges (or `CAP_BPF` + `CAP_NET_ADMIN`)
- Go 1.21+
- libpcap-dev
- clang (for running BPF load tests)

```bash
# Debian/Ubuntu
sudo apt install libpcap-dev clang

# Fedora/RHEL
sudo dnf install libpcap-devel clang
```

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

# Integration tests with veth pair (root required)
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

Verifies that the dynamically generated fentry/fexit programs pass the kernel's BPF verifier. Tests both with and without cbpfc filters. Requires root and clang.

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
