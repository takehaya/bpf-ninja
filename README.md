# bpf-ninja

> [!NOTE]
> Formerly xdp-ninja. GitHub redirects the old repository URL. The Go module path is `github.com/takehaya/bpf-ninja`, and environment variables use the `BPF_NINJA_*` prefix; `XDP_NINJA_*` names are not read.

bpf-ninja captures packets at BPF hook points: XDP, tc, cgroup-skb and netfilter.
tcpdump cannot show what an XDP or tc program did to a packet, and cBPF filters cannot read the inner headers of VXLAN, GTP, MPLS or SRv6.

- It attaches fentry or fexit to a running program without changing it, so you see the packet the program received, or the packet and verdict it produced.
- `--mode xdp` captures on a netdev that has no XDP program.
- Filters use a built-in DSL that walks through encapsulations, such as `eth/ipv4/udp/vxlan/eth/ipv4/tcp`.
- Output is pcap-ng, to stdout or to per-CPU files.
- The tcpdump syntax (`--cbpf`, through [cbpfc](https://github.com/cloudflare/cbpfc)) is kept for compatibility in an optional libpcap build and is planned for removal.
- The experimental [`inject-run`](docs/en/inject-run.md) adds hooks to selected XDP or tc programs as an unmodified loader loads them (Linux x86-64).

[Documentation / ドキュメント](docs/README.md) · [日本語の導入](docs/ja/getting-started.md) · [Examples](docs/ja/examples/README.md)

## Install

```bash
# One-liner (downloads pre-built binary from GitHub Releases, requires jq)
curl -fsSL https://raw.githubusercontent.com/takehaya/bpf-ninja/main/scripts/install.sh | sudo bash

# Specific version
curl -fsSL https://raw.githubusercontent.com/takehaya/bpf-ninja/main/scripts/install.sh | sudo bash -s -- --version vX.Y.Z

# Or via go install (requires Go; no libpcap needed)
CGO_ENABLED=0 go install github.com/takehaya/bpf-ninja/cmd/bpf-ninja@latest

# Or build from source
git clone https://github.com/takehaya/bpf-ninja.git
cd bpf-ninja
make build
```

The default release archive, `bpf-ninja_<version>_linux_x86_64.tar.gz`, is statically linked and needs no libpcap.
The installer above selects this archive.
DSL filters, pcapng output, and `convert` / `merge` work in this build.

For legacy `--cbpf` filters, download `bpf-ninja_<version>_linux_x86_64_enable_libpcap.tar.gz` from the same release and install its `bpf-ninja` binary.
This variant needs the libpcap runtime.
`checksums.txt` covers both archives.
To build it from source, install a C compiler and the libpcap development package, then run `make build-libpcap`, or:

```bash
CGO_ENABLED=1 go build -tags enable_libpcap ./cmd/bpf-ninja
```

## Quick start

```bash
# Observe the XDP program attached to eth0 (fentry on its entry)
sudo bpf-ninja -i eth0 | tcpdump -n -r -

# Filter with the DSL (the default syntax)
sudo bpf-ninja -i eth0 "eth/ipv4/tcp[dport==80]" | tcpdump -n -r -

# See the verdict (fexit) and filter on it
sudo bpf-ninja -i eth0 --mode exit "eth/ipv4/tcp where action == XDP_DROP" | tcpdump -n -r -

# Capture on a netdev with no XDP program
sudo bpf-ninja --mode xdp -i eth0 "eth/ipv4/tcp[dport==443]" | tcpdump -n -r -

# Attach by program ID: XDP, tc, cgroup-skb or netfilter, detected from the program type
sudo bpf-ninja -p 42 | tcpdump -n -r -

# Write to files and stop after 100 packets (see Sharded output)
sudo bpf-ninja -i eth0 -w capture.pcap -c 100

# Legacy tcpdump syntax (libpcap build only)
sudo bpf-ninja --cbpf -i eth0 "host 10.0.0.1 and tcp port 80" | tcpdump -n -r -
```

## Modes

`--mode` selects the capture point.
bpf-ninja detects the hook kind (XDP, tc clsact, cgroup-skb or netfilter) from the target program's type.

| Mode | Attach via | Existing program needed | Sees return action | Typical use |
|---|---|---|---|---|
| `entry` (default) | fentry on the target program | yes (with BTF) | no, packet only | observe what reaches the production program |
| `exit` | fexit on the target program | yes (with BTF) | yes (`XDP_PASS` / `TC_ACT_OK` / `SK_PASS` / ...) | observe the verdict; filter on `action == ...` |
| `xdp` | attach as the primary XDP on the netdev | no; fails if one is attached | n/a (bpf-ninja returns `XDP_PASS`, or `XDP_DROP` with `--bench-drop`) | capture on a netdev with no XDP; no BTF needed |

`entry` and `exit` attach through a BPF trampoline and leave the target program unchanged.
`tc-entry` and `tc-exit` are deprecated aliases for `entry` and `exit`.

| Hook | Target selection | Notes |
|---|---|---|
| XDP | `-i <iface>` (the interface's XDP) or `-p <progID>` | |
| tc clsact | `-p <progID>` only | The kernel moves the outer VLAN tag into skb metadata, so by default DSL filters see the frame without it; see [Filters](#filters) |
| cgroup-skb | `--cgroup <cgroup v2 path>` (the attached programs) or `-p <progID>` | Packet bytes start at the IP header: chains start at `ipv4`/`ipv6`, and pcap-ng uses LINKTYPE_RAW |
| netfilter | `-p <progID>` (kernel 6.4+, programs attached to `NF_INET_*` hooks through bpf_link) | Packet bytes start at the IP header, as for cgroup-skb; exit-mode verdicts are `NF_DROP` / `NF_ACCEPT` |

```bash
# cgroup-skb: packets start at the IP header
sudo bpf-ninja --cgroup /sys/fs/cgroup/my-service "ipv4/tcp[dport==443]" | tcpdump -n -r -
sudo bpf-ninja --cgroup /sys/fs/cgroup/my-service --mode exit "ipv4/tcp where action == SK_DROP"
```

### freplace programs

`-p <EXT_ID>` also accepts an attached freplace (`BPF_PROG_TYPE_EXT`) program.
`-p <dispatcher_ID> --list-progs` shows their IDs as `freplace` edges.

```sh
sudo bpf-ninja -p <EXT_ID> --mode entry 'eth/ipv4' --mode exit 'eth/ipv4' --emit both -w ext.pcap
sudo bpf-ninja -p <EXT_ID> --list-params
```

- The replaced program sets the packet layout and the action names; probes and BTF parameter lookup target the EXT itself.
- An unattached EXT is rejected.
- If the EXT entry has integer parameters after ctx (for example `orig_ret`), `--arg-filter`, `--list-params` and `--arg-echo` work without `--func`.
- Probing a replaced dispatcher stub is rejected with the EXT ID to use instead.
- Other global subfunctions of a program with live freplace links are guarded.
  `--allow-dispatcher-slot` permits probing them, but a later freplace may then fail with `EBUSY`.
- Link discovery is a snapshot, so a concurrent attachment change can still cause a kernel attach error; run the discovery again after such changes.

### Entry and exit together

`--mode` is repeatable.
`--mode entry EXPR --mode exit EXPR` captures only the packets that match both filters:

```bash
sudo bpf-ninja -i eth0 --mode entry "eth/ipv4/udp[dport==6081]" --mode exit "eth/ipv4/tcp where action == XDP_DROP" -w both.pcapng
```

- The entry filter sees the packet as the program received it; the exit filter sees it as the program left it (after decap or rewrite), plus the verdict.
- bpf-ninja holds the entry image in a per-CPU slot until the verdict is known.
  For example, you can capture the pre-decap header of every packet the program dropped, and nothing else.
- `--emit both` (the default) writes both images; `--emit entry` or `--emit exit` writes one.
- Entry records go to a `<hook>:entry` pcap-ng interface.
  Both images of one invocation carry the same opaque `epb_packetid` (CPU and per-CPU sequence, no kernel address), so they pair up.
- `-c` counts records: `-c 10` with `--emit both` is 5 pairs.
- The merged `-w` file and the output of `merge` and `convert` drop the id; pair on the per-CPU shard files or the raw dump, which keep it (see [offline output](docs/ja/examples/offline-output.md)).
- Under ring pressure an entry record can appear without its exit twin, because the exit-side reservation failed after the entry was written.
  Treat an unpaired entry as a drop, not as a verdict.

Gated capture attaches two probes to the target.
Kernels 7.0, 7.1 and 7.2.0 to 7.2.5 refuse a second tracing attach to a program that performs tail calls, as Cilium and Katran's inline decap do (CVE-2026-92485).
On those kernels, and on kernels whose version bpf-ninja cannot read, bpf-ninja refuses gated capture of such a program with an explanation.
It does not try, because the failed attach can leave the kernel's trampoline inconsistent and crash the machine.
Capture one point at a time there, or use 7.2.6, 7.3-rc1 or later.

## Filters

bpf-ninja reads the filter as the built-in DSL by default.
Write it as a protocol stack chain.
It covers what tcpdump's cBPF can express and adds the encapsulation cases cBPF cannot, such as MPLS label stacks, VXLAN inner Ethernet, GTP-U inner IP and SRv6:

```bash
# IPv4/TCP, dport 443
sudo bpf-ninja -i eth0 "eth/ipv4/tcp[dport==443]"

# Up to 3 VLAN tags before IPv4
sudo bpf-ninja -i eth0 "eth/vlan{1,3}/ipv4/tcp"

# MPLS label stack (terminates at the s-bit)
sudo bpf-ninja -i eth0 "eth/mpls+/ipv4/tcp"

# VXLAN inner IPv4/TCP
sudo bpf-ninja -i eth0 "eth/ipv4/udp/vxlan/eth/ipv4/tcp"

# Capture only headers + 64 bytes when the inner TCP dport > 1024
sudo bpf-ninja -i eth0 \
  "eth/ipv4/tcp capture headers+64 where tcp.dport > 1024"

# fexit: filter on the XDP return action
sudo bpf-ninja -i eth0 --mode exit \
  "eth/ipv4/tcp where action == XDP_DROP"
```

`bpf-ninja --dsl-help` prints the grammar and the bundled protocol catalogue.
`bpf-ninja --dsl-help <proto>` (for example `--dsl-help ipv4`) shows a protocol's fields, its dispatch parents and children, and any variable-layout note.

- A filter reads the first 512 bytes of the packet.
  In entry and exit mode only that prefix is copied for the filter, so layers and fields past it never match.
  In `--mode xdp` a chain of fixed-size headers can read further, but variable-length walks (IPv4/TCP options, IPv6 extension headers, SRv6 segments) and everything read after them must stay inside the first 512 bytes, or the packet is rejected.
- At a tc target the kernel has usually moved the outer VLAN tag into skb metadata: always at ingress, and at egress for frames sent through a VLAN device with the default `reorder_hdr on`.
  By default the filter reads the bytes as the kernel holds them, so `eth/ipv4/tcp` also matches single-tagged frames, and a filter that requires the outer tag (`eth/vlan[tci==100]/...`) is a compile error.
  `--tc-vlan-reinsert` puts the tag back into the bytes the filter reads, so you write filters against the frame as it was on the wire.
  Captured bytes stay as the kernel holds them either way.
  [dsl-usage.md](./docs/ja/dsl-usage.md#tc-での-vlan-tag) covers optional tags, QinQ and tunnels.
- bpf-ninja's `.p4` vocab files are a strict subset of P4-16: they declare only `header`, `const` and `parser` blocks, not a full p4c-compatible program.

Guides: [DSL usage](./docs/ja/dsl-usage.md), [grammar (EBNF)](./docs/ja/dsl-grammar.md), [internals and codegen ABI](./docs/ja/dsl-internals.md), [index](./docs/ja/dsl-overview.md).

### Legacy: tcpdump syntax (`--cbpf`)

`--cbpf` reads the filter as tcpdump syntax and compiles it to eBPF through [cbpfc](https://github.com/cloudflare/cbpfc).
It needs the `enable_libpcap` release archive or a build with `make build-libpcap` (see [Install](#install)).
In the default build, `--cbpf` stops with build guidance, also with `--dump-asm`; only `--dsl-help` runs regardless.
Each run prints `warning: --cbpf selects the legacy cBPF path; prefer the default DSL.` on stderr.

```bash
sudo bpf-ninja --cbpf -i eth0 "host 10.0.0.1 and tcp port 80"
```

### Check a filter without loading: `--dump-asm`

`--dump-asm` compiles a filter and prints the eBPF asm without loading it.
It needs no `-i` or `-p`:

```bash
# Just the filter body
bpf-ninja --dump-asm filter "eth/ipv4/tcp where tcp.dport == 443"

# The wrapped program with its prologue and epilogue, per mode
bpf-ninja --dump-asm full --mode entry "eth/ipv4/tcp[dport==443]"
bpf-ninja --dump-asm full --mode exit  "eth/ipv4/tcp where action == XDP_DROP"

# Legacy tcpdump syntax (libpcap build only)
bpf-ninja --dump-asm filter --cbpf "tcp port 443"
```

Resolver warnings, such as the never-matching second member of `eth/ipv4/(tcp|tcp)`, go to stderr as `warning:` lines, as in a live capture.
stdout carries only the asm, so you can diff or pipe dumps.
`--dump-hook` picks the hook (`xdp`, `tc`, `cgroup-skb` or `netfilter`) whose prologue `--dump-asm full` renders.

## Output

### Sharded output

Each CPU writes its own pcap-ng file from its own ringbuf shard, with no lock.
With `-w capture.pcap`:

```
capture.pcap          # all shards merged, time-ordered (ready to use)
capture.pcap.cpu0     # CPU 0 packets (kept)
capture.pcap.cpu1     # CPU 1 packets (kept)
...
```

- When the capture stops (Ctrl-C or `-c`), bpf-ninja merges the shards into `capture.pcap` as one time-ordered pcap-ng, ready for `tcpdump -r capture.pcap`.
- The `.cpuN` shards stay in place.
  You can read one with `tcpdump -r capture.pcap.cpu0`, or merge them yourself with `mergecap -w merged.pcap capture.pcap.cpu*`.
- `bpf-ninja convert` reads `--raw-dump` `.raw` shards, not pcap-ng shards.
- Without `-w`, bpf-ninja serializes all CPUs into one pcap-ng stream on stdout, so `sudo bpf-ninja ... | tcpdump -r -` shows every core's packets.
  Use `-w` for high-rate captures.

On exit, the capture prints a `capture status=...` line to stderr.
It counts selected export attempts, submitted records, reserve, lookup and copy failures, consumed and written records, intentional limits, and records drained after the producers stop.
A producer or output failure makes the status `incomplete`.
The counters do not count filter and parse rejections, so they do not cover every observed packet.
[Capture completion](docs/capture-lifecycle.md) describes the fields, shutdown, per-tag acknowledgements and output limits.

### Performance flags (high-rate captures)

| Flag | Purpose |
|------|---------|
| `--snaplen N` | Force the per-packet capture length. 0 (the default) uses the DSL `capture` clause, else 1500 bytes |
| `--fast-reader` | mmap+atomic ringbuf reader (lower CPU than cilium/ebpf generic) |
| `--no-wakeup` | Suppress eventfd wake per submit. Trades p50 latency for throughput. **Requires `--fast-reader`** |
| `--ringbuf-size MB` | Total ringbuf data budget in MiB, a power of two (default 64); divided across possible CPU IDs, with a 64 KiB minimum per shard |
| `--raw-dump` | Raw bytes path; convert offline with `bpf-ninja convert` |
| `--rx-cores N` | Pin readers to permitted CPU IDs at or above `N`. All producer shards are drained. **Requires `--fast-reader`**; configure RX affinity separately. |
| `--busy-poll` | Spin the fast-reader shards instead of sleeping in `epoll_wait`. Burns a core per shard. **Requires `--fast-reader`** |
| `--null-output` | Drop output entirely (bench only) |
| `--rx-hwts` | Use NIC hardware timestamps (`bpf_xdp_metadata_rx_timestamp` kfunc, Linux 6.8+). **Requires `--mode xdp`**; falls back to software timestamps when the kfunc or driver lacks support |
| `--legacy-timestamp` | Replace the per-packet kernel `bpf_ktime_get_ns()` timestamp with userland `time.Now()` taken when the reader reads the record (shared across a read batch on the default reader). No effect with `--raw-dump` |
| `--in-memory-buffer MB` | Buffer up to MB MiB per shard in pre-touched heap and write it out only when the buffer fills or at exit, keeping `write(2)` off the hot path. Memory use is MB × shard count. **Requires `--raw-dump`** |
| `--observer-prefetch` | Entry/exit only: always copy the full 512-byte scratch instead of only the prefix the filter needs. Costs observer CPU, but can speed up the observed program by warming its L1 data cache. Default off |

[dsl-usage.md](./docs/ja/dsl-usage.md#performance-flags) covers the flags in detail and the snaplen trade-off of the DSL `capture` clause.
[tuning.md](./docs/ja/tuning.md) gives the order in which to try them.

### Diagnostics and benchmarking flags

| Flag | Purpose |
|------|---------|
| `--bench-drop` | `--mode xdp` only (ignored otherwise): return `XDP_DROP` for every packet, matched or not, after capturing the matched ones, so no packet reaches the host stack. Benchmarks only |
| `--latency-sample-period N` | Sample every Nth record's BPF-submit → reader-read latency per shard. **Requires `--raw-dump` and `--fast-reader`**; otherwise nothing is sampled |
| `--latency-sample-output FILE` | Write the latency samples as TSV (one ns value per line); empty prints a percentile summary to stderr |
| `--cpuprofile FILE` | Write a Go CPU profile |
| `--no-async-preempt-off` | By default bpf-ninja re-execs with `GODEBUG=asyncpreemptoff=1`; this flag keeps Go's SIGURG-based preemption enabled (diagnostic opt-out) |
| `--no-cpu-affinity` | Do not pin shard readers to CPUs (also disables `--rx-cores` pinning). Diagnostic opt-out |

## Attaching to subfunctions (entry/exit only)

`--func` attaches fentry or fexit to a `__noinline` subfunction of the target program instead of its entry function.
The subfunction must take the program's context (for example `struct xdp_md *ctx`) as its first argument.
`--func`, `--list-funcs`, `--list-progs`, `--list-params` and `--arg-filter` apply only to `entry` and `exit` modes.

```bash
# List BTF functions and whether the loaded program has them
sudo bpf-ninja -i eth0 --list-funcs

# Attach to a subfunction
sudo bpf-ninja -i eth0 --func process_packet | tcpdump -n -r -

# Several (program, func) pairs in one run: -p and --func are repeatable,
# and each func attaches in every listed program whose BTF has it.
# All attach points share one ringbuf and merge into one pcap.
sudo bpf-ninja -p 1610 -p 1611 -p 1614 \
  --func upf_capture_point_ul --func upf_capture_point_dl -w all.pcap
```

`--list-funcs` keeps absent functions and external declarations in the list, including functions of other programs that share the BTF.
Text rows include a short reason; `--json` adds an `availability` object with the BTF type ID when known.
`present` means the function is in the loaded `func_info`; the kernel still runs its other attach checks.
[Function availability troubleshooting](docs/en/attach-troubleshooting.md) explains the reasons.

Global and static `__noinline` subfunctions both work:

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

- The subfunction needs a non-trivial body, for example one that reads `ctx->data`.
  `clang -O2` constant-folds a trivial body like `return 2;` and removes the bpf2bpf call.
- Arguments you read with `--arg-filter` or `--arg-echo` must be used in the subfunction body.
  `clang -O2` drops unused arguments from the calling convention even though BTF still lists them.
  The trampoline then saves whatever stale value is in that register: `--list-params` looks fine and unfiltered capture works, but exact matches never hit.
- Mark such arguments as used with `KEEP_ARGS()` from [`include/keep_args.h`](include/keep_args.h), which adds no instructions:

```c
#include "keep_args.h"

__attribute__((noinline))
int capture_point(struct xdp_md *ctx, __u64 imsi, __u32 teid) {
    KEEP_ARGS(ctx, imsi, teid);
    return 0;
}
```

If an exact `--arg-filter` never matches, check the value the trampoline saved with `--arg-echo` first.

### Filtering pointer members

`--arg-filter` can read an integer or enum member through a struct or union pointer argument.
Use `->` for the argument pointer and `.` for nested members.
Names, offsets, widths and signedness come from the target program's BTF.
List the usable expressions first:

```sh
sudo bpf-ninja -p <ID> --func sdf_classify --list-params --members
sudo bpf-ninja -p <ID> --func sdf_classify --list-params --members --json
```

For example, with `sdf_classify(struct xdp_md *ctx_buff, struct classifier_query *q)`:

```sh
sudo bpf-ninja -p <ID> --func sdf_classify --arg-filter 'q->imsi=262010000000001'
sudo bpf-ninja -p <ID> --func sdf_classify --arg-filter 'q->target.pdr_id=3'
sudo bpf-ninja -p <ID> --func sdf_classify --arg-filter 'q->seid=1..9'
sudo bpf-ninja -p <ID> --func sdf_classify --arg-echo 'q->imsi' 'q->target.pdr_id'
```

- The `--members` tree shows types (with typedef names), offsets, sizes, signedness, and whether `--arg-filter` and `--arg-echo` accept each expression.
  It gives the reason for rejected expressions, uses promoted names for anonymous members, and flags ambiguous names.
  It shows 3 named levels by default; `--members-depth N` (1 to 32) changes that, and omitted branches are marked.
- Members and integer arguments support `=`/`==`, `!=`, `>=`, `<=` and inclusive `min..max` ranges, with widths of 1, 2, 4 or 8 bytes.
- `be16(443)`, `be32(...)` and `be64(...)` give network-order equality; the width must match, and ordered comparisons or ranges with them are refused.
- Scalar pointers use `value[0]`; bare pointers accept `value==null` and `value!=null` without dereferencing.
- Bitfields, arrays and further pointer dereferences are not supported.
- A null pointer or a failed kernel read rejects the call, or suppresses its echo record.
- Member reads run in the existing entry or exit probe and add no probe.
  Gated capture still needs two probes; see [Entry and exit together](#entry-and-exit-together).
- `--list-params --json` marks pointers with `kind` (`ptr-struct`, `ptr-union` or `ptr`) and `type_name`; `--members` adds a `members` tree.
  Text goes to stderr and JSON to stdout.
- Bare `--arg-echo` prints integer arguments; positional expressions pick the arguments or members to print.
- Set keys support member mappings such as `key(dport=arg:key->dport)`, and bind same-name members when the mapping is omitted and unique.
- Filters and set keys run at both stages of gated capture; both must match.

At function entry, a member holds whatever the caller put there, which may be stale or uninitialized on some paths.
Check with `--arg-echo` before trusting a filter.
If the callee fills the field, use exit mode or a function reached after initialization, then check again.
The [English guide](docs/en/arg-member-filter.md) and [日本語ガイド](docs/ja/arg-member-filter.md) cover discovery, syntax, BTF resolution, read failures and a worked IMSI example.

## Sets

A set is a pinned BPF hash map whose key is the value to match.
Entries added or removed during a capture take effect at once, without re-attaching.
`bpf-ninja set` manages entries by field name, using the map's BTF.

```bash
# Match a function argument
sudo bpf-ninja set create /sys/fs/bpf/subs --key "imsi:u64"
sudo bpf-ninja set add /sys/fs/bpf/subs imsi=999990000000001
sudo bpf-ninja -p 1661 --func upf_capture_point_ul \
  --set "subs=/sys/fs/bpf/subs" --arg-filter "@subs" -w subs.pcap

# Capacity defaults to 1024 (set create --max-entries). resize keeps the entries
# and schema; the new capacity takes effect from the next attach.
sudo bpf-ninja set resize /sys/fs/bpf/subs --max-entries 4096

# Match a packet field (GTP TEID, SRv6 SID); works on fentry and xdp
sudo bpf-ninja set create /sys/fs/bpf/teids --key "teid:u32"
sudo bpf-ninja set add /sys/fs/bpf/teids teid=0x3039
sudo bpf-ninja -p 1661 --set "teids=/sys/fs/bpf/teids" \
  'eth/ipv4/udp/gtp[teid in @teids]' -w teids.pcap

# A 128-bit SRv6 SID (the IPv6 destination): key type ipv6, value an IPv6 literal
sudo bpf-ninja set create /sys/fs/bpf/sids --key "dst:ipv6"
sudo bpf-ninja set add /sys/fs/bpf/sids dst=fc00::1
sudo bpf-ninja -i eth0 --mode xdp --set "sids=/sys/fs/bpf/sids" \
  'eth/ipv6[dst in @sids]'
```

[The set guide](docs/ja/cli/sets.md) covers composite keys, tags, per-tag output and caps.

## Load-time hooks

`inject-run` starts an unmodified BPF loader and adds hooks to selected XDP or tc programs as it loads them.
It is experimental and runs on Linux x86-64 only.
`--list-progs --list-maps` shows the map operations of a loaded program.

- [inject-run](docs/en/inject-run.md): usage, rules and limits.
- [Walkthrough](docs/en/inject-walkthrough.md) from discovery to an fentry observer and a capture, with [example sources](examples/inject-walkthrough/README.md).
- [Observer examples](docs/en/inject-observers.md): in-kernel counters, CPU-tagged failures and timing across hooks, with [example sources](examples/inject-observers/README.md).

## Options

The [complete command reference](docs/ja/cli/generated/commands.md) lists every flag and subcommand; [protocols.md](docs/ja/cli/generated/protocols.md) lists the DSL protocols and fields.
Specify exactly one of `-i`, `-p` or `--cgroup`.

| Option | Description | Modes |
|---|---|---|
| `-i, --interface` | Network interface to capture on (XDP hook) | entry, exit, xdp |
| `-p, --prog-id` | BPF program ID to attach to, for any supported hook (detected from the program type); alternative to `-i` | entry, exit |
| `--prog-name` | Select target program(s) by name instead of ID (requires `-i`); resolved against the interface's reachable program tree. Repeatable. Kernel names are truncated to 15 chars, so a full name matches by prefix | entry, exit |
| `--cgroup` | cgroup v2 path; targets the cgroup-skb program(s) attached to it (alternative to `-i` / `-p`) | entry, exit |
| `--mode` | `entry` (default), `exit`, `xdp` (`tc-entry`/`tc-exit` are deprecated aliases). Repeatable: `--mode entry EXPR --mode exit EXPR` captures only packets matching both (see Modes above) | n/a |
| `--emit` | With two `--mode`: which image to write for a packet that matched both filters: `both` (default), `entry` or `exit` | entry+exit |
| `-w, --write` | Write to pcap file instead of stdout | all |
| `-c, --count` | Stop after N packets (0 = unlimited) | all |
| `-v, --verbose` | Verbose output to stderr | all |
| `--cbpf` | Use the legacy tcpdump/cBPF syntax (compiled via cbpfc); default is the built-in DSL. Prints a deprecation notice when used. | all |
| `--tc-vlan-reinsert` | At a tc target, put the outer VLAN tag the kernel moved into skb metadata back into the bytes the DSL filter reads (`eth/vlan[tci==100]/...` then works; `eth/ipv4/tcp` stops matching tagged frames). Captured bytes stay as the kernel holds them; layer-bounded captures grow by 4 bytes. Not allowed with `--cbpf`, or with a filter at a static `--func` whose context is read with `bpf_probe_read_kernel` | entry, exit |
| `--dsl-help` | Print the DSL grammar + bundled protocol catalogue and exit (no `-i`/`-p` required) | n/a |
| `--dump-asm` | Print compiled eBPF asm and exit. Values: `filter` (kunai/cbpfc body only) \| `full` (wrapped program). No `-i`/`-p` required | n/a |
| `--dump-hook` | Hook whose capabilities/prologue `--dump-asm` renders: `xdp` (default) \| `tc` \| `cgroup-skb` \| `netfilter` (offline compiles have no target program to auto-detect from) | n/a |
| `--func` | Attach to a specific `__noinline` subfunction by BTF name | entry, exit |
| `--list-funcs` | List all BTF functions with loaded availability and exit | entry, exit |
| `--allow-dispatcher-slot` | Allow probing an unreplaced global dispatcher subfunction; may block later freplace with `EBUSY` | entry, exit |
| `--list-progs` | List reachable freplace, tail-call, and redirect-map targets and exit | entry, exit |
| `--list-maps` | With `--list-progs`, also list each function's calls and the maps it uses, with the op (`lookup`, `update`, `delete`, `tail_call`, ...) and source line, read from the loaded program's translated instructions (needs root) | entry, exit |
| `--lookups-json` | With `--list-maps`, read the file `inject-run --lookups-json` wrote and mark each map use with its load-time site and why it cannot be instrumented | entry, exit |
| `--list-params` | List integer and pointer parameters for the target function (requires `--func` or an EXT entry with filterable parameters) | entry, exit |
| `--members` | With `--list-params`, show the pointee member tree or scalar `[0]` expression, layout, and filter/echo eligibility | entry, exit |
| `--members-depth` | Maximum named member levels for `--list-params --members` (default 3, range 1–32); omitted branches are marked | entry, exit |
| `--json` | Print `--list-progs` (with `--list-maps`) / `--list-funcs` / `--list-params` output as JSON on stdout instead of text on stderr | entry, exit |
| `--arg-filter` | Filter an integer argument or pointer member (requires `--func` or an EXT entry with filterable parameters); `=`, `==`, `!=`, `>=`, `<=`, and `min..max` for `param`, `param->member.member`, or `param[0]`; `be16/32/64(value)` for equality and `param==null`/`!=null` for pointers | entry, exit |
| `--set` | Define a named match set backed by a pinned BPF hash map: `NAME=/sys/fs/bpf/path[,key(field=arg:expression,...)]` (including members and `[0]`). Reference it with `--arg-filter @NAME` or the DSL predicate `layer[field in @NAME]`; manage entries at runtime with `bpf-ninja set`. Repeatable | all |
| `--arg-echo` | Print integer args or positional member/scalar-pointee expressions (e.g. `--arg-echo 'q->imsi' 'value[0]'`) for each call, gated by `--arg-filter`, instead of capturing. Requires `--func` or an EXT entry with filterable parameters, and a single `--mode`; combine with `-c N` | entry, exit |
| `--record` | At an injected hook, write decision state as each packet's pcapng comment: `filter` (default; the arguments and members `--arg-filter` and `--set` keys read), `entry` (site, status, key and value) or `none`. See [the walkthrough](docs/en/inject-walkthrough.md#record-the-decision-state-with-each-packet) | entry, exit |
| `--record-max` | With `--record entry`, record at most N bytes each of the key and the value (default 256, at most 4096) | entry, exit |
| `--split-by-tag` | Route matched packets to one pcap per set-map value (tag): `-w out.pcap` yields `out.<tag>.pcap` (requires `-w`) | all |
| `--max-bytes` | Stop the whole capture once total output bytes reach N (works with or without `--split-by-tag`). Per-tag caps live on the set entries: `set add ... max-bytes=N` (0 / omitted = uncapped; entries sharing a tag share one budget: an uncapped entry makes the tag uncapped, otherwise the largest cap wins) | all |
| `--exit-when-capped` | Exit 0 once every entry that has a per-entry cap reached it; uncapped entries don't participate (requires `--split-by-tag` and at least one `--set`) | all |
| `--finalize-on-del` | When a tag's last set entry is removed, merge its shards into `out.<tag>.pcap` while capturing continues; the file appearing is the completion ack (requires `--split-by-tag` and at least one `--set`) | all |
| `-V, --version` | Print the version and exit | n/a |

## Prerequisites

Common:

- Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- Root privileges
- Go 1.25+ to build; pre-built binaries do not need Go
- For the optional `enable_libpcap` build only: libpcap at run time, and a C compiler (cgo uses gcc unless `CC` says otherwise) and libpcap-dev to build from source

By feature:

| Feature | Needs |
|---|---|
| `--mode entry` / `exit` | A target BPF program (XDP, tc clsact, cgroup-skb or netfilter) already loaded with BTF. With `-i`, an XDP program attached to the interface; tc targets by `-p <progID>`; cgroup-skb targets by `--cgroup <path>` or `-p` |
| `--mode xdp` | No XDP program attached to the interface; bpf-ninja becomes the XDP program |
| Pointer arguments: member filters and echo, scalar-pointee `[0]` reads, pointer NULL comparisons, member-derived set keys | `bpf_get_func_arg` (Linux 5.17+) |
| Static XDP and tc context fallback | When the kernel rejects direct context reads in a static function, bpf-ninja reads the context with `bpf_probe_read_kernel`, after checking that every call from the entry function passes the context as the first argument. Exit and gated capture on this path need `bpf_get_func_ret` (Linux 5.17+). At tc, a filter with `--tc-vlan-reinsert` is refused on this path |
| DSL chain quantifiers (`+`, `*`, `{n,m>4}`) on a fixed-length layer, variable-length headers (IPv6 extension headers, GTP options, SRv6 segments), alternation (`(a\|b)`) | Linux 5.17+ (`bpf_loop` and bpf2bpf subprograms). A repeated variable-length layer (`ipv4+`, `ipv6*`) unrolls to `MAX_DEPTH` parser machines instead of a `bpf_loop` chain; each machine's own option or extension walk keeps the 5.17 requirement |
| Plain DSL chains and `--cbpf` filters | Linux 5.8+ |
| netfilter targets | Linux 6.4+ |
| `--rx-hwts` | Linux 6.8+ and driver support |

```bash
# Optional legacy build dependencies (Debian/Ubuntu)
sudo apt install libpcap-dev

# Optional legacy build dependencies (Fedora/RHEL)
sudo dnf install libpcap-devel
```

`clang` is needed for running BPF load tests locally; install it separately for development. It is not required for using bpf-ninja itself.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution checks.

```bash
make build          # CGO_ENABLED=0, no build tags
make build-libpcap  # CGO_ENABLED=1, -tags enable_libpcap; needs a C compiler and libpcap-dev
```

| Command | Runs | Needs |
|---|---|---|
| `make test` | Unit tests (`go test ./...`), with no BPF | nothing extra |
| `make test-bpf` | `scripts/test/privileged.py`: the privileged Go suites, including verifier load tests of the generated fentry, fexit and xdp programs | root, python3, clang, a C compiler and libpcap-dev (it builds with `-tags enable_libpcap`); see [privileged tests](docs/privileged-tests.md) |
| `make test-integration` | `scripts/test/run_tests.sh`: a veth pair with a dummy XDP program, entry and exit capture, filters, pcap output and graceful shutdown; it cleans up the veth pair | root, clang, tcpdump, libpcap-dev (it runs `make build-libpcap` first) |
| `make test-all` | All three | all of the above |

CI runs the privileged Go suites on kernels 6.1, 6.6, 6.12, 6.15, 6.18, 7.0, 7.1, 7.2 and 7.3-rc4 with [vimto](https://github.com/lmb/vimto) and QEMU.
The shell integration tests run once, on the CI runner's kernel.
To run the load tests on one kernel locally:

```bash
# Install vimto and QEMU
CGO_ENABLED=0 go install lmb.io/vimto@v0.4.0
sudo apt install qemu-system-x86

# BPF verifier load tests on a specific kernel
vimto -kernel :6.6 exec -- go test -v -count 1 -timeout 5m ./internal/program/ -run TestBpf
```

## Publications

- [eBPF Workshop 2026: Kunai](docs/publications/ebpf_workshop_2026/README.md) —
  paper source, figures, measurement data, and build instructions.

## Acknowledgements

bpf-ninja's design was inspired by the following projects:

- [xdp-dump](https://github.com/xdp-project/xdp-tools/blob/main/xdp-dump/README.org) (xdp-tools): the fentry/fexit trampoline approach for tracing XDP programs
- [xdpcap](https://github.com/cloudflare/xdpcap) (Cloudflare): tcpdump filter compilation via cBPF→eBPF ([cbpfc](https://github.com/cloudflare/cbpfc)), and the overall architecture of capturing XDP packets to pcap


## License

bpf-ninja is licensed under the [Apache License 2.0](LICENSE).

The eBPF programs that bpf-ninja generates and loads into the kernel declare the `GPL` license because they call GPL-only kernel helpers.
