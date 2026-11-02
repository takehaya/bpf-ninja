# Walkthrough: observe the map calls of a loaded program

This walkthrough takes a small XDP program from "which maps does it use?" to a live trace of its queue pushes and pops, using `--list-maps`, a rule for `inject-run`, and an fentry observer.
Every output below was recorded on a 7.0 host with the program and loader shown here; long file paths are shortened to `prog.c`.
Nothing is attached to an interface: the loader runs the program with `BPF_PROG_TEST_RUN`.
The program, the loader, the observer and the rule are in [examples/inject-walkthrough](../../examples/inject-walkthrough), with the commands to build and run them.

## The program and its loader

`prog.c` remembers the lengths of recent packets in a two-entry queue, notes each new length in a bloom filter, and reads a per-CPU counter:

```c
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_QUEUE);
  __uint(max_entries, 2);
  __type(value, __u64);
} recent SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
  __uint(max_entries, 16);
  __type(value, __u32);
} seen SEC(".maps");
struct stat {
  __u64 pkts;
  __u64 bytes;
};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct stat);
} stats SEC(".maps");

SEC("xdp")
int entry(struct xdp_md *ctx) {
  __u32 len = ctx->data_end - ctx->data;
  __u64 v = len;
  __u32 k = 0;
  struct stat *st;

  if (bpf_map_peek_elem(&seen, &len))
    bpf_map_push_elem(&seen, &len, BPF_ANY);
  if (bpf_map_push_elem(&recent, &v, BPF_ANY))
    bpf_map_pop_elem(&recent, &v);
  st = bpf_map_lookup_percpu_elem(&stats, &k, 0);
  if (st)
    return st->pkts ? XDP_DROP : XDP_PASS;
  return XDP_ABORTED;
}
char LICENSE[] SEC("license") = "GPL";
```

When the queue is full, the program pops the oldest length to make room, but it never pushes the new length again.
The trace below shows this.

The loader is an ordinary cilium/ebpf program.
It loads `prog.o`, prints the program's ID, then runs the program once a second on packets of 64, 80, 96 and 112 bytes in turn.
With a second argument, it waits for that file to appear before the workload starts; the observer examples use this.
`inject-run` needs no change to it:

```go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// Load prog.o, print the program id, then run the program once a second on
// packets of 64, 80, 96 and 112 bytes in turn, for a minute.
// With a second argument, wait for that file before starting the workload.
func main() {
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		panic(err)
	}
	// A zero-sized BTF key lets queue maps keep their declared value type.
	// Without it the loader retries map creation without BTF, and injected
	// hooks can only describe the value as opaque bytes.
	spec.Maps["recent"].Key = &btf.Struct{Name: "empty_key"}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	defer coll.Close()
	info, _ := coll.Programs["entry"].Info()
	id, _ := info.ID()
	fmt.Println(id)
	// Optional gate used by observers so the initial Bloom misses are observable.
	if len(os.Args) > 2 {
		for {
			if _, err := os.Stat(os.Args[2]); err == nil {
				break
			} else if !os.IsNotExist(err) {
				panic(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	for i := range 60 {
		n := 64 + 16*(i%4)
		ret, err := coll.Programs["entry"].Run(&ebpf.RunOptions{Data: make([]byte, n), Repeat: 1})
		fmt.Fprintf(os.Stderr, "run len=%d action=%d err=%v\n", n, ret, err)
		time.Sleep(time.Second)
	}
}
```

## 1. List the map calls

Run the loader under `inject-run` with only `--lookups-json`.
Nothing is transformed; the file lists what the loader loads:

```sh
bpf-ninja inject-run --lookups-json lookups.json -- ./loader prog.o
```

While the loader runs, `--list-maps` shows the map calls of the loaded program and, with the same file, whether `auto` can instrument each one:

```sh
bpf-ninja -p "$PROG_ID" --list-progs --list-maps --lookups-json lookups.json
```

```
prog 464334  entry
└─ func entry
   ├─ map seen    BloomFilter  peek    prog.c:33  ✓ injectable  (pc 11)
   ├─ map seen    BloomFilter  push    prog.c:34  ✓ injectable  (pc 18)
   ├─ map recent  Queue        push    prog.c:35  ✓ injectable  (pc 24)
   ├─ map recent  Queue        pop     prog.c:36  ✓ injectable  (pc 30)
   └─ map stats   PerCPUArray  lookup  prog.c:37  ✓ injectable  (pc 37)
```

`lookups.json` has the same calls with their load-time `pc` and a starting rule:

```json
"calls": [
  {"kind": "peek", "pc": 11, "map": "seen", "func": "entry", "file": "prog.c", "line": 33},
  {"kind": "push", "pc": 18, "map": "seen", "func": "entry", "file": "prog.c", "line": 34},
  {"kind": "push", "pc": 24, "map": "recent", "func": "entry", "file": "prog.c", "line": 35},
  {"kind": "pop", "pc": 30, "map": "recent", "func": "entry", "file": "prog.c", "line": 36},
  {"kind": "lookup", "pc": 37, "map": "stats", "func": "entry", "file": "prog.c", "line": 37}
],
"rule": {"program": "entry", "auto": true, "maps": ["stats"], "hook": "ninja", "stack_lowest_offset": null}
```

The starting rule names only the maps with lookups, because a rule without `ops` observes lookups only.

## 2. Write the rule

Observe every push and pop and the failed peeks, and leave the lookup alone:

```json
[{"program": "entry", "auto": true, "ops": ["push:any", "pop:any", "peek"], "hook": "ninja", "stack_lowest_offset": -64}]
```

- `push:any` and `pop:any` call the hooks after every call, and `peek`, which means `peek:error`, only when the peek fails (the length is new).
- `stack_lowest_offset` is the caller's audit of the deepest stack access, including aliases and callees; the transform's spill slots go below it.
  This program has no callees, and its deepest access, found with `llvm-objdump -d prog.o`, is `r10 - 0x14`, so -64 is below it.
- Without `maps`, `auto` takes every map; the lookup on `stats` is not instrumented because `lookup` is not in `ops`.

## 3. Load with the hooks

```sh
bpf-ninja inject-run --config rules.json --hooks-json hooks.json -- ./loader prog.o
```

The diagnostic names each hook, its op, map and site:

```
inject-run: program "entry": untrusted hook form global (probe_arg_untrusted_supported)
inject-run: program "entry": injected hook "ninja_seen_peek" (peek map "seen", site pc 11), hook "ninja_seen_push" (push map "seen", site pc 18), hook "ninja_recent_push" (push map "recent", site pc 24), hook "ninja_recent_pop" (pop map "recent", site pc 30), tracee fd 11
```

`hooks.json` gives the kernel ID of the transformed program and each hook with its sites:

```json
{"program": "entry", "func": "entry", "type": "XDP", "prog_id": 464331, "ctx_type": "xdp_md",
 "hook_form": {"form": "global", "reason": "probe_arg_untrusted_supported"}, "skipped": [],
 "hooks": [
  {"name": "ninja_seen_peek", "kind": "typed", "when": "error", "map": "seen",
   "sites": [{"kind": "peek", "pc": 11, "map": "seen", "func": "entry", "file": "prog.c", "line": 33}],
   "untrusted": false, "copied": false, "static": false, "read_only": false},
  ...
 ]}
```

Each hook is a global function of the transformed program:

```c
int ninja_recent_push(struct xdp_md *ctx, u32 site, const __u64 *value, u64 status);
int ninja_recent_pop(struct xdp_md *ctx, u32 site, const __u64 *value, u64 status);
int ninja_seen_peek(struct xdp_md *ctx, u32 site, const __u32 *value, u64 status);
```

`site` is the call's `pc`, and `status` holds the helper's result in the low 32 bits and a push's flags above them.
A pop hook runs after the helper and sees the value it wrote.

## 4. Attach an observer

`inject-run` does not attach observers.
Any fentry program attached to a hook of the program in `prog_id` sees its calls.
This one, `bpf/observer.c` in the example, reads the arguments with `bpf_get_func_arg` and sends them to user space through a ring buffer:

```c
struct event {
  __u32 op;
  __u32 site;
  __u64 value;
  __u64 status;
};
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} events SEC(".maps");

static int report(void *ctx, __u32 op) {
  __u64 site = 0, value = 0, status = 0;
  struct event *e;

  bpf_get_func_arg(ctx, 1, &site);
  bpf_get_func_arg(ctx, 2, &value);
  bpf_get_func_arg(ctx, 3, &status);
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
  e->op = op;
  e->site = site;
  e->value = 0;
  /* The bloom filter holds __u32 values, the queue __u64 ones. */
  bpf_probe_read_kernel(&e->value, op == 2 ? sizeof(__u32) : sizeof(__u64),
                        (void *)value);
  e->status = status;
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fentry/ninja_recent_push")
int on_push(void *ctx) { return report(ctx, 0); }

SEC("fentry/ninja_recent_pop")
int on_pop(void *ctx) { return report(ctx, 1); }

SEC("fentry/ninja_seen_peek")
int on_peek(void *ctx) { return report(ctx, 2); }
```

The Go side, `observer/main.go`, opens the transformed program by its ID, makes it the attach target, and prints each event:

```go
target, _ := ebpf.NewProgramFromID(ebpf.ProgramID(id))
spec, _ := ebpf.LoadCollectionSpec("observer.o")
for _, p := range spec.Programs {
	p.AttachTarget = target
}
coll, _ := ebpf.NewCollection(spec)
for _, name := range []string{"on_push", "on_pop", "on_peek"} {
	l, _ := link.AttachTracing(link.TracingOptions{Program: coll.Programs[name]})
	defer func() { _ = l.Close() }()
}
// read coll.Maps["events"] with ringbuf.NewReader and print each record
```

Reading the hook's pointer arguments directly from the fentry context instead (`BPF_PROG` with a `const __u64 *value`) was refused on 7.0 with `invalid bpf_context access`, and bpftrace 0.25 lists the hooks (`fentry:bpf:ID:ninja_recent_push`) but could not parse their arguments.

## 5. Read the trace

The observer started after the loader's first run, a 64-byte packet that filled the first slot of the queue:

```
peek site=11 value=80 ret=-2 flags=0
push site=24 value=80 ret=0 flags=0
peek site=11 value=96 ret=-2 flags=0
push site=24 value=96 ret=-7 flags=0
pop  site=30 value=64 ret=0 flags=0
peek site=11 value=112 ret=-2 flags=0
push site=24 value=112 ret=0 flags=0
push site=24 value=64 ret=-7 flags=0
pop  site=30 value=80 ret=0 flags=0
push site=24 value=80 ret=0 flags=0
push site=24 value=96 ret=-7 flags=0
pop  site=30 value=112 ret=0 flags=0
```

- A peek appears only for a length the bloom filter has not seen (`ret=-2`, `ENOENT`), because the rule observes failed peeks only.
- The third packet's push fails with `E2BIG` (`ret=-7`): the queue holds 64 and 80.
  The pop that follows takes 64 out, so the queue keeps 80 and never receives 96.
- From then on the 64- and 96-byte packets always find the queue full: each fails to push and only pops the oldest length, so the queue never holds 64 or 96 again.
  If the program meant to keep the two most recent lengths, it needed `BPF_EXIST`, which drops the oldest element on a full queue.

The program's actions do not change: every run returned `XDP_PASS` with the hooks, as it does when the loader runs without `inject-run`.

## 6. Capture the packets at a hook

A hook takes the program's `ctx` as its first argument, so bpf-ninja's own capture attaches to it like to any other function of the program, and writes the packet of every call to a pcap file instead of an observer's event:

```sh
bpf-ninja -p "$PROG_ID" --func ninja_recent_push -v -c 3 -w push.pcap
```

```
attach target: prog id=2 func="ninja_recent_push"
capturing (prog "ninja_recent_push" id=2, mode=entry, sharded, 2 shards via ringbuf.Reader)...

3 packets captured
```

- The capture sees a packet only when the program calls the hook, so the rule decides what it sees: with `peek`, `ninja_seen_peek` captures only the packets whose length the bloom filter has not seen, and nothing once all four lengths are in it. Use `peek:any` to capture every peek.
- `--list-params` lists the hook's integer and pointer arguments, and `--members` shows member or scalar-pointee expressions.
  `--arg-filter` can select `site` and `status`: `--arg-filter site=24` keeps the pushes at pc 24, and `--arg-filter status=0` keeps the calls that succeeded. `status` is unsigned, so an error such as `-7` is a large value.
- With `--mode exit` the capture runs when the hook returns. The recorded return value is the hook's, always 0, not the program's action; a recording capture (below) writes it as `return=0x00000000` at the start of each comment.
- The loader's packets are zero-filled, so `tcpdump` prints them as truncated frames.

The capture was checked with the walkthrough's program on 6.1, 6.15, 7.0 and 7.3-rc4, in entry and exit mode, and `--list-params` and `--arg-filter` on 7.0.

### Filter a key or value at the hook

For a hash map whose value is `struct pol { __u32 action; __u16 port; }`, discover the generated typed hook, then filter its value:

```sh
bpf-ninja -p "$PROG_ID" --func ninja_policies --list-params --members
bpf-ninja -p "$PROG_ID" --func ninja_policies \
  --arg-filter 'value->action==2' -c 3 -w action2.pcap
```

The [test fixture](../../scripts/test/argmember/) loads such a map under `inject-run` and sends TCP packets to ports 443, 80, and 22 with `BPF_PROG_TEST_RUN`.
Ports 443 and 80 have entries with actions 2 and 1; port 22 misses.
On kernel 7.0.13, the parameter list included:

```text
  value: const struct pol * (arg index 3)
    value->action  __u32  off 0  size 4  unsigned  filterable
    value->port  __u16  off 4  size 2  unsigned  filterable
```

The capture reported `3 packets captured`.
All three tcpdump rows had destination port 443; the first was:

```text
20:31:00.340572 IP 10.0.0.1.40000 > 10.0.0.2.443: Flags [S], seq 0:10, win 0, length 10
```

`value->action!=2` selected port 80, and `value->port==be16(443)` selected port 443 because `port` contains network-order bytes; a recorded `value->port` shows the stored bytes as a host-order integer, not the `be16` literal.
A set can also use `--set 'ports=/sys/fs/bpf/ports,key(dport=arg:key->dport)' --arg-filter '@ports'`.
See the [member filter guide](arg-member-filter.md) for comparisons, set bindings, and read failures.

The bloom and queue hooks take scalar pointers, so use `--arg-filter 'value[0]==64'` at `ninja_seen_peek` or `ninja_recent_push`.
Use `peek:any` to keep testing bloom values after all lengths have been seen.
The loader above gives the queue a zero-sized BTF key so its `__u64` value type survives map creation.
Without that key, this loader retries the queue creation without BTF and its injected hook describes opaque bytes, which cannot use `[0]`.

A typed lookup hook is called only on a hit; its `_miss` variant has no `value` argument.
To capture misses with `--arg-filter 'value==null'`, use a dispatch hook with `lookup:any`, whose `const void *value` can be NULL.
On kernels that reject the global hook's `arg:untrusted` pointers (6.1, 6.6, 6.12 and 6.15 in our test matrix), inject-run makes that hook static automatically; `"static_untrusted": true` forces it.
Capture reads the static XDP hook's ctx through the kernel-read helper when the direct context-read probe rejects that target.
On that fallback path, exit and gated capture obtain the action through `bpf_get_func_ret` (upstream Linux 5.17+) because the kernel has discarded the hook's BTF prototype.
`value!=null` selects the hits without dereferencing the value.

### Record the decision state with each packet

A capture at a generated hook writes, as each packet's pcapng comment, the values the hook's call was decided on.
`--record` selects them:

- `filter` (the default) records the arguments and members that `--arg-filter` and `--set` keys read, named as in `--arg-filter`.
  Without such a filter there is nothing to record and the file keeps the plain layout.
  A condition on a member inside a `bpf_*` struct other than the LPM trie key structs (for example `tuple->ipv4.dport` in `struct bpf_sock_tuple`) still filters but is not recorded: the default layout leaves it out and `-v` names it, and an explicit `--record filter` refuses it.
- `entry` records `site` (decimal) and `status` where the hook has them, and the whole key and value the hook received, decoded with the map's BTF. `status` is `(u32)ret | flags << 32`, written as `0x%016x` so both halves show, as in `status=0x00000002fffffffe`; `--arg-filter` accepts the same `0x` value. Key and value: `key->member=N` (members of anonymous structs and unions under their `--arg-filter` names), `value[0]=N` for a scalar, hex for arrays and named unions, and `value=` with the raw bytes in hex when the map has no BTF, the same at every hook form and cut to `--record-max`.
  Pointers, `bpf_*` structs (timers, locks, kptr holders and the like; the uapi LPM trie key structs `bpf_lpm_trie_key`, `bpf_lpm_trie_key_hdr` and `bpf_lpm_trie_key_u8` excepted) and arrays or unions holding either are left out of the comment, so no pointer-typed or kernel-managed field reaches the file; an address a program keeps in a plain integer field looks like any integer and is recorded as one.
  `--record-max N` (default 256, at most 4096) caps the recorded bytes of the key and of the value; `value_bytes=4/8` marks a value cut to 4 of its 8 bytes. An integer passed by value is recorded whole or not at all.
  An untrusted per-map hook's `const void *` key and value carry no BTF type, but `inject-run` attaches `bpf-ninja:key_size`/`value_size` decl tags from the map, which `entry` reads to record the raw bytes (hex), capped by `--record-max`.
  It attaches a size only when every byte is plain data or the map has no BTF for that side; a key or value holding any pointer or `bpf_*` field gets no size and is not recorded.
  A generic or dispatch hook serves several maps and carries no size tags, so `entry` records only site and status there: `site` (the low half of `info`) and the full `info` word, shown as `info=0x%016x`.
- `none` keeps the plain layout.

`filter` records the value each field's conditions tested, snapshotted from one read as the filter ran, so the recorded value satisfies those conditions; `entry` reads its fields at the hook, so a field the filter did not test can differ from a concurrently changing map entry.
A recording capture writes one pcapng interface per target (the function name, or `func@progid` when a name repeats across programs), and no `epb_packetid`. It has no per-verdict interfaces, so with `--mode exit` every comment starts with the function's return value, `return=0x%08x`.
By default only hooks that `inject-run` generated record; they carry the `bpf-ninja:hook` BTF decl tag, so an ordinary function keeps its plain layout even when its parameters have the same names. An explicit `--record filter` or `--record entry` records at every `--func`, and `-v` logs where recording is on.
Each field is read once and its conditions run on that read, so the recorded `filter` value is the value they tested; a field used by both an argument filter and a set key keeps the argument-filter read. An `entry` read that fails shows `?`.
An explicit `--record` is refused when its worst-case comment, with the `return=` prefix, would not fit one pcapng option (65535 bytes); lower `--record-max` for `entry`, or filter fewer fields for `filter`. The default turns itself off instead.
`--record` is refused with gated (entry plus exit) capture, `--raw-dump`, `--arg-echo`, `--mode xdp` and `--dump-asm`, where the default turns itself off.

With the [record fixture](../../internal/program/record_kernel_test.go), whose program looks up and updates `pols` and looks up a read-only `ro` map (a static hook), on kernel 7.0.13:

```sh
bpf-ninja -p "$PROG_ID" --func rec_pols --arg-filter 'value->pol_rc>=3' \
  --arg-filter 'key->policy_index<=9' -c 2 -w filter.pcapng
bpf-ninja -p "$PROG_ID" --func rec_pols --func rec_pols_update --func rec_ro \
  --record entry -c 10 -w entry.pcapng
tshark -r entry.pcapng -T fields -e frame.interface_name -e frame.comment
```

```text
rec_pols	site=13 key->policy_index=1 value->pol_rc=2 value->port=1001 value->pad=0
rec_pols_update	site=30 status=0x0000000200000000 key->policy_index=1 value->pol_rc=10 value->port=0 value->pad=0
rec_ro	site=35 key[0]=1 value[0]=7
...
rec_pols_update	site=30 status=0x00000002fffffffe key->policy_index=5 value->pol_rc=50 value->port=0 value->pad=0
```

The `filter.pcapng` comments were `value->pol_rc=3 key->policy_index=2` and `value->pol_rc=4 key->policy_index=3`.
Select packets by a value with `-Y 'frame.comment matches "value->pol_rc=3( |$)"'`; `contains` would also match `value->pol_rc=30`.
`entry` puts whole map values into the file, so use `filter` or a small `--record-max` when the values hold data that should not leave the host.

## See also

- [inject-observers.md](inject-observers.md) for small counting, CPU-tagged failure and timing observers.
- [inject-run.md](inject-run.md) for the rule fields, the hooks file and the lookups file.
- [lookup-site-injection.md](lookup-site-injection.md#pushes-pops-and-peeks) for the hook ABI of pushes, pops and peeks, and the other hook kinds.
