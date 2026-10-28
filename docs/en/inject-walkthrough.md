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
`inject-run` needs no change to it:

```go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

// Load prog.o, print the program id, then run the program once a second on
// packets of 64, 80, 96 and 112 bytes in turn, for a minute.
func main() {
	spec, err := ebpf.LoadCollectionSpec(os.Args[1])
	if err != nil {
		panic(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	defer coll.Close()
	info, _ := coll.Programs["entry"].Info()
	id, _ := info.ID()
	fmt.Println(id)
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
inject-run: program "entry": injected hook "ninja_seen_peek" (peek map "seen", site pc 11), hook "ninja_seen_push" (push map "seen", site pc 18), hook "ninja_recent_push" (push map "recent", site pc 24), hook "ninja_recent_pop" (pop map "recent", site pc 30), tracee fd 11
```

`hooks.json` gives the kernel ID of the transformed program and each hook with its sites:

```json
{"program": "entry", "func": "entry", "type": "XDP", "prog_id": 464331, "ctx_type": "xdp_md", "skipped": [],
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
- `--list-params` lists the hook's integer arguments, `site` and `status`, and `--arg-filter` selects calls by them: `--arg-filter site=24` keeps the pushes at pc 24, and `--arg-filter status=0` keeps the calls that succeeded. `status` is unsigned, so an error such as `-7` is a large value.
- With `--mode exit` the capture runs when the hook returns. The recorded return value is the hook's, always 0, not the program's action.
- The loader's packets are zero-filled, so `tcpdump` prints them as truncated frames.

The capture was checked with the walkthrough's program on 6.1, 6.15, 7.0 and 7.3-rc4, in entry and exit mode, and `--list-params` and `--arg-filter` on 7.0.

## See also

- [inject-run.md](inject-run.md) for the rule fields, the hooks file and the lookups file.
- [lookup-site-injection.md](lookup-site-injection.md#pushes-pops-and-peeks) for the hook ABI of pushes, pops and peeks, and the other hook kinds.
