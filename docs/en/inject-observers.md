# Small observers for inject hooks

Use the CLI first: `--func` selects a hook, `--arg-filter` selects calls by their integer arguments, `--arg-echo` prints those arguments, and `-w` saves packets.
Add an argument filter to the [walkthrough's capture example](inject-walkthrough.md#6-capture-the-packets-at-a-hook) to select failed pushes:

```sh
bpf-ninja -p "$PROG_ID" --func ninja_recent_push \
  --arg-filter 'status>=1' -w push.pcap
```

To print the arguments instead, run a separate command:

```sh
bpf-ninja -p "$PROG_ID" --func ninja_recent_push \
  --arg-filter 'status>=1' --arg-echo
```

`--arg-echo` selects argument output instead of packet capture; use the first command to write `push.pcap`.
With the walkthrough's zero push flags, this selects failed pushes because `status` is unsigned and errors such as `-7` are large values.
Write an observer when the CLI cannot supply the result: aggregate counts in the kernel, add the CPU ID to selected events, or keep state across hooks to measure elapsed time.
For packet bytes and lengths, use the built-in capture.

The three examples in [examples/inject-observers](../../examples/inject-observers) reuse the walkthrough's XDP program and loader.
Its [README](../../examples/inject-observers/README.md) has the build, run and VM verification commands.
These observers read hook arguments and write their own maps; they cannot change the target's verdict.
They obtain raw `u64` arguments with `bpf_get_func_arg`.
The conditional observer also reads pointed-to memory with `bpf_probe_read_kernel`, as in the walkthrough.
The low 32 bits of `status`, cast to a signed integer, hold the helper's return value; the upper bits hold push flags.

## Count calls and failures

[count.c](../../examples/inject-observers/bpf/count.c) attaches to `ninja_recent_push`, `ninja_recent_pop` and `ninja_seen_peek`.
It counts calls and failures by `(op, site)` in a per-CPU hash map with room for 128 keys:

```c
  __u64 site = 0, status = 0;
  bpf_get_func_arg(ctx, 1, &site);
  bpf_get_func_arg(ctx, 3, &status);
  struct key key = {.op = op, .site = site};
  struct counter zero = {}, *c = bpf_map_lookup_elem(&counters, &key);
  if (!c) {
    bpf_map_update_elem(&counters, &key, &zero, BPF_NOEXIST);
    c = bpf_map_lookup_elem(&counters, &key);
  }
  if (c) {
    c->calls++;
    /* The upper half holds push flags, not the helper's return value. */
    c->failures += (__s32)status != 0;
  }
```

The Go command sums the CPU values and prints cumulative totals every second.
The BPF observer sends no per-call events, so user space does not have to receive each call to count it.
Counts start when the observer attaches, and reading them does not produce an atomic snapshot across CPUs.

The reused rule has `push:any` and `pop:any`, but only `peek:error`, so every counted peek is a failure.
Use `peek:any` in a copy of the walkthrough rule to count successful peeks too.
A recorded snapshot on 7.0.13 was:

```text
snapshot
hook=ninja_recent_push site=24 calls=6 failures=2
hook=ninja_recent_pop site=30 calls=2 failures=0
hook=ninja_seen_peek site=11 calls=4 failures=4
```

## Add the CPU ID to failed calls

[conditional.c](../../examples/inject-observers/bpf/conditional.c) attaches to the same three hooks.
It emits events for failed calls to push, pop and peek.
Failure filtering alone is already available through `--arg-filter`; this observer adds `bpf_get_smp_processor_id()` to each selected event, which `--arg-echo` cannot provide.
It checks the signed low 32 bits of `status` in the kernel before reserving ring-buffer space:

```c
  __u64 site = 0, value = 0, status = 0;
  bpf_get_func_arg(ctx, 3, &status);
  if ((__s32)status == 0)
    return 0;
  bpf_get_func_arg(ctx, 1, &site);
  bpf_get_func_arg(ctx, 2, &value);
  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
  /* ... copy op, site, value and status into e ... */
  e->cpu = bpf_get_smp_processor_id();
  e->pad = 0;
  bpf_ringbuf_submit(e, 0);
```

The rule already suppresses successful peeks; the observer also suppresses successful pushes and pops despite their `:any` rules.
The two-entry queue returns `-7` (`-E2BIG`) when full, and a bloom-filter miss returns `-2` (`-ENOENT`).
The first events on 7.0.13 were:

```text
hook=ninja_seen_peek site=11 value=64 ret=-2 cpu=0
hook=ninja_seen_peek site=11 value=80 ret=-2 cpu=0
hook=ninja_seen_peek site=11 value=96 ret=-2 cpu=1
hook=ninja_recent_push site=24 value=96 ret=-7 cpu=1
```

For live XDP traffic, the CPU ID describes where the hook ran.
Softirq execution makes PID and comm unsuitable for identifying the source of a packet.

## Measure entry-to-push time

[latency.c](../../examples/inject-observers/bpf/latency.c) keeps state across hooks, which the CLI's argument filtering cannot do.
Its [rule](../../examples/inject-observers/latency-rules.json) adds `"entry": true` to the walkthrough rule to inject `ninja_entry(ctx)`.
The entry observer stores a timestamp in a one-element per-CPU array; observers on the queue and bloom-filter push hooks subtract it from the current time:

```c
SEC("fentry/ninja_entry")
int on_entry(void *ctx) {
  __u32 key = 0;
  __u64 *t = bpf_map_lookup_elem(&start, &key);
  if (t)
    *t = bpf_ktime_get_ns();
  return 0;
}

static int report(void *ctx, __u32 op) {
  __u64 now = bpf_ktime_get_ns(), site = 0, status = 0;
  __u32 key = 0;
  __u64 *t = bpf_map_lookup_elem(&start, &key);
  if (!t || !*t)
    return 0;
  __u64 elapsed = now - *t;
  /* ... emit op, site, status and elapsed through the ring buffer ... */
```

The Go command attaches `on_entry` first and closes links in reverse order, keeping entry attached until both push observers have detached.
This prevents a remaining push observer from using a timestamp from an earlier invocation during shutdown.
Before the first entry timestamp, `report` simply skips the event.
The Go command rejects an object that does not match the requested example with a descriptive error.
Latency events identify the hook as well as its original instruction position (`site`); compiler versions can change that position.
A run on 7.0.13 included both the bloom-filter push and queue push:

```text
hook=ninja_seen_push site=18 ret=0 ns=454
hook=ninja_recent_push site=24 ret=0 ns=3417
hook=ninja_seen_push site=18 ret=0 ns=1505
hook=ninja_recent_push site=24 ret=0 ns=18062
```

These times include intervening map calls and observer overhead; they measure neither the push helper alone nor the program's full duration.
The per-CPU slot suits this fixture's single, non-nested invocation per CPU.
Nested invocations would need separate state, and an entry hook reached through a tail call resets the timestamp.

## VM verification

On 2026-10-29, the following checks passed in KVM VMs with 2 GiB RAM and two CPUs.

| Kernel | Full check (clang 21) | Full check (clang 18) | Latency startup delayed 5 seconds | Load-only |
| --- | --- | --- | --- | --- |
| 6.1.188 | PASS | PASS | PASS | PASS |
| 7.0.13 | PASS | PASS | PASS | PASS |

The excerpts above are verbatim from the normal 7.0.13 run with clang 21.
The clang 18 program used push sites 20 and 27; the clang 21 program used 18 and 24.
The alternate compiler and delay were exercised by a local VM driver; the committed `verify.sh` runs the normal check or `--load-only`.

The full `verify.sh` check uses a fresh loader per observer and verifies event contents and `XDP_PASS` verdicts through `BPF_PROG_TEST_RUN`.
The loader prints its program ID, then waits for a start file created by the observer after attachment and reader setup.
This preserves the four initial Bloom-filter pushes even when observer startup is delayed.
The README's manual commands use the same gate.
Verification identifies the two latency producers by hook name rather than fixed instruction positions.
Counts, CPU placement and elapsed times can vary between runs.
Ring-buffer observers drop an event if reservation fails.

CI builds the objects and then runs `verify.sh --load-only` after the privileged BPF suites, as root with bpffs mounted.
That check loads and attaches all three examples for two seconds each; the full VM run also checks counters, event contents and loader verdicts.

## See also

- [inject-walkthrough.md](inject-walkthrough.md) for discovery, hook arguments and built-in capture.
- [inject-run.md](inject-run.md) for `entry`, `ops` and the hook metadata file.
- [lookup-site-injection.md](lookup-site-injection.md#pushes-pops-and-peeks) for the push/pop/peek ABI.
