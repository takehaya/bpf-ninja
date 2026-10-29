# Small observers for inject hooks

Use the CLI first: `--func` selects a hook, `--arg-filter` selects calls by their integer arguments, `--arg-echo` prints those arguments, and `-w` saves packets.
The [walkthrough's capture example](inject-walkthrough.md#6-capture-the-packets-at-a-hook) already captures the packet at an injected hook:

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
They obtain raw `u64` arguments with `bpf_get_func_arg` and read pointed-to memory with `bpf_probe_read_kernel`, as in the walkthrough.
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
hook=ninja_recent_push site=24 calls=6 failures=3
hook=ninja_recent_pop site=30 calls=3 failures=0
hook=ninja_seen_peek site=11 calls=2 failures=2
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
hook=ninja_seen_peek site=11 value=96 ret=-2 cpu=1
hook=ninja_recent_push site=24 value=96 ret=-7 cpu=1
hook=ninja_seen_peek site=11 value=112 ret=-2 cpu=1
hook=ninja_recent_push site=24 value=64 ret=-7 cpu=0
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

static int report(void *ctx) {
  __u64 now = bpf_ktime_get_ns(), site = 0, status = 0;
  __u32 key = 0;
  __u64 *t = bpf_map_lookup_elem(&start, &key);
  if (!t || !*t)
    return 0;
  __u64 elapsed = now - *t;
  /* ... emit site, status and elapsed through the ring buffer ... */
```

The Go command explicitly attaches `on_entry` before either push observer, so a push cannot consume a timestamp before the entry observer is attached.
The Go command rejects an object that does not match the requested example with a descriptive error.
On 7.0.13, the first events included both the bloom-filter push (`site=18`) and queue push (`site=24`):

```text
site=18 ret=0 ns=1683
site=24 ret=-7 ns=12415
site=18 ret=0 ns=1458
site=24 ret=0 ns=17360
```

These times include intervening map calls and observer overhead; they measure neither the push helper alone nor the program's full duration.
The per-CPU slot suits this fixture's single, non-nested invocation per CPU.
Nested invocations would need separate state, and an entry hook reached through a tail call resets the timestamp.

## VM verification

On 2026-10-29, `verify.sh` ran each observer for seven seconds against a fresh loader in KVM VMs with 2 GiB RAM and two CPUs.
The images were `ghcr.io/cilium/ci-kernels:6.1`, `:7.0` and `:7.3-rc4`.

| Kernel (`uname -r`) | count | conditional | latency |
| --- | --- | --- | --- |
| 6.1.188 | PASS | PASS | PASS |
| 7.0.13 | PASS | PASS | PASS |
| 7.3.0-rc4 | PASS | PASS | PASS |

The excerpts above are verbatim from the 7.0.13 logs.
The behavior on 6.1.188 and 7.3.0-rc4 was identical: counters included failed pushes and successful pops, failure events carried CPU IDs, and both push hooks reported positive elapsed times.
Attachment happens after the loader starts, so the observer can miss early calls.
Counts, CPU placement and elapsed times can vary between runs.
Ring-buffer observers drop an event if reservation fails.
All recorded loader runs returned `action=2 err=<nil>` (`XDP_PASS`).

CI builds the objects and then runs `verify.sh --load-only` after the privileged BPF suites, as root with bpffs mounted.
That check loads and attaches all three examples for two seconds each; the full VM run also checks counters, event contents and loader verdicts.

## See also

- [inject-walkthrough.md](inject-walkthrough.md) for discovery, hook arguments and built-in capture.
- [inject-run.md](inject-run.md) for `entry`, `ops` and the hook metadata file.
- [lookup-site-injection.md](lookup-site-injection.md#pushes-pops-and-peeks) for the push/pop/peek ABI.
