# Small observers for inject hooks

An fentry observer attached to an injected hook can aggregate calls, filter events, inspect a packet, or measure elapsed time inside the program.
The examples in [examples/inject-observers](../../examples/inject-observers) reuse the [walkthrough's](inject-walkthrough.md) XDP program, loader and rules.
Its README has the build, run and VM verification commands.

These observers read the target's arguments and packet and write their own maps.
They cannot change the target's verdict.
They obtain raw `u64` arguments with `bpf_get_func_arg` and read pointed-to memory with `bpf_probe_read_kernel`; directly loading typed pointer arguments from the fentry context was refused on 7.0.
The low 32 bits of `status`, cast to a signed integer, hold the helper's return value; the upper bits hold push flags.

## Count calls and failures

[count.c](../../examples/inject-observers/bpf/count.c) attaches to `ninja_recent_push`, `ninja_recent_pop` and `ninja_seen_peek`.
It uses `(op, site)` as the key of a per-CPU hash map, with separate call and failure counters.
The Go command sums the CPU values and prints cumulative totals every second; the BPF program sends no per-call events.
There is room for 128 keys, which covers this fixture's three sites.

The counts start when the observer attaches and cover only calls that reach these hooks.
The reused rule has `push:any` and `pop:any`, but only `peek:error`, so every counted peek is a failure.
Use `peek:any` in a copy of the walkthrough rule to count successful peeks too.
Reading the per-CPU counters does not produce an atomic snapshot across CPUs.

## Report only failures

[conditional.c](../../examples/inject-observers/bpf/conditional.c) attaches to the same three hooks and checks `(__s32)status != 0` before reserving a ring-buffer event.
The rule already suppresses successful peeks, but the observer itself filters successful pushes and pops despite their `:any` rules.
Each event includes `bpf_get_smp_processor_id()`.
For live XDP traffic, softirq execution makes PID and comm unsuitable for identifying the source of a packet.

The two-entry queue returns `-7` (`-E2BIG`) when full.
A bloom-filter miss returns `-2` (`-ENOENT`).
Neither successful pushes nor successful pops produce events.

## Read packet bytes through the hook context

[packet.c](../../examples/inject-observers/bpf/packet.c) attaches to `ninja_recent_push` and reads argument zero with `bpf_get_func_arg`.
Although the hook's BTF signature names `struct xdp_md *`, fentry receives the kernel's `struct xdp_buff *`.
Before loading the observer, the Go command finds `data` and `data_end` in the running kernel's BTF and fills two offset constants in the BPF object.
The BPF code uses `bpf_probe_read_kernel` to read those pointers and then the first eight packet bytes.

Each event reports the linear length (`data_end - data`), the first eight bytes, the site and the push's result.
The example skips packets shorter than eight bytes or any failed memory read, and does not inspect non-linear fragments.
The walkthrough loader supplies zero-filled packets, so the bytes are zero; the lengths vary from 64 to 112.
This method needs kernel BTF and the XDP context layout; it is not a tc observer.

## Measure entry-to-push time

[latency.c](../../examples/inject-observers/bpf/latency.c) needs the additional `ninja_entry(ctx)` hook.
Its [rule](../../examples/inject-observers/latency-rules.json) adds `"entry": true` to the walkthrough rule, corresponding to `LookupRequest.Entry` in the transform API.
The entry observer stores `bpf_ktime_get_ns()` in a one-element per-CPU array.
Observers on both the queue and bloom-filter push hooks subtract that timestamp from the current time and emit the difference with the site and result.

This is elapsed time from the entry observer to the push observer, including the intervening map calls and observer overhead.
It does not measure the push helper alone or the program's full duration.
The per-CPU slot suits this fixture's single, non-nested invocation per CPU; nested invocations would need separate state, and an entry hook reached through a tail call resets the timestamp.
Times under TCG include emulation and scheduling effects and are not native-performance measurements.

## Recorded VM runs

Both runs used local vimto VMs with KVM disabled (TCG), 2 GiB RAM and two CPUs, on 2026-10-29.
The kernel image tags `ghcr.io/cilium/ci-kernels:7.0` and `:6.1` reported the versions below.
`verify.sh` exited successfully for both; each example ran against a fresh loader and all recorded loader runs returned `action=2 err=<nil>` (`XDP_PASS`).
The script intentionally interrupts each observer after seven seconds and then stops its loader.

| Kernel (`uname -r`) | count | conditional | packet | latency |
| --- | --- | --- | --- | --- |
| 7.0.13 | PASS | PASS | PASS | PASS |
| 6.1.188 | PASS | PASS | PASS | PASS |

The following are verbatim excerpts from the observer logs.
Attachment happens after the loader starts, so early calls can be missed and the counts and first packet vary between runs.
The ring-buffer examples also drop an event if reservation fails.

### 7.0.13

Count, the final two one-second snapshots:

```text
snapshot
hook=ninja_recent_push site=24 calls=5 failures=3
hook=ninja_recent_pop site=30 calls=3 failures=0
hook=ninja_seen_peek site=11 calls=2 failures=2
snapshot
hook=ninja_recent_push site=24 calls=6 failures=3
hook=ninja_recent_pop site=30 calls=3 failures=0
hook=ninja_seen_peek site=11 calls=2 failures=2
```

Conditional, all recorded events:

```text
hook=ninja_seen_peek site=11 value=80 ret=-2 cpu=0
hook=ninja_seen_peek site=11 value=96 ret=-2 cpu=0
hook=ninja_recent_push site=24 value=96 ret=-7 cpu=0
hook=ninja_seen_peek site=11 value=112 ret=-2 cpu=0
hook=ninja_recent_push site=24 value=64 ret=-7 cpu=0
hook=ninja_recent_push site=24 value=96 ret=-7 cpu=0
```

Packet, the first four events:

```text
site=24 len=112 ret=0 first=0000000000000000
site=24 len=64 ret=-7 first=0000000000000000
site=24 len=80 ret=0 first=0000000000000000
site=24 len=96 ret=-7 first=0000000000000000
```

Latency, the first six events (`site=18` is the bloom-filter push, `site=24` the queue push):

```text
site=18 ret=0 ns=96520
site=24 ret=-7 ns=466087
site=18 ret=0 ns=9330
site=24 ret=0 ns=65960
site=24 ret=-7 ns=35180
site=24 ret=0 ns=10210
```

### 6.1.188

Count, the final two one-second snapshots:

```text
snapshot
hook=ninja_recent_push site=24 calls=5 failures=3
hook=ninja_recent_pop site=30 calls=3 failures=0
hook=ninja_seen_peek site=11 calls=2 failures=2
snapshot
hook=ninja_recent_push site=24 calls=6 failures=3
hook=ninja_recent_pop site=30 calls=3 failures=0
hook=ninja_seen_peek site=11 calls=2 failures=2
```

Conditional, all recorded events:

```text
hook=ninja_seen_peek site=11 value=80 ret=-2 cpu=0
hook=ninja_seen_peek site=11 value=96 ret=-2 cpu=0
hook=ninja_recent_push site=24 value=96 ret=-7 cpu=0
hook=ninja_seen_peek site=11 value=112 ret=-2 cpu=0
hook=ninja_recent_push site=24 value=64 ret=-7 cpu=0
hook=ninja_recent_push site=24 value=96 ret=-7 cpu=0
```

Packet, the first four events:

```text
site=24 len=96 ret=-7 first=0000000000000000
site=24 len=112 ret=0 first=0000000000000000
site=24 len=64 ret=-7 first=0000000000000000
site=24 len=80 ret=0 first=0000000000000000
```

Latency, the first six events (`site=18` is the bloom-filter push, `site=24` the queue push):

```text
site=18 ret=0 ns=177390
site=24 ret=0 ns=606790
site=18 ret=0 ns=15720
site=24 ret=-7 ns=88600
site=18 ret=0 ns=12180
site=24 ret=0 ns=82860
```

## See also

- [inject-run.md](inject-run.md) for `entry`, `ops` and the hook metadata file.
- [lookup-site-injection.md](lookup-site-injection.md#pushes-pops-and-peeks) for the push/pop/peek ABI.
