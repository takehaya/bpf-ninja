# Helper allow-list for generated observers

Every generated fentry or fexit capture program and argument-echo program passes a helper allow-list in the common tracing-program load path.
The scan includes generated callback subprograms because they share the same instruction stream.
BPF-to-BPF calls within that stream are allowed, while unknown helpers, indirect calls, and kfunc calls are rejected before the program reaches the kernel.
Native XDP capture is not a tracing observer and is outside this allow-list.
The earlier allow-list omitted `bpf_ringbuf_query` after wake-up batching added that helper, so it rejected current generated observers.
The list now includes that read-only query and tests every current tracing observer form against the full allow-list.

| Allowed helper | Generated use |
|---|---|
| `bpf_map_lookup_elem` | Read filters, gates, counters, scratch storage, and ring shards from observer maps. |
| `bpf_probe_read_kernel` | Copy packet, context, or argument bytes into observer-owned memory. |
| `bpf_ktime_get_ns`, `bpf_jiffies64`, `bpf_get_smp_processor_id` | Create timestamps, detect stale gated frames, and select a shard. |
| `bpf_get_func_arg`, `bpf_get_func_ret` | Read trampoline arguments and return values. |
| `bpf_loop` | Run bounded generated DSL callbacks. |
| `bpf_ringbuf_reserve`, `bpf_ringbuf_query`, `bpf_ringbuf_submit`, `bpf_ringbuf_discard` | Reserve output, calculate the batched wake-up flag, and release records in observer rings. |

The allow-list prevents a generator change from silently adding a helper that updates maps, writes user memory, redirects packets, overrides a return value, or tail-calls another program.
It does not prove that a permitted map belongs to the observer, that a permitted destination has no target alias, that callbacks terminate, or that observation has no timing, scheduling, memory-pressure, or cache effects.
The kernel verifier remains responsible for type, bounds, and control-flow checks.
