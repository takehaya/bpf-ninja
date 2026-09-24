# Capture completion

Shutdown detaches every observer, waits for existing non-sleepable BPF
invocations, records each ring's producer position, and joins readers after
those records reach the sink. Writers then flush/close and the CLI merges
files before releasing maps. `stop` and probe `Close` are idempotent.
A count/byte cap may deliberately omit records from the drained backlog.
An output error remains an error through shutdown; draining does not repair it.

Tag completion additionally inserts a capture-local tombstone before waiting
for BPF invocations. This prevents a concurrent set re-add from restarting the
tag. After the kernel barrier, every shard must acknowledge the recorded
producer position **after** writer registration and its batch write return.
The coordinator polls acknowledgements without blocking on a slow sink.
A stalled shard therefore delays completion instead of losing its backlog.
Tombstones are retained for the capture lifetime, with a limit of 65,536 tags;
allocation/update failure prevents an acknowledgement.

The kernel barrier uses an update of the existing map-in-map slot to the same
inner map. Linux's `maybe_wait_bpf_programs` waits for an RCU grace period on
map-in-map updates, so preexisting BPF invocations have finished when the
syscall returns. See the [Linux implementation](https://github.com/torvalds/linux/blob/v6.1/kernel/bpf/syscall.c#L156-L165).
This relies on the non-sleepable tracing/XDP programs that bpf-ninja loads;
it must be revisited before adding sleepable observers.

Completion covers successful write, flush, close and final-file rename.
It does not include `fsync` durability across power loss. Existing broken
shards or output failures prevent a successful final file/ack. Packet selection,
parse limits and intentional output caps still define the capture scope.
