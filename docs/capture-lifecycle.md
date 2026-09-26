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

After shutdown and merge, `capture status=...` reports one session's totals:

| Field | Unit and meaning |
| --- | --- |
| `selected` | Export attempts after the filter, set membership and tag gate; sum of the four producer outcomes below |
| `exported` | Records submitted to the ring |
| `ringbuf_reserve_fail` | Selected records lost because reserve returned NULL |
| `lookup_miss` | Selected records with no ring map for their CPU |
| `copy_fail` | Reserved records discarded after a packet-copy helper failed |
| `consumed` | Non-discard ring records consumed across all shards |
| `written` | Records in successful writer calls; final status also checks flush/close/merge |
| `intentional_limit` | Consumed records omitted because of a count/byte/tag cap |
| `null_discard` | Records intentionally sent to null output |
| `malformed` | Consumed records with invalid metadata/caplen; also a capture error |
| `persistence_unconfirmed` | Consumed records not accounted for by a successful write, cap, null sink or malformed record |
| `drained_at_stop` | Records consumed by the final drain after the producer barrier; excludes batches already being written |
| `affinity_failures` | Failed reader pin attempts in this session |

`complete` means all exported records were consumed and handed to successful
writers, no measured producer loss occurred, and final flush/close/merge
succeeded. `limited` marks intentional record omission; `discarded` marks null
output. `incomplete` overrides these for unexpected loss, invalid records,
unconfirmed records or any capture/persistence error. Counter-read failures
print `unknown`, never zero. Ring loss is diagnostic and does not itself make
the process exit nonzero; I/O, metadata and synchronization errors do.

These totals count observer events, not unique network packets: attaching to
multiple functions can produce multiple events for one packet. They describe
only the attached hooks and the possible CPU shards created at startup.
Filtering and parse rejection are not counted separately and are explicitly
`unmeasured`. Snapshot/capture limits still apply, including the tracing
filter's 512-byte scratch window, protocol loop bounds and the selected DSL
capture length or snaplen. `complete` does not promise full wire payloads,
all network traffic, fsync durability or recovery from a killed process.
Tag acks confirm the committed records through their barrier were saved;
producer losses remain visible in the session report.

`-c` is an exact maximum across concurrent shards; byte caps remain batch
boundaries and can overshoot by concurrent batches. A failed batch may have
partially reached a writer, so its bytes are not presented as confirmed records.
The `written` count alone is not a durability claim if final status is incomplete.

Reproduce the local successful-export and read-window cost comparisons with
`sudo go test ./internal/program -run '^$' -bench
'Benchmark(ExportAccounting|TracingReadWindow)$' -benchtime=10000x -count=5`.
They include syscall and amortized ring-drain time. They are comparison fixtures,
not NIC throughput measurements or a universal performance guarantee.
