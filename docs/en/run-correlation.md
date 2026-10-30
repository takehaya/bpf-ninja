# Run correlation primitives

The helpers in `internal/program/run_state.go` associate hook observations with a root invocation.
Hook capture uses them through the per-CPU and ctx locators.
They define the shared map layout, ID allocation and diagnostics for that lifecycle.
Legacy gated numbering and output layouts are unchanged.

A root invocation is one execution of the observed XDP/tc program.
Frames are found in either a per-CPU LIFO stack (`ninja_runs`) or a hash keyed by the root ctx pointer (`ninja_run_table`); both use the same frame layout.
Each frame starts pending, becomes tracked with an ID and an inherited output tag, or becomes blocked.
Bits above the low two state bits are reserved for consumer flags and masked by residual checks.

## Layout

`ninja_runs` is a per-CPU array with one 272-byte value.
Its 16-byte header holds depth at offset 0 and poison at offset 4; bytes 8–15 are reserved.
Eight 32-byte frames follow at offset 16.
A frame holds diagnostic owner PID/TID, packet ID, tag, state and root context identity at offsets 0, 8, 16, 20 and 24.
Only depths 1–8 select a frame; empty, overflowed and poisoned stacks fail without selecting a parent.
The caller owns depth changes, poison lifetime and diagnostic counter storage.

## ID allocation

`ninja_run_seq` separately holds a per-CPU counter and a sticky exhaustion flag.
The allocator checks that the CPU fits in 16 bits before atomically fetching and incrementing the counter.
It returns `cpu<<48 | sequence`, with sequence from 1 through `2^48-1`, and refuses further IDs after exhaustion.
It uses the fetched count directly so nested allocations cannot borrow another invocation's ID.
The allocator only requires CPU pinning between reading the CPU and looking up the sequence map.
Only the per-CPU stack locator requires LIFO execution; the consumer establishes attachment support.

## Register and stack contract

Frame lookup returns R0 and preserves R6–R9; identity checks accept caller-selected registers and use R1 as scratch.
Lookup uses the shared `runLookupStack` at -16 through -13.
Sequence allocation uses `runCPUStack` at -208 through -201; the context locator reserves `runKeyStack` at -216 through -209.
The ctx locator also uses `runFrameStack` at -192 through -161 for an initial frame, dead before any filter or hook prologue.
These named slots are listed in the layout table in `program.go` and do not alias the tag, return, argument, packet key or static XDP slots.
Run temporaries live only within one emitter and never across a filter, hook prologue or identity sequence; Kunai may reuse their bytes during filters.
Save live values before helper calls, move a found frame from R0 to R8 immediately, and find it again after a filter/prologue uses R8 for data_end.
Identity inputs cannot use scratch R1.
Root ctx is the primary identity; packet data/head changes do not invalidate it.
Owner is diagnostic only and must never poison a run.
The shared failure labels do not encode reasons; callers must classify failures before assigning diagnostic policy.

## Diagnostics

`inspectRunState` reads a quiesced snapshot, reports overflow through depth, and inspects at most eight frames.
`inspectRunTable` applies the same frame rules to residual hash entries and counts blocked entries.
`runTableMapSpec` creates a preallocated hash with an 8-byte ctx key, 32-byte value and `max(1024, 64 * possible CPUs)` entries.
Tracked frames require a nonzero ID; pending and blocked frames require zero, and tag zero remains valid.
`Probe.ObserverMisses` sums attached programs' kernel recursion misses, rejects unknown or pre-6.1 kernels, and fails the whole sample on a read error.
A consumer must compare samples at start, during capture, after in-flight runs finish and at shutdown; a miss cannot repair output.

See [injection observers](inject-observers.md) for the hooks being correlated.
Root entry/exit, hook recording, stop/drain and diagnostics are connected by `LoadHookCapture`; see the [hook capture guide](hook-pcapng.md).
