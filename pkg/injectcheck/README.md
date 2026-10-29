# Independent validation of injected instructions

[日本語](README.ja.md)

`pkg/injectcheck` is an offline test-time oracle for instruction streams rewritten by `pkg/inject`.
`cmd/inject-check` is a development tool, built separately so its dependency closure excludes the transformer; it is not integrated into `inject-run` or release binaries.
`Check` independently compares the originals, resolves control-flow edges, derives insertion regions and validates every inserted instruction.
It does not use the transformer's site selection, relocation or liveness decisions.

```go
counts, err := injectcheck.Check(original, transformed, injectcheck.Certificate{
    Original: originalIndices,
    Hooks: hookRanges,
}, injectcheck.Premises{LowestOffset: auditedFloor})
```

The **certificate** supplies untrusted correspondence hints.
`Original[i]` is original instruction i's decoded index in the transformed stream; `Hooks` contains half-open ranges of inserted function bodies.
An `LDIMM64` is one decoded instruction and two raw slots for relocation.
`Label` before transformation and `FromLabels` afterwards extract hints from preserved metadata; `Check` verifies their contents independently.
The separate **premise**, `LowestOffset`, is the caller's trusted stack-alias audit, including indirect accesses and callee use of caller-stack pointers.
The checker checks its range and direct RFP accesses, but cannot establish the alias audit from the instruction projection.

## Checked shapes

The pattern names used in comments have the following meanings.
They describe insertion shapes, while “original program” refers to the program being rewritten.

| Name | Shape | What is checked |
| --- | --- | --- |
| P1 | Entry context spill, optionally an entry/dispatch hook and R1 restore | Exact slot, dispatch arguments, hook destination and restore |
| P2 | Lookup/per-CPU lookup spill and conditional observer postlude | One result guard, at most two alternative calls, value-copy pairs, full-width R0 restoration on every path |
| P3 | Map update/delete spill and observer postlude | Helper argument spills, optional signed result guard, one call, full-width R0 restoration |
| P4 | Tail-call prelude and failure postlude | Unchanged helper arguments and target, one hook on failure, local or entry-frame context initialization |
| P5 | Queue/stack push/pop/peek spill and observer postlude | Helper-specific spills, one hook, full-width R0 restoration |
| P6 | A u32 hook after `ldxw R2, [R0+offset]` | Exact six-instruction save/call/restore region, u32 hook body, R1/R3–R5 dead at the original continuation |
| P7 | Observer function | No-op return, u32 XOR return, or permitted context/pointer reads followed by zero return; no stores or calls |

The stack layout is independent of the transformer's implementation.
Let `f = LowestOffset &^ 7` be the aligned floor.
Slots are relative to `f`: context at `f-8`, key or tail index at `f-16`, helper result at `f-24`, map at `f-32`, and update value at `f-40` (or `f-32` without a map spill).
The `f-24` slot intentionally holds update R4/push R3 flags before the postlude reloads them and overwrites it with R0.
The u32 region instead saves R0 at `f-8` and R2 at `f-16`, overlapping the entry context and key slots.
Mixed u32/helper streams therefore do not establish that a later observer receives the original context value; observation-argument correctness is outside acceptance.
All inserted stores must fit below `f` and within the 512-byte frame.

Each original instruction must occur exactly once and in order, with the same opcode, registers, offset, constant and non-edge reference.
Diagnostics name differing fields.
Branch, BPF-call and callback targets must relocate to the corresponding original instruction or its helper prelude.
Backward edges to original entry skip the one-time entry spill.
Hooks cannot overlap originals, split a contiguous insertion region or receive fall-through.
Inserted code preserves R6–R10 and the original stack; map-value copies use paired loads through R1 from R0 and stores into reserved space.

## Calling convention and scope

Helper postludes assume verifier-valid original BPF: after a helper, no executable path reads R1–R5 before redefining them.
Tail-call failure also leaves R0 unreadable under the `RET_VOID` convention.
The inserted code preserves readable original values and branch conditions, including an ordinary helper's full-width R0 on every postlude path; changing unreadable scratch registers cannot make an infeasible original path executable.
Syntactic liveness can include those infeasible paths and is not a rejection condition for helper postludes.
On tail-call success, unchanged helper arguments transfer control before the postlude.

A u32 load does not invalidate caller-saved registers, so its hook still requires R1/R3–R5 to be dead according to a fixed point on the original CFG.
Known helpers use their argument counts, original BPF callees use their live-in registers, and unknown helpers, kfuncs and variadic helpers read all R1–R5.
This conservative analysis can reject safe u32 sites.
Helper postludes have a 4096-step path budget; exhaustion rejects the pair.
An entry context spill initializes only the entry frame, bounded by function-referenced subprogram/callback entries; it never initializes a callee frame.
Unreferenced exception callbacks are outside this frame-identification premise.

Acceptance covers the **compared projection**: decoded instruction fields, references, resolved edges and the checked insertion rules.
In-memory originals must also retain identical CO-RE, kconfig, kfunc and ksym metadata pointers at every correspondence; none is permitted in inserted regions, including hooks.
This checks identity, not relocation meaning, and assumes the shared metadata objects are not mutated during checking or loading.
The implementation reads the private metadata keys of the pinned cilium/ebpf version because that library has no public iterator for them; tests parse an ELF fixture for each kind.
Associated maps are refused in both streams even if the associations are identical.
Check before map association, using a shared, unchanged external symbol/FD binding table.
Numeric FDs are identifiers in that namespace, not transferable live maps.

Acceptance is conditional on valid original and transformed BPF, the calling convention and the trusted stack audit.
The checker does not establish kernel acceptance, BTF/CO-RE meaning, JIT correctness, observer noninterference, observation arguments, concurrency, time or randomness.
It does not load, attach or pin BPF.

## JSON and error classification

```sh
go build -o inject-check ./cmd/inject-check
./inject-check pair.json
```

The writer and reader share the tagged `injectcheck.Pair` type.
Format 1 pins the decoded `asm.OpCode` representation of cilium/ebpf v0.22; it is not the kernel opcode byte.
Required, case-sensitive top-level keys are `format`, `original`, `transformed`, `certificate` and `premises`.
`certificate.original` and `premises.lowest_offset` are also required; `certificate.hooks` may be empty or omitted.
Span fields are `start` and `end`.
Instruction fields are `opcode`, `dst`, `src`, `offset`, `constant`, `symbol` and `reference`.
`PseudoMapValue` offsets remain in the upper 32 bits of `constant`, with its pseudo kind in `src`.
Unknown fields and noncanonical case spellings are input errors.
Duplicate keys, including case variants, are rejected at every nesting level, including optional evidence objects.
The optional top-level artefact keys `request`, `result` and `reason` are explicitly allowed and do not affect validation.

Marshal `Pair` with `injectcheck.Instructions` fields, never plain `asm.Instructions`, which silently drops metadata.
The instruction encoder refuses associated maps and all four load-time metadata kinds rather than discarding their identity.
A producer saving an explicit projection must first check the in-memory metadata identities and record that the JSON replay covers only the projection.
The local census harness follows this rule; its JSON cannot replay metadata identity checks.

The CLI emits `accepted`, `kind`, `counts`, `premises` and `reason`; `counts.sites` is the number of checked sites and is partial on rejection.
The premise is echoed with the verdict.
`errors.As` distinguishes the following API errors; both expose a stable `Kind` and human-readable `Detail`.

| Outcome | Type | CLI exit | Examples |
| --- | --- | --- | --- |
| Accepted | nil | 0 | All checked rules hold |
| Input error | `*InputError` | 2 | Malformed JSON; missing/null required field (message names it); empty original/mapping; mapping length/order error; invalid/overlapping hook ranges; floor outside [-512,0]; invalid original register; unsupported format |
| Rejected transformation | `*Rejection` | 1 | Changed instruction/reference/edge; unsafe inserted store, branch, register effect or hook; metadata change; associated map |

Decode/file/usage errors go to stderr; structural input errors found by validation also receive a JSON verdict.
The kinds distinguish empty original, empty mapping, length mismatch and invalid floor.

## Tests and local corpus evidence

Run `go test ./pkg/injectcheck ./pkg/inject ./cmd/inject-check`.
`TestPairCorpus` builds the CLI and compares its complete verdict with the API and expected `{accepted, kind}` for the committed pair JSON corpus, including seven accepted configurations and all eleven mutations.
This is the scope of the committed CLI/API agreement evidence.
`TestTranslationValidationEquivalence` asserts planned site/hook counts and reports site-bearing and zero-site fixtures separately.
The dependency test rejects a direct or transitive dependency on `pkg/inject` from the checker or CLI.

Privileged `TestBpf*` fixtures use only load and `BPF_PROG_TEST_RUN` and are registered in `scripts/test/privileged.py`.
Run them as root in a suitable test VM with `go test ./pkg/injectcheck -run '^TestBpf' -v`.
They cover map identity and the verifier premise for lookup, delete and tail-call postludes.

The local-only census requires `BPF_NINJA_VALIDATE_OBJECTS`, `BPF_NINJA_VALIDATE_CENSUS` and `BPF_NINJA_VALIDATE_OUTPUT`.
The census results must contain `<object>--<program>/plain/load.json` with a `Bound` from the external stack-audit tool; this repository does not produce that audit.
Missing bounds produce `INPUT_REFUSED` rows for all four forms and are excluded from acceptance counts.
Raw-form counts and plans are computed independently; a typed refusal produces an explicit `RAW_NOT_RUN` row.
Four forms repeat each program, so rows are not independent samples.
