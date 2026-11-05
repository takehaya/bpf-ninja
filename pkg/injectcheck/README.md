# Independent validation of injected instructions

[日本語](README.ja.md)

`pkg/injectcheck` independently validates instruction streams rewritten by `pkg/inject`; `pkg/inject` also uses its target-binding types in production code.
`cmd/inject-check` is a development tool built separately so its dependency closure excludes the transformer.
`inject-run` also uses this package to check the assembled substituted stream immediately before resuming `BPF_PROG_LOAD`; see [load-stream check](../../docs/en/inject-run.md#load-stream-check).
`Check` independently compares the originals, resolves control-flow edges, derives insertion regions and validates every inserted instruction.
It does not reuse the transformer's relocation or liveness decisions.
The trusted `Premises.Targets` input supplies the plan's site/result-to-hook binding because instruction shapes alone do not identify intent.

```go
plannedSiteTargets, err := inject.BuildLookupTargets(transformed, result.Hooks)
if err != nil {
    if errors.Is(err, inject.ErrCheckerNotApplicable) {
        // Apply the caller's policy for a stream the checker cannot pair.
    }
    return err
}
counts, err := injectcheck.Check(original, transformed, injectcheck.Certificate{
    Original: originalIndices,
    Hooks: hookRanges,
}, injectcheck.Premises{
    LowestOffset: auditedFloor,
    Targets: plannedSiteTargets,
})
```

The **certificate** supplies correspondence data.
`Original[i]` is original instruction i's decoded index in the transformed stream, and `Hooks` contains half-open ranges of inserted function bodies; both are untrusted hints whose contents `Check` verifies independently.
An `LDIMM64` is one decoded instruction and two raw slots for relocation.
`Label` before transformation and `FromLabels` afterwards extract hints from preserved metadata; `Check` verifies their contents independently.
The separate **premises** are trusted caller inputs.
`LowestOffset` is the stack-alias audit, including indirect accesses and callee use of caller-stack pointers.
`Targets` binds `{Site, When, Hook, Ctx}` in plan terms: the original instruction index, `hit`, `miss`, `any`, or `error`, the decoded index of the generated hook start, and an optional callee-frame context source.
`Ctx` names either R6-R9 or an aligned slot within the audited frame.
The checker verifies that the prelude copies the named source; it does not prove that source semantically contains context.
For map calls, omission selects the existing entry-frame path; the older P4 tail-call shape may instead initialize a callee frame directly from helper R1.
For a lookup, `any` requires the hook on both the hit and miss paths.
The caller must use `inject.BuildLookupTargets` or derive the same data from the plan, never from transformed call references.
`BuildLookupTargets` returns `inject.ErrCheckerNotApplicable` for an indirect `callx`, whose target it cannot pair.
`inject-run` loads that substituted stream without validation by default and refuses it only with `--fail-closed`.
The checker checks its range and direct RFP accesses, but cannot establish the alias audit from the instruction projection.

## Checked shapes

The pattern names used in comments have the following meanings.
They describe insertion shapes, while “original program” refers to the program being rewritten.

| Name | Shape | What is checked |
| --- | --- | --- |
| P1 | Entry context spill, optionally an entry/dispatch hook and R1 restore | Exact slot, dispatch arguments, hook destination and restore |
| P1c | Callee-frame context initialization before a map helper | Exact plan-named R6-R9 store, or exact audited-slot load through R0 and context store |
| P2 | Lookup/per-CPU lookup spill and conditional observer postlude | One result guard, at most two alternative calls, planned result-arm targets, R1 context and generic/dispatch R3-R5 provenance/order, value-copy pairs, full-width R0 restoration on every path |
| P3 | Map update/delete spill and observer postlude | Helper argument spills, optional signed result guard, planned result target, R1 context and generic/dispatch R3-R5 provenance/order, one call, full-width R0 restoration |
| P4 | Tail-call prelude and failure postlude | Unchanged helper arguments and target, planned hook, R1 context, dispatch R4/R5 provenance, local or entry-frame context initialization |
| P5 | Queue/stack push/pop/peek spill and observer postlude | Helper-specific spills, planned result target, R1 context and generic/dispatch R3-R5 provenance/order, one hook, full-width R0 restoration |
| P6 | A u32 hook after `ldxw R2, [R0+offset]` | Exact six-instruction save/call/restore region, u32 hook body, R1/R3–R5 dead at the original continuation |
| P7 | Observer function | No-op return, u32 XOR return, or permitted context/pointer reads followed by zero return; no stores or calls |

The stack layout is independent of the transformer's implementation.
Let `f = LowestOffset &^ 7` be the aligned floor.
Slots are relative to `f`: context at `f-8`, key or tail index at `f-16`, helper result at `f-24`, map at `f-32`, and update value at `f-40` (or `f-32` without a map spill).
The `f-24` slot intentionally holds update R4/push R3 flags before the postlude reloads them and overwrites it with R0.
The u32 region instead saves R0 at `f-8` and R2 at `f-16`, overlapping the entry context and key slots.
Helper hook calls require the saved context in R1. Generic and dispatch map calls additionally check their helper-specific R3-R5 roles, including constant zero for NULL roles; dispatch tail calls check R3-R5.
R2 (the site id or info word) remains unchecked at every site-tagged hook. Typed and static non-generic key/value roles also remain outside acceptance.
Mixed u32/helper streams do not establish that a later observer receives the original context: a u32 region stores R0 in the same slot from which a later helper hook may reload R1.
All inserted stores must fit below `f` and within the 512-byte frame.
P1c may read only the premise-named aligned slot at or above `LowestOffset`.

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
An entry context spill initializes only the entry frame, bounded by function-referenced subprogram/callback entries.
A callee-frame site must initialize its context slot in the helper prelude from the register or slot named by its trusted target premise.
Unreferenced exception callbacks are outside this frame-identification premise.

Acceptance covers the **compared projection**: decoded instruction fields, references, resolved edges and the checked insertion rules.
In-memory originals must also retain identical CO-RE, kconfig, kfunc and ksym metadata pointers at every correspondence; none is permitted in inserted regions, including hooks.
This checks identity, not relocation meaning, and assumes the shared metadata objects are not mutated during checking or loading.
The implementation reads the private metadata keys of the pinned cilium/ebpf version because that library has no public iterator for them; tests parse an ELF fixture for each kind.
Nil metadata keys carry no load-time meaning and are ignored by both the checker and the instruction encoder; unexpected metadata layouts return a typed `MetadataUnsupported` rejection.
Associated maps are refused in both streams even if the associations are identical.
Check before map association, using a shared, unchanged external symbol/FD binding table.
Numeric FDs are identifiers in that namespace, not transferable live maps.

Acceptance is conditional on valid original and transformed BPF, the calling convention, the trusted stack audit, and trusted plan-derived targets.
The checker does not establish kernel acceptance, BTF/CO-RE meaning, JIT correctness, observer noninterference, observation arguments beyond the listed checks, concurrency, time or randomness.
It does not load, attach or pin BPF.

## JSON and error classification

```sh
go build -o inject-check ./cmd/inject-check
./inject-check pair.json
```

The writer and reader share the tagged `injectcheck.Pair` type.
Format 3 adds the optional callee context source to the decoded `asm.OpCode` representation pinned by format 2; readers accept both versions.
The format number is not the kernel opcode byte.
Required, case-sensitive top-level keys are `format`, `original`, `transformed`, `certificate` and `premises`.
`certificate.original`, `premises.lowest_offset`, and `premises.targets` are also required; `certificate.hooks` may be empty or omitted, and `premises.targets` may be empty only when there are no inserted calls.
Span fields are `start` and `end`; target fields are `site`, `when`, `hook`, and optional `ctx`.
`ctx` contains either `reg` (6 through 9) or `slot` (an aligned negative frame offset).
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
The trusted premises, including targets, are echoed with the verdict.
`errors.As` distinguishes the following API errors; both expose a stable `Kind` and human-readable `Detail`.

| Outcome | Type | CLI exit | Examples |
| --- | --- | --- | --- |
| Accepted | nil | 0 | All checked rules hold |
| Input error | `*InputError` | 2 | Malformed JSON; missing/null required field; empty original/mapping; mapping length/order error; invalid/overlapping hook ranges; absent or malformed target plan; floor outside [-512,0]; invalid original register or CFG; unsupported format |
| Rejected transformation | `*Rejection` | 1 | Changed instruction/reference/edge; unplanned call or missing planned call; unsafe inserted store, branch, register effect or hook; metadata change; associated map |

Decode/file/usage errors go to stderr; structural input errors found by validation also receive a JSON verdict.
The kinds distinguish empty original, empty mapping, length mismatch and invalid floor.

## Tests and local corpus evidence

Run `go test ./pkg/injectcheck ./pkg/inject ./cmd/inject-check`.
`TestPairCorpus` builds the CLI and compares its complete verdict with the API and expected `{accepted, kind}` for the committed format 2 pair JSON corpus, including seven accepted configurations and all eleven mutations.
`TestTranslationValidationSubprogramContextPairCorpus` round-trips accepted register and slot premises through format 3 and rejects a different register, a different slot, and a missing matching initialization.
This is the scope of the committed CLI/API agreement evidence.
`TestTranslationValidationEquivalence` compares checked site counts and certificate hook names against the plan, including entry-only hooks, and reports site-bearing and zero-site fixtures separately.
The dependency test rejects a direct or transitive dependency on `pkg/inject` from the checker or CLI.

Privileged `TestBpf*` fixtures use only load and `BPF_PROG_TEST_RUN` and are registered in `scripts/test/privileged.py`.
Run them as root in a suitable test VM with `go test ./pkg/injectcheck -run '^TestBpf' -v`.
They cover map identity and the verifier premise for lookup, delete and tail-call postludes.

The local-only census requires `BPF_NINJA_VALIDATE_OBJECTS`, `BPF_NINJA_VALIDATE_CENSUS` and `BPF_NINJA_VALIDATE_OUTPUT`.
The census results must contain `<object>--<program>/plain/load.json` with a `Bound` from the external stack-audit tool; this repository does not produce that audit.
Missing bounds produce `INPUT_REFUSED` rows for all four forms and are excluded from acceptance counts.
Raw-form counts and plans are computed independently; a typed refusal produces an explicit `RAW_NOT_RUN` row.
Four forms repeat each program, so rows are not independent samples.
