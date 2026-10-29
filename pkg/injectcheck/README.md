# Independent validation of injected instructions

[日本語](README.ja.md)

`injectcheck.Check` takes the original instructions, transformed instructions and a certificate proposing their correspondence, and returns counts and an error.
It does not import `pkg/inject` or use the transformer's site selection, relocation or liveness decisions.
The certificate is an untrusted hint: the checker compares every corresponding instruction and checks every inserted instruction.

```go
counts, err := injectcheck.Check(original, transformed, injectcheck.Certificate{
    Original: originalIndices,
    Hooks: hookRanges,
    LowestOffset: auditedFloor,
})
```

`Original[i]` is the decoded instruction index of original instruction i in the transformed stream.
`Hooks` lists half-open ranges of inserted function bodies.
An `LDIMM64` is one decoded instruction but occupies two raw slots for relocation.
For transforms that preserve metadata, `Label` before transformation and `FromLabels` afterwards can extract correspondence hints.
Missing and duplicate labels are rejected; `Check` independently compares the instructions they identify.

An instruction with a non-nil `Instruction.Map()` is rejected in either stream, including insertion regions and hooks, even when both refer to the same map.
Run the checker before `AssociateMap` or map rewriting.
Map operands are compared as unresolved `Reference` names or numeric FDs in the same FD namespace, assuming a shared, unchanged external binding table.
Rebinding a map spec name to a different live map is outside this contract.

The checker verifies:

- Each original instruction appears once, in order, preserving its opcode, registers, offset, constant and map reference.
- Branches, BPF calls and callback references target the corresponding original instruction or the start of its helper prelude.
  Backward edges to the original entry skip the one-time entry spill.
- Entry code, helper preludes, u32 injection regions and hook bodies have allowed forms.
- Helper postludes use a limited instruction set and forward branches, and restore the full 64-bit R0 on every path except tail-call failure.
- Inserted stores use reserved stack space below the audited floor, and inserted code preserves R6–R10.
  Map-value copies are load/store pairs through R1 from R0 to reserved stack space.
- Hooks contain only allowed argument reads and a return.
  Stores, helpers, kfuncs and other BPF calls in hooks are rejected.
- Direct RFP accesses in the original stay at or above the audited floor.

## Calling convention and liveness

P2–P5 rely on G3 assumption A3 (the BPF calling convention).
The original P must be verifier-accepted, valid BPF: after a helper call, no executable path reads R1–R5 before redefining them.
The inserted region preserves R6–R10 and the original stack, and restores an ordinary helper's R0 on every path, so readable original values and branch conditions remain equal.
Changing scratch registers therefore cannot make a previously infeasible original path executable.
Syntactic CFG liveness includes such infeasible paths and is not a rejection condition for P2–P5.

For P4, a successful tail call skips the postlude, with unchanged helper arguments and destination.
On failure, its `RET_VOID` calling convention also makes R0 unreadable; under A3, clobbering R0–R5 cannot change P's observations.
This reasoning depends on P's verifier validity and A3; acceptance provides no guarantee for an invalid original.
The ctx slot is initialized only by a checked entry spill in the entry frame, or by a ctx spill in that site's prelude.
Original function-reference targets identify subprogram and callback entries; an entry-frame spill never initializes a callee frame.

P6 (the u32 variant) follows an ordinary load, so the helper rule in A3 does not apply.
P6 saves and restores R0 and R2 but clobbers R1 and R3–R5; the checker still requires these registers to be dead using a fixed point on the original CFG.
It uses known helper arities and original callee register usage, treating unknown helpers, kfuncs and variadic helpers such as `trace_printk` as reading all of R1–R5.
Without value or format analysis, this can reject safe P6 sites.
Unverified unreachable-edge claims in a certificate never remove CFG edges.
Helper postludes are checked along all paths within a 4096-step budget; unknown forms and budget exhaustion are rejected.

## Checking a serialized instruction pair

```sh
go build -o inject-check ./cmd/inject-check
./inject-check pair.json
```

The required top-level JSON fields are `Original`, `Transformed` and `Certificate`; field names are case-insensitive, so lowercase spellings are also accepted.
Missing or null required fields are input errors (exit code 2), with a message naming the field.
Instructions contain `asm.Instruction` fields `OpCode`, `Dst`, `Src`, `Offset` and `Constant`, plus string `Symbol` and `Reference` fields.
Use `json.Marshal(injectcheck.Instructions(insns))` to produce them.
This encoder preserves symbols and references and refuses associated maps before serialization can discard their identity.
Direct serialization of `asm.Instructions` loses map metadata and must not be used as CLI input.
The CLI rejects unknown instruction fields, including `Metadata` even when empty; only the dedicated encoder's fields are supported.
Map names and numeric FDs are shared identifiers, not serialized live maps or transferable process FDs.
The upper 32-bit offset of `PseudoMapValue` is retained in `Constant` and compared exactly along with the pseudo kind in `Src`.
The certificate has the same fields as the Go API.
The CLI prints `Accepted`, `Counts` and `Reason`, returning exit code 0 for acceptance, 1 for rejection and 2 for input errors.

Checking does not load, attach or pin BPF.

## Scope of acceptance

Acceptance is conditional on valid original and transformed BPF, the calling convention, and the caller's stack-alias audit.
These are the syntactic sufficient conditions of translation validation (G3 §3.3 T2), not a kernel verifier or a general equivalence proof.
Stack aliases, callee access to reserved caller-stack space, observer map updates, concurrency, time and randomness remain outside the checker.
It also does not validate BTF, CO-RE, kernel acceptance or JIT correctness.
Helper argument setup is checked for allowed instructions and preservation, not for correctness of the site ID or observation arguments passed to the observer.
Instruction preservation and observation-channel correctness are separate properties.

Run unit tests with `go test ./pkg/injectcheck ./pkg/inject`.
Run the equivalence fixtures with `go test ./pkg/inject -run '^TestTranslationValidation' -v`.
For the opt-in corpus test, set `BPF_NINJA_VALIDATE_OBJECTS` to an object directory, `BPF_NINJA_VALIDATE_CENSUS` to recorded census results, and `BPF_NINJA_VALIDATE_OUTPUT` to an output directory.
It records all rejections and fails if the checker rejects any transformed program.

`errors.As` distinguishes `*InputError` (malformed/missing input, empty original or certificate mapping, mapping length mismatch, stack floor outside [-512,0]; CLI exit 2) from `*Rejection` (semantic rule violation; exit 1). Both expose a stable `Kind` and a human-readable `Detail`. Acceptance exits 0.
