# Typed load-time observation injection (`pkg/inject`)

`pkg/inject` performs one bounded, load-time transformation of a BPF ELF.
It splices a single typed observation call into one explicitly selected site of one native XDP program.
It appends a generated global BTF function:

```c
int HOOK(u32 site, u32 value);
```

An injected BPF-to-BPF call invokes `HOOK`.
An fentry program can attach to `HOOK` to observe the `site` (which slot was instrumented) and a `u32 value` read at that site.
The transform runs on the instruction stream parsed from ELF bytes, **before** `ebpf.NewCollectionWithOptions`.
It never rewrites a running program, loads or attaches anything, infers sites, performs CO-RE-style fixups, or reads any path a second time.

This is a mechanism for cooperative loaders operating on **caller-audited** ELF builds.
It is not a compiler, a DSL, or a general instrumentation framework.

## Scope

The supported target is a native `ebpf.XDP` program; any other program type is refused.
The supported site is the fixed load `R2 = *(u32 *)(R0 + Offset)`, followed by an instruction that redefines `R1`.
The transform validates mechanical properties it can see and relies on a caller proof obligation for everything it cannot.
Kernel verifier acceptance of the transformed program is a separate step that this package does not perform.

## What the transform validates vs. what the caller certifies

The audit is a **trust boundary**, not a safety inference.
The transform cannot see register liveness, pointer aliases, or the stack usage of called subprograms, so it does not claim to.
It validates only mechanical properties of the bytecode:

| Transformer validates (refuses otherwise) | Caller must certify (cannot be checked) |
|---|---|
| The supplied ELF bytes are cloned, then hashed to `Request.ELFSHA256` before parsing, so the audit binds the exact bytes parsed. | That `ELFSHA256` is the build you actually audited. |
| The selected program is a native XDP program and the instruction at `SitePC` is exactly `R2 = *(u32 *)(R0 + Offset)`. | That this site is the value you intend to observe. |
| The instruction after the site cleanly redefines `R1` (a MOV, a 64-bit immediate load, or a load from a pointer other than `R1`). | That `R1`, `R3`, `R4`, `R5` are dead or redefined-before-use across the call. |
| The target carries BTF function info on its first instruction and a source line on every function start. | That the BTF describes the build you audited. |
| Every **direct** `R10`/`RFP` reference is at or above `StackAudit.LowestOffset`; the two 8-byte spill slots sit below it, 8-byte aligned, within 512 bytes. | That no pointer **aliases** `R10` into the spill region and no called subprogram's stack reaches below the audited mark. |
| Every relocated branch target is an original instruction boundary; no branch overflows `int16` and no call or callback offset overflows `int32`. | — |
| Every symbolic function reference resolves to exactly one symbol in the selected program's flattened instructions and every map load names a map the collection defines. | — |
| `HookName` is a valid C/BTF identifier, does not collide with an existing symbol, function-metadata name, or BTF `Func`, and is not already referenced by any instruction. | — |

Only `R0` and `R2` are saved and restored around the call.
`R1` is clobbered with the site immediate; the following-instruction redefinition is the structural confirmation the caller's "`R1` dead" certification relies on.
`PtrReg` is fixed to `R0`: a valid original load through `R0` shows `R0` is initialized at the site, which is what lets the splice spill and restore it.

## Fixed call shape

At the selected site the transform inserts six raw slots on the load's fall-through edge:

```
*(u64 *)(r10 + spill0) = r0        ; save r0
*(u64 *)(r10 + spill1) = r2        ; save observed value
r1 = <SitePC>                      ; hook arg 1: site (zero-extended u32)
call HOOK                          ; hook arg 2 (r2) is the observed value
r0 = *(u64 *)(r10 + spill0)        ; restore r0
r2 = *(u64 *)(r10 + spill1)        ; restore value
```

It appends the generated `HOOK` as a global function carrying both BTF function metadata and generated source-line info.
The kernel requires line info for every function, so the generated function needs a source line as well as func metadata.
A target without BTF function info on its first instruction, or without source lines on its function starts, is refused rather than turned into an inconsistent ext-info mix the kernel would reject.

Spill slots are placed strictly below the 8-byte floor of `StackAudit.LowestOffset`, so they cannot collide with any direct reference the transform validated.
The slot arithmetic is done in widened integers, so a very negative `LowestOffset` cannot wrap into a wrongly accepted positive offset; `LowestOffset` must be in `[-512, 0]`.

## Relocation

Instructions after the site shift by six raw slots (an `LdImm64` occupies two slots).
`SitePC` indexes the flattened `ProgramSpec.Instructions` before transformation, including any appended subprograms; it is not an ELF section offset.
The transform rewrites numeric branch offsets, call constants, and callback-load constants for the shift.
It keeps a branch that targeted the next original instruction landing past the insertion, so that branch still bypasses the hook.
It leaves symbolic bpf-to-bpf calls and callback loads for the loader to resolve by name.
It preserves original instruction, BTF, line, map, and CO-RE metadata.

Callback loads (`LDIMM64` with `BPF_PSEUDO_FUNC`) share the [lookup transform's relocation rules](lookup-site-injection.md#relocation-and-audit-outputs).
Symbolic loads require constant `-1` and exactly one matching symbol; numeric loads use a signed `int32` offset from the first raw slot plus one.
Both must target a non-entry instruction carrying BTF function metadata.
Malformed loads, already-resolved symbolic loads, missing or duplicate callback symbols, and targets without subprogram metadata are refused.
Callback support does not change the load shape, liveness certification, spill layout, or default site behavior of `Transform`.

It **refuses** (returning an error wrapping `inject.ErrRefused`, mutating nothing) on: a symbolic branch, a long (`Jump32` `Ja`) jump, an already-resolved symbolic call, a branch, call, or callback target that is not an instruction boundary, a branch that overflows `int16`, a call or callback offset that overflows `int32`, or an unrecognized instruction reference.

## Auditing the output

`Result` exposes `SourceChecksum` and `TransformedChecksum`, plus `InsertedAt`, `InsertedSlots`, and `AddedBytes`.
Each checksum is a SHA-256 over the raw per-instruction encoding of the target program before and after the transform.
That encoding covers opcodes, registers, offsets, and constants, with symbolic call and callback-load constants left unresolved at `-1`.
It does **not** cover BTF, source lines, CO-RE relocations, or map and symbol references, so it does not pin the resolved hook-call target and does not identify the full loaded kernel artifact.
Pin the checksums to detect instruction-level changes to the stream; the input ELF hash remains the binding for all source content.
`Result.Spec` is an independent clone; the parsed source spec is left pristine, and any refusal leaves every input untouched.

## Cooperative loader

A cooperative loader reads the pinned, audited ELF bytes, applies the transform, and only then builds the collection.
When the transform refuses, it stops; it does **not** fall back to loading the unmodified ELF.
`Example_cooperativeLoader` in the package tests is a compilable example of this flow with a synthetic placeholder ELF path and SHA-256; it is not runnable acceptance evidence.

bpf-ninja's existing `--func HOOK --mode entry --arg-echo` can attach to the generated function to echo `value`.
The existing CLI skips the first parameter, so it does not print `site`; the kernel test uses a separate fentry observer to check both arguments.
Because the first argument is a scalar site number (not a packet context), packet capture at this hook is out of scope.

## Tests

The package unit tests cover numeric and symbolic callback support through `Transform`, shared callback classification and relocation refusals, the transform core, the request and shape validation, relocation, the reference and metadata checks, and the checksum, all without a kernel or compiler.
`TestTransformThroughELF` additionally compiles a small synthetic fixture with clang and checks a successful exported `Transform` call, including its hash gate and source checksum, without BPF privileges.
This compiler check follows the repository's optional local clang handling and fails on compiler errors.
`TestBpfTypedInjectionObservesSiteAndValue` loads a synthetic XDP target plain and injected from asm fixtures, over the observed values `0`, `1`, and `0xffffffff`, attaches an fentry observer to the generated hook, and reads back the site and value with an explicit seen counter across the unobserved, attached, and detached phases.
It builds everything from asm fixtures with no clang, ELF file, or other external runtime dependency and exercises the transform core without parsing an ELF.
The acceptance tests are structural plus finite differential kernel inputs; they make no broad program-equivalence or non-interference claim, and no packet-capture or concurrency claim.
