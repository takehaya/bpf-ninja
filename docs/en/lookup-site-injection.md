# Typed map-lookup observation injection (`pkg/inject`)

`inject.TransformLookup` instruments one `bpf_map_lookup_elem` helper call in one native XDP program before loading it.
It generates a global BTF function whose pointer types come from the entry function and the map definition in the ELF:

```c
int HOOK(struct xdp_md *ctx, const KEY *key, const VALUE *value);
```

An fentry observer attached to `HOOK` can correlate packet context, the lookup key, and the returned value.
The hook runs only when the lookup returns a non-null value.
It uses all three arguments and returns zero; the injected code restores the original lookup result before the program continues.
This is a separate transform from the audited `u32` observation transform described in [typed-injection.md](typed-injection.md).
The existing `Transform` API and behavior are unchanged.

## Discovery and selection

`DiscoverLookups(elf, programName)` lists lookup helper calls in instruction order without loading BPF or requiring a stack audit.
Each `LookupSite` reports the map name, key and value BTF type names, containing BTF function, file and line, raw `SitePC`, and slice `InstructionIndex`.
`SitePC` counts raw BPF slots in the flattened `ProgramSpec.Instructions`; `LDIMM64` occupies two slots.
`InstructionIndex` indexes that Go instruction slice.
Source locations use the most recent BTF `line_info` within the containing function.
Missing names are empty strings, missing lines are zero, and anonymous BTF types may have no name.
Named typedefs retain their names.

Discovery resolves a map only when R1 is assigned by an `LDIMM64` map reference in the same basic block and remains unchanged before the helper.
It does not trace a map pointer through another register, stack memory, a preceding block, or an inner-map lookup.
Branch targets, function starts, and instructions after jumps or calls begin new blocks.
Atomic instructions and legacy packet loads conservatively invalidate map provenance.
Calls that cannot be resolved, lack usable map BTF, or lie in a called subprogram are still listed with a `Reason`.
Unsupported relocation shapes return an error instead of a partial listing.
A listing with an empty `Reason` does not certify the stack, context prototype, or the rest of the transform's checks.

`LookupSelector.MapName` is required.
`FuncName` and `Line` optionally filter by containing BTF function and source line.
The selector must match exactly one site, including sites with a `Reason`; ambiguity is refused rather than selecting the first match.
Two calls to the same map on the same source line cannot be disambiguated by this API.

```go
sites, err := inject.DiscoverLookups(elf, "ingress")
if err != nil {
    return err
}
for _, site := range sites {
    fmt.Printf("%s <%s, %s> %s %s:%d pc=%d index=%d %s\n",
        site.MapName, site.KeyTypeName, site.ValueTypeName,
        site.FuncName, site.File, site.Line,
        site.SitePC, site.InstructionIndex, site.Reason)
}

res, err := inject.TransformLookup(elf, inject.LookupRequest{
    ELFSHA256:   auditedSHA256,
    ProgramName: "ingress",
    Site: inject.LookupSelector{
        MapName: "sessions", FuncName: "ingress", Line: 200,
    },
    HookName: "observe_session",
    Stack:    inject.StackAudit{LowestOffset: -64},
})
if err != nil {
    return err // stop; do not silently load the unmodified ELF
}
coll, err := ebpf.NewCollectionWithOptions(res.Spec, ebpf.CollectionOptions{})
```

The names, source line, and stack bound above are placeholders for an audited build.
The loader owns the resulting collection and must close it when finished.
Discovery reads the supplied bytes; it does not establish an audit.
`TransformLookup` independently clones, hashes, and parses its supplied ELF bytes and requires the audited SHA-256.

## Supported sites and trust boundary

This version instruments **one site per transform call**, in the selected program's entry function.
Discovery includes called subprograms, but injection there is refused because their R10 refers to a different stack frame from the saved entry context.
The API does not compose transformations on an already transformed spec.
Only the selected program changes, including when other programs share a linked subprogram or a map.

Supported maps are hash, array, per-CPU hash/array, and LRU hash/per-CPU hash maps.
The key and value must have BTF with nonzero sizes exactly matching the map's key and value sizes.
The hook retains these types, including typedefs and qualifiers, under `const` pointer parameters.
Types named `struct xdp_md` or `struct bpf_dynptr` are refused as map key/value types because the verifier assigns those pointer types special argument semantics.
Other map kinds are refused rather than assuming their helper return is ordinary value memory.
The entry function must have one BTF parameter pointing to `struct xdp_md`.
The package checks the XDP program type; the cooperative loader owns attachment mode and verifier acceptance.

| Transformer validates | Caller must certify |
|---|---|
| The input ELF matches `ELFSHA256` before parsing. | The hash identifies the audited build. |
| The selector resolves exactly one direct-map lookup in the entry function. | This is the intended observation site. |
| Map BTF sizes match the map definition, and entry BTF describes an XDP context pointer. | The BTF describes the audited build. |
| Direct R10 references stay at or above `Stack.LowestOffset`; three aligned spill slots fit below it within 512 bytes. | Pointer aliases and called subprograms do not reach the reserved spill region. |
| Existing function and source metadata are complete, references resolve, and relocation fits. | The transformed program remains acceptable to the target kernel verifier. |

The stack audit has the same alias and callee limitations as `StackAudit` in the original transform.
Three 8-byte slots require an audited bound of at least `-488`, rounded down to an 8-byte boundary before allocating the slots.
The transform checks direct R10 references throughout the flattened selected program.
It does not infer stack usage through aliases.

Unlike the existing transform, this transform requires **no caller-saved register liveness certification**.
R1–R5 are dead after a helper call by the BPF calling convention.
R0 is the live lookup result and is saved and restored across the generated hook call.
R6–R9 retain the normal callee-saved calling convention.

## Inserted instructions

At entry to the selected program, one instruction saves R1 into `ctx_slot`.
The original entry function's symbol, BTF function metadata, and source line move to this instruction.
Back edges to the original first instruction skip this one-time spill.

At the selected lookup, the transform emits:

```text
*(u64 *)(r10 + key_slot) = r2
call bpf_map_lookup_elem             ; original instruction
*(u64 *)(r10 + result_slot) = r0
if r0 == 0 goto restore
r1 = *(u64 *)(r10 + ctx_slot)
r2 = *(u64 *)(r10 + key_slot)
r3 = r0
call HOOK
restore:
r0 = *(u64 *)(r10 + result_slot)
```

The appended hook reads `ctx->data`, checks its independently verified memory arguments for null, reads one byte from each non-null key/value pointer, and returns zero.
These reads keep all arguments used without modifying the packet, key, or map value.
The call-site null guard prevents observation of missing keys; no `__arg_nullable` annotation is used.
For global functions, the kernel derives generic memory argument sizes from the pointed-to BTF types, while recognizing the XDP context separately; see [`btf_prepare_func_args` in Linux](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/btf.c#L6930).
The hook's internal checks allow independent verification with nullable generic memory arguments.
The successful call site supplies the map value pointer and the original key pointer, including a stack key.

An fentry observer must also obey the tracing verifier's pointer rules.
On the tested kernel, directly loading the custom struct pointer from the fentry context is rejected.
The kernel test obtains key/value addresses with `bpf_get_func_arg` and reads their contents with `bpf_probe_read_kernel`.
It reads the first context argument directly, which tracing translates to `struct xdp_buff`, and resolves `data`/`data_end` offsets from kernel BTF.
Its length measurement covers the linear packet data.
The target needs global BTF memory-argument support and fentry; this observer also needs `bpf_get_func_arg` and kernel BTF.
The test skips without root or known missing BPF permissions/features and fails on verifier rejection.
No minimum kernel compatibility claim follows from the single tested version.

## Relocation and audit outputs

The transform reuses the original transform's relocation classifier, collision checks, reference checks, stack check, and ext-info check.
Numeric branches and calls retain their original targets after accounting for the entry spill and site insertion, including two-slot `LDIMM64` instructions.
A branch to the helper targets its key spill; a branch to the next original instruction bypasses the hook.
Symbolic calls remain unresolved for the loader.
Original map, line, BTF, and CO-RE metadata remain attached to their instructions, except for the entry metadata moved to the ctx spill.
The appended global function has its own function and source metadata.

As with the original transform, function-pointer loads, symbolic branches, long jumps, resolved symbolic calls, unknown references, targets off instruction boundaries, and relocation overflow are refused.
Calls back to the program entry are also refused.
Hook names must be valid C/BTF identifiers and must not collide with existing symbols or BTF functions or satisfy an existing reference in the selected program.
Refusals wrap `inject.ErrRefused`, return no result, and leave inputs untouched.
ELF parse failures remain parse errors.

`LookupResult` embeds `Result` and reports the original selected `Site`.
`InsertedAt` is zero because the first insertion saves ctx at entry.
`InsertedSlots` is 16: one entry spill, eight site instructions, and seven hook instructions, adding 128 bytes.
`SourceChecksum` and `TransformedChecksum` cover the raw instruction encoding, with symbolic calls unresolved.
They exclude BTF, source lines, CO-RE metadata, and symbolic/map references; they do not identify the fully loaded kernel artifact.
The ELF SHA-256 binds the full input.

## What is not covered

The transform observes successful lookup calls at the selected site only.
It does not observe update/delete helpers, LRU eviction, non-map lookups such as `bpf_fib_lookup`, map-in-map traversal, or `bpf_for_each_map_elem` callbacks.
It does not provide a consistent value version under concurrent control-plane updates or other writers.
The observer reads the returned object during the hook; the program's later reads may see different contents.
There is no snapshot, locking, or transaction guarantee, and observation adds execution cost.

This requires reloading.
Retrofitting a running program means loading a transformed copy that reuses the running program's maps by ID and swapping it in.
This package does not retrieve those maps, load or swap programs, attach to interfaces, pin objects, or modify a running instruction stream.

## Tests

Unit tests cover discovery, map provenance, ambiguity, map BTF validation, reserved stack boundaries, metadata preservation, clone isolation, relocation, refusal without mutation, and ELF hash/checksum handling.
`TestLookupThroughELF` compiles a synthetic BTF map fixture, discovers two lookup source lines, and transforms the line-selected site through the exported API without BPF privileges.
`TestBpfLookupInjectionObservesContextKeyValue` uses asm fixtures with a hash map keyed by a packet `u32` and a value `{u64 seid; u64 imsi;}`.
It compares plain and injected programs, checks two keys with different packet lengths and `imsi` values, verifies silence for a missing key, and checks observation before attachment and after detachment.
It exercises the transform core and fentry using `BPF_PROG_TEST_RUN`, without an interface attachment or pinning.

```sh
go build ./...
go vet ./...
go test -count=1 ./pkg/inject/...
sudo -E env PATH=$PATH go test -run TestBpfLookupInjectionObservesContextKeyValue ./pkg/inject/...
```

The privileged test passed on Linux `7.0.0-38-generic`.
This is finite test evidence for the fixture, not a general program-equivalence, concurrency, or kernel-version guarantee.
