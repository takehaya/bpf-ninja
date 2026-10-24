# Typed map-lookup observation injection (`pkg/inject`)

`inject.TransformLookup` instruments one or more `bpf_map_lookup_elem` helper calls to the same map in one native XDP program before loading it.
It generates a global BTF function whose pointer types come from the entry function and the map definition in the ELF:

```c
int HOOK(struct xdp_md *ctx, const KEY *key, const VALUE *value);
```

An fentry observer attached to `HOOK` can correlate packet context, the lookup key, and the returned value.
The hook runs only when the lookup returns a non-null value.
It uses all three arguments and returns zero; the injected code restores the original lookup result before the program continues.
This is a separate transform from the audited `u32` observation transform described in [typed-injection.md](typed-injection.md).
Both transforms share callback-reference relocation; their hook APIs and site-selection rules remain separate.

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
Unsupported relocation shapes, including invalid callback references, return an error instead of a partial listing.
Valid function-pointer loads do not prevent discovery or transformation of entry-function sites.
A listing with an empty `Reason` does not certify the stack, context prototype, or the rest of the transform's checks.

`LookupSelector.MapName` is required.
`FuncName` and `Line` optionally filter by containing BTF function and source line.
By default, the selector must match exactly one site, including sites with a `Reason`; ambiguity is refused rather than selecting the first match.
Two optional selection modes support duplicated inline lookups and other multiple-site cases:

- `SitePCs: []uint32{pc1, pc2}` selects explicit raw PCs from discovery, each of which must also match `MapName`, `FuncName`, and `Line`.
  A one-element list disambiguates a single call; an empty list is unspecified.
  Duplicate PCs, non-lookup PCs, and PCs that fail any filter are refused.
- `AllMatches: true` selects every site matching those filters and requires at least one match.

`SitePCs` and `AllMatches` are mutually exclusive.
All selected sites must resolve to the named map and be supported entry-function lookups; any refusal rejects the entire transform.
Selection results are always in original instruction order, regardless of the order in `SitePCs`.

### Automatic selection

`LookupRequest.Auto` instruments every supported lookup in the program instead of a selected one.
`Site` must then be empty, and `HookName` becomes a prefix.
Each map identity gets its own hook, because one hook prototype can only carry one key/value BTF type pair:

```c
int PREFIX_MAP(struct xdp_md *ctx, u32 site, const KEY *key, const VALUE *value);
```

`site` is the lookup's original `SitePC`, so an observer can tell inlined copies of the same lookup apart.
`MAP` is the map name with characters outside `[A-Za-z0-9_]` replaced by `_`.
When that name is empty, invalid, or already used by another hook in the request, the hook is named `PREFIX_<index>` instead, where index is the hook's position in `Hooks`.
Hooks are numbered in the order their maps first appear in the program.
`LookupResult.Hooks` lists each hook with its map name and sites.
Sites that discovery lists with a `Reason` are not instrumented; they are reported in `LookupResult.Skipped` rather than refusing the transform.
If no site is supported, the transform is refused.
Every hook name passes the same collision checks as a single `HookName`.

All hooks of one program share the three reserved stack slots, since only one lookup site runs at a time.
An observer attaches one fentry program per hook it wants to see.

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
        AllMatches: true, // include compiler-duplicated instances of this lookup
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

## Raw-load API

`DiscoverLookupsRaw(p RawProgram)` and `TransformLookupRaw(p RawProgram, req LookupRequestRaw)` accept one flattened `BPF_PROG_LOAD` input without an ELF or `ebpf.CollectionSpec`.
`RawProgram` contains decoded `asm.Instructions`, the `ebpf.ProgramType`, the `*btf.Spec` referenced by `prog_btf_fd`, and `FuncInfo`/`LineInfo` byte slices in native-endian kernel wire format (8-/16-byte records, no record-size header).
Metadata offsets count raw instruction slots; callers must normalize other record sizes.
The buffers supply function and source metadata independently of the instructions.
CO-RE relocations must already be applied.

`RawProgram.Maps` is a `map[int32]RawMap` keyed by the fd in each map-load immediate.
Each `RawMap` supplies `Name`, `Type`, `KeySize`, `ValueSize`, and key/value `btf.Type` values; those types may come from a separate map BTF object.
The selector uses `RawMap.Name`, while identity remains the fd: selecting sites with different fds is refused even when their names match.
`LookupRequestRaw` contains the existing `LookupSelector` as `Site`, `HookName`, and `StackAudit` as `Stack`.
The caller certifies the instructions, map identities, BTF and stack audit together; this API has no ELF hash binding.
Both front ends share discovery, selection, map ABI checks, hook generation, placement, relocation and refusal rules.

`LookupResultRaw` returns `Instructions`, `Site`/`Sites`, insertion counts and instruction checksums, plus an extended `BTF` spec and its `BTFBytes` blob.
Original type IDs are preserved; the hook's types and any external map types are appended.
`HookTypeID` identifies the generated `int hook(ctx, const KEY *, const VALUE *)` function, and `HookFuncInfo` contains its 8-byte function-info row.
The returned `FuncInfo` and `LineInfo` buffers include the hook and relocated original rows.
The BTF string table is rebuilt, so these buffers must accompany the returned blob.
A future syscall front end can load `BTFBytes` with `BPF_BTF_LOAD`, set `prog_btf_fd` to that result, and supply these metadata buffers.
`Instructions.Marshal` resolves generated symbolic hook calls; marshal a copy to retain the unresolved checksum representation.
Raw checksums also include the supplied fd immediates and already-resolved numeric function references.
This API performs no syscalls, BTF/program loads, interception, attachment or pinning.

## Supported sites and trust boundary

One transform call instruments the selected sites in the program's entry function with the same hook.
It saves ctx once, shares three spill slots across the sites, and inserts one hook function immediately after the entry function.
The sites execute sequentially, including on different paths or repeated loop iterations; they do not require nested spill storage.
Discovery includes called subprograms and callbacks, but injection there is refused because their R10 refers to a different stack frame from the saved entry context.
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
| The selector resolves supported lookups of the same map in the entry function. | These are the intended observation sites. |
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

At each selected lookup, the transform emits:

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

With `Auto`, the argument setup is `r1 = ctx`, `r2 = SitePC` (a 32-bit move), `r3 = key`, `r4 = r0`, one instruction longer per site.

The generated hook is placed immediately after the entry function (before any other subprograms or callbacks, or at the end of the program when there are none).
It reads `ctx->data`, checks its independently verified memory arguments for null, reads one byte from each non-null key/value pointer, and returns zero.
These reads keep all arguments used without modifying the packet, key, or map value.
The call-site null guard prevents observation of missing keys; no `__arg_nullable` annotation is used.
For global functions, the kernel derives generic memory argument sizes from the pointed-to BTF types, while recognizing the XDP context separately; see [`btf_prepare_func_args` in Linux](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/btf.c#L6930).
The hook's internal checks allow independent verification with nullable generic memory arguments.
The successful call site supplies the map value pointer and the original key pointer, including a stack key.
Placing the hook immediately after the always-live entry function (`subprog 1`) avoids a kernel verifier bug where dead-subprogram removal (`adjust_subprog_starts_after_remove` in `kernel/bpf/verifier.c`) compacts `prog->aux->func_info` without compacting `prog->aux->func_info_aux`: if an unreached subprogram precedes a static callback or helper subprogram whose BTF argument check marked `func_info_aux` as `unreliable`, a hook appended after that callback shifts onto the stale `unreliable` flag and `bpf_check_attach_target` drops `attach_func_proto`, downgrading `fentry` arguments to untyped scalars.

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
Numeric branches, calls, and callback loads retain their original targets after accounting for the entry spill, every site insertion, and the generated hook inserted after the entry function, including two-slot `LDIMM64` instructions.
A branch to the helper targets its key spill; a branch to the next original instruction bypasses the hook.
Symbolic calls and callback loads remain unresolved for the loader.
Original map, line, BTF, and CO-RE metadata remain attached to their instructions, except for the entry metadata moved to the ctx spill.
The generated global function has its own function and source metadata.

Function-pointer loads (`LDIMM64` with `BPF_PSEUDO_FUNC`, such as a `bpf_loop` callback) are classified separately from ordinary immediates.
A symbolic callback load must have the loader's unresolved constant `-1` and reference exactly one symbol in the flattened program.
Its instruction and metadata remain unchanged for the loader to resolve against the transformed stream.
A numeric callback load has no symbolic reference and carries a signed `int32` offset relative to its first raw slot plus one, despite occupying two slots.
That offset is relocated across the entry spill, every site insertion, and the generated hook, with an `int32` overflow check.
Both forms must target a non-entry instruction carrying BTF function metadata; references to the program entry, function interiors, missing or duplicate symbols, and non-instruction boundaries are refused.
A nonzero instruction offset, an immediate outside signed `int32`, or a symbolic load whose constant is already resolved is also refused.
Callback function and source metadata move with the original instructions.

As with the original transform, symbolic branches, long jumps, resolved symbolic calls, unknown references, targets off instruction boundaries, and relocation overflow are refused.
Calls back to the program entry are also refused.
Hook names must be valid C/BTF identifiers and must not collide with existing symbols or BTF functions or satisfy an existing reference in the selected program.
Refusals wrap `inject.ErrRefused`, return no result, and leave inputs untouched.
ELF parse failures remain parse errors.

`LookupResult` embeds `Result` and reports all original selected `Sites` in instruction order.
Its existing `Site` field is the first element of `Sites`.
`InsertedAt` is zero because the first insertion saves ctx at entry.
`InsertedSlots` is `8 + 8*len(Sites)`: one entry spill, eight instructions per site, and seven hook instructions.
One site adds 16 slots (128 bytes); two sites add 24 slots (192 bytes).
With `Auto`, it is `1 + 9*len(Sites) + 7*len(Hooks)`; the hooks are placed together right after the entry function.
`SourceChecksum` and `TransformedChecksum` cover the raw instruction encoding, with symbolic calls and callback loads unresolved.
They exclude BTF, source lines, CO-RE metadata, and symbolic/map references; they do not identify the fully loaded kernel artifact.
The ELF SHA-256 binds the full input.

## What is not covered

The transform observes successful lookup calls at the selected sites only.
It does not observe update/delete helpers, LRU eviction, non-map lookups such as `bpf_fib_lookup`, map-in-map traversal, or lookups inside `bpf_for_each_map_elem` callbacks.
It does not provide a consistent value version under concurrent control-plane updates or other writers.
The observer reads the returned object during the hook; the program's later reads may see different contents.
There is no snapshot, locking, or transaction guarantee, and observation adds execution cost.

This requires reloading.
Retrofitting a running program means loading a transformed copy that reuses the running program's maps by ID and swapping it in.
This package does not retrieve those maps, load or swap programs, attach to interfaces, pin objects, or modify a running instruction stream.

## Tests

Raw-load tests check ELF parity, fd identity, numeric callback and multi-site relocation, metadata validation, the hook ABI, and preservation of BTF type IDs and declaration tags.
Unit tests cover numeric and symbolic callback classification, relocation in both directions across one or several insertions, hook placement before subprograms, callback metadata and loader resolution, overflow and ambiguous-reference refusals, discovery, map provenance, ambiguity, explicit-PC and all-matches selection, map BTF validation, reserved stack boundaries, metadata preservation, clone isolation, relocation across multiple insertions and combined branch overflow, refusal without mutation, and ELF hash/checksum handling.
`TestLookupThroughELF` compiles a synthetic BTF map fixture with a `bpf_loop` callback, checks that its symbolic reference and metadata survive, discovers two lookup source lines, and transforms both a line-selected site and multiple sites through the exported API without BPF privileges.
`TestBpfLookupInjectionObservesContextKeyValue` uses asm fixtures with a hash map keyed by a packet `u32` and a value `{u64 seid; u64 imsi;}`.
It compares plain and injected programs, checks two keys with different packet lengths and `imsi` values, verifies silence for a missing key, and checks observation before attachment and after detachment.
`TestBpfLookupInjectionMultipleSites` repeats these checks with two lookups on different paths, observed by one fentry observer on the shared hook.
`TestBpfLookupInjectionAutoMultiMap` instruments a program with lookups on two maps whose values have different BTF types, attaches one observer per generated hook, and checks the key, value, and `site` argument each observer records.
`TestBpfLookupInjectionCallback` checks symbolic and numeric callback loads with an unreached subprogram preceding the `bpf_loop` callback and a stack counter incremented three times by `bpf_loop`; the program returns `XDP_ABORTED` unless those increments occur.
It repeats the plain/injected comparison and fentry observations (including direct `ctx` pointer dereferencing) for both callback forms.
These tests exercise the transform core and fentry using `BPF_PROG_TEST_RUN`, without an interface attachment or pinning.

```sh
go build ./...
go vet ./...
go test -count=1 ./pkg/inject/...
sudo -E env PATH=$PATH go test -run 'TestBpfLookupInjection' ./pkg/inject/...
```

All four privileged lookup tests passed on Linux `7.0.0-38-generic`.
This is finite test evidence for the fixture, not a general program-equivalence, concurrency, or kernel-version guarantee.
