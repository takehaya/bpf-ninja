# Typed map-lookup observation injection (`pkg/inject`)

`inject.TransformLookup` instruments one or more `bpf_map_lookup_elem` helper calls to the same map in one native XDP or tc (`SchedCLS`, `SchedACT`) program before loading it.
It generates a global BTF function whose pointer types come from the entry function and the map definition in the ELF:

```c
int HOOK(struct xdp_md *ctx, const KEY *key, const VALUE *value);
```

In a tc program the hooks take `struct __sk_buff *ctx` instead; the signatures on this page show the XDP form.
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
Such a site, a lookup on a map-in-map, and a direct lookup on a map kind that a typed hook refuses are listed with a `Reason`; only `Auto` observes them, through the generic hook below.
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
Sites that discovery lists with a `Reason` that the generic hook cannot take either are not instrumented; they are reported in `LookupResult.Skipped` rather than refusing the transform.
So are the sites of a hook whose name would pass 127 bytes, of a hook whose slots would pass the frame limit below, and, when the instrumented program would break a call-chain stack limit (see [Entry and tail-call hooks](#entry-and-tail-call-hooks)), first the sites of the generic hook and of copied read-only maps, then every lookup site, keeping the entry and tail-call hooks (with `Dispatch` every lookup site fills the map slot, so the first step already drops them all); each such site's `Reason` names the limit.
If nothing at all is instrumented, and neither `Entry` nor `TailCalls` is requested, the transform is refused.
Every hook name passes the same collision checks as a single `HookName`.

Lookups whose map a typed hook cannot take share one generic hook, placed after the per-map hooks and marked `Generic` and `Untrusted` (`Static` with `StaticUntrusted`, see [below](#supported-sites-and-trust-boundary)):

```c
int PREFIX_any(struct xdp_md *ctx, u64 info, const void *key __arg_untrusted,
               const void *value __arg_untrusted, const void *map __arg_untrusted);
```

The low 32 bits of `info` are the site; for a lookup the upper bits are zero (see [Updates and deletes](#updates-and-deletes)).

These are entry-function lookups where R1 is not a direct map reference in the same basic block, lookups on hash-of-maps and array-of-maps, and direct lookups on XSK maps, devmaps, devmap hashes, sockmaps and sockhashes.
Kernel tests load the generic hook over each of these, in XDP and tc programs, with and without `Dispatch`.
A sockmap or sockhash lookup returns a socket reference that the verifier tracks: the hook gets the socket as `value` and only reads it, and the program must still release it as before.
A direct lookup on any other map kind a typed hook refuses, or on a map whose key or value BTF a typed hook refuses, is skipped (the kernel refuses a program's lookup on a cpumap or reuseport array outright).
`map` is the lookup's R1 at run time, saved before the helper: the map itself, or for an inner lookup the inner map that an outer lookup returned.
For an outer map-in-map lookup, `value` is the selected inner map, not value memory.
Because the hook declares no value type, it also receives lookups whose map is only known at run time, of any kind, such as an XSK map whose lookup returns a socket; an observer must check the map type before decoding `value`.
The hook's BTF carries no key or value type, so an observer identifies the map from `map` (for example by reading `struct bpf_map` fields such as `id` with `bpf_probe_read_kernel`) and decodes the key and value by that map's sizes.
A map ID identifies the map only while it exists; IDs of freed maps can be reused.

All hooks of one program share the reserved stack slots, since only one lookup site runs at a time.
The generic hook's map pointer takes a fourth slot.
An observer attaches one fentry program per hook it wants to see.

`LookupRequest.Maps` limits `Auto` to lookups on the named maps, by exact kernel map name.
For an ELF, whose map symbols can be longer than the 15 bytes the kernel keeps, the full symbol name matches too.
The other lookups are reported in `Skipped` with the reason `map not selected by Maps`, so they cost nothing at run time.
A lookup whose map is only known at run time has no name and is never selected; a direct lookup on a named generic-hook kind, such as a sockmap, is.
A name that matches no lookup is a refusal, so a typo cannot silently instrument nothing.
This matters most with `Dispatch` on a kernel where a tail-calling program takes only one tracing attach: the one hook then sees only the chosen maps, without a filter in the observer.

### Misses

By default a lookup hook is called only when the lookup found an entry.
`LookupRequest.Lookups` changes that: `LookupMiss` calls the hooks only when the lookup returned NULL, and `LookupAny` on both results.
A typed hook cannot take a NULL value (kernels before 6.8 refuse NULL for a sized memory argument of a global function), so a miss calls a second hook with the key alone:

```c
int PREFIX_MAP_miss(struct xdp_md *ctx, u32 site, const KEY *key);
```

Without `Auto` it is `HOOKNAME_miss(ctx, key)`.
With `LookupAny` each map has both hooks, and with `LookupMiss` only the miss hook.
The key is program memory, not the map's, so the miss hook is an ordinary typed hook even on a `BPF_F_RDONLY_PROG` map and loads on kernels without `arg:untrusted`.
The `_miss` suffix counts toward the 127-byte name limit (`_0_miss` under `Auto`), and an underscore is appended while the name collides with another hook's.
The generic hook and the dispatch hook are called on a miss with a NULL `value` and the same `site`, `key` and `map` as on a hit.
`LookupHook.When` says which results call each hook: `LookupHit` or `LookupMiss` on a typed hook, and the request's set on a generic or dispatch hook.

The site keeps one test of R0 after the helper.
For hits it is the existing `if r0 == 0` skip, for misses the reverse, and for both a branch to each hook; R0 is then restored on every path.
Each hook therefore sees R0 as either a map value or zero, never as a pointer that may be NULL, and no slot is added, so the stack bounds do not change.

### Updates and deletes

`LookupRequest.Updates` and `Deletes`, which need `Auto`, also instrument `bpf_map_update_elem` and `bpf_map_delete_elem` in the entry function.
`CallError` calls the hook only when the helper failed (R0 is negative), and `CallAny` after every call.
`Lookups` set to `LookupNone` leaves the lookups alone, for a request that observes only updates or deletes.
Each map gets one hook per op, named after its lookup hook:

```c
int PREFIX_MAP_update(struct xdp_md *ctx, u32 site, const KEY *key, const VALUE *value, u64 status);
int PREFIX_MAP_delete(struct xdp_md *ctx, u32 site, const KEY *key, u64 status);
```

`status` is `(u32)ret | flags << 32`: the helper's result in the low half and, for an update, its flags argument in the upper half.
The key and value are usually the program's memory, never the map's, so these hooks are typed even on a `BPF_F_WRONLY_PROG` map; a key or value that points into a read-only map's value is the exception (see [Supported sites and trust boundary](#supported-sites-and-trust-boundary)).
A program cannot update or delete in a `BPF_F_RDONLY_PROG` map or in a map-in-map, so such sites never reach the transform.
The typed hooks cover the map kinds of the typed lookup hook.
An update on a sockmap or sockhash passes a socket, not memory, so updates and deletes on those two kinds go to the generic hooks below, whose `value` is untyped.
An update or delete on any other kind is skipped; programs cannot update a devmap, an XSK map or a map-in-map at all.
An update or delete whose map reaches R1 only at run time, such as the inner map an outer lookup returned, goes to `PREFIX_any_update` or `PREFIX_any_delete`, which have the generic hook's signature.
A generic or dispatch hook gets the result in its `info` argument:

| Bits | Content |
|---|---|
| 0-31 | the site's `SitePC` (`DispatchEntrySite` for the dispatch entry call) |
| 32-35 | 0 for a lookup, the entry or a tail call; `InfoOpUpdate` (1), `InfoOpDelete` (2), `InfoOpPush` (3), `InfoOpPop` (4) or `InfoOpPeek` (5) |
| 36-43 | the low 8 bits of an update's or a push's flags |
| 48-63 | the helper's result as a signed 16-bit value (an error is at least -4095) |

A lookup, the entry and a failed tail call leave bits 32 to 63 at zero, so their `info` equals the `u32 site` these hooks took before.
A delete passes a NULL `value`.
On these hooks `LookupHook.Kind` is `HookUpdate` or `HookDelete`, and `When` is `error` or `any`.
The `_update` and `_delete` suffixes count toward the 127-byte name limit (`_0_update` under `Auto`).

An update site keeps its flags in the result slot until the helper returns, and its value pointer in the map slot, or with a hook that also takes the map, in a fifth slot below it.
A typed update therefore needs a stack bound of `-448`, and a generic or dispatch update `-440`; `Auto` skips a generic update past that, and `CheckLookupStack` requires `-448` with `Updates`, or `-440` with `Dispatch` as well.
A delete uses the slots of a lookup.
With `CallError`, a successful call runs only the spills, one compare and the restore of R0.

### Pushes, pops and peeks

`LookupRequest.Pushes`, `Pops` and `Peeks`, which need `Auto` too, instrument `bpf_map_push_elem`, `bpf_map_pop_elem` and `bpf_map_peek_elem` in the entry function, with the same `CallError` and `CallAny`.
These helpers take no key: R2 is the value, which a push reads and a pop or peek writes.
Each map gets one hook per op:

```c
int PREFIX_MAP_push(struct xdp_md *ctx, u32 site, const VALUE *value, u64 status);
int PREFIX_MAP_pop(struct xdp_md *ctx, u32 site, const VALUE *value, u64 status);
int PREFIX_MAP_peek(struct xdp_md *ctx, u32 site, const VALUE *value, u64 status);
```

`status` is `(u32)ret | flags << 32` as for an update; only a push has flags.
The hook runs after the helper, so a pop or peek hook sees the value the helper wrote: the element on success, and zeroes when a queue or stack is empty (`ENOENT`).
On another error, such as `EBUSY` when the map's lock cannot be taken, the kernel writes nothing, and the hook sees whatever the buffer held before.
A push with `BPF_EXIST` on a full queue or stack drops its oldest element, and without it fails with `E2BIG`.
A peek on a bloom filter tests the value the program passed, and fails with `ENOENT` when the value is absent.
The value is usually the program's memory, so these hooks are typed, except for a value that points into a read-only map's value, as for an update.
A push, pop or peek whose map reaches R1 only at run time, such as an inner queue an outer lookup returned, goes to `PREFIX_any_push`, `PREFIX_any_pop` or `PREFIX_any_peek`, which have the generic hook's signature and get a NULL `key` and the value in `value`.
Only queues, stacks and bloom filters take these helpers; a site on any other kind, or on a map whose value BTF does not match its size, is skipped with a `Reason`.
With `Dispatch`, these sites call the dispatch hook with a NULL `key` and the value in `value`.
`LookupHook.Kind` is `HookPush`, `HookPop` or `HookPeek`, and the suffixes `_push`, `_pop` and `_peek` count toward the name limit like `_update`.
A push keeps its flags in the result slot and its value pointer in the key slot until the helper returns, so these sites use the slots of a lookup.

`bpf_map_lookup_percpu_elem` takes the lookup hooks of its map, hit and miss alike, and is selected with `Lookups`.
The hit hook gets the value of the CPU the program named; the CPU itself is not passed, so only the site tells a per-CPU lookup from a plain one on the same map.

### Entry and tail-call hooks

An fentry on an XDP program does not fire when the program is entered through `bpf_tail_call`: the tail call jumps past the trampoline at the program's start.
Calls made from inside the program still reach their fentry trampolines.
Two optional hooks use that to observe tail-call boundaries:

```c
int HOOK_entry(struct xdp_md *ctx);                        // LookupRequest.Entry
int HOOK_tail_call(struct xdp_md *ctx, u32 site, u32 index); // LookupRequest.TailCalls
```

`Entry` calls `HOOK_entry` once at the start of the program, on direct runs and on tail-call entry alike.
Instrument the tail-call target with it.
`TailCalls` calls `HOOK_tail_call` after every `bpf_tail_call` in the program, including those in subprograms.
The helper only returns when the tail call failed (empty slot, index out of range, or the tail-call limit), so the hook sees failures only; a successful tail call does not return.
`site` is the helper's original `SitePC`, and `index` is the index the program passed, truncated to 32 bits as the helper itself does.
Observers should read both arguments as `u32`: on architectures whose JIT needs explicit zero extension, the upper halves of the argument registers are not defined.
A tail call outside the entry function cannot reach the entry frame's ctx spill, so it also saves R1, the ctx the helper takes, into `ctx_slot` of its own frame before the helper.
The stack audit covers direct R10 references in every function, so the same slot offsets are free in that frame.
The transform deepens the entry frame, and every frame holding a site, to its spill region, and each hook is one more frame below the function that calls it. The verifier walks every call chain from the entry through bpf-to-bpf calls and callback references such as a `bpf_loop` callback (`check_max_stack_depth`), rounds each frame's stack depth up (to 32 bytes, at least 32, on 6.1 and for the interpreter; to 16 when newer kernels JIT the program), and rejects a chain whose frames above a tail-calling subprogram reach 256 bytes, whose frames total more than 512 bytes, or that is more than 8 frames deep. A deep entry frame, a stack-using intermediate frame or callback, the entry's own tail-call spill, a deep frame calling a hook, or a hook called from the 8th frame can each push a chain over a limit the original program stayed within. The transform measures the transformed program under both roundings, with each function's depth taken from its direct R10 references and supported constant-offset aliases, callbacks walked like calls, and a function no chain reaches walked from its own frame.
An unsupported alias uses the audited `Stack.LowestOffset` for its entire frame.
The transform refuses, naming the chain, when a chain the transform made deeper (a function with spill slots, or a hook frame) breaks a limit, rather than emit a program the verifier would reject; with `Auto` it first drops lookups, as described under [Automatic selection](#automatic-selection).
These depths come from the instructions, not from the verifier's walk, so a store behind a branch the verifier never takes still counts; an original chain that appears past a limit is therefore no proof that the kernel tolerates it, and only a chain the transform left unchanged may stay past one.
The model stays conservative in three known ways, each of which can only refuse a program the kernel would load, because the rewriter does not know the target kernel and keeps to what holds from 6.1 on. A function with an unsupported R10 alias is charged the audited bound rather than what the copy reaches. An async callback (`bpf_timer_set_callback`, `bpf_wq_set_callback_impl`, `bpf_task_work_schedule_*`) is walked under the chain that registers it: the kernel marks a callback `is_async_cb` only when `do_check` analyzes the registering call, and `check_max_stack_depth` (which runs before dead code is removed) walks a reference to an unmarked callback as a plain call, so a registration behind a branch the verifier proves dead by value keeps its callback in the chain; the instruction shape cannot tell such a registration from a live one, whose callback 6.6 and later check as a root of its own. The frame count never restarts, although 7.1 restarts it at a global function (`check_max_stack_depth_subprog`: `frame = bpf_subprog_is_global(env, idx) ? 0 : frame + 1`) where 6.1 through 7.0 count every frame, so a chain over eight frames through a global function loads only on 7.1 and later.
With `TailCalls` and no tail call in the program, the transform is refused.

Every hook is a bpf-to-bpf call, and the verifier only allows bpf-to-bpf calls in a program that also uses `bpf_tail_call` when the program is JIT-compiled on an architecture that supports it (x86-64, arm64, s390, and loongarch; see `check_map_func_compatibility` in `kernel/bpf/verifier.c`).
On such a program, any hook (lookup, entry, or tail-call) therefore makes it fail to load with "mixing of tail_calls and bpf-to-bpf calls is not supported" when the JIT is disabled or on other architectures.
A tail call whose index register holds a pointer, which privileged loaders may pass, is also rejected after `TailCalls`, because the inserted `w3 = w3` is a partial copy of a pointer.

Either flag may be combined with a lookup selector or `Auto`, or used alone with an empty `Site`.
The hook names are `HookName` with the suffix appended, and `Auto` lookup hooks avoid them.
`LookupResult.Hooks` lists lookup hooks first, then the entry hook, then the tail-call hook; `LookupHook.Kind` tells them apart.
`Site` is the zero value and `Sites` is empty when no lookup is instrumented.

### One dispatch hook

With `LookupRequest.Dispatch`, every instrumented site calls one hook named `HookName`, with the generic hook's signature:

```c
int HOOK(struct xdp_md *ctx, u64 info, const void *key, const void *value, const void *map);
```

| Caller | `info` | `key` | `value` | `map` |
|---|---|---|---|---|
| Lookup hit | `SitePC` | the key | the result | R1 at the lookup |
| Lookup miss (`Lookups` miss or any) | `SitePC` | the key | NULL | R1 at the lookup |
| Update (`Updates`) | `SitePC`, op, flags and result | the key | the value | R1 at the update |
| Delete (`Deletes`) | `SitePC`, op and result | the key | NULL | R1 at the delete |
| Entry (`Entry`) | `DispatchEntrySite` (`0xffffffff`) | NULL | NULL | NULL |
| Failed tail call (`TailCalls`) | `SitePC` | a pointer to the spilled index register (a `u64` whose low 32 bits the helper used) | NULL | the prog array |

[Updates and deletes](#updates-and-deletes) gives the layout of `info`.

One observer attach then sees every site of the program, which saves trampolines and observer programs, and is the only way to see more than one site per run on kernels that allow one tracing attach to a program that tail-calls (7.0 to 7.2.5; see `internal/program/tailcall_guard.go`).
The pointers are tagged `arg:untrusted` as in the generic hook, so the observer reads them with `bpf_probe_read_kernel`; with `StaticUntrusted` the hook is static and empty, and the observer reads every argument as a `u64`.
The tail-call index is the full register the program passed; the helper used its low 32 bits, and the upper half is whatever the program left there.
`LookupResult.Hooks` keeps its grouping: one element per map and op (and one per op for runtime-resolved maps, marked `Generic`), then the entry and the tail-call element, all with `Dispatch` set and the same `Name`.
`Kind`, `MapName` and `Sites`, whose key and value type names come from BTF, map each `site` the observer sees to its kind and types.
No suffix is appended to `HookName`.
Every lookup, delete and tail-call site uses the fourth spill slot in a frame that also calls the hook, so the stack bound must be at least `-448` (`LookupStackReserve` reports 32 bytes; see [Supported sites and trust boundary](#supported-sites-and-trust-boundary)), and an update site also the fifth (`-440`, 40 bytes), and a tail call in the entry function deepens that frame to the slot, which the call-chain check above counts; the entry call alone uses only the ctx slot.
Under `Auto`, a dispatch request whose lookups break a call-chain limit loses all of its lookup sites at once and keeps the entry and tail-call calls, as in [Automatic selection](#automatic-selection); a tail call still fills the map slot in its own frame, so a request whose tail calls alone break the limit is refused.
`Dispatch` refuses `CopyReadOnly`, since it passes no typed value.

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
Original non-DECL_TAG type IDs are preserved; each original DECL_TAG ID holds a separate unsigned-byte placeholder, and the declaration tags are regenerated after the original types.
The hook's types and any external map types are appended.
Attribute tags (`DECL_TAG` or `TYPE_TAG` with `kind_flag=1`) are unsupported: ebpf-go v0.22.0 loses that flag during decoding, before this API receives the `*btf.Spec`.
Callers must exclude those inputs before decoding; this API cannot detect or preserve the lost flag.
`HookTypeID` identifies the generated `int hook(ctx, const KEY *, const VALUE *)` function, and `HookFuncInfo` contains its 8-byte function-info row.
With several hooks, `HookTypeID`, `HookFuncInfo` and `HookName` describe the first element of `Hooks`.
The returned `FuncInfo` and `LineInfo` buffers include the hook and relocated original rows.
The BTF string table is rebuilt, so these buffers must accompany the returned blob.
A future syscall front end can load `BTFBytes` with `BPF_BTF_LOAD`, set `prog_btf_fd` to that result, and supply these metadata buffers.
`Instructions.Marshal` resolves generated symbolic hook calls; marshal a copy to retain the unresolved checksum representation.
Raw checksums also include the supplied fd immediates and already-resolved numeric function references.
This API performs no syscalls, BTF/program loads, interception, attachment or pinning.

## Supported sites and trust boundary

One transform call instruments the selected sites in the program's entry function with their hooks.
It saves ctx once, shares three spill slots across the sites, and inserts the generated hooks immediately after the entry function.
The sites execute sequentially, including on different paths or repeated loop iterations; they do not require nested spill storage.
Discovery includes called subprograms and callbacks, but injection there is refused because their R10 refers to a different stack frame from the saved entry context.
The API does not compose transformations on an already transformed spec.
Only the selected program changes, including when other programs share a linked subprogram or a map.

Supported maps are hash, array, per-CPU hash/array, LRU hash/per-CPU hash, and LPM trie maps.
An LPM trie hook receives the query key, not the matched prefix.
The verifier checks a global function's memory arguments for writes as well as reads, even through `const` pointers.
A value of a map created with `BPF_F_RDONLY_PROG` fails the write check, and one with `BPF_F_WRONLY_PROG` the read check, so the hook for such a map takes `const void *key` and `const void *value` tagged `arg:untrusted` instead, and `LookupHook.Untrusted` is set.
The verifier does not check an untrusted argument at the call and reads it in the hook with fault-handled loads.
The hook body reads through these pointers without comparing them with zero: an untrusted pointer is not nullable, and a pointer comparison would be rejected for loaders without `CAP_PERFMON`.
An observer reads these arguments by the map's key and value sizes; the hook's BTF no longer carries their types.
Kernels without the `arg:untrusted` tag reject the transformed program.
In the CI kernel matrix, 6.15 and older reject it and 6.18 and newer load it.
With `LookupRequest.CopyReadOnly`, a `BPF_F_RDONLY_PROG` map keeps a typed hook instead, and `LookupHook.Copied` is set.
On a hit, each site of such a map copies the value onto the stack below the spill slots, widest aligned loads first, and passes a pointer to the copy.
The copy is readable and writable stack memory, so the call passes the verifier on kernels without `arg:untrusted`.
The observer then reads the value's type from the hook's BTF, but the pointer is the copy's address, not the map value's.
The copy takes the value size rounded up to 8 bytes; a copy that would take the frame past 480 bytes is refused (see below).
A `BPF_F_WRONLY_PROG` map and the generic hook stay untrusted, since a program cannot read such a value to copy it.
With `LookupRequest.StaticUntrusted`, every hook that would take `arg:untrusted` pointers, the generic hook included, is instead a static function whose body only returns zero, and `LookupHook.Static` is set instead of `Untrusted`.
The verifier checks a static function at each call with the caller's registers rather than against its BTF, so the call needs no tag; in the CI kernel matrix, 6.1 and newer load it.
A per-map static hook still declares its key and value types in BTF, but the kernel need not trust that BTF.
On 7.0 it does not: an fentry observer receives every argument, `ctx` included, as a `u64` and reads through them with `bpf_probe_read_kernel`.
With `CopyReadOnly` as well, a `BPF_F_RDONLY_PROG` map keeps its copied typed hook, and only write-only maps and the generic hook become static.
A value that holds a field programs reach only through helpers and kfuncs cannot be passed as memory either: the verifier refuses a `bpf_spin_lock` or `bpf_timer` in it ("cannot be accessed directly by load/store") and a kptr ("cannot be accessed indirectly by helper").
The transform finds these fields in the value's BTF, through nested structs, unions, arrays and typedefs: `struct bpf_spin_lock`, `bpf_res_spin_lock`, `bpf_timer`, `bpf_wq`, `bpf_task_work`, `bpf_list_head`, `bpf_list_node`, `bpf_rb_root`, `bpf_rb_node` and `bpf_refcount`, and pointers tagged `kptr`, `kptr_untrusted`, `kptr_ref`, `percpu_kptr` or `uptr`.
A lookup hook on such a map takes untrusted pointers, or is static with `StaticUntrusted`, as for a write-only map, and `CopyReadOnly` never copies such a value, since the copy would read the field.
The miss, update and delete hooks stay typed, since their key and value are the program's memory, unless they point into a read-only map's value (below).
6.1 does not know the `kptr_untrusted` tag and takes such a field for a plain pointer, which a typed hook would accept; the transform does not depend on the kernel and treats it as a kptr.
A key or value that points into a `BPF_F_RDONLY_PROG` map's value, such as a `.rodata` constant, fails a typed hook's memory check too ("write into map forbidden").
Discovery follows such pointers through the entry function on every path: a map-value load (including `.kconfig`) or a lookup of a `BPF_F_RDONLY_PROG` map, a read-only inner-map template, 64-bit moves, adding or subtracting (a pointer added to a scalar included), 8-byte pointer spills to a known stack offset and their reloads, including atomic load-acquire and store-release, and the paths that join at a branch target.
inject-run cannot read an inner-map template's flags from the kernel, so it counts every inner map as read-only.
A store through a stack pointer whose offset it does not follow marks every slot. A subprogram passed a read-only value or map, or a stack pointer that can reach one, may return the value or write it through another stack-pointer argument; so may the callback of `bpf_loop`, `bpf_for_each_map_elem`, `bpf_timer_set_callback`, `bpf_find_vma` and `bpf_user_ringbuf_drain`, and a kfunc. A kfunc result may be such a pointer too.
A pointer the verifier sees as a scalar, such as one loaded from map memory or cut to 32 bits, does not count.
At a site whose key or value may be such a pointer, all the hooks of that site's map and op take untrusted pointers, or are static with `StaticUntrusted`, and a lookup's value is not copied.
A key or value with BTF must have a nonzero size exactly matching the map's key or value size.
The hook retains these types, including typedefs and qualifiers, under `const` pointer parameters.
A side the map declares only by size, such as `__uint(key_size, 4)`, has no BTF; the hook takes it as an anonymous `struct { u8 bytes[N]; }` of the map's size.
Types named `struct xdp_md`, `struct __sk_buff` or `struct bpf_dynptr` are refused as map key/value types because the verifier assigns those pointer types special argument semantics.
Other map kinds are refused by a typed hook rather than assuming their helper return is ordinary value memory; `Auto` observes XSK maps, devmaps, devmap hashes, sockmaps and sockhashes through the generic hook and skips the rest.
The entry function must have one BTF parameter pointing to `struct xdp_md` (XDP) or `struct __sk_buff` (tc).
The package checks the program type; the cooperative loader owns attachment mode and verifier acceptance.
The generated hooks read the context's first word (`len` for `__sk_buff`) and call no helper that changes packet data.

| Transformer validates | Caller must certify |
|---|---|
| The input ELF matches `ELFSHA256` before parsing. | The hash identifies the audited build. |
| The selector resolves supported lookups of the same map in the entry function. | These are the intended observation sites. |
| Map BTF sizes, where present, match the map definition, and entry BTF describes the program type's context pointer. | The BTF describes the audited build. |
| Direct R10 references stay at or above `Stack.LowestOffset`; three aligned spill slots (four with the generic hook, at a typed update, or, at lookup, delete and tail-call sites, `Dispatch`; five at a generic or dispatch update; plus a value copy with `CopyReadOnly`) fit below it within 512 bytes, and within 480 in a frame that calls a lookup hook. The call chains of the transformed program stay within the verifier's stack and frame limits wherever the original's do. | Pointer aliases and called subprograms do not reach the reserved spill region. |
| Existing function and source metadata are complete, references resolve, and relocation fits. | The transformed program remains acceptable to the target kernel verifier. |

The stack audit has the same alias and callee limitations as `StackAudit` in the original transform.
The audited bound is rounded down to an 8-byte boundary before allocating the slots.
A lookup site's frame also calls its hook, which kernels that round frames to 32 bytes count as 32 bytes of the 512-byte combined stack, so a site needs `-456` for three slots and `-448` for four; `Auto` skips a site past that, and explicit selection refuses it.
`CheckLookupStack`, which inject-run's configuration check also calls, requires `-456` when the request may hold a lookup site (`Site` or `Auto`).
Without one, the entry hook's frame holds only the 8-byte ctx slot and a tail-call site's frame the ctx and index slots, so `Entry` alone needs `-472` and `TailCalls` (with or without `Entry`) `-464`.
With `Dispatch`, a lookup or tail-call site also fills the map slot, so such a request needs `-448`; `Entry` alone still needs `-472`.
`Updates` needs `-448` for the update's value slot, and `-440` with `Dispatch`.
The transform checks direct R10 references throughout the flattened selected program.
The call-chain check tracks R10 aliases separately in each function, within basic blocks.
It follows 64-bit register copies and immediate addition/subtraction, counting both formed pointer offsets and memory accesses through them.
For `bpf_map_lookup_elem`, `bpf_map_delete_elem`, `bpf_map_update_elem`, and `bpf_xdp_load_bytes`, a stack argument in the documented buffer position accesses memory from that pointer forward, so the pointer offset also bounds its deepest access.
Calls clear R0–R5 and preserve R6–R9 in this analysis.

An alias that crosses a branch or jump target, is stored (including a stack spill), is returned, uses unsupported arithmetic, or is passed to another helper, a BPF subprogram, or a kfunc restores the shared audited bound for the entire frame.
A callee can subtract from a passed pointer and deepen the caller's frame; such escapes therefore need the audit even when the pointer's initial offset is known.
This restricted analysis needs no merging of register values across paths: every supported alias is defined and consumed within one basic block, and every memory access through it has a known offset.
Direct references in every block still count, including code the verifier may prove dead.
The shared audit remains required for spill placement and all unsupported aliases.
A transformed frame that reaches below the audit is always counted as changed, even when an unused pointer formation makes its estimated depth equal before and after injection.

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
A generic-hook site also saves R1 into `map_slot` before the helper and loads it into R5, two more instructions.

With `Entry`, the entry ctx spill is followed by `call HOOK_entry` and `r1 = *(u64 *)(r10 + ctx_slot)`.
Only R1 and R10 are initialized at program entry, so the call clobbers nothing the program can read.
Each `bpf_tail_call` with `TailCalls` becomes:

```text
*(u64 *)(r10 + key_slot) = r3        ; the index
*(u64 *)(r10 + ctx_slot) = r1        ; outside the entry function only
call bpf_tail_call                   ; original instruction
r1 = *(u64 *)(r10 + ctx_slot)
w2 = SitePC
r3 = *(u64 *)(r10 + key_slot)
w3 = w3
call HOOK_tail_call
```

The key slot is free here because no lookup is in progress.

Each `bpf_map_update_elem` with `Updates` becomes, for a typed hook:

```text
*(u64 *)(r10 + key_slot) = r2
*(u64 *)(r10 + result_slot) = r4     ; the flags
*(u64 *)(r10 + map_slot) = r3        ; the value
call bpf_map_update_elem             ; original instruction
r5 = *(u64 *)(r10 + result_slot)     ; the flags
*(u64 *)(r10 + result_slot) = r0
if w0 s>= 0 goto restore             ; CallError only
r5 <<= 32
w2 = w0
r5 |= r2                             ; status
r1 = *(u64 *)(r10 + ctx_slot)
w2 = SitePC
r3 = *(u64 *)(r10 + key_slot)
r4 = *(u64 *)(r10 + map_slot)
call PREFIX_MAP_update
restore:
r0 = *(u64 *)(r10 + result_slot)
```

The guard tests W0, not R0: on 6.1 the kernel replaces the helper call with a call to the map's own operation, which returns `int`, so a failed update leaves R0 as, say, `0xffffffef` and a 64-bit `r0 s>= 0` would take it for success.
A program that checks the result the same way misses the error too; on 6.6 and later the operation returns `long`.

A delete saves only the key, and its status is `w4 = w0`.
A generic or dispatch site also saves R1 into `map_slot`, keeps an update's value in the fifth slot, builds `info` in R2 with shifts and ORs (R3 as scratch), and passes the value (NULL for a delete) in R4 and the map in R5.
R0 is not saved: the verifier treats R0 as unreadable after `bpf_tail_call`.

With `Dispatch`, every lookup site is set up as a generic-hook site.
A tail call also saves R2 into `map_slot` before the helper, and after it passes `r3 = r10 + key_slot`, `r4 = 0` and `r5 = map_slot` instead of loading the index; there is no `w3 = w3`.
The entry call is preceded by `w2 = -1` and zeroing R3 to R5, since the hook reads every argument register.

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
Its existing `Site` field is the first element of `Sites`, and `Result.HookName` is the name of the first element of `Hooks`; with `Auto`, `Entry`, `TailCalls` or `Dispatch` use `Sites` and `Hooks` instead.
`InsertedAt` is zero because the first insertion saves ctx at entry.
`InsertedSlots` is `8 + 8*len(Sites)`: one entry spill, eight instructions per site, and seven hook instructions.
One site adds 16 slots (128 bytes); two sites add 24 slots (192 bytes).
In general it is the sum of:

- 1 for the entry ctx spill;
- per site, 8 slots for a selected site, 9 for a typed-hook site under `Auto` (the `site` argument), or 11 for a generic-hook site;
- per site with a `CopyReadOnly` value copy, 2 slots per load-store pair (widest aligned first, so 4 for a 16-byte value) and 2 for the copy's address;
- per lookup hook, 7 slots for a typed hook, 5 for an `Untrusted` one, 6 for the generic hook, and 2 for a `Static` one;
- with `Entry`, 2 slots in the prologue and a 3-slot hook;
- with `TailCalls`, 6 slots per tail call (7 outside the entry function) and a 3-slot hook.

With `Dispatch`, it is 1, plus 11 slots per lookup site, 6 in the prologue with `Entry`, 9 per tail call (10 outside the entry function), and the one 6-slot hook (2 slots when static).
The hooks are placed together right after the entry function.
`TestLookupInsertedSlots` pins these counts, the dispatch ones included.
`SourceChecksum` and `TransformedChecksum` cover the raw instruction encoding, with symbolic calls and callback loads unresolved.
They exclude BTF, source lines, CO-RE metadata, and symbolic/map references; they do not identify the fully loaded kernel artifact.
The ELF SHA-256 binds the full input.

## What is not covered

The transform observes lookups (`bpf_map_lookup_percpu_elem` included), updates, deletes, pushes, pops and peeks in the entry function and failed tail calls, and nothing else.
It does not observe other map helpers (`bpf_for_each_map_elem`, `bpf_ringbuf_*`, `bpf_sk_storage_get` and the like), LRU eviction, non-map lookups such as `bpf_fib_lookup`, or lookups inside `bpf_for_each_map_elem` callbacks.
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
`TestBpfLookupInjectionAutoMaps` limits the same program to one map with `Maps` and checks that only that map's hook is generated and fires, while the other lookup runs unchanged.
`TestBpfLookupMiss` and `TestBpfLookupAny` attach one observer to each typed hook of a map and check that the hit hook sees only the present key, with its value, and the miss hook only the absent one; `TestBpfLookupMissReadOnlyMap` loads the miss hook of a `BPF_F_RDONLY_PROG` map without `arg:untrusted`.
`TestBpfDispatchMiss`, `...Any`, `...AnyStatic`, `...AnyTC` and `...MissTCStatic` repeat `TestBpfDispatch` with `Lookups`, and check that a miss reaches the dispatch hook with the key, a NULL value and the map.
`TestBpfMapCallsTyped`, `...TypedAny` and `...TypedTC` run updates and deletes on a two-entry hash (`EEXIST` for `BPF_NOEXIST` on a present key, `ENOENT` for `BPF_EXIST` on an absent one, `E2BIG` when full, `ENOENT` for deleting an absent key) and check that the typed update and delete hooks see exactly the failed calls, or every call with `CallAny`, with the site, key, value and status, while the program, which returns its result, behaves as before.
`TestBpfMapCallsDispatch`, `...Static` and `...TCStatic` do the same through one dispatch hook at the lowest bound an update allows (`-440`) and check its `info` words; `TestBpfMapCallsArrayWriteOnly` loads the typed hooks on a `BPF_F_WRONLY_PROG` array and checks its `E2BIG`, `EEXIST` and `EINVAL` statuses; `TestBpfMapCallsInnerUpdate[Static]` sends an update of the inner map of an array of maps to `PREFIX_any_update`.
`TestBpfSpecialFieldsLookup[Static]` looks up values with a `bpf_spin_lock`, a `bpf_timer` and a kptr through the untrusted or static hook and checks the key, value and site its observer sees; `TestBpfSpecialFieldsUpdate` keeps the typed update and delete hooks for the spin lock and kptr values and checks each call's key, value and status.
`TestBpfSockHashUpdateTC[Static]` updates a sockhash from tc with the socket `BPF_PROG_TEST_RUN` gives the skb, which no socket map accepts, then deletes from the empty map, and checks that the generic update and delete hooks see each failure's `info`, the key, the socket (NULL for the delete) and the map, while the program's result does not change.
`TestBpfQueueOps`, `TestBpfStackOps` and `TestBpfQueueOpsTC` fill a two-entry queue or stack (`E2BIG` when full, `BPF_EXIST` dropping the oldest element), then pop and peek until both fail with `ENOENT`, and check that the push, pop and peek hooks see each call's site, value and status while the program's result does not change; `TestBpfBloomFilterOps` peeks a bloom filter before and after a push and checks that the push hook sees the push and the error-only peek hook only the misses; `TestBpfBloomPeekPoisoned` checks that 7.0 and older load the plain bloom filter fixture when its peeks are not preceded by a read of the value, and that 7.1 and newer either load it, when the kernel has the verifier fix, or reject it with "slot poisoned by dead code elimination"; `TestBpfBloomPeekInjected` checks that bloom filter programs which peek without that read, in shapes 7.1 to 7.3 load, still load with typed and static dispatch peek hooks; `TestBpfQueueOpsDispatch[Static]` checks the `info` words, with a push's `BPF_EXIST` in bits 36-43, the NULL key and the value at the dispatch hook; `TestBpfQueueOpsInner[Static]` sends a push and pop on the inner queue of an array of maps to `PREFIX_any_push` and `PREFIX_any_pop`; `TestBpfQueuePopUninit` and `...Dispatch` pop into stack the program never wrote, and check that the hook sees the element and then the zeroes of an empty queue; `TestBpfReadOnlyArg[Static]` pushes and updates with a constant from a `BPF_F_RDONLY_PROG` array through untrusted or static hooks, `TestBpfReadOnlyArgShapes[Static]` covers registers, branches, loops and stack-offset joins, and `TestBpfReadOnlyArgCalls[Static]` covers pointer spills, subprogram arguments and writes, a read-only inner map and a nonzero map-value offset; `TestReadOnlyKconfigThroughELF` covers a libbpf-style `.kconfig` extern; `TestBpfCopyReadOnlyKey` looks up a read-only map too large to copy with a read-only key, whose static hook copies nothing; `TestBpfLookupPercpu` looks up a per-CPU array on the first and last CPU and past the last, where the CPUs hold different actions, and checks that the hit hook sees the named CPU's value and the miss hook the CPU past the last; it needs two possible CPUs.
`TestBpfLookupInjectionReadOnlyMap`, `...Copy` and `...Static` cover the untrusted, copied and static hook forms for a `BPF_F_RDONLY_PROG` map; `TestBpfLookupInjectionMapInMap[Static]` and `TestBpfLookupInjectionGenericKinds[Static]` cover the generic hook over a map-in-map and over direct XSK and devmap lookups.
`TestBpfTailCallHooks` tail-calls from an instrumented caller into a target instrumented with `Entry`.
On a successful tail call, the entry hook fires and an fentry on the target program itself does not; on a failed one, the tail-call hook reports the site and index.
A direct run of the target fires both.
`TestBpfTailCallInSubprogram` fails a tail call inside a static subprogram and checks the hook gets that subprogram's ctx; `TestBpfTailCallStackLimit` and `TestBpfTailCallDepthSumsCallers` check the transform refuses one slot past the 256-byte caller-depth limit (for a deep entry frame, a stack-using middle frame, and the entry's own tail-call spill) while the original still loads, and that one slot under it transforms and loads.
`TestBpfStackLimitsAcrossCalls` does the same for a chain through a `bpf_loop` callback into a static or global tail-calling subprogram, for the 512-byte combined stack (a tail-calling entry that calls a 248-byte subprogram, and a lookup site's frame plus its hook, with and without `Dispatch`), and for the 8-frame limit (a hook called from the 8th frame), and for a callee that reaches 256 bytes only through a copy of R10.
`TestBpfStackBoundShallowLeaf` loads and compares a 240-byte entry with an 8-byte leaf that copies R10, using typed and static dispatch update hooks.
`TestBpfStackBoundDeepLeafRefused` loads the original with a 248-byte leaf, checks the transform refuses its added spills, and independently checks that the kernel rejects the deeper chain.
`TestBpfStackLimitsOverestimatedOriginal` loads a program whose callee has a store the verifier never reaches, so its instructions add up past 512 bytes while the kernel counts 512, and checks the transform refuses the `Entry` spill that really pushes the chain past the limit.
`TestBpfStackLimitsTimerCallback` loads a program whose entry registers a `bpf_timer` callback behind a branch the verifier proves dead, at 448 + 32 + 32 bytes with the callback and its callee unverified, checks the transform refuses the `Entry` spill that makes the chain 544 (which 6.1 and 6.6 reject; JITs that round to 16 count the dead frames at 0), and that a live registration is refused the same way.
`TestBpfStackLimitsReserve` transforms and loads an `Entry`-only request at `-472` and `TailCalls` requests at `-464`, and the same with a static `Dispatch` hook, whose tail calls need `-448`.
`TestBpfStackLimitsAutoRetry` loads what `Auto` keeps when the lookup slots alone would push a tail-calling subprogram's callers to 256 bytes: the tail-call hook without the lookup at `-208`, also as a static `Dispatch` hook, and the typed hook without the copied read-only map's at `-200`.
`TestBpfEntryHookWithLookup` combines `Entry` with a lookup hook in one program and observes both.
`TestBpfDispatch[Static]` attaches one observer to the dispatch hook and checks the entry, lookup and failed tail-call calls in order, with the map id and value bytes each passes; `TestBpfDispatchStackLimit` checks the transform refuses a dispatch tail call in the entry function one slot past the caller-depth limit and loads one slot under it.
`TestBpfDispatchTC[Static]` repeats `TestBpfDispatch[Static]` on a `SchedCLS` program with an `__sk_buff` context; `TestBpfLookupHooksTC` instruments the same `SchedCLS` program with per-map typed lookup, entry and tail-call hooks, and an fentry on each checks the key, value, `site`, tail-call index and the `sk_buff` length it sees; `TestLookupTC` (unprivileged) checks that every hook kind takes `__sk_buff` in a tc program, in the ELF and raw forms.
`TestBpfLookupInjectionCallback` checks symbolic and numeric callback loads with an unreached subprogram preceding the `bpf_loop` callback and a stack counter incremented three times by `bpf_loop`; the program returns `XDP_ABORTED` unless those increments occur.
It repeats the plain/injected comparison and fentry observations (including direct `ctx` pointer dereferencing) for both callback forms.
`TestBpfMapCallEquivalence` generates XDP programs and compares the plain and rewritten return value, output packet and final map contents under seven request configurations.
Its default 14 seeds cover entry-function operations, read-only pointers crossing stack spills and static or global subprogram calls, hash, queue and read-only array inner maps, and precise or conservative R10 aliases in lookup and XDP byte-load leaves.
`BPF_NINJA_EQUIV=1` defaults to seeds 1 through 14.
`BPF_NINJA_EQUIV_SEED` and `BPF_NINJA_EQUIV_SEEDS` select longer contiguous ranges.
Only seeds congruent to 1 modulo 14 randomize the entry program; the others repeat fixed feature shapes with new packet bytes.
These tests exercise the transform core and fentry using `BPF_PROG_TEST_RUN`, without an interface attachment or pinning.

```sh
go build ./...
go vet ./...
go test -count=1 ./pkg/inject/...
sudo -E env PATH=$PATH go test -count=1 -run 'TestBpfLookupInjection|TestBpfLookupMiss|TestBpfLookupAny|TestBpfMapCalls|TestBpfTailCall|TestBpfEntryHook|TestBpfStackLimits|TestBpfDispatch|TestBpfSpecialFields|TestBpfSockHash|TestBpfQueue|TestBpfStackOps|TestBpfBloom|TestBpfLookupPercpu' ./pkg/inject/
```

All 77 privileged `TestBpf` tests of this package, including the lookup, miss, update, delete, push, pop, peek, special-field, socket-map, entry, tail-call, stack-limit, dispatch and generated equivalence tests, pass across the CI kernel matrix (6.1 to 7.3-rc4) that `make test-bpf` runs, where the tests whose hooks need `arg:untrusted` skip on 6.1-6.15, the callback stack-limit subtests skip on 7.3, which forbids tail calls in callbacks, and the sockhash update tests skip on 7.3, which no longer lets tc update a socket map (see scripts/test/privileged.py).
This is finite test evidence for the fixture, not a general program-equivalence, concurrency, or kernel-version guarantee.

## Supplying missing live map types

The raw transform uses `RawMap.Key` and `RawMap.Value` as supplied by its caller.
For a loader that creates a map without BTF, `inject-run` can populate these from a hash-pinned ELF before calling the transform; see [map types from a loader ELF](inject-run.md#map-types-from-a-loader-elf).
The supervisor refuses supplementation when the live map already has BTF.
This changes hook metadata only and preserves the transform's existing map-kind, pointer-trust and stack restrictions.
