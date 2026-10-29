# Run an unmodified loader with lookup injection

`inject-run` is a Linux x86-64 prototype that rewrites selected BPF programs as a launched process loads them.
It reaches direct Go syscalls as well as C loaders, without changing the target's binary, source, or object files.
The name makes the bytecode transformation explicit and distinguishes it from the existing packet-observation command.

The implementation works end to end for the tested Go loader: the target receives a real fd for the transformed program, the kernel reports the generated hook in `func_info`, and `BPF_PROG_TEST_RUN` executes the program successfully.
There is no stub for fd transfer or memory growth.
This does not establish support for arbitrary Cilium, eUPF, or Ella deployments.
[inject-walkthrough.md](inject-walkthrough.md) follows one program from `--list-maps` through a rule and `inject-run` to an fentry observer.

## Usage and configuration

```sh
bpf-ninja inject-run --config rules.json -- ./loader --its-own-flags
```

`rules.json` is a JSON array:

```json
[
  {
    "program": "xdp_ingress",
    "map": "sessions",
    "func": "xdp_ingress",
    "line": 42,
    "hook": "lookup_hook",
    "stack_lowest_offset": -128
  }
]
```

Alternatively, `BPF_NINJA_INJECT_CONFIG` can contain the JSON itself.
`--config` takes precedence over the environment.
With `--lookups-json`, the rules may be left out entirely to only list what the target loads.
Flags before `--` belong to the supervisor; the command and arguments after it belong to the target.
Standard streams are inherited, diagnostics go to stderr, and the launcher returns the target's exit status (128 plus signal number for a signal termination).
Run with the privileges required for ptrace, the target's BPF operations, and opening BTF objects by ID in the supervisor; root is the tested setup.

`program` matches either the exact kernel program name or the entry function name from `func_info[0]` and remembered program BTF.
Kernel names are limited to 15 visible characters; function names allow a longer selector.
`map` is the exact kernel map name.
`func` and `line` are optional lookup-site filters.
One rule per program is supported.
By default a rule must match exactly one lookup; ambiguity is a refusal.
A lookup that inlining copies to several places shares one source line, so `"all_matches": true` instruments every matching site with the same hook, and `"site_pcs": [293, 1942]` instead names raw instruction indexes, each of which must also match the other filters.
The two are mutually exclusive, and duplicate or missing PCs are refused.
The transformation core currently accepts lookup sites in the entry function and applies its existing map, control-flow, reference, and stack restrictions.

`"auto": true` instruments every supported lookup in the program instead of one selected lookup.
`map`, `func`, `line`, `all_matches`, and `site_pcs` must then be absent, and `hook` is a prefix: each map gets its own hook named `HOOK_MAP`, with a `u32 site` argument after `ctx` that carries the lookup's raw instruction index.
Lookups whose map is only known at run time (map-in-map, or a map pointer that reaches R1 indirectly), and lookups on XSK maps, devmaps, devmap hashes, sockmaps and sockhashes, which have no typed hook, share one `HOOK_any` hook that also takes the map pointer.
Lookups that the transform cannot support are skipped and listed in the diagnostic rather than refusing the load: lookups on other map kinds without a typed hook, lookups whose hook name would pass 127 bytes or whose slots do not fit the audited stack and, when the instrumented program would break a kernel call-chain stack limit, first the `HOOK_any` and `copy_read_only` lookups and then every lookup (with `dispatch`, every lookup at once, since each passes its map).
`entry` and `tail_calls` hooks are kept; a rule that would instrument nothing at all is refused.
The naming and hook ABI are described in [lookup-site-injection.md](lookup-site-injection.md#automatic-selection).
`"maps": ["lb4_services_v2", "lb4_backends_v3"]` limits `auto` to lookups on those maps (exact kernel names); the others are skipped with `map not selected by Maps` and run unchanged.
A name that matches no lookup refuses the rule, and `maps` without `auto` is a configuration error.
[Lookups as JSON](#lookups-as-json) lists the names to choose from.
`"ops": ["lookup:miss"]` calls the lookup hooks when the lookup finds nothing instead of when it finds an entry, and `"lookup:any"` on both; `"lookup"` or `"lookup:hit"` is the default.
A typed hook then gets a second hook, `HOOK_MAP_miss(ctx, u32 site, key)`, since its value cannot be NULL; the `HOOK_any` and dispatch hooks are called with a NULL value ([lookup-site-injection.md](lookup-site-injection.md#misses)).
`"update"` and `"delete"` (or `"update:error"`, `"delete:error"`) call `HOOK_MAP_update(ctx, u32 site, key, value, u64 status)` and `HOOK_MAP_delete(ctx, u32 site, key, u64 status)` when the helper fails, and `"update:any"` and `"delete:any"` after every call; `status` is the helper's result in the low 32 bits and the update's flags above them ([lookup-site-injection.md](lookup-site-injection.md#updates-and-deletes)).
An update or delete on a map known only at run time, or on a sockmap or sockhash, whose update passes a socket rather than memory, calls `HOOK_any_update` or `HOOK_any_delete` with the generic hook's arguments instead.
`"push"`, `"pop"` and `"peek"` (each also with `:error` or `:any`) do the same for the queue, stack and bloom-filter helpers, calling `HOOK_MAP_push`, `HOOK_MAP_pop` or `HOOK_MAP_peek` with `(ctx, u32 site, value, u64 status)`; a pop or peek hook sees the value the helper wrote ([lookup-site-injection.md](lookup-site-injection.md#pushes-pops-and-peeks)).
On a map known only at run time they call `HOOK_any_push`, `HOOK_any_pop` or `HOOK_any_peek` with the generic hook's arguments and a NULL key.
A `bpf_map_lookup_percpu_elem` call is a lookup and takes the `lookup` op.
With `ops`, a rule observes only the ops it lists, so `"ops": ["update"]` leaves the lookups alone.
`ops` needs `map` or `auto`, and `update`, `delete`, `push`, `pop` and `peek` need `auto`.

`"entry": true` adds `HOOK_entry(ctx)`, called at the start of the program, which also runs when the program is entered through a tail call.
`"tail_calls": true` adds `HOOK_tail_call(ctx, u32 site, u32 index)`, called when a `bpf_tail_call` anywhere in the program fails.
Either can be combined with a lookup rule, or used without `map` or `auto` to instrument no lookup.
`"copy_read_only": true` passes a stack copy of a `BPF_F_RDONLY_PROG` map's value to a typed hook instead of an `arg:untrusted` one, so kernels that reject `arg:untrusted` (6.15 and older in the CI matrix) load it; see [lookup-site-injection.md](lookup-site-injection.md#supported-sites-and-trust-boundary).
`"dispatch": true` sends every instrumented site, lookups, the entry and failed tail calls, to one hook named `hook` with the generic signature, so one observer attach sees them all; it needs `stack_lowest_offset` of at least -448 (with only `entry`, -472 as without `dispatch`) and cannot be combined with `copy_read_only` ([lookup-site-injection.md](lookup-site-injection.md#one-dispatch-hook)).
`"static_untrusted": true` makes every hook that would take `arg:untrusted` pointers, the generic hook included, a static function instead, which those kernels also load; an observer then reads all of its arguments as `u64` values (same section).
See [lookup-site-injection.md](lookup-site-injection.md#entry-and-tail-call-hooks), including why any hook in a program that uses `bpf_tail_call` needs the JIT on a supported architecture; without it the transformed load fails and the original program is loaded (or refused with `--fail-closed`).

```json
[{"program": "xdp_ingress", "auto": true, "hook": "obs", "stack_lowest_offset": -128}]
```

`stack_lowest_offset` is mandatory: it is an explicit audit of the deepest stack access, including aliases and callees, not an inferred value.
It must be between -456 and 0 for a rule with `map` or `auto`; a rule with only `tail_calls` (and `entry`) allows -464, and one with only `entry` -472. With `dispatch`, a rule with `map`, `auto` or `tail_calls` needs -448. An `update` op needs -448, and -440 with `dispatch`.
The transform reserves three eight-byte slots below the audited region, aligned downward (one for `entry` alone, two for `tail_calls` without lookups), four with `dispatch` (unless the rule has only `entry`) or when `auto` finds a lookup whose map a typed hook cannot take, plus the value copy with `copy_read_only` (see the transform's refusal message for the exact bound).
The frame holding the slots also calls the hook, which kernels that round frames to 32 bytes count as 32 bytes of the 512-byte stack, so the slots must end 480 bytes below the frame.
Do not copy the example bound without auditing the actual program.
`hook` must be a C identifier of at most 127 bytes, leaving room for the longest suffix the transform appends: at most 117 bytes with `tail_calls` (`_tail_call`), 121 with `entry` (`_entry`), 125 with `auto` (`_0`), 120 with `lookup:miss` (`_0_miss`), and 118 with `update`, `delete`, `push`, `pop` or `peek` (`_0_update`); with `dispatch` the hook is named `hook` itself, so up to 127 bytes. Under `auto`, a map whose hook name would still not fit is skipped.
Unknown JSON fields, duplicate program selectors, trailing JSON, and configurations larger than 1 MiB are rejected before launching.

## Map types from a loader ELF

Some loaders create maps without kernel BTF even though their ELF contains the key and value definitions.
For one explicit `map` rule, `map_types_elf` supplies those definitions to the generated hook:

```json
[
  {
    "program": "ingress",
    "map": "sessions",
    "hook": "observe",
    "stack_lowest_offset": -4,
    "map_types_elf": "/path/to/loader-generated.o",
    "map_types_sha256": "REPLACE_WITH_64_HEXADECIMAL_DIGITS"
  }
]
```

Compute the digest with `sha256sum /path/to/loader-generated.o` and audit the stack bound for the actual program.
The supervisor reads the path in its own filesystem, relative to its working directory, at each matching program load.
The SHA-256 is mandatory and case-insensitive; the same bytes are hashed and parsed.
The feature takes metadata from this ELF; it does not load its instructions or maps, change map contents, or attach BTF to the live map.
The generated program's hook BTF makes members available to `--list-params --members` and `--arg-filter`.

The rule requires a single explicit kernel `map` name of at most 15 bytes and cannot use `auto`.
Exactly one ELF map definition must match that name after truncation to 15 bytes, and exactly one referenced live map must match it.
Map type, key size, value size and flags must agree exactly, and each supplied BTF type must have the corresponding size.
An absent or ambiguous map, an ELF read/parse error, a different byte order, a hash mismatch, or missing, ambiguous or incorrectly sized types refuses the injection.
A live map with any BTF is also refused, including a map whose existing value type is an anonymous byte array; existing types are never replaced.
These errors follow the usual `inject-run` policy: without `--fail-closed` the original program can load unchanged; use `--fail-closed` to require successful injection.

For a legacy map definition that declares sizes instead of types, optional `map_key_type` and `map_value_type` select exact BTF names from the same hashed ELF.
For example, `"map_key_type": "__u32", "map_value_type": "real_definition"` selects a typedef and a struct if those names each occur exactly once.
Only full type names count: a unique `record` is selected even alongside `record___old` and `record___other`, while those flavors alone do not satisfy `record`.
Use `real_definition`, without the C `struct ` prefix.
An omitted side uses the map definition's own type, so a legacy map without either type needs both names.
The feature neither infers layouts from source nor creates types; a name missing from the ELF BTF is an error.
A size match cannot prove that a chosen type describes the map's semantics, byte order of individual members, or a layout changed by loader relocation.
Types of the same size with a different member order cannot be detected by these checks.
The operator must choose an ELF and types that describe the actual map, including any CO-RE or loader adjustments; the digest pins that choice rather than proving it.

After injection, use the program ID in `hooks.json`.
Keep the loader running and run the observer commands in another terminal:

```sh
bpf-ninja inject-run --fail-closed --config rules.json --hooks-json hooks.json -- ./loader
bpf-ninja -p "$PROG_ID" --func observe --list-params --members
bpf-ninja -p "$PROG_ID" --func observe --arg-filter 'value->identity==7' -w selected.pcapng
```

Without type supplementation, a map with no BTF still uses the existing opaque byte-array hook arguments; member predicates for the missing struct fail.
[The CLI integration check](../../scripts/test/map-types.py) exercises both paths with a loader that creates a map without BTF, compares selected packet bytes, and checks the existing-BTF refusal.
[日本語の説明](../ja/inject-map-types.md) covers the same configuration.

## Hooks as JSON

`--hooks-json PATH` writes the injected programs and their hooks to `PATH`, so a tracer can find what to attach to without parsing the diagnostic.
The target owns stdout, so the result goes to a file.
The file is created before the target starts, with an empty `programs` list, and an unwritable path refuses before launching.
After each injected load it is rewritten whole, by writing a temporary file in the same directory and renaming it, and this happens before the target receives the new program fd.
A reader therefore sees a complete document, and every program the target can attach or run is already listed.
Loads that fell back to the original program, or were refused, are not listed; the diagnostic still reports them.
If a rewrite fails, the launcher reports it on stderr, keeps running the target, and exits with an error if the target itself succeeded.

```json
{
  "version": 1,
  "programs": [
    {
      "program": "p",
      "func": "entry_with_long_name",
      "type": "XDP",
      "prog_id": 2,
      "ctx_type": "xdp_md",
      "hooks": [
        {
          "name": "lookup_hook_sessions",
          "kind": "typed",
          "when": "hit",
          "map": "sessions",
          "sites": [{"kind": "lookup", "pc": 6, "map": "sessions", "func": "entry_with_long_name"}],
          "untrusted": false,
          "copied": false,
          "static": false,
          "read_only": false
        },
        {"name": "lookup_hook_entry", "kind": "entry", "sites": [], "untrusted": false, "copied": false, "static": false, "read_only": false}
      ],
      "skipped": []
    }
  ]
}
```

`version` is 1 and changes only when a field changes meaning or is removed; new fields can appear without a version change.
Each entry of `programs` is one injected load, in load order, so a program loaded twice appears twice.
`program` is the kernel program name, `func` the entry function, `type` the program type as cilium/ebpf names it (`XDP`, `SchedCLS`, `SchedACT`), and `prog_id` the kernel ID of the loaded program, which an fentry observer can open with `BPF_PROG_GET_FD_BY_ID`.
`prog_id` is 0 if the launcher could not query it; the diagnostic then says why.
`ctx_type` is the BTF struct the hooks' `ctx` argument points to: `xdp_md` or `__sk_buff`.

Each hook is one function in the loaded program:

- `kind` is `typed` (a hook with the map's key and value types), `generic` (a `HOOK_any` hook that also takes the map pointer), `entry`, `tail_call`, or `dispatch`. The sites of a `typed` or `generic` hook say which map helper it observes.
- `when` is the results that call the hook: `hit`, `miss` (a typed hook's `_miss` hook, which takes no value) or `any` for lookups, and `error` or `any` for updates, deletes, pushes, pops and peeks. A `dispatch` hook's `when` is its lookups'; its other map-call sites carry their own `when`.
- `map` is the map of a `typed` hook. A `generic` or `dispatch` hook serves several maps, so the map is given on each site instead.
- `sites` are the helper calls that call the hook, in instruction order. Each has a `kind` (`lookup`, `update`, `delete`, `push`, `pop`, `peek`, `tail_call`, or `entry`), its raw instruction index `pc` (the `site` argument the hook receives, or the low 32 bits of a generic or dispatch hook's `info`), and, where known, `map`, `func`, `file` and `line`. An `entry` hook has no sites.
- A `dispatch` rule produces one hook with every site: the lookups, the failed tail calls, and the entry call as the site `4294967295` (`inject.DispatchEntrySite`). The entry call comes first, since it runs at program start, and the other sites follow in instruction order across maps and kinds.
- `untrusted`, `copied`, `static` and `read_only` mirror `inject.LookupHook`: the hook takes `arg:untrusted` pointers (a lookup hook on a read-only or write-only map, or on a value holding a `bpf_spin_lock`, `bpf_timer`, kptr or similar field, or any hook whose key or value may point into a read-only map's value), its value is a stack copy, it is a static function (read every argument as a `u64`), and its map is `BPF_F_RDONLY_PROG`.

`skipped` lists the map calls that `auto` did not instrument, with the same site fields plus `reason`.

## Maps of a running program

Before writing a rule, `bpf-ninja --list-progs --list-maps` shows where the maps are used in a program that is already loaded.
Under each program of the reachable tree it lists the functions, the functions each one calls, and every map reference with its op and source line.
With `--lookups-json` it also reads the file `inject-run --lookups-json` wrote for the same load, and marks each map call with whether it can be instrumented and its load-time `pc`:

```sh
bpf-ninja inject-run --lookups-json lookups.json -- ./loader &
bpf-ninja -p "$PROG_ID" --list-progs --list-maps --lookups-json lookups.json
```

This output is from a test program on 7.0:

```
prog 2  entry
├─ func entry  (calls: classify, global_sub)
│  ├─ map stats   Array         lookup     prog.c:29  ✓ injectable  (inlined, pc 7)
│  ├─ map flows   Hash          delete     prog.c:33  ✓ injectable  (pc 18)
│  └─ map jmp     ProgramArray  tail_call  prog.c:35  → prog 3
├─ func classify
│  ├─ map flows   Hash          lookup     prog.c:11  ✗ not in the entry function  (pc 33)
│  └─ map flows   Hash          update     prog.c:14  ✗ not in the entry function  (pc 45)
├─ func global_sub
│  └─ map routes  LPMTrie       lookup     prog.c:21  ✗ not in the entry function  (pc 56)
└─ prog 3  next_stage  (tail call: jmp[0])
   └─ func next_stage
      └─ map flows  Hash  update  prog.c:45  ✓ injectable  (pc 11)
```

Each `map` line gives the map's name and type, the op and the source line of the helper call (of the map load when the op is not known), then:

- for a tail call or redirect, the reached program (`→ prog 3`);
- with `--lookups-json`, `✓ injectable` for a map call `auto` can instrument (`(generic hook)` when it goes to the generic hook), `✗` and the reason for one it skips, and `? not in the lookups file` when no load-time call matched;
- in parentheses, `inlined` for an array lookup the verifier inlined, and the load-time `pc` of the matched call, the one the lookups and hooks files use.

Without `--lookups-json` there is no status column.
A reached program's line names each map and the keys that reach it, such as `(tail call: jmp[0-1], alt[7])`.

The listing reads the translated instructions the kernel keeps for the loaded program, so it needs root.
The verifier rewrites some calls there: an array lookup becomes inline instructions, marked `inlined`, and other map helpers call the map's own function, whose kernel symbol gives the op.
Without access to kernel addresses (`kptr_restrict`) the op shows as `ref`.
Instruction indexes differ between the load and the translated program, so a use is matched to the load-time call with the same op, map, function, file and line, in order; the program is found by its entry function, and a program loaded more than once uses its last load.
With `--json`, each program gets a `maps` list of functions with their `calls`, `callbacks` and `uses`; a use's `pc` indexes the translated instructions, and `site` and `reason` come from the lookups file.

## Lookups as JSON

`--lookups-json PATH` lists every XDP and tc program the target loads with BTF, whether or not a rule selects it, so the maps to instrument can be chosen before a run that injects:

```sh
bpf-ninja inject-run --lookups-json lookups.json -- ./loader
jq '[.programs[].rule | .stack_lowest_offset = -64 | .dispatch = true | .maps = ["sessions"]]' lookups.json > rules.json
bpf-ninja inject-run --config rules.json --hooks-json hooks.json -- ./loader
```

The listing happens before any rule's transform and does not change the load.
Programs whose attr lacks BTF or func_info, or whose lookups cannot be discovered, are reported in the diagnostic and left out.
The file is written like the [hooks file](#hooks-as-json): it exists before the target starts and is rewritten whole after each listed load.
This output is from the integration loader on 7.0:

```json
{
  "version": 1,
  "programs": [
    {
      "program": "p",
      "func": "entry_with_long_name",
      "type": "XDP",
      "ctx_type": "xdp_md",
      "maps": [
        {"name": "sessions", "type": "Hash", "sites": [6], "ops": ["lookup"]}
      ],
      "lookups": [
        {"kind": "lookup", "pc": 6, "map": "sessions", "func": "entry_with_long_name"}
      ],
      "calls": [
        {"kind": "lookup", "pc": 6, "map": "sessions", "func": "entry_with_long_name"}
      ],
      "rule": {
        "program": "entry_with_long_name",
        "auto": true,
        "maps": ["sessions"],
        "hook": "ninja",
        "stack_lowest_offset": null
      }
    }
  ]
}
```

- `maps` lists every map the program references: first those with lookups, in the order of their first lookup, with the `pc` of each in `sites`, then the others by name with no sites.
- `lookups` are the discovered lookup sites with the fields of a hooks-file site; one that `auto` would skip carries a `reason`, and one it sends to the generic hook despite its `reason` has `"generic": true`.
- `calls` lists every `bpf_map_lookup_elem`, `bpf_map_lookup_percpu_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`, `bpf_map_push_elem`, `bpf_map_pop_elem` and `bpf_map_peek_elem` call, with the op as `kind`, and each map's `ops` lists the ops called on it. As in `lookups`, a call with a `reason` is one `auto` skips, unless it also has `"generic": true`.
- `rule` is a rule for this program that instruments every named map with lookups. Its `stack_lowest_offset` is `null` because only the caller can audit the program's stack, so the rule is refused until it is filled in. Edit `maps`, and add `dispatch`, `entry` or `tail_calls` as needed.
- A program loaded twice is listed twice.

## What happens at the syscall boundary

The launcher uses Go's fork/exec support with `PTRACE_TRACEME` and keeps ptrace operations on one locked OS thread.
It follows target threads with `PTRACE_O_TRACECLONE` and uses `PTRACE_GET_SYSCALL_INFO` to distinguish syscall entry from exit, requiring Linux 5.3 or newer.
It intercepts native x86-64 `SYS_bpf`; compat and x32 calls are passed through without injection.
Every original BPF command other than `BPF_BTF_LOAD` and matched `BPF_PROG_LOAD` passes through untouched.
The supervisor also issues its own metadata and load operations as described below.

At `BPF_BTF_LOAD` entry it copies the blob; at successful exit it remembers the blob under the returned tracee fd, together with the object's kernel BTF ID.
An injected object-info query obtains that ID in the tracee.
At a matched program load it rechecks the live fd's BTF ID before trusting the cache, preventing a reused fd from substituting unrelated cached types.
If necessary, it obtains BTF from the kernel by ID instead.
The cache is capped at 64 MiB and is cleared on exec or capacity exhaustion.

The supervisor reads the instructions, `func_info`, and `line_info` from tracee memory to construct `inject.RawProgram`.
For each map reference it injects `BPF_OBJ_GET_INFO_BY_FD` **in the tracee**, where the map fd is valid.
The returned map name, kind, sizes, BTF ID, and key/value type IDs identify the map and its ABI.
It opens that system-wide BTF ID in the supervisor with `BPF_BTF_GET_FD_BY_ID` and reads the types, including when maps and programs have separate BTF objects.
It never treats a tracee fd number as a supervisor fd.
A map without BTF, or a side with a zero type ID, keeps its identity and sizes; the transform passes that side as opaque bytes of the map's size.

`inject.TransformLookupRaw` produces the new instructions and extended BTF with matching function and line records.
A supervisor-only BTF load would produce an fd the target cannot use.
Instead, the supervisor injects `bpf(BPF_BTF_LOAD)` directly into the tracee and uses the returned tracee-owned fd in the copied program attr.
No fd transfer or redundant supervisor BTF load is needed.
The target's credentials and syscall restrictions govern this load.

Injected syscalls replay the existing two-byte x86 `SYSCALL` instruction at saved `RIP-2`.
The original program-load syscall is first suppressed with an invalid syscall number to reach an exit stop.
Catchable signals are masked during replay; the saved mask and registers are restored before returning to the target.
Executable memory and the target's stack are not patched.
An injected anonymous read/write `mmap` provides a 64 MiB scratch arena for the larger buffers and copied attr.
The supervisor points the injected program-load syscall at those buffers, then closes the temporary BTF fd and unmaps the arena after the kernel has copied the data.
The original instruction and metadata buffers remain intact.
The caller's verifier log and `log_true_size` output are preserved as syscall outputs.

The wire offsets and stop discriminators follow the Linux [BPF UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h) and [ptrace UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/ptrace.h).

## Failure behavior

By default, read, metadata, transform, BTF-load, and transformed-program rejection errors produce an `injection skipped` diagnostic and allow the original program load.
If the transformed load has already been attempted, the supervisor retries the original syscall with its original attr and input pointers.
It reports `injected hook` only after the transformed load returns a nonnegative program fd.
The diagnostic names each hook with its map and site PCs, followed by any lookups that `auto` skipped and why.
When the transformed load is rejected, the diagnostic also names the hooks it attempted.
If any used `arg:untrusted` pointers and the kernel returned `EINVAL`, `EOPNOTSUPP` or `EACCES` (6.1 and 6.6 reject the tag with `EINVAL`, 6.12 and 6.15 with `EOPNOTSUPP`), it suggests `"static_untrusted": true`, and `"copy_read_only": true` as well when one of them is a read-only map's hook, to load on kernels that reject the tag (6.15 and older in the CI matrix).
A successful target exit alone does not prove injection; inspect the diagnostic or loaded program metadata.

`--fail-closed` returns `EPERM` when a matched program cannot be injected.
Errors that prevent reading a handled command's attr, or remembering an input BTF blob, are also refused because the supervisor cannot reliably determine eligibility.
Invalid configuration always fails before launching.
Unmatched programs pass through, including with `--fail-closed`.

A broken ptrace stop sequence, failed register restoration, or failed scratch cleanup is fatal in either mode.
The supervisor kills and reaps the target because it cannot safely resume with uncertain machine state.
Cancellation, SIGINT, and SIGTERM also kill the launched process; graceful signal forwarding is not implemented.
`PTRACE_O_EXITKILL` protects the tracee if the tracing thread dies.

## Limits and TODOs

- **Scope:** only the launched process and its threads are instrumented.
  Fork/vfork children are not supervised; separate processes reported by TRACECLONE are detached.
  TODO: add `PTRACE_O_TRACEFORK`/`PTRACE_O_TRACEVFORK`, maintain per-process fd caches and thread groups, and handle nonleader exec identity transitions across the process tree.
  Attach-to-existing-process support needs `PTRACE_SEIZE` over every `/proc/<pid>/task` entry and a way to recover BTF loaded before attachment.
- **Concurrency:** the loading thread is stopped, but siblings may still run while buffers and fd identity are read.
  The fixture exercises a multithreaded Go runtime, not concurrent mutation or closure of load inputs.
  TODO: use a seize-based launcher with `PTRACE_INTERRUPT` to quiesce all siblings, drain their stops, snapshot inputs and fd identities, and resume them after the transaction.
  Do not use this prototype with loaders that concurrently mutate load buffers, replace referenced fds, unshare fd tables, or exec during injection.
- **Signals and restrictions:** ordinary signal-delivery stops are forwarded outside replay; job-control stops, seccomp tracing/notification, and uncatchable signals during replay are not fully supported.
  TODO: distinguish group stops with `PTRACE_GETSIGINFO`, use `PTRACE_LISTEN` after switching to SEIZE, and model `PTRACE_EVENT_SECCOMP` and syscall restarts explicitly.
  A replay that encounters an unexpected stop terminates supervision.
- **Full function names:** preselection uses the BTF cached under the program's fd.
  Duped, inherited, externally supplied, or evicted BTF fds may therefore fail to match a function-only selector.
  Use the kernel program name in those cases.
  TODO: resolve the live BTF ID before function-name preselection, or track fd duplication and inheritance; do not infer identity from the numeric fd alone.
- **Load formats:** only eight-byte function records and sixteen-byte line records are supported.
  Individual input buffers are capped at 16 MiB and attrs at 4096 bytes.
  Nonzero kernel-side CO-RE records, fd arrays, token/signature inputs, and unknown extensions are refused.
  TODO: normalize larger known metadata records, relocate all offset-bearing fields, and resolve indexed map references before accepting those formats.
- **Coverage:** the tested case uses a Go loader, one hash map with BTF, one XDP entry function, and one lookup.
  No C/libbpf integration fixture, production UPF deployment, fentry observer attachment, throughput evaluation, or alternate architecture has been validated here.
  Observers can be attached separately; automatic observer attachment is outside this launcher.

## Tests

Unprivileged tests cover strict config parsing, attr sizes and offsets, target argument/exit-status handling, threaded launch, cancellation, and failure policy.
The integration test is guarded by the `integration` build tag and a root check.
It launches the same Go loader both directly and under the supervisor, verifies kernel function metadata, and executes the loaded XDP program using `BPF_PROG_TEST_RUN`.
It covers kernel-name and function-name selection, fail-open, fail-closed, and unmatched loads.
It also checks that the launcher reports each successful injection, and only those, with the program ID the loader sees, that `maps` instruments the named map and refuses an unknown one, and that discovery reports the loader's lookup, among its map calls, with and without a rule; `--hooks-json` and `--lookups-json` are covered by unit tests of the JSON shape and of the file they write.
It never attaches to an interface, pins objects, or changes sysctls, routes, or firewall rules.

```sh
go build ./...
go vet ./...
go test ./...
go test -count=50 -timeout 60s ./pkg/syscallhook
sudo -E env PATH=$PATH go test -tags integration -run '^TestIntegrationLoader$' -v -timeout 90s ./pkg/syscallhook
```

The privileged test fails on missing BPF capabilities even if uid is zero; it does not disguise a failed injection as a skip.
Only the explicit non-root guard skips it.
