# Run an unmodified loader with lookup injection

`inject-run` is a Linux x86-64 prototype that rewrites selected BPF programs as a launched process loads them.
It reaches direct Go syscalls as well as C loaders, without changing the target's binary, source, or object files.
The name makes the bytecode transformation explicit and distinguishes it from the existing packet-observation command.

The implementation works end to end for the tested Go loader: the target receives a real fd for the transformed program, the kernel reports the generated hook in `func_info`, and `BPF_PROG_TEST_RUN` executes the program successfully.
There is no stub for fd transfer or memory growth.
This does not establish support for arbitrary Cilium, eUPF, or Ella deployments.

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
It must be between -456 and 0 for a rule with `map` or `auto`; a rule with only `tail_calls` (and `entry`) allows -464, and one with only `entry` -472. With `dispatch`, a rule with `map`, `auto` or `tail_calls` needs -448.
The transform reserves three eight-byte slots below the audited region, aligned downward (one for `entry` alone, two for `tail_calls` without lookups), four with `dispatch` (unless the rule has only `entry`) or when `auto` finds a lookup whose map a typed hook cannot take, plus the value copy with `copy_read_only` (see the transform's refusal message for the exact bound).
The frame holding the slots also calls the hook, which kernels that round frames to 32 bytes count as 32 bytes of the 512-byte stack, so the slots must end 480 bytes below the frame.
Do not copy the example bound without auditing the actual program.
`hook` must be a C identifier of at most 127 bytes, leaving room for the longest suffix the transform appends: at most 117 bytes with `tail_calls` (`_tail_call`), 121 with `entry` (`_entry`), and 125 with `auto` (`_0`); with `dispatch` the hook is named `hook` itself, so up to 127 bytes. Under `auto`, a map whose hook name would still not fit is skipped.
Unknown JSON fields, duplicate program selectors, trailing JSON, and configurations larger than 1 MiB are rejected before launching.

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

- `kind` is `typed` (a lookup hook with the map's key and value types), `generic` (the `HOOK_any` hook that also takes the map pointer), `entry`, `tail_call`, or `dispatch`.
- `map` is the map of a `typed` hook. A `generic` or `dispatch` hook serves several maps, so the map is given on each site instead.
- `sites` are the helper calls that call the hook, in instruction order. Each has a `kind` (`lookup`, `tail_call`, or `entry`), its raw instruction index `pc` (the `site` argument the hook receives), and, where known, `map`, `func`, `file` and `line`. An `entry` hook has no sites.
- A `dispatch` rule produces one hook with every site: the lookups, the failed tail calls, and the entry call as the site `4294967295` (`inject.DispatchEntrySite`). The entry call comes first, since it runs at program start, and the other sites follow in instruction order across maps and kinds.
- `untrusted`, `copied`, `static` and `read_only` mirror `inject.LookupHook`: the hook takes `arg:untrusted` pointers, its value is a stack copy, it is a static function (read every argument as a `u64`), and its map is `BPF_F_RDONLY_PROG`.

`skipped` lists the lookups that `auto` did not instrument, with the same site fields plus `reason`.

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
- `lookups` are the discovered lookup sites with the fields of a hooks-file site; one that `auto` would skip carries a `reason`.
- `calls` lists every `bpf_map_lookup_elem`, `bpf_map_update_elem` and `bpf_map_delete_elem` call, with the op as `kind`, and each map's `ops` lists the ops called on it. Only lookups can be instrumented so far; the `reason` of an update or delete only says why its map or `ctx` is out of reach.
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
