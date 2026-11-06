# Add hooks at load time with inject-run

`bpf-ninja inject-run` starts a BPF loader under ptrace and rewrites selected XDP, tc, cgroup_skb and netfilter programs as the loader loads them.
It adds hook functions at map calls, at program entry and after failed tail calls.
You then capture packets at a hook with `--func`, or attach your own fentry observer.
Use it to see what a program does with its maps, such as which key a lookup used or which update failed, without changing the loader, its source or its object files.
The loader can be a Go program that calls `bpf(2)` directly or a C loader.
`inject-run` is experimental and runs on Linux x86-64 only.
Each substituted instruction stream that the checker can pair is checked by `pkg/injectcheck` before its `BPF_PROG_LOAD` runs; see the [`callx` exception](#load-stream-check).
[inject-walkthrough.md](inject-walkthrough.md) runs every step below on an example program.

## Quick start

Run as root.

```sh
# 1. List the programs and map calls the loader loads. Nothing is rewritten.
bpf-ninja inject-run --lookups-json lookups.json -- ./loader

# 2. Take the suggested rule and load with hooks.
jq '[.programs[0].rule]' lookups.json > rules.json
bpf-ninja inject-run --config rules.json --hooks-json hooks.json -- ./loader

# 3. In another terminal, while the loader runs, capture the packets that reach a hook.
PROG_ID=$(jq '.programs[0].prog_id' hooks.json)
HOOK=$(jq -r '.programs[0].hooks[0].name' hooks.json)
bpf-ninja -p "$PROG_ID" --func "$HOOK" -c 10 -w hook.pcap
```

- `inject-run` obtains each function's stack floor from a trial verifier load; see [Stack floor](#stack-floor).
- The suggested rule uses `auto` with the hook prefix `ninja`, so a lookup on the map `sessions` gets the hook `ninja_sessions`.
- stderr reports each injection, for example `inject-run: program "xdp_ingress": injected hook "ninja_sessions" (lookup map "sessions", site pc 6), tracee fd 9`.
  If `inject-run` cannot rewrite a load, it logs `injection skipped` and lets the original program load.

## Common tasks

### Choose the maps and operations to observe

```json
[{"program": "xdp_ingress", "auto": true, "maps": ["sessions"], "ops": ["lookup:any", "update"],
  "hook": "obs"}]
```

`auto` instruments every supported call of the observed ops, with one hook per map and op: lookups by default, or exactly the ops that `ops` lists.
`maps` limits it to the named maps; calls on other maps run unchanged.
`ops` picks the calls and results that call a hook:

| Op | The hook runs |
|---|---|
| `lookup` or `lookup:hit` (the default) | after a lookup that found an entry |
| `lookup:miss` | after a lookup that found nothing; the `_miss` hook gets only the key |
| `lookup:any` | after every lookup |
| `update` or `update:error` | after a `bpf_map_update_elem` that failed |
| `update:any` | after every update |
| `delete`, `push`, `pop`, `peek` | as for `update`, with `:error` (the default) or `:any` |

An entry in `ops` names an op and, after the colon, the results that call its hook.
Each op appears once, so use `lookup:any`, not `lookup:hit` together with `lookup:miss`.

- A rule with `ops` observes only the ops it lists, so `"ops": ["update"]` leaves the lookups alone.
- `bpf_map_lookup_percpu_elem` counts as a lookup.
- Every op except `lookup` needs `auto`.
- `push`, `pop` and `peek` work on queues, stacks and bloom filters.
  On a queue or stack, a pop or peek hook sees the value the helper wrote; a bloom-filter peek hook sees the value tested.

`auto` skips a site it cannot instrument, leaves it unchanged, and lists it with the reason in the diagnostic and in the `skipped` list of the [hooks file](#hooks-file).
It skips these sites:

- a function without a context parameter, a caller that does not pass the context, or a site where no callee-saved register or aligned stack slot still holds it, unless the context can be passed down to the function (see [Limits](#limits)); the reason then ends with `; ctx pass:` and why not, for example a function that is not static, is used as a callback, reads every argument register before writing it, or has a caller that cannot pass the context either;
- a site whose context would be passed through a function without an audited stack floor, or whose context slot does not fit below it;
- a callback, unless its context can be proved through its caller (see [Limits](#limits)), for example a timer callback, a callback passed to another helper or a kfunc, a callback that is not static, a callback passed by a function other than the entry, a NULL or non-stack `callback_ctx`, a `callback_ctx` below the entry's stack floor, different `callback_ctx` values at different calls, an atomic, a legacy packet load or a branch between the function pointer or `callback_ctx` and the helper call, or a callback that is also called directly;
- a callback site whose key or value may be read-only memory, when it shares a hook with sites outside callbacks that would otherwise stay typed;
- a call on a map that `maps` does not name (`map not selected by Maps`);
- a call on a map kind that has no hook;
- a site whose hook name would be longer than 127 bytes;
- a site whose spill slots do not fit below its function's stack floor, unless a [wrapper](#stack-floor) can hold them;
- sites that would make the rewritten program break a kernel call-chain stack limit.
  `auto` first drops the sites in callbacks and those whose context is passed down, then the sites that need slots below the three base ones (see [Stack floor](#stack-floor); the generic hook, update hooks and copied read-only values), and then, if the program still breaks the limit, every map-call site.
  With `dispatch` it drops every map-call site at once.

`auto` keeps the `entry` and `tail_calls` hooks.
If nothing is left to instrument, the injection fails.
A map call whose op the rule does not observe is left alone and does not appear in `skipped`.

### Observe one lookup

```json
[{"program": "xdp_ingress", "map": "sessions", "func": "xdp_ingress", "line": 42,
  "hook": "lookup_hook"}]
```

The rule must match exactly one supported lookup; if it matches several, the injection fails.
The compiler can inline one lookup into several places with the same source line.
To take them all, add `"all_matches": true`.
To take some of them, list their load-time instruction indexes in `"site_pcs": [293, 1942]`.
The [lookups file](#lookups-file) and [`--list-maps --lookups-json`](#map-listing-of-a-running-program) show those indexes.
This hook has no `site` argument: `lookup_hook(ctx, key, value)`.

### Observe program entry and failed tail calls

An fentry on a program does not fire when the program is entered through `bpf_tail_call`.
`"entry": true` adds `HOOK_entry(ctx)`, which runs at the start of every run, tail-call entry included.
`"tail_calls": true` adds `HOOK_tail_call(ctx, u32 site, u32 index)`, which runs after a `bpf_tail_call` fails anywhere in the program.
A successful tail call does not return, so it calls no hook.
Both keys work with a lookup rule or on their own.

```json
[{"program": "next_stage", "entry": true, "hook": "obs"}]
```

A program that calls `bpf_tail_call` loads with hooks only when the BPF JIT is enabled.

### See every site through one hook

`"dispatch": true` sends every instrumented site, including the entry call and failed tail calls, to one hook named `hook`.
One observer attach then sees them all.
This matters on kernels 7.0 to 7.2.5, where a program that tail-calls accepts only one tracing attach.
The hook has the generic signature: `hook(ctx, u64 info, const void *key, const void *value, const void *map)`.
The low 32 bits of `info` are the site; [lookup-site-injection.md](lookup-site-injection.md#one-dispatch-hook) gives the other bits and what each caller passes.
`dispatch` needs one more stack slot and does not combine with `copy_read_only` or `map_btf`.

### Capture packets at a hook

A hook takes the program's `ctx` as its first argument, so bpf-ninja's own capture attaches to it like to any other function:

```sh
bpf-ninja -p "$PROG_ID" --func ninja_sessions -w sessions.pcap
bpf-ninja -p "$PROG_ID" --func ninja_sessions --list-params --members
bpf-ninja -p "$PROG_ID" --func ninja_sessions --arg-filter 'value->action==2' -w action2.pcap
```

- The capture sees a packet only when the program calls the hook, so your rule sets what gets captured.
- `--arg-filter` can select members of the key and value, and `site` and `status` where the hook has them. `status.ret` and `status.flags` select one half of `status`.
- At a hook that `inject-run` generated, the capture writes decision state as each packet's pcapng comment. `--record` picks it:
  - `filter` (the default) records the arguments and members that `--arg-filter` and `--set` keys read, and records nothing without them;
  - `entry` records whichever of `site`, `status`, the key and the value the hook has, the key and value cut to `--record-max` bytes (default 256); at a generic or dispatch hook it records only `site` and `info`;
  - `none` turns recording off.
- At a static XDP, tc, cgroup_skb or netfilter hook, the capture reads the context with `bpf_probe_read_kernel` when the kernel rejects direct reads.
  This is a fallback: a static function that accepts direct reads keeps them.
  It first checks that the entry function passes the context to every call; [arg-member-filter.md](arg-member-filter.md) lists what that check refuses.
  The hooks inject-run generates, tagged `bpf-ninja:hook`, skip that repeated check: their first argument is the saved program context.
  At a tc, cgroup_skb or netfilter hook on this path, it captures only the linear packet head.
  At a tc hook it refuses a filter with `--tc-vlan-reinsert`; cgroup_skb and netfilter packets have no Ethernet header, so the flag has no effect there.

[The walkthrough](inject-walkthrough.md#6-capture-the-packets-at-a-hook) shows filters, set lookups and recorded state with real output.

### Attach your own observer

`inject-run` does not attach observers.
Open the program by the `prog_id` in the [hooks file](#hooks-file) and attach an fentry program to a hook by name.
Read the arguments with `bpf_get_func_arg` and pointed-to memory with `bpf_probe_read_kernel`.
[inject-observers.md](inject-observers.md) has counting, CPU-tagging and timing examples.

### Load on kernels without `arg:untrusted`

Some hooks take `arg:untrusted` pointers:

- a lookup hook on a `BPF_F_RDONLY_PROG` or `BPF_F_WRONLY_PROG` map;
- a lookup hook on a map whose value holds a `bpf_spin_lock`, `bpf_timer`, kptr or similar field;
- a hook whose key or value may point into a read-only map's value;
- a hook with a site in a callback whose key, or an update's value, is not the callback's own stack;
- the generic `HOOK_any` hooks and the dispatch hook.

Kernels that do not know the tag reject such a hook in its global form.
By default, `inject-run` loads a minimal probe program once per run to test the tag.
If the kernel accepts it, these hooks stay global.
If the verifier rejects it as an unsupported tag or an unsized `UNKNOWN` reference, these hooks become static.
The probe tests the ABI rather than the kernel version, so it also handles backports.
If the probe fails for another reason, such as permissions or resources, `inject-run` logs it and keeps the global form.
If the kernel then rejects the hooks, the load falls back as described in [Diagnostics and failures](#diagnostics-and-failures).
`"static_untrusted": true` makes these hooks static without probing.
The choice affects only these hooks; ordinary typed hooks stay global.

An observer at a static hook reads every argument, `ctx` included, as a `u64` address and reads memory with `bpf_probe_read_kernel`.
`"copy_read_only": true` keeps typed hooks for `BPF_F_RDONLY_PROG` maps instead: the hook gets a pointer to a stack copy of the value.
Write-only maps and the generic hook still follow the global or static choice.
The [hooks file](#hooks-file) reports the choice in `hook_form` and the form of each hook in `untrusted`, `copied` and `static`.
[lookup-site-injection.md](lookup-site-injection.md#supported-sites-and-trust-boundary) explains the verifier rules behind these forms.

### Map types from a loader ELF

Some loaders create maps without BTF, even though their ELF has the key and value types.
Without types, the hook passes the key and value as opaque bytes, and member filters such as `value->identity` fail.
`map_btf` takes the types from the ELF for one explicit `map` rule:

```json
[{"program": "ingress", "map": "sessions", "hook": "observe",
  "map_btf": {"elf": "/path/to/loader-generated.o", "sha256": "REPLACE_WITH_64_HEXADECIMAL_DIGITS"}}]
```

```sh
sha256sum /path/to/loader-generated.o
# --fail-closed: without it, a failed supplementation loads the original program without hooks
bpf-ninja inject-run --fail-closed --config rules.json --hooks-json hooks.json -- ./loader

# In another terminal, while the loader runs
PROG_ID=$(jq '.programs[0].prog_id' hooks.json)
bpf-ninja -p "$PROG_ID" --func observe --list-params --members
bpf-ninja -p "$PROG_ID" --func observe --arg-filter 'value->identity==7' -w selected.pcapng
```

The rule:

- needs `map` with a kernel name of at most 15 bytes, and cannot use `auto` or `dispatch`;
- observes lookups only; other ops are refused;
- works on Hash, Array, PerCPUHash, PerCPUArray, LRUHash, LRUCPUHash and LPMTrie maps;
- needs both key and value types, even with `ops: ["lookup:miss"]`.

`map_btf` takes `elf` and `sha256`, both required, and the optional `key_type` and `value_type`.
`null` or no `map_btf` supplies nothing; `{}` and unknown fields inside it are errors.
The digest is 64 hexadecimal digits in either case; a malformed digest fails the configuration check.

At each matching load, the supervisor reads `elf` from its own filesystem, relative to its working directory.
The file must be a regular file of at most 64 MiB.
The supervisor reads and hashes it on every load, without a cache, and parses the same bytes it hashed.
It checks the file only at those loads: nothing reads it when `inject-run` starts, so a missing or wrong file shows up as a failed injection, not as a configuration error.
`inject-run` refuses the injection, and the normal [failure policy](#diagnostics-and-failures) applies, unless all of these hold:

- exactly one referenced live map has the name, and it has no BTF at all, not even an anonymous byte-array value type;
- exactly one ELF map definition has the name after truncation to 15 bytes;
- the map type, key size, value size and flags are equal;
- the ELF has the program's byte order and its digest matches;
- each type exists, is unique and has the map's key or value size;
- each type is plain data, through typedefs and qualifiers, with no special fields such as spin locks, timers or kptrs, and is not `xdp_md`, `__sk_buff`, `bpf_nf_ctx` or `bpf_dynptr`.

`map_btf` changes only the hook's BTF.
The emitted instructions, pointer trust and value copies stay the same.
`inject-run` never loads the ELF's instructions or maps, and leaves the live map, its contents and its BTF alone.

For a legacy map definition that declares sizes instead of types, `key_type` and `value_type` name exact BTF types in the same ELF, such as `"key_type": "u32", "value_type": "record"`:

- A name fills only a side the ELF declares by size.
  If the ELF already types that side, the name must resolve to the same type.
- An omitted side uses the map definition's own type, so a legacy map with neither type needs both names.
- Only full names match: `record` matches `record`, not `record___old`.
  Give struct names without `struct `.
- `inject-run` ignores forward declarations and other unsized entries.
  Typedefs of the same type count as one layout.
  Distinct layouts with the same name, such as a struct and a union, are ambiguous.
- A name missing from the ELF is an error; nothing is inferred or created.

The checks compare names and sizes, not meaning.
Two types of the same size pass even when their members differ in order or byte order, or when the loader relocated the layout.
Choose an ELF and types that describe the live map, including CO-RE or loader adjustments; the digest pins that choice.
[日本語の説明](../ja/inject-map-types.md) covers the same configuration.

## Reference

### Command line

```text
bpf-ninja inject-run [--config FILE] [--fail-closed] [--hooks-json FILE] [--lookups-json FILE] -- TARGET [ARGS...]
```

| Flag | Meaning |
|---|---|
| `--config FILE` | Rules file (JSON). Without it, the environment variable `BPF_NINJA_INJECT_CONFIG` holds the JSON itself. |
| `--fail-closed` | Refuse a matched load with `EPERM` when transformation, checking, or the substituted kernel load fails, or when the checker is not applicable. By default a failed check loads the original program, while a checker-inapplicable transformed program loads without validation. |
| `--hooks-json FILE` | Write the injected programs and their hooks to FILE. See [Hooks file](#hooks-file). |
| `--lookups-json FILE` | Write every XDP, tc, cgroup_skb and netfilter program the target loads, with its map calls and a suggested rule. Rules are then optional. See [Lookups file](#lookups-file). |

- Flags before `--` belong to `inject-run`; the command and arguments after it belong to the target.
- `--config` takes precedence over `BPF_NINJA_INJECT_CONFIG`.
  Without either, `--lookups-json` is required.
- The target inherits stdin, stdout and stderr.
  `inject-run` writes its diagnostics to stderr, prefixed with `inject-run:`.
- The exit status is the target's, or 128 plus the signal number if a signal killed it.
  A nonzero target status also prints `target exited with status N`.
- `inject-run` exits with status 1 and an `error: ...` line when its configuration is invalid, when it fails, when SIGINT or SIGTERM stops it, or when writing the hooks or lookups file fails although the target succeeded.
- Every `bpf(2)` command other than `BPF_BTF_LOAD` and a matched `BPF_PROG_LOAD` passes through unchanged.
- `inject-run` needs ptrace, the target's BPF operations, and opening BTF objects by ID in the supervisor.
  The tests run as root.

### Rule keys

The configuration is a JSON array of rules.
`inject-run` rejects unknown keys, trailing data, an empty array, two rules for the same `program`, and files over 1 MiB before the target starts.
It catches most errors against the table below at that point too.
The rest, such as a selector that matches nothing, show up only when the program loads, and that load's injection fails.
A rule whose `program` never loads produces no diagnostic at all.

| Key | Type | Default | Meaning | Constraints |
|---|---|---|---|---|
| `program` | string | required | The program to rewrite: its kernel name or its entry function name. | Kernel names have at most 15 characters; a function name can be longer. One rule per program. |
| `hook` | string | required | The hook name. With `auto`, `entry`, `tail_calls` or `ops`, the prefix of the hook names. With `dispatch`, the name of the one hook. | A C identifier. It must leave room for the longest suffix within 127 bytes; see [Hook names](#hook-names). |
| `map` | string | none | Observe lookups on this map, by exact kernel map name. | Not with `auto`. A rule needs one of `map`, `auto`, `entry` or `tail_calls`. |
| `func` | string | none | With `map`: only lookups in this BTF function. | Needs `map`. |
| `line` | integer | none | With `map`: only lookups on this source line. | Needs `map`. |
| `all_matches` | bool | false | With `map`: take every matching lookup instead of requiring exactly one. | Needs `map`. Not with `site_pcs`. |
| `site_pcs` | integer array | none | With `map`: take the lookups at these load-time instruction indexes. | Needs `map`. Not with `all_matches`. Each PC must be a lookup that matches the other filters, and must appear once. |
| `auto` | bool | false | Instrument every supported call of the observed ops (lookups by default, or the ops that `ops` lists), with one hook per map and op. | Not with `map`, `func`, `line`, `all_matches` or `site_pcs`. |
| `maps` | string array | every map | With `auto`: only calls on these maps, by exact kernel name. Calls on other maps run unchanged. | Needs `auto`. Names must be unique, and each must match a call the rule observes. |
| `ops` | string array | `["lookup"]` | The calls and results that call a hook; see the [ops table](#choose-the-maps-and-operations-to-observe). | Needs `map` or `auto`. Ops other than `lookup` need `auto`. Each op appears once, so `lookup:hit` and `lookup:miss` together are refused; use `lookup:any`. |
| `entry` | bool | false | Add `HOOK_entry(ctx)` at program start. | |
| `tail_calls` | bool | false | Add `HOOK_tail_call(ctx, site, index)` after each failed tail call. | The program must call `bpf_tail_call`. |
| `dispatch` | bool | false | Send every site to one hook named `hook`. | Not with `copy_read_only` or `map_btf`. |
| `copy_read_only` | bool | false | Pass a stack copy of a `BPF_F_RDONLY_PROG` map's value to a typed hook. | Not with `dispatch`. The copy needs stack below the slots. |
| `static_untrusted` | bool | false (probe) | Make hooks that would take `arg:untrusted` pointers static, without probing. | |
| `map_btf` | object | none | Key and value types for a map created without BTF. | See [Map types from a loader ELF](#map-types-from-a-loader-elf). |

### Stack floor

`inject-run` places each hook's spill slots below the deepest stack byte accounted to the function that owns the site.
It obtains that per-function floor by loading the original program once with verifier statistics enabled, reading the loaded function order, and closing the trial file descriptor immediately.
The verifier's accounting includes stack aliases, helper buffers, variable offsets, and writes through a caller's frame pointer.
If a direct instruction reaches deeper than the verifier reported, as can happen after fast-call spill removal, the direct access wins.
The trial uses the original load attributes and adds one verification pass, which can take seconds for a large program.

Linux before 6.8 does not include every variable-offset access in its reported depth.
On those kernels, `inject-run` skips sites in a function whose instruction scan is not exact.
If trial loading, statistics parsing, or function matching fails, automatic rules leave the original program unchanged, explicit rules refuse the load, and `--fail-closed` refuses either kind.
A program with an [indirect jump](#load-stream-check) has no trial load and no floor: an explicit rule loads it unchanged, and `--fail-closed` still refuses it.

The `stack` block in `--lookups-json` and `--hooks-json` records the kernel release, every function's verifier and direct-text depths, the selected floor, source, and reserved slots.
Each hook site also records its `frame` and `floor`.
stderr prints the same floors in a compact line before transformation.
There is no manual override.
Rules containing `stack_lowest_offset` are rejected with an error that tells you to remove it.

The transform rounds each floor down to 8 bytes and puts that frame's spill slots below it.
The frame that holds them also calls the hook.
Kernels that round frames to 32 bytes (6.1-era kernels and the interpreter) count that call as 32 bytes of the 512-byte stack, so the transform keeps the slots within 480 bytes there.
On Linux 6.9 or newer with `net.core.bpf_jit_enable` set to `1` or `2`, `inject-run` uses the JIT's 16-byte rounding and zero-byte empty hook frame, allowing the site frame to use all 512 bytes.
If `uname` or the sysctl cannot be read, or the state is not recognized, it keeps the 32-byte rule.
There is no rule override.
Rules containing the retired `frame_rounding` field are rejected with an error that tells you to remove it.
The deepest floor that still leaves room depends on the rule:

| Rule has | Slots | 32-byte / unknown | Linux 6.9+ JIT |
|---|---:|---:|---:|
| `map` or `auto` | 3 | -456 | -488 |
| `tail_calls`, with or without `entry`, and no lookups | 2 | -464 | -496 |
| only `entry` (also with `dispatch`) | 1 | -472 | -504 |
| `dispatch` with `map`, `auto` or `tail_calls` | 4 | -448 | -480 |
| an `update` op | 4 | -448 | -480 |
| an `update` op and `dispatch` | 5 | -440 | -472 |

The transform checks the rest, which depends on the program.
A generic hook takes a fourth slot (bound -448), or a fifth at an update (-440).
`copy_read_only` puts the value copy below the fourth slot, so a copied value needs a bound of at least -448 plus its size rounded up to 8 bytes.
`auto` skips a site that does not fit, and an explicit `map` rule fails.
The refusal names the function and the slots or bytes that do not fit.

A lookup site that does not fit is not refused under the 6.9+ JIT rule when it needs no stack of its own:
the transform moves its helper into a small static function, `HOOK__siteN` for the site at slot N.
That function keeps ctx, the key, the result and the map in its own R6-R9, calls the helper and the hook, and returns the helper's result.
It uses no stack, so it counts as zero bytes and adds one frame to the 8-frame limit.
The site loads ctx into R4 from the entry frame's spill slot, or from the register or slot that holds it in a subprogram.
An entry-frame site therefore still needs that one slot, so `-504` is the deepest entry floor.
The 32-byte rule charges the function 32 bytes, so it does not apply there.
Only `lookup` sites take this form; a copied read-only value still needs stack.
Each hook site records the function in its `wrapper` field.

### Hook names

`MAP` in a hook name is the map name, with characters outside `[A-Za-z0-9_]` replaced by `_`.
If that name is empty, invalid, taken or too long, `inject-run` names the hook `HOOK_<index>` instead.
`site` is the call's load-time instruction index.
`status` holds the helper's result in the low 32 bits and the update or push flags above them; `--arg-filter` reads them as `status.ret` and `status.flags`.
`ctx` is `struct xdp_md *` in XDP, `struct __sk_buff *` in tc and cgroup_skb, and `struct bpf_nf_ctx *` in netfilter.

| Rule | Hook | Arguments |
|---|---|---|
| `map` | `HOOK` | `(ctx, const KEY *key, const VALUE *value)` |
| `map`, `lookup:miss` or `lookup:any` | `HOOK_miss` | `(ctx, const KEY *key)` |
| `auto` lookup | `HOOK_MAP` | `(ctx, u32 site, const KEY *key, const VALUE *value)` |
| `auto` lookup miss | `HOOK_MAP_miss` | `(ctx, u32 site, const KEY *key)` |
| `update` | `HOOK_MAP_update` | `(ctx, u32 site, const KEY *key, const VALUE *value, u64 status)` |
| `delete` | `HOOK_MAP_delete` | `(ctx, u32 site, const KEY *key, u64 status)` |
| `push`, `pop`, `peek` | `HOOK_MAP_push`, `HOOK_MAP_pop`, `HOOK_MAP_peek` | `(ctx, u32 site, const VALUE *value, u64 status)` |
| a call on a map known only at run time (map-in-map or an indirect map pointer), or a lookup on an XSK map, sockmap or sockhash | `HOOK_any`, `HOOK_any_update`, `HOOK_any_delete`, `HOOK_any_push`, `HOOK_any_pop`, `HOOK_any_peek` | `(ctx, u64 info, const void *key, const void *value, const void *map)` |
| `entry` | `HOOK_entry` | `(ctx)` |
| `tail_calls` | `HOOK_tail_call` | `(ctx, u32 site, u32 index)` |
| `dispatch` | `HOOK` | as `HOOK_any`, for every site |

- A typed hook with `untrusted: true` in the [hooks file](#hooks-file) takes `const void *key` and `const void *value` instead of typed pointers, with their sizes in BTF decl tags when the bytes are plain data. Member filters such as `value->action` need `untrusted: false`; a sized pointer reads as `struct { u8 bytes[N]; }`, so `value->bytes[0]` selects its first byte, as on a static hook of a map without BTF.
- A devmap or devmap hash lookup gets a typed hook like a `BPF_F_RDONLY_PROG` map's, since the kernel makes those maps read-only to programs: untrusted, static with `static_untrusted`, or copied with `copy_read_only`. Its value is the target ifindex, followed by the attached program's ID when the value is 8 bytes.
- An update or delete on a sockmap or sockhash goes to `HOOK_any_update` or `HOOK_any_delete`, since its value is a socket.
- A `HOOK_any` hook gets a NULL `value` on a lookup miss or a delete, and a push, pop or peek on it gets a NULL `key`.

The longest suffix a rule appends limits the length of `hook`:

| The rule has | Longest suffix | `hook` length |
|---|---|---|
| `dispatch` (with any other keys), or `map` without misses | none | up to 127 bytes |
| `auto` | `_0` | up to 125 |
| `map` with `lookup:miss` or `lookup:any` | `_miss` | up to 122 |
| `entry`, or `pop` with `auto` | `_entry`, `_0_pop` | up to 121 |
| `push`, `peek`, `lookup:miss` or `lookup:any` with `auto` | `_0_push`, `_0_peek`, `_0_miss` | up to 120 |
| `update` or `delete` | `_0_update`, `_0_delete` | up to 118 |
| `tail_calls` | `_tail_call` | up to 117 |

[lookup-site-injection.md](lookup-site-injection.md#automatic-selection) describes the full hook ABI, including the `info` bits.

### Hooks file

`--hooks-json FILE` lists the injected programs and their hooks, so a tracer knows what to attach to.
The file exists, with an empty `programs` list, before the target starts; an unwritable path stops `inject-run` before launch.
After each injected load, `inject-run` rewrites the whole file through a temporary file and a rename.
This happens before the target receives the new program fd, so every program the target can attach or run is already listed.
It also compares each generated hook with that load's `func_info`.
If the verifier removed a hook because it is unreachable, the file marks the hook instead of presenting a later attach refusal as an attach failure.
If a rewrite fails, `inject-run` reports it on stderr and keeps running the target.

```json
{
  "version": 2,
  "programs": [
    {
      "program": "p",
      "func": "entry_with_long_name",
      "type": "XDP",
      "prog_id": 2,
      "ctx_type": "xdp_md",
      "stack": {"source": "verifier", "kernel": "7.0.0", "frame_rounding": 16,
        "functions": [{"name": "entry_with_long_name", "verified_depth": 8,
          "text_depth": 4, "text_exact": true, "floor": -8,
          "slots": {"ctx": -16, "key": -24, "result": -32, "map": -40, "value": -48}}]},
      "hook_form": {"form": "global", "reason": "probe_arg_untrusted_supported"},
      "hooks": [
        {
          "name": "lookup_hook_sessions",
          "kind": "typed",
          "when": "hit",
          "map": "sessions",
          "sites": [{"kind": "lookup", "pc": 6, "map": "sessions", "func": "entry_with_long_name", "ctx_source": "entry", "frame": "entry_with_long_name", "floor": -8}],
          "untrusted": false,
          "copied": false,
          "static": false,
          "read_only": false
        },
        {"name": "lookup_hook_entry", "kind": "entry", "sites": [{"kind": "entry", "pc": 4294967295, "frame": "entry_with_long_name", "floor": -8}], "untrusted": false, "copied": false, "static": false, "read_only": false}
      ],
      "skipped": []
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `version` | 2. It changes only when a field changes meaning or is removed; new fields can appear. |
| `programs` | One entry per injected load, in load order; a program loaded twice appears twice. Loads that fell back or were refused are not listed. |
| `program`, `func` | The kernel program name and the entry function. |
| `type` | `XDP`, `SchedCLS`, `SchedACT`, `CGroupSKB` or `Netfilter`. |
| `prog_id` | The loaded program's kernel ID, for `-p` or `BPF_PROG_GET_FD_BY_ID`. 0 if `inject-run` could not query it; the diagnostic says why. |
| `ctx_type` | The struct the hooks' `ctx` points to: `xdp_md`, `__sk_buff` or `bpf_nf_ctx`. |
| `hook_form.form` | `global` or `static`: the choice for hooks that would take untrusted pointers, even if the program has none. |
| `hook_form.reason` | `probe_arg_untrusted_supported`, `probe_arg_untrusted_unsupported`, `probe_inconclusive` or `config_static_untrusted_true`. |
| `hooks[].name` | The function to attach to. |
| `hooks[].kind` | `typed` (one map's hook; its key and value carry the map's types unless `untrusted` is set), `generic` (a `HOOK_any` hook), `entry`, `tail_call` or `dispatch`. |
| `hooks[].when` | The results that call it: `hit`, `miss` or `any` for lookups; `error` or `any` for other map calls. A dispatch hook's `when` is its lookups'; its other map-call sites carry their own. |
| `hooks[].map` | The map of a `typed` hook. Generic and dispatch hooks give the map on each site. |
| `stack` | The trial load's verifier accounting and the exact per-function floors used by this injection. |
| `hooks[].sites` | The calls that call the hook, in instruction order: `kind` (`lookup`, `update`, `delete`, `push`, `pop`, `peek`, `tail_call` or `entry`), `pc` (the `site` argument, or the low 32 bits of `info`), and `map`, `func`, `file`, `line`, `ctx_source`, `frame` and `floor` where known. `ctx_source` is `entry`, `r6` through `r9`, or an aligned frame slot such as `fp-80`. `frame` owns the stack slots and `floor` is the value used for them. A dispatch hook lists the entry call first, as `pc` 4294967295. |
| `hooks[].untrusted` | The hook takes `arg:untrusted` pointers: its key and value are `const void *`. |
| `hooks[].copied` | The value is a stack copy. |
| `hooks[].static` | The hook is static; read every argument as a `u64`. |
| `hooks[].read_only` | A typed lookup hook on a `BPF_F_RDONLY_PROG` map. |
| `hooks[].dead_in_this_load` | `true` when this generated hook is absent from the loaded program's `func_info`. Do not try to attach to it in this load. |
| `hooks[].dead_cause` | Why a dead hook was marked. Currently this says that the verifier removed the generated hook as unreachable in this load. |
| `hooks[].sites[].dead_in_this_load`, `dead_cause` | A site is dead only when every generated hook that reports that site is absent. For example, an absent miss hook does not make a site dead while its hit hook remains. |
| `skipped` | Map calls that `auto` did not instrument, with the site fields and a `reason`. |
| `dead_check_error` | Present when one or more hook comparisons failed. Affected hooks, and any site they may report, remain unmarked; independently confirmed absent hooks and sites can still be marked. Consumers must not guess from an unmarked result. |

Treat a marked site as having no live observation point in this load, not as an attach failure.
The marks describe this program load only; a configuration change can make the same generated hook live on the next load.

### Lookups file

`--lookups-json FILE` lists every XDP, tc, cgroup_skb and netfilter program the target loads with BTF, whether or not a rule selects it.
Use it to write a rule before a run that injects:

```sh
bpf-ninja inject-run --lookups-json lookups.json -- ./loader
jq '[.programs[].rule | .dispatch = true | .maps = ["sessions"]]' lookups.json > rules.json
bpf-ninja inject-run --config rules.json --hooks-json hooks.json -- ./loader
```

The listing runs before any transform and does not change the load.
`inject-run` leaves out programs without BTF or `func_info`, or whose calls it cannot list, and reports them in the diagnostic.
It writes the file like the hooks file: the file exists before the target starts and is rewritten after each listed load.

```json
{
  "version": 2,
  "programs": [
    {
      "program": "p",
      "func": "entry_with_long_name",
      "type": "XDP",
      "ctx_type": "xdp_md",
      "stack": {
        "source": "verifier",
        "kernel": "7.0.0",
        "frame_rounding": 16,
        "functions": [
          {"name": "entry_with_long_name", "verified_depth": 8, "text_depth": 4,
           "text_exact": true, "floor": -8,
           "slots": {"ctx": -16, "key": -24, "result": -32, "map": -40, "value": -48}}
        ]
      },
      "maps": [
        {"name": "sessions", "type": "Hash", "sites": [6], "ops": ["lookup"]}
      ],
      "lookups": [
        {"kind": "lookup", "pc": 6, "map": "sessions", "func": "entry_with_long_name",
         "frame": "entry_with_long_name", "floor": -8}
      ],
      "calls": [
        {"kind": "lookup", "pc": 6, "map": "sessions", "func": "entry_with_long_name",
         "frame": "entry_with_long_name", "floor": -8}
      ],
      "rule": {
        "program": "entry_with_long_name",
        "auto": true,
        "maps": ["sessions"],
        "hook": "ninja"
      }
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `maps` | Every map the program references. Maps with lookups come first, in the order of their first lookup, with each lookup's `pc` in `sites`. The others follow by name. `ops` lists the ops called on each map. |
| `lookups` | The lookup calls, with the fields of a hooks-file site. |
| `calls` | Every lookup, per-CPU lookup, update, delete, push, pop and peek call, with the op as `kind`. |
| `reason` on a lookup or call | `auto` would skip it, unless it also has `"generic": true`, which means `auto` sends it to the generic hook. |
| `ctx_source` on a lookup or call | The proven source used to initialize the site's frame: `entry`, `r6` through `r9`, or an aligned slot such as `fp-80`. It is omitted when no source was proven. |
| `frame`, `floor` on a lookup or call | The function frame that owns the site and the floor used to place its spill slots. |
| `stack` | The trial load's verifier accounting. A function with `skip_reason` is not instrumented; `dead` means the verifier omitted that function from this load. |
| `rule` | A rule that instruments the lookups on every named map. Its `program` is the entry function name. Edit `maps`, and add `ops`, `dispatch`, `entry` or `tail_calls` as needed. |

A program loaded twice is listed twice.

### Map listing of a running program

`bpf-ninja -p ID --list-progs --list-maps` shows the functions of a loaded program, the functions each one calls, and every map it uses, with the op and source line.
With `--lookups-json`, it also reads the file `inject-run` wrote for the same load and marks whether `auto` can instrument each call:

```sh
bpf-ninja inject-run --lookups-json lookups.json -- ./loader &
bpf-ninja -p "$PROG_ID" --list-progs --list-maps --lookups-json lookups.json
```

```text
prog 2  entry
├─ func entry  (calls: classify, global_sub)
│  ├─ map stats   Array         lookup     prog.c:29  ✓ injectable  (inlined, pc 7)
│  ├─ map flows   Hash          delete     prog.c:33  ✓ injectable  (pc 18)
│  └─ map jmp     ProgramArray  tail_call  prog.c:35  → prog 3
├─ func classify
│  ├─ map flows   Hash          lookup     prog.c:11  ✗ function has no context parameter  (pc 33)
│  └─ map flows   Hash          update     prog.c:14  ✗ context is not held in a callee-saved register or an 8-byte slot at the site  (pc 45)
├─ func global_sub
│  └─ map routes  LPMTrie       lookup     prog.c:21  ✗ a caller does not pass the context (entry@42)  (pc 56)
└─ prog 3  next_stage  (tail call: jmp[0])
   └─ func next_stage
      └─ map flows  Hash  update  prog.c:45  ✓ injectable  (pc 11)
```

- Each `map` line gives the map's name and type, the op, and the source line of the call, or of the map load when the op is unknown.
- `✓ injectable` marks a call `auto` can instrument, with `(generic hook)` when it goes to the generic hook.
  `✗` gives the reason `auto` skips it, and `? not in the lookups file` means no load-time call matched.
  Without `--lookups-json` there is no status column and no `pc`.
- In parentheses, `inlined` marks an array lookup the verifier inlined, and `pc` is the load-time index the lookups and hooks files use.
- A tail call or redirect shows the program it reaches (`→ prog 3`), with or without `--lookups-json`.
  A reached program's line names the maps and keys that reach it, such as `(tail call: jmp[0-1], alt[7])`.

The listing reads the translated instructions the kernel keeps, so it needs root.
There the verifier has replaced map helpers with calls to the map's own functions, whose kernel symbols give the op.
Without access to kernel addresses (`kptr_restrict`), the op shows as `ref`.
Each use is matched, in order, to the load-time call with the same op, map, function, file and line.
The program is found by its entry function; a program loaded more than once uses its last load.
With `--json`, each program gets a `maps` list of functions with their `calls`, `callbacks` and `uses`.
A use's `pc` there indexes the translated instructions, and its `site` and `reason` come from the lookups file.

## Diagnostics and failures

By default `inject-run` fails open for transformation, metadata, BTF-load, substituted kernel-load, and checker failures: a rejected transform loads unchanged.
If the checker is not applicable, the substituted program loads without validation by default.
Diagnostics go to stderr:

| Diagnostic | Meaning |
|---|---|
| `program "P": untrusted hook form F (REASON)` | The hook form chosen for a matched load. |
| `program "P": checker accepted sites=N hooks=N floor=N` | The assembled substituted stream passed the load-stream checker. |
| `program "P": checker not applicable: REASON; load not validated` | The checker cannot pair this stream. The substituted load proceeds unchecked by default; `--fail-closed` returns `EPERM`. |
| `program "P": injection skipped: checker rejected the transform: ERR; probe was not installed; attempted ...` | The stream could not be read or decoded, or the checker rejected it. The original program is retried by default; `--fail-closed` returns `EPERM`. |
| `program "P": injected hook "H" (...), tracee fd N` | The rewritten program loaded. The line names each hook with its map and site PCs, then each site `auto` skipped and why. After a [jump sequence limit](#jump-sequence-limit) retry it ends with `, lookup branches miss-first`. |
| `program "P": ...: verifier jump sequence limit: ...; retrying with lookup misses first` | The verifier refused the rewritten program with `The sequence of N jumps is too complex`; see [Jump sequence limit](#jump-sequence-limit). |
| `program "P": injection skipped: ERR[; attempted ...]` | A read, metadata, transform or BTF-load error, or the kernel rejected the rewritten program. After a rejection the line names the hooks it attempted. |
| `bpf command N: injection skipped: ERR` | `inject-run` could not read or accept the arguments of a `BPF_BTF_LOAD` or `BPF_PROG_LOAD` call, for example a matched load without BTF, or two rules match the same load (`ambiguous program selectors`). |
| `global arg:untrusted probe inconclusive: ERR` | The probe failed for a reason other than the tag. The global form is kept. |
| `program "P": lookup discovery skipped: ERR` or `failed: ERR` | `--lookups-json` could not list this program. |
| `program "P": cannot query program ID: ERR` | The hooks file lists the program with `prog_id` 0. |
| `program "P": map "M" types from ELF sha256 ...: key "K", value "V"` | `map_btf` supplied these types. |

When the rewritten load fails, `inject-run` retries the original syscall with its original arguments.
It also retries the original syscall after a checker read, decode, or validation failure.
It does not retry with another hook form; the only other rewrite it tries is the one in [Jump sequence limit](#jump-sequence-limit).
The loader's verifier log buffer can still hold the log of the attempted load.
After an inconclusive probe, a rejection with `EINVAL`, `EOPNOTSUPP` or `EACCES` of a program with untrusted hooks adds a hint.
The hint always suggests `"static_untrusted": true`; for a read-only map's lookup hook it also offers `"copy_read_only": true` as an alternative.
A target that exits successfully has not necessarily been injected; check the diagnostic or the hooks file.

### Jump sequence limit

The verifier keeps at most 8192 branches pending on one path.
The rewrite tests each lookup's result before its hooks, which keeps one more branch pending until the verifier returns to it.
By default the hit follows that test and the miss waits, which costs nothing where the program goes on after a miss, but leaves one more pending branch per site, and per loop iteration, where the program goes on after a hit.
A program close to the limit, such as LoxiLB's `tc_packet_func_fw`, then fails with `The sequence of 8193 jumps is too complex`.

When the rewritten load of a program with hit or `any` lookup hooks fails, `inject-run` loads it once more with a verifier log of its own, without touching the loader's log, to read why.
If the reason is this limit, it rewrites the program with every lookup's miss following the test and the hit waiting, and loads that; the loader's log buffer then holds that load's log.
The miss-first layout has the opposite cost, so it is only the fallback.
A refused load binds no map, so the earlier attempts leave nothing behind.
If the second layout fails as well, the load continues as any failed rewrite does: the original program, or `EPERM` with `--fail-closed`.

With `--fail-closed`:

- a matched program that cannot be injected gets `EPERM`;
- so does a `BPF_BTF_LOAD` or `BPF_PROG_LOAD` call whose arguments `inject-run` cannot read, since it cannot tell whether the call matches;
- unmatched programs still load unchanged.

### Load-stream check

Previously, `inject-run` transformed and marshalled the substituted stream without invoking the existing independent checker on the load path.
`inject-run` labels the original decoded instructions, derives hook ranges and plan-based site targets after transformation, and marshals the result.
After allocating the substituted `bpf_attr` and instruction buffer in the tracee, it reads back the exact byte range named by `attr.insns` and `insn_cnt`.
It decodes and checks that byte range immediately before resuming the stopped thread for `BPF_PROG_LOAD`.
No option is needed to enable this check.

The check establishes that the bytes read at that moment satisfy `pkg/injectcheck` under the trial load's per-function floors and plan-derived site targets.
It does not freeze tracee memory, so a sibling thread can still mutate the instruction buffer after the read and before the kernel copies it.
It also does not establish kernel acceptance, BTF meaning, fd identity, verifier correctness, JIT correctness, or behavior of externally attached observers.

The checker cannot pair an indirect `callx` instruction with its target.
`inject.BuildLookupTargets` therefore returns `inject.ErrCheckerNotApplicable` for a matched transformed stream containing `callx`.
By default `inject-run` reports `checker not applicable: cannot pair indirect callx at instruction N; load not validated` and loads the substituted stream unchecked, preserving programs such as Kmesh that use indirect BPF calls.
With `--fail-closed`, it refuses that load with `EPERM`.

A program with an indirect jump (`BPF_JA|BPF_X`) is not rewritten.
Its jump table holds instruction indexes of the original program, and the table is frozen before the load, so inserted instructions would send the jump to the wrong place.
`inject-run` skips the trial load too, because a successful load binds the table for good.
It then loads the original program, even under an explicit rule, or refuses with `EPERM` under `--fail-closed`.

In both modes:

- an invalid configuration fails before the target starts;
- a broken ptrace stop sequence, a failed register restore or a failed scratch cleanup is fatal, and `inject-run` kills and reaps the target;
- SIGINT or SIGTERM sent to `inject-run` kills the target instead of being forwarded to it;
- the kernel kills the target if the tracing thread dies (`PTRACE_O_EXITKILL`).

## Limits

- `inject-run` supervises only the launched process and its threads.
  It does not follow children from fork or vfork, and it detaches a separate process created by clone.
  `inject-run` cannot attach to a running process.
- Sibling threads keep running while the loading thread is stopped.
  The checker reads the substituted stream immediately before resuming the loading thread, but it does not stop a sibling from changing that buffer afterward.
  Do not use `inject-run` with loaders that change load buffers, replace referenced fds, unshare fd tables or exec while another thread loads a program.
- `inject-run` forwards ordinary signals outside syscall replay.
  It does not fully support job-control stops, seccomp tracing and notification, or uncatchable signals during replay; an unexpected stop during replay ends supervision.
- `inject-run` handles only native x86-64 `bpf(2)` calls.
  Compat and x32 calls pass through without injection.
- `inject-run` can rewrite only XDP, tc (`SchedCLS`, `SchedACT`), cgroup_skb (`CGroupSKB`) and netfilter (`Netfilter`) programs loaded with BTF and `func_info`.
  In cgroup_skb and netfilter programs the packet starts at the network header, so `--func` records have no Ethernet header.
  A loader without `CAP_BPF` cannot load BTF, so `inject-run` skips its cgroup_skb programs: they load unchanged, or, when a rule matches the load, are refused with `--fail-closed`.
- It instruments map calls in the entry function and in called subprograms whose BTF parameter, callers and held context value can all be proved, and in `bpf_loop` and `bpf_for_each_map_elem` callbacks that the entry function passes a pointer into its own frame, at the same offset at every call.
  Such a callback loads the context from the entry's context slot through that pointer on entry, and its sites report `ctx_source` `callback:r2:fp-104`: the register the callback receives the pointer in, and the pointer's offset in the entry frame.
  A callback site's hook takes untrusted pointers unless its key, and an update's value, are the callback's own stack (see [Load on kernels without `arg:untrusted`](#load-on-kernels-without-arguntrusted)).
  Other callbacks and unproved sites remain skipped.
  A static function without a held context gets one passed down from the entry: it stores the context into its context slot on entry, from its own proved context parameter, or from an argument register that it never reads before writing it and that every direct call to it first loads from the caller's context slot, the entry's or that of another such function.
  Its sites report `ctx_source` `pass:r5@120,saved-r1@40`: the register and decoded start index of the site's function and of each function above it, `saved-` marking one that saves its own parameter.
  The kernel does not check the context a generated static hook receives, so these proofs and the checker are what stand behind it.
  One rule applies per program.
- A function-name selector uses the BTF `inject-run` saw the loader load.
  It may not match when the BTF fd was duplicated, inherited, passed in from outside, or evicted from the 64 MiB cache.
  Use the kernel program name then.
- Loads must use 8-byte `func_info` and 16-byte `line_info` records.
  Each input buffer can be at most 16 MiB, and the attr at most 4096 bytes.
  `inject-run` refuses loads with kernel-side CO-RE records, fd arrays, tokens, signatures or other unknown extensions.
- A program with an indirect jump (`BPF_JA|BPF_X`) is never rewritten, so its sites are not observed and it does not appear in `--lookups-json`.
- A program that a rule matches or `--lookups-json` discovers, and that references a `BPF_MAP_TYPE_INSN_ARRAY` map without an indirect jump, fails to load under `inject-run`, even when failing open.
  A successful trial load binds the array, so the loads that follow get `EBUSY`; the loader may report a different final error after retrying.
- The integration tests use a Go loader built on cilium/ebpf.
  C and libbpf loaders go through the same syscall path but have no integration test.

[bpf-syscall-hook-design.md](bpf-syscall-hook-design.md#remaining-work) lists the work needed to lift these limits.

## Kernel requirements

| Need | For | Kernel |
|---|---|---|
| `PTRACE_GET_SYSCALL_INFO` | `inject-run` itself | 5.3 or newer |
| `arg:untrusted` on global functions | the global form of untrusted hooks | 6.18 or newer in CI; older kernels get static hooks automatically |
| static BPF functions | static hooks | 6.1 or newer in CI |
| BPF JIT enabled | any hook in a program that calls `bpf_tail_call` | x86-64 JIT on; otherwise the rewritten load fails |
| fentry and kernel BTF | `--func` capture and observers at a hook | kernel BTF (`/sys/kernel/btf/vmlinux`) |
| `bpf_get_func_arg` | `--arg-filter` on pointer members at a hook | 5.17 or newer |
| `bpf_get_func_ret` | exit and gated capture at a static hook whose ctx is read with `bpf_probe_read_kernel` | 5.17 or newer |
| more than one tracing attach to a program that tail-calls | several observers or captures on such a program | any but 7.0 to 7.2.5; use `dispatch` there |

CI runs the `pkg/inject` hook tests on 6.1, 6.6, 6.12, 6.15, 6.18, 7.0, 7.1, 7.2 and 7.3-rc4.

## See also

- [inject-walkthrough.md](inject-walkthrough.md): one program from the map listing to a trace and a capture.
- [inject-observers.md](inject-observers.md): small fentry observers.
- [lookup-site-injection.md](lookup-site-injection.md): the hook ABI and the `pkg/inject` API.
- [bpf-syscall-hook-design.md](bpf-syscall-hook-design.md): how the supervisor works, its tests and remaining work.
