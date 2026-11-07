# Design: retrofit injection through the bpf(2) syscall

`bpf-ninja inject-run` implements this design on Linux x86-64 with a ptrace supervisor and the [raw-load front end](lookup-site-injection.md#raw-load-api) of `pkg/inject`.
`bpf-ninja inject-run --config rules.json -- ./target` transforms loads in the target through `inject.TransformLookupRaw`.
See [inject-run](inject-run.md) for usage, failure behavior and limits.

## The problem this solves

`pkg/inject` transforms an ELF before it is loaded.
Using it directly requires the target's own loader to call it, or to load an ELF that it produced.
The goal is the model `mptcpize` uses: run an unmodified binary under a wrapper, and transform its BPF programs as they load, with no change to the target's source, files, or loader.

The interception point is the `bpf(2)` syscall.
At `BPF_PROG_LOAD` the kernel already has the final instruction stream, the map file descriptors resolved into `ld_imm64` as `BPF_PSEUDO_MAP_FD`, a `prog_btf_fd`, and `func_info` and `line_info`.
That is everything `pkg/inject` needs.
The one difference from the ELF path is that it arrives as raw syscall arguments rather than as an ELF.

## Why LD_PRELOAD alone is not enough

`mptcpize` overrides a libc symbol through `LD_PRELOAD`.
That reaches only the loaders that issue `bpf(2)` through libc, such as libbpf, bpftool, and other C agents.

Many loaders worth instrumenting do not.
Cilium, eUPF, and Ella Core are Go programs built on `cilium/ebpf`, which issues `SYS_bpf` directly through the Go runtime and never calls the libc `bpf()` wrapper.
An `LD_PRELOAD` override of `bpf()` or `syscall()` never observes those calls.
This constraint, not a preference, decides the backend: an `LD_PRELOAD`-only tool cannot instrument these Go loaders.

The general interception that does reach a Go process is `ptrace`.
A supervisor stops the target on entry to `bpf(2)`, reads and rewrites its registers and memory, and lets the call proceed.
This works at the syscall boundary, below libc, so the loader's language does not matter.

| Backend | Reaches | Mechanism | Cost |
|---|---|---|---|
| `LD_PRELOAD` shim | C/libbpf loaders, dynamically linked | override `bpf()`/`syscall()`, rewrite `attr`, call the real syscall | small, the `mptcpize` model |
| `ptrace` supervisor | any loader, including Go and statically linked ones | `PTRACE_SYSCALL`, rewrite tracee registers and memory at `bpf(2)` | larger, but language-independent |
| seccomp user-notify | nothing here | can skip a call or replace its return, but cannot swap in larger instruction or BTF buffers with new pointers | rejected as the wrong tool |

`inject-run` uses the `ptrace` supervisor, since it reaches Go loaders as well as C loaders.
An `LD_PRELOAD` shim would drive the same transform core, but none exists.

## What the transform core must accept

The core needs an entry point that takes raw load inputs instead of an ELF.
Three inputs change.

The instructions arrive as a `struct bpf_insn[]` to decode rather than an ELF section.

Map identity arrives as a file descriptor, not a map definition.
Each `ld_imm64 BPF_PSEUDO_MAP_FD` names a map fd, and an injected `BPF_OBJ_GET_INFO_BY_FD` executed by the tracee on that fd returns the map's `btf_id` with `btf_key_type_id` and `btf_value_type_id`.
The supervisor cannot query a tracee fd directly: fd numbers are local to the owning process.
It can open the returned system-wide BTF ID with `BPF_BTF_GET_FD_BY_ID` and read the types, subject to its own permissions.
This is the default source of key and value types.
For a map with `btf_id == 0` and no existing key/value types, an explicit rule with `map_btf.elf` and required `map_btf.sha256` can instead supply ordinary data types from an operator-selected, SHA-256-pinned ELF; see [map types from a loader ELF](inject-run.md#map-types-from-a-loader-elf).
The supervisor refuses special fields and pointer-ABI types before supplementation, so only hook metadata changes.
Existing live-map BTF is never replaced; the operator remains responsible for matching the ELF layout to the actual map, since the digest pins a choice rather than proving its provenance.

The program BTF arrives behind `prog_btf_fd`, alongside `func_info` and `line_info`.

Site discovery already runs on a flattened instruction slice in `DiscoverLookups`, so that logic carries over.
What changes is where the inputs come from.

## The hard part: BTF loads before the program

The hook needs a BTF `FUNC` and `FUNC_PROTO` for `int hook(struct xdp_md *, const KEY *, const VALUE *)`, and a `func_info` row that points at the `FUNC`.
But BTF is loaded by an earlier, separate `BPF_BTF_LOAD`, and `BPF_PROG_LOAD` only references it by fd.
So the supervisor has to intercept `BPF_BTF_LOAD` as well.

At a `BPF_BTF_LOAD`, the supervisor cannot yet know whether the BTF belongs to a program it will transform, so it remembers every BTF blob under the fd the kernel returns.
At a matched `BPF_PROG_LOAD`, it extends that BTF with the hook's types and loads the result inside the tracee, because a BTF fd the supervisor owns would be useless as the target's `prog_btf_fd`.
[How the supervisor handles a load](#how-the-supervisor-handles-a-load) gives the steps.

The transform places the hooks right after the entry function, which avoids a kernel verifier bug; see [Inserted instructions](lookup-site-injection.md#inserted-instructions).
The supervisor keeps the original attr and buffers, so it can retry a rejected transformed load unchanged before the syscall returns to the target.

## Selection and failure behavior

Selection reuses the existing map-name, function, and line selector, with the program chosen by name from `func_info[0]` or the program name in `attr`.
The target process has no CLI of ours, so a config file or environment variable states what to inject and where.

The failure rule is to fail open by default for extraction, transform, and kernel-load errors.
A transform or BTF error must not silently pass a load the original would have rejected, and must not break a load the target needs.
On any such error, log it, pass the original load through unchanged, and record for that program that injection did not happen.
Refusing the load with `EPERM` instead is opt-in through `--fail-closed`.
Loss of ptrace control is fatal in either mode: the supervisor terminates the target rather than resuming it with uncertain registers or memory.

## How the supervisor handles a load

The launcher uses Go's fork/exec support with `PTRACE_TRACEME`, moves the target to `PTRACE_SEIZE` before it runs, and keeps ptrace operations on one locked OS thread.
Its wait loop uses broad `wait4(-1)` calls inherited from the original every-syscall implementation, so library callers must not call `Run` from a process that has other children it waits for.
A seccomp filter installed at the target's first syscall limits the stops to program and BTF loads; where it cannot be installed, the target stops on every syscall ([inject-run.md](inject-run.md#syscall-stops)).
Child processes inherit the filter, so with it the supervisor also follows them with `PTRACE_O_TRACEFORK` and `PTRACE_O_TRACEVFORK`, without instrumenting them, until each has exited, also after the target has; it resumes group stops with `PTRACE_LISTEN`.
It follows target threads with `PTRACE_O_TRACECLONE` and uses `PTRACE_GET_SYSCALL_INFO` to tell syscall entry from exit.
It intercepts native x86-64 `SYS_bpf`; compat and x32 calls pass through without injection.
Every original BPF command other than `BPF_BTF_LOAD` and a matched `BPF_PROG_LOAD` passes through untouched.
The supervisor also issues its own metadata and load operations, described below.

At `BPF_BTF_LOAD` entry it copies the blob.
At successful exit it remembers the blob under the returned tracee fd, with the object's kernel BTF ID, which an injected object-info query obtains in the tracee.
At a matched program load it rechecks the live fd's BTF ID before trusting the cache, so a reused fd cannot substitute unrelated cached types.
If needed, it obtains the BTF from the kernel by ID instead.
The cache holds at most 64 MiB and is cleared on exec or when full.

The supervisor reads the instructions, `func_info` and `line_info` from tracee memory to build an `inject.RawProgram`.
For each map reference it injects `BPF_OBJ_GET_INFO_BY_FD` into the tracee, where the map fd is valid.
The returned name, kind, sizes, flags, BTF ID and key/value type IDs identify the map and its ABI.
It opens that system-wide BTF ID in the supervisor with `BPF_BTF_GET_FD_BY_ID` and reads the types, also when maps and programs have separate BTF objects.
It never treats a tracee fd number as a supervisor fd.
A map without BTF, or a side with a zero type ID, keeps its identity and sizes; the transform passes that side as opaque bytes of the map's size.
The kernel does not report an inner-map template's flags, so the supervisor treats every inner map as read-only.

`inject.TransformLookupRaw` produces the new instructions and extended BTF with matching function and line records.
The supervisor injects `bpf(BPF_BTF_LOAD)` into the tracee and puts the returned tracee-owned fd in a copied program attr.
The target's credentials and syscall restrictions govern this load.

Injected syscalls replay the existing two-byte x86 `SYSCALL` instruction at the saved `RIP-2`.
The original program-load syscall is first suppressed with an invalid syscall number to reach an exit stop.
Catchable signals are masked during replay; the saved mask and registers are restored before returning to the target.
Executable memory and the target's stack are not patched.
An injected anonymous read/write `mmap` provides a 64 MiB scratch arena for the larger buffers and the copied attr.
The injected program load points at those buffers; afterwards the supervisor closes the temporary BTF fd and unmaps the arena.
The original instruction and metadata buffers stay intact.
The caller's verifier log and `log_true_size` output are preserved as syscall outputs.

The wire offsets and stop discriminators follow the Linux [BPF UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h) and [ptrace UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/ptrace.h).

## Design decisions

1. Inject `mmap` and repoint a copied attr at the larger instruction and metadata buffers.
2. Name the command `inject-run` to set transformation apart from packet observation.
3. Attach observers separately with the existing observation commands.
   The launcher adds the hooks but attaches nothing.
4. By load time the CO-RE relocations are already applied in the instructions, so the transform works on a resolved program.
   The raw transformer preserves the original type IDs.
   Kernel-side CO-RE records and fd arrays are refused, because the transform does not relocate their offsets and references.

## Remaining work

These mechanisms would lift the [launcher's limits](inject-run.md#limits):

- Child processes: instrument the child processes that the filter path already follows, with per-process fd caches and thread groups.
- Attaching to a running process: `PTRACE_SEIZE` every `/proc/<pid>/task` entry, and recover BTF loaded before the attach.
- Concurrent threads: use a seize-based launcher with `PTRACE_INTERRUPT` to stop all siblings, drain their stops, snapshot inputs and fd identities, and resume them after the load.
- Signals and seccomp: hold signals that arrive during syscall replay, and model the target's own seccomp tracing and notification and syscall restarts.
- Function-name selection: resolve the live BTF ID before preselection, or track fd duplication and inheritance, instead of trusting the numeric fd.
- Load formats: normalize larger known metadata records, relocate every offset-bearing field, and resolve indexed map references before accepting kernel-side CO-RE records and fd arrays.

## What this reuses

This design reuses the instruction-level transform, the placement fix, and the callback relocation already in `pkg/inject`.
It adds a raw-load front end and the `bpf(2)` and `BPF_BTF_LOAD` interception.
The ELF path does not change.

## Tests

Unprivileged tests in `pkg/syscallhook` cover strict config parsing, attr sizes and offsets, target arguments and exit status, threaded launch, cancellation and the failure policy.
Unit tests in `cmd/bpf-ninja` cover the JSON shape of `--hooks-json` and `--lookups-json` and the files they write.

`TestIntegrationLoader` needs the `integration` build tag and root.
It launches the same Go loader directly and under the supervisor, checks the kernel function metadata, and runs the loaded XDP program with `BPF_PROG_TEST_RUN`.
It covers kernel-name and function-name selection, fail-open, fail-closed and unmatched loads.
It checks that the launcher reports each successful injection, and only those, with the program ID the loader sees.
It checks that `maps` instruments the named map and refuses an unknown one, and that discovery reports the loader's lookup among its map calls, with and without a rule.

`TestBpfAutoStatic`, under the same tag, leaves `static_untrusted` unset on a read-only map lookup and on a dispatch rule.
It checks the selected form and reason, and loads and attaches an fentry observer to the injected hook.
A third case replaces the probe result with an unsupported-tag rejection, so static hooks are selected and attached on every kernel.
With `BPF_NINJA_EXPECT_HOOK_FORM` set to `global` or `static`, the real probe's choice must match it; CI sets `global` for its runner kernel.
The loader runs without `-test.v`, and the audit ignores result lines of tests nested inside another test.

[The map types check](../../scripts/test/map-types.py) runs the CLI with a loader that creates a map without BTF.
It exercises the paths with and without `map_btf`, compares selected packet bytes, and checks the refusal of a map that already has BTF.

The tests never attach to an interface, pin objects, or change sysctls, routes or firewall rules.

```sh
go build ./...
go vet ./...
go test ./...
go test -count=50 -timeout 60s ./pkg/syscallhook
sudo -E env PATH=$PATH go test -tags integration -run '^TestIntegrationLoader$' -v -timeout 90s ./pkg/syscallhook
sudo -E env PATH=$PATH go test -tags integration -run '^TestBpfAutoStatic$' -v -timeout 90s ./pkg/syscallhook
```

The privileged tests fail on missing BPF capabilities even when the uid is zero; they do not turn a failed injection into a skip.
Only the explicit non-root guard skips them, and `TestIntegrationIndirectJump` also skips on a kernel that rejects `BPF_MAP_TYPE_INSN_ARRAY` with `EINVAL`.
`scripts/test/privileged.py --syscallhook-binary` still fails on that skip, because the CI runner's kernel has the map type.
