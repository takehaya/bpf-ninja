# Design: retrofit injection through the bpf(2) syscall

Status: the [raw-load front end](lookup-site-injection.md#raw-load-api) and a Linux x86-64 ptrace launcher prototype are implemented.
`bpf-ninja inject-run --config rules.json -- ./target` transforms loads in the target through `inject.TransformLookupRaw`.
The privileged integration test verifies the hook in the child's loaded program and executes it with `BPF_PROG_TEST_RUN`.
See [inject-run](inject-run.md) for usage, failure behavior and limits.

## The problem this solves

`pkg/inject` transforms an ELF before it is loaded.
Using it today requires the target's own loader to call us, or to load an ELF we produced.
We want the model `mptcpize` uses: run an unmodified binary under a wrapper, and transform its BPF programs as they load, with no change to the target's source, files, or loader.

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
| `ptrace` supervisor | Go and statically linked loaders | `PTRACE_SYSCALL`, rewrite tracee registers and memory at `bpf(2)` | larger, but language-independent |
| seccomp user-notify | nothing here | can skip a call or replace its return, but cannot swap in larger instruction or BTF buffers with new pointers | rejected as the wrong tool |

The plan is to ship the `ptrace` supervisor first, since it reaches Go loaders, and to add the `LD_PRELOAD` shim later for C loaders.
Both drive the same transform core.

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

On `BPF_BTF_LOAD`, parse the BTF blob and remember it under the fd the kernel returns.
At this point we cannot yet know whether the BTF belongs to a program we will transform, so we remember every BTF, which is cheap.

On `BPF_PROG_LOAD` of a matched program, the supervisor builds the hook's types and extends the program's BTF using the raw transformer.
It injects `bpf(BPF_BTF_LOAD)` into the tracee, so the new fd belongs to the tracee.
Loading extended BTF only in the supervisor would produce an unusable `prog_btf_fd` for the target; the prototype therefore loads it directly in the target and does not perform a redundant supervisor load.
It builds a copied attr with that fd, transformed instructions, and the updated `func_info` and `line_info` in an injected anonymous mapping.
After the injected `BPF_PROG_LOAD`, it closes the temporary BTF fd, unmaps the scratch memory, and returns the program fd through the target's saved registers.

The placement rule from `b87bc75`, which puts the hook right after the entry function, applies here and matters more.
On the ELF path a verifier rejection is a failed load we can diagnose and retry.
The prototype retains the original attr and buffers so a rejected transformed load can be retried unchanged before the syscall returns to the target.

## Selection and failure behavior

Selection reuses the existing map-name, function, and line selector, with the program chosen by name from `func_info[0]` or the program name in `attr`.
The target process has no CLI of ours, so a config file or environment variable states what to inject and where.

The failure rule is to fail open by default for extraction, transform, and kernel-load errors.
A transform or BTF error must not silently pass a load the original would have rejected, and must not break a load the target needs.
On any such error, log it, pass the original load through unchanged, and record for that program that injection did not happen.
Refusing the load with `EPERM` instead is opt-in through `--fail-closed`.
Loss of ptrace control is fatal in either mode: the supervisor terminates the target rather than resuming it with uncertain registers or memory.

The supervisor sees every `bpf(2)` the target makes, including map creation and link attachment.
Everything it does not transform it passes through untouched.

## How the supervisor handles a load

The launcher uses Go's fork/exec support with `PTRACE_TRACEME` and keeps ptrace operations on one locked OS thread.
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
The original instruction and metadata buffers stay intact, so a rejected load can be retried unchanged.
The caller's verifier log and `log_true_size` output are preserved as syscall outputs.

The wire offsets and stop discriminators follow the Linux [BPF UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h) and [ptrace UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/ptrace.h).

## Prototype decisions

The prototype makes the following choices.

1. Inject `mmap` and repoint a copied attr; the integration test covers a Go tracee with a larger instruction stream and additional function metadata.
2. Launch with `PTRACE_TRACEME`, then use `PTRACE_SYSCALL` and follow threads with `PTRACE_O_TRACECLONE`.
   The command is `inject-run` to distinguish transformation from ordinary packet observation.
   Attaching to an existing process and supervising forked processes remain TODO.
3. Attach an fentry observer separately with the existing observation commands.
   The launcher adds the hook but does not attach an observer.
4. CO-RE.
   By load time the CO-RE relocations are already applied in the instructions, so we inherit a resolved program, which helps.
   The raw transformer preserves original type IDs; the integration fixture carries its own BTF.
   Kernel-side CO-RE records and fd arrays are refused until their offsets and references can be relocated.

## Remaining work

These mechanisms would lift the [launcher's limits](inject-run.md#limits):

- Child processes: add `PTRACE_O_TRACEFORK` and `PTRACE_O_TRACEVFORK`, keep per-process fd caches and thread groups, and handle nonleader exec identity changes across the process tree.
- Attaching to a running process: `PTRACE_SEIZE` every `/proc/<pid>/task` entry, and recover BTF loaded before the attach.
- Concurrent threads: use a seize-based launcher with `PTRACE_INTERRUPT` to stop all siblings, drain their stops, snapshot inputs and fd identities, and resume them after the load.
- Signals and seccomp: tell group stops apart with `PTRACE_GETSIGINFO`, use `PTRACE_LISTEN` after switching to `PTRACE_SEIZE`, and model `PTRACE_EVENT_SECCOMP` and syscall restarts.
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
Only the explicit non-root guard skips them.
