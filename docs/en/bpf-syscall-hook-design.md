# Design: retrofit injection through the bpf(2) syscall

Status: the [raw-load front end](lookup-site-injection.md#raw-load-api) and a Linux x86-64 ptrace launcher prototype are implemented.
`bpf-ninja inject-run --config rules.json -- ./target` transforms loads in the target through `inject.TransformLookupRaw`.
The privileged integration test verifies the hook in the child's loaded program and executes it with `BPF_PROG_TEST_RUN`.
See [inject-run](inject-run.md) for the supported scope, failure behavior, tests, and remaining work; this is not yet a production supervisor for UPFs.
Goal set 2026-10-24.

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

Our targets do not qualify.
Cilium, eUPF, and Ella are Go programs built on `cilium/ebpf`, which issues `SYS_bpf` directly through the Go runtime and never calls the libc `bpf()` wrapper.
An `LD_PRELOAD` override of `bpf()` or `syscall()` never observes those calls.
This constraint, not a preference, decides the backend: an `LD_PRELOAD`-only tool cannot instrument the Go UPFs this research is about.

The general interception that does reach a Go process is `ptrace`.
A supervisor stops the target on entry to `bpf(2)`, reads and rewrites its registers and memory, and lets the call proceed.
This works at the syscall boundary, below libc, so the loader's language does not matter.

| Backend | Reaches | Mechanism | Cost |
|---|---|---|---|
| `LD_PRELOAD` shim | C/libbpf loaders, dynamically linked | override `bpf()`/`syscall()`, rewrite `attr`, call the real syscall | small, the `mptcpize` model |
| `ptrace` supervisor | Go and statically linked loaders (our UPFs) | `PTRACE_SYSCALL`, rewrite tracee registers and memory at `bpf(2)` | larger, but language-independent |
| seccomp user-notify | nothing here | can skip a call or replace its return, but cannot swap in larger instruction or BTF buffers with new pointers | rejected as the wrong tool |

The plan is to ship the `ptrace` supervisor first, since it reaches the Go UPFs, and to add the `LD_PRELOAD` shim later for C loaders.
Both drive the same transform core.

## What the transform core must accept

The core needs an entry point that takes raw load inputs instead of an ELF.
Three inputs change.

The instructions arrive as a `struct bpf_insn[]` to decode rather than an ELF section.

Map identity arrives as a file descriptor, not a map definition.
Each `ld_imm64 BPF_PSEUDO_MAP_FD` names a map fd, and an injected `BPF_OBJ_GET_INFO_BY_FD` executed by the tracee on that fd returns the map's `btf_id` with `btf_key_type_id` and `btf_value_type_id`.
The supervisor cannot query a tracee fd directly: fd numbers are local to the owning process.
It can open the returned system-wide BTF ID with `BPF_BTF_GET_FD_BY_ID` and read the types, subject to its own permissions.
That call replaces reading the key and value types from the ELF.

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

## Prototype decisions and remaining work

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

The remaining ptrace work includes stopping sibling threads during snapshots, following fork/vfork with per-process fd identity, handling job-control stops, and supporting seccomp interactions.
The [launcher guide](inject-run.md#limits-and-todos) specifies the mechanisms needed.

## What this reuses

This design reuses the instruction-level transform, the placement fix, and the callback relocation already in `pkg/inject`.
It adds a raw-load front end and the `bpf(2)` and `BPF_BTF_LOAD` interception.
The ELF path does not change.
