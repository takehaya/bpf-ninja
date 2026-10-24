# Design: retrofit injection through the bpf(2) syscall

Status: the [raw-load front end](lookup-site-injection.md#raw-load-api) exists as `inject.DiscoverLookupsRaw` / `inject.TransformLookupRaw`; syscall interception remains unimplemented.
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
Each `ld_imm64 BPF_PSEUDO_MAP_FD` names a map fd, and `BPF_OBJ_GET_INFO_BY_FD` on that fd returns the map's `btf_id` with `btf_key_type_id` and `btf_value_type_id`.
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

On `BPF_PROG_LOAD` of a matched program, build the hook's types, append them to that program's remembered BTF blob, and load the extended BTF ourselves to get a new fd.
Rewrite `attr.prog_btf_fd` to that fd, add a `func_info` row for the hook with the new type id, and fix the `func_info` and `line_info` counts and offsets across the insertion exactly as the ELF path does.

The placement rule from `b87bc75`, which puts the hook right after the entry function, applies here and matters more.
On the ELF path a verifier rejection is a failed load we can diagnose and retry.
Here the transformed load either passes the kernel or breaks the target, with no second attempt.

## Selection and failure behavior

Selection reuses the existing map-name, function, and line selector, with the program chosen by name from `func_info[0]` or the program name in `attr`.
The target process has no CLI of ours, so a config file or environment variable states what to inject and where.

The failure rule is to fail open by default.
A transform or BTF error must not silently pass a load the original would have rejected, and must not break a load the target needs.
On any such error, log it, pass the original load through unchanged, and record for that program that injection did not happen.
Refusing the load instead is opt-in.

The supervisor sees every `bpf(2)` the target makes, including map creation and link attachment.
Everything it does not transform it passes through untouched.

## Open questions

These need a decision before implementation.

1. The ptrace memory-rewrite strategy.
   Overwrite in place when the transformed program is no larger, padding to fit, or inject an `mmap` into the tracee for a scratch buffer and repoint `attr`.
   The second is general; confirm it against a Go tracee.
2. One supervisor per already-running target, or a launcher that forks, ptraces, and execs the target.
   The launcher gives the `mptcpize` ergonomics, `bpf-ninja run -- ./eupf ...`.
3. Whether the fentry observer on the hook is also injected here, or attached afterward by an ordinary `bpf-ninja` run against the now-present hook.
   The second is smaller and is preferred.
4. CO-RE.
   By load time the CO-RE relocations are already applied in the instructions, so we inherit a resolved program, which helps.
   The appended BTF ids must not collide with the program's own, so verify against a program that carries its own BTF.

## What this reuses

This design reuses the instruction-level transform, the placement fix, and the callback relocation already in `pkg/inject`.
It adds a raw-load front end and the `bpf(2)` and `BPF_BTF_LOAD` interception.
The ELF path does not change.
