# Functions missing from a loaded program

If fentry/fexit reports `Subprog <name> doesn't exist`, check the program ID and exact BTF function name:

```sh
sudo bpf-ninja -p "$PROG_ID" --list-funcs
sudo bpf-ninja -p "$PROG_ID" --func "$FUNC" --list-params
```

A BTF name alone does not guarantee that a function is attachable.
`absent_from_loaded_func_info` means the BTF FUNC exists but is absent from this program's `func_info`.
If the function belongs to this program, the verifier removed it as unreachable in this load, for example because a feature was disabled by configuration.
Nothing in that removed function can run now.
Loading the program again with that feature enabled makes it observable.
Kernels without lazy verification of global subprogs keep these global functions.
That mechanism first shipped in Linux v6.8 with [commit 2afae08c9dcb8ac648414277cec70c2fe6a34d9e](https://github.com/torvalds/linux/commit/2afae08c9dcb8ac648414277cec70c2fe6a34d9e).
Our tests on 6.1 kept them and on 7.0 removed them; retention depends on the kernel and backports.
Disabled static functions can be removed on 6.1 too.
Shared BTF may instead describe a function whose body belongs to another program; target that program.
Absence alone cannot distinguish these causes.

`present` means the BTF type ID occurs in the loaded program's `func_info`; attachment still depends on the kernel's other checks.
`missing_btf_func` means the exact BTF FUNC name is missing.
`not_in_target_program` identifies an external BTF declaration without a body in this target.
`unknown` means membership could not be checked, for example because reading `func_info` was denied or unsupported.
A zero function count can indicate missing CAP_BPF.
Unknown targets still go through kernel validation; a failed load retains its original verifier error and full log.
Names are never guessed or redirected to another program.

A single distinct program/function request fails with the full diagnostic, even if the same `--func` name is repeated.
Multiple distinct `--func` names or multiple programs skip unavailable targets, warn with a short reason for each, and print separate counts for absent functions and external declarations on stderr.
BTF names missing from some selected programs are silently skipped, as before; a name missing from every selected program is an error.
If no attachable targets remain, the command fails with one link to this troubleshooting page and without JSON on stdout, as on other resolution errors.
`--list-params --json` keeps its array of attachable entries containing `func`, `id`, and `params`; skipped targets appear only in stderr warnings.
Normal capture output remains packet data; `--json` applies only to listings.
