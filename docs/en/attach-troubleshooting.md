# Functions missing from a loaded program

If fentry or fexit reports `Subprog <name> doesn't exist`, check the program ID and the exact BTF function name:

```sh
sudo bpf-ninja -p "$PROG_ID" --list-funcs --json
sudo bpf-ninja -p "$PROG_ID" --func "$FUNC" --list-params
```

A name in BTF does not make a function attachable.
`--list-funcs` gives each function an availability reason.

## Availability reasons

| Reason | Meaning |
|---|---|
| `present` | The BTF type ID is in the loaded program's `func_info`. The kernel still runs its other attach checks. |
| `absent_from_loaded_func_info` | The BTF FUNC exists but is not in this program's `func_info`. See [below](#a-function-absent-from-func_info). |
| `missing_btf_func` | No BTF FUNC has this exact name. |
| `not_in_target_program` | The BTF has only an external declaration, with no body in this target. |
| `unknown` | bpf-ninja could not check membership, for example because reading `func_info` was denied or is unsupported. |

A function count of zero means the loader did not supply `func_info`, or the caller lacks `CAP_BPF`.
An `unknown` target still goes through kernel validation; a failed load keeps its verifier error and full log.
bpf-ninja never guesses a name or redirects a request to another program.

Some kernels lose tail-call reachability metadata when a static or global BPF subprogram contains `bpf_tail_call` and calls another BPF subprogram, which can make attached JIT code crash even though the program loaded successfully.
`inject-run` previously could create that shape by adding a hook call.
It now detects rewrites that would introduce the shape, runs a native `BPF_PROG_TEST_RUN` probe once without attaching it, and refuses the affected hook sites if the kernel fails the probe or the result is inconclusive; other sites remain available, and the normal failure policy applies when none remain.

## A function absent from func_info

The reason alone cannot tell these two causes apart:

- The verifier removed the function as unreachable in this load, for example because the configuration disabled a feature.
  Nothing in that function can run now.
  Load the program again with the feature enabled to observe it.
  Any kernel can remove an unreachable static function.
  Only kernels with lazy verification of global subprograms remove an unreachable global function.
  Linux 6.8 added that mechanism in [commit 2afae08c9dcb8ac648414277cec70c2fe6a34d9e](https://github.com/torvalds/linux/commit/2afae08c9dcb8ac648414277cec70c2fe6a34d9e); whether an older kernel has it depends on its backports.
- Shared BTF describes a function whose body belongs to another program.
  Target that program instead.

## Several functions or programs

- A request for one distinct program and function fails with the full diagnostic when that function is unavailable, even if the same `--func` name is repeated.
- With several distinct `--func` names or several programs, bpf-ninja skips unavailable targets.
  It also skips an individual target when the static-context proof refuses it or the kernel rejects that target's observer, while keeping observers that already attached to other targets.
  It warns with a short reason for each, and prints separate counts for absent functions, external declarations, static-context refusals and observer-load failures on stderr.
- A name missing from the BTF of some selected programs is skipped without a warning.
  A name missing from every selected program is an error.
- If no target attaches, the command fails; it never weakens an observer or guesses that a refused context is safe.
- `--list-params --json` prints an array of the attachable entries, each with `func`, `id` and `params`.
  Skipped targets appear only in the stderr warnings.
- `--json` applies only to listings; capture output stays packet data.

## The --list-funcs listing

- `--list-funcs` lists every BTF FUNC, including absent functions and external declarations.
- Functions of other programs that share the object's BTF also show `absent_from_loaded_func_info`, so this reason alone does not mean the verifier removed the function.
- Rows are matched by their exact BTF type IDs, so functions with the same name keep their own availability.
- Text rows show a short reason.
  JSON adds an `availability` object with `reason`, `btf_func_present`, `func_type_id` when known, and `detail` when the availability could not be determined.
- If the availability is `unknown`, text mode prints the first detail once per program.
- `--list-progs --list-funcs` shows the same fields.
