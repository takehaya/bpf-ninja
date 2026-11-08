# regionval

regionval checks a bpf-ninja rewrite offline. It reads a capture file that holds
the original instructions of one program load (O) and the rewritten instructions
that bpf-ninja passed to the kernel (T). It then decides whether every
instruction bpf-ninja inserted keeps the original program's behaviour. It never
loads BPF and needs no privileges.

The answer is binary for each load: `validated` or not. Every failure carries a
reason, and anything regionval does not model counts as a failure. A load that
is not validated may still be correct; regionval is sound, not complete.

regionval is its own Go module, separate from the bpf-ninja binary, and it does
not import bpf-ninja's packages. Its only input is the capture file.

## Running it

Go 1.25 or later is needed. `scripts/corpus.sh` also needs `jq`, `make lint`
needs golangci-lint, and the proof steps need Dafny (see
[Dafny core](#dafny-core)).

```sh
cd tools/regionval
make build                         # ./regionval
./regionval capture.json...        # one JSON result per line on stdout
make test                          # Go tests, no Dafny needed
./scripts/corpus.sh DIR            # every *.json under DIR, with a summary
make ci                            # what CI runs (Dafny, Go tests, golangci-lint)
```

From the repository root, `make regionval-test` runs the Go tests and
`make regionval-check` runs the CI steps.

`scripts/corpus.sh DIR [OUT]` writes the results to OUT (default
`regionval-corpus.jsonl`) and prints how many loads were validated, how many
failed each structure stage, and how many windows failed each rule. It exits
0 if every load is validated, 1 if any is not, and 2 on a usage error, a
missing tool, a build failure or a directory without capture files.

### Output

One JSON object per capture file:

```json
{
  "load": "xsk_def_prog.json",
  "validated": true,
  "structure": {"kappa_ok": true, "edges_ok": true, "ok": true},
  "windows": [
    {"kind": "prologue", "core_kind": "prologue-P1", "func": "xsk_def_prog",
     "start": 0, "end": 1, "validated": true, "reason": "", "paths": 1},
    {"kind": "site", "core_kind": "site", "func": "xsk_def_prog",
     "start": 10, "end": 29, "validated": true, "reason": "", "paths": 2},
    {"kind": "hook", "core_kind": "hook-P7", "func": "ninja_any",
     "start": 39, "end": 41, "validated": true, "reason": "", "paths": 1}
  ],
  "counts": {"windows": 3, "validated": 3, "not_validated": 0,
             "by_kind": {"hook": 1, "prologue": 1, "site": 1}},
  "time_ms": 0,
  "time_us": 497
}
```

- `validated` is true only if `structure.ok` is true and every window is
  validated. Every boolean defaults to false, so a partly filled result never
  reads as validated.
- When the structure check fails, `structure.failed_stage` is one of `load`,
  `decode`, `funcs`, `floors`, `kappa`, `windows`, `edges` or `calls`, and
  `windows` is `null`.
- `load` is the path as given on the command line.
- The command exits 0 whatever the verdicts; it exits 1 only if it cannot
  write a result, and 2 without arguments. Read `validated` to decide.
- `start` and `end` are instruction indices in T, counting a 16-byte
  `ld_imm64` as one instruction.
- A window that is not validated has `rule` (the first failed obligation, see
  [Obligations](#obligations)) and `reason`.
- `paths` is the number of paths regionval explored in the window.

### Capture files

A capture is a JSON object with `"format": 1`. regionval reads these fields and
ignores the rest:

| Field | Content |
|---|---|
| `original_insns_hex`, `transformed_insns_hex` | O and T, 8-byte little-endian instructions |
| `original_func_info_hex`, `transformed_func_info_hex` | `struct bpf_func_info` records (8 bytes each) |
| `transformed_btf_hex` | the BTF blob; function names come from its FUNC types |
| `floors` | `[{"name": func, "floor": f}]`, the lowest stack offset each original function uses |
| `hints.certificate.original` | where each original instruction sits in T; not trusted, the `kappa` check below verifies it |

bpf-ninja does not write capture files yet. The files under
`testdata/captures` were taken from loads on Linux 6.12.

## What it checks

### Structure

The structure check runs on the whole load. Any failure makes the load not
validated.

- `decode`: both streams decode, and each `ld_imm64` has a second slot with
  only `imm` set. Reserved fields of other instructions are checked later, by
  the allowlist, for instructions inside a window.
- `funcs`: func_info and BTF give the function boundaries of O and T. A
  function of T whose name is not in O was inserted (a hook or a wrapper).
- `floors`: each floor entry is unique and in `[-512, 0]`. A function without
  a floor is not a structure failure; its windows fail rule `C1`.
- `kappa`: each original instruction appears in T, in order, with the same
  opcode, registers, offset and immediate. Jump offsets and function references
  must match after relocation. A helper call that bpf-ninja wrapped appears as
  `call W`, and the wrapper W contains the original call exactly once.
- `edges`: each original jump and function reference lands on the relocated
  target.
- `windows`: the inserted code between two original instructions can be cut
  into windows, for example an entry prologue and the prelude of the first
  site do not overlap.
- `calls`: every call to an inserted function targets a function start and
  comes from an allowed place, every inserted function is called (a wrapper
  exactly once), and every inserted instruction belongs to exactly one window.

In the code these checks are tagged S1 (`kappa`), S2 (`edges`) and S3
(window coverage); S10 is the liveness check of rule `P9`.

### Windows

A window is a run of inserted instructions in T, together with the original
helper call it surrounds, if there is one. `kind` in the output is where the
window sits in T, and `core_kind` is the set of obligations it is judged by:

| `core_kind` | Window |
|---|---|
| `site` | code before and after an original helper call |
| `site-P4` | the same around `bpf_tail_call` (no r0 obligation) |
| `site-P8` | the code before `call W`, with the wrapper body W inlined |
| `prologue-P1` | the entry prologue of the program |
| `prologue-P1b` | the prologue of a callback |
| `prologue-P9` | the prologue of a function that receives the context from its caller |
| `passload-P9` | the instructions before a call to such a function that pass the context |
| `hook-P7` | the body of an inserted hook function |

For each window regionval enumerates every path through the inserted code with
a symbolic machine. A path is followed whether or not its branch conditions can
hold, so this covers more paths than can run. At the end of each path it checks
the obligations below by comparing symbolic terms. Two terms that are equal but
written differently compare as unequal, so that case fails closed.

### Obligations

The `rule` of a window that is not validated is one of these. Here f is the
floor of the function that holds the window, and "entry value" is the value a
register or stack byte had when the window started.

| Rule | Obligation |
|---|---|
| `C1` | Every store goes to `r10 + c` and stays below the floor: `-512 <= c` and `c + width <= f`. A window outside a hook needs a floor. |
| `C2` | r6 to r9 and r10 hold their entry values at the window exit. |
| `C3` | The stack bytes `[f, 0)` hold their entry values at the window exit. |
| `C4` | Every branch goes forward and lands inside the window or on the instruction just after it. A hook body ends in `exit`. |
| `C5` | Calls are hook calls, the wrapper call, or the window's original helper call. A path calls at most one hook. |
| `C6` | Every instruction is in the allowlist (below). |
| `site` | A site window has its original helper call and executes it exactly once on every path. For `site-P4` that call is `bpf_tail_call`. |
| `R15` | At the helper call, r1 to r5 hold their entry values. In a wrapper, r4 is not checked for the lookup helpers, which do not read it. |
| `R0` | At the exit of a site or wrapper window, r0 is the helper's result. |
| `P1` | The entry prologue leaves r1 at its entry value. |
| `P1b` | A callback prologue writes no register except r0. |
| `P9` | A pass prologue stores exactly one of r1 to r5 (the register r_G) once, below the floor, and writes no register. The pass load before a call to that function writes only r_G, and r_G is not live at the callee's entry in O. |
| `P7` | A hook body has no store and no call, loads only into r0 to r5, and returns 0. |
| `P8` | The code before `call W` writes only r4 and stores nothing. W stores nothing, does not name r10, contains the original helper call and no other helper call, executes it once, and returns its result. |
| `kind` | The window kind is known. |
| `model` | The path left what the symbolic machine models, for example a load or store whose address it cannot place. |
| `limit` | The window has more than 1024 paths, or a path runs more than 4096 instructions. |

### Allowed instructions

Only these instructions may appear in a window. Each row has an ID that
appears in `C6` reasons. The semantics follow RFC 9669.

| ID | Opcode | Instruction | Zero fields |
|---|---|---|---|
| A64-1 | 0xb7 | `dst = imm` | src, off |
| A64-2 | 0xbf | `dst = src` | off, imm |
| A64-3 | 0x07 | `dst += imm` | src, off |
| A64-4, A64-5 | 0x57, 0x5f | `dst &= imm`, `dst &= src` | src, off / off, imm |
| A64-6, A64-7 | 0x47, 0x4f | `dst \|= imm`, `dst \|= src` | src, off / off, imm |
| A64-8 | 0x67 | `dst <<= imm`, imm in [0, 64) | src, off |
| A32-1 to A32-8 | 0xb4, 0xbc, 0x04, 0x54, 0x5c, 0x44, 0x4c, 0x64 | the same operations on 32 bits, with the upper half cleared; shift in [0, 32) | as for 64 bits |
| LDX-1 to LDX-4 | 0x61, 0x69, 0x71, 0x79 | `dst = *(u32/u16/u8/u64 *)(src + off)` | imm |
| STX-1 to STX-4 | 0x63, 0x6b, 0x73, 0x7b | `*(u32/u16/u8/u64 *)(dst + off) = src` | imm |
| J-1 | 0x05 | `goto +off` | dst, src, imm |
| J-2, J-3 | 0x15, 0x55 | `if dst == imm`, `if dst != imm` (64-bit) | src |
| J-4 | 0x76 | `if (s32)dst >= imm` | src |
| C-1 | 0x85, src 0 | helper call | dst, off |
| C-2 | 0x85, src 1 | call to a BPF function (hook or wrapper) | dst, off |
| E-1 | 0x95 | `exit` | dst, src, off, imm |

No row writes r10, and register numbers above r10 are refused. Everything else
is refused inside a window, including `st` (immediate stores), atomics, xor,
other jump conditions, `ld_imm64`, `ld_abs` and `ld_ind`, kfunc calls,
`callx` and `gotox`. Original instructions outside windows are only compared
with O.

## What it trusts

regionval does not check these. If one is wrong, a `validated` answer can be
wrong.

- **Floors.** The `floors` field comes from the kernel verifier's stack
  report for the original program and is taken as given. The original program
  uses no stack below its floor, so a helper called with the original
  arguments writes only `[f, 0)`.
- **Instruction semantics.** The allowlist rows above, the wire decoder and the
  func_info and BTF parsers match the kernel. The differential tests compare
  the symbolic machine with a separately written interpreter
  (`interp/`); both follow the same table, so they do not test the table
  against the kernel.
- **Calling convention.** A helper call sets r0 to its result, leaves r1 to r5
  undefined and keeps r6 to r10. It may write any stack byte in `[f, 0)`. The
  lookup helpers do not read r4. A call to a hook or wrapper keeps r6 to r10
  and the caller's whole stack; hooks rely on their own `hook-P7` check for
  this. A load from memory outside the stack changes nothing but its
  destination register.
- **The original program is valid.** O passed the verifier, so it never reads
  r1 to r5 after a call before writing them. The liveness used by `P9` relies
  on this and on a table of argument counts for common helpers (unknown helpers
  count as reading r1 to r5).
- **Window cutting and kinds.** The code that cuts T into windows and assigns
  each window's kind (`layout.go`) is outside the checked core. The core
  re-checks the shape of a site, wrapper and pass window, and it rejects an
  unknown kind.
- **What was checked is what was loaded.** The capture records the exact
  instructions given to the kernel.
- **From windows to the program.** regionval shows that every window meets its
  obligations. That these local obligations imply the whole rewritten program
  behaves like the original is argued separately; regionval does not check it.
- The Go toolchain.

## Dafny core

`dafny/` holds a second implementation of the per-window check, written in
Dafny together with a proof that it is sound.

- `dafny/src/Semantics.dfy` and `Bits.dfy` are the concrete semantics of the
  allowed instructions. `Obligations.dfy` states what `Validated` promises.
  These three files are the specification and are trusted.
- `Checker.dfy` and `Terms.dfy` are the checker. `Soundness.dfy` proves that
  if `Validate(insns, spec)` returns `Validated`, then every run of the window
  from any registers, stack, helper results and loaded values meets the
  obligations of `spec`.
- The sources contain no `assume`, `{:axiom}`, `{:verify false}` or
  `{:extern}`, nor the `@Axiom`, `@Verify` and `@Extern` attributes.
  `make check-trust` fails if one appears, or if a file in `dafny/src` is
  missing from the list that `make dafny-verify` verifies.
- `dafny/gen-go` is Go translated from the sources and is checked in.
  `dafny/regionvaldafny` is a small wrapper around it.
- `dafny/xcheck` runs both cores on hand-written windows and requires the
  same verdicts, and compares the Dafny semantics with `interp/` on random
  inputs. It also runs both cores on every window of every capture in
  `testdata` and fails if the Dafny core validates a window the Go core
  rejects.

The Dafny core covers every window kind in the table above. For a wrapper site
(`site-P8`) the window is the code before `call W` and the call itself, and
the model runs W's body as a second frame: on entry W's r1 to r5 are the caller's and r0 and r6
to r9 are unknown values; on `exit` the caller gets W's r0, unknown r1 to r5
and its own r6 to r10. The proof shows that the helper that runs is the
original call in every field and runs exactly once, that the code before
`call W` writes only r4, that the helper's arguments (r4 aside for the lookup
helpers) are the site's entry values, and that r0 at W's and the window's exit
is the helper's result. W's own stack frame is not modelled; this is sound
because a validated W never names r10.

The regionval command still judges windows with the Go core in `core/`. To
use the Dafny core in its place, a caller does what the Go core does around
it and then calls `Validate` with the spec for the window's kind:

| Kind | Spec |
|---|---|
| `site` | `SiteSpec(f)` |
| `site-P4` | `TailSiteSpec(f)` |
| `site-P8` | `WrapSiteSpec(f, W, O[i])`: W's instructions and the 8 bytes of the original helper call |
| `prologue-P1` | `EntryPrologueSpec(f)` |
| `prologue-P1b` | `CallbackPrologueSpec(f)` |
| `prologue-P9` | `CustomSpec(f, nil, ...)` with stores allowed |
| `passload-P9` | `CustomSpec(f, {r_G}, ...)` |
| `hook-P7` | `HookBodySpec()` |

The checks that stay outside `Validate`: a window outside a hook has a floor;
every pseudo call is to a hook (except `call W` at the end of a wrapper
window, and including those inside W); a helper call in a site window is its
centre, and the centre of `site-P4` is `bpf_tail_call`; the `P9` certificate
and the `S10` liveness check. `dafny/xcheck/corpus_test.go` implements them.

The Dafny core is stricter than the Go core in a few places: an entry
prologue may not call a hook, the code before `call W` must write only r4 in
every instruction rather than on the paths it takes, and its limit of 10
branches per window counts that code and W together.

Beyond the list above, the Dafny core trusts Dafny's Go translation, the Go
runtime `github.com/dafny-lang/DafnyRuntimeGo/v4` v4.11.0 and the wrapper,
and that running W in the model as described matches the kernel. Its proof is
about one window; the window cutting, kinds and hook checks stay with the Go
code.

### Tools

CI uses Dafny 4.11.0 (`dafny-4.11.0-x64-ubuntu-22.04.zip` from the Dafny
GitHub release, SHA-256
`a46a9ff7cdd720f7955854c78e95df13f4cfe6b80691b05f8654fe19e8267179`). The zip
bundles .NET and Z3 4.12.1. `dafny translate go` also needs `goimports`
(`go install golang.org/x/tools/cmd/goimports@v0.52.0`).

```sh
make check-trust       # no assume, axiom or extern
make dafny-verify      # about 130 s
make dafny-check-gen   # dafny/gen-go matches a fresh translation
make dafny-gen         # regenerate dafny/gen-go after changing dafny/src
```

`dafny-verify` passes `smt.case_split=0` to Z3. With Z3's default, some goals
about recursive functions returning `bv64` do not finish. The option changes
only how Z3 searches, not what counts as a proof.

## Tests

- `testdata/captures`: five real captures. The test pins the result of each:
  four validated (covering site, hook, entry, callback, pass and wrapper
  windows) and one that fails the structure check.
- `testdata/export`: synthetic captures. The `clean` set must be validated.
  Each capture in `planted` has one planted fault and must be rejected by one
  specific rule.
- `interp/`: random windows and every window in `testdata` are run
  both symbolically and in the reference interpreter. They must agree on the
  path taken, registers, stack and the number of unknown values used.
  `REGIONVAL_DIFF_GLOB` points the test at other capture files.
