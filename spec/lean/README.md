# kunai DSL — Lean 4 formal specification

`docs/ja/dsl-types.md` Part II (§11 abstract syntax, §13 big-step semantics)
rewritten as total Lean 4 functions. `Kunai.eval` produces the verdict for
golden test vectors; the vectors are exported as JSON and checked against the
real BPF program by `pkg/kunai/dsltest/spec_vectors_test.go`.

Scope: syntax and semantics of the DSL only. eBPF instruction semantics,
codegen correctness, and the verifier are out of scope. Aux headers (options,
extension headers, stacks) are not modelled yet (Phase 5).

## Build

Requires [elan](https://github.com/leanprover/elan). The toolchain is pinned in
`lean-toolchain`; `lake` downloads it on first build. No external packages
(Lean core only, no mathlib).

```sh
make lean-build   # cd spec/lean && lake build
make lean-gen     # regenerate pkg/kunai/dsltest/testdata/spec_vectors.json
```

`lake build` also checks every `example` and `theorem`, so a successful build
means every vector agrees with the evaluator.

## Layout

| File | Content |
|---|---|
| `Kunai/Syntax.lean` | §11 abstract syntax, one constructor per `pkg/kunai/ast` kind |
| `Kunai/Print.lean` | AST → canonical DSL text (`Filter.text`) |
| `Kunai/Json.lean` | JSON encoding; mirrored by `dsltest/spec_ast_json_test.go` |
| `Kunai/Packet.lean` | `Packet = List UInt8`, big-endian bit reads |
| `Kunai/Vocab.lean` | Protocol table (fields, length rule, dispatch edges) transcribed from `protocols/*.p4` |
| `Kunai/Host.lean` | `codegen.Capabilities` mirror per host kind |
| `Kunai/Eval/Core.lean` | State `σ`, `Result`, field reads, literal lifting (§7.3, §12.1) |
| `Kunai/Eval/Layer.lean` | §13.3–§13.5 chain, layer, quantifiers, alternation |
| `Kunai/Eval/Where.lean` | §13.6–§13.9 captures, `where`, arithmetic |
| `Kunai/Eval/Check.lean` | Static checks (§12); decides `Result.illTyped` |
| `Kunai/Eval.lean` | `eval` (§13.2) |
| `Kunai/Packets.lean` | Packet builders for vectors |
| `Kunai/Vectors/*.lean` | Golden vectors, each with its `decide` proof |
| `Kunai/Laws.lean` | Equational theorems ("these forms mean the same") |
| `Main.lean` | `lake exe gen`: prints the vectors as JSON |
| `DECISIONS.md` | Log of behaviours the Markdown spec left open |

## Adding a vector

1. In `Kunai/Vectors/*.lean`, write

   ```lean
   vector myCase := {
     id := "where-my-case", ast := W (cmp dport .eq (k 80)), expected := .accept [] }
   ```

   and append `myCase` to that file's list. The `vector` macro also emits
   `example : myCase.check = true := by decide`, so the build fails if the
   expected verdict disagrees with `eval`.
2. Set `goStatus` when the Go implementation is known to differ:
   `.notImplemented` (`Compile` returns `ErrNotImplemented`) or `.mismatch`
   (documented divergence; logged, not asserted). Reference the
   `DECISIONS.md` entry in `note`.
3. `make lean-gen`, then commit the regenerated JSON together with the Lean
   change. CI (`lean-spec.yml`) fails if the JSON drifts from the Lean source.

The Go side runs `TestSpecASTRoundTrip` (printer → parser → JSON) and
`TestSpecVectors` (compile expectations; with root, `Runner.Match` on
`xdp_entry` vectors). Other hosts are compile-only until the runner accepts
`Capabilities`, and only the verdict is compared: the `captures` ranges in
the JSON are not checked against the BPF program yet (`Runner.Match` returns
the verdict only).

## DECISIONS.md

One entry per open point, numbered `D-NNN`. Each records the question, the
candidates, what the Go implementation does today (with the test or code that
shows it), the recommendation, the status (提案中 / 承認済 with date), and
where it is reflected. Entries are never deleted; a rejected candidate stays
in the log.

Rules for the Lean code: no `partial def`, no `sorry`. `native_decide` is
allowed where `decide` is too slow, with a comment saying so. Loops must be
structural (`for x in list`), not `for i in [0:n]`, or `decide` cannot unfold
them.
