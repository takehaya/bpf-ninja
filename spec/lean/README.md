# kunai DSL formal specification (Lean 4)

This directory holds `docs/ja/dsl-types.md` Part II (§11 abstract syntax, §13
big-step semantics) written as total Lean 4 functions. `Kunai.eval` computes
the verdict for a set of golden test vectors; `lake exe gen` exports those
vectors as JSON and `pkg/kunai/dsltest/spec_vectors_test.go` runs them against
the real BPF program.

The spec covers the syntax and semantics of the DSL, including the p4lite
parser machines for aux headers (options, extension headers, stacks). It does
not model eBPF instruction semantics, codegen correctness, or the verifier.

## Build

You need [elan](https://github.com/leanprover/elan). `lean-toolchain` pins the
toolchain and `lake` downloads it on the first build. The project depends on
Lean core only; there is no mathlib.

```sh
make lean-build   # cd spec/lean && lake build
make lean-gen     # regenerate VocabData.lean, spec_vectors.json and spec_vectors_gen.json
make lean-vocab   # regenerate Kunai/VocabData.lean from pkg/kunai/protocols/*.p4
```

`spec/lean/gen/vocab2lean` (Go) writes `VocabData.lean` from the loader's
output, so the Lean vocabulary cannot drift from the `.p4` files. Regenerate it
whenever a `.p4` file changes.

`lake build` checks every `example` and `theorem`, so a build that succeeds
means every vector agrees with the evaluator.

## Layout

| File | Content |
|---|---|
| `Kunai/Syntax.lean` | §11 abstract syntax, one constructor per `pkg/kunai/ast` kind |
| `Kunai/Print.lean` | AST to canonical DSL text (`Filter.text`) |
| `Kunai/Json.lean` | JSON encoding, mirrored by `dsltest/spec_ast_json_test.go` |
| `Kunai/Packet.lean` | `Packet = List UInt8`, big-endian bit reads |
| `Kunai/Vocab.lean` | Protocol table types |
| `Kunai/Machine.lean` | p4lite parser machine as data (mirror of `vocab.ParseStateMachine`) |
| `Kunai/VocabData.lean` | Generated: all bundled protocols, edges, and machines (`make lean-vocab`) |
| `Kunai/Eval/Machine.lean` | §14 small-step machine: extract, stacks, tails, write-back, counters, select |
| `Kunai/Host.lean` | `codegen.Capabilities` mirror per host kind |
| `Kunai/Eval/Core.lean` | State `σ`, `Result`, field reads, literal lifting (§7.3, §12.1) |
| `Kunai/Eval/Layer.lean` | §13.3 to §13.5: chain, layer, quantifiers, alternation, bracket predicates |
| `Kunai/Eval/Where.lean` | §13.6 to §13.9: captures, `where`, arithmetic, field resolution |
| `Kunai/Eval/Check.lean` | Static checks (§12); decides `Result.illTyped` |
| `Kunai/Eval.lean` | `eval` (§13.2) |
| `Kunai/Packets.lean` | Packet builders for vectors |
| `Kunai/Vectors/*.lean` | Golden vectors, each with its `decide` proof |
| `Kunai/Gen.lean` | Generated vectors: truncations and byte flips of every golden packet, verdicts computed by `eval` (not proved); exported by `lake exe gen --generated` to `spec_vectors_gen.json` |
| `Kunai/Laws.lean` | Equational theorems: forms that mean the same thing |
| `Main.lean` | `lake exe gen [--generated]`: prints the golden (or generated) vectors as JSON |
| `DECISIONS.md` | Log of behaviours the Markdown spec left open, and how each was settled |

## Adding a vector

1. In `Kunai/Vectors/*.lean`, write

   ```lean
   vector myCase := {
     id := "where-my-case", ast := W (cmp dport .eq (k 80)), expected := .accept [] }
   ```

   and append `myCase` to that file's list. The `vector` macro also emits
   `example : myCase.check = true := by decide`, so the build fails when the
   expected verdict disagrees with `eval`.
2. Set `goStatus` when the Go implementation is known to differ:
   `.notImplemented` when `Compile` returns `ErrNotImplemented`, `.mismatch`
   for a documented divergence (logged, not asserted). Name the `DECISIONS.md`
   entry in `note`.
3. Run `make lean-gen` and commit the regenerated JSON with the Lean change.
   CI (`lean-spec.yml`) fails when the JSON drifts from the Lean source.

On the Go side, `TestSpecASTRoundTrip` checks printer, parser and JSON
agree, and `TestSpecVectors` checks the compile expectations; under root it
also runs `Runner.Match` on every vector whose compile is expected to
succeed, compiled for the vector's host (`dsltest.NewFromOutput`); on an
exit host the vector's `action` stands in for the traced program's return
value. The test compares the
verdict only: `Runner.Match` returns the verdict, so the `captures` ranges
in the JSON are not checked against the BPF program yet.

## Conventions for the Lean code

No `partial def` and no `sorry`. `native_decide` is allowed where `decide`
is too slow, with a comment saying so. Write loops structurally (`for x in
list`), not as `for i in [0:n]`, or `decide` cannot unfold them. In `check`,
a loop a law reasons about is an `allOk` (`allOk_ok` turns it into a
statement about every element).
