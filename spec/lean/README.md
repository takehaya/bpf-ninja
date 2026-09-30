# kunai DSL — Lean 4 formal specification

`docs/ja/dsl-types.md` Part II (§11 abstract syntax, §13 big-step semantics)
rewritten as total Lean 4 functions. The evaluator produces the expected
verdict for golden test vectors; the vectors are exported as JSON and checked
against the real BPF program by `pkg/kunai/dsltest/spec_vectors_test.go`.

Scope: syntax and semantics of the DSL only. eBPF instruction semantics,
codegen correctness, and the verifier are out of scope.

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
| `Kunai/Syntax.lean` | §11 abstract syntax, 1:1 with `pkg/kunai/ast` |
| `Kunai/Vocab.lean` | Protocol table (fields, lengths, dispatch) as data |
| `Kunai/Packet.lean` | `Packet = List UInt8`, big-endian bit reads |
| `Kunai/Host.lean` | Host parameters (`codegen.Capabilities` mirror) |
| `Kunai/Eval.lean` | §13 evaluator (total; fuel = chain depth) |
| `Kunai/Print.lean` | AST → canonical DSL text |
| `Kunai/Json.lean` | JSON encoding for the Go side |
| `Kunai/Vectors.lean` | Golden vectors, each paired with an `example` |
| `Kunai/Laws.lean` | Equational theorems ("these forms mean the same") |
| `Main.lean` | `lake exe gen`: prints the vectors as JSON |
| `DECISIONS.md` | Log of behaviours the Markdown spec left open |

## Adding a vector

1. Add a `Vector` to `Kunai/Vectors.lean` with a stable `id`, and the
   `example : eval … = expected := by decide` next to it.
2. `make lean-gen`, then commit the regenerated JSON together with the Lean
   change. CI fails if the JSON drifts from the Lean source.
3. If the vector exercises a behaviour §13 does not define, add or reference a
   `DECISIONS.md` entry.

## DECISIONS.md

One entry per open point, numbered `D-NNN`. Each records the question, the
candidates, what the Go implementation does today (with the test or code that
shows it), the recommendation, the status (proposed / approved with date), and
where it is reflected. Entries are never deleted; a rejected candidate stays
in the log.

Rules for the Lean code: no `partial def`, no `sorry`. `native_decide` is
allowed where `decide` is too slow, with a comment saying so.
