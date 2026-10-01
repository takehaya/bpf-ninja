import Kunai.Eval.Core

/-!
# `where` clauses, arithmetic, and captures (§13.6–§13.9)
-/
namespace Kunai

/-- Protocol a label is declared on, from the static chain. -/
private def labelProto (layers : List Layer) (l : String) : Option String :=
  layers.findSome? fun
    | .proto p => if p.label == some l then some p.name else none
    | .alt _ => none

/-- How many instances of `p` the chain can bind: 0, 1, or 2 (= ambiguous, D-013). -/
private def staticCount (layers : List Layer) (p : String) : Nat :=
  (layers.map fun
    | .proto q =>
      if q.name != p then 0
      else match q.quant with
        | .one | .opt | .range _ (some 1) => 1
        | _ => 2
    | .alt alts => if alts.any (·.name == p) then 1 else 0).sum

/-- Static resolution of a reference head (`label` or `proto`) to a protocol. -/
def staticProto (c : Ctx) (head : String) : Except Stop String :=
  match labelProto c.layers head with
  | some p => pure p
  | none =>
    if (c.V.proto? head).isNone then throw (.illTyped s!"unknown protocol or label {head}")
    else match staticCount c.layers head with
      | 0 => throw (.illTyped s!"protocol {head} is not in the chain")
      | 1 => pure head
      | _ => throw (.illTyped s!"protocol {head} is ambiguous; qualify with an @label")

/-- Runtime instance for a reference head; `none` when the layer was skipped (D-003). -/
private def resolveRef (c : Ctx) (st : State) (head : String) : Except Stop (Option Inst) := do
  let p ← staticProto c head
  match st.labels.find? (·.1 == head) with
  | some (_, inst) => pure (some inst)
  | none => pure (if (labelProto c.layers head).isSome then none else st.insts.find? (·.proto == p))

/-- Static field of a `proto.field` path: its declaring protocol and spec. -/
def staticField (c : Ctx) (f : FieldPath) : Except Stop (String × FieldSpec) :=
  match f.segs with
  | [(head, none), (field, none)] => do
    let p ← staticProto c head
    let some spec := c.V.proto? p | throw (.illTyped s!"unknown protocol {p}")
    let some fs := spec.field? field | throw (.illTyped s!"unknown field {p}.{field}")
    pure (p, fs)
  | _ => throw (.illTyped s!"unsupported: field path {f.text} (aux, index, or slice)")

/-- E-A-Field: `load(f, σ, P)`. `none` = the layer is absent (D-003);
a field past the end of the packet rejects (D-006). -/
def loadField (c : Ctx) (st : State) (f : FieldPath) : Except Stop (Option Nat) := do
  let (_, fs) ← staticField c f
  match ← resolveRef c st (f.segs.headD ("", none)).1 with
  | none => pure none
  | some inst =>
    match readField c.P inst fs with
    | some n => pure (some n)
    | none => throw .reject

/-- T-ArithBin width; `none` for constant-only expressions (D-009). -/
def arithWidth (c : Ctx) : Arith → Except Stop (Option Nat)
  | .const _ => pure none
  | .field f => do pure (some (← staticField c f).2.width)
  | .bin _ l r => do
    match ← arithWidth c l, ← arithWidth c r with
    | some a, some b => pure (some (max a b))
    | some a, none => pure (some a)
    | none, some b => pure (some b)
    | none, none => pure none

/-- Context width for each side of a binary node: a constant takes its
sibling's width, and 64 when both sides are constants (D-009). -/
def sideWidths (wl wr : Option Nat) : Nat × Nat :=
  let w := max (wl.getD (wr.getD 64)) (wr.getD (wl.getD 64))
  (wl.getD w, wr.getD w)

/-- E-A-BinOp in 64 bits (D-015: the Go implementation does not wrap at
`max(width(e₁), width(e₂))` as §13.9 says; it computes in 64-bit registers).
Division by zero gives 0 and modulo by zero leaves the dividend, as BPF does
(D-022; §13.9 says 0 for both); shifts use the BPF masked amount (D-014). -/
def binop (op : ArithOp) (a b : Nat) : Nat :=
  let m := 2 ^ 64
  match op with
  | .add => (a + b) % m
  | .sub => (a + m - b % m) % m
  | .mul => (a * b) % m
  | .div => if b == 0 then 0 else a / b
  | .mod => if b == 0 then a else a % b
  | .band => a &&& b
  | .bor => a ||| b
  | .bxor => a ^^^ b
  | .shl => (a <<< (b % 64)) % m
  | .shr => a >>> (b % 64)

/-- E-A-Const / E-A-Field / E-A-BinOp. `ctx` is the width a constant is
narrowed to. `none` propagates an absent layer. -/
def evalArith (c : Ctx) (st : State) (ctx : Nat) : Arith → Except Stop (Option Nat)
  | .const n =>
    match narrowInt ctx n with
    | .ok v => pure (some v)
    | .error r => throw (.illTyped r)
  | .field f => loadField c st f
  | .bin op l r => do
    let wl ← arithWidth c l
    let wr ← arithWidth c r
    let (cl, cr) := sideWidths wl wr
    if max cl cr > 64 then throw (.illTyped "unsupported: arithmetic on fields wider than 64 bits")
    let some a ← evalArith c st cl l | pure none
    let some b ← evalArith c st cr r | pure none
    pure (some (binop op a b))

/-- Strict evaluation of both operands (E-W-And/Or premises), but a dynamic
`reject` in the second operand is short-circuited when the first already
decides (D-019); type errors are never hidden. -/
def logic (a : Bool) (decided : Bool) (r : Except Stop Bool) (k : Bool → Bool) : Except Stop Bool :=
  match r with
  | .ok b => pure (k b)
  | .error .reject => if a == decided then pure (k a) else throw .reject
  | .error e => throw e

/-- §13.8. Atoms on an absent layer are false (D-003). -/
def evalWhere (c : Ctx) (st : State) : Where → Except Stop Bool
  | .or l r => do let a ← evalWhere c st l; logic a true (evalWhere c st r) (a || ·)
  | .and l r => do let a ← evalWhere c st l; logic a false (evalWhere c st r) (a && ·)
  | .not w => do pure (!(← evalWhere c st w))
  | .arith l op r => do
    let wl ← arithWidth c l
    let wr ← arithWidth c r
    let (cl, cr) := sideWidths wl wr
    let some a ← evalArith c st cl l | pure false
    let some b ← evalArith c st cr r | pure false
    pure (cmpNat op a b)
  | .litCmp f op v => do
    let (_, fs) ← staticField c f
    let some n ← loadField c st f | pure false
    match cmpValue fs.width n op v with
    | .ok b => pure b
    | .error r => throw (.illTyped r)
  | .action a => do
    if c.H.actions.isEmpty then throw (.illTyped "`action ==` is not available on this host")
    let some (_, v) := c.H.actions.find? (·.1 == a) | throw (.illTyped s!"unknown action {a}")
    pure (c.H.action == v)
  | .any _ => throw (.illTyped "unsupported: aux stacks (Phase 5)")
  | .all _ => throw (.illTyped "unsupported: aux stacks (Phase 5)")
  | .boolLit b => pure b
  | .fieldExists _ => throw (.illTyped "unsupported: aux exists (Phase 5)")
  | .boolEq l op r => do
    let a ← evalWhere c st l
    let b ← evalWhere c st r
    pure (if op == .eq then a == b else a != b)

/-- §13.6 `eval-cap`. The per-capture `where` is ANDed into the verdict
(D-021), so a false one rejects. `none` = the target layer is absent (D-020). -/
def evalCapture (c : Ctx) (st : State) (cap : Capture) : Except Stop (Option (Nat × Nat)) := do
  let gate ← match cap.cond with | some w => evalWhere c st w | none => pure true
  if !gate then throw .reject
  let n := c.P.length
  match cap.spec with
  | .all => pure (some (0, n))
  | .headers => pure (some (0, min st.cursor n))
  | .headersPlus k => pure (some (0, min (st.cursor + k) n))
  | .absolute k => pure (some (0, min k n))
  | .toLayer name k =>
    match ← resolveRef c st name with
    | none => pure none
    | some inst => pure (some (inst.off, min (inst.off + inst.len + k) n))

end Kunai
