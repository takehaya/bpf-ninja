import Kunai.Eval.Core
import Kunai.Eval.Machine

/-!
# `where` clauses, arithmetic, and captures (§13.6–§13.9)

Field references resolve in two stages. `resolvePath` is static: it maps a
`FieldPath` to the protocol, the aux header (option, stack entry) and the
field it names, or an `illTyped` reason. `loadRef` is dynamic: it reads the
value from the matched instance, giving `none` when the layer, option, or
stack entry is absent (D-003, D-027).
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

/-- The one name for a layer: its label when it has one, else the protocol
name. A label and the protocol name of the same layer denote the same stack. -/
def canonicalHead (c : Ctx) (head : String) : Except Stop String := do
  if (labelProto c.layers head).isSome then pure head
  else
    let p ← staticProto c head
    pure ((c.layers.findSome? fun
      | .proto q => if q.name == p then some (q.label.getD p) else none
      | .alt _ => none).getD p)

/-- Runtime instance for a reference head; `none` when the layer was skipped (D-003). -/
def resolveRef (c : Ctx) (st : State) (head : String) : Except Stop (Option Inst) := do
  let p ← staticProto c head
  match st.labels.find? (·.1 == head) with
  | some (_, inst) => pure (some inst)
  | none => pure (if (labelProto c.layers head).isSome then none else st.insts.find? (·.proto == p))

/-- Where a field lives relative to its layer. -/
inductive AuxRef
  | primary
  /-- An extracted aux header (`gtp.opt`, `tcp.options.MSS`), by out parameter. -/
  | option (outParam : String)
  /-- One stack entry; `index = none` is the iteration variable of `any`/`all`. -/
  | stackEntry (stack : String) (index : Option Index)
  deriving Repr, BEq, DecidableEq

/-- Iteration variables bound by enclosing `any`/`all`: `(head, stack)` ↦ index. -/
abbrev IterEnv := List ((String × String) × Nat)

/-- What a field path names below its protocol head. -/
structure RefBody where
  aux : AuxRef
  field : FieldSpec
  /-- `[lo:hi]` bit slice of the field (bit 0 = MSB). -/
  slice : Option (Nat × Nat) := none
  deriving Repr, BEq

/-- A statically resolved field reference: the body under the head that
names the layer. -/
structure Ref extends RefBody where
  head : String
  proto : String
  spec : ProtoSpec
  deriving Repr, BEq

def RefBody.toRef (b : RefBody) (head proto : String) (spec : ProtoSpec) : Ref :=
  { b with head, proto, spec }

def Ref.width (r : Ref) : Nat :=
  match r.slice with
  | some (lo, hi) => hi - lo
  | none => r.field.width

/-- ASCII lower-casing by structural recursion (`String.toLower` is defined
by well-founded recursion, which `decide` cannot unfold). -/
def lowerAscii (s : String) : String :=
  String.ofList (s.toList.map fun c => if 'A' ≤ c && c ≤ 'Z' then Char.ofNat (c.toNat + 32) else c)

/-- The option declaration of an out parameter (never the primary header). -/
def option? (m : Machine) (outParam : String) : Option OptionDecl :=
  m.options.find? (·.outParam == outParam)

private def fieldOf (m : Machine) (header fieldName : String) : Except Stop FieldSpec := do
  let some h := m.header? header | throw (.illTyped s!"unknown header {header}")
  let some fs := h.fields.find? (·.name == fieldName) | throw (.illTyped s!"unknown field {header}.{fieldName}")
  pure fs

private def applySlice (fs : FieldSpec) (idx : Option Index) : Except Stop (Option (Nat × Nat)) :=
  match idx with
  | none => pure none
  | some (.slice lo hi) =>
    if lo < hi && hi ≤ fs.width then pure (some (lo, hi))
    else throw (.illTyped s!"bit-slice [{lo}:{hi}] exceeds field width bit<{fs.width}>")
  | some _ => throw (.illTyped s!"field {fs.name} does not take an index")

/-- A dynamic stack index must be a primary field of the same protocol. -/
private def checkDynamicIndex (c : Ctx) (proto : String) (spec : ProtoSpec) (parts : List String) : Except Stop FieldSpec := do
  let [ih, fieldName] := parts | throw (.illTyped s!"dynamic index {String.intercalate "." parts} must be <proto>.<field>")
  let ip ← staticProto c ih
  if ip != proto then throw (.illTyped s!"dynamic index {ih}.{fieldName} must be a primary field of {proto}")
  let some fs := spec.field? fieldName | throw (.illTyped s!"unknown field {proto}.{fieldName}")
  pure fs

private def checkIndex (c : Ctx) (proto : String) (spec : ProtoSpec) (sd : StackDecl) : Option Index → Except Stop Unit
  | some (.nat i) => if i < sd.capacity then pure () else throw (.illTyped s!"stack index {i} exceeds capacity {sd.capacity}")
  | some (.slice ..) => throw (.illTyped s!"stack {sd.name} does not take a bit-slice")
  | some (.field parts) => discard <| checkDynamicIndex c proto spec parts
  | none => pure ()

/-- The segments of a field path after its protocol head, resolved against
that protocol: shared by where clauses (`resolvePath`) and bracket
predicates (`resolveBracket`), whose paths have no head. The result does
not depend on how the head was written (Laws.lean `bracket_eq_where`). -/
def resolveRest (c : Ctx) (proto : String) (spec : ProtoSpec)
    (rest : List (String × Option Index)) : Except Stop RefBody := do
  let unsupported : Stop := .illTyped s!"unsupported: field path {proto}.{(FieldPath.mk rest).text}"
  match rest with
  | [(fieldName, idx)] => do
    let some fs := spec.field? fieldName | throw (.illTyped s!"unknown field {proto}.{fieldName}")
    pure { aux := .primary, field := fs, slice := ← applySlice fs idx }
  | _ => do
    let some m := spec.machine | throw (.illTyped s!"{proto} has no auxiliary headers")
    match rest with
    | [(x, xIdx), (fieldName, fIdx)] =>
      if let some sd := m.stack? x then
        if sd.ownerOption != "" then throw (.illTyped s!"{proto}.{x} is reached through {proto}.{spec.optionSegment}.{sd.ownerOption}")
        checkIndex c proto spec sd xIdx
        let fs ← fieldOf m sd.header fieldName
        pure { aux := .stackEntry x xIdx, field := fs, slice := ← applySlice fs fIdx }
      else if x == spec.optionSegment then throw (.illTyped s!"{proto}.{x} needs an option name and a field")
      else
        let some o := option? m x | throw (.illTyped s!"unknown auxiliary header {proto}.{x}")
        if xIdx.isSome then throw (.illTyped s!"{proto}.{x} does not take an index")
        let fs ← fieldOf m o.header fieldName
        pure { aux := .option x, field := fs, slice := ← applySlice fs fIdx }
    | [(seg, none), (name, none), (fieldName, fIdx)] =>
      if seg != spec.optionSegment then throw unsupported
      let opt := lowerAscii name
      -- `<proto>.options.NAME` names a TLV option (one with a kind byte).
      let some o := option? m opt | throw (.illTyped s!"unknown option {proto}.{seg}.{name}")
      if o.kindByte.isNone then throw (.illTyped s!"{proto}.{seg}.{name} is not a TLV option")
      let fs ← fieldOf m o.header fieldName
      pure { aux := .option opt, field := fs, slice := ← applySlice fs fIdx }
    | [(seg, none), (name, none), (stack, sIdx), (fieldName, fIdx)] =>
      if seg != spec.optionSegment then throw unsupported
      let some sd := m.stack? stack | throw (.illTyped s!"unknown stack {proto}.{stack}")
      if sd.ownerOption != lowerAscii name then throw (.illTyped s!"stack {stack} does not belong to option {name}")
      checkIndex c proto spec sd sIdx
      let fs ← fieldOf m sd.header fieldName
      pure { aux := .stackEntry stack sIdx, field := fs, slice := ← applySlice fs fIdx }
    | _ => throw unsupported

/-- Static resolution of a field path (T-FieldPrim, T-FieldAux, T-FieldStackStatic). -/
def resolvePath (c : Ctx) (f : FieldPath) : Except Stop Ref := do
  let (head, headIdx) :: rest := f.segs | throw (.illTyped "empty field path")
  if headIdx.isSome then throw (.illTyped s!"{head} does not take an index")
  let proto ← staticProto c head
  let some spec := c.V.proto? proto | throw (.illTyped s!"unknown protocol {proto}")
  pure ((← resolveRest c proto spec rest).toRef head proto spec)

/-- A bracket field is scoped to the layer's own header: a primary field, or
an aux / constant-indexed stack entry as in a where clause (T-FieldAux,
T-FieldStackStatic). The iterator and dynamic-index forms need `where`. -/
def resolveBracket (c : Ctx) (spec : ProtoSpec) (f : FieldPath) : Except Stop Ref := do
  let b ← resolveRest c spec.name spec f.segs
  match b.aux with
  | .stackEntry stack none =>
    throw (.illTyped s!"stack {spec.name}.{stack} needs a constant index inside a bracket predicate")
  | .stackEntry stack (some (.field _)) =>
    throw (.illTyped s!"stack {spec.name}.{stack} needs a constant index inside a bracket predicate (a dynamic index needs a where clause)")
  | _ => pure (b.toRef spec.name spec.name spec)

/-- `proto.X.exists` / `proto.options.NAME.exists` → (head, out parameter). -/
def resolveExists (c : Ctx) (f : FieldPath) : Except Stop (String × String) := do
  let (head, none) :: rest := f.segs | throw (.illTyped s!"unsupported: {f.text}.exists")
  let proto ← staticProto c head
  let some spec := c.V.proto? proto | throw (.illTyped s!"unknown protocol {proto}")
  let some m := spec.machine | throw (.illTyped s!"{proto} has no auxiliary headers")
  let opt ← match rest with
    | [(x, none)] => pure x
    | [(seg, none), (name, none)] =>
      if seg == spec.optionSegment then pure (lowerAscii name) else throw (.illTyped s!"unsupported: {f.text}.exists")
    | _ => throw (.illTyped s!"unsupported: {f.text}.exists")
  if (m.stack? opt).isSome then throw (.illTyped s!"{proto}.{opt} is a stack; use any/all")
  let some o := option? m opt | throw (.illTyped s!"unknown auxiliary header {proto}.{opt}")
  if rest.length == 2 && o.kindByte.isNone then throw (.illTyped s!"{proto}.{opt} is not a TLV option")
  pure (head, opt)

/-- Entries of a stack on an instance: pushed entries from the parser, or an
owner-bound stack laid out after its owner option's header, whose count
comes from the owner's length byte. -/
def stackEntries (P : Packet) (inst : Inst) (m : Machine) (sd : StackDecl) : List AuxView :=
  if sd.ownerOption == "" then stackViews inst.aux sd.name
  else
    match latestView inst.aux sd.ownerOption with
    | none => []
    | some owner =>
      -- The owner option's `length` field counts the option including its header.
      let lenField := (m.header? owner.header).bind fun h => h.fields.find? (·.name == "length")
      match lenField.bind fun lf => readBits P (owner.off * 8 + lf.bitOff) lf.width with
      | none => []
      | some lenByte =>
        let count := if lenByte < sd.offsetAfterOwner then 0 else (lenByte - sd.offsetAfterOwner) / sd.elemBytes
        (List.range (min count sd.capacity)).map fun i =>
          { outParam := sd.name, header := sd.header, stackIdx := some i,
            off := owner.off + sd.offsetAfterOwner + i * sd.elemBytes, len := sd.elemBytes }

/-- Dynamic index value: a primary field of the same layer. -/
private def indexValue (c : Ctx) (inst : Inst) (r : Ref) (parts : List String) : Except Stop Nat := do
  let fs ← checkDynamicIndex c r.proto r.spec parts
  match readField c.P inst fs with
  | some n => pure n
  | none => throw .reject

/-- The bytes a reference denotes on an instance: `none` when the option or
stack entry is absent. -/
private def refView (c : Ctx) (env : IterEnv) (inst : Inst) (r : Ref) : Except Stop (Option (Nat × Nat)) :=
  match r.aux with
  | .primary => pure (some (inst.off, inst.len))
  | .option x => pure ((latestView inst.aux x).map fun v => (v.off, v.len))
  | .stackEntry stack idx => do
    let some m := r.spec.machine | throw (.illTyped s!"{r.proto} has no auxiliary headers")
    let some sd := m.stack? stack | throw (.illTyped s!"unknown stack {stack}")
    let i ← match idx with
      | some (.nat i) => pure i
      | some (.field parts) => indexValue c inst r parts
      | _ =>
        match env.find? (·.1 == (← canonicalHead c r.head, stack)) with
        | some (_, i) => pure i
        | none => throw (.illTyped s!"index-less stack reference {r.proto}.{stack} outside any/all")
    pure ((stackEntries c.P inst m sd)[i]?.map fun v => (v.off, v.len))

/-- `load` on a given instance: `none` = the option or entry is absent
(D-027, D-031); a field past the end of the packet rejects (D-006). -/
def loadRefOn (c : Ctx) (env : IterEnv) (inst : Inst) (r : Ref) : Except Stop (Option Nat) := do
  let some (off, _) ← refView c env inst r | pure none
  let some v := readBits (patched c.P inst.patches) (off * 8 + r.field.bitOff) r.field.width | throw .reject
  pure (some (match r.slice with
    | some (lo, hi) => (v >>> (r.field.width - hi)) % 2 ^ (hi - lo)
    | none => v))

/-- E-A-Field: `load(f, σ, P)`. `none` = the layer, option, or entry is
absent (D-003, D-027); a field past the end of the packet rejects (D-006). -/
def loadRef (c : Ctx) (st : State) (env : IterEnv) (r : Ref) : Except Stop (Option Nat) := do
  let some inst ← resolveRef c st r.head | pure none
  loadRefOn c env inst r

def loadField (c : Ctx) (st : State) (env : IterEnv) (f : FieldPath) : Except Stop (Option Nat) := do
  loadRef c st env (← resolvePath c f)

/-- T-ArithBin width; `none` for constant-only expressions (D-009). -/
def arithWidth (c : Ctx) : Arith → Except Stop (Option Nat)
  | .const _ => pure none
  | .field f => do pure (some (← resolvePath c f).width)
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

/-- E-A-BinOp in `w` bits: 64 for every field up to 64 bits wide (D-015: the
Go implementation does not wrap at `max(width(e₁), width(e₂))` as §13.9 says;
it computes in 64-bit registers), 128 when an Int<128> field takes part
(D-035; only `+` and `-` reach here at that width). Division by zero gives 0
and modulo by zero leaves the dividend, as BPF does (D-022; §13.9 says 0 for
both); shifts use the BPF masked amount (D-014). -/
def binop (op : ArithOp) (a b : Nat) (w : Nat := 64) : Nat :=
  let m := 2 ^ w
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

/-- The width a binary node computes in: 64 up to 64-bit operands (D-015),
the operand width above that, where only `+` and `-` are defined (D-035). -/
def wideArithWidth (w : Nat) (op : ArithOp) : Except Stop Nat :=
  if w ≤ 64 then pure 64
  else if op == .add || op == .sub then pure w
  else throw (.illTyped "unsupported: only + and - are defined on fields wider than 64 bits")

/-- E-A-Const / E-A-Field / E-A-BinOp. `ctx` is the width a constant is
narrowed to. `none` propagates an absent layer. -/
def evalArith (c : Ctx) (st : State) (env : IterEnv) (ctx : Nat) : Arith → Except Stop (Option Nat)
  | .const n =>
    match narrowInt ctx n with
    | .ok v => pure (some v)
    | .error r => throw (.illTyped r)
  | .field f => loadField c st env f
  | .bin op l r => do
    let wl ← arithWidth c l
    let wr ← arithWidth c r
    let (cl, cr) := sideWidths wl wr
    let w ← wideArithWidth (max cl cr) op
    let some a ← evalArith c st env cl l | pure none
    let some b ← evalArith c st env cr r | pure none
    pure (some (binop op a b (w := w)))

/-- Strict evaluation of both operands (E-W-And/Or premises), but a dynamic
`reject` in the second operand is short-circuited when the first already
decides (D-019); type errors are never hidden. -/
def logic (a : Bool) (decided : Bool) (r : Except Stop Bool) (k : Bool → Bool) : Except Stop Bool :=
  match r with
  | .ok b => pure (k b)
  | .error .reject => if a == decided then pure (k a) else throw .reject
  | .error e => throw e

/-- Field paths of a `where` expression, including nested quantifier bodies. -/
def Where.paths : Where → List FieldPath
  | .or l r | .and l r | .boolEq l _ r => l.paths ++ r.paths
  | .not w | .any w | .all w => w.paths
  | .arith l _ r => arithPaths l ++ arithPaths r
  | .litCmp f _ _ => [f]
  | .fieldExists _ | .action _ | .boolLit _ => []
where
  arithPaths : Arith → List FieldPath
    | .const _ => []
    | .field f => [f]
    | .bin _ l r => arithPaths l ++ arithPaths r

/-- T-Quant: the one stack a quantifier iterates, from the index-less stack
references inside it (nested quantifiers included, as the resolver does):
`(proto, stack)`, so a label and the protocol name denote the same stack.
`bound` names stacks an enclosing quantifier already iterates. -/
def quantStack (c : Ctx) (bound : List (String × String)) (w : Where) : Except Stop (String × String) := do
  let refs ← w.paths.mapM (resolvePath c)
  let iters : List (String × String) ← refs.filterMapM fun r => match r.aux with
    | .stackEntry s none => do pure (some (← canonicalHead c r.head, s))
    | _ => pure none
  match iters.eraseDups.filter (!bound.contains ·) with
  | [one] => pure one
  | [] => throw (.illTyped "any/all needs exactly one index-less stack reference")
  | _ => throw (.illTyped "any/all iterates a single aux header stack")

/-- Number of entries of `stack` on the instance bound to `head`; `none`
when the layer is absent (then the quantifier is false, like any other atom
on an absent layer, D-003). -/
def stackCount (c : Ctx) (st : State) (head stack : String) : Except Stop (Option Nat) := do
  let some inst ← resolveRef c st head | pure none
  let some spec := c.V.proto? inst.proto | pure (some 0)
  let some m := spec.machine | pure (some 0)
  let some sd := m.stack? stack | pure (some 0)
  pure (some (stackEntries c.P inst m sd).length)

/-- §13.8. Atoms on an absent layer, option, or stack entry are false (D-003,
D-027). `env` binds the iteration variables of enclosing `any`/`all`. -/
def evalWhere (c : Ctx) (st : State) (env : IterEnv) : Where → Except Stop Bool
  | .or l r => do let a ← evalWhere c st env l; logic a true (evalWhere c st env r) (a || ·)
  | .and l r => do let a ← evalWhere c st env l; logic a false (evalWhere c st env r) (a && ·)
  | .not w => do pure (!(← evalWhere c st env w))
  | .arith l op r => do
    let wl ← arithWidth c l
    let wr ← arithWidth c r
    let (cl, cr) := sideWidths wl wr
    let some a ← evalArith c st env cl l | pure false
    let some b ← evalArith c st env cr r | pure false
    pure (cmpNat op a b)
  | .litCmp f op v => do
    let r ← resolvePath c f
    let some n ← loadRef c st env r | pure false
    Stop.ofExcept (cmpValue r.width n op v)
  | .action a => do
    if c.H.actions.isEmpty then throw (.illTyped "`action ==` is not available on this host")
    let some (_, v) := c.H.actions.find? (·.1 == a) | throw (.illTyped s!"unknown action {a}")
    pure (c.H.action == v)
  | .any w => do
    -- E-W-Any: ∃ i < count(stack). ⟨w[x ↦ stack[i]], σ⟩ ⇓ true (empty stack: false, D-007)
    let (head, stack) ← quantStack c (env.map (·.1)) w
    let some n ← stackCount c st head stack | pure false
    (List.range n).anyM fun i => evalWhere c st (((head, stack), i) :: env) w
  | .all w => do
    -- E-W-All over the extracted entries; an absent layer makes it false (D-003), not vacuously true
    let (head, stack) ← quantStack c (env.map (·.1)) w
    let some n ← stackCount c st head stack | pure false
    (List.range n).allM fun i => evalWhere c st (((head, stack), i) :: env) w
  | .boolLit b => pure b
  | .fieldExists f => do
    -- E-W-Exists: the aux header was extracted (`(LayerInst × AuxName) ∈ dom(α)`).
    let (head, opt) ← resolveExists c f
    let some inst ← resolveRef c st head | pure false
    pure (latestView inst.aux opt).isSome
  | .boolEq l op r => do
    let a ← evalWhere c st env l
    let b ← evalWhere c st env r
    pure (if op == .eq then a == b else a != b)

/-- §13.6 `eval-cap`. The per-capture `where` is ANDed into the verdict
(D-021), so a false one rejects. `none` = the target layer is absent (D-020). -/
def evalCapture (c : Ctx) (st : State) (cap : Capture) : Except Stop (Option (Nat × Nat)) := do
  let gate ← match cap.cond with | some w => evalWhere c st [] w | none => pure true
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
