import Kunai.Eval.Core

/-!
# Layers and chains (§13.3–§13.5, plus alternation)

Behaviours the Markdown leaves open are marked `D-NNN` (see DECISIONS.md).
-/
namespace Kunai

inductive Disp
  | ok
  | miss
  | illTyped (reason : String)

/-- `parent_dispatch(p, σ, P)`: the previous instance's dispatch edge admits
`p`. The chain root has no parent. A self-chain ends after a header whose
`CHAIN_END` field matches (mpls `s == 1`). A protocol with no edge from
this parent is admitted only if it self-validates (`requires ≠ []`). -/
def dispatch (c : Ctx) (st : State) (child : String) : Disp :=
  match st.insts.getLast? with
  | none => .ok
  | some parent =>
    let ended := parent.proto == child &&
      match c.V.proto? child with
      | some spec =>
        match spec.chainEnd with
        | some (f, v) => ((spec.field? f).bind (readField c.P parent)) == some v
        | none => false
      | none => false
    if ended then .miss else
    match c.V.edge? child parent.proto with
    | some ⟨_, _, .noCheck⟩ => .ok
    | some ⟨_, _, .field f vs⟩ =>
      match (c.V.proto? parent.proto).bind (·.field? f) |>.bind (readField c.P parent) with
      | some v => if vs.contains v then .ok else .miss
      | none => .illTyped s!"dispatch field {parent.proto}.{f} is not declared"
    | none =>
      match c.V.proto? child with
      | some spec =>
        if spec.requires.isEmpty then .illTyped s!"no dispatch constant for {child} under {parent.proto}"
        else
          -- D-017: with no parent constant, self-validation is the dispatch. A readable
          -- header that fails it is a miss; an unreadable one falls through to bounds.
          let probe : Inst := ⟨child, st.cursor, spec.fixedLen⟩
          let failed := spec.requires.any fun (f, v) =>
            match (spec.field? f).bind (readField c.P probe) with
            | some n => n != v
            | none => false
          if failed then .miss else .ok
      | none => .illTyped s!"unknown protocol {child}"

/-- Bracket field: a single segment naming a field of the layer's own header. -/
private def bracketField (c : Ctx) (spec : ProtoSpec) (inst : Inst) (f : FieldPath)
    : Except String (FieldSpec × Nat) :=
  match f.segs with
  | [(name, none)] =>
    match spec.field? name with
    | none => throw s!"unknown field {spec.name}.{name}"
    | some fs =>
      match readField c.P inst fs with
      | some n => pure (fs, n)
      | none => throw "internal: primary field outside the header"
  | _ => throw s!"unsupported: bracket field path {f.text}"

/-- E-Pred-Cmp, plus `in [...]` (D-011). -/
def evalPred (c : Ctx) (spec : ProtoSpec) (inst : Inst) : Predicate → Except String Bool
  | .cmp f op v => do
    let (fs, n) ← bracketField c spec inst f
    cmpValue fs.width n op v
  | .inList f vs => do
    let (fs, n) ← bracketField c spec inst f
    vs.anyM fun
      | .range lo hi => pure (lo ≤ n && n ≤ hi)
      | v => cmpValue fs.width n .eq v
  | .inSet .. => throw "unsupported: in @set"

/-- E-Layer-Proto-1 and its three failure rules. -/
def extract (c : Ctx) (st : State) (p : ProtoLayer) : Except LayerFail State := do
  let some spec := c.V.proto? p.name | throw (.illTyped s!"unknown protocol {p.name}")
  match dispatch c st p.name with
  | .miss => throw .dispMiss
  | .illTyped r => throw (.illTyped r)
  | .ok => pure ()
  -- [E-Layer-Proto-1-Fail-Bounds] on the fixed header
  if st.cursor + spec.fixedLen > c.P.length then throw .bounds
  let fixed : Inst := ⟨p.name, st.cursor, spec.fixedLen⟩
  -- parser-block self validation under a parent constant: the parent already named this
  -- protocol, so a failing header is broken, not absent (D-017: Fail-Pred, like D-005)
  for (f, v) in spec.requires do
    if ((spec.field? f).bind (readField c.P fixed)) != some v then throw .pred
  -- total_bytes(p, P, π): declared header length (D-016: below the fixed header ⇒ reject)
  let len ← match spec.lenRule with
    | none => pure spec.fixedLen
    | some r =>
      match readBytes c.P (st.cursor + r.byteOff) 1 with
      | none => throw .bounds
      | some b =>
        let l := ((b &&& r.mask) >>> r.shift) * r.scale
        if l < spec.fixedLen then throw .pred else pure l
  if st.cursor + len > c.P.length then throw .bounds
  let inst : Inst := ⟨p.name, st.cursor, len⟩
  -- [E-Layer-Proto-1-Fail-Pred]
  for ρ in p.preds do
    match evalPred c spec inst ρ with
    | .error r => throw (.illTyped r)
    | .ok false => throw .pred
    | .ok true => pure ()
  pure { cursor := st.cursor + len, insts := st.insts ++ [inst],
         labels := match p.label with | some l => (l, inst) :: st.labels | none => st.labels }

/-- `(n, m)` of `q`; `none` = `m_chain`. -/
def quantBounds : Quant → Nat × Option Nat
  | .one => (1, some 1) | .opt => (0, some 1) | .plus => (1, none) | .star => (0, none)
  | .range n m => (n, m)

/-- E-Quant-Range-Step / E-Quant-Range-Fail: greedy, no backtracking (D-002).
Only a dispatch miss stops the iteration; a bounds failure (D-005) or a
predicate failure (D-001) fails the layer, exactly as for `?`. -/
def iterate (c : Ctx) (p : ProtoLayer) (n : Nat) : Nat → Nat → State → Except LayerFail State
  | 0, k, st => if k < n then throw (.illTyped "iteration bound below the quantifier minimum") else pure st
  | fuel + 1, k, st =>
    match extract c st p with
    | .ok st' => iterate c p n fuel (k + 1) st'
    | .error .dispMiss => if k < n then throw .dispMiss else pure st
    | .error e => throw e

/-- `L(q)` for one protocol layer. -/
def evalProtoLayer (c : Ctx) (st : State) (p : ProtoLayer) : Except LayerFail State := do
  let some spec := c.V.proto? p.name | throw (.illTyped s!"unknown protocol {p.name}")
  let (n, m) := quantBounds p.quant
  if c.H.vlanInMetadata && p.name == "vlan" && n ≥ 1 then
    throw (.illTyped "vlan is in metadata on this host; the layer must be optional")
  match p.quant with
  | .one => extract c st p
  | .opt =>
    -- [E-Quant-Optional]: case B skips on dispatch miss only; `?` ≡ `{0,1}` (Laws.lean: opt_eq_range)
    match extract c st p with
    | .error .dispMiss => pure st
    | r => r
  | _ =>
    let fuel := m.getD spec.maxDepth
    if fuel > chainCap then throw (.illTyped s!"chain depth {fuel} exceeds {chainCap}")
    iterate c p n fuel 0 st

/-- E-Layer-Alt-First (D-004, D-010): the first alternative whose parent
dispatch matches is committed; alternatives need a field dispatch edge. -/
def evalAlt (c : Ctx) (st : State) : List ProtoLayer → Except LayerFail State
  | [] => throw .dispMiss
  | a :: rest => do
    let some parent := st.insts.getLast? | throw (.illTyped "alternation cannot be the first layer")
    if a.quant != .one then throw (.illTyped "alternatives cannot carry quantifiers")
    let some ⟨_, _, .field ..⟩ := c.V.edge? a.name parent.proto
      | throw (.illTyped s!"alternative {a.name} needs a field dispatch under {parent.proto}")
    match dispatch c st a.name with
    | .ok => extract c st a
    | .miss => evalAlt c st rest
    | .illTyped r => throw (.illTyped r)

/-- E-Chain-Empty / E-Chain-Cons / E-Chain-Fail. -/
def evalChain (c : Ctx) : List Layer → State → Except LayerFail State
  | [], st => pure st
  | .proto p :: rest, st => do
    if st.insts.isEmpty && (quantBounds p.quant).1 == 0 then
      throw (.illTyped "the first layer cannot be optional")
    evalChain c rest (← evalProtoLayer c st p)
  | .alt alts :: rest, st => do evalChain c rest (← evalAlt c st alts)

end Kunai
