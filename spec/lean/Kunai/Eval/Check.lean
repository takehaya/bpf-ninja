import Kunai.Eval.Layer
import Kunai.Eval.Where

/-!
# Static checks (§12, resolver-side)

`check` returns the first reason the resolver would reject a filter, so that
`Result.illTyped` depends on the filter and host alone, never on the packet.
The dynamic evaluator keeps its own `illTyped` paths for totality; after a
successful `check` they are unreachable for the modelled constructs.
-/
namespace Kunai

private def layerNames : Layer → List String
  | .proto p => [p.name]
  | .alt alts => alts.map (·.name)

private def layerMin : Layer → Nat
  | .proto p => (quantBounds p.quant).1
  | .alt _ => 1

/-- Protocols that can precede layer `i` at run time: the previous layer, and
its own parents if it can be skipped. -/
private def possibleParents (layers : List Layer) : Nat → List String
  | 0 => []
  | i + 1 =>
    match layers[i]? with
    | none => []
    | some l => layerNames l ++ (if layerMin l == 0 then possibleParents layers i else [])

private def checkValue (spec : ProtoSpec) (fs : FieldSpec) (op : CmpOp) (v : Value) : Except String Unit := do
  match v with
  | .cidr4 .. => if op != .eq && op != .ne then throw "ordered comparison on a cidr literal"
                 if fs.width != 32 then throw "cidr literal requires an Int<32> field"
  | .cidr6 .. => if op != .eq && op != .ne then throw "ordered comparison on a cidr literal"
                 if fs.width != 128 then throw "cidr literal requires an Int<128> field"
  | .range .. => throw s!"range literal is only valid in `in [...]` ({spec.name}.{fs.name})"
  | v => discard <| liftValue fs.width v

private def checkPred (spec : ProtoSpec) : Predicate → Except String Unit
  | .cmp f op v => do
    let some fs := bracketSpec spec f | throw s!"unknown field {spec.name}.{f.text}"
    checkValue spec fs op v
  | .inList f vs => do
    let some fs := bracketSpec spec f | throw s!"unknown field {spec.name}.{f.text}"
    for v in vs do
      match v with
      | .range .. => pure ()
      | v => checkValue spec fs .eq v
  | .inSet .. => throw "unsupported: in @set"
where
  bracketSpec (spec : ProtoSpec) (f : FieldPath) : Option FieldSpec :=
    match f.segs with
    | [(name, none)] => spec.field? name
    | _ => none

private def checkEdge (V : Vocab) (child parent : String) (alt optional : Bool) : Except String Unit :=
  match V.edge? child parent, V.proto? child with
  | some ⟨_, _, .field ..⟩, _ => pure ()
  | some ⟨_, _, .noCheck⟩, spec? =>
    -- A NO_CHECK self-edge with a CHAIN_END rule (mpls `s == 1`) does detect absence.
    let selfEnd := child == parent && (spec?.bind (·.chainEnd)).isSome
    if alt then throw s!"alternative {child} needs a field dispatch under {parent}"
    else if optional && !selfEnd then throw s!"optional {child} with no-check dispatch cannot detect absence"
    else pure ()
  | none, some spec =>
    if alt then throw s!"alternative {child} needs a field dispatch under {parent}"
    else if spec.requires.isEmpty then throw s!"no dispatch constant for {child} under {parent}"
    else pure ()
  | none, none => throw s!"unknown protocol {child}"

private def checkProtoLayer (c : Ctx) (i : Nat) (p : ProtoLayer) (alt : Bool) : Except String Unit := do
  let some spec := c.V.proto? p.name | throw s!"unknown protocol {p.name}"
  let (n, m) := quantBounds p.quant
  if i == 0 && n == 0 then throw "the first layer cannot be optional"
  if alt && p.quant != .one then throw "alternatives cannot carry quantifiers"
  if c.H.vlanInMetadata && p.name == "vlan" && n ≥ 1 then
    throw "vlan is in metadata on this host; the layer must be optional"
  let fuel := m.getD spec.maxDepth
  if fuel > chainCap then throw s!"chain depth {fuel} exceeds {chainCap}"
  if n > fuel then throw "iteration bound below the quantifier minimum"
  for parent in possibleParents c.layers i do checkEdge c.V p.name parent alt (n == 0)
  for ρ in p.preds do checkPred spec ρ

-- Structural iteration (`List.forIn`) rather than `[0:n]`, whose
-- well-founded loop the kernel cannot unfold under `decide`.
private def checkLayers (c : Ctx) : Except String Unit := do
  for (l, i) in c.layers.zipIdx do
    match l with
    | .proto p => checkProtoLayer c i p false
    | .alt alts =>
      if i == 0 then throw "alternation cannot be the first layer"
      for a in alts do checkProtoLayer c i a true

private def stop (e : Except Stop α) : Except String α :=
  match e with
  | .ok a => pure a
  | .error .reject => throw "internal: static check hit a dynamic reject" -- unreachable: no packet reads here
  | .error (.illTyped r) => throw r

/-- A field reference: resolvable, and an index-less stack reference only
under an `any`/`all` that binds that stack. -/
private def checkRef (c : Ctx) (bound : List (String × String)) (f : FieldPath) : Except String Ref := do
  let r ← stop (resolvePath c f)
  if let .stackEntry s none := r.aux then
    if !bound.contains (r.proto, s) then throw s!"index-less stack reference {r.proto}.{s} outside any/all"
  pure r

private def checkArith (c : Ctx) (bound : List (String × String)) (ctx : Nat) : Arith → Except String Unit
  | .const n => discard <| narrowInt ctx n
  | .field f => discard <| checkRef c bound f
  | .bin _ l r => do
    let (cl, cr) := sideWidths (← stop (arithWidth c l)) (← stop (arithWidth c r))
    if max cl cr > 64 then throw "unsupported: arithmetic on fields wider than 64 bits"
    checkArith c bound cl l
    checkArith c bound cr r

private def checkWhere (c : Ctx) (bound : List (String × String)) : Where → Except String Unit
  | .or l r | .and l r | .boolEq l _ r => do checkWhere c bound l; checkWhere c bound r
  | .not w => checkWhere c bound w
  | .arith l _ r => do
    let (cl, cr) := sideWidths (← stop (arithWidth c l)) (← stop (arithWidth c r))
    checkArith c bound cl l
    checkArith c bound cr r
  | .litCmp f op v => do
    let r ← checkRef c bound f
    checkValue r.spec { r.field with width := r.width } op v
  | .action a => do
    if c.H.actions.isEmpty then throw "`action ==` is not available on this host"
    if (c.H.actions.find? (·.1 == a)).isNone then throw s!"unknown action {a}"
  | .any w | .all w => do
    -- T-Quant: exactly one stack is iterated; check the body with it bound.
    let hs ← stop (quantStack c bound w)
    checkWhere c (hs :: bound) w
  | .boolLit _ => pure ()
  | .fieldExists f => discard <| stop (resolveExists c f)

private def checkCapture (c : Ctx) (cap : Capture) : Except String Unit := do
  if let some w := cap.cond then checkWhere c [] w
  if let .toLayer name _ := cap.spec then discard <| stop (staticProto c name)

/-- `none` when the filter type-checks; otherwise the resolver's complaint. -/
def check (c : Ctx) (F : Filter) : Option String :=
  let r : Except String Unit := do
    checkLayers c
    if let some w := F.cond then checkWhere c [] w
    for cap in F.captures do checkCapture c cap
  match r with
  | .ok () => none
  | .error e => some e

end Kunai
