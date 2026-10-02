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

private def stop (e : Except Stop α) : Except String α :=
  match e with
  | .ok a => pure a
  | .error .reject => throw "internal: static check hit a dynamic reject" -- unreachable: no packet reads here
  | .error (.illTyped r) => throw r

/-- Bracket predicates resolve their field like a where clause scoped to the
layer (`resolveBracket`); a bit slice narrows the compared width. `mandatory`
says the layer is extracted on every accepting path (not quantified, not an
alternative), which `in @set` needs. -/
private def checkPred (c : Ctx) (spec : ProtoSpec) (mandatory : Bool) : Predicate → Except String Unit
  | .cmp f op v => do
    let r ← stop (resolveBracket c spec f)
    checkValue spec { r.field with width := r.width } op v
  | .inList f vs => do
    let r ← stop (resolveBracket c spec f)
    for v in vs do
      match v with
      | .range lo hi =>
        -- both bounds fit the field (T-PredIn); an empty range is a typo
        if lo ≥ 2 ^ r.width || hi ≥ 2 ^ r.width then
          throw s!"range {lo}..{hi} exceeds bit<{r.width}> ({spec.name}.{f.text})"
        if lo > hi then throw s!"range {lo}..{hi} is empty ({spec.name}.{f.text})"
      | v => checkValue spec { r.field with width := r.width } .eq v
  | .inSet f name => do
    let r ← stop (resolveBracket c spec f)
    -- D-036: the key is written while the layer is extracted and read after
    -- the filter, so the layer must be on every accepting path.
    if !mandatory then
      throw s!"in @{name} on an optional, repeated, or alternative layer: the key is only written when the layer is present"
    -- The set must be declared, and its keys as wide as the bytes the
    -- filter extracts for the field (whole bytes: a 4-bit field is a
    -- bit<8> key; a narrower key would only hold a prefix of the field).
    let some s := c.H.set? name | throw s!"undeclared set @{name}"
    let extracted := 8 * ((r.width + 7) / 8)
    if s.width != extracted then
      throw s!"set @{name} keys are bit<{s.width}>, {spec.name}.{f.text} extracts bit<{extracted}>"

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
  for ρ in p.preds do checkPred c spec (!alt && p.quant == .one) ρ

-- Structural iteration (`List.forIn`) rather than `[0:n]`, whose
-- well-founded loop the kernel cannot unfold under `decide`.
private def checkLayers (c : Ctx) : Except String Unit := do
  for (l, i) in c.layers.zipIdx do
    match l with
    | .proto p => checkProtoLayer c i p false
    | .alt alts =>
      if i == 0 then throw "alternation cannot be the first layer"
      for a in alts do checkProtoLayer c i a true

/-- A field reference: resolvable, and an index-less stack reference only
under an `any`/`all` that binds that stack. -/
private def checkRef (c : Ctx) (bound : List (String × String)) (f : FieldPath) : Except String Ref := do
  let r ← stop (resolvePath c f)
  if let .stackEntry s none := r.aux then
    if !bound.contains (← stop (canonicalHead c r.head), s) then throw s!"index-less stack reference {r.proto}.{s} outside any/all"
  pure r

private def checkArith (c : Ctx) (bound : List (String × String)) (ctx : Nat) : Arith → Except String Unit
  | .const n => discard <| narrowInt ctx n
  | .field f => discard <| checkRef c bound f
  | .bin op l r => do
    let (cl, cr) := sideWidths (← stop (arithWidth c l)) (← stop (arithWidth c r))
    discard <| stop (wideArithWidth (max cl cr) op)
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

private def setRef : Predicate → Option String
  | .inSet _ s => some s
  | _ => none

/-- The set names a filter's bracket predicates reference, in chain order. -/
private def setRefs (layers : List Layer) : List String :=
  layers.flatMap fun
    | .proto p => p.preds.filterMap setRef
    | .alt alts => alts.flatMap (·.preds.filterMap setRef)

/-- D-036 across the filter, mirroring the host's key buffer: a referenced
set is declared once with a `set create` key width and keys that fit it,
each set is referenced by at most one predicate (the host holds one key per
set and looks it up once), and the referenced keys fit the 16-byte buffer. -/
private def checkSets (c : Ctx) : Except String Unit := do
  let refs := setRefs c.layers
  for name in refs.eraseDups do
    let some s := c.H.set? name | pure ()
    if (c.H.sets.filter (·.name == name)).length > 1 then throw s!"set @{name} is declared twice"
    if ![8, 16, 32, 64, 128].contains s.width then
      throw s!"set @{name} declares bit<{s.width}> keys; keys are 8, 16, 32, 64 or 128 bits"
    if s.members.any (· ≥ 2 ^ s.width) then throw s!"set @{name} holds a key that does not fit bit<{s.width}>"
    if (refs.filter (· == name)).length > 1 then
      throw s!"set @{name} is referenced twice: the host holds one key per set"
  let bytes : Nat := refs.foldl (fun acc n => acc + ((c.H.set? n).map (·.width / 8)).getD 0) 0
  if bytes > 16 then throw s!"packet keys take {bytes} bytes; the host's key buffer holds 16"

/-- `none` when the filter type-checks; otherwise the resolver's complaint. -/
def check (c : Ctx) (F : Filter) : Option String :=
  let r : Except String Unit := do
    checkLayers c
    checkSets c
    if let some w := F.cond then checkWhere c [] w
    for cap in F.captures do checkCapture c cap
  match r with
  | .ok () => none
  | .error e => some e

end Kunai
