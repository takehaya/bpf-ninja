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

/-- Run `f` on each element in order, stopping at the first complaint.
Structural recursion, so the kernel unfolds it under `decide` and the laws
below can reason about it by membership. -/
def allOk (xs : List α) (f : α → Except String Unit) : Except String Unit :=
  match xs with
  | [] => pure ()
  | x :: tl => do f x; allOk tl f

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
    | some l => l.names ++ (if layerMin l == 0 then possibleParents layers i else [])

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

/-- The smallest load (1, 2, 4 or 8 bytes) covering `cover` bytes. -/
private def ldxBytes (cover : Nat) : Nat :=
  if cover ≤ 1 then 1 else if cover ≤ 2 then 2 else if cover ≤ 4 then 4 else 8

/-- The bytes the filter extracts for a bracket field, which is the key an
`in @set` predicate writes: a whole-byte field is itself (16 for Int<128>),
anything else is the smallest load window covering its bits. -/
private def keyBytes (r : Ref) : Nat :=
  match r.slice with
  | some (lo, hi) => ldxBytes ((r.field.bitOff + hi + 7) / 8 - (r.field.bitOff + lo) / 8)
  | none =>
    if r.field.width == 128 then 16
    else if r.field.bitOff % 8 == 0 && r.field.width % 8 == 0 then r.field.width / 8
    else ldxBytes ((r.field.bitOff % 8 + r.field.width + 7) / 8)

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
    -- filter extracts for the field (keyBytes: a 4-bit field is a bit<8>
    -- key, a 20-bit one a bit<32> key; a narrower key would only hold a
    -- prefix of the field).
    let some s := c.H.set? name | throw s!"undeclared set @{name}"
    let extracted := 8 * keyBytes r
    if s.width != extracted then
      throw s!"set @{name} keys are bit<{s.width}>, {spec.name}.{f.text} extracts bit<{extracted}>"
  | .optionsValid f => do
    -- the same rule as `where p.options.valid` (resolveValid)
    if let some e := spec.validRegionError? f.text then throw e
    if f.segs != [(spec.optionSegment, none)] then throw s!"unsupported: {spec.name}[{f.text}.valid]"

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

/-- Layer `i` of the chain is an outer VLAN tag position (D-008): the root
is `eth` and every layer between them is a tag (an alternation of tags
counts as one). It looks at the chain's protocol names only
(`Layer.names`), so bracket predicates do not change it. -/
private def outerTagPos (names : List (List String)) (i : Nat) : Bool :=
  i ≥ 1 && names[0]? == some ["eth"] && ((names.take i).drop 1).all (·.all isTagName)

/-- The checks on a layer that do not look at its predicates. -/
private def checkProtoShape (c : Ctx) (layers : List Layer) (i : Nat) (p : ProtoLayer) (spec : ProtoSpec)
    (alt : Bool) : Except String Unit := do
  -- A label never shadows a protocol name, so a name in a where clause is
  -- either a label or a protocol, statically and at run time alike.
  if let some l := p.label then
    if (c.V.proto? l).isSome then throw s!"label {l} collides with protocol name"
  let (n, m) := quantBounds p.quant
  if i == 0 && n == 0 then throw "the first layer cannot be optional"
  if alt && p.quant != .one then throw "alternatives cannot carry quantifiers"
  if c.H.tagInMetadata p.name && outerTagPos (layers.map Layer.names) i && n ≥ 1 then
    throw s!"{p.name} is in metadata on this host; the layer must be optional"
  let fuel := m.getD spec.maxDepth
  if fuel > chainCap then throw s!"chain depth {fuel} exceeds {chainCap}"
  if n > fuel then throw "iteration bound below the quantifier minimum"
  -- A layer that can repeat dispatches its second and later instances
  -- against its own protocol, and needs a declared edge for that (D-037):
  -- the self-validation probe (D-017) is not a chain link, and with no
  -- edge at all the failure would only show once one instance matched.
  let canRepeat := match m with | some k => k > 1 | none => true
  if canRepeat && (c.V.edge? p.name p.name).isNone then
    throw s!"repeated {p.name} needs a dispatch constant under itself"
  allOk (possibleParents layers i) fun parent => checkEdge c.V p.name parent alt (n == 0)

private def checkProtoLayer (c : Ctx) (layers : List Layer) (i : Nat) (p : ProtoLayer) (alt : Bool) :
    Except String Unit :=
  match c.V.proto? p.name with
  | none => throw s!"unknown protocol {p.name}"
  | some spec => do
    checkProtoShape c layers i p spec alt
    allOk p.preds (checkPred c spec (!alt && p.quant == .one))

/-- One layer at position `i` of the chain. -/
private def checkLayer (c : Ctx) (layers : List Layer) : Layer × Nat → Except String Unit
  | (.proto p, i) => checkProtoLayer c layers i p false
  | (.alt alts, i) =>
    if i == 0 then throw "alternation cannot be the first layer"
    else allOk alts fun a => checkProtoLayer c layers i a true

private def checkLayers (c : Ctx) (layers : List Layer) : Except String Unit :=
  allOk layers.zipIdx (checkLayer c layers)

/-- A field reference: resolvable, and an index-less stack reference only
under an `any`/`all` that binds that stack. -/
private def checkRef (c : Ctx) (bound : List (String × String)) (f : FieldPath) : Except String Ref := do
  let r ← stop (resolvePath c f)
  if let .stackEntry s none := r.aux then
    if !bound.contains (← stop (canonicalHead c r.head), s) then throw s!"index-less stack reference {r.proto}.{s} outside any/all"
  pure r

private def checkArith (c : Ctx) (bound : List (String × String)) (ctx : Nat) : Arith → Except String Unit
  | .const n => discard <| narrowInt ctx n
  | .wide n => discard <| wideLit n
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
  | .optionsValid f => discard <| stop (resolveValid c f)

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

/-- `x` rounded up to a multiple of `a`. -/
private def alignUp (x a : Nat) : Nat := ((x + a - 1) / a) * a

/-- D-036 across the filter, mirroring the host's key buffer: each set is
referenced by at most one predicate (the host holds one key per set and
looks it up once), and the referenced keys, laid out in chain order with
each key aligned to its own width (8 at most), fit the 16-byte buffer. -/
private def checkSets (c : Ctx) (layers : List Layer) : Except String Unit := do
  let refs := setRefs layers
  for name in refs.eraseDups do
    if (refs.filter (· == name)).length > 1 then
      throw s!"set @{name} is referenced twice: the host holds one key per set"
  let bytes : Nat := refs.foldl (fun used n =>
    match c.H.set? n with
    | some s => alignUp (used + s.width / 8) (min (s.width / 8) 8)
    | none => used) 0
  if bytes > 16 then throw s!"packet keys take {bytes} bytes; the host's key buffer holds 16"

/-- A label names one layer: two layers (alternation members included)
cannot carry the same one. -/
private def checkLabels (layers : List Layer) : Except String Unit := do
  let labels := layers.flatMap Layer.labels
  for l in labels.eraseDups do
    if (labels.filter (· == l)).length > 1 then throw s!"duplicate label {l}"

private def checkCond (c : Ctx) : Option Where → Except String Unit
  | some w => checkWhere c [] w
  | none => pure ()

private def checkAll (c : Ctx) (F : Filter) : Except String Unit := do
  checkLabels F.layers
  -- The layers are checked from `F.layers` (predicates, positions, parents);
  -- `c.layers`, the chain's shape, only serves name resolution.
  checkLayers c F.layers
  checkSets c F.layers
  checkCond c F.cond
  allOk F.captures (checkCapture c)

/-- `none` when the filter type-checks; otherwise the resolver's complaint. -/
def check (c : Ctx) (F : Filter) : Option String :=
  match checkAll c F with
  | .ok () => none
  | .error e => some e

/-! ## Laws of `check`

A bracket comparison on a layer and the same comparison in a `where` clause
are checked alike: if the bracket form type-checks, so does the where form.
-/

theorem allOk_ok {xs : List α} {f : α → Except String Unit} :
    allOk xs f = .ok () ↔ ∀ x ∈ xs, f x = .ok () := by
  induction xs with
  | nil => simp [allOk, pure, Except.pure]
  | cons x tl ih =>
    simp only [allOk, bind, Except.bind, List.mem_cons, forall_eq_or_imp]
    cases hx : f x with
    | error e => simp
    | ok u => simp [ih]

private theorem seq_ok {x y : Except String Unit} :
    (x >>= fun _ => y) = .ok () ↔ x = .ok () ∧ y = .ok () := by
  cases x with
  | error e => simp [bind, Except.bind]
  | ok u => simp [bind, Except.bind]

/-- The parents a layer can have depend on the chain's names and quantifiers
only. -/
private theorem possibleParents_congr (L L' : List Layer)
    (h : L.map (fun l => (l.names, layerMin l)) = L'.map (fun l => (l.names, layerMin l))) (i : Nat) :
    possibleParents L i = possibleParents L' i := by
  induction i with
  | zero => rfl
  | succ i ih =>
    have hi : (L[i]?).map (fun l => (l.names, layerMin l)) = (L'[i]?).map (fun l => (l.names, layerMin l)) := by
      rw [← List.getElem?_map, ← List.getElem?_map, h]
    simp only [possibleParents]
    cases hl : L[i]? with
    | none =>
      cases hl' : L'[i]? with
      | none => rfl
      | some l' => simp [hl, hl'] at hi
    | some l =>
      cases hl' : L'[i]? with
      | none => simp [hl, hl'] at hi
      | some l' =>
        simp [hl, hl'] at hi
        simp [hi.1, hi.2, ih]

private theorem checkLayer_congr (c : Ctx) (L L' : List Layer)
    (h : ∀ i, possibleParents L i = possibleParents L' i)
    (hn : L.map Layer.names = L'.map Layer.names) (x : Layer × Nat) :
    checkLayer c L x = checkLayer c L' x := by
  obtain ⟨l, i⟩ := x
  cases l with
  | proto p => simp [checkLayer, checkProtoLayer, checkProtoShape, h, hn]
  | alt alts => simp [checkLayer, checkProtoLayer, checkProtoShape, h, hn]

/-- The layers of the where form check when those of the bracket form do,
and the bracket predicate itself checked. -/
private theorem checkLayers_bracket (c : Ctx) (pre rest : List Layer) (p : ProtoLayer) (spec : ProtoSpec)
    (ρ : Predicate) (hq : p.quant = .one) (hnp : p.preds = []) (hspec : c.V.proto? p.name = some spec)
    (h : checkLayers c (pre ++ .proto { p with preds := [ρ] } :: rest) = .ok ()) :
    checkLayers c (pre ++ .proto p :: rest) = .ok () ∧ checkPred c spec true ρ = .ok () := by
  have hpp : ∀ i, possibleParents (pre ++ .proto { p with preds := [ρ] } :: rest) i
      = possibleParents (pre ++ .proto p :: rest) i :=
    possibleParents_congr _ _ (by simp [Layer.names, layerMin])
  simp only [checkLayers, allOk_ok, List.zipIdx_append, List.zipIdx_cons, List.mem_append, List.mem_cons] at h ⊢
  have hmid := h (.proto { p with preds := [ρ] }, 0 + pre.length) (Or.inr (Or.inl rfl))
  simp only [checkLayer, checkProtoLayer, hspec, seq_ok, allOk_ok, List.mem_singleton, forall_eq] at hmid
  have hshape : checkProtoShape c (pre ++ .proto { p with preds := [ρ] } :: rest) (0 + pre.length)
      { p with preds := [ρ] } spec false
      = checkProtoShape c (pre ++ .proto { p with preds := [ρ] } :: rest) (0 + pre.length) p spec false := rfl
  have hone : (Quant.one == Quant.one) = true := by decide
  refine ⟨?_, by simpa [hq, hone] using hmid.2⟩
  intro x hx
  rw [← checkLayer_congr c _ _ hpp (by simp [Layer.names])]
  rcases hx with hx | hx | hx
  · exact h x (Or.inl hx)
  · subst hx
    simp only [checkLayer, checkProtoLayer, hspec, seq_ok, allOk_ok, hnp]
    exact ⟨hshape ▸ hmid.1, by simp⟩
  · exact h x (Or.inr (Or.inr hx))

private theorem checkProtoLayer_label (c : Ctx) (L : List Layer) (i : Nat) (p : ProtoLayer) (alt : Bool)
    (h : checkProtoLayer c L i p alt = .ok ()) : ∀ l ∈ p.label.toList, c.V.proto? l = none := by
  intro l hl
  simp only [checkProtoLayer] at h
  cases hs : c.V.proto? p.name with
  | none => simp [hs, throw, throwThe, MonadExceptOf.throw] at h
  | some spec =>
    simp only [hs, seq_ok] at h
    have h1 := h.1
    cases hp : p.label with
    | none => simp [hp] at hl
    | some l' =>
      simp only [hp, Option.toList_some, List.mem_singleton] at hl
      subst hl
      cases hc : c.V.proto? l with
      | none => rfl
      | some s => simp [checkProtoShape, hp, hc, bind, Except.bind, throw, throwThe, MonadExceptOf.throw] at h1

/-- A chain that checks has no label that is also a protocol name. -/
private theorem checkLayers_labels (c : Ctx) (L : List Layer) (h : checkLayers c L = .ok ()) :
    ∀ l ∈ L.flatMap Layer.labels, c.V.proto? l = none := by
  intro l hl
  simp only [checkLayers, allOk_ok] at h
  obtain ⟨x, hx, hlx⟩ := List.mem_flatMap.mp hl
  obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem hx
  have hmem : (L[i], i) ∈ L.zipIdx := by
    simp [List.mem_zipIdx_iff_getElem?, hi]
  have hx' := h _ hmem
  cases hxl : L[i] with
  | proto p =>
    rw [hxl] at hx' hlx
    exact checkProtoLayer_label c L i p false (by simpa [checkLayer] using hx') l (by simpa [Layer.labels] using hlx)
  | alt alts =>
    rw [hxl] at hx' hlx
    simp only [checkLayer] at hx'
    split at hx'
    · simp [throw, throwThe, MonadExceptOf.throw] at hx'
    · simp only [Layer.labels, List.mem_filterMap] at hlx
      obtain ⟨a, ha, hal⟩ := hlx
      exact checkProtoLayer_label c L i a true (allOk_ok.mp hx' a ha) l (by simp [hal])

private theorem check_none {c : Ctx} {F : Filter} : check c F = none ↔ checkAll c F = .ok () := by
  simp only [check]
  cases checkAll c F <;> simp

/-- A bracket comparison that checks resolves, and the same path under the
layer's name checks as a `where` comparison. -/
private theorem checkPred_where (c : Ctx) (p : ProtoLayer) (spec : ProtoSpec)
    (f : FieldPath) (op : CmpOp) (v : Value)
    (hname : spec.name = p.name) (hspec : c.V.proto? p.name = some spec)
    (hproto : staticProto c p.name = .ok p.name)
    (h : checkPred c spec true (.cmp f op v) = .ok ()) :
    checkWhere c [] (.litCmp ⟨(p.name, none) :: f.segs⟩ op v) = .ok ()
      ∧ ∃ r, resolveBracket c spec f = .ok r := by
  simp only [checkPred, bind, Except.bind] at h
  cases hr : resolveBracket c spec f with
  | error e => cases e <;> simp [hr, stop, throw, throwThe, MonadExceptOf.throw] at h
  | ok r =>
    refine ⟨?_, r, rfl⟩
    simp only [hr, stop, pure, Except.pure] at h
    simp only [resolveBracket, bind, Except.bind, hname] at hr
    cases hb : resolveRest c p.name spec f.segs with
    | error e => simp [hb] at hr
    | ok b =>
      simp only [hb] at hr
      have hpath : resolvePath c ⟨(p.name, none) :: f.segs⟩ = .ok (b.toRef p.name p.name spec) := by
        simp [resolvePath, hproto, hspec, hb, bind, Except.bind, pure, Except.pure]
      simp only [checkWhere, checkRef, hpath, stop, bind, Except.bind, pure, Except.pure]
      cases haux : b.aux with
      | primary =>
        simp only [haux, pure, Except.pure] at hr
        cases hr
        simpa [RefBody.toRef, haux, Ref.width] using h
      | option o =>
        simp only [haux, pure, Except.pure] at hr
        cases hr
        simpa [RefBody.toRef, haux, Ref.width] using h
      | stackEntry stack idx =>
        cases idx with
        | none => simp [haux, throw, throwThe, MonadExceptOf.throw] at hr
        | some ix =>
          cases ix with
          | field g => simp [haux, throw, throwThe, MonadExceptOf.throw] at hr
          | _ =>
            simp only [haux, pure, Except.pure] at hr
            cases hr
            simpa [RefBody.toRef, haux, Ref.width] using h

/-- A filter that checks has no label that is also a protocol name. -/
theorem check_labels (c : Ctx) (F : Filter) (h : check c F = none) :
    ∀ l ∈ F.layers.flatMap Layer.labels, c.V.proto? l = none := by
  rw [check_none] at h
  simp only [checkAll, seq_ok] at h
  exact checkLayers_labels c F.layers h.2.1

/-- D-023, statically: when `…/p[f op v]/…` type-checks, so does
`…/p/… where p.f op v`, and the bracket path resolves. `p` is a mandatory
layer with no other predicate whose name resolves to itself in `c`
(`hproto`). Neither filter has captures. -/
theorem check_bracket_where (c : Ctx) (pre rest : List Layer) (p : ProtoLayer) (spec : ProtoSpec)
    (f : FieldPath) (op : CmpOp) (v : Value)
    (hq : p.quant = .one) (hnp : p.preds = []) (hname : spec.name = p.name)
    (hspec : c.V.proto? p.name = some spec)
    (hproto : staticProto c p.name = .ok p.name)
    (hB : check c { layers := pre ++ .proto { p with preds := [.cmp f op v] } :: rest } = none) :
    check c { layers := pre ++ .proto p :: rest, cond := some (.litCmp ⟨(p.name, none) :: f.segs⟩ op v) } = none
      ∧ ∃ r, resolveBracket c spec f = .ok r := by
  rw [check_none] at hB ⊢
  simp only [checkAll, seq_ok] at hB ⊢
  obtain ⟨hlabels, hlayers, hsets, -, -⟩ := hB
  obtain ⟨hL, hpred⟩ := checkLayers_bracket c pre rest p spec (.cmp f op v) hq hnp hspec hlayers
  obtain ⟨hw, hres⟩ := checkPred_where c p spec f op v hname hspec hproto hpred
  refine ⟨⟨?_, hL, ?_, hw, by simp [allOk, pure, Except.pure]⟩, hres⟩
  · simpa [checkLabels, Layer.labels] using hlabels
  · have hrefs : setRefs (pre ++ .proto p :: rest)
        = setRefs (pre ++ .proto { p with preds := [.cmp f op v] } :: rest) := by
      simp [setRefs, setRef, hnp]
    simpa only [checkSets, hrefs] using hsets

end Kunai
