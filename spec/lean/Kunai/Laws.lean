import Kunai.Eval
import Kunai.VocabData
import Kunai.Vectors

/-!
# Laws: forms that mean the same

Theorems users can rely on. Each is stated against the evaluator, so it holds
for every host, vocabulary, packet, and state. Candidates that turned out to
be false are kept as proved counterexamples (see DECISIONS.md).
-/
namespace Kunai

/-- The quantifier plays no part in extracting one header. -/
theorem extract_quant (c : Ctx) (st : State) (p : ProtoLayer) (q : Quant) :
    extract c st { p with quant := q } = extract c st p := by
  cases p; rfl

/-- A protocol without a chain-end signal always counts as ended. -/
theorem chainEnded_of_noEnd (c : Ctx) (p : ProtoLayer) (spec : ProtoSpec)
    (hspec : c.V.proto? p.name = some spec) (hend : spec.chainEnd = none) (st : State) :
    chainEnded c p st = true := by
  simp [chainEnded, hspec, hend]

/-- One iteration bounded by `{1,1}` is one extraction (E-Quant-Range-Step
with n = m = 1) when no chain-end signal is required at the bound. -/
theorem iterate_one (c : Ctx) (st : State) (p : ProtoLayer) (spec : ProtoSpec)
    (hspec : c.V.proto? p.name = some spec) (hend : spec.chainEnd = none) :
    iterate c p 1 1 0 st = extract c st p := by
  simp only [iterate]
  cases extract c st p with
  | ok st' => simp [chainEnded_of_noEnd c p spec hspec hend]; rfl
  | error e => cases e <;> rfl

/-- `proto{1,1}` ≡ `proto` for protocols without a chain-end signal
(dsl-usage.md: `{n}` ≡ `{n,n}`, instance n = 1). For a chain-end protocol
such as mpls, `{1,1}` additionally requires the stack to end there (D-024),
so the two differ by design. -/
theorem one_eq_range_layer (c : Ctx) (st : State) (p : ProtoLayer) (spec : ProtoSpec)
    (hspec : c.V.proto? p.name = some spec) (hend : spec.chainEnd = none) :
    evalProtoLayer c st { p with quant := .range 1 (some 1) }
      = evalProtoLayer c st { p with quant := .one } := by
  unfold evalProtoLayer
  simp only [hspec, quantBounds, bind, Except.bind, chainCap, Option.getD]
  simp only [iterate_one c st { p with quant := Quant.range 1 (some 1) } spec hspec hend, extract_quant]
  simp

/-- The same, inside a chain. -/
theorem one_eq_range_chain (c : Ctx) (st : State) (p : ProtoLayer) (rest : List Layer) (spec : ProtoSpec)
    (hspec : c.V.proto? p.name = some spec) (hend : spec.chainEnd = none) :
    evalChain c (.proto { p with quant := .range 1 (some 1) } :: rest) st
      = evalChain c (.proto { p with quant := .one } :: rest) st := by
  simp [evalChain, quantBounds, one_eq_range_layer c st p spec hspec hend]

/-- `and` commutes when neither side stops the evaluation (D-019: a dynamic
`reject` in the second operand is short-circuited, so the hypotheses are needed). -/
theorem and_comm_where (c : Ctx) (st : State) (a b : Where) (x y : Bool)
    (ha : evalWhere c st [] a = .ok x) (hb : evalWhere c st [] b = .ok y) :
    evalWhere c st [] (.and a b) = evalWhere c st [] (.and b a) := by
  simp [evalWhere, ha, hb, bind, Except.bind, logic, Bool.and_comm]

theorem or_comm_where (c : Ctx) (st : State) (a b : Where) (x y : Bool)
    (ha : evalWhere c st [] a = .ok x) (hb : evalWhere c st [] b = .ok y) :
    evalWhere c st [] (.or a b) = evalWhere c st [] (.or b a) := by
  simp [evalWhere, ha, hb, bind, Except.bind, logic, Bool.or_comm]

/-- The quantifier plays no part in an optional extraction either. -/
theorem extractOpt_quant (c : Ctx) (st : State) (p : ProtoLayer) (q : Quant) :
    extractOpt c st { p with quant := q } = extractOpt c st p := by
  cases p; rfl

/-- `{0,1}` is one optional extraction. -/
theorem iterate_opt (c : Ctx) (st : State) (p : ProtoLayer) :
    iterate c p 0 1 0 st = extractOpt c st p := by
  simp only [iterate, extractOpt]
  cases extract c st p with
  | ok st' => cases h : chainEnded c p st' <;> simp [h]
  | error e => cases e <;> rfl

/-- `proto?` ≡ `proto{0,1}` (D-005, D-024): both skip on a dispatch miss
only and both require the chain-end signal after an extraction. -/
theorem opt_eq_range (c : Ctx) (st : State) (p : ProtoLayer) :
    evalProtoLayer c st { p with quant := .opt }
      = evalProtoLayer c st { p with quant := .range 0 (some 1) } := by
  unfold evalProtoLayer
  cases c.V.proto? p.name with
  | none => rfl
  | some spec =>
    simp only [quantBounds, bind, Except.bind, chainCap, Option.getD]
    simp [iterate_opt, extractOpt_quant]

/-- A chain evaluates in two parts. -/
theorem evalChain_append (c : Ctx) (pre rest : List Layer) (st : State) :
    evalChain c (pre ++ rest) st = (evalChain c pre st).bind (evalChain c rest) := by
  induction pre generalizing st with
  | nil => rfl
  | cons l tl ih =>
    cases l with
    | proto p =>
      simp only [List.cons_append, evalChain, bind, Except.bind]
      split
      · rfl
      · cases evalProtoLayer c st p with
        | error e => rfl
        | ok s => simp only [ih]; cases evalChain c tl s <;> rfl
    | alt alts =>
      simp only [List.cons_append, evalChain, bind, Except.bind]
      cases evalAlt c st alts with
      | error e => rfl
      | ok s => simp only [ih]; cases evalChain c tl s <;> rfl

/-- One bracket comparison on a layer is the layer without it, followed by
the comparison on the instance just extracted (E-Layer-Proto-1 and its
Fail-Pred rule). -/
theorem extract_cmp (c : Ctx) (st : State) (name : String) (label : Option String) (q : Quant)
    (spec : ProtoSpec) (inst : Inst) (ρ : Predicate)
    (hx : extractInst c st name = .ok (spec, inst)) :
    extract c st { name, label, preds := [ρ], quant := q } =
      match evalPred c spec inst ρ with
      | .ok true => .ok (st.push label inst)
      | .ok false => .error .pred
      | .error .reject => .error .bounds
      | .error (.illTyped r) => .error (.illTyped r) := by
  simp only [extract, hx, bind, Except.bind, checkPreds]
  cases evalPred c spec inst ρ with
  | error e => cases e <;> rfl
  | ok b => cases b <;> rfl

/-- The where atom `p.f op v` and the bracket predicate `[f op v]` on the
instance that `p` names are the same evaluation: both resolve the path with
`resolveRest` and read it with `loadRefOn`. -/
theorem litCmp_eq_evalPred (c : Ctx) (st : State) (spec : ProtoSpec) (inst : Inst)
    (f : FieldPath) (op : CmpOp) (v : Value) (r : Ref)
    (hproto : staticProto c spec.name = .ok spec.name)
    (hspec : c.V.proto? spec.name = some spec)
    (hinst : resolveRef c st spec.name = .ok (some inst))
    (hres : resolveBracket c spec f = .ok r) :
    evalWhere c st [] (.litCmp ⟨(spec.name, none) :: f.segs⟩ op v)
      = evalPred c spec inst (.cmp f op v) := by
  have hres' := hres
  unfold resolveBracket at hres'
  cases hb : resolveRest c spec.name spec f.segs with
  | error e => simp [hb, bind, Except.bind] at hres'
  | ok b =>
    simp only [hb, bind, Except.bind] at hres'
    have hr : r = b.toRef spec.name spec.name spec := by
      split at hres' <;> simp_all [pure, Except.pure]
    have hpath : resolvePath c ⟨(spec.name, none) :: f.segs⟩ = .ok r := by
      simp [resolvePath, hproto, hspec, hb, hr, bind, Except.bind, pure, Except.pure]
    have hhead : r.head = spec.name := by rw [hr]; rfl
    simp only [evalWhere, evalPred, hpath, hres, bind, Except.bind, loadRef, hhead, hinst]
    cases loadRefOn c [] inst r with
    | error e => rfl
    | ok o =>
      cases o with
      | none => rfl
      | some n => simp only [typed]; split <;> simp_all

/-- `…/p[f op v]/…` ≡ `…/p/… where p.f op v` (D-023), for a mandatory layer
whose name denotes the instance it extracts.

Given the chain without the bracket matches (`pre` to `s1`, the layer's
header to `inst`, `rest` to `stF`) and `p`'s name resolves to `inst` in the
final state (the layer is the only one of its protocol and no label hides
the name), the chain with the bracket matches exactly when the where atom
is true on the final state, and fails as a predicate failure when it is
false. The two forms differ only in what they report when the atom cannot
be evaluated: the bracket stops the chain at its layer, so a field past the
packet end is the layer's bounds failure there, while `where` sees it after
the whole chain. -/
theorem bracket_eq_where
    (c : Ctx) (pre rest : List Layer) (p : ProtoLayer) (spec : ProtoSpec) (inst : Inst)
    (f : FieldPath) (op : CmpOp) (v : Value) (r : Ref) (st s1 stF : State)
    (hq : p.quant = .one) (hname : spec.name = p.name)
    (hvlan : (c.H.vlanInMetadata && p.name == "vlan") = false)
    (hpre : evalChain c pre st = .ok s1)
    (hx : extractInst c s1 p.name = .ok (spec, inst))
    (hrest : evalChain c rest (s1.push p.label inst) = .ok stF)
    (hproto : staticProto c spec.name = .ok spec.name)
    (hspec : c.V.proto? spec.name = some spec)
    (hinst : resolveRef c stF spec.name = .ok (some inst))
    (hres : resolveBracket c spec f = .ok r) :
    evalChain c (pre ++ .proto { p with preds := [.cmp f op v] } :: rest) st
      = match evalWhere c stF [] (.litCmp ⟨(spec.name, none) :: f.segs⟩ op v) with
        | .ok true => .ok stF
        | .ok false => .error .pred
        | .error .reject => .error .bounds
        | .error (.illTyped e) => .error (.illTyped e) := by
  have hsp : c.V.proto? p.name = some spec := hname ▸ hspec
  have hw := litCmp_eq_evalPred c stF spec inst f op v r hproto hspec hinst hres
  rw [evalChain_append, hpre, hw]
  simp only [Except.bind, evalChain, bind, hq, quantBounds, evalProtoLayer, hsp, hvlan]
  simp only [extract_cmp c s1 p.name p.label _ spec inst (.cmp f op v) hx]
  cases evalPred c spec inst (.cmp f op v) with
  | error e => cases e <;> simp
  | ok b => cases b <;> simp [hrest]

/-- Alternation order matters when dispatch overlaps (D-004): the first
matching alternative commits. Vector `alt-first-pred-fails`. -/
theorem alt_order_matters :
    eval {} vocab { layers := [P "eth", .alt [{ name := "ipv4", preds := [.cmp (f "ttl") .eq (.int 1)] }, { name := "ipv4" }], P "tcp"] } Pkt.ethIPv4TCP
      ≠ eval {} vocab { layers := [P "eth", .alt [{ name := "ipv4" }, { name := "ipv4", preds := [.cmp (f "ttl") .eq (.int 1)] }], P "tcp"] } Pkt.ethIPv4TCP := by
  decide

end Kunai
