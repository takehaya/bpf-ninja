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
    (hspec : c.V.proto? name = some spec)
    (hx : extractInst c st name spec = .ok inst) :
    extract c st { name, label, preds := [ρ], quant := q } =
      match evalPred c spec inst ρ with
      | .ok true => .ok (st.push label inst)
      | .ok false => .error .pred
      | .error .reject => .error .bounds
      | .error (.illTyped r) => .error (.illTyped r) := by
  simp only [extract, hspec, hx, bind, Except.bind, checkPreds]
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
      | some n => rfl

/-- `bracket_eq_where` on the pieces of the chain: `pre` evaluates to `s1`,
the layer's header to `inst`, `rest` to `stF`, and the layer's name denotes
`inst` in `stF`. -/
theorem bracket_eq_where_at
    (c : Ctx) (pre rest : List Layer) (p : ProtoLayer) (spec : ProtoSpec) (inst : Inst)
    (f : FieldPath) (op : CmpOp) (v : Value) {r : Ref} (st s1 stF : State)
    (hq : p.quant = .one) (hname : spec.name = p.name)
    (hvlan : (c.H.vlanInMetadata && p.name == "vlan") = false)
    (hpre : evalChain c pre st = .ok s1)
    (hx : extractInst c s1 p.name spec = .ok inst)
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
  simp only [extract_cmp c s1 p.name p.label _ spec inst (.cmp f op v) hsp hx]
  cases evalPred c spec inst (.cmp f op v) with
  | error e => cases e <;> simp
  | ok b => cases b <;> simp [hrest]

/-- A chain that matches through a mandatory layer without predicates
splits at that layer: the prefix gives `s1`, the layer's header `inst`,
and the rest runs from `s1 ⊕ inst`. -/
theorem evalChain_proto_inv (c : Ctx) (pre rest : List Layer) (p : ProtoLayer) (spec : ProtoSpec)
    (st stF : State) (hq : p.quant = .one) (hnp : p.preds = [])
    (hsp : c.V.proto? p.name = some spec)
    (h : evalChain c (pre ++ .proto p :: rest) st = .ok stF) :
    ∃ s1 inst, evalChain c pre st = .ok s1 ∧ extractInst c s1 p.name spec = .ok inst ∧
      evalChain c rest (s1.push p.label inst) = .ok stF ∧
      (c.H.vlanInMetadata && p.name == "vlan") = false := by
  rw [evalChain_append] at h
  cases hpre : evalChain c pre st with
  | error e => simp [hpre, Except.bind] at h
  | ok s1 =>
    simp only [hpre, Except.bind, evalChain, bind, hq, quantBounds, evalProtoLayer, hsp] at h
    cases hv : (c.H.vlanInMetadata && p.name == "vlan") with
    | true => simp [hv] at h
    | false =>
      simp only [hv, extract, hsp, hnp, checkPreds, bind, Except.bind] at h
      cases hx : extractInst c s1 p.name spec with
      | error e => simp [hx] at h
      | ok inst =>
        simp [hx, pure, Except.pure] at h
        exact ⟨s1, inst, rfl, hx, h, rfl⟩

/-- `…/p[f op v]/…` ≡ `…/p/… where p.f op v` (D-023), for a mandatory layer
`p` without other predicates whose name denotes the instance it extracts.

When the chain without the bracket matches with final state `stF`, and
`p`'s name resolves in `stF` to the instance the layer extracted (the layer
is the only one of its protocol and no label hides the name), the chain
with the bracket matches with the same `stF` exactly when the where atom is
true on `stF`, and fails as a predicate failure when it is false. The two
forms differ only in what they report when the atom cannot be evaluated:
the bracket stops the chain at its layer, so a field past the packet end
is the layer's bounds failure there, while `where` sees it after the whole
chain.

The statement is about the chain and where evaluators under one context
`c`. `bracket_iff_where_eval` below carries it to `eval` on the two
filters, which share that context and additionally run `check`. -/
theorem bracket_eq_where
    (c : Ctx) (pre rest : List Layer) (p : ProtoLayer) (spec : ProtoSpec)
    (f : FieldPath) (op : CmpOp) (v : Value) {r : Ref} (st stF : State)
    (hq : p.quant = .one) (hnp : p.preds = []) (hname : spec.name = p.name)
    (hspec : c.V.proto? spec.name = some spec)
    (hchain : evalChain c (pre ++ .proto p :: rest) st = .ok stF)
    (hproto : staticProto c spec.name = .ok spec.name)
    (hinst : ∀ s1 inst, evalChain c pre st = .ok s1 → extractInst c s1 p.name spec = .ok inst →
      resolveRef c stF spec.name = .ok (some inst))
    (hres : resolveBracket c spec f = .ok r) :
    evalChain c (pre ++ .proto { p with preds := [.cmp f op v] } :: rest) st
      = match evalWhere c stF [] (.litCmp ⟨(spec.name, none) :: f.segs⟩ op v) with
        | .ok true => .ok stF
        | .ok false => .error .pred
        | .error .reject => .error .bounds
        | .error (.illTyped e) => .error (.illTyped e) := by
  have hsp : c.V.proto? p.name = some spec := hname ▸ hspec
  obtain ⟨s1, inst, hpre, hx, hrest, hvlan⟩ := evalChain_proto_inv c pre rest p spec st stF hq hnp hsp hchain
  exact bracket_eq_where_at c pre rest p spec inst f op v st s1 stF hq hname hvlan hpre hx hrest
    hproto hspec (hinst s1 inst hpre hx) hres

/-! ## What a chain adds to the state

Evaluating layers only appends instances of the layers' protocols and only
binds the layers' labels. This is what makes "the layer is the only one of
its protocol" a static condition. -/

/-- `st'` extends `st`: the new instances all have a protocol in `names`,
the new label bindings a label in `labels`. -/
def Grows (names labels : List String) (st st' : State) : Prop :=
  ∃ new newL, st'.insts = st.insts ++ new ∧ (∀ i ∈ new, i.proto ∈ names) ∧
    st'.labels = newL ++ st.labels ∧ (∀ kv ∈ newL, kv.1 ∈ labels)

theorem Grows.refl (names labels : List String) (st : State) : Grows names labels st st :=
  ⟨[], [], by simp, by simp, by simp, by simp⟩

theorem Grows.trans {n1 l1 n2 l2 : List String} {a b c : State}
    (h1 : Grows n1 l1 a b) (h2 : Grows n2 l2 b c) : Grows (n1 ++ n2) (l1 ++ l2) a c := by
  obtain ⟨new1, nl1, hi1, hp1, hl1, hk1⟩ := h1
  obtain ⟨new2, nl2, hi2, hp2, hl2, hk2⟩ := h2
  refine ⟨new1 ++ new2, nl2 ++ nl1, by simp [hi2, hi1], ?_, by simp [hl2, hl1], ?_⟩
  · intro i hi
    rcases List.mem_append.mp hi with h | h
    · exact List.mem_append_left _ (hp1 i h)
    · exact List.mem_append_right _ (hp2 i h)
  · intro kv hkv
    rcases List.mem_append.mp hkv with h | h
    · exact List.mem_append_right _ (hk2 kv h)
    · exact List.mem_append_left _ (hk1 kv h)

theorem Grows.mono {n l n' l' : List String} {a b : State} (h : Grows n l a b)
    (hn : ∀ x ∈ n, x ∈ n') (hl : ∀ x ∈ l, x ∈ l') : Grows n' l' a b := by
  obtain ⟨new, nl, hi, hp, hlb, hk⟩ := h
  exact ⟨new, nl, hi, fun i h => hn _ (hp i h), hlb, fun kv h => hl _ (hk kv h)⟩

/-- The instance a layer extracts carries the layer's protocol. -/
theorem extractInst_proto {c : Ctx} {st : State} {name : String} {spec : ProtoSpec} {inst : Inst}
    (h : extractInst c st name spec = .ok inst) : inst.proto = name := by
  unfold extractInst at h
  cases hb : extractBody c st name spec with
  | error e => simp [hb, bind, Except.bind] at h
  | ok b =>
    obtain ⟨len, aux, patches⟩ := b
    simp [hb, bind, Except.bind, pure, Except.pure] at h
    rw [← h]

theorem push_grows (st : State) (label : Option String) (inst : Inst) :
    Grows [inst.proto] label.toList st (st.push label inst) := by
  refine ⟨[inst], (match label with | some l => [(l, inst)] | none => []), rfl, by simp, ?_, ?_⟩
  · cases label <;> rfl
  · cases label <;> simp

theorem extract_grows {c : Ctx} {st st' : State} {p : ProtoLayer}
    (h : extract c st p = .ok st') : Grows [p.name] p.label.toList st st' := by
  unfold extract at h
  cases hs : c.V.proto? p.name with
  | none => simp [hs] at h
  | some spec =>
    simp only [hs, bind, Except.bind] at h
    cases hx : extractInst c st p.name spec with
    | error e => simp [hx] at h
    | ok inst =>
      simp only [hx] at h
      cases hc : checkPreds c spec inst p.preds with
      | error e => simp [hc] at h
      | ok u =>
        simp [hc, pure, Except.pure] at h
        have hp := extractInst_proto hx
        rw [← h, ← hp]
        exact push_grows st p.label inst

theorem extractOpt_grows {c : Ctx} {st st' : State} {p : ProtoLayer}
    (h : extractOpt c st p = .ok st') : Grows [p.name] p.label.toList st st' := by
  unfold extractOpt at h
  cases hx : extract c st p with
  | ok s =>
    simp only [hx] at h
    split at h
    · simp [pure, Except.pure] at h; rw [← h]; exact extract_grows hx
    · simp [throw, throwThe, MonadExceptOf.throw] at h
  | error e =>
    cases e <;> simp [hx, pure, Except.pure, throw, throwThe, MonadExceptOf.throw] at h
    rw [← h]; exact Grows.refl _ _ _

theorem iterate_grows {c : Ctx} {p : ProtoLayer} {n : Nat} :
    ∀ (fuel k : Nat) (st st' : State), iterate c p n fuel k st = .ok st' →
      Grows [p.name] p.label.toList st st' := by
  intro fuel
  induction fuel with
  | zero =>
    intro k st st' h
    simp only [iterate] at h
    split at h
    · simp [throw, throwThe, MonadExceptOf.throw] at h
    · split at h
      · simp [throw, throwThe, MonadExceptOf.throw] at h
      · simp [pure, Except.pure] at h; rw [← h]; exact Grows.refl _ _ _
  | succ fuel ih =>
    intro k st st' h
    simp only [iterate] at h
    cases hx : extract c st p with
    | ok s =>
      simp only [hx] at h
      have g := Grows.trans (extract_grows hx) (ih _ _ _ h)
      exact g.mono (by simp) (by simp)
    | error e =>
      cases e <;> simp [hx, throw, throwThe, MonadExceptOf.throw] at h
      split at h
      · simp at h
      · simp [pure, Except.pure] at h; rw [← h]; exact Grows.refl _ _ _

theorem evalProtoLayer_grows {c : Ctx} {st st' : State} {p : ProtoLayer}
    (h : evalProtoLayer c st p = .ok st') : Grows [p.name] p.label.toList st st' := by
  unfold evalProtoLayer at h
  cases hs : c.V.proto? p.name with
  | none => simp [hs] at h
  | some spec =>
    simp only [hs, bind, Except.bind] at h
    split at h
    · simp [throw, throwThe, MonadExceptOf.throw] at h
    · split at h
      · exact extract_grows h
      · exact extractOpt_grows h
      · split at h
        · simp [throw, throwThe, MonadExceptOf.throw] at h
        · exact iterate_grows _ _ _ _ h

theorem evalAlt_grows {c : Ctx} {st : State} :
    ∀ (alts : List ProtoLayer) (st' : State), evalAlt c st alts = .ok st' →
      Grows (alts.map (·.name)) (alts.filterMap (·.label)) st st' := by
  intro alts
  induction alts with
  | nil => intro st' h; simp [evalAlt, throw, throwThe, MonadExceptOf.throw] at h
  | cons a rest ih =>
    intro st' h
    have hn : ∀ x ∈ [a.name], x ∈ (a :: rest).map (·.name) := by simp
    have hl : ∀ x ∈ a.label.toList, x ∈ (a :: rest).filterMap (·.label) := by
      intro x hx; cases hlab : a.label <;> simp_all [List.filterMap_cons]
    have hn' : ∀ x ∈ rest.map (·.name), x ∈ (a :: rest).map (·.name) := by
      intro x hx; simp only [List.map_cons, List.mem_cons]; exact Or.inr hx
    have hl' : ∀ x ∈ rest.filterMap (·.label), x ∈ (a :: rest).filterMap (·.label) := by
      intro x hx; cases hlab : a.label <;> simp_all [List.filterMap_cons]
    simp only [evalAlt, bind, Except.bind] at h
    repeat' (split at h)
    all_goals first
      | (simp [throw, throwThe, MonadExceptOf.throw] at h; done)
      | exact (extract_grows h).mono hn hl
      | exact (ih _ h).mono hn' hl'

/-- A chain appends instances of its layers' protocols and binds its
layers' labels, nothing else. -/
theorem evalChain_grows {c : Ctx} :
    ∀ (L : List Layer) (st st' : State), evalChain c L st = .ok st' →
      Grows (L.flatMap Layer.names) (L.flatMap Layer.labels) st st' := by
  intro L
  induction L with
  | nil =>
    intro st st' h
    simp [evalChain, pure, Except.pure] at h
    rw [← h]; exact Grows.refl _ _ _
  | cons l tl ih =>
    intro st st' h
    cases l with
    | proto p =>
      simp only [evalChain, bind, Except.bind] at h
      split at h
      · simp [throw, throwThe, MonadExceptOf.throw] at h
      · cases hp : evalProtoLayer c st p with
        | error e => simp [hp] at h
        | ok s =>
          simp only [hp] at h
          simpa [List.flatMap_cons, Layer.names, Layer.labels] using
            Grows.trans (evalProtoLayer_grows hp) (ih _ _ h)
    | alt alts =>
      simp only [evalChain, bind, Except.bind] at h
      cases hp : evalAlt c st alts with
      | error e => simp [hp] at h
      | ok s =>
        simp only [hp] at h
        simpa [List.flatMap_cons, Layer.names, Layer.labels] using
          Grows.trans (evalAlt_grows alts s hp) (ih _ _ h)

/-- No layer of the chain carries the label `l`, so `l` is not a label. -/
theorem labelProto_shape_none (L : List Layer) (l : String)
    (h : l ∉ L.flatMap Layer.labels) : labelProto (L.map Layer.shape) l = none := by
  induction L with
  | nil => rfl
  | cons x tl ih =>
    simp only [List.flatMap_cons, List.mem_append, not_or] at h
    cases x with
    | proto q =>
      have hq : q.label ≠ some l := by
        intro hql; exact h.1 (by simp [Layer.labels, hql])
      simp [labelProto, List.findSome?_cons, Layer.shape, hq] at *
      exact ih h.2
    | alt alts =>
      simp [labelProto, List.findSome?_cons, Layer.shape] at *
      exact ih h.2

/-- A name that no label shadows resolves to the first instance of its
protocol. -/
theorem resolveRef_first (c : Ctx) (st : State) (name : String) (inst : Inst)
    (before after : List Inst)
    (hproto : staticProto c name = .ok name)
    (hlp : labelProto c.layers name = none)
    (hlabels : ∀ kv ∈ st.labels, kv.1 ≠ name)
    (hinsts : st.insts = before ++ inst :: after)
    (hbefore : ∀ i ∈ before, i.proto ≠ name)
    (hinstp : inst.proto = name) :
    resolveRef c st name = .ok (some inst) := by
  have hfl : st.labels.find? (·.1 == name) = none := by
    rw [List.find?_eq_none]
    intro kv hkv; simpa using hlabels kv hkv
  have hfb : before.find? (·.proto == name) = none := by
    rw [List.find?_eq_none]
    intro i hi; simpa using hbefore i hi
  simp [resolveRef, hproto, hfl, hlp, hinsts, List.find?_append, hfb, hinstp, bind, Except.bind,
    pure, Except.pure]

/-- Dropping a mandatory layer's one bracket predicate cannot turn its
extraction into a failure. -/
theorem evalProtoLayer_drop_pred (c : Ctx) (s1 s2 : State) (p : ProtoLayer) (ρ : Predicate)
    (hq : p.quant = .one) (hnp : p.preds = [])
    (h : evalProtoLayer c s1 { p with preds := [ρ] } = .ok s2) :
    evalProtoLayer c s1 p = .ok s2 := by
  unfold evalProtoLayer at h ⊢
  cases hs : c.V.proto? p.name with
  | none => simp [hs] at h
  | some spec =>
    simp only [hs, hq, quantBounds, bind, Except.bind] at h ⊢
    split at h
    · simp [throw, throwThe, MonadExceptOf.throw] at h
    · rename_i hv
      simp only [hv]
      unfold extract at h ⊢
      simp only [hs, bind, Except.bind] at h ⊢
      cases hx : extractInst c s1 p.name spec with
      | error e => simp [hx] at h
      | ok inst =>
        simp only [hx, checkPreds, hnp] at h ⊢
        cases hp : evalPred c spec inst ρ with
        | error e => cases e <;> simp [hp, throw, throwThe, MonadExceptOf.throw] at h
        | ok b =>
          cases b
          · simp [hp, throw, throwThe, MonadExceptOf.throw] at h
          · simpa [hp] using h

/-- A chain that matches with one bracket predicate on a mandatory layer
matches without it, with the same state. -/
theorem evalChain_drop_pred (c : Ctx) (pre rest : List Layer) (p : ProtoLayer) (ρ : Predicate)
    (st stF : State) (hq : p.quant = .one) (hnp : p.preds = [])
    (h : evalChain c (pre ++ .proto { p with preds := [ρ] } :: rest) st = .ok stF) :
    evalChain c (pre ++ .proto p :: rest) st = .ok stF := by
  rw [evalChain_append] at h ⊢
  cases hpre : evalChain c pre st with
  | error e => simp [hpre, Except.bind] at h
  | ok s1 =>
    simp only [hpre, Except.bind, evalChain, bind] at h ⊢
    split at h
    · simp [throw, throwThe, MonadExceptOf.throw] at h
    · rename_i hg
      have hg' : ¬(s1.insts.isEmpty && (quantBounds p.quant).fst == 0) = true := hg
      simp only [hg']
      cases hpl : evalProtoLayer c s1 { p with preds := [ρ] } with
      | error e => simp [hpl] at h
      | ok s2 =>
        simp only [hpl] at h
        simp [evalProtoLayer_drop_pred c s1 s2 p ρ hq hnp hpl, h]

/-- At the end of a chain, the name of a mandatory layer that is the first
of its protocol and that no label shadows resolves to the instance that
layer extracted. -/
theorem resolveRef_layer (c : Ctx) (pre rest : List Layer) (p : ProtoLayer) (spec : ProtoSpec)
    (inst : Inst) (s1 stF : State)
    (hlayers : c.layers = (pre ++ .proto p :: rest).map Layer.shape)
    (hnames : p.name ∉ pre.flatMap Layer.names)
    (hlab : p.name ∉ (pre ++ .proto p :: rest).flatMap Layer.labels)
    (hproto : staticProto c p.name = .ok p.name)
    (hpre : evalChain c pre {} = .ok s1)
    (hx : extractInst c s1 p.name spec = .ok inst)
    (hrest : evalChain c rest (s1.push p.label inst) = .ok stF) :
    resolveRef c stF p.name = .ok (some inst) := by
  obtain ⟨new1, nl1, hi1, hp1, hl1, hk1⟩ := evalChain_grows pre {} s1 hpre
  obtain ⟨new3, nl3, hi3, hp3, hl3, hk3⟩ := evalChain_grows rest _ stF hrest
  simp only [List.flatMap_append, List.flatMap_cons, List.mem_append, Layer.labels, not_or] at hlab
  apply resolveRef_first c stF p.name inst new1 new3 hproto
  · rw [hlayers]; exact labelProto_shape_none _ _ (by
      simp only [List.flatMap_append, List.flatMap_cons, List.mem_append, Layer.labels, not_or]
      exact hlab)
  · intro kv hkv heq
    rw [hl3] at hkv
    rcases List.mem_append.mp hkv with h | h
    · exact hlab.2.2 (heq ▸ hk3 kv h)
    · simp only [State.push] at h
      have hs1 : kv ∈ s1.labels → False := by
        intro h1; rw [hl1] at h1; simp at h1
        exact hlab.1 (heq ▸ hk1 kv h1)
      cases hpl : p.label with
      | none => rw [hpl] at h; exact hs1 h
      | some l =>
        rw [hpl] at h
        rcases List.mem_cons.mp h with h | h
        · exact hlab.2.1 (by rw [hpl, ← heq, h]; simp)
        · exact hs1 h
  · simp [hi3, State.push, hi1]
  · intro i hi heq
    simp at hi1
    exact hnames (heq ▸ hp1 i hi)
  · exact extractInst_proto hx

/-- `eval` of a filter with no `where` and no capture: the chain decides. -/
theorem eval_chain (H : Host) (V : Vocab) (P : Packet) (L : List Layer)
    (hck : check (Filter.ctx { layers := L } H V P) { layers := L } = none) :
    eval H V { layers := L } P =
      match evalChain (Filter.ctx { layers := L } H V P) L {} with
      | .error (.illTyped r) => .illTyped r
      | .error _ => .reject
      | .ok _ => .accept [] := by
  simp only [eval, hck]
  cases evalChain (Filter.ctx { layers := L } H V P) L {} with
  | error e => cases e <;> rfl
  | ok st => simp [bind, Except.bind, pure, Except.pure]

/-- `eval` of a filter with one `where` and no capture. -/
theorem eval_chain_where (H : Host) (V : Vocab) (P : Packet) (L : List Layer) (w : Where)
    (hck : check (Filter.ctx { layers := L, cond := some w } H V P) { layers := L, cond := some w } = none) :
    eval H V { layers := L, cond := some w } P =
      match evalChain (Filter.ctx { layers := L, cond := some w } H V P) L {} with
      | .error (.illTyped r) => .illTyped r
      | .error _ => .reject
      | .ok st =>
        match evalWhere (Filter.ctx { layers := L, cond := some w } H V P) st [] w with
        | .ok true => .accept []
        | .ok false => .reject
        | .error .reject => .reject
        | .error (.illTyped r) => .illTyped r := by
  simp only [eval, hck]
  cases evalChain (Filter.ctx { layers := L, cond := some w } H V P) L {} with
  | error e => cases e <;> rfl
  | ok st =>
    simp only [bind, Except.bind]
    cases evalWhere (Filter.ctx { layers := L, cond := some w } H V P) st [] w with
    | error e => cases e <;> rfl
    | ok b => cases b <;> simp [pure, Except.pure, throw, throwThe, MonadExceptOf.throw]

/-- `…/p[f op v]/…` and `…/p/… where p.f op v` accept the same packets
(D-023), as filters under `eval`.

The two filters are a chain with one bracket comparison on `p` and no
`where`, and the same chain without it and with the comparison as its
`where`; neither has captures. `p` is a mandatory layer with no other
predicate. No layer is labelled with its name (`hlab`), and the name
resolves statically to the protocol itself (`hproto`: no other layer has
that protocol). The bracket form type-checks; that the where form does,
and that the bracket path resolves, follows (`check_bracket_where`). Then
one filter accepts a packet exactly when the other does.

Only acceptance is related. On a packet neither accepts, the two can
report differently: the bracket stops the chain at its layer, so the
bracket form rejects where the where form goes on to a later layer's
failure. -/
theorem bracket_iff_where_eval
    (H : Host) (V : Vocab) (P : Packet) (pre rest : List Layer) (p : ProtoLayer) (spec : ProtoSpec)
    (f : FieldPath) (op : CmpOp) (v : Value)
    (hq : p.quant = .one) (hnp : p.preds = []) (hname : spec.name = p.name)
    (hspec : V.proto? p.name = some spec)
    (hlab : p.name ∉ (pre ++ .proto p :: rest).flatMap Layer.labels)
    (hproto : staticProto (Filter.ctx { layers := pre ++ .proto p :: rest } H V P) p.name = .ok p.name)
    (hckB : check (Filter.ctx { layers := pre ++ .proto { p with preds := [.cmp f op v] } :: rest } H V P)
      { layers := pre ++ .proto { p with preds := [.cmp f op v] } :: rest } = none) :
    eval H V { layers := pre ++ .proto { p with preds := [.cmp f op v] } :: rest } P = .accept []
      ↔ eval H V { layers := pre ++ .proto p :: rest,
                   cond := some (.litCmp ⟨(p.name, none) :: f.segs⟩ op v) } P = .accept [] := by
  -- both filters run in one context: their chains have the same shape
  have hcB : Filter.ctx ({ layers := pre ++ .proto { p with preds := [.cmp f op v] } :: rest } : Filter) H V P
      = Filter.ctx ({ layers := pre ++ .proto p :: rest } : Filter) H V P := by
    simp [Filter.ctx, Layer.shape]
  have hcW : Filter.ctx ({ layers := pre ++ .proto p :: rest, cond := some (.litCmp ⟨(p.name, none) :: f.segs⟩ op v) } : Filter) H V P
      = Filter.ctx ({ layers := pre ++ .proto p :: rest } : Filter) H V P := rfl
  -- the where form type-checks and the bracket path resolves, from `hckB`
  obtain ⟨hckW, r, hres⟩ := check_bracket_where
    (Filter.ctx { layers := pre ++ .proto p :: rest } H V P) pre rest p spec f op v hq hnp hname hspec hproto
    (hcB ▸ hckB)
  have hckW : check
      (Filter.ctx { layers := pre ++ .proto p :: rest, cond := some (.litCmp ⟨(p.name, none) :: f.segs⟩ op v) } H V P)
      { layers := pre ++ .proto p :: rest, cond := some (.litCmp ⟨(p.name, none) :: f.segs⟩ op v) } = none := hckW
  -- `p` is the first layer of its protocol
  have hnames : p.name ∉ pre.flatMap Layer.names :=
    (staticProto_unique (Filter.ctx { layers := pre ++ .proto p :: rest } H V P) pre rest p hq rfl
      (labelProto_shape_none _ _ hlab) hproto).1
  rw [eval_chain H V P _ hckB, eval_chain_where H V P _ _ hckW, hcB, hcW]
  have hsp : (Filter.ctx { layers := pre ++ .proto p :: rest } H V P).V.proto? p.name = some spec := hspec
  cases hW : evalChain (Filter.ctx { layers := pre ++ .proto p :: rest } H V P) (pre ++ .proto p :: rest) {} with
  | ok stF =>
    obtain ⟨s1, inst, hpre, hx, hrest, hvlan⟩ :=
      evalChain_proto_inv _ pre rest p spec {} stF hq hnp hsp hW
    have hinst := resolveRef_layer _ pre rest p spec inst s1 stF rfl hnames hlab hproto hpre hx hrest
    have key := bracket_eq_where_at _ pre rest p spec inst f op v {} s1 stF hq hname hvlan hpre hx hrest
      (by rw [hname]; exact hproto) (by rw [hname]; exact hsp) (by rw [hname]; exact hinst) hres
    rw [hname] at key
    rw [key]
    cases hw : evalWhere (Filter.ctx { layers := pre ++ .proto p :: rest } H V P) stF []
        (.litCmp ⟨(p.name, none) :: f.segs⟩ op v) with
    | error e => cases e <;> simp [hw]
    | ok b => cases b <;> simp [hw]
  | error e =>
    cases hB : evalChain (Filter.ctx { layers := pre ++ .proto p :: rest } H V P)
        (pre ++ .proto { p with preds := [.cmp f op v] } :: rest) {} with
    | ok st =>
      have hdrop := evalChain_drop_pred _ pre rest p (.cmp f op v) {} st hq hnp hB
      rw [hW] at hdrop
      cases hdrop
    | error e' => cases e <;> cases e' <;> simp

/-- The hypotheses of `bracket_iff_where_eval` are static and are
discharged by evaluation: `eth/ipv4/tcp[dport < 1024]` and
`eth/ipv4/tcp where tcp.dport < 1024` accept the same packets, for every
packet. -/
theorem tcp_dport_bracket_iff_where (pkt : Packet) :
    eval {} vocab { layers := [P "eth", P "ipv4", .proto { name := "tcp", preds := [.cmp (f "dport") .lt (.int 1024)] }] } pkt = .accept []
      ↔ eval {} vocab { layers := chain3, cond := some (.litCmp (ff "tcp" "dport") .lt (.int 1024)) } pkt = .accept [] :=
  bracket_iff_where_eval {} vocab pkt [P "eth", P "ipv4"] [] { name := "tcp" }
    ((vocab.proto? "tcp").get (by decide)) (f "dport") .lt (.int 1024)
    rfl rfl (by decide) (by decide) (by decide) rfl rfl

/-- Alternation order matters when dispatch overlaps (D-004): the first
matching alternative commits. Vector `alt-first-pred-fails`. -/
theorem alt_order_matters :
    eval {} vocab { layers := [P "eth", .alt [{ name := "ipv4", preds := [.cmp (f "ttl") .eq (.int 1)] }, { name := "ipv4" }], P "tcp"] } Pkt.ethIPv4TCP
      ≠ eval {} vocab { layers := [P "eth", .alt [{ name := "ipv4" }, { name := "ipv4", preds := [.cmp (f "ttl") .eq (.int 1)] }], P "tcp"] } Pkt.ethIPv4TCP := by
  decide

end Kunai
