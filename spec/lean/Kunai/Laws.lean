import Kunai.Eval
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
    (ha : evalWhere c st a = .ok x) (hb : evalWhere c st b = .ok y) :
    evalWhere c st (.and a b) = evalWhere c st (.and b a) := by
  simp [evalWhere, ha, hb, bind, Except.bind, logic, Bool.and_comm]

theorem or_comm_where (c : Ctx) (st : State) (a b : Where) (x y : Bool)
    (ha : evalWhere c st a = .ok x) (hb : evalWhere c st b = .ok y) :
    evalWhere c st (.or a b) = evalWhere c st (.or b a) := by
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

/-- Alternation order matters when dispatch overlaps (D-004): the first
matching alternative commits. Vector `alt-first-pred-fails`. -/
theorem alt_order_matters :
    eval {} vocab { layers := [P "eth", .alt [{ name := "ipv4", preds := [.cmp (f "ttl") .eq (.int 1)] }, { name := "ipv4" }], P "tcp"] } Pkt.ethIPv4TCP
      ≠ eval {} vocab { layers := [P "eth", .alt [{ name := "ipv4" }, { name := "ipv4", preds := [.cmp (f "ttl") .eq (.int 1)] }], P "tcp"] } Pkt.ethIPv4TCP := by
  decide

end Kunai
