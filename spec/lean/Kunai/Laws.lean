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

/-- One iteration bounded by `{1,1}` is one extraction (E-Quant-Range-Step with n = m = 1). -/
theorem iterate_one (c : Ctx) (st : State) (p : ProtoLayer) :
    iterate c p 1 1 0 st = extract c st p := by
  simp only [iterate]
  cases extract c st p with
  | ok st' => rfl
  | error e => cases e <;> rfl

/-- `proto{1,1}` ≡ `proto` (dsl-usage.md: `{n}` ≡ `{n,n}`, instance n = 1). -/
theorem one_eq_range_layer (c : Ctx) (st : State) (p : ProtoLayer) :
    evalProtoLayer c st { p with quant := .range 1 (some 1) }
      = evalProtoLayer c st { p with quant := .one } := by
  unfold evalProtoLayer
  cases c.V.proto? p.name with
  | none => rfl
  | some spec =>
    simp only [quantBounds, extract_quant, bind, Except.bind, chainCap, Option.getD]
    simp [iterate_one, extract_quant]

/-- The same, inside a chain. -/
theorem one_eq_range_chain (c : Ctx) (st : State) (p : ProtoLayer) (rest : List Layer) :
    evalChain c (.proto { p with quant := .range 1 (some 1) } :: rest) st
      = evalChain c (.proto { p with quant := .one } :: rest) st := by
  simp [evalChain, quantBounds, one_eq_range_layer]

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

/-- `proto?` ≡ `proto{0,1}` (D-005): both skip on a dispatch miss only. -/
theorem opt_eq_range (c : Ctx) (st : State) (p : ProtoLayer) :
    evalProtoLayer c st { p with quant := .opt }
      = evalProtoLayer c st { p with quant := .range 0 (some 1) } := by
  unfold evalProtoLayer
  cases c.V.proto? p.name with
  | none => rfl
  | some spec =>
    simp only [quantBounds, extract_quant, bind, Except.bind, chainCap, Option.getD, iterate]
    cases h : extract c st p with
    | ok st' => simp; rfl
    | error e => cases e <;> simp <;> rfl

/-- Alternation order matters when dispatch overlaps (D-004): the first
matching alternative commits. Vector `alt-first-pred-fails`. -/
theorem alt_order_matters :
    eval {} vocab { layers := [P "eth", .alt [{ name := "ipv4", preds := [.cmp (f "ttl") .eq (.int 1)] }, { name := "ipv4" }], P "tcp"] } Pkt.ethIPv4TCP
      ≠ eval {} vocab { layers := [P "eth", .alt [{ name := "ipv4" }, { name := "ipv4", preds := [.cmp (f "ttl") .eq (.int 1)] }], P "tcp"] } Pkt.ethIPv4TCP := by
  decide

end Kunai
