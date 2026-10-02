import Kunai.Eval.Core
import Kunai.Eval.Layer
import Kunai.Eval.Where
import Kunai.Eval.Check

/-!
# `eval` (§13.2): the whole filter
-/
namespace Kunai

/-- The read-only context a filter is evaluated in. Its `layers` is the
chain's shape, so filters that differ only in bracket predicates share it. -/
def Filter.ctx (F : Filter) (H : Host) (V : Vocab) (P : Packet) : Ctx :=
  { V, H, layers := F.layers.map Layer.shape, P }

/-- E-Filter-Accept / E-Filter-Reject-Chain / E-Filter-Reject-Where. -/
def eval (H : Host) (V : Vocab) (F : Filter) (P : Packet) : Result :=
  let c : Ctx := F.ctx H V P
  match check c F with
  | some r => .illTyped r
  | none =>
  match evalChain c F.layers {} with
  | .error (.illTyped r) => .illTyped r
  | .error _ => .reject
  | .ok st =>
    let verdict : Except Stop (List (Nat × Nat)) := do
      let ok ← match F.cond with | some w => evalWhere c st [] w | none => pure true
      if !ok then throw .reject
      let cs ← F.captures.mapM (evalCapture c st)
      pure (cs.filterMap id)
    match verdict with
    | .ok cs => .accept cs
    | .error .reject => .reject
    | .error (.illTyped r) => .illTyped r

end Kunai
