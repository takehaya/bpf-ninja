import Kunai.Eval.Core
import Kunai.Eval.Layer
import Kunai.Eval.Where
import Kunai.Eval.Check

/-!
# `eval` (§13.2): the whole filter
-/
namespace Kunai

/-- E-Filter-Accept / E-Filter-Reject-Chain / E-Filter-Reject-Where. -/
def eval (H : Host) (V : Vocab) (F : Filter) (P : Packet) : Result :=
  let c : Ctx := { V, H, layers := F.layers, P }
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
