import Lean.Data.Json
import Kunai.Syntax
import Kunai.Print
/-!
# JSON encoding for the Go side

Every node is a tagged object `{"kind": …}`. 64-bit integers travel as decimal
strings; addresses as their DSL text. Integers use Go's representation
(`ast.Value.Int` / `ast.ArithExpr.Const`): the two's complement in `value`
plus a `negative` flag. The Go mirror is `spec_ast_json_test.go` in
`pkg/kunai/dsltest`; the two must agree key for key.
-/

namespace Kunai
open Lean (Json ToJson)

private def u64Str (n : Nat) : Json := Json.str (toString n)

/-- Signed integer as Go stores it: `{"value": "<two's complement>", "negative": b}`. -/
private def intFields (n : Int) : List (String × Json) :=
  if n < 0 then
    [("value", u64Str (2 ^ 64 + n).toNat), ("negative", Json.bool true)]
  else
    [("value", u64Str n.toNat), ("negative", Json.bool false)]

private def optJson (f : α → Json) : Option α → Json
  | some x => f x
  | none => Json.null

def CmpOp.toJson (op : CmpOp) : Json := Json.str op.text
def ArithOp.toJson (op : ArithOp) : Json := Json.str op.text

def Quant.toJson : Quant → Json
  | .one => Json.mkObj [("kind", "one")]
  | .opt => Json.mkObj [("kind", "opt")]
  | .plus => Json.mkObj [("kind", "plus")]
  | .star => Json.mkObj [("kind", "star")]
  | .range lo hi => Json.mkObj [("kind", "range"), ("lo", lo), ("hi", optJson (fun h : Nat => h) hi)]

def Index.toJson : Index → Json
  | .nat n => Json.mkObj [("kind", "int"), ("value", u64Str n)]
  | .field parts => Json.mkObj [("kind", "field"), ("parts", Json.arr (parts.map Json.str).toArray)]
  | .slice lo hi => Json.mkObj [("kind", "slice"), ("lo", u64Str lo), ("hi", u64Str hi)]

def FieldPath.toJson (f : FieldPath) : Json :=
  Json.mkObj [("parts", Json.arr (f.segs.map fun (name, idx) =>
    Json.mkObj [("name", name), ("index", optJson Index.toJson idx)]).toArray)]

def Value.toJson : Value → Json
  | .int n => Json.mkObj (("kind", "int") :: intFields n)
  | .ipv4 a => Json.mkObj [("kind", "ipv4"), ("value", ipv4Text a)]
  | .ipv6 a => Json.mkObj [("kind", "ipv6"), ("value", ipv6Text a)]
  | .mac a => Json.mkObj [("kind", "mac"), ("value", macText a)]
  | v@(.cidr4 ..) => Json.mkObj [("kind", "cidr"), ("value", v.text)]
  | v@(.cidr6 ..) => Json.mkObj [("kind", "cidr"), ("value", v.text)]
  | .range lo hi => Json.mkObj [("kind", "range"), ("lo", u64Str lo), ("hi", u64Str hi)]
  | .ident s => Json.mkObj [("kind", "ident"), ("value", s)]

def Predicate.toJson : Predicate → Json
  | .cmp f op v => Json.mkObj [("kind", "cmp"), ("field", f.toJson), ("op", op.toJson), ("value", v.toJson)]
  | .inList f vs => Json.mkObj [("kind", "in"), ("field", f.toJson), ("values", Json.arr (vs.map Value.toJson).toArray)]
  | .inSet f s => Json.mkObj [("kind", "inSet"), ("field", f.toJson), ("set", s)]
  | .optionsValid f => Json.mkObj [("kind", "valid"), ("field", f.toJson)]

def ProtoLayer.toJson (p : ProtoLayer) : Json :=
  Json.mkObj [("kind", "proto"), ("name", p.name), ("label", optJson Json.str p.label),
    ("preds", Json.arr (p.preds.map Predicate.toJson).toArray), ("quant", p.quant.toJson)]

def Layer.toJson : Layer → Json
  | .proto p => p.toJson
  | .alt alts => Json.mkObj [("kind", "alt"), ("alts", Json.arr (alts.map ProtoLayer.toJson).toArray)]

def Arith.toJson : Arith → Json
  | .const n => Json.mkObj (("kind", "const") :: intFields n)
  | .wide n => Json.mkObj [("kind", "wide"), ("value", u64Str n)]
  | .field f => Json.mkObj [("kind", "field"), ("field", f.toJson)]
  | .bin op l r => Json.mkObj [("kind", "bin"), ("op", op.toJson), ("left", l.toJson), ("right", r.toJson)]

def Where.toJson : Where → Json
  | .or l r => Json.mkObj [("kind", "or"), ("left", l.toJson), ("right", r.toJson)]
  | .and l r => Json.mkObj [("kind", "and"), ("left", l.toJson), ("right", r.toJson)]
  | .not w => Json.mkObj [("kind", "not"), ("inner", w.toJson)]
  | .arith l op r => Json.mkObj [("kind", "arith"), ("left", l.toJson), ("op", op.toJson), ("right", r.toJson)]
  | .litCmp f op v => Json.mkObj [("kind", "litCmp"), ("field", f.toJson), ("op", op.toJson), ("value", v.toJson)]
  | .action a => Json.mkObj [("kind", "action"), ("value", a)]
  | .any w => Json.mkObj [("kind", "any"), ("inner", w.toJson)]
  | .all w => Json.mkObj [("kind", "all"), ("inner", w.toJson)]
  | .boolLit b => Json.mkObj [("kind", "bool"), ("value", b)]
  | .fieldExists f => Json.mkObj [("kind", "exists"), ("field", f.toJson)]
  | .optionsValid f => Json.mkObj [("kind", "valid"), ("field", f.toJson)]
  | .boolEq l op r => Json.mkObj [("kind", "boolEq"), ("left", l.toJson), ("op", op.toJson), ("right", r.toJson)]

def CaptureSpec.toJson : CaptureSpec → Json
  | .all => Json.mkObj [("kind", "all")]
  | .headers => Json.mkObj [("kind", "headers")]
  | .headersPlus n => Json.mkObj [("kind", "headersPlus"), ("extra", n)]
  | .toLayer name n => Json.mkObj [("kind", "toLayer"), ("layer", name), ("extra", n)]
  | .absolute n => Json.mkObj [("kind", "absolute"), ("extra", n)]

def Capture.toJson (c : Capture) : Json :=
  Json.mkObj [("spec", c.spec.toJson), ("where", optJson Where.toJson c.cond)]

def Filter.toJson (F : Filter) : Json :=
  Json.mkObj [("layers", Json.arr (F.layers.map Layer.toJson).toArray),
    ("where", optJson Where.toJson F.cond),
    ("captures", Json.arr (F.captures.map Capture.toJson).toArray)]

instance : ToJson Filter := ⟨Filter.toJson⟩

/-- Bytes as lowercase hex, two digits per byte. -/
def hexOfBytes (bs : List UInt8) : String :=
  String.join (bs.map fun b => hexN 2 b.toNat)

end Kunai
