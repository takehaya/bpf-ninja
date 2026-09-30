import Kunai.Syntax
/-!
# Printer: AST → canonical DSL text (dsl-grammar.md)

One canonical form so that `parser.Parse (print F)` in Go yields `F` again:

* layers joined by `/`, predicates before the quantifier (`vlan[tci==1]?`);
* every binary `where` / arithmetic node is parenthesised except at the top
  of a `where` clause or inside `any(…)` / `all(…)`;
* IPv6 is printed as eight 4-digit hex groups (no `::` compression).
-/

namespace Kunai

private def hexDigit (n : Nat) : Char :=
  if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

/-- Fixed-width lowercase hex. -/
def hexN (width : Nat) (n : Nat) : String :=
  String.ofList ((List.range width).reverse.map fun i => hexDigit ((n / 16 ^ i) % 16))

private def sepBy (sep : String) (xs : List String) : String :=
  String.intercalate sep xs

def ipv4Text (a : BitVec 32) : String :=
  sepBy "." ((List.range 4).reverse.map fun i => toString ((a.toNat / 256 ^ i) % 256))

def ipv6Text (a : BitVec 128) : String :=
  sepBy ":" ((List.range 8).reverse.map fun i => hexN 4 ((a.toNat / 65536 ^ i) % 65536))

def macText (a : BitVec 48) : String :=
  sepBy ":" ((List.range 6).reverse.map fun i => hexN 2 ((a.toNat / 256 ^ i) % 256))

def CmpOp.text : CmpOp → String
  | .eq => "==" | .ne => "!=" | .lt => "<" | .le => "<=" | .gt => ">" | .ge => ">="

def ArithOp.text : ArithOp → String
  | .add => "+" | .sub => "-" | .mul => "*" | .div => "/" | .mod => "%"
  | .band => "&" | .bor => "|" | .bxor => "^" | .shl => "<<" | .shr => ">>"

def Value.text : Value → String
  | .int n => toString n
  | .ipv4 a => ipv4Text a
  | .ipv6 a => ipv6Text a
  | .mac a => macText a
  | .cidr4 a p => ipv4Text a ++ "/" ++ toString p
  | .cidr6 a p => ipv6Text a ++ "/" ++ toString p
  | .range lo hi => toString lo ++ ".." ++ toString hi
  | .ident s => s

def Index.text : Index → String
  | .nat n => toString n
  | .field parts => sepBy "." parts
  | .slice lo hi => toString lo ++ ":" ++ toString hi

def FieldPath.text (f : FieldPath) : String :=
  sepBy "." (f.segs.map fun (name, idx) =>
    name ++ (match idx with | some i => "[" ++ i.text ++ "]" | none => ""))

def Quant.text : Quant → String
  | .one => "" | .opt => "?" | .plus => "+" | .star => "*"
  | .range lo (some hi) => "{" ++ toString lo ++ "," ++ toString hi ++ "}"
  | .range lo none => "{" ++ toString lo ++ ",}"

def Predicate.text : Predicate → String
  | .cmp f op v => f.text ++ " " ++ op.text ++ " " ++ v.text
  | .inList f vs => f.text ++ " in [" ++ sepBy ", " (vs.map Value.text) ++ "]"
  | .inSet f s => f.text ++ " in @" ++ s

def ProtoLayer.text (p : ProtoLayer) : String :=
  p.name
    ++ (match p.label with | some l => "@" ++ l | none => "")
    ++ (if p.preds.isEmpty then "" else "[" ++ sepBy ", " (p.preds.map Predicate.text) ++ "]")
    ++ p.quant.text

def Layer.text : Layer → String
  | .proto p => p.text
  | .alt alts => "(" ++ sepBy "|" (alts.map ProtoLayer.text) ++ ")"

def Arith.text : Arith → String
  | .const n => toString n
  | .field f => f.text
  | .bin op l r => "(" ++ l.text ++ " " ++ op.text ++ " " ++ r.text ++ ")"

mutual
/-- Parenthesised form, safe in any operand position. -/
def Where.text : Where → String
  | .or l r => "(" ++ l.text ++ " or " ++ r.text ++ ")"
  | .and l r => "(" ++ l.text ++ " and " ++ r.text ++ ")"
  | .not w => "not " ++ w.text
  | .arith l op r => "(" ++ l.text ++ " " ++ op.text ++ " " ++ r.text ++ ")"
  | .litCmp f op v => "(" ++ f.text ++ " " ++ op.text ++ " " ++ v.text ++ ")"
  | .action a => "action == " ++ a
  | .any w => "any(" ++ w.textTop ++ ")"
  | .all w => "all(" ++ w.textTop ++ ")"
  | .boolLit b => if b then "true" else "false"
  | .fieldExists f => f.text ++ ".exists"
  | .boolEq l op r => "(" ++ l.text ++ " " ++ op.text ++ " " ++ r.text ++ ")"

/-- Top-of-clause form: one layer of parentheses dropped. -/
def Where.textTop : Where → String
  | .or l r => l.text ++ " or " ++ r.text
  | .and l r => l.text ++ " and " ++ r.text
  | .arith l op r => l.text ++ " " ++ op.text ++ " " ++ r.text
  | .litCmp f op v => f.text ++ " " ++ op.text ++ " " ++ v.text
  | .boolEq l op r => l.text ++ " " ++ op.text ++ " " ++ r.text
  | w => w.text
end

def CaptureSpec.text : CaptureSpec → String
  | .all => "all"
  | .headers => "headers"
  | .headersPlus n => "headers+" ++ toString n
  | .toLayer name 0 => name
  | .toLayer name n => name ++ "+" ++ toString n
  | .absolute n => "absolute " ++ toString n

def Capture.text (c : Capture) : String :=
  "capture " ++ c.spec.text ++ (match c.cond with | some w => " where " ++ w.textTop | none => "")

/-- `print F`: the canonical DSL text of a filter. -/
def Filter.text (F : Filter) : String :=
  sepBy "/" (F.layers.map Layer.text)
    ++ (match F.cond with | some w => " where " ++ w.textTop | none => "")
    ++ String.join (F.captures.map fun c => " " ++ c.text)

end Kunai
