/-!
# Abstract syntax (dsl-types.md §11.2)

One constructor per Go AST shape (`pkg/kunai/ast`). Go's flat structs with a
`Kind` discriminator become inductives here. Deliberately absent:

* `Position` — no semantic content.
* `ValString` — the lexer never produces it.
* `PredHas`, `CapFields` — MVP-unsupported (rejected by resolver / parser).
* Nested alternation groups — the parser accepts `((a|b)|c)` and flattens it,
  so `alt` holds protocol layers only (see DECISIONS.md).
* Indices nested inside an index (`a[b[0].c]`) — rejected by the parser.
-/
namespace Kunai

inductive CmpOp | eq | ne | lt | le | gt | ge
  deriving Repr, BEq, DecidableEq

inductive ArithOp | add | sub | mul | div | mod | band | bor | bxor | shl | shr
  deriving Repr, BEq, DecidableEq

/-- `q ::= 1 | ? | + | * | {n,m}`. `range lo none` is the open form `{n,}`. -/
inductive Quant
  | one | opt | plus | star
  | range (lo : Nat) (hi : Option Nat)
  deriving Repr, BEq, DecidableEq

/-- `[…]` after a path segment (`ast.IndexExpr`). `slice` is a half-open bit
range with bit 0 = network-order MSB. -/
inductive Index
  | nat (n : Nat)
  | field (path : List String)
  | slice (lo hi : Nat)
  deriving Repr, BEq, DecidableEq

/-- `ident(.ident)*`, each segment with an optional index (`ast.FieldPath`). -/
structure FieldPath where
  segs : List (String × Option Index)
  deriving Repr, BEq, DecidableEq

/-- Dotted path without indices, the common case. -/
def FieldPath.ofParts (parts : List String) : FieldPath := ⟨parts.map (·, none)⟩

/-- Literal values (`ast.Value`). Integers are signed here; Go stores the
two's complement with a `Negative` flag, and `Json.lean` converts. -/
inductive Value
  | int (n : Int)
  | ipv4 (a : BitVec 32)
  | ipv6 (a : BitVec 128)
  | mac (a : BitVec 48)
  | cidr4 (a : BitVec 32) (plen : Nat)
  | cidr6 (a : BitVec 128) (plen : Nat)
  | range (lo hi : Nat)
  | ident (name : String)
  deriving Repr, BEq, DecidableEq

/-- Bracket predicate `π` (`ast.Predicate`). -/
inductive Predicate
  | cmp (field : FieldPath) (op : CmpOp) (value : Value)
  | inList (field : FieldPath) (values : List Value)
  | inSet (field : FieldPath) (set : String)
  deriving Repr, BEq, DecidableEq

/-- `proto(p, ℓ?, q, π̄)`. -/
structure ProtoLayer where
  name : String
  label : Option String := none
  preds : List Predicate := []
  quant : Quant := .one
  deriving Repr, BEq, DecidableEq

/-- `L ::= proto(…) | alt(L̄)`. -/
inductive Layer
  | proto (p : ProtoLayer)
  | alt (alts : List ProtoLayer)
  deriving Repr, BEq, DecidableEq

/-- A layer without its bracket predicates: all that static name
resolution (labels, how many instances a name can bind) looks at. -/
def Layer.shape : Layer → Layer
  | .proto p => .proto { p with preds := [] }
  | .alt alts => .alt (alts.map fun a => { a with preds := [] })

/-- The protocols a layer can extract. -/
def Layer.names : Layer → List String
  | .proto p => [p.name]
  | .alt alts => alts.map (·.name)

/-- The labels a layer can bind. -/
def Layer.labels : Layer → List String
  | .proto p => p.label.toList
  | .alt alts => alts.filterMap (·.label)

/-- `e ::= const(n) | field(f) | binop(op, e, e)` (`ast.ArithExpr`). -/
inductive Arith
  | const (n : Int)
  | field (f : FieldPath)
  | bin (op : ArithOp) (l r : Arith)
  deriving Repr, BEq, DecidableEq

/-- `w` (`ast.WhereExpr`). `litCmp` only ever carries `eq`/`ne`; `boolEq`
likewise (the parser rejects ordered comparison on those). -/
inductive Where
  | or (l r : Where)
  | and (l r : Where)
  | not (w : Where)
  | arith (l : Arith) (op : CmpOp) (r : Arith)
  | litCmp (field : FieldPath) (op : CmpOp) (value : Value)
  | action (name : String)
  | any (w : Where)
  | all (w : Where)
  | boolLit (b : Bool)
  | fieldExists (field : FieldPath)
  /-- `head.options.valid` (D-029): the layer's declared option region
  parsed without fault. `field` is `head.options`. -/
  | optionsValid (field : FieldPath)
  | boolEq (l : Where) (op : CmpOp) (r : Where)
  deriving Repr, BEq, DecidableEq

/-- `spec ::= all | headers | headers+N | layer(+N) | absolute(N)`.
Go cannot distinguish `capture x` from `capture x+0`; neither can we. -/
inductive CaptureSpec
  | all
  | headers
  | headersPlus (n : Nat)
  | toLayer (name : String) (extra : Nat)
  | absolute (n : Nat)
  deriving Repr, BEq, DecidableEq

/-- `c ::= cap(spec, w?)`. -/
structure Capture where
  spec : CaptureSpec
  cond : Option Where := none
  deriving Repr, BEq, DecidableEq

/-- `F ::= ⟨L̄, w?, c̄⟩`. -/
structure Filter where
  layers : List Layer
  cond : Option Where := none
  captures : List Capture := []
  deriving Repr, BEq, DecidableEq

end Kunai
