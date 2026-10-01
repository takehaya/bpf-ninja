/-!
# p4lite parser machine as data (§14)

Mirror of `vocab.ParseStateMachine` (`pkg/kunai/vocab/model.go`), the
loader's output for a protocol's `parser` block. Byte offsets follow the
loader's conventions: `LenExpr.byteOff` is within the named header for
`CounterOp.set` / `AdvanceOp.field`, and from the cursor for lookaheads.
`Kunai/VocabData.lean` is generated from the bundled `.p4` files by
`spec/lean/gen/vocab2lean`; do not edit it by hand.
-/
namespace Kunai

structure FieldSpec where
  name : String
  bitOff : Nat
  width : Nat
  deriving Repr, BEq, DecidableEq

/-- A header type: its fields laid out back to back, and its byte size. -/
structure HeaderDecl where
  name : String
  fields : List FieldSpec
  bytes : Nat
  deriving Repr, BEq, DecidableEq

/-- `((byte & mask) >> shift) * scale - base + addend` (`vocab.HeaderLength`). -/
structure LenExpr where
  byteOff : Nat
  mask : Nat
  shift : Nat
  scale : Nat
  base : Nat
  addend : Nat := 0
  deriving Repr, BEq, DecidableEq

def LenExpr.apply (e : LenExpr) (b : Nat) : Option Nat :=
  let v := ((b &&& e.mask) >>> e.shift) * e.scale + e.addend
  if v < e.base then none else some (v - e.base)

inductive AdvanceOp
  | literal (bytes : Nat)
  /-- `pkt.advance(((target.f - K) << S))`: `byteOff` is within `target`'s view. -/
  | field (target : String) (len : LenExpr)
  /-- `pkt.advance(lookahead<bit<M>>()[hi:lo] << S)`: `byteOff` is from the cursor. -/
  | lookahead (len : LenExpr)
  deriving Repr, BEq, DecidableEq

inductive CounterOp
  /-- `c.set(((hdr.f - K) << S))`: `byteOff` is within the primary header. -/
  | set (counter : String) (len : LenExpr)
  | decLiteral (counter : String) (bytes : Nat)
  /-- `c.decrement(target.f)` with an 8-bit field at `byteOff` of `target`'s view. -/
  | decField (counter target : String) (byteOff : Nat)
  /-- `c.decrement(lookahead<bit<M>>()[hi:lo])`: a byte at `byteOff` from the cursor. -/
  | decLookahead (counter : String) (byteOff : Nat)
  deriving Repr, BEq, DecidableEq

inductive SelectKey
  /-- A field of an already extracted header (`target` = out parameter, or the
  stack name with `stackLast`). -/
  | field (target : String) (stackLast : Bool) (bitOff width : Nat)
  | lookahead (bits : Nat)
  | counterIsZero (counter : String)
  deriving Repr, BEq, DecidableEq

inductive MatchVal
  | wild
  | val (n : Nat)
  | bool (b : Bool)
  deriving Repr, BEq, DecidableEq

inductive Target
  | state (i : Nat)
  | accept
  | reject
  deriving Repr, BEq, DecidableEq

structure SelectCase where
  values : List MatchVal
  target : Target
  deriving Repr, BEq, DecidableEq

structure Select where
  keys : List SelectKey
  cases : List SelectCase
  default : Target
  deriving Repr, BEq, DecidableEq

inductive Trans
  | goto (t : Target)
  | select (s : Select)
  deriving Repr, BEq, DecidableEq

structure Extract where
  /-- Out parameter: the primary header's name, an option name, or a stack name. -/
  outParam : String
  header : String
  bytes : Nat
  stackPush : Bool
  deriving Repr, BEq, DecidableEq

structure ParseState where
  name : String
  extracts : List Extract
  counters : List CounterOp
  advances : List AdvanceOp
  trans : Trans
  deriving Repr, BEq, DecidableEq

structure StackDecl where
  name : String
  header : String
  capacity : Nat
  elemBytes : Nat
  /-- Declare-only stacks laid out after an owner option (`tcp.blocks` after `sack`). -/
  ownerOption : String := ""
  offsetAfterOwner : Nat := 0
  deriving Repr, BEq, DecidableEq

/-- `@kunai_variable_tail[len_field, scale, mask]`: extra bytes after the fixed header. -/
structure TailRule where
  byteOff : Nat
  mask : Nat
  shift : Nat
  scale : Nat
  base : Nat
  deriving Repr, BEq, DecidableEq

/-- `@kunai_writeback[source, parent]`: copy a byte of the aux into the primary header view. -/
structure WriteBack where
  sourceByteOff : Nat
  parentByteOff : Nat
  deriving Repr, BEq, DecidableEq

structure Machine where
  states : List ParseState
  entry : Nat
  headers : List HeaderDecl
  stacks : List StackDecl
  tails : List (String × TailRule)
  writebacks : List (String × WriteBack)
  deriving Repr, BEq, DecidableEq

def Machine.header? (m : Machine) (name : String) : Option HeaderDecl :=
  m.headers.find? (·.name == name)

def Machine.stack? (m : Machine) (name : String) : Option StackDecl :=
  m.stacks.find? (·.name == name)

end Kunai
