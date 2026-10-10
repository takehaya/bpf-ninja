import Kunai.Syntax
import Kunai.Packet
import Kunai.Vocab
import Kunai.Host
import Kunai.Print

/-!
# Evaluator core: state (§13.1), results, field reads, literal lifting
-/
namespace Kunai

/-- An extracted aux header (`AuxView` in §13.1): an option, or one stack
entry (`stackIdx = some k`), at `[off, off+len)` in the packet. -/
structure AuxView where
  outParam : String
  header : String
  stackIdx : Option Nat := none
  off : Nat
  len : Nat
  deriving Repr, BEq, DecidableEq

/-- A matched layer instance: protocol and byte range `[off, off+len)`,
its aux views (`α` restricted to this layer), and the bytes the parser
wrote back into its primary header (`@kunai_writeback`). -/
structure Inst where
  proto : String
  off : Nat
  len : Nat
  aux : List AuxView := []
  patches : List (Nat × Nat) := []
  /-- The parser walked the declared option region without fault (D-029);
  `false` when the region was malformed and the layer has no options. -/
  optsValid : Bool := true
  /-- Stacks that filled up inside the declared region: the packet holds
  more entries than the stack keeps, so `all` over them is false. -/
  truncated : List String := []
  deriving Repr, BEq, DecidableEq

/-- The packet as this layer's parser left it: write-backs applied. -/
def patched (P : Packet) (patches : List (Nat × Nat)) : Packet :=
  patches.foldl (fun acc (i, v) => acc.set i (UInt8.ofNat v)) P

/-- `σ = ⟨π, α, Λ⟩`. `insts` is the resolved chain in order, each carrying
its slice of `α` (`Inst.aux`); `labels` is `Λ`, most recent binding first
(`Λ ⊕ {ℓ ↦ inst}`). -/
structure State where
  cursor : Nat := 0
  insts : List Inst := []
  labels : List (String × Inst) := []
  deriving Repr, BEq, DecidableEq

inductive Result
  | accept (captures : List (Nat × Nat))
  | reject
  /-- The resolver rejects this filter (§12); tests expect `Compile` to fail. -/
  | illTyped (reason : String)
  deriving Repr, BEq, DecidableEq

/-- Why one layer failed. Quantifiers distinguish the cases (§13.5). -/
inductive LayerFail
  | dispMiss
  | bounds
  | pred
  | illTyped (reason : String)
  deriving Repr, BEq, DecidableEq

/-- Why a `where` / capture evaluation stopped. -/
inductive Stop
  | reject
  | illTyped (reason : String)
  deriving Repr, BEq, DecidableEq

/-- Everything the evaluator reads but never writes. -/
structure Ctx where
  V : Vocab
  H : Host
  /-- The shape of the filter's chain (`Layer.shape`: no bracket
  predicates), for static resolution of field references. Two filters
  that differ only in bracket predicates share this context. -/
  layers : List Layer
  P : Packet

/-- `(n, m)` of `q`; `none` = `m_chain`. -/
def quantBounds : Quant → Nat × Option Nat
  | .one => (1, some 1) | .opt => (0, some 1) | .plus => (1, none) | .star => (0, none)
  | .range n m => (n, m)

/-- Hard cap on quantifier iterations (`bpfLoopChainCap` in Go). -/
def chainCap : Nat := 32

def readField (P : Packet) (inst : Inst) (f : FieldSpec) : Option Nat :=
  readBits (patched P inst.patches) (inst.off * 8 + f.bitOff) f.width

def cmpNat (op : CmpOp) (a b : Nat) : Bool :=
  match op with
  | .eq => a == b | .ne => a != b | .lt => a < b | .le => a ≤ b | .gt => a > b | .ge => a ≥ b

/-- Two's complement of `n` in `w` bits, after the §7.3 fit check
`-2^(w-1) ≤ n < 2^w` (T-IntLit narrow). -/
def narrowInt (w : Nat) (n : Int) : Except String Nat :=
  -- A plain literal is at most 64 bits whatever the width it narrows to;
  -- a wider value is written `int<128>(n)`.
  if w > 64 ∧ n ≥ (2 : Int) ^ 64 then
    throw s!"literal {n} exceeds 64 bits; write int<128>({n}) for a wider value"
  else if w > 64 ∧ n < -((2 : Int) ^ 63) then
    throw s!"literal {n} is below -2^63"
  else if n < -((2 : Int) ^ (w - 1)) ∨ n ≥ (2 : Int) ^ w then
    throw s!"literal {n} does not fit Int<{w}>"
  else if n < 0 then pure ((2 : Int) ^ w + n).toNat
  else pure n.toNat

/-- `lift(v)` against a field of width `w` (T-IntLit, T-IPv4Lit, T-IPv6Lit, T-MACLit). -/
def liftValue (w : Nat) : Value → Except String Nat
  | .int n => narrowInt w n
  | .ipv4 a => if w == 32 then pure a.toNat else throw "ipv4 literal requires an Int<32> field"
  | .ipv6 a => if w == 128 then pure a.toNat else throw "ipv6 literal requires an Int<128> field"
  | .mac a => if w == 48 then pure a.toNat else throw "mac literal requires an Int<48> field"
  | .cidr4 .. => throw "cidr literal is not a plain value"
  | .cidr6 .. => throw "cidr literal is not a plain value"
  | .range .. => throw "range literal is only valid in `in [...]`"
  | .ident s => throw s!"unsupported: identifier literal {s}"

/-- `int<128>(n)`: the value must fit 128 bits. -/
def wideLit (n : Nat) : Except String Nat :=
  if n ≥ 2 ^ 128 then throw s!"int<128>({n}) does not fit Int<128>" else pure n

/-- T-CmpCIDR4 / T-CmpCIDR6: subnet membership, `==` / `!=` only. -/
private def cidrCmp (w W : Nat) (n : Nat) (op : CmpOp) (a k : Nat) : Except String Bool := do
  if w != W then throw s!"cidr literal requires an Int<{W}> field"
  let member := n / 2 ^ (W - k) == a / 2 ^ (W - k)
  match op with
  | .eq => pure member
  | .ne => pure (!member)
  | _ => throw "ordered comparison on a cidr literal"

/-- A typing failure found while evaluating stops the evaluation as
ill-typed. One named adapter (rather than `Except.mapError` at each site)
so the where atom and the bracket predicate end in the same term. -/
def Stop.ofExcept (e : Except String α) : Except Stop α :=
  match e with
  | .ok a => pure a
  | .error r => throw (.illTyped r)

/-- `op_c(n_f, lift(v))` for a field value `n` of width `w` (E-Pred-Cmp, E-W-LitCmp). -/
def cmpValue (w : Nat) (n : Nat) (op : CmpOp) : Value → Except String Bool
  | .cidr4 a k => cidrCmp w 32 n op a.toNat k
  | .cidr6 a k => cidrCmp w 128 n op a.toNat k
  | v => do pure (cmpNat op n (← liftValue w v))

end Kunai
