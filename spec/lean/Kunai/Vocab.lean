import Kunai.Machine

/-!
# Vocabulary (protocol table) types

The data lives in `Kunai/VocabData.lean`, generated from
`pkg/kunai/protocols/*.p4` by `spec/lean/gen/vocab2lean` (`make lean-vocab`).
Primary header, length rule, self-validation, dispatch edges, and the p4lite
parser machine for aux headers (§14).
-/
namespace Kunai

structure FlagTrigger where
  name : String
  bitMask : Nat
  lenBytes : Nat
  deriving Repr, BEq, DecidableEq

structure ProtoSpec where
  name : String
  fields : List FieldSpec
  /-- Byte length of the fixed header (`SumBits / 8`). -/
  fixedLen : Nat
  /-- Declared total length minus the fixed header (ipv4 IHL, tcp data offset):
  `vocab.HeaderLength`, applied to a byte of the primary header. -/
  lenRule : Option LenExpr := none
  /-- Self-validation of the start state (`select(version) { 4: …; default: reject }`):
  the field must take one of the listed values. -/
  requires : List (String × List Nat) := []
  /-- `<SELF>_CHAIN_END_<FIELD> = v`: a self-chain stops after a header whose field equals `v`. -/
  chainEnd : Option (String × Nat) := none
  /-- `<SELF>_MAX_DEPTH` (default 8): iteration bound for `+`, `*`, `{n,}` and the parser loop. -/
  maxDepth : Nat := 8
  /-- p4lite parser machine for aux headers; `none` for extract-and-accept parsers. -/
  machine : Option Machine := none
  /-- Reserved path segment for option lookups (`tcp.options.MSS.value`). -/
  optionSegment : String := "options"
  flagsByteOff : Nat := 0
  flagTriggers : List FlagTrigger := []
  deriving Repr, BEq, DecidableEq

inductive EdgeKind
  | noCheck
  | field (name : String) (values : List Nat)
  deriving Repr, BEq, DecidableEq

/-- `KUNAI_<CHILD>_<PARENT>_<FIELD> = v` (with `_ALT_*` folded into `values`)
or `KUNAI_<CHILD>_<PARENT>_NO_CHECK`. -/
structure Edge where
  child : String
  parent : String
  kind : EdgeKind
  deriving Repr, BEq, DecidableEq

structure Vocab where
  protos : List ProtoSpec
  edges : List Edge
  deriving Repr, BEq, DecidableEq

def Vocab.proto? (V : Vocab) (name : String) : Option ProtoSpec :=
  V.protos.find? (·.name == name)

def Vocab.edge? (V : Vocab) (child parent : String) : Option Edge :=
  V.edges.find? fun e => e.child == child && e.parent == parent

def ProtoSpec.field? (p : ProtoSpec) (name : String) : Option FieldSpec :=
  p.fields.find? (·.name == name)

end Kunai
