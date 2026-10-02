import Kunai.Eval
import Kunai.VocabData
import Kunai.Packets
import Kunai.Json

/-!
# Vector definitions

A vector pairs a filter, a host, and a packet with the verdict `eval` must
produce. The `vector` macro defines it and, right next to it, the `example`
proving `eval … = expected` by `decide`, so every exported vector is checked
against the semantics at build time.
-/
namespace Kunai

/-- What the Go implementation does with this vector (DECISIONS.md). -/
inductive GoStatus
  /-- `Compile` succeeds and `Runner.Match` agrees with `expected`. -/
  | ok
  /-- `Compile` returns `codegen.ErrNotImplemented`; the verdict is not checked. -/
  | notImplemented
  /-- `Compile` succeeds but the BPF program disagrees or fails to load; logged, not asserted. -/
  | mismatch
  deriving Repr, BEq, DecidableEq

def GoStatus.text : GoStatus → String
  | .ok => "ok" | .notImplemented => "notImplemented" | .mismatch => "mismatch"

structure Vector where
  id : String
  ast : Filter
  host : HostKind := .xdp_entry
  action : Nat := 0
  sets : List SetDecl := []
  packet : Packet := Pkt.ethIPv4TCP
  expected : Result
  goStatus : GoStatus := .ok
  note : String := ""

def Vector.check (v : Vector) : Bool :=
  eval (v.host.host v.action v.sets) vocab v.ast v.packet == v.expected

/-- `vector name := { … }` defines the vector and its `decide` proof. -/
macro "vector " n:ident " := " v:term : command =>
  `(def $n : Vector := $v
    example : Vector.check $n = true := by decide)

open Lean in
def Result.toJson : Result → Json
  | .accept cs => Json.mkObj [("kind", "accept"),
      ("captures", Json.arr (cs.map fun (s, e) => Json.arr #[s, e]).toArray)]
  | .reject => Json.mkObj [("kind", "reject")]
  | .illTyped r => Json.mkObj [("kind", "illTyped"), ("reason", r)]

open Lean in
def SetDecl.toJson (s : SetDecl) : Json :=
  Json.mkObj [("name", s.name), ("width", (s.width : Json)),
    ("members", Json.arr (s.members.toArray.map fun (m : Nat) => (m : Json)))]

open Lean in
def Vector.toJson (v : Vector) : Json :=
  Json.mkObj [("id", v.id), ("expr", v.ast.text), ("ast", v.ast.toJson),
    ("host", v.host.text), ("action", (v.action : Json)),
    ("sets", Json.arr (v.sets.map SetDecl.toJson).toArray),
    ("packet", hexOfBytes v.packet), ("expected", v.expected.toJson),
    ("goStatus", v.goStatus.text), ("note", v.note)]

-- Shorthands for writing filters.
def f (name : String) : FieldPath := FieldPath.ofParts [name]
def ff (a b : String) : FieldPath := FieldPath.ofParts [a, b]
def P (name : String) : Layer := .proto { name }
def Pq (name : String) (q : Quant) : Layer := .proto { name, quant := q }
def fld (a b : String) : Arith := .field (ff a b)
def k (n : Int) : Arith := .const n
def chain3 : List Layer := [P "eth", P "ipv4", P "tcp"]

end Kunai
