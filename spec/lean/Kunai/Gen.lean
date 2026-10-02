import Kunai.Vectors

/-!
# Generated vectors

Deterministic mutations of every golden vector's packet (truncations and
single-byte flips at header boundaries). Their verdicts are computed by
`eval` at generation time rather than proved, so they inherit the golden
vector's `goStatus` and exist to widen the surface the Go implementation
is compared on. Exported to `spec_vectors_gen.json`.
-/
namespace Kunai

/-- Byte positions worth disturbing: eth type, ipv4 version/ihl, ipv4
protocol, start of the transport header, and the middle of the packet. -/
private def flipPositions (n : Nat) : List Nat :=
  ([12, 13, 14, 23, 34, n / 2].filter (· < n)).eraseDups

private def truncLengths (n : Nat) : List Nat :=
  ([14, 34, 54, n - 1].filter (· < n)).eraseDups

/-- `(tag, packet)` for each mutation of `P`. -/
def mutations (P : Packet) : List (String × Packet) :=
  let n := P.length
  (truncLengths n).map (fun k => (s!"trunc{k}", P.take k))
    ++ (flipPositions n).map fun i => (s!"flip{i}", P.set i ((P.getD i 0) ^^^ 0xff))

/-- Mutations known to hit a documented Go divergence (DECISIONS.md); the
generated vector inherits its base vector's `goStatus` otherwise. -/
def goOverrides : List (String × GoStatus × String) := [
  ("chain-ipv4-ihl6/flip34", .mismatch, "D-029: an unknown ipv4 option kind is only rejected when an option is queried"),
  ("quant-exact-one-machine/flip34", .mismatch, "D-029: an unknown ipv4 option kind is only rejected when an option is queried")]

def Vector.mutate (v : Vector) : List Vector :=
  match v.expected with
  | .illTyped _ => []
  | _ => (mutations v.packet).map fun (tag, P) =>
    let id := v.id ++ "/" ++ tag
    let (goStatus, note) := match goOverrides.find? (·.1 == id) with
      | some (_, g, n) => (g, n)
      | none => (v.goStatus, "generated from " ++ v.id)
    { v with id, packet := P, expected := eval (v.host.host v.action v.sets) vocab v.ast P, goStatus, note }

def generatedVectors : List Vector := vectors.flatMap Vector.mutate

end Kunai
