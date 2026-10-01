/-!
# Packets

`Packet := List UInt8` rather than `ByteArray` so that `decide` can evaluate
the semantics in the kernel. Reads are network byte order (big endian) and
return `none` when any needed byte lies past the end of the packet.
-/
namespace Kunai

abbrev Packet := List UInt8

/-- Unsigned big-endian value of `P[start .. start+len)`, `none` if out of range. -/
def readBytes (P : Packet) (start len : Nat) : Option Nat :=
  if start + len ≤ P.length then
    some ((List.range len).foldl (fun acc i => acc * 256 + (P.getD (start + i) 0).toNat) 0)
  else none

/-- `width` bits starting at absolute bit position `bitPos` (bit 0 = MSB of
byte 0), as an unsigned integer. -/
def readBits (P : Packet) (bitPos width : Nat) : Option Nat :=
  let firstByte := bitPos / 8
  let lastByte := (bitPos + width - 1) / 8
  let nbytes := lastByte + 1 - firstByte
  match readBytes P firstByte nbytes with
  | none => none
  | some v =>
    let trailing := nbytes * 8 - (bitPos % 8 + width)
    some ((v / 2 ^ trailing) % 2 ^ width)

end Kunai
