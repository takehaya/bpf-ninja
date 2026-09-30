/-!
Phase 0 smoke test: confirms that `decide` reduces a small computation over
`List UInt8` in the kernel. Replaced by real modules in Phase 1+.
-/
namespace Kunai

/-- Sum of a byte list as `Nat`. -/
def byteSum : List UInt8 → Nat
  | [] => 0
  | b :: bs => b.toNat + byteSum bs

example : byteSum [0x08, 0x00, 0xff] = 263 := by decide

end Kunai
