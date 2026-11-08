// Bit-level helpers shared by the concrete semantics and the checker.
// Part of the trusted specification: these define how wire fields and
// stack bytes are read (RFC 9669 section 3: little-endian encoding).
module Bits {
  datatype Option<T> = None | Some(value: T)

  const TWO64: int := 0x1_0000_0000_0000_0000

  // Two's-complement reading of a 64-bit value.
  // Opaque: proofs only need that equal arguments give equal results.
  opaque function Signed64(x: bv64): int {
    if x < 0x8000_0000_0000_0000 then x as int else x as int - TWO64
  }

  function Signed32(x: bv32): int {
    if x < 0x8000_0000 then x as int else x as int - 0x1_0000_0000
  }

  function Signed16(x: bv16): int {
    if x < 0x8000 then x as int else x as int - 0x1_0000
  }

  function Sext32(x: bv32): bv64 {
    if x & 0x8000_0000 == 0 then x as bv64 else (x as bv64) | 0xffff_ffff_0000_0000
  }

  function Sext16(x: bv16): bv64 {
    if x & 0x8000 == 0 then x as bv64 else (x as bv64) | 0xffff_ffff_ffff_0000
  }

  function Low32(x: bv64): bv64 { x & 0xffff_ffff }

  function Zext8(b: bv8): bv64 { b as bv64 }

  function ByteOf(x: bv64, i: nat): bv8
    requires i < 8
  {
    // case split keeps shift amounts literal (no int/bv conversion)
    var y := if i == 0 then x else if i == 1 then x >> 8 else if i == 2 then x >> 16
             else if i == 3 then x >> 24 else if i == 4 then x >> 32 else if i == 5 then x >> 40
             else if i == 6 then x >> 48 else x >> 56;
    (y & 0xff) as bv8
  }

  // Little-endian value of up to 8 bytes, zero-extended to 64 bits.
  function LE(bs: seq<bv8>): bv64
    requires |bs| <= 8
  {
    if |bs| == 0 then 0 else (bs[0] as bv64) | (LE(bs[1..]) << 8)
  }

  function BytesOf(x: bv64, w: nat): seq<bv8>
    requires w <= 8
  {
    seq(w, i requires 0 <= i < w => ByteOf(x, i))
  }

  // ---- lemmas used by the normaliser and the simulation proof ----

  lemma LEStep(bs: seq<bv8>)
    requires 0 < |bs| <= 8
    ensures LE(bs) == (bs[0] as bv64) | (LE(bs[1..]) << 8)
  {}

  // Reassembling the eight bytes of x gives x back.  Unrolled with literal
  // shift amounts so that the bit-vector solver sees constant shifts only.
  lemma {:isolate_assertions} LEBytesOf8(x: bv64)
    ensures LE(BytesOf(x, 8)) == x
  {
    var bs := BytesOf(x, 8);
    assert bs[7] == ((x >> 56) & 0xff) as bv8;
    assert bs[6] == ((x >> 48) & 0xff) as bv8;
    assert bs[5] == ((x >> 40) & 0xff) as bv8;
    assert bs[4] == ((x >> 32) & 0xff) as bv8;
    assert bs[3] == ((x >> 24) & 0xff) as bv8;
    assert bs[2] == ((x >> 16) & 0xff) as bv8;
    assert bs[1] == ((x >> 8) & 0xff) as bv8;
    assert bs[0] == ((x >> 0) & 0xff) as bv8;
    assert bs[8..] == [];
    LEStep(bs[7..]); assert bs[7..][1..] == bs[8..];
    assert LE(bs[7..]) == x >> 56;
    LEStep(bs[6..]); assert bs[6..][1..] == bs[7..];
    assert LE(bs[6..]) == (((x >> 48) & 0xff) | ((x >> 56) << 8));
    assert (((x >> 48) & 0xff) | ((x >> 56) << 8)) == x >> 48;
    LEStep(bs[5..]); assert bs[5..][1..] == bs[6..];
    assert LE(bs[5..]) == (((x >> 40) & 0xff) | ((x >> 48) << 8));
    assert (((x >> 40) & 0xff) | ((x >> 48) << 8)) == x >> 40;
    LEStep(bs[4..]); assert bs[4..][1..] == bs[5..];
    assert LE(bs[4..]) == (((x >> 32) & 0xff) | ((x >> 40) << 8));
    assert (((x >> 32) & 0xff) | ((x >> 40) << 8)) == x >> 32;
    LEStep(bs[3..]); assert bs[3..][1..] == bs[4..];
    assert LE(bs[3..]) == (((x >> 24) & 0xff) | ((x >> 32) << 8));
    assert (((x >> 24) & 0xff) | ((x >> 32) << 8)) == x >> 24;
    LEStep(bs[2..]); assert bs[2..][1..] == bs[3..];
    assert LE(bs[2..]) == (((x >> 16) & 0xff) | ((x >> 24) << 8));
    assert (((x >> 16) & 0xff) | ((x >> 24) << 8)) == x >> 16;
    LEStep(bs[1..]); assert bs[1..][1..] == bs[2..];
    assert LE(bs[1..]) == (((x >> 8) & 0xff) | ((x >> 16) << 8));
    assert (((x >> 8) & 0xff) | ((x >> 16) << 8)) == x >> 8;
    LEStep(bs[0..]); assert bs[0..][1..] == bs[1..];
    assert LE(bs[0..]) == (((x >> 0) & 0xff) | ((x >> 8) << 8));
    assert (((x >> 0) & 0xff) | ((x >> 8) << 8)) == x >> 0;
    assert bs[0..] == bs;
  }

  lemma ByteOfZext(b: bv8)
    ensures ByteOf(b as bv64, 0) == b
  {}

  lemma Low32Idem(x: bv64)
    ensures Low32(Low32(x)) == Low32(x)
  {}

  lemma AddAssoc(x: bv64, c1: bv64, c2: bv64)
    ensures (x + c1) + c2 == x + (c1 + c2)
  {}

  lemma SubOfAdd(fp: bv64, c: bv64)
    ensures (fp + c) - fp == c
  {}
}
