// Symbolic terms over entry symbols, their evaluation, and the normaliser.
// The normaliser is a set of smart constructors; each one comes with a
// lemma saying it does not change the value of the term (identity rules).
include "Bits.dfy"

module Terms {
  import opened Bits

  datatype Term =
    | Entry(k: nat)              // value of rk at region entry (r10 = frame pointer)
    | Fresh(n: nat)              // n-th value the region obtained from outside (havoc)
    | Const(c: bv64)
    | AddT(a: Term, b: Term)
    | AndT(a: Term, b: Term)
    | OrT(a: Term, b: Term)
    | LshT(a: Term, b: Term)     // a << (b & 63)
    | Zext32(a: Term)            // low 32 bits, zero-extended
    | Bytes(bs: seq<BTerm>)      // little-endian concatenation, zero-extended

  datatype BTerm =
    | BEntry(i: nat)             // stack byte i (index into [r10-512, r10)) at entry
    | BOf(t: Term, j: nat)       // byte j of t

  // An assignment of the symbols: entry registers, entry stack, fresh values.
  datatype Env = Env(regs: seq<bv64>, stack: seq<bv8>, log: seq<bv64>)

  // Opaque: the bit-vector solver handles one unfolding at a time far better;
  // the equations below (one per constructor) are what proofs use.
  opaque function Eval(t: Term, e: Env): bv64
    decreases t
  {
    match t
    case Entry(k) => if k < |e.regs| then e.regs[k] else 0
    case Fresh(n) => if n < |e.log| then e.log[n] else 0
    case Const(c) => c
    case AddT(a, b) => Eval(a, e) + Eval(b, e)
    case AndT(a, b) => Eval(a, e) & Eval(b, e)
    case OrT(a, b) => Eval(a, e) | Eval(b, e)
    case LshT(a, b) => Eval(a, e) << (Eval(b, e) & 63)
    case Zext32(a) => Low32(Eval(a, e))
    case Bytes(bs) => if |bs| <= 8 then LE(EvalBs(bs, e)) else 0
  }

  opaque function EvalB(b: BTerm, e: Env): bv8
    decreases b
  {
    match b
    case BEntry(i) => if i < |e.stack| then e.stack[i] else 0
    case BOf(t, j) => if j < 8 then ByteOf(Eval(t, e), j) else 0
  }

  function EvalBs(bs: seq<BTerm>, e: Env): seq<bv8>
    decreases bs
    ensures |EvalBs(bs, e)| == |bs|
    ensures forall i :: 0 <= i < |bs| ==> EvalBs(bs, e)[i] == EvalB(bs[i], e)
  {
    if |bs| == 0 then [] else [EvalB(bs[0], e)] + EvalBs(bs[1..], e)
  }

  lemma EvEntry(k: nat, e: Env) ensures Eval(Entry(k), e) == if k < |e.regs| then e.regs[k] else 0 { reveal Eval(); }
  lemma EvFresh(n: nat, e: Env) ensures Eval(Fresh(n), e) == if n < |e.log| then e.log[n] else 0 { reveal Eval(); }
  lemma EvConst(c: bv64, e: Env) ensures Eval(Const(c), e) == c { reveal Eval(); }
  lemma EvAdd(a: Term, b: Term, e: Env) ensures Eval(AddT(a, b), e) == Eval(a, e) + Eval(b, e) { reveal Eval(); }
  lemma EvAnd(a: Term, b: Term, e: Env) ensures Eval(AndT(a, b), e) == Eval(a, e) & Eval(b, e) { reveal Eval(); }
  lemma EvOr(a: Term, b: Term, e: Env) ensures Eval(OrT(a, b), e) == Eval(a, e) | Eval(b, e) { reveal Eval(); }
  lemma EvLsh(a: Term, b: Term, e: Env) ensures Eval(LshT(a, b), e) == Eval(a, e) << (Eval(b, e) & 63) { reveal Eval(); }
  lemma EvZext(a: Term, e: Env) ensures Eval(Zext32(a), e) == Low32(Eval(a, e)) { reveal Eval(); }
  lemma EvBytes(bs: seq<BTerm>, e: Env) requires |bs| <= 8 ensures Eval(Bytes(bs), e) == LE(EvalBs(bs, e)) { reveal Eval(); }
  lemma EvBEntry(i: nat, e: Env) ensures EvalB(BEntry(i), e) == if i < |e.stack| then e.stack[i] else 0 { reveal EvalB(); }
  lemma EvBOf(t: Term, j: nat, e: Env) requires j < 8 ensures EvalB(BOf(t, j), e) == ByteOf(Eval(t, e), j) { reveal EvalB(); }

  // ---------------- normaliser (identity-preserving rules only) ----------------

  // Rule 1: (x + c1) + c2  ->  x + (c1 + c2)
  function MkAdd(a: Term, b: Term): Term {
    if b.Const? && a.AddT? && a.b.Const? then AddT(a.a, Const(a.b.c + b.c)) else AddT(a, b)
  }

  lemma {:isolate_assertions} MkAddEval(a: Term, b: Term, e: Env)
    ensures Eval(MkAdd(a, b), e) == Eval(a, e) + Eval(b, e)
  {
    if b.Const? && a.AddT? && a.b.Const? {
      EvAdd(a.a, a.b, e); EvConst(a.b.c, e); EvConst(b.c, e);
      EvAdd(a.a, Const(a.b.c + b.c), e); EvConst(a.b.c + b.c, e);
      AddAssoc(Eval(a.a, e), a.b.c, b.c);
    } else {
      EvAdd(a, b, e);
    }
  }

  // Rule 2: zext32(zext32(x))  ->  zext32(x)
  function MkZext(a: Term): Term {
    if a.Zext32? then a else Zext32(a)
  }

  lemma MkZextEval(a: Term, e: Env)
    ensures Eval(MkZext(a), e) == Low32(Eval(a, e))
  {
    if a.Zext32? { EvZext(a.a, e); Low32Idem(Eval(a.a, e)); } else { EvZext(a, e); }
  }

  // Rule 3: the 8 bytes of t, in order  ->  t
  predicate AllBytesOf(bs: seq<BTerm>) {
    |bs| == 8 && bs[0].BOf? && forall j :: 0 <= j < 8 ==> bs[j] == BOf(bs[0].t, j)
  }

  function MkBytes(bs: seq<BTerm>): Term
    requires |bs| <= 8
  {
    if AllBytesOf(bs) then bs[0].t else Bytes(bs)
  }

  lemma MkBytesEval(bs: seq<BTerm>, e: Env)
    requires |bs| <= 8
    ensures Eval(MkBytes(bs), e) == LE(EvalBs(bs, e))
  {
    if AllBytesOf(bs) {
      var t := bs[0].t;
      var x := Eval(t, e);
      forall j | 0 <= j < 8 ensures EvalBs(bs, e)[j] == BytesOf(x, 8)[j] {
        EvBOf(t, j, e);
      }
      assert EvalBs(bs, e) == BytesOf(x, 8);
      LEBytesOf8(x);
    } else {
      EvBytes(bs, e);
    }
  }

  // Address recognition: r10 + c.  The only form accepted for stores.
  function FpOff(t: Term): Option<bv64> {
    if t == Entry(10) then Some(0)
    else if t.AddT? && t.a == Entry(10) && t.b.Const? then Some(t.b.c)
    else None
  }

  lemma FpOffEval(t: Term, e: Env)
    requires FpOff(t).Some? && |e.regs| == 11
    ensures Eval(t, e) == e.regs[10] + FpOff(t).value
  {
    EvEntry(10, e);
    if t != Entry(10) {
      EvAdd(Entry(10), t.b, e); EvConst(t.b.c, e);
    }
  }
}
