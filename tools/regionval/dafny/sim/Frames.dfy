// Frames: the invariant of reachable configurations of P (frame depths,
// r10, owners, waiting frames), and Corr split into the waiting frames
// (LowRel) and the top frame, so that a step that changes only the top
// frame keeps the rest folded.
include "Bridge.dfy"
include "LayoutFacts.dfy"

module SimFrames {
  import opened Bits
  import opened SimModel
  import opened SimRewrite
  import opened SimPremises
  import opened SimTheorem
  import opened SimBridge
  import S = Semantics
  import Obligations

  // ---------------- the frame invariant of P ----------------

  // Frame k of a reachable configuration of P.
  ghost predicate FrInv(P: seq<OInstr>, k: nat, f: Frame) {
    |f.regs| == NR && |f.stack| == STK && k < MAXF && f.regs[10] == W(StackTop(k))
    && f.fn in FnSet(P) && 0 <= f.pc < |P| && Owner(P, f.pc) == f.fn
  }

  // f waits for the frame above it, of kind up: at a call, or at the callback helper i.
  ghost predicate Waits(P: seq<OInstr>, f: Frame, up: Kind) {
    0 <= f.pc < |P| && ((up.Sub? && P[f.pc].Call?) || (up.Cb? && up.idx == f.pc && P[f.pc].CbCall?))
  }

  ghost predicate InvB(P: seq<OInstr>, fr: seq<Frame>) {
    0 < |fr| <= MAXF && fr[0].kind == Main
    && (forall k | 0 <= k < |fr| :: FrInv(P, k, fr[k]))
    && (forall k | 0 < k < |fr| :: (fr[k].kind.Sub? || fr[k].kind.Cb?) && Waits(P, fr[k - 1], fr[k].kind))
  }

  opaque ghost predicate Inv(P: seq<OInstr>, c: Cfg) { InvB(P, c.fr) }

  lemma InvIs(P: seq<OInstr>, c: Cfg)
    requires Inv(P, c)
    ensures 0 < |c.fr| <= MAXF && Top(c) == c.fr[|c.fr| - 1] && FrInv(P, |c.fr| - 1, Top(c))
    ensures (Top(c).kind.Main? <==> |c.fr| == 1)
    ensures !Top(c).kind.Ins?
    ensures |c.fr| > 1 ==> Waits(P, c.fr[|c.fr| - 2], Top(c).kind)
    ensures forall k | 0 <= k < |c.fr| :: FrInv(P, k, c.fr[k])
  { reveal Inv(); }

  lemma OwnerFn(P: seq<OInstr>, g: nat)
    requires g in FnSet(P)
    ensures Owner(P, g) == g
  {}

  // The floor of the top frame is the floor of the window at its pc.
  lemma FlTop(P: seq<OInstr>, ell: nat -> int, c: Cfg)
    requires Inv(P, c)
    ensures 0 <= Top(c).pc && Fl(P, ell, Top(c).pc) == Fl(P, ell, Top(c).fn) == Floor8(ell(Top(c).fn))
  {
    InvIs(P, c);
    OwnerFn(P, Top(c).fn);
  }

  // The top frame replaced by one of the same function, kind and r10.
  lemma InvPut(P: seq<OInstr>, c: Cfg, c1: Cfg)
    requires Inv(P, c) && |c1.fr| == |c.fr| > 0 && Below(c1) == Below(c)
    requires FrInv(P, |c.fr| - 1, Top(c1)) && Top(c1).kind == Top(c).kind
    ensures Inv(P, c1)
  {
    reveal Inv();
    var n := |c.fr|;
    assert Top(c1) == c1.fr[n - 1];
    forall k | 0 <= k < n ensures FrInv(P, k, c1.fr[k]) {
      if k < n - 1 { assert c1.fr[k] == Below(c1)[k] == Below(c)[k] == c.fr[k]; }
    }
    forall k | 0 < k < n ensures (c1.fr[k].kind.Sub? || c1.fr[k].kind.Cb?) && Waits(P, c1.fr[k - 1], c1.fr[k].kind) {
      assert c1.fr[k - 1] == c.fr[k - 1];
      if k < n - 1 { assert c1.fr[k] == c.fr[k]; } else { assert c1.fr[k].kind == c.fr[k].kind; }
    }
  }

  // Only stacks changed (a write set, a store).
  lemma InvStacks(P: seq<OInstr>, c: Cfg, c1: Cfg)
    requires Inv(P, c) && |c1.fr| == |c.fr|
    requires forall k | 0 <= k < |c.fr| :: c1.fr[k] == c.fr[k].(stack := c1.fr[k].stack) && |c1.fr[k].stack| == STK
    ensures Inv(P, c1)
  {
    reveal Inv();
    forall k | 0 <= k < |c.fr| ensures FrInv(P, k, c1.fr[k]) {}
    forall k | 0 < k < |c.fr| ensures (c1.fr[k].kind.Sub? || c1.fr[k].kind.Cb?) && Waits(P, c1.fr[k - 1], c1.fr[k].kind) {
      assert c1.fr[k - 1].pc == c.fr[k - 1].pc;
    }
  }

  lemma InvPush(P: seq<OInstr>, c: Cfg, c1: Cfg, f: Frame)
    requires Inv(P, c) && c1.fr == c.fr + [f] && |c.fr| < MAXF
    requires FrInv(P, |c.fr|, f) && (f.kind.Sub? || f.kind.Cb?) && Waits(P, Top(c), f.kind)
    ensures Inv(P, c1)
  {
    reveal Inv();
    var n := |c.fr|;
    assert Top(c) == c.fr[n - 1];
    forall k | 0 <= k < n + 1 ensures FrInv(P, k, c1.fr[k]) { if k < n { assert c1.fr[k] == c.fr[k]; } }
    forall k | 0 < k < n + 1 ensures (c1.fr[k].kind.Sub? || c1.fr[k].kind.Cb?) && Waits(P, c1.fr[k - 1], c1.fr[k].kind) {
      if k < n { assert c1.fr[k] == c.fr[k] && c1.fr[k - 1] == c.fr[k - 1]; }
      else { assert c1.fr[k] == f && c1.fr[k - 1] == c.fr[n - 1]; }
    }
  }

  lemma InvPop(P: seq<OInstr>, c: Cfg)
    requires Inv(P, c) && |c.fr| > 1
    ensures Inv(P, Pop(c)) && Below(c) == Pop(c).fr && Top(Pop(c)) == c.fr[|c.fr| - 2]
  {
    reveal Inv();
    var c1 := Pop(c);
    forall k | 0 <= k < |c1.fr| ensures FrInv(P, k, c1.fr[k]) { assert c1.fr[k] == c.fr[k]; }
    forall k | 0 < k < |c1.fr| ensures (c1.fr[k].kind.Sub? || c1.fr[k].kind.Cb?) && Waits(P, c1.fr[k - 1], c1.fr[k].kind) {
      assert c1.fr[k] == c.fr[k] && c1.fr[k - 1] == c.fr[k - 1];
    }
  }

  lemma InvFields(P: seq<OInstr>, c: Cfg, c1: Cfg)
    requires Inv(P, c) && c1.fr == c.fr
    ensures Inv(P, c1)
  { reveal Inv(); }

  lemma InvInit(P: seq<OInstr>, L: Local)
    requires 0 < |P|
    ensures Inv(P, InitP(L))
  {
    reveal Inv();
    var f := InitP(L).fr[0];
    assert 0 in FnSet(P);
    assert Owner(P, 0) == 0;
    assert FrInv(P, 0, f);
  }

  // ---------------- the relation, split ----------------

  ghost predicate RegRel(c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>) {
    forall r | 0 <= r < NR :: Rel(Reg(Top(c), r), Reg(Top(c'), r)) || (r in er && 1 <= r <= 5 && r !in lv)
  }
  ghost predicate StkRel(c: Cfg, c': Cfg, fl: int) {
    |Top(c).stack| == STK && |Top(c').stack| == STK
    && forall o | 0 <= o < STK && o - STK as int >= fl :: RelB(Top(c).stack[o], Top(c').stack[o])
  }

  // A waiting frame of P and of P'.
  ghost predicate WaitRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, f: Frame, f': Frame) {
    f'.kind == f.kind && |f.regs| == NR && |f.stack| == STK && FrameOk(f')
    && 0 <= f.pc < |P| && f'.pc == K(D, f.pc)
    && (forall r | 6 <= r < NR :: Rel(f.regs[r], f'.regs[r]))
    && (forall o | 0 <= o < STK && o - STK as int >= Fl(P, ell, f.fn) :: RelB(f.stack[o], f'.stack[o]))
  }

  ghost predicate LowRelB(P: seq<OInstr>, D: Decomp, ell: nat -> int, fr: seq<Frame>, fr': seq<Frame>) {
    |fr'| == |fr| && forall k | 0 <= k < |fr| :: WaitRel(P, D, ell, fr[k], fr'[k])
  }

  // The waiting frames correspond (R1-R4 below the top), and both runs have the same depth.
  opaque ghost predicate LowRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg) {
    |c'.fr| == |c.fr| > 0 && LowRelB(P, D, ell, Below(c), Below(c'))
  }

  lemma LowRelLen(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg)
    requires LowRel(P, D, ell, c, c')
    ensures |c'.fr| == |c.fr| > 0
  { reveal LowRel(); }

  // The same waiting frames (only the top frame, L, h changed).
  lemma LowRelSame(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, c1: Cfg, c1': Cfg)
    requires LowRel(P, D, ell, c, c')
    requires |c1.fr| == |c.fr| && |c1'.fr| == |c'.fr| && Below(c1) == Below(c) && Below(c1') == Below(c')
    ensures LowRel(P, D, ell, c1, c1')
  { reveal LowRel(); }

  // The top frame of P and of P' at e(pc).
  ghost predicate TopRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, c: Cfg, c': Cfg, er: set<nat>) {
    var f := Top(c); var f' := Top(c');
    f'.kind == f.kind && |f.regs| == NR && |f.stack| == STK && FrameOk(f')
    && 0 <= f.pc < |P| && f'.pc == E(D, f.pc)
    && RegRel(c, c', er, live(f.pc)) && StkRel(c, c', Fl(P, ell, f.fn))
    && c'.L == c.L && c'.h == c.h
  }

  lemma {:isolate_assertions} CorrIntro(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, c: Cfg, c': Cfg, er: set<nat>)
    requires LowRel(P, D, ell, c, c') && TopRel(P, D, ell, live, c, c', er)
    ensures Corr(P, D, ell, live, c, c', er)
  {
    reveal LowRel();
    var n := |c.fr|;
    assert Top(c) == c.fr[n - 1] && Top(c') == c'.fr[n - 1];
    forall k | 0 <= k < n - 1 ensures WaitRel(P, D, ell, c.fr[k], c'.fr[k]) {
      assert Below(c)[k] == c.fr[k] && Below(c')[k] == c'.fr[k];
    }
    forall k | 0 <= k < n
      ensures c'.fr[k].kind == c.fr[k].kind && |c.fr[k].regs| == NR && |c'.fr[k].regs| == NR
           && |c.fr[k].stack| == STK && |c'.fr[k].stack| == STK
    {}
    forall k, r | 0 <= k < n - 1 && 6 <= r < NR ensures Rel(Reg(c.fr[k], r), Reg(c'.fr[k], r)) {}
    forall k, o | 0 <= k < n && 0 <= o < STK && o - STK as int >= Fl(P, ell, c.fr[k].fn)
      ensures RelB(c.fr[k].stack[o], c'.fr[k].stack[o])
    {}
    forall k | 0 <= k < n
      ensures (forall r | 0 <= r < NR :: Reg(c'.fr[k], r).W?) && (forall o | 0 <= o < |c'.fr[k].stack| :: c'.fr[k].stack[o].B?)
    {
      assert FrameOk(c'.fr[k]);
    }
    assert NoBot(c');
  }

  lemma {:isolate_assertions} CorrElim(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, c: Cfg, c': Cfg, er: set<nat>)
    requires Corr(P, D, ell, live, c, c', er)
    ensures LowRel(P, D, ell, c, c') && TopRel(P, D, ell, live, c, c', er)
  {
    reveal LowRel();
    var n := |c.fr|;
    assert Top(c) == c.fr[n - 1] && Top(c') == c'.fr[n - 1];
    forall k | 0 <= k < n ensures FrameOk(c'.fr[k]) {
      forall r | 0 <= r < NR ensures c'.fr[k].regs[r].W? { assert Reg(c'.fr[k], r).W?; }
    }
    forall k | 0 <= k < n - 1 ensures WaitRel(P, D, ell, Below(c)[k], Below(c')[k]) {
      assert Below(c)[k] == c.fr[k] && Below(c')[k] == c'.fr[k];
      forall r | 6 <= r < NR ensures Rel(c.fr[k].regs[r], c'.fr[k].regs[r]) { assert Rel(Reg(c.fr[k], r), Reg(c'.fr[k], r)); }
    }
    assert LowRelB(P, D, ell, Below(c), Below(c'));
  }
  // ---------------- LowRel under frame operations ----------------

  lemma LowRelAt(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, d: nat)
    requires LowRel(P, D, ell, c, c') && d < |c.fr| - 1
    ensures |c'.fr| == |c.fr| && WaitRel(P, D, ell, c.fr[d], c'.fr[d])
  {
    reveal LowRel();
    assert Below(c)[d] == c.fr[d] && Below(c')[d] == c'.fr[d];
  }

  // The old top frame starts waiting under a new frame.
  lemma LowRelPush(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, c1: Cfg, c1': Cfg, f: Frame, f': Frame)
    requires LowRel(P, D, ell, c, c') && WaitRel(P, D, ell, Top(c), Top(c'))
    requires c1.fr == c.fr + [f] && c1'.fr == c'.fr + [f']
    ensures LowRel(P, D, ell, c1, c1')
  {
    reveal LowRel();
    var n := |c.fr|;
    assert Below(c1) == c.fr && Below(c1') == c'.fr;
    forall k | 0 <= k < n ensures WaitRel(P, D, ell, c.fr[k], c'.fr[k]) {
      if k < n - 1 { assert Below(c)[k] == c.fr[k] && Below(c')[k] == c'.fr[k]; }
      else { assert Top(c) == c.fr[k] && Top(c') == c'.fr[k]; }
    }
  }

  // The top frame returns; the frame below it is on top.
  lemma LowRelPop(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg)
    requires LowRel(P, D, ell, c, c') && |c.fr| > 1
    ensures LowRel(P, D, ell, Pop(c), Pop(c')) && WaitRel(P, D, ell, Top(Pop(c)), Top(Pop(c')))
    ensures |Pop(c).fr| == |c.fr| - 1 && |Pop(c').fr| == |c'.fr| - 1
  {
    reveal LowRel();
    var n := |c.fr|;
    assert Top(Pop(c)) == Below(c)[n - 2] && Top(Pop(c')) == Below(c')[n - 2];
    forall k | 0 <= k < n - 2 ensures WaitRel(P, D, ell, Below(Pop(c))[k], Below(Pop(c'))[k]) {
      assert Below(Pop(c))[k] == Below(c)[k] && Below(Pop(c'))[k] == Below(c')[k];
    }
  }

  lemma WaitRelApply(P: seq<OInstr>, D: Decomp, ell: nat -> int, f: Frame, f': Frame, d: nat, wr: map<int, bv8>)
    requires WaitRel(P, D, ell, f, f')
    ensures WaitRel(P, D, ell, ApplyF(f, d, wr), ApplyF(f', d, wr))
  {}

  // A write set applied in both runs.
  lemma LowRelApply(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, wr: map<int, bv8>)
    requires LowRel(P, D, ell, c, c')
    ensures LowRel(P, D, ell, ApplyW(c, wr), ApplyW(c', wr))
  {
    reveal LowRel();
    ApplyWAt(c, wr);
    ApplyWAt(c', wr);
    var a := ApplyW(c, wr);
    var a' := ApplyW(c', wr);
    var n := |c.fr|;
    forall k | 0 <= k < n - 1 ensures WaitRel(P, D, ell, Below(a)[k], Below(a')[k]) {
      assert Below(a)[k] == ApplyF(c.fr[k], k, wr) && Below(a')[k] == ApplyF(c'.fr[k], k, wr);
      assert Below(c)[k] == c.fr[k] && Below(c')[k] == c'.fr[k];
      WaitRelApply(P, D, ell, c.fr[k], c'.fr[k], k, wr);
    }
  }

  lemma InvApply(P: seq<OInstr>, c: Cfg, wr: map<int, bv8>)
    requires Inv(P, c)
    ensures Inv(P, ApplyW(c, wr))
  {
    ApplyWAt(c, wr);
    InvIs(P, c);
    InvStacks(P, c, ApplyW(c, wr));
  }

  // The same defined bytes written to a waiting frame d in both runs.
  lemma LowRelWrite(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, d: nat, o: nat, bs: seq<Byte>)
    requires LowRel(P, D, ell, c, c') && d < |c.fr| && o + |bs| <= STK && forall i | 0 <= i < |bs| :: bs[i].B?
    requires |c'.fr| == |c.fr| && |c.fr[d].stack| == STK && |c'.fr[d].stack| == STK
    ensures LowRel(P, D, ell, WriteStack(c, d, o, bs), WriteStack(c', d, o, bs))
    ensures |WriteStack(c, d, o, bs).fr| == |c.fr| && |WriteStack(c', d, o, bs).fr| == |c'.fr|
  {
    reveal LowRel();
    var a := WriteStack(c, d, o, bs);
    var a' := WriteStack(c', d, o, bs);
    var n := |c.fr|;
    if d == n - 1 {
      assert Below(a) == Below(c) && Below(a') == Below(c');
    } else {
      forall k | 0 <= k < n - 1 ensures WaitRel(P, D, ell, Below(a)[k], Below(a')[k]) {
        assert Below(c)[k] == c.fr[k] && Below(c')[k] == c'.fr[k];
        if k != d {
          assert Below(a)[k] == c.fr[k] && Below(a')[k] == c'.fr[k];
        } else {
          var st := c.fr[d].stack;
          var st' := c'.fr[d].stack;
          assert Below(a)[k] == c.fr[d].(stack := st[..o] + bs + st[o + |bs|..]);
          assert Below(a')[k] == c'.fr[d].(stack := st'[..o] + bs + st'[o + |bs|..]);
          forall i | 0 <= i < STK ensures (st[..o] + bs + st[o + |bs|..])[i] == (if o <= i < o + |bs| then bs[i - o] else st[i])
            && (st'[..o] + bs + st'[o + |bs|..])[i] == (if o <= i < o + |bs| then bs[i - o] else st'[i]) {}
        }
      }
    }
  }

  lemma InvWrite(P: seq<OInstr>, c: Cfg, d: nat, o: nat, bs: seq<Byte>)
    requires Inv(P, c) && o + |bs| <= STK
    ensures Inv(P, WriteStack(c, d, o, bs))
  {
    InvIs(P, c);
    var a := WriteStack(c, d, o, bs);
    if d < |c.fr| { assert |a.fr[d].stack| == STK; }
    InvStacks(P, c, a);
  }

  // A stack byte of P at or above its frame's floor is P''s byte.
  lemma LowByte(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, d: nat, o: nat)
    requires LowRel(P, D, ell, c, c') && d < |c.fr| - 1 && o < STK && o as int - STK as int >= Fl(P, ell, c.fr[d].fn)
    ensures |c'.fr| == |c.fr| && |c.fr[d].stack| == STK && |c'.fr[d].stack| == STK
    ensures RelB(c.fr[d].stack[o], c'.fr[d].stack[o]) && c'.fr[d].stack[o].B?
  {
    LowRelAt(P, D, ell, c, c', d);
  }

  // The floor of frame d is at most l_F of its function.
  lemma FlFrame(P: seq<OInstr>, ell: nat -> int, c: Cfg, d: nat)
    requires Inv(P, c) && FloorsOk(P, ell) && d < |c.fr|
    ensures -(STK as int) <= Fl(P, ell, c.fr[d].fn) <= ell(c.fr[d].fn) <= 0
  {
    InvIs(P, c);
    OwnerFn(P, c.fr[d].fn);
    var l := ell(c.fr[d].fn);
    assert l / 8 >= -64;
  }

  // ---------------- footprints in any frame ----------------

  lemma FrameOfIn(p: bv64, w: nat, d: nat)
    requires FrameOf(p, w, d).Some?
    ensures FrameOf(p, w, d).value < MAXF_RW && S.InFrame(S.Rel(p, StackTop(FrameOf(p, w, d).value)), w)
    decreases d
  {
    if d - 1 < MAXF_RW && S.InFrame(S.Rel(p, StackTop(d - 1)), w) {
      assert FrameOf(p, w, d) == Some(d - 1);
    } else {
      assert FrameOf(p, w, d) == FrameOf(p, w, d - 1);
      FrameOfIn(p, w, d - 1);
    }
  }

  lemma ClassifyStack(p: bv64, w: nat, nfr: nat, dom: set<int>)
    requires Classify(p, w, nfr, dom).InStack?
    ensures Classify(p, w, nfr, dom).d < nfr && Classify(p, w, nfr, dom).o + w <= STK
  {
    reveal Classify();
    assert FrameOf(p, w, nfr).Some?;
    FrameOfIn(p, w, nfr);
  }

  // A footprint address in the stack lies at or above l_F of its frame.
  ghost predicate FootInF(ell: nat -> int, c: Cfg, a: bv64) {
    match Classify(a, 1, |c.fr|, c.L.mem.Keys)
    case InStack(d, o) => d < |c.fr| && o as int - STK as int >= ell(c.fr[d].fn)
    case _ => true
  }

  // The relation FootBytes needs: waiting frames, the top frame's bytes, L.
  opaque ghost predicate MemRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg) {
    Inv(P, c) && LowRel(P, D, ell, c, c') && StkRel(c, c', Fl(P, ell, Top(c).fn)) && c'.L == c.L && FloorsOk(P, ell)
  }

  lemma MemRelI(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg)
    requires Inv(P, c) && LowRel(P, D, ell, c, c') && StkRel(c, c', Fl(P, ell, Top(c).fn)) && c'.L == c.L && FloorsOk(P, ell)
    ensures MemRel(P, D, ell, c, c')
  { reveal MemRel(); }

  lemma MemRelE(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg)
    requires MemRel(P, D, ell, c, c')
    ensures Inv(P, c) && LowRel(P, D, ell, c, c') && StkRel(c, c', Fl(P, ell, Top(c).fn)) && c'.L == c.L && FloorsOk(P, ell)
  { reveal MemRel(); }

  // A stack byte P reads (defined, at or above l_F) is the same in P'.
  lemma {:isolate_assertions} ByteEq(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, d: nat, o: nat)
    requires MemRel(P, D, ell, c, c') && d < |c.fr| && o < STK && o as int - STK as int >= ell(c.fr[d].fn)
    ensures |c'.fr| == |c.fr| && |c.fr[d].stack| == STK && |c'.fr[d].stack| == STK
    ensures RelB(c.fr[d].stack[o], c'.fr[d].stack[o])
  {
    MemRelE(P, D, ell, c, c');
    LowRelLen(P, D, ell, c, c');
    FlFrame(P, ell, c, d);
    InvIs(P, c);
    if d == |c.fr| - 1 {
      FlTop(P, ell, c);
      assert Top(c) == c.fr[d] && Top(c') == c'.fr[d];
    } else {
      LowByte(P, D, ell, c, c', d, o);
    }
  }

  lemma {:isolate_assertions} FootRelG(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, addrs: seq<bv64>)
    requires MemRel(P, D, ell, c, c')
    requires forall i | 0 <= i < |addrs| :: FootInF(ell, c, addrs[i])
    requires FootBytes(c, addrs).FOk?
    ensures FootBytes(c', addrs) == FootBytes(c, addrs)
    decreases |addrs|
  {
    reveal FootBytes();
    MemRelE(P, D, ell, c, c');
    LowRelLen(P, D, ell, c, c');
    if |addrs| > 0 {
      assert forall i | 0 <= i < |addrs[1..]| :: FootInF(ell, c, addrs[1..][i]) by {
        forall i | 0 <= i < |addrs[1..]| ensures FootInF(ell, c, addrs[1..][i]) { assert addrs[1..][i] == addrs[i + 1]; }
      }
      var cl := Classify(addrs[0], 1, |c.fr|, c.L.mem.Keys);
      assert Classify(addrs[0], 1, |c'.fr|, c'.L.mem.Keys) == cl;
      assert FootBytes(c, addrs[1..]).FOk?;
      FootRelG(P, D, ell, c, c', addrs[1..]);
      match cl
      case InStack(d, o) =>
        ClassifyStack(addrs[0], 1, |c.fr|, c.L.mem.Keys);
        assert FootInF(ell, c, addrs[0]);
        ByteEq(P, D, ell, c, c', d, o);
        assert StackBytes(c, d, o, 1) == [c.fr[d].stack[o]];
        assert StackBytes(c', d, o, 1) == [c'.fr[d].stack[o]];
      case _ =>
    }
  }

  // ---------------- windows ----------------

  // The region state of a window entered at c' (its top frame).
  lemma BRInit(c': Cfg, base: int)
    requires 0 < |c'.fr| <= MAXF_RW && FrameOk(Top(c')) && Top(c').pc == base
    requires Top(c').regs[10] == W(StackTop(|c'.fr| - 1))
    ensures BR(c', S.InitState(R64(Top(c')), Plain(Top(c').stack)), base)
  {}

  // The parts of FinalOk the step proofs use.
  lemma FinalFacts(sp: Obligations.Spec, s0: S.CState, s: S.CState)
    requires S.CWF(s0) && Obligations.FinalOk(sp, s0, s)
    ensures S.CWF(s)
    ensures forall k | 6 <= k <= 10 :: s.regs[k] == s0.regs[k]
    ensures forall k | 0 <= k <= 5 && k !in sp.free && !(k == 0 && Obligations.R0Special(sp)) :: s.regs[k] == s0.regs[k]
    ensures sp.helper.Helper? && sp.helper.restoreR0 ==> s.regs[0] == Obligations.HelperRet(s.events)
    ensures Obligations.CountHelpers(s.events) == (if sp.helper.Helper? then 1 else 0)
    ensures |Obligations.UpperBase(s.events, s0.stack)| == S.STACK
    ensures forall i | 0 <= i < S.STACK && S.STACK as int + sp.floor <= i :: s.stack[i] == Obligations.UpperBase(s.events, s0.stack)[i]
  {}

  lemma ApplyTop(c: Cfg, wr: map<int, bv8>)
    requires |c.fr| > 0
    ensures |ApplyW(c, wr).fr| == |c.fr| && Top(ApplyW(c, wr)) == ApplyF(Top(c), |c.fr| - 1, wr)
    ensures ApplyW(c, wr).L == ApplyL(c.L, wr) && ApplyW(c, wr).h == c.h
  { ApplyWAt(c, wr); }

  lemma PutSame(c: Cfg)
    requires |c.fr| > 0
    ensures Put(c, Top(c)) == c
  { assert c.fr[|c.fr| - 1 := c.fr[|c.fr| - 1]] == c.fr; }

  // The same defined bytes spliced into two related stacks.
  lemma SpliceRel(st: seq<Byte>, st': seq<Byte>, o: nat, bs: seq<Byte>, fl: int)
    requires |st| == STK && |st'| == STK && o + |bs| <= STK && forall i | 0 <= i < |bs| :: bs[i].B?
    requires forall i | 0 <= i < STK && i - STK as int >= fl :: RelB(st[i], st'[i])
    requires forall i | 0 <= i < STK :: st'[i].B?
    ensures var a := st[..o] + bs + st[o + |bs|..]; var a' := st'[..o] + bs + st'[o + |bs|..];
      |a| == STK && |a'| == STK && (forall i | 0 <= i < STK && i - STK as int >= fl :: RelB(a[i], a'[i]))
      && (forall i | 0 <= i < STK :: a'[i].B?)
  {
    var a := st[..o] + bs + st[o + |bs|..];
    var a' := st'[..o] + bs + st'[o + |bs|..];
    forall i | 0 <= i < STK ensures a[i] == (if o <= i < o + |bs| then bs[i - o] else st[i])
      && a'[i] == (if o <= i < o + |bs| then bs[i - o] else st'[i]) {}
  }
}
