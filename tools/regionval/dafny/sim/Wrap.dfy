// P8: the wrapper site WP . call W_i.  W_i runs in its own frame (an Ins
// frame above the caller); the region model sees W's registers with the
// caller's r10 and the caller's stack (EnterW/ReturnW of Semantics.dfy).
// This file connects that run (RunWrap) to the whole model and proves the
// step of P at a wrapped helper.
include "Calls.dfy"

module SimWrap {
  import opened Bits
  import S = Semantics
  import opened Obligations
  import opened SimModel
  import opened SimRewrite
  import opened SimPremises
  import opened SimTheorem
  import opened SimBridge
  import opened SimLayoutFacts
  import opened SimFrames
  import opened SimSites
  import opened SimRegion
  import SimFacts
  import SimCalls
  import SimClasses
  import Soundness
  import Checker
  import Api

  // ================= frame addresses =================

  // StackTop(d) as a literal (int-to-bv conversions of terms do not verify).
  function TB(d: nat): bv64 requires d < MAXF_RW {
    if d == 0 then 0x4000_0000_0000_0000 else if d == 1 then 0x3FFF_FFFF_FFFF_F000
    else if d == 2 then 0x3FFF_FFFF_FFFF_E000 else if d == 3 then 0x3FFF_FFFF_FFFF_D000
    else if d == 4 then 0x3FFF_FFFF_FFFF_C000 else if d == 5 then 0x3FFF_FFFF_FFFF_B000
    else if d == 6 then 0x3FFF_FFFF_FFFF_A000 else if d == 7 then 0x3FFF_FFFF_FFFF_9000
    else if d == 8 then 0x3FFF_FFFF_FFFF_8000 else 0x3FFF_FFFF_FFFF_7000
  }

  lemma RT(n: int) requires 0 <= n < TWO64 ensures (n as bv64) as int == n {}

  lemma TopLit(d: nat) requires d < MAXF_RW ensures StackTop(d) == TB(d)
  {
    RT(TOP0 - d * STRIDE);
    if d == 0 { assert StackTop(0) as int == 0x4000_0000_0000_0000; }
    else if d == 1 { assert StackTop(1) as int == 0x3FFF_FFFF_FFFF_F000; }
    else if d == 2 { assert StackTop(2) as int == 0x3FFF_FFFF_FFFF_E000; }
    else if d == 3 { assert StackTop(3) as int == 0x3FFF_FFFF_FFFF_D000; }
    else if d == 4 { assert StackTop(4) as int == 0x3FFF_FFFF_FFFF_C000; }
    else if d == 5 { assert StackTop(5) as int == 0x3FFF_FFFF_FFFF_B000; }
    else if d == 6 { assert StackTop(6) as int == 0x3FFF_FFFF_FFFF_A000; }
    else if d == 7 { assert StackTop(7) as int == 0x3FFF_FFFF_FFFF_9000; }
    else if d == 8 { assert StackTop(8) as int == 0x3FFF_FFFF_FFFF_8000; }
    else { assert StackTop(9) as int == 0x3FFF_FFFF_FFFF_7000; }
  }

  // An access in frame d lies in the 512 bytes below StackTop(d).
  lemma FrameRange(a: bv64, d: nat, w: nat)
    requires d < MAXF_RW && 1 <= w && S.InFrame(S.Rel(a, StackTop(d)), w)
    ensures TB(d) - 512 <= a < TB(d)
  {
    TopLit(d);
    reveal Signed64();
    var x := a - TB(d);
    assert x >= 0xFFFF_FFFF_FFFF_FE00;
  }

  lemma FramesDisj(a: bv64, d1: nat, d2: nat, w: nat)
    requires d1 < MAXF_RW && d2 < MAXF_RW && d1 != d2 && 1 <= w
    requires S.InFrame(S.Rel(a, StackTop(d1)), w)
    ensures !S.InFrame(S.Rel(a, StackTop(d2)), w)
  {
    FrameRange(a, d1, w);
    if S.InFrame(S.Rel(a, StackTop(d2)), w) { FrameRange(a, d2, w); }
  }

  lemma AreaInt(a: bv64)
    requires 0x3FFF_FFFF_FFFF_6000 <= a < 0x4000_0000_0000_0000
    ensures 0x3FFF_FFFF_FFFF_6000 <= a as int < 0x4000_0000_0000_0000
  {}

  lemma AIZero(a: bv64) ensures AI(a, 0) == a as int { assert 0 <= a as int < TWO64; }

  lemma AreaAt(a: bv64)
    requires 0x3FFF_FFFF_FFFF_6000 <= a as int < 0x4000_0000_0000_0000
    ensures TouchesStackArea(a, 1)
  {
    AIZero(a);
    assert InStackArea(AI(a, 0));
  }

  lemma FrameInArea(a: bv64, d: nat)
    requires d < MAXF_RW && S.InFrame(S.Rel(a, StackTop(d)), 1)
    ensures TouchesStackArea(a, 1)
  {
    FrameRange(a, d, 1);
    assert 0x3FFF_FFFF_FFFF_6000 <= a < 0x4000_0000_0000_0000 by { TopLit(d); }
    AreaInt(a);
    AreaAt(a);
  }

  // One more frame on top changes no classification of an access below it.
  lemma FrameOfPush(a: bv64, w: nat, n: nat)
    requires n < MAXF_RW && 1 <= w && !S.InFrame(S.Rel(a, StackTop(n)), w)
    ensures FrameOf(a, w, n + 1) == FrameOf(a, w, n)
  {}

  lemma {:isolate_assertions} ClassifyUp(a: bv64, w: nat, n: nat, dom: set<int>)
    requires 0 < n && n + 1 <= MAXF_RW && 1 <= w && S.InFrame(S.Rel(a, StackTop(n - 1)), w)
    ensures Classify(a, w, n + 1, dom) == InStack(n - 1, S.Rel(a, StackTop(n - 1)) + STK)
  {
    FramesDisj(a, n - 1, n, w);
    FrameOfPush(a, w, n);
    FrameOfTop(a, w, n);
    ClassifyFrame(a, w, n + 1, dom, n - 1);
  }

  lemma {:isolate_assertions} ClassifyPush(a: bv64, n: nat, dom: set<int>)
    requires n + 1 <= MAXF_RW && Classify(a, 1, n, dom) != Bad
    ensures Classify(a, 1, n + 1, dom) == Classify(a, 1, n, dom)
  {
    if S.InFrame(S.Rel(a, StackTop(n)), 1) {
      match FrameOf(a, 1, n)
      case Some(d) =>
        FrameOfIn(a, 1, n);
        FramesDisj(a, d, n, 1);
      case None =>
        FrameInArea(a, n);
        assert Classify(a, 1, n, dom) == Bad by { reveal Classify(); }
    }
    FrameOfPush(a, 1, n);
    reveal Classify();
  }

  // The footprint bytes are the same with one more frame on top (P' inside W).
  lemma {:isolate_assertions} FootPush(c: Cfg, cW: Cfg, addrs: seq<bv64>)
    requires |cW.fr| == |c.fr| + 1 <= MAXF_RW && cW.L == c.L
    requires forall k | 0 <= k < |c.fr| :: cW.fr[k].stack == c.fr[k].stack
    requires FootBytes(c, addrs).FOk?
    ensures FootBytes(cW, addrs) == FootBytes(c, addrs)
    decreases |addrs|
  {
    reveal FootBytes();
    if |addrs| > 0 {
      var cl := Classify(addrs[0], 1, |c.fr|, c.L.mem.Keys);
      assert cl != Bad;
      ClassifyPush(addrs[0], |c.fr|, c.L.mem.Keys);
      assert FootBytes(c, addrs[1..]).FOk?;
      FootPush(c, cW, addrs[1..]);
      match cl
      case InStack(d, o) =>
        ClassifyStack(addrs[0], 1, |c.fr|, c.L.mem.Keys);
        assert StackBytes(cW, d, o, 1) == StackBytes(c, d, o, 1);
      case _ =>
    }
  }

  // ================= layout of a wrapper site =================

  lemma {:isolate_assertions} WrapCode(P: seq<OInstr>, D: Decomp, i: nat)
    requires i < |P| && AllFnsWF(P, D) && i in D.wrap && i !in D.pl
    ensures K(D, i) == E(D, i) + NI(D.wrap[i].wp) && PostLen(D, i) == 0 && K(D, i) < |Layout(P, D).code|
    ensures forall r | 0 <= r < NI(D.wrap[i].wp) :: SimCalls.PlacedAt(Layout(P, D), E(D, i), D.wrap[i].wp, r)
    ensures Layout(P, D).code[K(D, i)] == N(EncCallLocal(WStart(P, D, i) - K(D, i) - 1))
  {
    BlockParts(P, D, i);
    var fl := FnsLen(D, FnsAt(D, i));
    var fp := FPLen(D, i);
    assert PLLen(D, i) == 0;
    assert E(D, i) == Start(D, i) + fl + fp;
    forall r | 0 <= r < NI(D.wrap[i].wp) ensures SimCalls.PlacedAt(Layout(P, D), E(D, i), D.wrap[i].wp, r) {
      CodeAt(P, D, i, fl + fp + r);
    }
    CodeAt(P, D, i, fl + fp + NI(D.wrap[i].wp));
  }

  lemma WStartInIs(fs: seq<(InsFn, nat)>, s: nat, k: nat)
    requires k < |fs| && fs[k].0 == WrapFn(s)
    ensures exists k' :: 0 <= k' < |fs| && fs[k'] == (WrapFn(s), WStartIn(fs, s))
    decreases |fs|
  {
    if fs[0].0 == WrapFn(s) {
      assert fs[0] == (WrapFn(s), WStartIn(fs, s));
    } else {
      WStartInIs(fs[1..], s, k - 1);
      var k' :| 0 <= k' < |fs[1..]| && fs[1..][k'] == (WrapFn(s), WStartIn(fs[1..], s));
      assert fs[k' + 1] == fs[1..][k'];
    }
  }

  // W_i is placed once; WStart is its entry.
  lemma {:isolate_assertions} WEntry(P: seq<OInstr>, D: Decomp, i: nat) returns (k: nat)
    requires PiecesOk(P, D) && i in D.wrap
    ensures k < |AllFns(P, D)| && AllFns(P, D)[k] == (WrapFn(i), WStart(P, D, i))
  {
    var ks := set k | 0 <= k < |AllFns(P, D)| && AllFns(P, D)[k].0 == WrapFn(i);
    assert |ks| == 1;
    var k0 :| k0 in ks;
    WStartInIs(AllFns(P, D), i, k0);
    k :| 0 <= k < |AllFns(P, D)| && AllFns(P, D)[k] == (WrapFn(i), WStartIn(AllFns(P, D), i));
  }

  ghost predicate WAt(P: seq<OInstr>, D: Decomp, i: nat, r: nat)
    requires i in D.wrap && i < |P| && r < NI(D.wrap[i].body)
  {
    var b := D.wrap[i].body;
    WStart(P, D, i) + r < |Layout(P, D).code| && 8 * r + 8 <= |b|
    && Layout(P, D).code[WStart(P, D, i) + r] ==
         (if S.Decode(Slice(b, r)).Some? && S.Decode(Slice(b, r)).value.CallHelper? then O(P[i], i) else N(Slice(b, r)))
  }

  lemma {:isolate_assertions} WPlaced(P: seq<OInstr>, D: Decomp, i: nat) returns (k: nat)
    requires PiecesOk(P, D) && i in D.wrap
    ensures i < |P| && k < |AllFns(P, D)| && AllFns(P, D)[k] == (WrapFn(i), WStart(P, D, i))
    ensures WStart(P, D, i) + NI(D.wrap[i].body) <= |Layout(P, D).code|
    ensures forall r | 0 <= r < NI(D.wrap[i].body) :: WAt(P, D, i, r)
  {
    AllFnsWFOk(P, D);
    k := WEntry(P, D, i);
    AllFnsPlaced(P, D, k);
    var b := D.wrap[i].body;
    assert FnLen(D, WrapFn(i)) == NI(b);
    forall r | 0 <= r < NI(b) ensures WAt(P, D, i, r) {
      assert Layout(P, D).code[WStart(P, D, i) + r] == FnCode(P, D, WrapFn(i))[r];
    }
  }

  // ---- inserted functions are not at a kappa ----

  lemma KInBlock(D: Decomp, i: nat)
    ensures Start(D, i) + FnsLen(D, FnsAt(D, i)) <= K(D, i) < Start(D, i + 1)
  {}

  lemma KBefore(D: Decomp, i: nat, j: nat)
    requires i < j
    ensures K(D, i) < Start(D, j)
  {
    KInBlock(D, i);
    StartMono(D, i + 1, j);
  }

  lemma FnStartsRange(D: Decomp, gs: seq<InsFn>, base: nat, q: nat, r: nat)
    requires q < |gs| && r < FnLen(D, gs[q])
    ensures |FnStarts(D, gs, base)| == |gs|
    ensures base <= FnStarts(D, gs, base)[q].1 + r < base + FnsLen(D, gs)
  {
    FnStartsAt(D, gs, base, q);
    FnsLenSnoc(D, gs, q);
  }

  lemma {:isolate_assertions} AllFnsFromNotK(D: Decomp, n: nat, i0: nat, k: nat, r: nat, i: nat)
    requires i0 <= n && k < |AllFnsFrom(D, n, i0)| && r < FnLen(D, AllFnsFrom(D, n, i0)[k].0) && i < n
    ensures AllFnsFrom(D, n, i0)[k].1 + r != K(D, i)
    decreases n - i0
  {
    if i0 >= n {
      assert AllFnsFrom(D, n, i0) == FnStarts(D, D.tail, Start(D, n));
      FnStartsLen(D, D.tail, Start(D, n));
      FnStartsAt(D, D.tail, Start(D, n), k);
      FnStartsRange(D, D.tail, Start(D, n), k, r);
      KBefore(D, i, n);
    } else {
      var a := FnStarts(D, FnsAt(D, i0), Start(D, i0));
      FnStartsLen(D, FnsAt(D, i0), Start(D, i0));
      var b := AllFnsFrom(D, n, i0 + 1);
      assert AllFnsFrom(D, n, i0) == a + b;
      if k < |a| {
        assert (a + b)[k] == a[k];
        FnStartsAt(D, FnsAt(D, i0), Start(D, i0), k);
        FnStartsRange(D, FnsAt(D, i0), Start(D, i0), k, r);
        if i < i0 { KBefore(D, i, i0); }
        else if i == i0 { KInBlock(D, i0); }
        else { StartMono(D, i0 + 1, i); KInBlock(D, i); }
      } else {
        assert (a + b)[k] == b[k - |a|];
        AllFnsFromNotK(D, n, i0 + 1, k - |a|, r, i);
      }
    }
  }

  lemma WNotK(P: seq<OInstr>, D: Decomp, i: nat, k: nat, r: nat)
    requires PiecesOk(P, D) && i in D.wrap && k < |AllFns(P, D)| && AllFns(P, D)[k] == (WrapFn(i), WStart(P, D, i))
    requires r < NI(D.wrap[i].body)
    ensures !(exists i' :: i' in D.wrap && WStart(P, D, i) + r == K(D, i'))
  {
    forall i' | i' in D.wrap ensures WStart(P, D, i) + r != K(D, i') {
      assert FnLen(D, WrapFn(i)) == NI(D.wrap[i].body);
      AllFnsFromNotK(D, |P|, 0, k, r, i');
    }
  }

  // ---- the encoding of call W ----

  function Imm4(b: seq<bv8>): bv32 requires |b| == 4 {
    (b[0] as bv32) | ((b[1] as bv32) << 8) | ((b[2] as bv32) << 16) | ((b[3] as bv32) << 24)
  }
  lemma ImmLow(u: bv64) ensures Imm4([ByteOf(u, 0), ByteOf(u, 1), ByteOf(u, 2), ByteOf(u, 3)]) == (u & 0xffff_ffff) as bv32 {}
  lemma Narrow(u: bv64) requires u < 0x1_0000_0000 ensures ((u & 0xffff_ffff) as bv32) as int == u as int {}

  lemma B4Signed(v: int)
    requires -0x8000_0000 <= v < 0x8000_0000
    ensures Signed32(Imm4(B4(v))) == v
  {
    var m := v % 0x1_0000_0000;
    var u := m as bv64;
    RT(m);
    assert u < 0x1_0000_0000;
    ImmLow(u);
    Narrow(u);
  }

  lemma DecodeCL(q: seq<bv8>)
    requires |q| == 4
    ensures S.Decode([0x85, 0x10, 0, 0] + q) == Some(S.CallLocal(Imm4(q)))
  {
    var b := [0x85, 0x10, 0, 0] + q;
    assert b == [0x85, 0x10, 0, 0, q[0], q[1], q[2], q[3]];
  }

  lemma DecodeCallW(v: int)
    requires -0x8000_0000 <= v < 0x8000_0000
    ensures |EncCallLocal(v)| == 8 && S.Decode(EncCallLocal(v)).Some? && S.Decode(EncCallLocal(v)).value.CallLocal?
    ensures Signed32(S.Decode(EncCallLocal(v)).value.imm) == v
  {
    var q := B4(v);
    assert EncCallLocal(v) == [0x85, 0x10, 0, 0] + q;
    DecodeCL(q);
    B4Signed(v);
  }

  // ================= the wrapper window =================

  // raw = WP . call W at base; wraw = W's bytes at wbase; F: the fuel of
  // RunWrap (W's body gets the same fuel as the window).
  datatype WW = WW(Pp: RwProg, x: Ctx, obsv: Observer, raw: seq<bv8>, wraw: seq<bv8>, sp: Spec,
                   base: int, wbase: int, hins: OInstr, hidx: nat, hc: HCtx, c0: Cfg, s0: S.CState, F: nat)

  // The caller's stack after the helper.
  ghost function StAfter(ww: WW): seq<Byte> requires |ww.c0.fr| > 0 {
    ApplyF(Top(ww.c0), |ww.c0.fr| - 1, ww.hc.wr).stack
  }

  ghost predicate WWBasic(ww: WW) {
    ww.x.m.MR? && ww.sp.wrap.Wrap? && ww.sp.wrap.body == ww.wraw
    && ww.sp.helper == Helper(false, true) && !ww.sp.allowStore && ww.sp.hookCalls
    && -(S.STACK as int) <= ww.sp.floor <= 0 && S.NumInsns(ww.raw) >= 1 && |ww.raw| % 8 == 0 && S.CWF(ww.s0)
  }

  // The helper the window's W issues (the original lookup), from the window's entry.
  ghost predicate HelperOkW(ww: WW) {
    var args := SimFacts.Words(Top(ww.c0), Upto(1, ww.hc.n));
    ww.hins.Hcall? && !ww.hins.kf && IsLookup(ww.hins.id)
    && ww.hc.n == ww.x.env.arity(false, ww.hins.id) && ww.hc.n <= 3
    && ww.hc.addrs == ww.x.env.foot(false, ww.hins.id, args)
    && FootBytes(ww.c0, ww.hc.addrs).FOk?
    && ww.hc.eh == ECall(ww.hidx, false, ww.hins.id, args, FootBytes(ww.c0, ww.hc.addrs).bs)
    && ww.x.om(ww.c0.h, ww.hc.eh, Wh(ww.c0)) == RRet(ww.hc.v, ww.hc.wr)
    && WrTop(ww.c0, ww.hc.wr, ww.sp.floor)
  }

  ghost predicate WCodeAt(ww: WW, r: nat) requires r < S.NumInsns(ww.wraw) {
    0 <= ww.wbase && ww.wbase + r < |ww.Pp.code|
    && ww.Pp.code[ww.wbase + r] == (if IsHelperCall(S.InsnAt(ww.wraw, r)) then O(ww.hins, ww.hidx) else N(S.InsnAt(ww.wraw, r)))
    && (S.Decode(S.InsnAt(ww.wraw, r)).Some? && S.Decode(S.InsnAt(ww.wraw, r)).value.CallLocal? ==>
          ww.wbase + r + 1 + Signed32(S.Decode(S.InsnAt(ww.wraw, r)).value.imm) in ww.Pp.hooks)
  }

  ghost predicate CallWAt(ww: WW) requires S.NumInsns(ww.raw) >= 1 {
    var n := S.NumInsns(ww.raw);
    S.Decode(S.InsnAt(ww.raw, n - 1)).Some? && S.Decode(S.InsnAt(ww.raw, n - 1)).value.CallLocal?
    && ww.base + n + Signed32(S.Decode(S.InsnAt(ww.raw, n - 1)).value.imm) == ww.wbase
  }

  opaque ghost predicate WWPreO(ww: WW) {
    var n := S.NumInsns(ww.raw);
    WWBasic(ww) && A5(ww.obsv) && A8(ww.x.om) && SpecWF(ww.sp) && WrapStatic(ww.raw, ww.sp)
    && 0 <= ww.base && ww.base + n <= |ww.Pp.code|
    && (forall r | 0 <= r < n :: ww.Pp.code[ww.base + r] == N(S.InsnAt(ww.raw, r)))
    && CallWAt(ww) && 0 <= ww.wbase
    && (forall r | 0 <= r < S.NumInsns(ww.wraw) :: WCodeAt(ww, r))
    && HooksOk(ww.Pp) && HelperOkW(ww)
    && 0 < |ww.c0.fr| <= MAXF && BR(ww.c0, ww.s0, ww.base) && ww.s0 == S.InitState(ww.s0.regs, ww.s0.stack)
  }

  ghost predicate WWPre(ww: WW) { WWBasic(ww) && WWPreO(ww) }

  lemma WWStat(ww: WW) requires WWPre(ww) ensures WrapStatic(ww.raw, ww.sp) { reveal WWPreO(); }
  lemma WWA5(ww: WW) requires WWPre(ww) ensures A5(ww.obsv) { reveal WWPreO(); }
  lemma WWA8(ww: WW) requires WWPre(ww) ensures A8(ww.x.om) { reveal WWPreO(); }
  lemma WWSpec(ww: WW) requires WWPre(ww) ensures SpecWF(ww.sp) { reveal WWPreO(); }
  lemma WWAtP(ww: WW, r: nat)
    requires WWPre(ww) && r < S.NumInsns(ww.raw)
    ensures 0 <= ww.base && ww.base + r < |ww.Pp.code| && ww.Pp.code[ww.base + r] == N(S.InsnAt(ww.raw, r))
  { reveal WWPreO(); }
  lemma WWCall(ww: WW) requires WWPre(ww) ensures CallWAt(ww) { reveal WWPreO(); }
  lemma WWAtW(ww: WW, r: nat) requires WWPre(ww) && r < S.NumInsns(ww.wraw) ensures WCodeAt(ww, r) { reveal WWPreO(); }
  lemma WWHooks(ww: WW) requires WWPre(ww) ensures HooksOk(ww.Pp) { reveal WWPreO(); }
  lemma WWHelper(ww: WW) requires WWPre(ww) ensures HelperOkW(ww) { reveal WWPreO(); }
  lemma WWInit(ww: WW)
    requires WWPre(ww)
    ensures 0 < |ww.c0.fr| <= MAXF && BR(ww.c0, ww.s0, ww.base) && ww.s0 == S.InitState(ww.s0.regs, ww.s0.stack)
  { reveal WWPreO(); }

  // ---------------- what the window may change ----------------

  // Before call W: the top frame is the region state; nothing else changed.
  opaque ghost predicate SideP(ww: WW, c: Cfg, s: S.CState) {
    |c.fr| == |ww.c0.fr| && Below(c) == Below(ww.c0) && c.L == ww.c0.L && c.h == ww.c0.h
    && Top(c).stack == Top(ww.c0).stack && Top(c).kind == Top(ww.c0).kind && Top(c).fn == Top(ww.c0).fn
    && CountHelpers(s.events) == 0
  }
  lemma SidePE(ww: WW, c: Cfg, s: S.CState)
    requires SideP(ww, c, s)
    ensures |c.fr| == |ww.c0.fr| && Below(c) == Below(ww.c0) && c.L == ww.c0.L && c.h == ww.c0.h
    ensures Top(c).stack == Top(ww.c0).stack && Top(c).kind == Top(ww.c0).kind && Top(c).fn == Top(ww.c0).fn
    ensures CountHelpers(s.events) == 0
  { reveal SideP(); }
  lemma SidePI(ww: WW, c: Cfg, s: S.CState)
    requires |c.fr| == |ww.c0.fr| && Below(c) == Below(ww.c0) && c.L == ww.c0.L && c.h == ww.c0.h
    requires Top(c).stack == Top(ww.c0).stack && Top(c).kind == Top(ww.c0).kind && Top(c).fn == Top(ww.c0).fn
    requires CountHelpers(s.events) == 0
    ensures SideP(ww, c, s)
  { reveal SideP(); }

  ghost predicate PreP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>) {
    WWPre(ww) && BR(c, s, ww.base) && s.oc == |prefix| && SideP(ww, c, s)
  }

  // Inside W: W's frame is on top; the region sees W's registers with the
  // caller's r10, and the caller's stack.
  ghost predicate BRW(c: Cfg, s: S.CState, wbase: int) {
    1 < |c.fr| <= MAXF_RW && S.CWF(s) && |Top(c).regs| == NR && |Top(c).stack| == STK && BRWO(c, s, wbase)
  }

  opaque ghost predicate BRWO(c: Cfg, s: S.CState, wbase: int) {
    var n := |c.fr|;
    1 < n <= MAXF_RW && S.CWF(s) && FrameOk(Top(c)) && FrameOk(c.fr[n - 2]) && Top(c).kind == Ins
    && Top(c).pc == wbase + s.pc
    && (forall k | 0 <= k < 10 :: R64(Top(c))[k] == s.regs[k])
    && s.regs[10] == StackTop(n - 2) && Plain(c.fr[n - 2].stack) == s.stack
  }

  // s1: the region state at call W.
  ghost predicate CallSt(ww: WW, s1: S.CState) {
    S.CWF(s1) && s1.pc == S.NumInsns(ww.raw) - 1 && S.CWF(ww.s0) && s1.regs[10] == ww.s0.regs[10]
  }

  opaque ghost predicate SideW(ww: WW, s1: S.CState, c: Cfg, s: S.CState) {
    var d := |ww.c0.fr|;
    0 < d && |c.fr| == d + 1 && |Top(ww.c0).stack| == STK
    && var cf := c.fr[d - 1];
    cf.pc == ww.base + s1.pc && |cf.regs| == NR && R64(cf) == s1.regs && cf.kind == Top(ww.c0).kind && cf.fn == Top(ww.c0).fn
    && CountHelpers(s.events) <= 1
    && (CountHelpers(s.events) == 0 ==>
          c.fr[..d - 1] == Below(ww.c0) && cf.stack == Top(ww.c0).stack && c.L == ww.c0.L && c.h == ww.c0.h)
    && (CountHelpers(s.events) == 1 ==>
          c.fr[..d - 1] == Below(ApplyW(ww.c0, ww.hc.wr)) && cf.stack == StAfter(ww)
          && c.L == ApplyL(ww.c0.L, ww.hc.wr) && c.h == ww.c0.h + [ww.hc.eh]
          && (ww.hc.v.W? ==> HelperRet(s.events) == ww.hc.v.w)
          && UpperBase(s.events, ww.s0.stack) == Plain(StAfter(ww)))
  }

  lemma SideWE(ww: WW, s1: S.CState, c: Cfg, s: S.CState)
    requires SideW(ww, s1, c, s)
    ensures var d := |ww.c0.fr|; (0 < d && |c.fr| == d + 1 && |Top(ww.c0).stack| == STK
          && c.fr[d - 1].pc == ww.base + s1.pc && |c.fr[d - 1].regs| == NR && R64(c.fr[d - 1]) == s1.regs
          && c.fr[d - 1].kind == Top(ww.c0).kind && c.fr[d - 1].fn == Top(ww.c0).fn && CountHelpers(s.events) <= 1)
  { reveal SideW(); }

  lemma SideW0(ww: WW, s1: S.CState, c: Cfg, s: S.CState)
    requires SideW(ww, s1, c, s) && CountHelpers(s.events) == 0
    ensures var d := |ww.c0.fr|; (0 < d && |c.fr| == d + 1
          && c.fr[..d - 1] == Below(ww.c0) && c.fr[d - 1].stack == Top(ww.c0).stack && c.L == ww.c0.L && c.h == ww.c0.h)
  { reveal SideW(); }

  lemma SideW1(ww: WW, s1: S.CState, c: Cfg, s: S.CState)
    requires SideW(ww, s1, c, s) && CountHelpers(s.events) == 1
    ensures var d := |ww.c0.fr|; (0 < d && |c.fr| == d + 1
          && c.fr[..d - 1] == Below(ApplyW(ww.c0, ww.hc.wr)) && c.fr[d - 1].stack == StAfter(ww)
          && c.L == ApplyL(ww.c0.L, ww.hc.wr) && c.h == ww.c0.h + [ww.hc.eh]
          && (ww.hc.v.W? ==> HelperRet(s.events) == ww.hc.v.w)
          && UpperBase(s.events, ww.s0.stack) == Plain(StAfter(ww)))
  { reveal SideW(); }

  // A step that changes only W's frame (registers, pc), with no helper event.
  lemma SideWKeep(ww: WW, s1: S.CState, c: Cfg, s: S.CState, c': Cfg, s': S.CState)
    requires SideW(ww, s1, c, s) && TopOnly(c, c')
    requires CountHelpers(s'.events) == CountHelpers(s.events) && HelperRet(s'.events) == HelperRet(s.events)
    requires UpperBase(s'.events, ww.s0.stack) == UpperBase(s.events, ww.s0.stack)
    ensures SideW(ww, s1, c', s')
  {
    reveal SideW();
    var d := |ww.c0.fr|;
    assert c'.fr[..d] == Below(c') == Below(c) == c.fr[..d];
    assert c'.fr[..d - 1] == c'.fr[..d][..d - 1];
    assert c.fr[..d - 1] == c.fr[..d][..d - 1];
    assert c'.fr[d - 1] == c'.fr[..d][d - 1];
    assert c.fr[d - 1] == c.fr[..d][d - 1];
  }

  lemma SideWEvent(ww: WW, s1: S.CState, c: Cfg, s: S.CState, c': Cfg, s': S.CState, e: S.Event)
    requires SideW(ww, s1, c, s) && TopOnly(c, c') && s'.events == s.events + [e] && !e.EHelper?
    ensures SideW(ww, s1, c', s')
  {
    Soundness.EventsSnoc(s.events, e, ww.s0.stack);
    SideWKeep(ww, s1, c, s, c', s');
  }

  ghost predicate PreW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>) {
    WWPre(ww) && CallSt(ww, s1) && BRW(c, s, ww.wbase) && s.oc == |prefix| && SideW(ww, s1, c, s)
  }

  // ---------------- the end of the window ----------------

  opaque ghost predicate EndOk(ww: WW, c2: Cfg, sf: S.CState) {
    BR(c2, sf, ww.base) && sf.pc == S.NumInsns(ww.raw)
    && |c2.fr| == |ww.c0.fr| && |ww.c0.fr| > 0 && Below(c2) == Below(ApplyW(ww.c0, ww.hc.wr))
    && c2.L == ApplyL(ww.c0.L, ww.hc.wr) && c2.h == ww.c0.h + [ww.hc.eh]
    && Top(c2).kind == Top(ww.c0).kind && Top(c2).fn == Top(ww.c0).fn && Top(c2).stack == StAfter(ww)
    && (ww.hc.v.W? ==> HelperRet(sf.events) == ww.hc.v.w)
    && UpperBase(sf.events, ww.s0.stack) == Plain(StAfter(ww))
  }

  lemma EndOkE(ww: WW, c2: Cfg, sf: S.CState)
    requires EndOk(ww, c2, sf)
    ensures BR(c2, sf, ww.base) && sf.pc == S.NumInsns(ww.raw)
    ensures |c2.fr| == |ww.c0.fr| && |ww.c0.fr| > 0 && Below(c2) == Below(ApplyW(ww.c0, ww.hc.wr))
    ensures c2.L == ApplyL(ww.c0.L, ww.hc.wr) && c2.h == ww.c0.h + [ww.hc.eh]
    ensures Top(c2).kind == Top(ww.c0).kind && Top(c2).fn == Top(ww.c0).fn && Top(c2).stack == StAfter(ww)
    ensures ww.hc.v.W? ==> HelperRet(sf.events) == ww.hc.v.w
    ensures UpperBase(sf.events, ww.s0.stack) == Plain(StAfter(ww))
  { reveal EndOk(); }

  opaque ghost predicate EndsW(ww: WW, c: Cfg, sf: S.CState) {
    exists k: nat, c2: Cfg :: ReachR(ww.Pp, ww.x, ww.obsv, c, k) == Some(c2) && EndOk(ww, c2, sf)
  }

  lemma EndsWHere(ww: WW, c: Cfg, sf: S.CState)
    requires EndOk(ww, c, sf)
    ensures EndsW(ww, c, sf)
  {
    reveal EndsW();
    assert ReachR(ww.Pp, ww.x, ww.obsv, c, 0) == Some(c);
  }

  lemma EndsWPrefix(ww: WW, c: Cfg, k: nat, c': Cfg, sf: S.CState)
    requires ReachR(ww.Pp, ww.x, ww.obsv, c, k) == Some(c') && EndsW(ww, c', sf)
    ensures EndsW(ww, c, sf)
  {
    reveal EndsW();
    var k2: nat, c2: Cfg :| ReachR(ww.Pp, ww.x, ww.obsv, c', k2) == Some(c2) && EndOk(ww, c2, sf);
    ReachAdd(ww.Pp, ww.x, ww.obsv, c, k, k2, c');
  }

  lemma EndsWGet(ww: WW, c: Cfg, sf: S.CState) returns (k: nat, c2: Cfg)
    requires EndsW(ww, c, sf)
    ensures ReachR(ww.Pp, ww.x, ww.obsv, c, k) == Some(c2) && EndOk(ww, c2, sf)
  {
    reveal EndsW();
    k, c2 :| ReachR(ww.Pp, ww.x, ww.obsv, c, k) == Some(c2) && EndOk(ww, c2, sf);
  }

  // ---------------- the rest of the window run ----------------

  ghost function OutP(ww: WW, s: S.CState, o: seq<bv64>, fuel: nat): S.Outcome
    requires WWBasic(ww) && S.CWF(s)
  {
    S.WPPost(ww.raw, ww.wraw, ww.sp.floor, o, ww.F, S.Run(S.WPart(ww.raw), ww.sp.floor, s, o, fuel))
  }

  ghost function OutW(ww: WW, s1: S.CState, s: S.CState, o: seq<bv64>, fuel: nat): S.Outcome
    requires WWBasic(ww) && S.CWF(s)
  {
    S.WPost(s1, o, S.Run(ww.wraw, ww.sp.floor, s, o, fuel))
  }

  ghost predicate PostP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, rest: seq<bv64>)
    requires WWBasic(ww) && S.CWF(s)
  {
    var O := OutP(ww, s, prefix + rest, fuel);
    (O.Done? && FinalOkO(ww.sp, ww.s0, O.s)) ==> EndsW(ww, c, O.s)
  }

  ghost predicate PostW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, rest: seq<bv64>)
    requires WWBasic(ww) && S.CWF(s)
  {
    var O := OutW(ww, s1, s, prefix + rest, fuel);
    (O.Done? && FinalOkO(ww.sp, ww.s0, O.s)) ==> EndsW(ww, c, O.s)
  }

  // A run of the window without a helper call does not meet the obligations.
  lemma NoHelperNotFinal(ww: WW, s: S.CState)
    requires WWBasic(ww) && CountHelpers(s.events) == 0
    ensures !FinalOkO(ww.sp, ww.s0, s)
  { reveal FinalOkO(); }

  lemma RunAdv(code: seq<bv8>, floor: int, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr, vals: seq<bv64>,
               s': S.CState, rest': seq<bv64>)
    requires -(S.STACK as int) <= floor <= 0 && S.CWF(s) && S.CWF(s') && 0 <= s.pc < S.NumInsns(code) && fuel > 0
    requires S.Decode(S.InsnAt(code, s.pc)) == Some(ins)
    requires s.oc + Need(floor, ins, s) <= |prefix + vals|
    requires S.Step(floor, ins, s, prefix + vals) == S.Next(s')
    ensures prefix + (vals + rest') == (prefix + vals) + rest'
    ensures S.Run(code, floor, s, prefix + (vals + rest'), fuel) == S.Run(code, floor, s', (prefix + vals) + rest', fuel - 1)
  {
    var rest := vals + rest';
    assert prefix + rest == (prefix + vals) + rest';
    assert SameUpTo(prefix + rest, prefix + vals, s.oc + Need(floor, ins, s));
    StepOracleLocal(floor, ins, s, prefix + rest, prefix + vals);
    Soundness.RunNext(code, floor, s, prefix + rest, fuel, ins, s');
  }

  // Events of the rest of the window run only grow.
  lemma {:isolate_assertions} OutEventsW(ww: WW, s1: S.CState, s: S.CState, o: seq<bv64>, fuel: nat)
    requires WWBasic(ww) && S.CWF(s)
    ensures OutW(ww, s1, s, o, fuel).Done? ==> s.events <= OutW(ww, s1, s, o, fuel).s.events
  {
    var R := S.Run(ww.wraw, ww.sp.floor, s, o, fuel);
    RunEventsGrow(ww.wraw, ww.sp.floor, s, o, fuel);
    if OutW(ww, s1, s, o, fuel).Done? {
      assert R.Exited? && S.CWF(s1) && S.CWF(R.s);
      assert OutW(ww, s1, s, o, fuel).s.events == R.s.events + [S.ERet(R.s.regs[0])];
    }
  }

  lemma {:isolate_assertions} OutEventsP(ww: WW, s: S.CState, o: seq<bv64>, fuel: nat)
    requires WWBasic(ww) && S.CWF(s)
    ensures OutP(ww, s, o, fuel).Done? ==> s.events <= OutP(ww, s, o, fuel).s.events
  {
    var fl := ww.sp.floor;
    var R := S.Run(S.WPart(ww.raw), fl, s, o, fuel);
    RunEventsGrow(S.WPart(ww.raw), fl, s, o, fuel);
    var O := OutP(ww, s, o, fuel);
    if O.Done? && R.Done? {
      var s1 := R.s;
      assert O == S.CallW(ww.raw, ww.wraw, fl, s1, o, ww.F);
      assert S.CWF(s1) && s1.pc == S.NumInsns(ww.raw) - 1;
      var e := S.EnterW(s1, o);
      assert e.events == s1.events + [S.ECallW(s1.regs)];
      var R2 := S.Run(ww.wraw, fl, e, o, ww.F);
      RunEventsGrow(ww.wraw, fl, e, o, ww.F);
      assert O == S.WPost(s1, o, R2);
      assert R2.Exited? && S.CWF(R2.s);
      assert O.s.events == R2.s.events + [S.ERet(R2.s.regs[0])];
    }
  }

  // ---------------- glue, phase W ----------------

  lemma StuckPostW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    requires WWPre(ww) && S.CWF(s) && 0 <= s.pc < S.NumInsns(ww.wraw) && fuel > 0
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(ins) && S.Step(ww.sp.floor, ins, s, prefix) == S.Stuck
    ensures PostW(ww, s1, c, s, prefix, fuel, [])
  {
    assert prefix + [] == prefix;
    Soundness.RunAt(ww.wraw, ww.sp.floor, s, prefix, fuel, ins);
  }

  lemma {:isolate_assertions} BadPostW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr, s': S.CState)
    requires WWPre(ww) && S.CWF(s) && 0 <= s.pc < S.NumInsns(ww.wraw) && fuel > 0
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(ins) && S.Step(ww.sp.floor, ins, s, prefix) == S.Next(s') && S.CWF(s')
    requires (|s'.events| > |s.events| && !EventOk(ww.sp, ww.s0, s'.events[|s.events|])) || CountHelpers(s'.events) > 1
    ensures PostW(ww, s1, c, s, prefix, fuel, [])
  {
    reveal FinalOkO();
    assert prefix + [] == prefix;
    Soundness.RunNext(ww.wraw, ww.sp.floor, s, prefix, fuel, ins, s');
    var f1: nat := fuel - 1;
    OutEventsW(ww, s1, s', prefix, f1);
    var O := OutW(ww, s1, s, prefix, fuel);
    assert O == OutW(ww, s1, s', prefix, f1);
    if O.Done? {
      SimFacts.CountHelpersMono(s'.events, O.s.events);
      if |s'.events| > |s.events| && !EventOk(ww.sp, ww.s0, s'.events[|s.events|]) {
        assert O.s.events[|s.events|] == s'.events[|s.events|];
      }
    }
  }

  lemma AdvWPost(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr, vals: seq<bv64>,
                 k: nat, c': Cfg, s': S.CState, rest': seq<bv64>)
    requires WWPre(ww) && S.CWF(s) && S.CWF(s') && fuel > 0 && 0 <= s.pc < S.NumInsns(ww.wraw)
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(ins)
    requires s.oc + Need(ww.sp.floor, ins, s) <= |prefix + vals|
    requires S.Step(ww.sp.floor, ins, s, prefix + vals) == S.Next(s')
    requires ReachR(ww.Pp, ww.x, ww.obsv, c, k) == Some(c')
    requires PostW(ww, s1, c', s', prefix + vals, fuel - 1, rest')
    ensures PostW(ww, s1, c, s, prefix, fuel, vals + rest')
  {
    RunAdv(ww.wraw, ww.sp.floor, s, prefix, fuel, ins, vals, s', rest');
    var O := OutW(ww, s1, s, prefix + (vals + rest'), fuel);
    assert O == OutW(ww, s1, s', (prefix + vals) + rest', fuel - 1);
    if O.Done? && FinalOkO(ww.sp, ww.s0, O.s) { EndsWPrefix(ww, c, k, c', O.s); }
  }

  lemma AdvW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr,
             vals: seq<bv64>, k: nat, c': Cfg, s': S.CState) returns (rest: seq<bv64>)
    requires PreW(ww, s1, c, s, prefix) && 0 <= s.pc < S.NumInsns(ww.wraw) && fuel > 0
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(ins)
    requires s.oc + Need(ww.sp.floor, ins, s) <= |prefix + vals|
    requires S.Step(ww.sp.floor, ins, s, prefix + vals) == S.Next(s')
    requires ReachR(ww.Pp, ww.x, ww.obsv, c, k) == Some(c') && PreW(ww, s1, c', s', prefix + vals)
    ensures PostW(ww, s1, c, s, prefix, fuel, rest)
    decreases fuel, 0
  {
    var rest' := BridgeW(ww, s1, c', s', prefix + vals, fuel - 1);
    rest := vals + rest';
    AdvWPost(ww, s1, c, s, prefix, fuel, ins, vals, k, c', s', rest');
  }

  // ---------------- one step inside W ----------------

  lemma BRWE(c: Cfg, s: S.CState, wbase: int)
    requires BRW(c, s, wbase)
    ensures var n := |c.fr|;
      1 < n <= MAXF_RW && S.CWF(s) && FrameOk(Top(c)) && FrameOk(c.fr[n - 2]) && Top(c).kind == Ins
      && Top(c).pc == wbase + s.pc
      && (forall k | 0 <= k < 10 :: R64(Top(c))[k] == s.regs[k])
      && s.regs[10] == StackTop(n - 2) && Plain(c.fr[n - 2].stack) == s.stack
  { reveal BRWO(); }

  lemma BRWKeep(c: Cfg, s: S.CState, c': Cfg, s': S.CState, wbase: int)
    requires BRW(c, s, wbase) && TopOnly(c, c') && S.CWF(s')
    requires FrameOk(Top(c')) && Top(c').pc == wbase + s'.pc && Top(c').kind == Ins
    requires forall k | 0 <= k < 10 :: R64(Top(c'))[k] == s'.regs[k]
    requires s'.regs[10] == s.regs[10] && s'.stack == s.stack
    ensures BRW(c', s', wbase)
  {
    reveal BRWO();
    var n := |c.fr|;
    assert c'.fr[n - 2] == Below(c')[n - 2] == Below(c)[n - 2] == c.fr[n - 2];
  }

  lemma AtW(ww: WW, c: Cfg, s: S.CState, ins: S.Instr)
    requires WWPre(ww) && BRW(c, s, ww.wbase) && 0 <= s.pc < S.NumInsns(ww.wraw)
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(ins) && !ins.CallHelper?
    ensures AtIns(ww.Pp, c, ins)
  {    BRWE(c, s, ww.wbase);

    WWAtW(ww, s.pc);
    assert !IsHelperCall(S.InsnAt(ww.wraw, s.pc));
  }

  lemma {:isolate_assertions} AluW(c: Cfg, s: S.CState, wbase: int, floor: int,
                                   is64: bool, op: S.AluOp, dst: nat, opnd: S.Operand, oracle: seq<bv64>)
    requires BRW(c, s, wbase) && dst < 10 && opnd != S.Reg(10) && -(S.STACK as int) <= floor <= 0
    ensures S.Step(floor, S.Alu(is64, op, dst, opnd), s, oracle).Next?
    ensures var s' := S.Step(floor, S.Alu(is64, op, dst, opnd), s, oracle).s;
      IAlu(c, is64, op, dst, opnd).Go? && BRW(IAlu(c, is64, op, dst, opnd).c, s', wbase)
      && TopOnly(c, IAlu(c, is64, op, dst, opnd).c) && s'.events == s.events && s'.oc == s.oc
  {    BRWE(c, s, wbase);

    StepAluEq(floor, is64, op, dst, opnd, s, oracle);
    reveal IAlu();
    var f := Top(c);
    var rs := R64(f);
    assert S.OperandVal(is64, opnd, rs) == S.OperandVal(is64, opnd, s.regs) by {
      if opnd.Reg? && opnd.r < 10 { assert rs[opnd.r] == s.regs[opnd.r]; }
    }
    assert rs[dst] == s.regs[dst];
    var v := S.AluVal(is64, op, s.regs[dst], S.OperandVal(is64, opnd, s.regs));
    var f' := Adv(SetR(f, dst, W(v)));
    PutTop(c, f');
    R64Set(f, dst, v);
    var s' := S.Step(floor, S.Alu(is64, op, dst, opnd), s, oracle).s;
    BRWKeep(c, s, Put(c, f'), s', wbase);
  }

  lemma {:isolate_assertions} JaW(c: Cfg, s: S.CState, wbase: int, floor: int, off: bv16, oracle: seq<bv64>)
    requires BRW(c, s, wbase) && -(S.STACK as int) <= floor <= 0
    ensures S.Step(floor, S.Ja(off), s, oracle).Next?
    ensures var s' := S.Step(floor, S.Ja(off), s, oracle).s;
      var c' := Put(c, Top(c).(pc := Top(c).pc + 1 + Signed16(off)));
      BRW(c', s', wbase) && TopOnly(c, c') && s'.events == s.events && s'.oc == s.oc
  {    BRWE(c, s, wbase);

    Soundness.StepEq(floor, S.Ja(off), s, oracle);
    var c' := Put(c, Top(c).(pc := Top(c).pc + 1 + Signed16(off)));
    PutTop(c, Top(c).(pc := Top(c).pc + 1 + Signed16(off)));
    BRWKeep(c, s, c', S.Step(floor, S.Ja(off), s, oracle).s, wbase);
  }

  lemma {:isolate_assertions} JcondW(c: Cfg, s: S.CState, wbase: int, floor: int,
                                     cnd: S.Cond, dst: nat, imm: bv32, off: bv16, oracle: seq<bv64>)
    requires BRW(c, s, wbase) && dst < 10 && -(S.STACK as int) <= floor <= 0
    ensures S.Step(floor, S.Jcond(cnd, dst, imm, off), s, oracle).Next?
    ensures var s' := S.Step(floor, S.Jcond(cnd, dst, imm, off), s, oracle).s;
      IJcond(c, cnd, dst, imm, off).Go? && BRW(IJcond(c, cnd, dst, imm, off).c, s', wbase)
      && TopOnly(c, IJcond(c, cnd, dst, imm, off).c) && s'.events == s.events && s'.oc == s.oc
  {    BRWE(c, s, wbase);

    Soundness.StepEq(floor, S.Jcond(cnd, dst, imm, off), s, oracle);
    reveal IJcond();
    var f := Top(c);
    assert R64(f)[dst] == s.regs[dst];
    var f' := f.(pc := if S.CondHolds(cnd, R64(f)[dst], imm) then f.pc + 1 + Signed16(off) else f.pc + 1);
    PutTop(c, f');
    BRWKeep(c, s, Put(c, f'), S.Step(floor, S.Jcond(cnd, dst, imm, off), s, oracle).s, wbase);
  }

  // The region's loaded value is the whole model's (the caller's frame is the region's).
  lemma {:isolate_assertions} LdxValW(x: Ctx, c: Cfg, s: S.CState, wbase: int, a: bv64, w: nat, oracle: seq<bv64>)
    requires BRW(c, s, wbase) && (w == 1 || w == 2 || w == 4 || w == 8)
    requires !S.InFrame(S.Rel(a, s.regs[10]), w) ==> S.Orc(oracle, s.oc) == LoadedW(x, c, a, w)
    ensures S.LoadVal(s, a, w, oracle) == LoadedW(x, c, a, w)
  {    BRWE(c, s, wbase);

    reveal InsLoad(), S.LoadVal();
    var n := |c.fr|;
    if S.InFrame(S.Rel(a, s.regs[10]), w) {
      ClassifyUp(a, w, n - 1, c.L.mem.Keys);
      var o := S.Rel(a, s.regs[10]) + STK;
      PlainSlice(c.fr[n - 2].stack, o, w);
      assert StackBytes(c, n - 2, o, w) == c.fr[n - 2].stack[o .. o + w];
    } else {
      match Classify(a, w, |c.fr|, c.L.mem.Keys)
      case InStack(d, o) => BytesOfLE(Plain(StackBytes(c, d, o, w)));
      case InLocal => BytesOfLE(LBytes(c.L.mem, a, w));
      case _ => BytesOfLE(BytesOf(HV(x, c), w));
    }
  }

  lemma {:isolate_assertions} LdxW(x: Ctx, c: Cfg, s: S.CState, wbase: int, floor: int,
                                   w: nat, dst: nat, rb: nat, off: bv16, oracle: seq<bv64>)
    requires BRW(c, s, wbase) && dst < 10 && rb < 10 && (w == 1 || w == 2 || w == 4 || w == 8)
    requires -(S.STACK as int) <= floor <= 0
    requires var a := s.regs[rb] + Sext16(off);
      !S.InFrame(S.Rel(a, s.regs[10]), w) ==> S.Orc(oracle, s.oc) == LoadedW(x, c, a, w)
    ensures S.Step(floor, S.Ldx(w, dst, rb, off), s, oracle).Next?
    ensures var s' := S.Step(floor, S.Ldx(w, dst, rb, off), s, oracle).s;
      ILdx(x, c, w, dst, rb, off).Go? && BRW(ILdx(x, c, w, dst, rb, off).c, s', wbase)
      && TopOnly(c, ILdx(x, c, w, dst, rb, off).c) && s'.events == s.events
      && s'.oc == s.oc + (if S.InFrame(S.Rel(s.regs[rb] + Sext16(off), s.regs[10]), w) then 0 else 1)
  {    BRWE(c, s, wbase);

    StepLdx(floor, w, dst, rb, off, s, oracle);
    var a := s.regs[rb] + Sext16(off);
    var f := Top(c);
    assert R64(f)[rb] == s.regs[rb];
    assert R64(f)[rb] + Sext16(off) == a;
    LdxValW(x, c, s, wbase, a, w, oracle);
    var vw := LoadedW(x, c, a, w);
    var kk := InsLoad(x, c, a, w).1;
    ILdxEq(x, c, w, dst, rb, off, a);
    var c1 := c.(hc := c.hc + kk);
    PutTop(c1, Adv(SetR(f, dst, W(vw))));
    R64Set(f, dst, vw);
    var s' := S.Step(floor, S.Ldx(w, dst, rb, off), s, oracle).s;
    BRWKeep(c, s, Put(c1, Adv(SetR(f, dst, W(vw)))), s', wbase);
  }

  // The region's registers after a hook call in W are the whole model's.
  lemma HookRegsW(s: S.CState, prefix: seq<bv64>, f: Frame, f2: Frame)
    requires S.CWF(s) && s.oc == |prefix| && (forall k | 0 <= k < 10 :: R64(f)[k] == s.regs[k])
    requires |f.regs| == NR && |f2.regs| == NR && forall r | 6 <= r < NR :: f2.regs[r] == f.regs[r]
    ensures var s' := S.HookStep(s, prefix + R64(f2)[0..6]).s;
      (forall k | 0 <= k < 10 :: R64(f2)[k] == s'.regs[k]) && s'.regs[10] == s.regs[10]
  {
    var vals := R64(f2)[0..6];
    var s' := S.HookStep(s, prefix + vals).s;
    assert s'.regs == S.HavocRegs(s.regs, prefix + vals, s.oc, 6);
    forall k | 0 <= k < 10 ensures R64(f2)[k] == s'.regs[k] {
      if k < 6 { assert S.Orc(prefix + vals, s.oc + k) == vals[k]; }
      else { assert s'.regs[k] == s.regs[k] == R64(f)[k]; }
    }
  }

  // ---------------- the bridge, phase W ----------------

  lemma BridgeW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat) returns (rest: seq<bv64>)
    requires PreW(ww, s1, c, s, prefix)
    ensures PostW(ww, s1, c, s, prefix, fuel, rest)
    decreases fuel, 3
  {
    var n := S.NumInsns(ww.wraw);
    var fl := ww.sp.floor;
    rest := [];
    assert prefix + rest == prefix;
    if s.pc == n {
      Soundness.RunEnd(ww.wraw, fl, s, prefix, fuel);
      return;
    }
    if s.pc < 0 || s.pc > n || fuel == 0 {
      reveal S.Run();
      return;
    }
    match S.Decode(S.InsnAt(ww.wraw, s.pc))
    case None =>
      reveal S.Run();
    case Some(ins) =>
      rest := BInsW(ww, s1, c, s, prefix, fuel, ins);
  }

  // Every instruction of W meets WInsnOk (no r10 operand).
  lemma WIns(ww: WW, pc: nat, ins: S.Instr)
    requires WWPre(ww) && pc < S.NumInsns(ww.wraw) && S.Decode(S.InsnAt(ww.wraw, pc)) == Some(ins)
    ensures WInsnOk(ins, ww.sp)
  {
    WWStat(ww);
  }

  ghost predicate AtWI(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr) {
    PreW(ww, s1, c, s, prefix) && 0 <= s.pc < S.NumInsns(ww.wraw) && fuel > 0
    && S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(ins) && !S.NamesR10(ins)
  }

  lemma {:isolate_assertions} BInsW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    returns (rest: seq<bv64>)
    requires PreW(ww, s1, c, s, prefix) && 0 <= s.pc < S.NumInsns(ww.wraw) && fuel > 0
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(ins)
    ensures PostW(ww, s1, c, s, prefix, fuel, rest)
    decreases fuel, 2
  {
    WIns(ww, s.pc, ins);
    assert !S.NamesR10(ins);
    assert AtWI(ww, s1, c, s, prefix, fuel, ins);
    rest := [];
    match ins
    case Alu(_, _, _, _) => rest := BAluW(ww, s1, c, s, prefix, fuel, ins);
    case Ja(_) => rest := BJaW(ww, s1, c, s, prefix, fuel, ins);
    case Jcond(_, _, _, _) => rest := BJcondW(ww, s1, c, s, prefix, fuel, ins);
    case Ldx(wd, dst, rb, off) => rest := BLdxW(ww, s1, c, s, prefix, fuel, wd, dst, rb, off);
    case Stx(_, _, _, _) => BStW(ww, s1, c, s, prefix, fuel, ins);
    case St(_, _, _, _) => BStW(ww, s1, c, s, prefix, fuel, ins);
    case CallHelper(id) => rest := BHelperW(ww, s1, c, s, prefix, fuel, id);
    case CallLocal(imm) => rest := BHookW(ww, s1, c, s, prefix, fuel, imm);
    case Exit => rest := ExitW(ww, s1, c, s, prefix, fuel);
  }

  lemma {:isolate_assertions} BAluW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    returns (rest: seq<bv64>)
    requires AtWI(ww, s1, c, s, prefix, fuel, ins) && ins.Alu?
    ensures PostW(ww, s1, c, s, prefix, fuel, rest)
    decreases fuel, 1
  {
    var fl := ww.sp.floor;
    rest := [];
    if ins.dst >= 10 {
      assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
      StuckPostW(ww, s1, c, s, prefix, fuel, ins);
    } else {
      AtW(ww, c, s, ins);
      AluW(c, s, ww.wbase, fl, ins.is64, ins.op, ins.dst, ins.opnd, prefix);
      var r := IAlu(c, ins.is64, ins.op, ins.dst, ins.opnd);
      StepIns(ww.Pp, ww.x, ww.obsv, c, ins);
      ReachOne(ww.Pp, ww.x, ww.obsv, c, r.c);
      var s' := S.Step(fl, ins, s, prefix).s;
      assert prefix + [] == prefix;
      SideWKeep(ww, s1, c, s, r.c, s');
      rest := AdvW(ww, s1, c, s, prefix, fuel, ins, [], 1, r.c, s');
    }
  }

  lemma {:isolate_assertions} BJaW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    returns (rest: seq<bv64>)
    requires AtWI(ww, s1, c, s, prefix, fuel, ins) && ins.Ja?
    ensures PostW(ww, s1, c, s, prefix, fuel, rest)
    decreases fuel, 1
  {
    var fl := ww.sp.floor;
    AtW(ww, c, s, ins);
    JaW(c, s, ww.wbase, fl, ins.off, prefix);
    var c' := Put(c, Top(c).(pc := Top(c).pc + 1 + Signed16(ins.off)));
    StepIns(ww.Pp, ww.x, ww.obsv, c, ins);
    ReachOne(ww.Pp, ww.x, ww.obsv, c, c');
    var s' := S.Step(fl, ins, s, prefix).s;
    assert prefix + [] == prefix;
    SideWKeep(ww, s1, c, s, c', s');
    rest := AdvW(ww, s1, c, s, prefix, fuel, ins, [], 1, c', s');
  }

  lemma {:isolate_assertions} BJcondW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    returns (rest: seq<bv64>)
    requires AtWI(ww, s1, c, s, prefix, fuel, ins) && ins.Jcond?
    ensures PostW(ww, s1, c, s, prefix, fuel, rest)
    decreases fuel, 1
  {
    var fl := ww.sp.floor;
    rest := [];
    if ins.dst > 10 {
      assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
      StuckPostW(ww, s1, c, s, prefix, fuel, ins);
    } else {
      AtW(ww, c, s, ins);
      JcondW(c, s, ww.wbase, fl, ins.cond, ins.dst, ins.imm, ins.off, prefix);
      var r := IJcond(c, ins.cond, ins.dst, ins.imm, ins.off);
      StepIns(ww.Pp, ww.x, ww.obsv, c, ins);
      ReachOne(ww.Pp, ww.x, ww.obsv, c, r.c);
      var s' := S.Step(fl, ins, s, prefix).s;
      assert prefix + [] == prefix;
      SideWKeep(ww, s1, c, s, r.c, s');
      rest := AdvW(ww, s1, c, s, prefix, fuel, ins, [], 1, r.c, s');
    }
  }

  lemma {:isolate_assertions} BStW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    requires AtWI(ww, s1, c, s, prefix, fuel, ins) && (ins.Stx? || ins.St?)
    ensures PostW(ww, s1, c, s, prefix, fuel, [])
  {
    var fl := ww.sp.floor;
    match ins
    case Stx(wd, rb, src, off) =>
      if rb > 10 || src > 10 || wd > 8 {
        assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
        StuckPostW(ww, s1, c, s, prefix, fuel, ins);
      } else {
        StepStx(fl, wd, rb, src, off, s, prefix);
        var s' := S.StoreStep(s, s.regs[rb] + Sext16(off), wd, s.regs[src]).s;
        assert s'.events[|s.events|] == S.EStore(s.regs[rb] + Sext16(off), wd);
        BadPostW(ww, s1, c, s, prefix, fuel, ins, s');
      }
    case St(wd, rb, off, imm) =>
      if rb > 10 || wd > 8 {
        assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
        StuckPostW(ww, s1, c, s, prefix, fuel, ins);
      } else {
        StepSt(fl, wd, rb, off, imm, s, prefix);
        var s' := S.StoreStep(s, s.regs[rb] + Sext16(off), wd, Sext32(imm)).s;
        assert s'.events[|s.events|] == S.EStore(s.regs[rb] + Sext16(off), wd);
        BadPostW(ww, s1, c, s, prefix, fuel, ins, s');
      }
  }

  lemma {:isolate_assertions} BLdxW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat,
                                    wd: nat, dst: nat, rb: nat, off: bv16) returns (rest: seq<bv64>)
    requires PreW(ww, s1, c, s, prefix) && 0 <= s.pc < S.NumInsns(ww.wraw) && fuel > 0
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(S.Ldx(wd, dst, rb, off))
    ensures PostW(ww, s1, c, s, prefix, fuel, rest)
    decreases fuel, 1
  {    BRWE(c, s, ww.wbase);

    var fl := ww.sp.floor;
    var ins := S.Ldx(wd, dst, rb, off);
    WIns(ww, s.pc, ins);
    DecodeWidth(S.InsnAt(ww.wraw, s.pc));
    rest := [];
    if dst >= 10 || rb > 10 {
      assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
      StuckPostW(ww, s1, c, s, prefix, fuel, ins);
      return;
    }
    assert rb != 10;
    AtW(ww, c, s, ins);
    var a := s.regs[rb] + Sext16(off);
    var inF := S.InFrame(S.Rel(a, s.regs[10]), wd);
    var vals: seq<bv64> := if inF then [] else [LoadedW(ww.x, c, a, wd)];
    assert !inF ==> S.Orc(prefix + vals, s.oc) == LoadedW(ww.x, c, a, wd);
    LdxW(ww.x, c, s, ww.wbase, fl, wd, dst, rb, off, prefix + vals);
    var r := ILdx(ww.x, c, wd, dst, rb, off);
    StepIns(ww.Pp, ww.x, ww.obsv, c, ins);
    ReachOne(ww.Pp, ww.x, ww.obsv, c, r.c);
    var s' := S.Step(fl, ins, s, prefix + vals).s;
    SideWKeep(ww, s1, c, s, r.c, s');
    NeedLdx(fl, wd, dst, rb, off, s);
    assert PreW(ww, s1, r.c, s', prefix + vals);
    rest := AdvW(ww, s1, c, s, prefix, fuel, ins, vals, 1, r.c, s');
  }

  lemma {:isolate_assertions} BHookW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, imm: bv32)
    returns (rest: seq<bv64>)
    requires PreW(ww, s1, c, s, prefix) && 0 <= s.pc < S.NumInsns(ww.wraw) && fuel > 0
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(S.CallLocal(imm))
    ensures PostW(ww, s1, c, s, prefix, fuel, rest)
    decreases fuel, 1
  {
    var fl := ww.sp.floor;
    var ins := S.CallLocal(imm);
    var k, c2 := HookRunW(ww, s1, c, s, imm);
    var vals := R64(Top(c2))[0..6];
    var s' := HookAfterW(ww, s1, c, s, prefix, imm, c2);
    assert PreW(ww, s1, c2, s', prefix + vals);
    StepHook(fl, imm, s, prefix + vals);
    rest := AdvW(ww, s1, c, s, prefix, fuel, ins, vals, k, c2, s');
  }

  // A hook call in W runs the hook and returns to W.
  lemma {:isolate_assertions} HookRunW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, imm: bv32) returns (k: nat, c2: Cfg)
    requires WWPre(ww) && BRW(c, s, ww.wbase) && SideW(ww, s1, c, s) && 0 <= s.pc < S.NumInsns(ww.wraw)
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(S.CallLocal(imm))
    ensures ReachR(ww.Pp, ww.x, ww.obsv, c, k) == Some(c2)
    ensures |c2.fr| == |c.fr| && Below(c2) == Below(c) && c2.L == c.L && c2.h == c.h
    ensures FrameOk(Top(c2)) && Top(c2).pc == Top(c).pc + 1 && Top(c2).stack == Top(c).stack
    ensures Top(c2).kind == Top(c).kind && Top(c2).fn == Top(c).fn
    ensures forall r | 6 <= r < NR :: Top(c2).regs[r] == Top(c).regs[r]
  {
    BRWE(c, s, ww.wbase);
    AtW(ww, c, s, S.CallLocal(imm));
    WWHooks(ww);
    WWInit(ww);
    WWA5(ww);
    SideWE(ww, s1, c, s);
    HookTargetW(ww, s.pc, imm);
    assert Top(c).pc == ww.wbase + s.pc;
    k, c2 := HookRun(ww.Pp, ww.x, ww.obsv, c, imm);
  }

  lemma HookTargetW(ww: WW, pc: nat, imm: bv32)
    requires WWPre(ww) && pc < S.NumInsns(ww.wraw) && S.Decode(S.InsnAt(ww.wraw, pc)) == Some(S.CallLocal(imm))
    ensures ww.wbase + pc + 1 + Signed32(imm) in ww.Pp.hooks
  {
    WWAtW(ww, pc);
  }

  // The region state after the hook call, and the window's relation kept.
  lemma {:isolate_assertions} HookAfterW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, imm: bv32, c2: Cfg)
    returns (s': S.CState)
    requires PreW(ww, s1, c, s, prefix)
    requires |c2.fr| == |c.fr| && Below(c2) == Below(c) && c2.L == c.L && c2.h == c.h
    requires FrameOk(Top(c2)) && Top(c2).pc == Top(c).pc + 1 && Top(c2).stack == Top(c).stack
    requires Top(c2).kind == Top(c).kind && Top(c2).fn == Top(c).fn
    requires forall r | 6 <= r < NR :: Top(c2).regs[r] == Top(c).regs[r]
    ensures s' == S.HookStep(s, prefix + R64(Top(c2))[0..6]).s
    ensures PreW(ww, s1, c2, s', prefix + R64(Top(c2))[0..6])
  {
    var vals := R64(Top(c2))[0..6];
    s' := S.HookStep(s, prefix + vals).s;
    BRWE(c, s, ww.wbase);
    HookRegsW(s, prefix, Top(c), Top(c2));
    var e := S.EHook(s.pc, s.regs[1..6], s.regs[0], s.regs[10]);
    assert s'.events == s.events + [e];
    assert TopOnly(c, c2);
    BRWKeep(c, s, c2, s', ww.wbase);
    SideWEvent(ww, s1, c, s, c2, s', e);
  }

  // W's helper (the original lookup I_i) in the whole model.
  lemma {:isolate_assertions} HelperWholeW(ww: WW, s1: S.CState, c: Cfg, s: S.CState) returns (c': Cfg)
    requires WWPre(ww) && BRW(c, s, ww.wbase) && SideW(ww, s1, c, s) && CountHelpers(s.events) == 0
    requires 0 < |ww.c0.fr| && |c.fr| == |ww.c0.fr| + 1
    requires 0 <= s.pc < S.NumInsns(ww.wraw) && IsHelperCall(S.InsnAt(ww.wraw, s.pc))
    requires s.regs[1] == ww.s0.regs[1] && s.regs[2] == ww.s0.regs[2] && s.regs[3] == ww.s0.regs[3]
    ensures StepR(ww.Pp, ww.x, ww.obsv, c) == Go(c')
    ensures Finish(ww.x, c.(h := c.h + [ww.hc.eh]), ww.hc.v, ww.hc.wr) == Go(c')
  {
    WWHelper(ww); WWA8(ww);
    SideWE(ww, s1, c, s); SideW0(ww, s1, c, s);
    var x := ww.x;
    var id := ww.hins.id;
    HelperAtW(ww, c, s);
    HelperArgsW(ww, c, s);
    HelperFootW(ww, c);
    assert x.om(c.h, ww.hc.eh, Wh(c)) == x.om(c.h, ww.hc.eh, Wh(ww.c0));
    HelperStepFin(x, c, ww.hidx, id, ww.hc.n, SimFacts.Words(Top(ww.c0), Upto(1, ww.hc.n)), ww.hc.addrs,
                  FootBytes(ww.c0, ww.hc.addrs).bs, ww.hc.v, ww.hc.wr);
    var c1 := c.(h := c.h + [ww.hc.eh]);
    FinishFacts(x, c1, ww.hc.v, ww.hc.wr);
    c' := Finish(x, c1, ww.hc.v, ww.hc.wr).c;
  }

  // The step at a helper slice of W is the original lookup.
  lemma HelperAtW(ww: WW, c: Cfg, s: S.CState)
    requires WWPre(ww) && BRW(c, s, ww.wbase) && 0 <= s.pc < S.NumInsns(ww.wraw) && IsHelperCall(S.InsnAt(ww.wraw, s.pc))
    requires HelperOkW(ww)
    ensures StepR(ww.Pp, ww.x, ww.obsv, c) == HelperStep(ww.x, c, ww.hidx, false, ww.hins.id, false)
  {
    BRWE(c, s, ww.wbase);
    WWAtW(ww, s.pc);
    assert ww.Pp.code[Top(c).pc] == O(Hcall(false, ww.hins.id), ww.hidx);
  }

  // W's r1..r3 are the window's entry values.
  lemma {:isolate_assertions} HelperArgsW(ww: WW, c: Cfg, s: S.CState)
    requires WWPre(ww) && BRW(c, s, ww.wbase) && HelperOkW(ww)
    requires s.regs[1] == ww.s0.regs[1] && s.regs[2] == ww.s0.regs[2] && s.regs[3] == ww.s0.regs[3]
    ensures Rds(Top(c), Upto(1, ww.hc.n)) == Some(SimFacts.Words(Top(ww.c0), Upto(1, ww.hc.n)))
  {
    BRWE(c, s, ww.wbase);
    WWInit(ww);
    var n := ww.hc.n;
    var f := Top(c);
    var f0 := Top(ww.c0);
    forall i | 0 <= i < |Upto(1, n)| ensures Reg(f, Upto(1, n)[i]).W? && Reg(f, Upto(1, n)[i]) == Reg(f0, Upto(1, n)[i]) {
      UptoAt(1, n, i);
      var r := Upto(1, n)[i];
      assert 1 <= r <= 3;
      assert R64(f)[r] == s.regs[r] == ww.s0.regs[r] == R64(f0)[r];
    }
    SimFacts.RdsAll(f, Upto(1, n));
    assert SimFacts.Words(f, Upto(1, n)) == SimFacts.Words(f0, Upto(1, n));
  }

  // The footprint is read as at the window's entry.
  lemma {:isolate_assertions} HelperFootW(ww: WW, c: Cfg)
    requires 0 < |ww.c0.fr| && |c.fr| == |ww.c0.fr| + 1 <= MAXF_RW && |Top(ww.c0).stack| == STK
    requires c.fr[..|ww.c0.fr| - 1] == Below(ww.c0) && c.fr[|ww.c0.fr| - 1].stack == Top(ww.c0).stack && c.L == ww.c0.L
    requires FootBytes(ww.c0, ww.hc.addrs).FOk?
    ensures FootBytes(c, ww.hc.addrs) == FootBytes(ww.c0, ww.hc.addrs)
  {
    var c0 := ww.c0;
    var d := |c0.fr|;
    forall k | 0 <= k < d ensures c.fr[k].stack == c0.fr[k].stack {
      if k < d - 1 { assert c.fr[k] == c.fr[..d - 1][k] == Below(c0)[k] == c0.fr[k]; }
      else { assert c0.fr[k] == Top(c0); }
    }
    FootPush(c0, c, ww.hc.addrs);
  }

  lemma HelperStepFin(x: Ctx, c: Cfg, idx: nat, id: bv32, n: nat, args: seq<bv64>, addrs: seq<bv64>,
                      beta: seq<bv8>, v: Val, wr: map<int, bv8>)
    requires n == x.env.arity(false, id) && n <= 5 && Rds(Top(c), Upto(1, n)) == Some(args)
    requires addrs == x.env.foot(false, id, args) && FootBytes(c, addrs) == FOk(beta)
    requires x.om(c.h, ECall(idx, false, id, args, beta), Wh(c)) == RRet(v, wr)
    ensures HelperStep(x, c, idx, false, id, false) == Finish(x, c.(h := c.h + [ECall(idx, false, id, args, beta)]), v, wr)
  { reveal HelperStep(); }

  // The configuration after W's helper.
  lemma {:isolate_assertions} HelperAfterW(ww: WW, c: Cfg, c': Cfg)
    requires ww.x.m.MR? && 0 < |ww.c0.fr| && |c.fr| == |ww.c0.fr| + 1 && FrameOk(Top(c)) && |Top(ww.c0).stack| == STK
    requires c.fr[..|ww.c0.fr| - 1] == Below(ww.c0) && c.fr[|ww.c0.fr| - 1].stack == Top(ww.c0).stack
    requires c.L == ww.c0.L && c.h == ww.c0.h
    requires Finish(ww.x, c.(h := c.h + [ww.hc.eh]), ww.hc.v, ww.hc.wr) == Go(c')
    ensures |c'.fr| == |c.fr| && FrameOk(Top(c')) && Top(c').pc == Top(c).pc + 1
    ensures Top(c').kind == Top(c).kind && Top(c').fn == Top(c).fn
    ensures forall k | 6 <= k < NR :: Top(c').regs[k] == Top(c).regs[k]
    ensures ww.hc.v.W? ==> Top(c').regs[0] == ww.hc.v
    ensures c'.fr[..|ww.c0.fr| - 1] == Below(ApplyW(ww.c0, ww.hc.wr))
    ensures c'.fr[|ww.c0.fr| - 1] == c.fr[|ww.c0.fr| - 1].(stack := StAfter(ww))
    ensures c'.L == ApplyL(ww.c0.L, ww.hc.wr) && c'.h == ww.c0.h + [ww.hc.eh]
  {
    var c1 := c.(h := c.h + [ww.hc.eh]);
    FinishFacts(ww.x, c1, ww.hc.v, ww.hc.wr);
    HelperFramesW(ww, c, c1, c');
    FinishFrameOk(ww.x, c1, ww.hc.v, ww.hc.wr);
    ApplyWAt(c1, ww.hc.wr);
  }

  // The frames below W after its helper: the write set applied, as in P.
  lemma {:isolate_assertions} HelperFramesW(ww: WW, c: Cfg, c1: Cfg, c': Cfg)
    requires 0 < |ww.c0.fr| && |c.fr| == |ww.c0.fr| + 1 && c1.fr == c.fr && |Top(ww.c0).stack| == STK
    requires c.fr[..|ww.c0.fr| - 1] == Below(ww.c0) && c.fr[|ww.c0.fr| - 1].stack == Top(ww.c0).stack
    requires |c'.fr| == |c.fr| && Below(c') == Below(ApplyW(c1, ww.hc.wr))
    ensures c'.fr[..|ww.c0.fr| - 1] == Below(ApplyW(ww.c0, ww.hc.wr))
    ensures c'.fr[|ww.c0.fr| - 1] == c.fr[|ww.c0.fr| - 1].(stack := StAfter(ww))
  {
    var c0 := ww.c0;
    var d := |c0.fr|;
    var wr := ww.hc.wr;
    ApplyWAt(c1, wr);
    ApplyWAt(c0, wr);
    var a := ApplyW(c1, wr);
    forall k | 0 <= k < d - 1 ensures c'.fr[k] == Below(ApplyW(c0, wr))[k] {
      assert c'.fr[k] == Below(c')[k] == a.fr[k] == ApplyF(c1.fr[k], k, wr);
      assert c1.fr[k] == c.fr[..d - 1][k] == Below(c0)[k] == c0.fr[k];
    }
    assert c'.fr[d - 1] == Below(c')[d - 1] == a.fr[d - 1] == ApplyF(c.fr[d - 1], d - 1, wr);
    assert c0.fr[d - 1] == Top(c0);
    assert ApplyF(c.fr[d - 1], d - 1, wr).stack == ApplyF(Top(c0), d - 1, wr).stack;
  }

  // After a helper finish in P', the top frame has no unreadable value.
  lemma {:isolate_assertions} FinishFrameOk(x: Ctx, c: Cfg, v: Val, wr: map<int, bv8>)
    requires x.m.MR? && |c.fr| > 0 && FrameOk(Top(c))
    ensures Finish(x, c, v, wr).Go? && FrameOk(Top(Finish(x, c, v, wr).c))
  {
    FinishFacts(x, c, v, wr);
    var c' := Finish(x, c, v, wr).c;
    ApplyWAt(c, wr);
    forall k | 0 <= k < NR ensures Top(c').regs[k].W? {
      if 6 <= k { assert Top(c').regs[k] == Top(c).regs[k]; } else { UndW(x, c, k); }
    }
    forall o | 0 <= o < STK ensures Top(c').stack[o].B? {
      assert Top(c').stack[o] == ApplyF(Top(c), |c.fr| - 1, wr).stack[o];
    }
  }

  // The region's helper step from the whole model's result (W's registers, the caller's stack).
  lemma {:isolate_assertions} HelperBRW(fl: int, id: bv32, c: Cfg, s: S.CState, wbase: int, c': Cfg, prefix: seq<bv64>)
    returns (vals: seq<bv64>, s': S.CState)
    requires BRW(c, s, wbase) && -(S.STACK as int) <= fl <= 0 && s.oc == |prefix|
    requires FrameOk(Top(c)) && FrameOk(c.fr[|c.fr| - 2])
    requires |c'.fr| == |c.fr| && FrameOk(Top(c')) && Top(c').pc == Top(c).pc + 1 && Top(c').kind == Ins
    requires forall k | 6 <= k < NR :: Top(c').regs[k] == Top(c).regs[k]
    requires FrameOk(c'.fr[|c.fr| - 2])
    requires forall o {:nowarn} | 0 <= o < STK && o < STK as int + fl :: c'.fr[|c.fr| - 2].stack[o] == c.fr[|c.fr| - 2].stack[o]
    ensures S.Step(fl, S.CallHelper(id), s, prefix + vals) == S.Next(s') && S.CWF(s')
    ensures BRW(c', s', wbase) && s'.oc == |prefix + vals| && s.oc + Need(fl, S.CallHelper(id), s) <= |prefix + vals|
    ensures s'.events == s.events + [S.EHelper(s.regs[1..6], s'.regs[0], s'.stack, id)]
    ensures s'.regs[0] == R64(Top(c'))[0] && s'.stack == Plain(c'.fr[|c.fr| - 2].stack)
  {
    BRWE(c, s, wbase);
    var n := |c.fr|;
    var f2 := Top(c');
    var cf2 := c'.fr[n - 2];
    var lo := STK as int + fl;
    var up := -fl;
    vals := HelperValsW(R64(f2)[0..6], cf2.stack, fl);
    StepHelper(fl, id, s, prefix + vals);
    s' := S.HelperStep(fl, s, prefix + vals, id).s;
    assert s'.regs == S.HavocRegs(s.regs, prefix + vals, s.oc, 6);
    assert s'.stack == S.HelperStack(fl, s, prefix + vals);
    HelperRegsW(s, prefix, vals, Top(c), f2);
    HelperStackW(fl, s, prefix, vals, cf2.stack, c.fr[n - 2].stack);
    assert s'.stack == Plain(cf2.stack);
    assert s'.pc == s.pc + 1;
    BRWIntro(c', s', wbase);
  }

  lemma BRWIntro(c: Cfg, s: S.CState, wbase: int)
    requires 1 < |c.fr| <= MAXF_RW && S.CWF(s) && FrameOk(Top(c)) && FrameOk(c.fr[|c.fr| - 2]) && Top(c).kind == Ins
    requires Top(c).pc == wbase + s.pc
    requires forall k | 0 <= k < 10 :: R64(Top(c))[k] == s.regs[k]
    requires s.regs[10] == StackTop(|c.fr| - 2) && Plain(c.fr[|c.fr| - 2].stack) == s.stack
    ensures BRW(c, s, wbase)
  { reveal BRWO(); }

  // The oracle values of W's helper step: r0..r5, then the bytes at or above the floor.
  lemma HelperValsW(r: seq<bv64>, st: seq<Byte>, fl: int) returns (vals: seq<bv64>)
    requires |r| == 6 && |st| == STK && -(STK as int) <= fl <= 0
    ensures |vals| == 6 - fl && vals[0..6] == r
    ensures forall j {:nowarn} | 0 <= j < -fl :: vals[6 + j] == Zext8(Plain(st)[STK as int + fl + j])
  {
    var lo := STK as int + fl;
    vals := r + seq(-fl, j requires 0 <= j < -fl => Zext8(Plain(st)[lo + j]));
  }

  lemma {:isolate_assertions} HelperRegsW(s: S.CState, prefix: seq<bv64>, vals: seq<bv64>, f: Frame, f2: Frame)
    requires S.CWF(s) && s.oc == |prefix| && |vals| >= 6 && vals[0..6] == R64(f2)[0..6]
    requires |f.regs| == NR && |f2.regs| == NR && (forall k | 0 <= k < 10 :: R64(f)[k] == s.regs[k])
    requires forall k | 6 <= k < NR :: f2.regs[k] == f.regs[k]
    ensures var r := S.HavocRegs(s.regs, prefix + vals, s.oc, 6);
      (forall k | 0 <= k < 10 :: r[k] == R64(f2)[k]) && r[10] == s.regs[10]
  {
    var r := S.HavocRegs(s.regs, prefix + vals, s.oc, 6);
    forall k | 0 <= k < 10 ensures r[k] == R64(f2)[k] {
      if k >= 6 { assert r[k] == s.regs[k] == R64(f)[k]; }
      else { assert r[k] == S.Orc(prefix + vals, s.oc + k) == vals[k]; }
    }
  }

  lemma {:isolate_assertions} HelperStackW(fl: int, s: S.CState, prefix: seq<bv64>, vals: seq<bv64>,
                                           st2: seq<Byte>, st1: seq<Byte>)
    requires S.CWF(s) && -(S.STACK as int) <= fl <= 0 && s.oc == |prefix|
    requires |st2| == STK && |st1| == STK && Plain(st1) == s.stack
    requires forall o {:nowarn} | 0 <= o < STK && o < STK as int + fl :: st2[o] == st1[o]
    requires |vals| == 6 - fl
    requires forall j {:nowarn} | 0 <= j < -fl :: vals[6 + j] == Zext8(Plain(st2)[STK as int + fl + j])
    ensures S.HelperStack(fl, s, prefix + vals) == Plain(st2)
  {
    var lo := STK as int + fl;
    var hs := S.HelperStack(fl, s, prefix + vals);
    forall i | 0 <= i < S.STACK ensures hs[i] == Plain(st2)[i] {
      if i >= lo {
        var j := i - lo;
        assert vals[6 + j] == Zext8(Plain(st2)[STK as int + fl + j]);
        assert hs[i] == ByteOf(S.Orc(prefix + vals, s.oc + 6 + (i - lo)), 0);
        assert S.Orc(prefix + vals, s.oc + 6 + (i - lo)) == vals[6 + (i - lo)] == Zext8(Plain(st2)[i]);
        ByteOfZext(Plain(st2)[i]);
      } else {
        assert hs[i] == s.stack[i];
        assert st2[i] == st1[i];
      }
    }
  }

  lemma {:isolate_assertions} SideWHelper(ww: WW, s1: S.CState, c: Cfg, s: S.CState, c': Cfg, s': S.CState)
    requires SideW(ww, s1, c, s) && CountHelpers(s.events) == 0
    requires 0 < |ww.c0.fr| && |c.fr| == |ww.c0.fr| + 1 && |c'.fr| == |c.fr|
    requires c'.fr[..|ww.c0.fr| - 1] == Below(ApplyW(ww.c0, ww.hc.wr))
    requires c'.fr[|ww.c0.fr| - 1] == c.fr[|ww.c0.fr| - 1].(stack := StAfter(ww))
    requires c'.L == ApplyL(ww.c0.L, ww.hc.wr) && c'.h == ww.c0.h + [ww.hc.eh]
    requires exists e :: s'.events == s.events + [e] && e.EHelper? && e.stackAfter == Plain(StAfter(ww))
               && (ww.hc.v.W? ==> e.ret == ww.hc.v.w)
    ensures SideW(ww, s1, c', s')
  {
    var e :| s'.events == s.events + [e] && e.EHelper? && e.stackAfter == Plain(StAfter(ww)) && (ww.hc.v.W? ==> e.ret == ww.hc.v.w);
    Soundness.EventsSnoc(s.events, e, ww.s0.stack);
    reveal SideW();
  }

  lemma {:isolate_assertions} BHelperW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, id: bv32)
    returns (rest: seq<bv64>)
    requires PreW(ww, s1, c, s, prefix) && 0 <= s.pc < S.NumInsns(ww.wraw) && fuel > 0
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(S.CallHelper(id))
    ensures PostW(ww, s1, c, s, prefix, fuel, rest)
    decreases fuel, 1
  {    BRWE(c, s, ww.wbase);

    var fl := ww.sp.floor;
    var ins := S.CallHelper(id);
    rest := [];
    StepHelper(fl, id, s, prefix);
    var sB := S.HelperStep(fl, s, prefix, id).s;
    var eB := S.EHelper(s.regs[1..6], S.HavocRegs(s.regs, prefix, s.oc, 6)[0], S.HelperStack(fl, s, prefix), id);
    assert sB.events == s.events + [eB];
    Soundness.EventsSnoc(s.events, eB, ww.s0.stack);
    SideWE(ww, s1, c, s);
    if CountHelpers(s.events) != 0 {
      BadPostW(ww, s1, c, s, prefix, fuel, ins, sB);
      return;
    }
    if !(s.regs[1] == ww.s0.regs[1] && s.regs[2] == ww.s0.regs[2] && s.regs[3] == ww.s0.regs[3]) {
      assert eB.args == s.regs[1..6];
      assert !EventOk(ww.sp, ww.s0, eB);
      BadPostW(ww, s1, c, s, prefix, fuel, ins, sB);
      return;
    }
    WWHelper(ww);
    WWInit(ww);
    var d := |ww.c0.fr|;
    var c' := HelperWholeW(ww, s1, c, s);
    SideW0(ww, s1, c, s);
    HelperAfterW(ww, c, c');
    assert c'.fr[|c.fr| - 2] == c.fr[d - 1].(stack := StAfter(ww));
    forall o {:nowarn} | 0 <= o < STK && o < STK as int + fl ensures c'.fr[|c.fr| - 2].stack[o] == c.fr[|c.fr| - 2].stack[o] {
      assert SAddr(d - 1, o) as int !in ww.hc.wr;
      SideW0(ww, s1, c, s);
      assert c.fr[d - 1].stack == Top(ww.c0).stack;
    }
    assert FrameOk(c'.fr[|c.fr| - 2]) by {
      SideW0(ww, s1, c, s);
      assert FrameOk(c.fr[d - 1]);
      forall o | 0 <= o < STK ensures StAfter(ww)[o].B? {
        assert Top(ww.c0).stack[o].B?;
      }
    }
    var vals, s' := HelperBRW(fl, id, c, s, ww.wbase, c', prefix);
    assert s'.events == s.events + [S.EHelper(s.regs[1..6], s'.regs[0], s'.stack, id)];
    assert ww.hc.v.W? ==> s'.regs[0] == ww.hc.v.w;
    SideWHelper(ww, s1, c, s, c', s');
    ReachOne(ww.Pp, ww.x, ww.obsv, c, c');
    assert PreW(ww, s1, c', s', prefix + vals);
    rest := AdvW(ww, s1, c, s, prefix, fuel, ins, vals, 1, c', s');
  }

  // EXIT in W returns to the caller (as a hook's exit does), keeping W's r0.
  lemma {:isolate_assertions} WRet(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg) returns (c2: Cfg)
    requires x.m.MR? && |c.fr| > 1 && FrameOk(Top(c)) && Top(c).kind == Ins && FrameOk(c.fr[|c.fr| - 2])
    requires AtIns(Pp, c, S.Exit)
    ensures ReachR(Pp, x, obsv, c, 1) == Some(c2)
    ensures |c2.fr| == |c.fr| - 1 && Below(c2) == c.fr[..|c.fr| - 2] && c2.L == c.L && c2.h == c.h
    ensures FrameOk(Top(c2)) && Top(c2).pc == c.fr[|c.fr| - 2].pc + 1 && Top(c2).stack == c.fr[|c.fr| - 2].stack
    ensures Top(c2).kind == c.fr[|c.fr| - 2].kind && Top(c2).fn == c.fr[|c.fr| - 2].fn
    ensures Top(c2).regs[0] == Top(c).regs[0]
    ensures forall r | 6 <= r < NR :: Top(c2).regs[r] == c.fr[|c.fr| - 2].regs[r]
  {
    var v := Top(c).regs[0].w;
    assert Reg(Top(c), 0) == W(v);
    StepIns(Pp, x, obsv, c, S.Exit);
    var cP := Pop(c);
    assert cP.fr == c.fr[..|c.fr| - 1];
    assert Top(cP) == c.fr[|c.fr| - 2];
    assert ExitO(x, c) == ExitFrame(x, c, v) by { reveal ExitO(); }
    assert ExitFrame(x, c, v) == Finish(x, cP, W(v), map[]) by { reveal ExitFrame(); }
    FinishFacts(x, cP, W(v), map[]);
    SimFacts.ApplyNone(cP);
    ApplyWAt(cP, map[]);
    var r := Finish(x, cP, W(v), map[]);
    c2 := r.c;
    assert StepR(Pp, x, obsv, c) == r;
    assert ApplyF(Top(cP), |cP.fr| - 1, map[]) == Top(cP);
    assert Below(c2) == Below(cP) == c.fr[..|c.fr| - 2];
    forall k | 0 <= k < NR ensures Top(c2).regs[k].W? {
      if k == 0 { assert Top(c2).regs[0] == W(v); }
      else if k <= 5 { UndW(x, cP, k); assert Top(c2).regs[k] == Und(x, cP, k); }
      else { assert Top(c2).regs[k] == Top(cP).regs[k]; }
    }
    assert FrameOk(Top(c2));
  }

  lemma {:isolate_assertions} ExitW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat)
    returns (rest: seq<bv64>)
    requires PreW(ww, s1, c, s, prefix) && 0 <= s.pc < S.NumInsns(ww.wraw) && fuel > 0
    requires S.Decode(S.InsnAt(ww.wraw, s.pc)) == Some(S.Exit)
    ensures PostW(ww, s1, c, s, prefix, fuel, rest)
  {    BRWE(c, s, ww.wbase);

    var fl := ww.sp.floor;
    AtW(ww, c, s, S.Exit);
    var c2 := WRet(ww.Pp, ww.x, ww.obsv, c);
    var vals := R64(Top(c2))[1..6];
    rest := vals;
    var o := prefix + vals;
    Soundness.RunHalt(ww.wraw, fl, s, o, fuel);
    var sf := S.ReturnW(s1, s, o);
    assert OutW(ww, s1, s, o, fuel) == S.Done(sf);
    var e := S.ERet(s.regs[0]);
    assert sf.events == s.events + [e];
    Soundness.EventsSnoc(s.events, e, ww.s0.stack);
    SideWE(ww, s1, c, s);
    if CountHelpers(s.events) == 0 {
      NoHelperNotFinal(ww, sf);
      return;
    }
    SideW1(ww, s1, c, s);
    WWInit(ww);
    ExitEndW(ww, s1, c, s, prefix, vals, c2, sf);
    EndsWHere(ww, c2, sf);
    EndsWPrefix(ww, c, 1, c2, sf);
  }

  // The state after W's EXIT is the window's end.
  lemma {:isolate_assertions} ExitEndW(ww: WW, s1: S.CState, c: Cfg, s: S.CState, prefix: seq<bv64>, vals: seq<bv64>,
                                       c2: Cfg, sf: S.CState)
    requires 0 < |ww.c0.fr| && |c.fr| == |ww.c0.fr| + 1 && S.CWF(ww.s0) && BR(ww.c0, ww.s0, ww.base)
    requires CallSt(ww, s1) && S.CWF(s) && s.oc == |prefix| && |Top(c).regs| == NR
    requires R64(Top(c))[0] == s.regs[0]
    requires var cf := c.fr[|ww.c0.fr| - 1];
      FrameOk(cf) && Plain(cf.stack) == s.stack && cf.pc == ww.base + s1.pc && R64(cf) == s1.regs
      && cf.kind == Top(ww.c0).kind && cf.fn == Top(ww.c0).fn && cf.stack == StAfter(ww)
    requires c.fr[..|ww.c0.fr| - 1] == Below(ApplyW(ww.c0, ww.hc.wr))
    requires c.L == ApplyL(ww.c0.L, ww.hc.wr) && c.h == ww.c0.h + [ww.hc.eh]
    requires ww.hc.v.W? ==> HelperRet(s.events) == ww.hc.v.w
    requires UpperBase(s.events, ww.s0.stack) == Plain(StAfter(ww))
    requires |c2.fr| == |c.fr| - 1 && Below(c2) == c.fr[..|c.fr| - 2] && c2.L == c.L && c2.h == c.h
    requires var cf := c.fr[|ww.c0.fr| - 1];
      FrameOk(Top(c2)) && Top(c2).pc == cf.pc + 1 && Top(c2).stack == cf.stack
      && Top(c2).kind == cf.kind && Top(c2).fn == cf.fn && Top(c2).regs[0] == Top(c).regs[0]
      && (forall r | 6 <= r < NR :: Top(c2).regs[r] == cf.regs[r])
    requires vals == R64(Top(c2))[1..6] && sf == S.ReturnW(s1, s, prefix + vals)
    ensures EndOk(ww, c2, sf)
  {
    var d := |ww.c0.fr|;
    var cf := c.fr[d - 1];
    var o := prefix + vals;
    forall k | 0 <= k < NR ensures R64(Top(c2))[k] == sf.regs[k] {
      if k == 0 { assert R64(Top(c2))[0] == R64(Top(c))[0]; }
      else if k <= 5 { assert S.Orc(o, s.oc + (k - 1)) == vals[k - 1]; }
      else { assert sf.regs[k] == s1.regs[k] == R64(cf)[k]; }
    }
    assert sf.stack == s.stack == Plain(cf.stack);
    assert BR(c2, sf, ww.base);
    var e := S.ERet(s.regs[0]);
    assert sf.events == s.events + [e];
    Soundness.EventsSnoc(s.events, e, ww.s0.stack);
    reveal EndOk();
  }

  // ---------------- glue, phase WP ----------------

  lemma WPartLen(raw: seq<bv8>)
    requires S.NumInsns(raw) >= 1 && |raw| % 8 == 0
    ensures S.NumInsns(S.WPart(raw)) == S.NumInsns(raw) - 1
  {}

  lemma StuckPostP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    requires WWPre(ww) && S.CWF(s) && 0 <= s.pc < S.NumInsns(S.WPart(ww.raw)) && fuel > 0
    requires S.NumInsns(S.WPart(ww.raw)) == S.NumInsns(ww.raw) - 1
    requires S.Decode(S.InsnAt(S.WPart(ww.raw), s.pc)) == Some(ins) && S.Step(ww.sp.floor, ins, s, prefix) == S.Stuck
    ensures PostP(ww, c, s, prefix, fuel, [])
  {
    assert prefix + [] == prefix;
    Soundness.RunAt(S.WPart(ww.raw), ww.sp.floor, s, prefix, fuel, ins);
  }

  lemma {:isolate_assertions} BadPostP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr, s': S.CState)
    requires WWPre(ww) && S.CWF(s) && 0 <= s.pc < S.NumInsns(S.WPart(ww.raw)) && fuel > 0
    requires S.Decode(S.InsnAt(S.WPart(ww.raw), s.pc)) == Some(ins) && S.Step(ww.sp.floor, ins, s, prefix) == S.Next(s') && S.CWF(s')
    requires |s'.events| > |s.events| && !EventOk(ww.sp, ww.s0, s'.events[|s.events|])
    ensures PostP(ww, c, s, prefix, fuel, [])
  {
    reveal FinalOkO();
    assert prefix + [] == prefix;
    Soundness.RunNext(S.WPart(ww.raw), ww.sp.floor, s, prefix, fuel, ins, s');
    var f1: nat := fuel - 1;
    OutEventsP(ww, s', prefix, f1);
    var O := OutP(ww, s, prefix, fuel);
    assert O == OutP(ww, s', prefix, f1);
    if O.Done? {
      assert O.s.events[|s.events|] == s'.events[|s.events|];
    }
  }

  lemma AdvPPost(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr, vals: seq<bv64>,
                 k: nat, c': Cfg, s': S.CState, rest': seq<bv64>)
    requires WWPre(ww) && S.CWF(s) && S.CWF(s') && fuel > 0 && 0 <= s.pc < S.NumInsns(S.WPart(ww.raw))
    requires S.Decode(S.InsnAt(S.WPart(ww.raw), s.pc)) == Some(ins)
    requires s.oc + Need(ww.sp.floor, ins, s) <= |prefix + vals|
    requires S.Step(ww.sp.floor, ins, s, prefix + vals) == S.Next(s')
    requires ReachR(ww.Pp, ww.x, ww.obsv, c, k) == Some(c')
    requires PostP(ww, c', s', prefix + vals, fuel - 1, rest')
    ensures PostP(ww, c, s, prefix, fuel, vals + rest')
  {
    RunAdv(S.WPart(ww.raw), ww.sp.floor, s, prefix, fuel, ins, vals, s', rest');
    var O := OutP(ww, s, prefix + (vals + rest'), fuel);
    assert O == OutP(ww, s', (prefix + vals) + rest', fuel - 1);
    if O.Done? && FinalOkO(ww.sp, ww.s0, O.s) { EndsWPrefix(ww, c, k, c', O.s); }
  }

  lemma AdvP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr,
             vals: seq<bv64>, k: nat, c': Cfg, s': S.CState) returns (rest: seq<bv64>)
    requires PreP(ww, c, s, prefix) && 0 <= s.pc < S.NumInsns(S.WPart(ww.raw)) && fuel > 0
    requires S.Decode(S.InsnAt(S.WPart(ww.raw), s.pc)) == Some(ins)
    requires s.oc + Need(ww.sp.floor, ins, s) <= |prefix + vals|
    requires S.Step(ww.sp.floor, ins, s, prefix + vals) == S.Next(s')
    requires ReachR(ww.Pp, ww.x, ww.obsv, c, k) == Some(c') && PreP(ww, c', s', prefix + vals)
    ensures PostP(ww, c, s, prefix, fuel, rest)
    decreases fuel, 0
  {
    var rest' := BridgeP(ww, c', s', prefix + vals, fuel - 1);
    rest := vals + rest';
    AdvPPost(ww, c, s, prefix, fuel, ins, vals, k, c', s', rest');
  }

  lemma PreKeepP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, c': Cfg, s': S.CState, vals: seq<bv64>)
    requires PreP(ww, c, s, prefix) && BR(c', s', ww.base) && TopOnly(c, c')
    requires s'.events == s.events && s'.oc == s.oc + |vals|
    ensures PreP(ww, c', s', prefix + vals)
  {
    SidePE(ww, c, s);
    SidePI(ww, c', s');
  }

  // ---------------- the bridge, phase WP ----------------

  lemma BridgeP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat) returns (rest: seq<bv64>)
    requires PreP(ww, c, s, prefix)
    ensures PostP(ww, c, s, prefix, fuel, rest)
    decreases fuel, 3
  {
    var n := S.NumInsns(ww.raw);
    var wp := S.WPart(ww.raw);
    var fl := ww.sp.floor;
    WPartLen(ww.raw);
    rest := [];
    assert prefix + rest == prefix;
    SidePE(ww, c, s);
    if s.pc == n - 1 {
      rest := CallWStep(ww, c, s, prefix, fuel);
      return;
    }
    if s.pc < 0 || s.pc > n - 1 || fuel == 0 {
      reveal S.Run();
      NoHelperNotFinal(ww, s);
      return;
    }
    match S.Decode(S.InsnAt(wp, s.pc))
    case None =>
      reveal S.Run();
    case Some(ins) =>
      rest := BInsP(ww, c, s, prefix, fuel, ins);
  }

  ghost predicate AtP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr) {
    PreP(ww, c, s, prefix) && 0 <= s.pc < S.NumInsns(ww.raw) - 1 && fuel > 0
    && S.NumInsns(S.WPart(ww.raw)) == S.NumInsns(ww.raw) - 1
    && S.Decode(S.InsnAt(S.WPart(ww.raw), s.pc)) == Some(ins) && AtIns(ww.Pp, c, ins)
  }

  lemma {:isolate_assertions} BInsP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    returns (rest: seq<bv64>)
    requires PreP(ww, c, s, prefix) && 0 <= s.pc < S.NumInsns(ww.raw) - 1 && fuel > 0
    requires S.Decode(S.InsnAt(S.WPart(ww.raw), s.pc)) == Some(ins)
    ensures PostP(ww, c, s, prefix, fuel, rest)
    decreases fuel, 2
  {
    Soundness.WPartInsn(ww.raw, s.pc);
    WWStat(ww);
    assert S.Writes(ins) <= {4};
    WWAtP(ww, s.pc);
    assert AtIns(ww.Pp, c, ins);
    assert AtP(ww, c, s, prefix, fuel, ins);
    rest := [];
    match ins
    case Alu(_, _, _, _) => rest := BAluP(ww, c, s, prefix, fuel, ins);
    case Ja(_) => rest := BJaP(ww, c, s, prefix, fuel, ins);
    case Jcond(_, _, _, _) => rest := BJcondP(ww, c, s, prefix, fuel, ins);
    case Ldx(wd, dst, rb, off) => rest := BLdxP(ww, c, s, prefix, fuel, wd, dst, rb, off);
    case Stx(_, _, _, _) => BStP(ww, c, s, prefix, fuel, ins);
    case St(_, _, _, _) => BStP(ww, c, s, prefix, fuel, ins);
    case CallHelper(_) => assert false;
    case CallLocal(_) => assert false;
    case Exit => BExitP(ww, c, s, prefix, fuel);
  }

  lemma {:isolate_assertions} BAluP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    returns (rest: seq<bv64>)
    requires AtP(ww, c, s, prefix, fuel, ins) && ins.Alu?
    ensures PostP(ww, c, s, prefix, fuel, rest)
    decreases fuel, 1
  {
    var fl := ww.sp.floor;
    rest := [];
    if ins.dst >= 10 {
      assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
      StuckPostP(ww, c, s, prefix, fuel, ins);
    } else {
      AluSim(c, s, ww.base, fl, ins.is64, ins.op, ins.dst, ins.opnd, prefix);
      var r := IAlu(c, ins.is64, ins.op, ins.dst, ins.opnd);
      StepIns(ww.Pp, ww.x, ww.obsv, c, ins);
      ReachOne(ww.Pp, ww.x, ww.obsv, c, r.c);
      var s' := S.Step(fl, ins, s, prefix).s;
      assert prefix + [] == prefix;
      PreKeepP(ww, c, s, prefix, r.c, s', []);
      rest := AdvP(ww, c, s, prefix, fuel, ins, [], 1, r.c, s');
    }
  }

  lemma {:isolate_assertions} BJaP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    returns (rest: seq<bv64>)
    requires AtP(ww, c, s, prefix, fuel, ins) && ins.Ja?
    ensures PostP(ww, c, s, prefix, fuel, rest)
    decreases fuel, 1
  {
    var fl := ww.sp.floor;
    JaSim(c, s, ww.base, fl, ins.off, prefix);
    var c' := Put(c, Top(c).(pc := Top(c).pc + 1 + Signed16(ins.off)));
    StepIns(ww.Pp, ww.x, ww.obsv, c, ins);
    ReachOne(ww.Pp, ww.x, ww.obsv, c, c');
    var s' := S.Step(fl, ins, s, prefix).s;
    assert prefix + [] == prefix;
    PreKeepP(ww, c, s, prefix, c', s', []);
    rest := AdvP(ww, c, s, prefix, fuel, ins, [], 1, c', s');
  }

  lemma {:isolate_assertions} BJcondP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    returns (rest: seq<bv64>)
    requires AtP(ww, c, s, prefix, fuel, ins) && ins.Jcond?
    ensures PostP(ww, c, s, prefix, fuel, rest)
    decreases fuel, 1
  {
    var fl := ww.sp.floor;
    rest := [];
    if ins.dst > 10 {
      assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
      StuckPostP(ww, c, s, prefix, fuel, ins);
    } else {
      JcondSim(c, s, ww.base, fl, ins.cond, ins.dst, ins.imm, ins.off, prefix);
      var r := IJcond(c, ins.cond, ins.dst, ins.imm, ins.off);
      StepIns(ww.Pp, ww.x, ww.obsv, c, ins);
      ReachOne(ww.Pp, ww.x, ww.obsv, c, r.c);
      var s' := S.Step(fl, ins, s, prefix).s;
      assert prefix + [] == prefix;
      PreKeepP(ww, c, s, prefix, r.c, s', []);
      rest := AdvP(ww, c, s, prefix, fuel, ins, [], 1, r.c, s');
    }
  }

  // A store in WP: a bad event (no store in a P8 window), or stuck.
  lemma {:isolate_assertions} BStP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    requires AtP(ww, c, s, prefix, fuel, ins) && (ins.Stx? || ins.St?)
    ensures PostP(ww, c, s, prefix, fuel, [])
  {
    var fl := ww.sp.floor;
    match ins
    case Stx(wd, rb, src, off) =>
      if rb > 10 || src > 10 || wd > 8 {
        assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
        StuckPostP(ww, c, s, prefix, fuel, ins);
      } else {
        StepStx(fl, wd, rb, src, off, s, prefix);
        var s' := S.StoreStep(s, s.regs[rb] + Sext16(off), wd, s.regs[src]).s;
        assert s'.events[|s.events|] == S.EStore(s.regs[rb] + Sext16(off), wd);
        BadPostP(ww, c, s, prefix, fuel, ins, s');
      }
    case St(wd, rb, off, imm) =>
      if rb > 10 || wd > 8 {
        assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
        StuckPostP(ww, c, s, prefix, fuel, ins);
      } else {
        StepSt(fl, wd, rb, off, imm, s, prefix);
        var s' := S.StoreStep(s, s.regs[rb] + Sext16(off), wd, Sext32(imm)).s;
        assert s'.events[|s.events|] == S.EStore(s.regs[rb] + Sext16(off), wd);
        BadPostP(ww, c, s, prefix, fuel, ins, s');
      }
  }

  // EXIT in WP: the window run exits, which the obligations of a P8 window exclude.
  lemma BExitP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat)
    requires AtP(ww, c, s, prefix, fuel, S.Exit)
    ensures PostP(ww, c, s, prefix, fuel, [])
  {
    StepExit(ww.sp.floor, s, prefix);
    Soundness.RunAt(S.WPart(ww.raw), ww.sp.floor, s, prefix, fuel, S.Exit);
    assert prefix + [] == prefix;
  }

  lemma {:isolate_assertions} BLdxP(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat,
                                    wd: nat, dst: nat, rb: nat, off: bv16) returns (rest: seq<bv64>)
    requires PreP(ww, c, s, prefix) && 0 <= s.pc < S.NumInsns(ww.raw) - 1 && fuel > 0
    requires S.Decode(S.InsnAt(S.WPart(ww.raw), s.pc)) == Some(S.Ldx(wd, dst, rb, off))
    requires AtIns(ww.Pp, c, S.Ldx(wd, dst, rb, off))
    ensures PostP(ww, c, s, prefix, fuel, rest)
    decreases fuel, 1
  {
    var fl := ww.sp.floor;
    var ins := S.Ldx(wd, dst, rb, off);
    WPartLen(ww.raw);
    DecodeWidth(S.InsnAt(S.WPart(ww.raw), s.pc));
    rest := [];
    if dst >= 10 || rb > 10 {
      assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
      StuckPostP(ww, c, s, prefix, fuel, ins);
      return;
    }
    var a := s.regs[rb] + Sext16(off);
    var inF := S.InFrame(S.Rel(a, s.regs[10]), wd);
    var vals: seq<bv64> := if inF then [] else [LoadedW(ww.x, c, a, wd)];
    assert !inF ==> S.Orc(prefix + vals, s.oc) == LoadedW(ww.x, c, a, wd);
    LdxSim(ww.x, c, s, ww.base, fl, wd, dst, rb, off, prefix + vals);
    var r := ILdx(ww.x, c, wd, dst, rb, off);
    StepIns(ww.Pp, ww.x, ww.obsv, c, ins);
    ReachOne(ww.Pp, ww.x, ww.obsv, c, r.c);
    var s' := S.Step(fl, ins, s, prefix + vals).s;
    PreKeepP(ww, c, s, prefix, r.c, s', vals);
    NeedLdx(fl, wd, dst, rb, off, s);
    rest := AdvP(ww, c, s, prefix, fuel, ins, vals, 1, r.c, s');
  }

  // ---------------- call W ----------------

  // The call at kappa(i) pushes W's frame (the observer, if W's entry is
  // also a hook entry, changes only its own state).
  lemma {:isolate_assertions} WEnter(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, imm: bv32) returns (cW: Cfg)
    requires x.m.MR? && A5(obsv) && 0 < |c.fr| < MAXF_RW && FrameOk(Top(c)) && AtIns(Pp, c, S.CallLocal(imm))
    requires Top(c).pc + 1 + Signed32(imm) >= 0
    ensures ReachR(Pp, x, obsv, c, 1) == Some(cW)
    ensures |cW.fr| == |c.fr| + 1 && Below(cW) == c.fr && cW.L == c.L && cW.h == c.h
    ensures FrameOk(Top(cW)) && Top(cW).pc == Top(c).pc + 1 + Signed32(imm) && Top(cW).kind == Ins
    ensures forall k | 1 <= k <= 5 :: Top(cW).regs[k] == Top(c).regs[k]
  {
    var f := Top(c);
    var t := f.pc + 1 + Signed32(imm);
    var args := seq(5, k requires 0 <= k < 5 => Reg(f, k + 1));
    reveal Push(), ICall();
    var c1 := Push(x, c, t, t, Ins, args).c;
    assert Push(x, c, t, t, Ins, args).Go?;
    StepIns(Pp, x, obsv, c, S.CallLocal(imm));
    cW := if t in Pp.hooks then obsv(c1, R64(f)[1..6]) else c1;
    assert ICall(x, Pp.hooks, obsv, c, imm) == Go(cW);
    assert cW == c1.(os := cW.os);
    assert Top(cW) == Top(c1);
    var st := seq(STK, i requires 0 <= i < STK => UndB(x, c, NR + i));
    assert Top(c1).stack == st;
    forall o | 0 <= o < STK ensures st[o].B? { assert st[o] == UndB(x, c, NR + o); assert !x.m.MP?; }
    forall k | 1 <= k <= 5 ensures Top(cW).regs[k] == Top(c).regs[k] { assert args[k - 1] == Reg(f, k); }
  }

  lemma EnterWLocal(s: S.CState, o1: seq<bv64>, o2: seq<bv64>)
    requires S.CWF(s) && SameUpTo(o1, o2, s.oc + 5)
    ensures S.EnterW(s, o1) == S.EnterW(s, o2)
  {
    var r1 := S.EnterW(s, o1).regs;
    var r2 := S.EnterW(s, o2).regs;
    forall k | 0 <= k < S.NREGS ensures r1[k] == r2[k] {}
    assert r1 == r2;
  }

  lemma {:isolate_assertions} EnterWRegs(s: S.CState, prefix: seq<bv64>, f: Frame, f1: Frame)
    requires S.CWF(s) && s.oc == |prefix| && FrameOk(f) && FrameOk(f1) && R64(f1) == s.regs
    requires forall k | 1 <= k <= 5 :: f.regs[k] == f1.regs[k]
    ensures var vals := [R64(f)[0], R64(f)[6], R64(f)[7], R64(f)[8], R64(f)[9]];
      var sW := S.EnterW(s, prefix + vals);
      S.CWF(sW) && sW.pc == 0 && sW.oc == |prefix + vals| && sW.stack == s.stack && sW.regs[10] == s.regs[10]
      && (forall k | 0 <= k < 10 :: R64(f)[k] == sW.regs[k])
      && sW.events == s.events + [S.ECallW(s.regs)]
  {
    var vals := [R64(f)[0], R64(f)[6], R64(f)[7], R64(f)[8], R64(f)[9]];
    var o := prefix + vals;
    var sW := S.EnterW(s, o);
    forall k | 0 <= k < 10 ensures R64(f)[k] == sW.regs[k] {
      if 1 <= k <= 5 { assert sW.regs[k] == s.regs[k] == R64(f1)[k]; }
      else if k == 0 { assert S.Orc(o, s.oc) == vals[0]; }
      else { assert S.Orc(o, s.oc + (k - 5)) == vals[k - 5]; }
    }
  }

  // At the end of WP the rest of the window run is call W and W's body.
  lemma {:isolate_assertions} CallWOut(ww: WW, s: S.CState, o: seq<bv64>, fuel: nat, sW: S.CState)
    requires WWPre(ww) && S.CWF(s) && s.pc == S.NumInsns(ww.raw) - 1 && S.EnterW(s, o) == sW
    ensures OutP(ww, s, o, fuel) == OutW(ww, s, sW, o, ww.F)
  {
    WPartLen(ww.raw);
    WWCall(ww);
    Soundness.RunEnd(S.WPart(ww.raw), ww.sp.floor, s, o, fuel);
    var n := S.NumInsns(ww.raw);
    assert S.Decode(S.InsnAt(ww.raw, n - 1)).value.CallLocal?;
  }

  lemma {:isolate_assertions} AtCallW(ww: WW, c: Cfg, s: S.CState) returns (imm: bv32)
    requires WWPre(ww) && BR(c, s, ww.base) && s.pc == S.NumInsns(ww.raw) - 1
    ensures AtIns(ww.Pp, c, S.CallLocal(imm)) && Top(c).pc + 1 + Signed32(imm) == ww.wbase
  {
    var n := S.NumInsns(ww.raw);
    var pc := Top(c).pc;
    assert pc == ww.base + (n - 1);
    var b := CallWBytes(ww);
    imm := S.Decode(b).value.imm;
    AtCode(ww.Pp, c, pc, b, S.CallLocal(imm));
  }

  // The bytes of call W at kappa(i).
  lemma CallWBytes(ww: WW) returns (b: seq<bv8>)
    requires WWPre(ww)
    ensures var n := S.NumInsns(ww.raw);
      0 <= ww.base + (n - 1) < |ww.Pp.code| && ww.Pp.code[ww.base + (n - 1)] == N(b) && |b| == 8
      && S.Decode(b).Some? && S.Decode(b).value.CallLocal? && ww.base + n + Signed32(S.Decode(b).value.imm) == ww.wbase
  {
    var n := S.NumInsns(ww.raw);
    WWCall(ww); WWAtP(ww, n - 1);
    b := S.InsnAt(ww.raw, n - 1);
  }

  lemma AtCode(Pp: RwProg, c: Cfg, pc: int, b: seq<bv8>, ins: S.Instr)
    requires Top(c).pc == pc && 0 <= pc < |Pp.code| && Pp.code[pc] == N(b) && |b| == 8 && S.Decode(b) == Some(ins)
    ensures AtIns(Pp, c, ins)
  {}

  lemma {:isolate_assertions} CallWStep(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat) returns (rest: seq<bv64>)
    requires PreP(ww, c, s, prefix) && s.pc == S.NumInsns(ww.raw) - 1
    ensures PostP(ww, c, s, prefix, fuel, rest)
  {

    var n := S.NumInsns(ww.raw);
    var fl := ww.sp.floor;
    var wp := S.WPart(ww.raw);
    WPartLen(ww.raw);
    WWCall(ww); WWAtP(ww, n - 1); WWInit(ww);
    SidePE(ww, c, s);
    var imm := AtCallW(ww, c, s);
    WWAtWBase(ww);
    WWA5(ww);
    var cW := WEnter(ww.Pp, ww.x, ww.obsv, c, imm);
    var f := Top(cW);
    var vals := [R64(f)[0], R64(f)[6], R64(f)[7], R64(f)[8], R64(f)[9]];
    EnterWRegs(s, prefix, f, Top(c));
    var sW := S.EnterW(s, prefix + vals);
    assert cW.fr[|cW.fr| - 2] == Top(c);
    BRWIntro(cW, sW, ww.wbase);
    assert CallSt(ww, s);
    Soundness.EventsSnoc(s.events, S.ECallW(s.regs), ww.s0.stack);
    var d := |ww.c0.fr|;
    assert cW.fr[..d - 1] == Below(c);
    assert cW.fr[d - 1] == Top(c);
    reveal SideW();
    assert SideW(ww, s, cW, sW);
    var restW := BridgeW(ww, s, cW, sW, prefix + vals, ww.F);
    rest := vals + restW;
    CallWPost(ww, c, s, prefix, fuel, vals, cW, sW, restW);
  }

  // The window's run from call W is W's run: PostW at W's entry gives PostP at call W.
  lemma {:isolate_assertions} CallWPost(ww: WW, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, vals: seq<bv64>,
                                        cW: Cfg, sW: S.CState, restW: seq<bv64>)
    requires WWPre(ww) && S.CWF(s) && S.CWF(sW) && s.pc == S.NumInsns(ww.raw) - 1 && s.oc == |prefix| && |vals| == 5
    requires sW == S.EnterW(s, prefix + vals)
    requires ReachR(ww.Pp, ww.x, ww.obsv, c, 1) == Some(cW)
    requires PostW(ww, s, cW, sW, prefix + vals, ww.F, restW)
    ensures PostP(ww, c, s, prefix, fuel, vals + restW)
  {
    var o := prefix + (vals + restW);
    SeqAssoc(prefix, vals, restW);
    assert SameUpTo(o, prefix + vals, s.oc + 5);
    EnterWLocal(s, o, prefix + vals);
    CallWOut(ww, s, o, fuel, sW);
    var O := OutP(ww, s, o, fuel);
    if O.Done? && FinalOkO(ww.sp, ww.s0, O.s) {
      EndsWPrefix(ww, c, 1, cW, O.s);
    }
  }

  lemma SeqAssoc(a: seq<bv64>, b: seq<bv64>, c: seq<bv64>) ensures a + (b + c) == (a + b) + c {}

  lemma WWAtWBase(ww: WW) requires WWPre(ww) ensures 0 <= ww.wbase { reveal WWPreO(); }

  // ================= the step of P at a wrapped helper =================

  // A validated P8 window is WP . call W with W's instructions checked (its
  // obligations hold for every run, so its static part holds).
  lemma WrapStaticOf(raw: seq<bv8>, sp: Spec)
    requires Checker.Validate(raw, sp) == Checker.Validated && sp.wrap.Wrap?
    ensures SpecWF(sp) && WrapStatic(raw, sp)
  {
    var regs := seq(S.NREGS, _ => 0 as bv64);
    var stack := seq(S.STACK, _ => 0 as bv8);
    var fuel := S.NumInsns(raw) + WrapLen(sp) + 1;
    Soundness.Soundness(raw, sp, regs, stack, [], fuel);
  }

  lemma {:isolate_assertions} WrapRawAt(wp: seq<bv8>, cw: seq<bv8>, r: nat)
    requires |wp| % 8 == 0 && |cw| == 8 && r < NI(wp) + 1
    ensures |wp + cw| % 8 == 0 && S.NumInsns(wp + cw) == NI(wp) + 1
    ensures S.InsnAt(wp + cw, r) == if r < NI(wp) then Slice(wp, r) else cw
  {
    assert wp + cw == wp + cw + [];
    RawAt(wp, cw, [], r);
  }

  // The offset of call W fits in 32 bits (Loadable).
  lemma WrapNear(P: seq<OInstr>, D: Decomp, j: nat)
    requires Loadable(P, D) && PiecesOk(P, D) && j in D.wrap && j !in D.pl && j < |P|
    ensures -0x8000_0000 <= WStart(P, D, j) - K(D, j) - 1 < 0x8000_0000
    ensures K(D, j) < |Layout(P, D).code| && WStart(P, D, j) + NI(D.wrap[j].body) <= |Layout(P, D).code|
  {
    AllFnsWFOk(P, D);
    WrapCode(P, D, j);
    var k := WPlaced(P, D, j);
  }

  ghost function WrapWin(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, xR: Ctx, obsv: Observer,
                         j: nat, c': Cfg, hc: HCtx): WW
    requires j in D.wrap && j < |P|
  {
    var wr := D.wrap[j];
    var raw := wr.wp + EncCallLocal(WStart(P, D, j) - K(D, j) - 1);
    var sp := Api.WithBinds(Api.WrapSiteSpec(Fl(P, ell, j), wr.body, Enc(P[j])), wr.binds);
    WW(Pp, xR, obsv, raw, wr.body, sp, E(D, j), WStart(P, D, j), P[j], j, hc, c',
       S.InitState(R64(Top(c')), Plain(Top(c').stack)), S.NumInsns(raw) + WrapLen(sp) + 1)
  }

  // The code facts of a wrapper window.
  // One slot of WP . call W in P'.
  lemma {:isolate_assertions} WPSlot(Pp: RwProg, raw: seq<bv8>, wp: seq<bv8>, cw: seq<bv8>, base: int, kap: int, r: nat)
    requires raw == wp + cw && |wp| % 8 == 0 && |cw| == 8 && r < NI(wp) + 1 && kap == base + NI(wp)
    requires forall q | 0 <= q < NI(wp) :: SimCalls.PlacedAt(Pp, base, wp, q)
    requires 0 <= kap < |Pp.code| && Pp.code[kap] == N(cw)
    ensures 0 <= base + r < |Pp.code| && Pp.code[base + r] == N(S.InsnAt(raw, r))
  {
    WrapRawAt(wp, cw, r);
    if r < NI(wp) { assert SimCalls.PlacedAt(Pp, base, wp, r); }
  }

  lemma {:isolate_assertions} WrapWinCode(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                          tbl: bv32 -> set<nat>, ww: WW, j: nat)
    requires ww.Pp == Layout(P, D) && PiecesOk(P, D) && CallsOk(D, ww.Pp) && Loadable(P, D)
    requires j in D.wrap && j < |P|
    requires ww.raw == D.wrap[j].wp + EncCallLocal(WStart(P, D, j) - K(D, j) - 1) && ww.wraw == D.wrap[j].body
    requires ww.base == E(D, j) && ww.wbase == WStart(P, D, j) && ww.hins == P[j] && ww.hidx == j
    ensures |ww.raw| % 8 == 0 && S.NumInsns(ww.raw) == NI(D.wrap[j].wp) + 1
    ensures 0 <= ww.base && ww.base + S.NumInsns(ww.raw) <= |ww.Pp.code|
    ensures forall r | 0 <= r < S.NumInsns(ww.raw) :: ww.Pp.code[ww.base + r] == N(S.InsnAt(ww.raw, r))
    ensures CallWAt(ww) && 0 <= ww.wbase
    ensures forall r | 0 <= r < S.NumInsns(ww.wraw) :: WCodeAt(ww, r)
    ensures ww.base + S.NumInsns(ww.raw) == K(D, j) + 1
  {
    var wr := D.wrap[j];
    assert j !in D.pl;
    AllFnsWFOk(P, D);
    WrapCode(P, D, j);
    WrapNear(P, D, j);
    var v := WStart(P, D, j) - K(D, j) - 1;
    DecodeCallW(v);
    var cw := EncCallLocal(v);
    var n := NI(wr.wp) + 1;
    WrapRawAt(wr.wp, cw, 0);
    forall r | 0 <= r < n ensures ww.Pp.code[ww.base + r] == N(S.InsnAt(ww.raw, r)) {
      WPSlot(ww.Pp, ww.raw, wr.wp, cw, ww.base, K(D, j), r);
    }
    WrapRawAt(wr.wp, cw, n - 1);
    assert S.InsnAt(ww.raw, n - 1) == cw;
    assert CallWAt(ww);
    var k := WPlaced(P, D, j);
    forall r | 0 <= r < S.NumInsns(ww.wraw) ensures WCodeAt(ww, r) {
      WCodeOne(P, D, ww, j, k, r);
    }
  }

  lemma {:isolate_assertions} WCodeOne(P: seq<OInstr>, D: Decomp, ww: WW, j: nat, k: nat, r: nat)
    requires ww.Pp == Layout(P, D) && PiecesOk(P, D) && CallsOk(D, ww.Pp)
    requires j in D.wrap && j < |P| && ww.wraw == D.wrap[j].body && ww.wbase == WStart(P, D, j)
    requires ww.hins == P[j] && ww.hidx == j
    requires k < |AllFns(P, D)| && AllFns(P, D)[k] == (WrapFn(j), WStart(P, D, j))
    requires forall r | 0 <= r < NI(D.wrap[j].body) :: WAt(P, D, j, r)
    requires r < S.NumInsns(ww.wraw)
    ensures WCodeAt(ww, r)
  {
    assert WAt(P, D, j, r);
    assert S.InsnAt(ww.wraw, r) == Slice(D.wrap[j].body, r);
    var p := ww.wbase + r;
    var b := S.InsnAt(ww.wraw, r);
    if S.Decode(b).Some? && S.Decode(b).value.CallLocal? {
      assert ww.Pp.code[p] == N(b);
      WNotK(P, D, j, k, r);
      assert p + 1 + Signed32(S.Decode(b).value.imm) in ww.Pp.hooks;
    }
  }

  lemma {:isolate_assertions} WrapHelperOk(P: seq<OInstr>, ell: nat -> int, ww: WW, c: Cfg, xP: Ctx, tbl: bv32 -> set<nat>,
                                           n: nat, args: seq<bv64>, beta: seq<bv8>, v: Val, wr: map<int, bv8>)
    requires 0 < |c.fr| <= MAXF && Top(c) == c.fr[|c.fr| - 1]
    requires |ww.c0.fr| == |c.fr| && ww.c0.h == c.h && A8(xP.om)
    requires ww.hins.Hcall? && !ww.hins.kf && IsLookup(ww.hins.id) && ww.x.env == xP.env && ww.x.om == xP.om
    requires A3b(xP.env, tbl)
    requires n == xP.env.arity(false, ww.hins.id)
    requires SimFacts.Words(Top(ww.c0), Upto(1, n)) == args
    requires FootBytes(ww.c0, xP.env.foot(false, ww.hins.id, args)) == FOk(beta)
    requires xP.om(c.h, ECall(ww.hidx, false, ww.hins.id, args, beta), Wh(c)) == RRet(v, wr)
    requires ww.hc == HCtx(n, xP.env.foot(false, ww.hins.id, args), ECall(ww.hidx, false, ww.hins.id, args, beta), v, wr)
    requires forall o: nat {:nowarn} | o < STK && o as int - STK as int < ell(Top(c).fn) :: SAddr(|c.fr| - 1, o) as int !in wr
    requires ww.sp.floor <= ell(Top(c).fn)
    ensures HelperOkW(ww)
  {
    assert xP.om(c.h, ww.hc.eh, Wh(ww.c0)) == xP.om(c.h, ww.hc.eh, Wh(c));
    assert WrTop(ww.c0, wr, ww.sp.floor);
  }

  // The code facts of a wrapper window, bundled.
  ghost predicate WWCodeOk(ww: WW) {
    |ww.raw| % 8 == 0 && S.NumInsns(ww.raw) >= 1
    && 0 <= ww.base && ww.base + S.NumInsns(ww.raw) <= |ww.Pp.code|
    && (forall r | 0 <= r < S.NumInsns(ww.raw) :: ww.Pp.code[ww.base + r] == N(S.InsnAt(ww.raw, r)))
    && CallWAt(ww) && 0 <= ww.wbase
    && (forall r | 0 <= r < S.NumInsns(ww.wraw) :: WCodeAt(ww, r))
    && HooksOk(ww.Pp)
  }

  lemma {:isolate_assertions} WrapWinPre(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                                         tbl: bv32 -> set<nat>, xR: Ctx, obsv: Observer, j: nat, c': Cfg, hc: HCtx)
    requires Structure(P, D, Pp, ell, live, tbl) && Loadable(P, D) && AllValidated(P, D, ell)
    requires j in D.wrap && j < |P|
    ensures var ww := WrapWin(P, D, Pp, ell, xR, obsv, j, c', hc);
      Checker.Validate(ww.raw, ww.sp) == Checker.Validated && SpecWF(ww.sp) && WrapStatic(ww.raw, ww.sp)
      && WWCodeOk(ww) && ww.base + S.NumInsns(ww.raw) == K(D, j) + 1
      && ww.sp.floor == Fl(P, ell, j) && ww.sp.wrap.Wrap? && ww.sp.wrap.body == ww.wraw
      && ww.sp.helper == Helper(false, true) && !ww.sp.allowStore && ww.sp.hookCalls
      && ww.F == S.NumInsns(ww.raw) + WrapLen(ww.sp) + 1 && ww.hins == P[j] && ww.hidx == j && ww.hc == hc && ww.c0 == c'
      && ww.Pp == Pp && ww.x == xR && ww.obsv == obsv && ww.base == E(D, j)
      && ww.s0 == S.InitState(R64(Top(c')), Plain(Top(c').stack))
  {
    var ww := WrapWin(P, D, Pp, ell, xR, obsv, j, c', hc);
    assert Pp == Layout(P, D) && PiecesOk(P, D) && CallsOk(D, Pp);
    assert Valid(ww.raw, ww.sp);
    assert Checker.Validate(ww.raw, ww.sp) == Checker.Validated by { reveal Valid(); }
    WrapStaticOf(ww.raw, ww.sp);
    WrapWinCode(P, D, ell, live, tbl, ww, j);
    HooksOkLayout(P, D, ell);
  }

  lemma WWPreIntro(ww: WW)
    requires WWBasic(ww) && A5(ww.obsv) && A8(ww.x.om) && SpecWF(ww.sp) && WrapStatic(ww.raw, ww.sp)
    requires WWCodeOk(ww) && HelperOkW(ww)
    requires 0 < |ww.c0.fr| <= MAXF && BR(ww.c0, ww.s0, ww.base) && ww.s0 == S.InitState(ww.s0.regs, ww.s0.stack)
    ensures WWPre(ww)
  { reveal WWPreO(); }

  // The window from its entry to its end.
  lemma {:isolate_assertions} RunWrapWin(ww: WW) returns (k: nat, c2: Cfg, sf: S.CState)
    requires WWPre(ww) && Checker.Validate(ww.raw, ww.sp) == Checker.Validated
    requires ww.F == S.NumInsns(ww.raw) + WrapLen(ww.sp) + 1
    ensures ReachR(ww.Pp, ww.x, ww.obsv, ww.c0, k) == Some(c2)
    ensures EndOk(ww, c2, sf) && FinalOk(ww.sp, ww.s0, sf)
  {
    WWInit(ww);
    WWSpec(ww);
    var s0 := ww.s0;
    assert S.CWF(s0);
    SidePI(ww, ww.c0, s0);
    assert PreP(ww, ww.c0, s0, []);
    var rest := BridgeP(ww, ww.c0, s0, [], ww.F);
    Soundness.Soundness(ww.raw, ww.sp, s0.regs, s0.stack, rest, ww.F);
    assert [] + rest == rest;
    var O := OutP(ww, s0, rest, ww.F);
    assert WindowRun(ww.raw, ww.sp, S.InitState(s0.regs, s0.stack), rest, ww.F) == O;
    assert O.Done? && FinalOk(ww.sp, s0, O.s);
    assert FinalOkO(ww.sp, s0, O.s) by { reveal FinalOkO(); }
    k, c2 := EndsWGet(ww, ww.c0, O.s);
    sf := O.s;
  }

  // The configurations after a wrapper window and after the helper step of P are related.
  lemma {:isolate_assertions} WrapAfter(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
      ww: WW, c: Cfg, er: set<nat>, c1: Cfg, c2: Cfg, sf: S.CState, j: nat, xP: Ctx)
    requires xP.m.MP?
    requires Inv(P, c) && Corr(P, D, ell, live, c, ww.c0, er) && Top(c).pc == j
    requires WWBasic(ww) && ww.sp.floor == Fl(P, ell, Top(c).fn)
    requires ww.s0 == S.InitState(R64(Top(ww.c0)), Plain(Top(ww.c0).stack))
    requires ww.base + S.NumInsns(ww.raw) == E(D, j + 1) && j + 1 < |P| && Owner(P, j + 1) == Top(c).fn
    requires Finish(xP, c.(h := c.h + [ww.hc.eh]), ww.hc.v, ww.hc.wr) == Go(c1)
    requires EndOk(ww, c2, sf) && FinalOk(ww.sp, ww.s0, sf)
    ensures Inv(P, c1) && Corr(P, D, ell, live, c1, c2, {})
  {
    var c0 := ww.c0;
    var wr := ww.hc.wr;
    var v := ww.hc.v;
    CorrElim(P, D, ell, live, c, c0, er);
    InvIs(P, c);
    LowRelLen(P, D, ell, c, c0);
    var n := |c.fr|;
    var ch := c.(h := c.h + [ww.hc.eh]);
    FinishFacts(xP, ch, v, wr);
    EndOkE(ww, c2, sf);
    WrapAfterFrames(P, D, ell, c, c0, ch, v, wr, c1, c2, j, xP);
    assert Top(c) == c.fr[n - 1] && Top(c0) == c0.fr[n - 1];
    ApplyTop(c0, wr);
    ApplyTop(ch, wr);
    assert forall r | 1 <= r <= 5 :: Top(c1).regs[r] == Und(xP, ch, r) == Bot;
    FinalFacts(ww.sp, ww.s0, sf);
    assert R0Special(ww.sp);
    assert v.W? ==> sf.regs[0] == v.w;
    SiteAfterRegs(c, c0, c1, c2, sf, ww.s0, v, er, live(j));
    assert RegRel(c1, c2, {}, live(Top(c1).pc));
    assert Top(c1).stack == ApplyF(Top(c), n - 1, wr).stack;
    SiteAfterStack(c, c0, c1, c2, sf, ww.s0, wr, ww.sp.floor, n - 1);
    assert c2.L == c1.L && c2.h == c1.h;
    assert Top(c1).pc == j + 1 && Top(c2).pc == ww.base + sf.pc;
    assert TopRel(P, D, ell, live, c1, c2, {});
    CorrIntro(P, D, ell, live, c1, c2, {});
  }

  lemma {:isolate_assertions} WrapAfterFrames(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c0: Cfg, ch: Cfg,
                                              v: Val, wr: map<int, bv8>, c1: Cfg, c2: Cfg, j: nat, xP: Ctx)
    requires Inv(P, c) && LowRel(P, D, ell, c, c0) && ch.fr == c.fr && Top(c).pc == j
    requires j + 1 < |P| && Owner(P, j + 1) == Top(c).fn
    requires Finish(xP, ch, v, wr) == Go(c1)
    requires |c2.fr| == |c0.fr| && Below(c2) == Below(ApplyW(c0, wr))
    ensures Inv(P, c1) && LowRel(P, D, ell, c1, c2)
  {
    InvIs(P, c);
    assert Top(ch) == Top(c);
    FinishFacts(xP, ch, v, wr);
    assert |c1.fr| == |c.fr| && Below(c1) == Below(ApplyW(ch, wr));
    assert Top(c1).fn == Top(c).fn && Top(c1).kind == Top(c).kind && |Top(c1).regs| == NR;
    assert |Top(c1).stack| == STK && Top(c1).regs[10] == Top(c).regs[10];
    assert Top(c1).pc == j + 1;
    AfterFrames(P, D, ell, c, c0, ch, wr, c1, c2);
  }

  // Everything WrapAfter needs, folded.
  opaque ghost predicate WrapReady(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                   ww: WW, c: Cfg, er: set<nat>, c1: Cfg, xP: Ctx) {
    var j := Top(c).pc;
    xP.m.MP? && Inv(P, c) && Corr(P, D, ell, live, c, ww.c0, er) && 0 <= j
    && WWPre(ww) && ww.sp.floor == Fl(P, ell, Top(c).fn)
    && ww.s0 == S.InitState(R64(Top(ww.c0)), Plain(Top(ww.c0).stack))
    && ww.base + S.NumInsns(ww.raw) == E(D, j + 1) && j + 1 < |P| && Owner(P, j + 1) == Top(c).fn
    && Finish(xP, c.(h := c.h + [ww.hc.eh]), ww.hc.v, ww.hc.wr) == Go(c1)
    && Checker.Validate(ww.raw, ww.sp) == Checker.Validated && ww.F == S.NumInsns(ww.raw) + WrapLen(ww.sp) + 1
  }

  // The run of the window and the relation after it.
  lemma {:isolate_assertions} WrapRun(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                      ww: WW, c: Cfg, er: set<nat>, c1: Cfg, xP: Ctx) returns (k: nat, c2: Cfg)
    requires WrapReady(P, D, ell, live, ww, c, er, c1, xP)
    ensures ReachR(ww.Pp, ww.x, ww.obsv, ww.c0, k) == Some(c2)
    ensures Inv(P, c1) && Corr(P, D, ell, live, c1, c2, {})
  {
    reveal WrapReady();
    var sf;
    k, c2, sf := RunWrapWin(ww);
    WrapAfter(P, D, ell, live, ww, c, er, c1, c2, sf, Top(c).pc, xP);
  }

  // What P's helper step at a wrapped site gives, and what A1a and Corr say about it.
  lemma {:isolate_assertions} WrapArgs(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, om: Oracle, c: Cfg, c': Cfg, er: set<nat>, c1: Cfg)
    returns (nA: nat, args: seq<bv64>, beta: seq<bv8>, v: Val, wr: map<int, bv8>)
    requires Structure(P, D, Pp, ell, live, tbl) && E0Shape(P) && A3b(env, tbl) && Inv(P, c)
    requires forall a | a in Acc(P, CtxP(P, env, sem, om), c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.wrap
    requires StepP(P, CtxP(P, env, sem, om), c) == Go(c1)
    ensures 0 <= Top(c).pc < |P| && P[Top(c).pc].Hcall? && !P[Top(c).pc].kf && IsLookup(P[Top(c).pc].id)
    ensures 0 < |c.fr| <= MAXF && Top(c) == c.fr[|c.fr| - 1] && |c'.fr| == |c.fr| && c'.h == c.h
    ensures nA == env.arity(false, P[Top(c).pc].id) && nA <= 5
    ensures SimFacts.Words(Top(c'), Upto(1, nA)) == args
    ensures FootBytes(c', env.foot(false, P[Top(c).pc].id, args)) == FOk(beta)
    ensures om(c.h, ECall(Top(c).pc, false, P[Top(c).pc].id, args, beta), Wh(c)) == RRet(v, wr)
    ensures Finish(CtxP(P, env, sem, om), c.(h := c.h + [ECall(Top(c).pc, false, P[Top(c).pc].id, args, beta)]), v, wr) == Go(c1)
    ensures forall o: nat {:nowarn} | o < STK && o as int - STK as int < ell(Top(c).fn) :: SAddr(|c.fr| - 1, o) as int !in wr
    ensures Fl(P, ell, Top(c).pc) == Fl(P, ell, Top(c).fn) == Floor8(ell(Top(c).fn)) <= ell(Top(c).fn)
    ensures -(STK as int) <= ell(Top(c).fn) <= 0
  {
    var xP := CtxP(P, env, sem, om);
    var j := Top(c).pc;
    CorrElim(P, D, ell, live, c, c', er);
    InvIs(P, c);
    LowRelLen(P, D, ell, c, c');
    assert PiecesOk(P, D);
    assert j < |P| && P[j].Hcall? && !P[j].kf && IsLookup(P[j].id);
    var id := P[j].id;
    assert StepP(P, xP, c) == HelperStep(xP, c, j, false, id, false);
    nA, args, beta, v, wr := HelperGo(xP, c, j, id, c1);
    var addrs := env.foot(false, id, args);
    var fn := Top(c).fn;
    FlTop(P, ell, c);
    assert FloorsOk(P, ell);
    FlFrame(P, ell, c, |c.fr| - 1);
    HelperFloor(P, xP, c, ell, j, id, nA, args, beta, v, wr);
    assert LiveOk(P, live, tbl);
    assert ReadsL(P[j], live, tbl) <= live(j);
    forall i | 0 <= i < |Upto(1, nA)| ensures Rel(Reg(Top(c), Upto(1, nA)[i]), Reg(Top(c'), Upto(1, nA)[i])) {
      UptoAt(1, nA, i);
      var r := 1 + i;
      assert r in tbl(id);
      assert r in live(j);
    }
    RdsRel(Top(c), Top(c'), Upto(1, nA));
    forall i | 0 <= i < |Upto(1, nA)| ensures Reg(Top(c'), Upto(1, nA)[i]).W? { UptoAt(1, nA, i); }
    SimFacts.RdsAll(Top(c'), Upto(1, nA));
    MemRelI(P, D, ell, c, c');
    FootRelG(P, D, ell, c, c', addrs);
  }

  // The window of the site, with every precondition of its run.
  lemma {:isolate_assertions} WrapPrep(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64,
      c: Cfg, c': Cfg, er: set<nat>, c1: Cfg,
      nA: nat, args: seq<bv64>, beta: seq<bv8>, v: Val, wr: map<int, bv8>) returns (ww: WW)
    requires Structure(P, D, Pp, ell, live, tbl) && Loadable(P, D) && AllValidated(P, D, ell) && E0Shape(P)
    requires A3b(env, tbl) && A5(obsv) && A8(om) && Inv(P, c)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.wrap
    requires 0 <= Top(c).pc < |P| && P[Top(c).pc].Hcall? && !P[Top(c).pc].kf && IsLookup(P[Top(c).pc].id)
    requires 0 < |c.fr| <= MAXF && Top(c) == c.fr[|c.fr| - 1] && |c'.fr| == |c.fr| && c'.h == c.h
    requires nA == env.arity(false, P[Top(c).pc].id) && nA <= 5
    requires SimFacts.Words(Top(c'), Upto(1, nA)) == args
    requires FootBytes(c', env.foot(false, P[Top(c).pc].id, args)) == FOk(beta)
    requires om(c.h, ECall(Top(c).pc, false, P[Top(c).pc].id, args, beta), Wh(c)) == RRet(v, wr)
    requires Finish(CtxP(P, env, sem, om), c.(h := c.h + [ECall(Top(c).pc, false, P[Top(c).pc].id, args, beta)]), v, wr) == Go(c1)
    requires forall o: nat {:nowarn} | o < STK && o as int - STK as int < ell(Top(c).fn) :: SAddr(|c.fr| - 1, o) as int !in wr
    requires Fl(P, ell, Top(c).pc) == Fl(P, ell, Top(c).fn) == Floor8(ell(Top(c).fn)) <= ell(Top(c).fn)
    requires -(STK as int) <= ell(Top(c).fn) <= 0
    ensures WrapReady(P, D, ell, live, ww, c, er, c1, CtxP(P, env, sem, om))
    ensures ww.Pp == Pp && ww.x == CtxR(Pp, env, sem, om, hv) && ww.obsv == obsv && ww.c0 == c'
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    var j := Top(c).pc;
    var id := P[j].id;
    var addrs := env.foot(false, id, args);
    var e := ECall(j, false, id, args, beta);
    var hc := HCtx(nA, addrs, e, v, wr);
    ww := WrapWin(P, D, Pp, ell, xR, obsv, j, c', hc);
    WrapWinPre(P, D, Pp, ell, live, tbl, xR, obsv, j, c', hc);
    WrapHelperOk(P, ell, ww, c, xP, tbl, nA, args, beta, v, wr);
    WrapEntry(P, D, ell, live, c, c', er);
    BRInit(c', E(D, j));
    Floor8Bounds(ell(Top(c).fn));
    assert WWBasic(ww);
    WWPreIntro(ww);
    WrapNext(P, D, j);
    InvIs(P, c);
    assert Owner(P, j) == Top(c).fn;
    reveal WrapReady();
  }

  lemma WrapEntry(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, c: Cfg, c': Cfg, er: set<nat>)
    requires Inv(P, c) && Corr(P, D, ell, live, c, c', er)
    ensures 0 < |c'.fr| <= MAXF_RW && FrameOk(Top(c')) && Top(c').pc == E(D, Top(c).pc)
    ensures Top(c').regs[10] == W(StackTop(|c'.fr| - 1))
  {
    CorrElim(P, D, ell, live, c, c', er);
    InvIs(P, c);
    LowRelLen(P, D, ell, c, c');
    assert Rel(Reg(Top(c), 10), Reg(Top(c'), 10));
  }

  lemma WrapNext(P: seq<OInstr>, D: Decomp, j: nat)
    requires PiecesOk(P, D) && E0Shape(P) && j in D.wrap
    ensures j + 1 < |P| && E(D, j + 1) == K(D, j) + 1 && Owner(P, j + 1) == Owner(P, j)
  {
    NextE(P, D, j);
    assert PostLen(D, j) == 0;
    assert j + 1 !in FnSet(P);
  }

  // The wrapper lemma: the helper step of P at a P8 site is matched by the run of WP . call W . W.
  lemma {:isolate_assertions} WrapStep(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64,
      c: Cfg, c': Cfg, er: set<nat>, c1: Cfg)
    requires Structure(P, D, Pp, ell, live, tbl) && Loadable(P, D) && AllValidated(P, D, ell) && E0Shape(P)
    requires A3b(env, tbl) && A5(obsv) && A8(om) && Inv(P, c)
    requires forall a | a in Acc(P, CtxP(P, env, sem, om), c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.wrap
    requires StepP(P, CtxP(P, env, sem, om), c) == Go(c1)
    ensures Inv(P, c1)
    ensures exists k: nat, c1': Cfg :: ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Some(c1')
                                       && Corr(P, D, ell, live, c1, c1', {})
  {
    var nA, args, beta, v, wr := WrapArgs(P, D, Pp, ell, live, tbl, env, sem, om, c, c', er, c1);
    var ww := WrapPrep(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er, c1, nA, args, beta, v, wr);
    var k, c2 := WrapRun(P, D, ell, live, ww, c, er, c1, CtxP(P, env, sem, om));
  }
}
