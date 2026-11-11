// A validated window of P', run in the whole model, ends where the region
// model says, related to the step of P it replaces: site windows (P1c, P2
// with MF, P3, P5) around an original helper call, and the entry prologue
// (P1).
include "Frames.dfy"

module SimSites {
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
  import SimFacts
  import Soundness
  import Checker
  import Api

  // ---------------- a whole window run ----------------

  lemma RunDonePc(raw: seq<bv8>, floor: int, s: S.CState, oracle: seq<bv64>, fuel: nat)
    requires S.CWF(s) && -(S.STACK as int) <= floor <= 0
    ensures S.Run(raw, floor, s, oracle, fuel).Done? ==> S.Run(raw, floor, s, oracle, fuel).s.pc == S.NumInsns(raw)
    decreases fuel
  {
    reveal S.Run();
    if s.pc != S.NumInsns(raw) && 0 <= s.pc < S.NumInsns(raw) && fuel > 0 {
      match S.Decode(S.InsnAt(raw, s.pc))
      case None =>
      case Some(ins) =>
        match S.Step(floor, ins, s, oracle)
        case Stuck =>
        case Halt(_) =>
        case Next(s') => if S.CWF(s') { RunDonePc(raw, floor, s', oracle, fuel - 1); }
    }
  }

  // A validated window that is not a hook body runs to its end, and the
  // obligations hold for the region state it ends in.
  lemma RunWindow(w: Win) returns (k: nat, c2: Cfg, sf: S.CState)
    requires WinPre(w) && Checker.Validate(w.raw, w.sp) == Checker.Validated && !w.sp.exitMode && !w.hins.Tail?
    requires w.sp.hookCalls ==> |w.c0.fr| < MAXF_RW
    ensures ReachR(w.Pp, w.x, w.obsv, w.c0, k) == Some(c2)
    ensures BR(c2, sf, w.base) && Side(w, c2, sf) && FinalOk(w.sp, w.s0, sf) && sf.pc == S.NumInsns(w.raw)
  {
    WinPreFacts(w);
    SideInit(w);
    var fuel := S.NumInsns(w.raw) + 1;
    assert Pre(w, w.c0, w.s0, []);
    var rest := Bridge(w, w.c0, w.s0, [], fuel);
    Soundness.Soundness(w.raw, w.sp, w.s0.regs, w.s0.stack, rest, fuel);
    assert [] + rest == rest;
    var O := S.Run(w.raw, w.sp.floor, w.s0, rest, fuel);
    assert WindowRun(w.raw, w.sp, S.InitState(w.s0.regs, w.s0.stack), rest, fuel) == O;
    assert O.Done? && FinalOk(w.sp, w.s0, O.s);
    assert FinalOkO(w.sp, w.s0, O.s) by { reveal FinalOkO(); }
    RunDonePc(w.raw, w.sp.floor, w.s0, rest, fuel);
    k, c2 := EndsGet(w, w.c0, O.s, false);
    sf := O.s;
  }

  // ---------------- layout facts about P' ----------------

  lemma AllFnsFromHas(D: Decomp, n: nat, i: nat, i': nat, q: nat)
    requires i <= i' < n && q < |FnsAt(D, i')|
    ensures |FnStarts(D, FnsAt(D, i'), Start(D, i'))| == |FnsAt(D, i')|
    ensures FnStarts(D, FnsAt(D, i'), Start(D, i'))[q] in AllFnsFrom(D, n, i)
    decreases n - i
  {
    FnStartsLen(D, FnsAt(D, i'), Start(D, i'));
    var a := FnStarts(D, FnsAt(D, i), Start(D, i));
    assert AllFnsFrom(D, n, i) == a + AllFnsFrom(D, n, i + 1);
    if i < i' { AllFnsFromHas(D, n, i + 1, i', q); }
  }

  lemma AllFnsFromTail(D: Decomp, n: nat, i: nat, q: nat)
    requires i <= n && q < |D.tail|
    ensures |FnStarts(D, D.tail, Start(D, n))| == |D.tail|
    ensures FnStarts(D, D.tail, Start(D, n))[q] in AllFnsFrom(D, n, i)
    decreases n - i
  {
    FnStartsLen(D, D.tail, Start(D, n));
    if i < n {
      var a := FnStarts(D, FnsAt(D, i), Start(D, i));
      assert AllFnsFrom(D, n, i) == a + AllFnsFrom(D, n, i + 1);
      AllFnsFromTail(D, n, i + 1, q);
    }
  }

  // Every placed wrapper has its body (PiecesOk names every function of AllFns).
  lemma {:isolate_assertions} AllFnsWFOk(P: seq<OInstr>, D: Decomp)
    requires PiecesOk(P, D)
    ensures AllFnsWF(P, D)
  {
    forall i | i in D.fns ensures FnsWF(P, D, D.fns[i]) {
      assert 0 < i < |P|;
      forall q | 0 <= q < |D.fns[i]| && D.fns[i][q].WrapFn? ensures D.fns[i][q].site in D.wrap && D.fns[i][q].site < |P| {
        assert FnsAt(D, i) == D.fns[i];
        AllFnsFromHas(D, |P|, 0, i, q);
        FnStartsAt(D, FnsAt(D, i), Start(D, i), q);
        var gt := FnStarts(D, FnsAt(D, i), Start(D, i))[q];
        var k :| 0 <= k < |AllFns(P, D)| && AllFns(P, D)[k] == gt;
        assert AllFns(P, D)[k].0 == D.fns[i][q];
      }
    }
    forall q | 0 <= q < |D.tail| && D.tail[q].WrapFn? ensures D.tail[q].site in D.wrap && D.tail[q].site < |P| {
      AllFnsFromTail(D, |P|, 0, q);
      FnStartsAt(D, D.tail, Start(D, |P|), q);
      var gt := FnStarts(D, D.tail, Start(D, |P|))[q];
      var k :| 0 <= k < |AllFns(P, D)| && AllFns(P, D)[k] == gt;
      assert AllFns(P, D)[k].0 == D.tail[q];
    }
  }

  // Every hook of P' is a validated hook body laid out at its entry.
  lemma {:isolate_assertions} HooksOkLayout(P: seq<OInstr>, D: Decomp, ell: nat -> int)
    requires PiecesOk(P, D) && AllValidated(P, D, ell)
    ensures HooksOk(Layout(P, D))
  {
    AllFnsWFOk(P, D);
    LayoutIs(P, D);
    var Pp := Layout(P, D);
    forall t | t in Pp.hooks ensures exists body :: HookAt(Pp, t, body) {
      var k :| 0 <= k < |AllFns(P, D)| && AllFns(P, D)[k].0.HookFn? && AllFns(P, D)[k].1 == t;
      var b := AllFns(P, D)[k].0.body;
      AllFnsPlaced(P, D, k);
      assert Bytes8(b) && NoHelperIn(b);
      assert Valid(b, Api.HookBodySpec());
      assert Checker.Validate(b, Api.HookBodySpec()) == Checker.Validated by { reveal Valid(); }
      NsAt(b);
      forall r | 0 <= r < S.NumInsns(b) ensures Pp.code[t + r] == N(S.InsnAt(b, r)) && !IsHelperCall(S.InsnAt(b, r)) {
        assert Pp.code[t + r] == FnCode(P, D, HookFn(b))[r];
        assert S.InsnAt(b, r) == Slice(b, r);
      }
      assert HookAt(Pp, t, b);
    }
  }

  // ---------------- encodings ----------------

  lemma {:isolate_assertions} RawAt(pre: seq<bv8>, mid: seq<bv8>, post: seq<bv8>, r: nat)
    requires |pre| % 8 == 0 && |mid| == 8 && |post| % 8 == 0
    requires r < NI(pre) + 1 + NI(post)
    ensures |pre + mid + post| % 8 == 0 && S.NumInsns(pre + mid + post) == NI(pre) + 1 + NI(post)
    ensures S.InsnAt(pre + mid + post, r) ==
      if r < NI(pre) then Slice(pre, r) else if r == NI(pre) then mid else Slice(post, r - NI(pre) - 1)
  {
    var raw := pre + mid + post;
    assert |pre| == 8 * NI(pre) && |post| == 8 * NI(post);
    assert |raw| == 8 * (NI(pre) + 1 + NI(post));
    if r < NI(pre) { assert raw[8 * r .. 8 * r + 8] == pre[8 * r .. 8 * r + 8]; }
    else if r == NI(pre) { assert raw[8 * r .. 8 * r + 8] == mid; }
    else {
      var q := r - NI(pre) - 1;
      var pm := pre + mid;
      assert raw == pm + post && |pm| == 8 * NI(pre) + 8;
      assert 8 * r == |pm| + 8 * q;
      forall k {:nowarn} | 0 <= k < 8 ensures raw[8 * r + k] == post[8 * q + k] { assert raw[|pm| + (8 * q + k)] == post[8 * q + k]; }
      assert raw[8 * r .. 8 * r + 8] == post[8 * q .. 8 * q + 8];
    }
  }

  lemma ImmBytes(u: bv64, id: bv32)
    requires u == id as bv64
    ensures (ByteOf(u, 0) as bv32) | ((ByteOf(u, 1) as bv32) << 8) | ((ByteOf(u, 2) as bv32) << 16) | ((ByteOf(u, 3) as bv32) << 24) == id
  {}

  lemma DecodeEncHelper(id: bv32)
    ensures |EncHelper(id)| == 8 && S.Decode(EncHelper(id)) == Some(S.CallHelper(id))
  {
    var u := id as bv64;
    var b := EncHelper(id);
    assert b == [0x85, 0, 0, 0, ByteOf(u, 0), ByteOf(u, 1), ByteOf(u, 2), ByteOf(u, 3)];
    ImmBytes(u, id);
  }

  // ---------------- single-function programs ----------------

  lemma Floor8Bounds(l: int)
    requires -(STK as int) <= l <= 0
    ensures -(STK as int) <= Floor8(l) <= l
  {
    assert l / 8 >= -64;
  }

  // Corr for one frame on each side (the entry frame).
  lemma LowRelOne(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg)
    requires |c.fr| == 1 && |c'.fr| == 1
    ensures LowRel(P, D, ell, c, c')
  { reveal LowRel(); }

  lemma HelperGo(x: Ctx, c: Cfg, idx: nat, id: bv32, c1: Cfg)
    returns (n: nat, args: seq<bv64>, beta: seq<bv8>, v: Val, wr: map<int, bv8>)
    requires HelperStep(x, c, idx, false, id, false) == Go(c1)
    ensures n == x.env.arity(false, id) && n <= 5 && Rds(Top(c), Upto(1, n)) == Some(args)
    ensures FootBytes(c, x.env.foot(false, id, args)) == FOk(beta)
    ensures x.om(c.h, ECall(idx, false, id, args, beta), Wh(c)) == RRet(v, wr)
    ensures Finish(x, c.(h := c.h + [ECall(idx, false, id, args, beta)]), v, wr) == Go(c1)
  {
    reveal HelperStep();
    n := x.env.arity(false, id);
    args := Rds(Top(c), Upto(1, n)).value;
    beta := FootBytes(c, x.env.foot(false, id, args)).bs;
    var r := x.om(c.h, ECall(idx, false, id, args, beta), Wh(c));
    v := r.v;
    wr := r.wr;
  }

  lemma RdsRel(f: Frame, f': Frame, rs: seq<nat>)
    requires Rds(f, rs).Some?
    requires forall i | 0 <= i < |rs| :: Rel(Reg(f, rs[i]), Reg(f', rs[i]))
    ensures Rds(f', rs) == Rds(f, rs)
    decreases |rs|
  {
    if |rs| > 0 {
      assert Reg(f, rs[0]).W?;
      RdsRel(f, f', rs[1..]);
    }
  }

  lemma FootAccHas(c: Cfg, addrs: seq<bv64>, i: nat)
    requires i < |addrs| && Classify(addrs[i], 1, |c.fr|, c.L.mem.Keys).InStack?
    ensures (Classify(addrs[i], 1, |c.fr|, c.L.mem.Keys).d, Classify(addrs[i], 1, |c.fr|, c.L.mem.Keys).o) in FootAcc(c, addrs)
    decreases |addrs|
  {
    if i > 0 { FootAccHas(c, addrs[1..], i - 1); assert addrs[1..][i - 1] == addrs[i]; }
  }

  lemma HelperAccIs(x: Ctx, c: Cfg, idx: nat, id: bv32, n: nat, args: seq<bv64>, beta: seq<bv8>, v: Val, wr: map<int, bv8>)
    requires n == x.env.arity(false, id) && Rds(Top(c), Upto(1, n)) == Some(args)
    requires FootBytes(c, x.env.foot(false, id, args)) == FOk(beta)
    requires x.om(c.h, ECall(idx, false, id, args, beta), Wh(c)) == RRet(v, wr)
    ensures HelperAcc(x, c, idx, false, id) == FootAcc(c, x.env.foot(false, id, args)) + WrAcc(c, wr)
  {}

  // What A1a says about the helper step of P at c.
  lemma {:isolate_assertions} HelperFloor(P: seq<OInstr>, x: Ctx, c: Cfg, ell: nat -> int, idx: nat, id: bv32,
                                          n: nat, args: seq<bv64>, beta: seq<bv8>, v: Val, wr: map<int, bv8>)
    requires 0 < |c.fr| <= MAXF && 0 <= Top(c).pc < |P| && P[Top(c).pc] == Hcall(false, id) && idx == Top(c).pc
    requires Top(c) == c.fr[|c.fr| - 1]
    requires forall a | a in Acc(P, x, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires n == x.env.arity(false, id) && Rds(Top(c), Upto(1, n)) == Some(args)
    requires FootBytes(c, x.env.foot(false, id, args)) == FOk(beta)
    requires x.om(c.h, ECall(idx, false, id, args, beta), Wh(c)) == RRet(v, wr)
    ensures forall i | 0 <= i < |x.env.foot(false, id, args)| :: FootInF(ell, c, x.env.foot(false, id, args)[i])
    ensures forall o: nat {:nowarn} | o < STK && o as int - STK as int < ell(Top(c).fn) :: SAddr(|c.fr| - 1, o) as int !in wr
  {
    var addrs := x.env.foot(false, id, args);
    var d := |c.fr| - 1;
    assert Acc(P, x, c) == HelperAcc(x, c, idx, false, id);
    HelperAccIs(x, c, idx, id, n, args, beta, v, wr);
    assert FootAcc(c, addrs) <= Acc(P, x, c);
    assert WrAcc(c, wr) <= Acc(P, x, c);
    forall i | 0 <= i < |addrs| ensures FootInF(ell, c, addrs[i]) {
      if Classify(addrs[i], 1, |c.fr|, c.L.mem.Keys).InStack? { FootAccHas(c, addrs, i); }
    }
    forall o: nat | o < STK && o as int - STK as int < ell(Top(c).fn) ensures SAddr(d, o) as int !in wr {
      if SAddr(d, o) as int in wr { assert (d, o) in WrAcc(c, wr); }
    }
  }

  // The window of a site helper at j, entered at c' (the region state is c''s top frame).
  ghost function SiteWin(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, xR: Ctx, obsv: Observer,
                         j: nat, c': Cfg, hc: HCtx): Win
    requires j in D.site && j < |P|
  {
    Win(Pp, xR, obsv, D.site[j].pre + Enc(P[j]) + D.site[j].post,
        SiteSpecFor(P[j], Fl(P, ell, j), D.site[j].binds), E(D, j),
        NI(D.site[j].pre), P[j], j, hc, c', S.InitState(R64(Top(c')), Plain(Top(c').stack)))
  }

  // A position of block j other than kappa(j) is no kappa.
  lemma InBlockNotK(D: Decomp, j: nat, p: int, i: nat)
    requires E(D, j) <= p <= K(D, j) + PostLen(D, j) && p != K(D, j) && i != j
    ensures p != K(D, i)
  {
    assert Start(D, j + 1) == K(D, j) + 1 + PostLen(D, j);
    assert Start(D, i) + FnsLen(D, FnsAt(D, i)) <= K(D, i) < Start(D, i + 1);
    if i < j { StartMono(D, i + 1, j); } else { StartMono(D, j + 1, i); }
  }

  lemma {:isolate_assertions} SiteWinAt(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                        tbl: bv32 -> set<nat>, w: Win, j: nat)
    requires Structure(P, D, w.Pp, ell, live, tbl)
    requires j in D.site && j < |P| && ((P[j].Hcall? && !P[j].kf) || P[j].Tail?)
    requires w.raw == D.site[j].pre + Enc(P[j]) + D.site[j].post && w.base == E(D, j) && w.hp == NI(D.site[j].pre)
    requires w.hins == P[j] && w.hidx == j
    ensures WinAt(w) && HasHelper(w)
    ensures S.NumInsns(w.raw) == NI(D.site[j].pre) + 1 + NI(D.site[j].post)
    ensures w.base + S.NumInsns(w.raw) == K(D, j) + 1 + PostLen(D, j)
  {
    var site := D.site[j];
    var Pp := w.Pp;
    assert PiecesOk(P, D) && CallsOk(D, Pp) && Pp == Layout(P, D);
    assert Bytes8(site.pre) && Bytes8(site.post) && NoHelperIn(site.pre) && NoHelperIn(site.post);
    AllFnsWFOk(P, D);
    assert j !in D.pl;
    SiteCode(P, D, j);
    DecodeEncHelper(HId(P[j]));
    assert Enc(P[j]) == EncHelper(HId(P[j]));
    var n := NI(site.pre) + 1 + NI(site.post);
    RawAt(site.pre, Enc(P[j]), site.post, w.hp);
    assert Reloc(D, P[j]) == P[j];
    forall r | 0 <= r < n && r != w.hp
      ensures Pp.code[w.base + r] == N(S.InsnAt(w.raw, r)) && !IsHelperCall(S.InsnAt(w.raw, r))
      ensures w.sp.hookCalls && S.Decode(S.InsnAt(w.raw, r)).Some? && S.Decode(S.InsnAt(w.raw, r)).value.CallLocal? ==>
                w.base + r + 1 + Signed32(S.Decode(S.InsnAt(w.raw, r)).value.imm) in Pp.hooks
    {
      SiteSlot(P, D, w, j, r);
    }
  }

  // One slot of a site window other than its centre.
  lemma {:isolate_assertions} SiteSlot(P: seq<OInstr>, D: Decomp, w: Win, j: nat, r: nat)
    requires PiecesOk(P, D) && CallsOk(D, w.Pp) && w.Pp == Layout(P, D) && AllFnsWF(P, D)
    requires j in D.site && j < |P| && j !in D.pl && ((P[j].Hcall? && !P[j].kf) || P[j].Tail?)
    requires w.raw == D.site[j].pre + Enc(P[j]) + D.site[j].post && w.base == E(D, j) && w.hp == NI(D.site[j].pre)
    requires |Enc(P[j])| == 8 && Bytes8(D.site[j].pre) && Bytes8(D.site[j].post)
    requires NoHelperIn(D.site[j].pre) && NoHelperIn(D.site[j].post)
    requires r < NI(D.site[j].pre) + 1 + NI(D.site[j].post) && r != w.hp
    ensures w.base + r < |w.Pp.code| && S.NumInsns(w.raw) == NI(D.site[j].pre) + 1 + NI(D.site[j].post)
    ensures w.Pp.code[w.base + r] == N(S.InsnAt(w.raw, r)) && !IsHelperCall(S.InsnAt(w.raw, r))
    ensures w.sp.hookCalls && S.Decode(S.InsnAt(w.raw, r)).Some? && S.Decode(S.InsnAt(w.raw, r)).value.CallLocal? ==>
              w.base + r + 1 + Signed32(S.Decode(S.InsnAt(w.raw, r)).value.imm) in w.Pp.hooks
  {
    var site := D.site[j];
    var Pp := w.Pp;
    SiteCode(P, D, j);
    RawAt(site.pre, Enc(P[j]), site.post, r);
    if r < NI(site.pre) {
      assert Pp.code[w.base + r] == N(Slice(site.pre, r));
    } else {
      var q := r - NI(site.pre) - 1;
      assert w.base + r == K(D, j) + 1 + q;
      assert Pp.code[w.base + r] == N(Slice(site.post, q));
    }
    var p := w.base + r;
    assert E(D, j) <= p <= K(D, j) + PostLen(D, j) && p != K(D, j);
    forall i | i in D.wrap ensures p != K(D, i) {
      assert i != j && i < |P|;
      InBlockNotK(D, j, p, i);
    }
    assert !(exists i :: i in D.wrap && p == K(D, i));
  }

  lemma {:isolate_assertions} SiteHelperOk(P: seq<OInstr>, ell: nat -> int, w: Win, c: Cfg, xP: Ctx,
                                           n: nat, args: seq<bv64>, beta: seq<bv8>, v: Val, wr: map<int, bv8>)
    requires 0 < |c.fr| <= MAXF && Top(c) == c.fr[|c.fr| - 1]
    requires |w.c0.fr| == |c.fr| && w.c0.L == c.L && w.c0.h == c.h && Top(w.c0).kind == Top(c).kind
    requires w.hins.Hcall? && !w.hins.kf && w.x.env == xP.env && w.x.om == xP.om
    requires n == xP.env.arity(false, w.hins.id) && n <= 5
    requires SimFacts.Words(Top(w.c0), Upto(1, n)) == args
    requires FootBytes(w.c0, xP.env.foot(false, w.hins.id, args)) == FOk(beta)
    requires xP.om(c.h, ECall(w.hidx, false, w.hins.id, args, beta), Wh(c)) == RRet(v, wr)
    requires w.hc == HCtx(n, xP.env.foot(false, w.hins.id, args), ECall(w.hidx, false, w.hins.id, args, beta), v, wr)
    requires forall i | 0 <= i < |w.hc.addrs| :: FootInF(ell, c, w.hc.addrs[i])
    requires forall o: nat {:nowarn} | o < STK && o as int - STK as int < ell(Top(c).fn) :: SAddr(|c.fr| - 1, o) as int !in wr
    requires w.sp.floor <= ell(Top(c).fn)
    ensures HelperOk(w)
  {
    assert Wh(w.c0) == Wh(c);
    forall i | 0 <= i < |w.hc.addrs| ensures
      match Classify(w.hc.addrs[i], 1, |w.c0.fr|, w.c0.L.mem.Keys)
      case InStack(d, o) => d == |w.c0.fr| - 1 ==> o >= STK as int + w.sp.floor
      case _ => true
    {
      assert FootInF(ell, c, w.hc.addrs[i]);
    }
    assert FootTop(w.c0, w.hc.addrs, w.sp.floor);
    assert WrTop(w.c0, wr, w.sp.floor);
  }

  // The frames after a site window (or any helper finish): the invariant and the waiting frames.
  lemma {:isolate_assertions} AfterFrames(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c0: Cfg, ch: Cfg, wr: map<int, bv8>,
                                          c1: Cfg, c2: Cfg)
    requires Inv(P, c) && LowRel(P, D, ell, c, c0) && ch.fr == c.fr && |Top(c).regs| == NR
    requires |c1.fr| == |c.fr| && Below(c1) == Below(ApplyW(ch, wr))
    requires Top(c1).fn == Top(c).fn && Top(c1).kind == Top(c).kind && |Top(c1).regs| == NR && |Top(c1).stack| == STK
    requires Top(c1).regs[10] == Top(c).regs[10] && 0 <= Top(c1).pc < |P| && Owner(P, Top(c1).pc) == Top(c).fn
    requires |c2.fr| == |c0.fr| && Below(c2) == Below(ApplyW(c0, wr))
    ensures Inv(P, c1) && LowRel(P, D, ell, c1, c2)
  {
    InvIs(P, c);
    LowRelLen(P, D, ell, c, c0);
    InvFields(P, c, ch);
    InvApply(P, ch, wr);
    ApplyWAt(ch, wr);
    ApplyWAt(c0, wr);
    var a := ApplyW(ch, wr);
    var a0 := ApplyW(c0, wr);
    assert FrInv(P, |c.fr| - 1, Top(c));
    assert FrInv(P, |c.fr| - 1, Top(c1));
    InvPut(P, a, c1);
    LowRelSame(P, D, ell, c, c0, ch, c0);
    LowRelApply(P, D, ell, ch, c0, wr);
    LowRelSame(P, D, ell, a, a0, c1, c2);
  }

  // The registers after a site window: r0 is the helper's result, r1..r5 are unreadable in P, r6..r10 are kept.
  lemma {:isolate_assertions} SiteAfterRegs(c: Cfg, c0: Cfg, c1: Cfg, c2: Cfg, sf: S.CState, s0: S.CState, v: Val,
                                            er: set<nat>, lv: set<nat>)
    requires |Top(c).regs| == NR && FrameOk(Top(c0)) && FrameOk(Top(c2)) && |Top(c1).regs| == NR && S.CWF(sf)
    requires R64(Top(c2)) == sf.regs && s0.regs == R64(Top(c0))
    requires forall r | 6 <= r <= 10 :: sf.regs[r] == s0.regs[r]
    requires v.W? ==> sf.regs[0] == v.w
    requires Top(c1).regs[0] == (if v.W? then v else Bot)
    requires forall r | 1 <= r <= 5 :: Top(c1).regs[r] == Bot
    requires forall r | 6 <= r < NR :: Top(c1).regs[r] == Top(c).regs[r]
    requires RegRel(c, c0, er, lv)
    ensures forall r | 0 <= r < NR :: Rel(Reg(Top(c1), r), Reg(Top(c2), r))
  {
    forall r | 0 <= r < NR ensures Rel(Reg(Top(c1), r), Reg(Top(c2), r)) {
      assert Top(c2).regs[r] == W(sf.regs[r]);
      if 6 <= r {
        assert Top(c0).regs[r] == W(R64(Top(c0))[r]);
        assert Rel(Reg(Top(c), r), Reg(Top(c0), r));
      }
    }
  }

  // The bytes at or above the floor after a site window: the helper's write set in both runs.
  lemma {:isolate_assertions} SiteAfterStack(c: Cfg, c0: Cfg, c1: Cfg, c2: Cfg, sf: S.CState, s0: S.CState, wr: map<int, bv8>,
                                             fl: int, d: nat)
    requires |Top(c).stack| == STK && |Top(c0).stack| == STK && |Top(c2).stack| == STK && -(STK as int) <= fl <= 0
    requires Top(c1).stack == ApplyF(Top(c), d, wr).stack && Plain(Top(c2).stack) == sf.stack && FrameOk(Top(c2))
    requires |UpperBase(sf.events, s0.stack)| == STK
    requires forall i | 0 <= i < STK && STK as int + fl <= i :: sf.stack[i] == UpperBase(sf.events, s0.stack)[i]
    requires forall i | 0 <= i && STK as int + fl <= i < STK :: UpperBase(sf.events, s0.stack)[i] == Plain(ApplyF(Top(c0), d, wr).stack)[i]
    requires forall o | 0 <= o < STK && o - STK as int >= fl :: RelB(Top(c).stack[o], Top(c0).stack[o])
    ensures StkRel(c1, c2, fl)
  {
    forall o | 0 <= o < STK && o - STK as int >= fl ensures RelB(Top(c1).stack[o], Top(c2).stack[o]) {
      assert Top(c2).stack[o] == B(sf.stack[o]);
    }
  }

  // The configurations after a site window and after the helper step of P are related.
  lemma {:isolate_assertions} SiteAfter(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
      w: Win, c: Cfg, er: set<nat>, c1: Cfg, c2: Cfg, sf: S.CState, j: nat, xP: Ctx)
    requires xP.m.MP?
    requires Inv(P, c) && Corr(P, D, ell, live, c, w.c0, er) && Top(c).pc == j
    requires WinPre(w) && w.sp.helper.Helper? && (w.hc.v.W? ==> w.sp.helper.restoreR0) && w.sp.floor == Fl(P, ell, Top(c).fn)
    requires w.s0 == S.InitState(R64(Top(w.c0)), Plain(Top(w.c0).stack))
    requires w.base + S.NumInsns(w.raw) == E(D, j + 1) && j + 1 < |P| && Owner(P, j + 1) == Top(c).fn
    requires Finish(xP, c.(h := c.h + [w.hc.eh]), w.hc.v, w.hc.wr) == Go(c1)
    requires BR(c2, sf, w.base) && Side(w, c2, sf) && FinalOk(w.sp, w.s0, sf) && sf.pc == S.NumInsns(w.raw)
    ensures Inv(P, c1) && Corr(P, D, ell, live, c1, c2, {})
  {
    var c0 := w.c0;
    var wr := w.hc.wr;
    var v := w.hc.v;
    CorrElim(P, D, ell, live, c, c0, er);
    InvIs(P, c);
    LowRelLen(P, D, ell, c, c0);
    var n := |c.fr|;
    var ch := c.(h := c.h + [w.hc.eh]);
    FinishFacts(xP, ch, v, wr);
    WinPreFacts(w);
    SideFacts(w, c2, sf);
    assert CountHelpers(sf.events) == 1;
    Side1(w, c2, sf);
    assert Top(ch) == Top(c) && ch.fr == c.fr;
    assert |c1.fr| == |c.fr| && Below(c1) == Below(ApplyW(ch, wr));
    assert Top(c1).fn == Top(c).fn && Top(c1).kind == Top(c).kind && |Top(c1).regs| == NR;
    assert |Top(c1).stack| == STK && Top(c1).regs[10] == Top(c).regs[10];
    assert Top(c1).pc == j + 1;
    assert Owner(P, Top(c1).pc) == Owner(P, j + 1);
    assert |c2.fr| == |c0.fr| && Below(c2) == Below(ApplyW(c0, wr));
    AfterFrames(P, D, ell, c, c0, ch, wr, c1, c2);
    assert Top(c) == c.fr[n - 1] && Top(c0) == c0.fr[n - 1];
    ApplyTop(c0, wr);
    ApplyTop(ch, wr);
    assert forall r | 1 <= r <= 5 :: Top(c1).regs[r] == Und(xP, ch, r) == Bot;
    FinalFacts(w.sp, w.s0, sf);
    assert v.W? ==> sf.regs[0] == v.w;
    SiteAfterRegs(c, c0, c1, c2, sf, w.s0, v, er, live(j));
    assert RegRel(c1, c2, {}, live(Top(c1).pc));
    assert Top(c1).stack == ApplyF(Top(c), n - 1, wr).stack;
    SiteAfterStack(c, c0, c1, c2, sf, w.s0, wr, w.sp.floor, n - 1);
    assert c2.L == c1.L && c2.h == c1.h;
    assert Top(c1).pc == j + 1 && Top(c2).pc == w.base + sf.pc;
    assert TopRel(P, D, ell, live, c1, c2, {});
    CorrIntro(P, D, ell, live, c1, c2, {});
  }

  // WinPre from its parts (the opaque part is revealed here only).
  lemma WinPreIntro(w: Win)
    requires w.x.m.MR? && SimPremises.A5(w.obsv) && SpecWF(w.sp) && w.sp.wrap.NoWrap?
    requires WinAt(w) && HooksOk(w.Pp)
    requires BR(w.c0, w.s0, w.base) && w.s0 == S.InitState(w.s0.regs, w.s0.stack)
    requires HasHelper(w) ==> HelperOk(w) && w.sp.helper.Helper? && w.sp.helper.checkArgs
    requires -(S.STACK as int) <= w.sp.floor <= 0 && S.CWF(w.s0)
    ensures WinPre(w)
  { reveal WinPreO(); }

  // The site lemma: the helper step of P at a site is matched by the run of its window.
  lemma {:isolate_assertions} SiteStep(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64,
      c: Cfg, c': Cfg, er: set<nat>, c1: Cfg)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A3b(env, tbl) && A5(obsv)
    requires Inv(P, c)
    requires forall a | a in Acc(P, CtxP(P, env, sem, om), c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.site && !P[Top(c).pc].Tail?
    requires StepP(P, CtxP(P, env, sem, om), c) == Go(c1)
    ensures Inv(P, c1)
    ensures exists k: nat, c1': Cfg :: ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Some(c1')
                                       && Corr(P, D, ell, live, c1, c1', {})
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    var j := Top(c).pc;
    CorrElim(P, D, ell, live, c, c', er);
    InvIs(P, c);
    LowRelLen(P, D, ell, c, c');
    assert PiecesOk(P, D);
    assert j < |P| && P[j].Hcall? && !P[j].kf;
    var id := P[j].id;
    assert StepP(P, xP, c) == HelperStep(xP, c, j, false, id, false);
    var nA, args, beta, v, wr := HelperGo(xP, c, j, id, c1);
    var addrs := env.foot(false, id, args);
    var e := ECall(j, false, id, args, beta);
    var fn := Top(c).fn;
    FlTop(P, ell, c);
    var fl := Fl(P, ell, j);
    assert FloorsOk(P, ell);
    FlFrame(P, ell, c, |c.fr| - 1);
    assert fl == Fl(P, ell, fn) <= ell(fn);
    HelperFloor(P, xP, c, ell, j, id, nA, args, beta, v, wr);
    // P' reads the same arguments and the same footprint
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
    assert SimFacts.Words(Top(c'), Upto(1, nA)) == args;
    MemRelI(P, D, ell, c, c');
    FootRelG(P, D, ell, c, c', addrs);
    // the window
    var hc := HCtx(nA, addrs, e, v, wr);
    var w := SiteWin(P, D, Pp, ell, xR, obsv, j, c', hc);
    assert Valid(w.raw, w.sp);
    assert Checker.Validate(w.raw, w.sp) == Checker.Validated by { reveal Valid(); }
    Soundness.ValidateOk(w.raw, w.sp);
    SiteWinAt(P, D, ell, live, tbl, w, j);
    HooksOkLayout(P, D, ell);
    SiteHelperOk(P, ell, w, c, xP, nA, args, beta, v, wr);
    assert Rel(Reg(Top(c), 10), Reg(Top(c'), 10));
    BRInit(c', E(D, j));
    WinPreIntro(w);
    var k, c2, sf := RunWindow(w);
    NextE(P, D, j);
    assert Owner(P, j + 1) == Owner(P, j) by { assert j + 1 !in FnSet(P); }
    SiteAfter(P, D, ell, live, w, c, er, c1, c2, sf, j, xP);
  }

  // ---------------- tail-call sites (P4) ----------------

  lemma {:isolate_assertions} TailArgs(P: seq<OInstr>, live: nat -> set<nat>, tbl: bv32 -> set<nat>, c: Cfg, c': Cfg,
                                       er: set<nat>, j: nat)
    requires j < |P| && P[j].Tail? && LiveOk(P, live, tbl) && {1, 2, 3} <= tbl(12) && Top(c).pc == j
    requires forall r | 0 <= r < NR :: Rel(Reg(Top(c), r), Reg(Top(c'), r)) || (r in er && 1 <= r <= 5 && r !in live(j))
    requires FrameOk(Top(c')) && Rds(Top(c), [1, 2, 3]).Some?
    ensures Rds(Top(c'), [1, 2, 3]) == Rds(Top(c), [1, 2, 3])
    ensures SimFacts.Words(Top(c'), [1, 2, 3]) == Rds(Top(c), [1, 2, 3]).value
  {
    assert ReadsL(P[j], live, tbl) <= live(j);
    forall i | 0 <= i < 3 ensures Rel(Reg(Top(c), [1, 2, 3][i]), Reg(Top(c'), [1, 2, 3][i])) {
      assert [1, 2, 3][i] in tbl(12);
    }
    RdsRel(Top(c), Top(c'), [1, 2, 3]);
    forall i | 0 <= i < 3 ensures Reg(Top(c'), [1, 2, 3][i]).W? {}
    SimFacts.RdsAll(Top(c'), [1, 2, 3]);
  }

  // The tail-call step of P at a P4 site is matched by the run of its window:
  // P' ends with the same tail transfer, or passes the failed call.
  lemma {:isolate_assertions} TailStep(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64,
      c: Cfg, c': Cfg, er: set<nat>)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A3b(env, tbl) && A5(obsv)
    requires Inv(P, c)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.site && P[Top(c).pc].Tail?
    ensures StepP(P, CtxP(P, env, sem, om), c).Go? ==> Inv(P, StepP(P, CtxP(P, env, sem, om), c).c)
    ensures match StepP(P, CtxP(P, env, sem, om), c)
      case Go(c1) => exists k: nat, c1': Cfg :: ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Some(c1')
                                               && Corr(P, D, ell, live, c1, c1', {})
      case Done(t) => exists k: nat :: RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t)
      case Stuck(_) => true
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    var j := Top(c).pc;
    CorrElim(P, D, ell, live, c, c', er);
    InvIs(P, c);
    LowRelLen(P, D, ell, c, c');
    assert PiecesOk(P, D);
    assert StepP(P, xP, c) == TailO(xP, c, j);
    if Rds(Top(c), [1, 2, 3]).None? {
      assert TailO(xP, c, j).Stuck? by { reveal TailO(); }
      return;
    }
    var args := Rds(Top(c), [1, 2, 3]).value;
    var e := ECall(j, false, 12, args, []);
    TailIsB(xP, c, j);
    var r := om(c.h, e, Wh(c));
    if !(r.RTailOk? || r.RTailFail?) { return; }
    assert LiveOk(P, live, tbl);
    TailArgs(P, live, tbl, c, c', er, j);
    FlTop(P, ell, c);
    assert FloorsOk(P, ell);
    FlFrame(P, ell, c, |c.fr| - 1);
    var hc := HCtx(0, [], e, Bot, map[]);
    var w := SiteWin(P, D, Pp, ell, xR, obsv, j, c', hc);
    assert w.sp == Api.TailSiteSpec(Fl(P, ell, j));
    assert Valid(w.raw, w.sp);
    assert Checker.Validate(w.raw, w.sp) == Checker.Validated by { reveal Valid(); }
    Soundness.ValidateOk(w.raw, w.sp);
    SiteWinAt(P, D, ell, live, tbl, w, j);
    HooksOkLayout(P, D, ell);
    assert Wh(w.c0) == Wh(c);
    assert TailHOk(w);
    assert HelperOk(w);
    assert Rel(Reg(Top(c), 10), Reg(Top(c'), 10));
    BRInit(c', E(D, j));
    WinPreIntro(w);
    WinPreFacts(w);
    SideInit(w);
    var fuel := S.NumInsns(w.raw) + 1;
    var rest := Bridge(w, w.c0, w.s0, [], fuel);
    Soundness.Soundness(w.raw, w.sp, w.s0.regs, w.s0.stack, rest, fuel);
    assert [] + rest == rest;
    var O := S.Run(w.raw, w.sp.floor, w.s0, rest, fuel);
    assert WindowRun(w.raw, w.sp, S.InitState(w.s0.regs, w.s0.stack), rest, fuel) == O;
    assert O.Done? && FinalOk(w.sp, w.s0, O.s);
    assert FinalOkO(w.sp, w.s0, O.s) by { reveal FinalOkO(); }
    if r.RTailOk? {
      assert TailOkW(w);
      var k := EndsTail(w, w.c0, O.s, false);
      assert TailT(w) == TTail(r.q, args[0], c.L.(budget := if c.L.budget > 0 then c.L.budget - 1 else 0), c.h + [e]);
      assert StepP(P, xP, c) == Done(TailT(w));
    } else {
      assert !TailOkW(w);
      RunDonePc(w.raw, w.sp.floor, w.s0, rest, fuel);
      var k, c2 := EndsGet(w, w.c0, O.s, false);
      var sf := O.s;
      var c1 := TailFailC(xP, c, e);
      assert StepP(P, xP, c) == Go(c1);
      TailFailFinish(xP, c, e);
      NextE(P, D, j);
      assert Owner(P, j + 1) == Owner(P, j) by { assert j + 1 !in FnSet(P); }
      assert w.base + S.NumInsns(w.raw) == E(D, j + 1);
      SiteAfter(P, D, ell, live, w, c, er, c1, c2, sf, j, xP);
    }
  }

  // Corr at e(0) for a P' state whose top frame kept r1, r10 and L, h of the input.
  lemma {:isolate_assertions} InitCorr(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, L: Local, c2: Cfg)
    requires 0 < |P| && |c2.fr| == 1 && FrameOk(Top(c2)) && Top(c2).kind == Main && Top(c2).pc == E(D, 0)
    requires Top(c2).regs[1] == W(CTX) && Top(c2).regs[10] == W(StackTop(0))
    requires c2.L == L && c2.h == []
    ensures Corr(P, D, ell, live, InitP(L), c2, {})
  {
    var c := InitP(L);
    forall r | 0 <= r < NR ensures Rel(Reg(Top(c), r), Reg(Top(c2), r)) {
      assert Top(c).regs[r] == if r == 1 then W(CTX) else if r == 10 then W(StackTop(0)) else Bot;
    }
    forall o | 0 <= o < STK ensures RelB(Top(c).stack[o], Top(c2).stack[o]) { assert Top(c).stack[o] == BBot; }
    assert RegRel(c, c2, {}, live(Top(c).pc));
    assert StkRel(c, c2, Fl(P, ell, Top(c).fn));
    LowRelOne(P, D, ell, c, c2);
    assert TopRel(P, D, ell, live, c, c2, {});
    CorrIntro(P, D, ell, live, c, c2, {});
  }

  // The initial configuration of P'.
  lemma InitRFacts(L: Local, hv: nat -> bv64)
    ensures var c0 := InitR(L, hv);
      |c0.fr| == 1 && Top(c0) == c0.fr[0] && FrameOk(Top(c0)) && Top(c0).kind == Main && Top(c0).pc == 0
      && Top(c0).regs[1] == W(CTX) && Top(c0).regs[10] == W(StackTop(0)) && c0.L == L && c0.h == []
  {
    var c0 := InitR(L, hv);
    assert forall k | 0 <= k < NR :: Top(c0).regs[k].W?;
    assert forall o | 0 <= o < STK :: Top(c0).stack[o].B?;
  }

  lemma {:isolate_assertions} EntryWinAt(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                         tbl: bv32 -> set<nat>, w: Win)
    requires Structure(P, D, w.Pp, ell, live, tbl)
    requires w.raw == D.pro0 && w.base == 0 && w.hp == -1
    ensures WinAt(w) && !HasHelper(w)
  {
    var Pp := w.Pp;
    assert PiecesOk(P, D) && CallsOk(D, Pp) && Pp == Layout(P, D);
    assert Bytes8(D.pro0) && NoHelperIn(D.pro0);
    AllFnsWFOk(P, D);
    if NI(D.pro0) > 0 { CodePro(P, D, NI(D.pro0) - 1); }
    assert S.NumInsns(w.raw) <= |Pp.code|;
    forall r | 0 <= r < S.NumInsns(w.raw) && r != w.hp
      ensures w.Pp.code[w.base + r] == N(S.InsnAt(w.raw, r)) && !IsHelperCall(S.InsnAt(w.raw, r))
          && (w.sp.hookCalls && S.Decode(S.InsnAt(w.raw, r)).Some? && S.Decode(S.InsnAt(w.raw, r)).value.CallLocal? ==>
                w.base + r + 1 + Signed32(S.Decode(S.InsnAt(w.raw, r)).value.imm) in w.Pp.hooks)
    {
      CodePro(P, D, r);
      assert S.InsnAt(w.raw, r) == Slice(D.pro0, r);
      assert Pp.code[r].N? && Pp.code[r].b == S.InsnAt(w.raw, r);
      forall i | i in D.wrap ensures r != K(D, i) {
        StartMono(D, 0, i);
      }
      assert !(exists i :: i in D.wrap && r == K(D, i));
    }
    assert WinAt(w);
  }

  // The base case: the run of P' passes Pro_0 and reaches e(0) related to the initial state of P.
  lemma {:isolate_assertions} EntryStep(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, L: Local, om: Oracle, hv: nat -> bv64)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A5(obsv)
    ensures exists n: nat, c': Cfg :: ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, InitR(L, hv), n) == Some(c')
                                      && Corr(P, D, ell, live, InitP(L), c', {})
  {
    var xR := CtxR(Pp, env, sem, om, hv);
    var c0 := InitR(L, hv);
    assert PiecesOk(P, D);
    E0Pro(P, D);
    InitRFacts(L, hv);
    if |D.pro0| == 0 {
      assert NI(D.pro0) == 0;
      InitCorr(P, D, ell, live, L, c0);
      assert ReachR(Pp, xR, obsv, c0, 0) == Some(c0);
    } else {
      OwnerSingle0(P);
      var fl := Fl(P, ell, 0);
      assert FloorsOk(P, ell) && 0 in FnSet(P);
      Floor8Bounds(ell(0));
      var sp := Api.EntryPrologueSpec(fl);
      var s0 := S.InitState(R64(Top(c0)), Plain(Top(c0).stack));
      var w := Win(Pp, xR, obsv, D.pro0, sp, 0, -1, Exit, 0, HCtx(0, [], EMg(0), Bot, map[]), c0, s0);
      assert Valid(w.raw, w.sp);
      assert Checker.Validate(w.raw, w.sp) == Checker.Validated by { reveal Valid(); }
      Soundness.ValidateOk(w.raw, w.sp);
      EntryWinAt(P, D, ell, live, tbl, w);
      HooksOkLayout(P, D, ell);
      assert BR(w.c0, w.s0, w.base);
      WinPreIntro(w);
      var k, c2, sf := RunWindow(w);
      SideFacts(w, c2, sf);
      assert CountHelpers(sf.events) == 0;
      Side0(w, c2, sf);
      assert |c2.fr| == 1 && Top(c2) == c2.fr[0];
      assert Top(c2).regs[1] == W(sf.regs[1]) && sf.regs[1] == s0.regs[1] == CTX;
      assert Top(c2).regs[10] == W(sf.regs[10]) && sf.regs[10] == s0.regs[10] == StackTop(0);
      InitCorr(P, D, ell, live, L, c2);
    }
  }

  lemma OwnerSingle0(P: seq<OInstr>) ensures Owner(P, 0) == 0 {}

  lemma SimInitProof(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                     tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                     L: Local, om: Oracle, hv: nat -> bv64)
    requires Hyp(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm) && A8(om) && Adm(L, om)
    ensures exists n: nat, c': Cfg ::
      ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, InitR(L, hv), n) == Bits.Some(c')
      && Corr(P, D, ell, live, InitP(L), c', {})
  {
    EntryStep(P, D, Pp, ell, live, tbl, env, sem, obsv, L, om, hv);
  }
}

