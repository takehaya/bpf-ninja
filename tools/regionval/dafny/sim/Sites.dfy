// A validated window of P', run in the whole model, ends where the region
// model says, related to the step of P it replaces: site windows (P1c, P2
// with MF, P3, P5) around an original helper call, and the entry prologue
// (P1).  The site lemma is stated for single-function programs.
include "Bridge.dfy"
include "LayoutFacts.dfy"

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
    requires WinPre(w) && Checker.Validate(w.raw, w.sp) == Checker.Validated && !w.sp.exitMode
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
      forall k | 0 <= k < 8 ensures raw[8 * r + k] == post[8 * q + k] { assert raw[|pm| + (8 * q + k)] == post[8 * q + k]; }
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

  // The scope of the single-function step lemma: one function, no
  // wrapper (P8) and no tail-call site (P4).
  ghost predicate Single(P: seq<OInstr>, D: Decomp) {
    FnSet(P) == {0} && (forall j | 0 <= j < |P| :: !P[j].Call? && !P[j].CbCall?)
    && D.wrap == map[] && (forall i | i in D.site :: i < |P| && !P[i].Tail?)
  }

  // A reachable configuration of a single-function P: the main frame only, r10 intact.
  ghost predicate Inv1(c: Cfg) {
    |c.fr| == 1 && c.fr[0].fn == 0 && c.fr[0].kind == Main && |c.fr[0].regs| == NR && |c.fr[0].stack| == STK
    && c.fr[0].regs[10] == W(StackTop(0))
  }

  lemma OwnerSingle(P: seq<OInstr>, i: nat)
    requires FnSet(P) == {0}
    ensures Owner(P, i) == 0
    decreases i
  {
    if i > 0 { OwnerSingle(P, i - 1); }
  }

  lemma Floor8Bounds(l: int)
    requires -(STK as int) <= l <= 0
    ensures -(STK as int) <= Floor8(l) <= l
  {
    assert l / 8 >= -64;
  }

  ghost predicate RegRel(c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>) {
    forall r | 0 <= r < NR :: Rel(Reg(Top(c), r), Reg(Top(c'), r)) || (r in er && 1 <= r <= 5 && r !in lv)
  }
  ghost predicate StkRel(c: Cfg, c': Cfg, fl: int) {
    |Top(c).stack| == STK && |Top(c').stack| == STK
    && forall o | 0 <= o < STK && o - STK as int >= fl :: RelB(Top(c).stack[o], Top(c').stack[o])
  }

  lemma CorrIntro1(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, c: Cfg, c': Cfg, er: set<nat>)
    requires Inv1(c) && |c'.fr| == 1 && FrameOk(Top(c')) && Top(c').kind == Main
    requires 0 <= Top(c).pc < |P| && Top(c').pc == E(D, Top(c).pc)
    requires RegRel(c, c', er, live(Top(c).pc)) && StkRel(c, c', Fl(P, ell, 0))
    requires c'.L == c.L && c'.h == c.h
    ensures Corr(P, D, ell, live, c, c', er)
  {
    assert Top(c) == c.fr[0] && Top(c') == c'.fr[0];
  }

  lemma CorrElim1(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, c: Cfg, c': Cfg, er: set<nat>)
    requires Inv1(c) && Corr(P, D, ell, live, c, c', er)
    ensures |c'.fr| == 1 && FrameOk(Top(c')) && Top(c').kind == Main
    ensures 0 <= Top(c).pc < |P| && Top(c').pc == E(D, Top(c).pc)
    ensures RegRel(c, c', er, live(Top(c).pc)) && StkRel(c, c', Fl(P, ell, 0))
    ensures c'.L == c.L && c'.h == c.h
  {
    assert Top(c) == c.fr[0] && Top(c') == c'.fr[0];
    forall k | 0 <= k < NR ensures c'.fr[0].regs[k].W? { assert Reg(c'.fr[0], k).W?; }
  }

  // ---------------- the helper step of P ----------------

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

  lemma FrameOfIn(p: bv64, w: nat, d: nat)
    requires FrameOf(p, w, d).Some?
    ensures FrameOf(p, w, d).value < MAXF_RW && S.InFrame(S.Rel(p, StackTop(FrameOf(p, w, d).value)), w)
    decreases d
  {
    if !(d - 1 < MAXF_RW && S.InFrame(S.Rel(p, StackTop(d - 1)), w)) { FrameOfIn(p, w, d - 1); }
  }

  lemma ClassifyStack(p: bv64, w: nat, nfr: nat, dom: set<int>)
    requires Classify(p, w, nfr, dom).InStack?
    ensures Classify(p, w, nfr, dom).d < nfr && Classify(p, w, nfr, dom).o + w <= STK
  {
    reveal Classify();
    assert FrameOf(p, w, nfr).Some?;
    FrameOfIn(p, w, nfr);
  }

  // A footprint address in the stack is in the top frame at or above fl.
  ghost predicate FootIn(c: Cfg, a: bv64, fl: int) {
    match Classify(a, 1, |c.fr|, c.L.mem.Keys)
    case InStack(d, o) => o as int - STK as int >= fl
    case _ => true
  }

  lemma {:isolate_assertions} FootRel(c: Cfg, c': Cfg, addrs: seq<bv64>, fl: int)
    requires |c.fr| == 1 && |c'.fr| == 1 && c'.L == c.L
    requires StkRel(c, c', fl)
    requires forall i | 0 <= i < |addrs| :: FootIn(c, addrs[i], fl)
    requires FootBytes(c, addrs).FOk?
    ensures FootBytes(c', addrs) == FootBytes(c, addrs)
    decreases |addrs|
  {
    reveal FootBytes();
    if |addrs| > 0 {
      assert forall i | 0 <= i < |addrs[1..]| :: FootIn(c, addrs[1..][i], fl) by {
        forall i | 0 <= i < |addrs[1..]| ensures FootIn(c, addrs[1..][i], fl) { assert addrs[1..][i] == addrs[i + 1]; }
      }
      var cl := Classify(addrs[0], 1, |c.fr|, c.L.mem.Keys);
      assert Classify(addrs[0], 1, |c'.fr|, c'.L.mem.Keys) == cl;
      assert FootBytes(c, addrs[1..]).FOk?;
      FootRel(c, c', addrs[1..], fl);
      match cl
      case InStack(d, o) =>
        ClassifyStack(addrs[0], 1, |c.fr|, c.L.mem.Keys);
        assert d == 0 && o < STK && FootIn(c, addrs[0], fl);
        assert Top(c) == c.fr[0] && Top(c') == c'.fr[0];
        assert RelB(c.fr[0].stack[o], c'.fr[0].stack[o]);
        assert StackBytes(c, d, o, 1) == [c.fr[0].stack[o]];
        assert StackBytes(c', d, o, 1) == [c'.fr[0].stack[o]];
      case _ =>
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
    requires Inv1(c) && 0 <= Top(c).pc < |P| && P[Top(c).pc] == Hcall(false, id) && idx == Top(c).pc
    requires forall a | a in Acc(P, x, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires n == x.env.arity(false, id) && Rds(Top(c), Upto(1, n)) == Some(args)
    requires FootBytes(c, x.env.foot(false, id, args)) == FOk(beta)
    requires x.om(c.h, ECall(idx, false, id, args, beta), Wh(c)) == RRet(v, wr)
    ensures forall i | 0 <= i < |x.env.foot(false, id, args)| :: FootIn(c, x.env.foot(false, id, args)[i], ell(0))
    ensures forall o: nat | o < STK && o as int - STK as int < ell(0) :: SAddr(0, o) as int !in wr
  {
    var addrs := x.env.foot(false, id, args);
    assert Acc(P, x, c) == HelperAcc(x, c, idx, false, id);
    HelperAccIs(x, c, idx, id, n, args, beta, v, wr);
    assert FootAcc(c, addrs) <= Acc(P, x, c);
    assert WrAcc(c, wr) <= Acc(P, x, c);
    forall i | 0 <= i < |addrs| ensures FootIn(c, addrs[i], ell(0)) {
      if Classify(addrs[i], 1, |c.fr|, c.L.mem.Keys).InStack? { FootAccHas(c, addrs, i); }
    }
    forall o: nat | o < STK && o as int - STK as int < ell(0) ensures SAddr(0, o) as int !in wr {
      if SAddr(0, o) as int in wr { assert (0, o) in WrAcc(c, wr); }
    }
  }

  // ---------------- site windows ----------------

  // The window of a site helper at j, entered at c' (the region state is c''s top frame).
  ghost function SiteWin(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, xR: Ctx, obsv: Observer,
                         j: nat, c': Cfg, hc: HCtx): Win
    requires j in D.site && j < |P|
  {
    Win(Pp, xR, obsv, D.site[j].pre + Enc(P[j]) + D.site[j].post,
        SiteSpecFor(P[j], Fl(P, ell, j), D.site[j].binds), E(D, j),
        NI(D.site[j].pre), P[j], j, hc, c', S.InitState(R64(Top(c')), Plain(Top(c').stack)))
  }

  lemma {:isolate_assertions} SiteWinAt(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                        tbl: bv32 -> set<nat>, w: Win, j: nat)
    requires Structure(P, D, w.Pp, ell, live, tbl)
    requires j in D.site && j < |P| && D.wrap == map[] && P[j].Hcall? && !P[j].kf
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
    DecodeEncHelper(P[j].id);
    assert Enc(P[j]) == EncHelper(P[j].id);
    var n := NI(site.pre) + 1 + NI(site.post);
    RawAt(site.pre, Enc(P[j]), site.post, w.hp);
    assert Reloc(D, P[j]) == P[j];
    forall r | 0 <= r < n && r != w.hp
      ensures Pp.code[w.base + r] == N(S.InsnAt(w.raw, r)) && !IsHelperCall(S.InsnAt(w.raw, r))
      ensures w.sp.hookCalls && S.Decode(S.InsnAt(w.raw, r)).Some? && S.Decode(S.InsnAt(w.raw, r)).value.CallLocal? ==>
                w.base + r + 1 + Signed32(S.Decode(S.InsnAt(w.raw, r)).value.imm) in Pp.hooks
    {
      RawAt(site.pre, Enc(P[j]), site.post, r);
      if r < NI(site.pre) {
        assert Pp.code[w.base + r] == N(Slice(site.pre, r));
      } else {
        var q := r - NI(site.pre) - 1;
        assert w.base + r == K(D, j) + 1 + q;
        assert Pp.code[w.base + r] == N(Slice(site.post, q));
      }
      var p := w.base + r;
      assert !(exists i :: i in D.wrap && p == K(D, i));
    }
  }

  lemma {:isolate_assertions} SiteHelperOk(P: seq<OInstr>, ell: nat -> int, w: Win, c: Cfg, xP: Ctx,
                                           n: nat, args: seq<bv64>, beta: seq<bv8>, v: Val, wr: map<int, bv8>)
    requires Inv1(c) && |w.c0.fr| == 1 && w.c0.L == c.L && w.c0.h == c.h && Top(w.c0).kind == Main
    requires w.hins.Hcall? && !w.hins.kf && w.x.env == xP.env && w.x.om == xP.om
    requires n == xP.env.arity(false, w.hins.id) && n <= 5
    requires SimFacts.Words(Top(w.c0), Upto(1, n)) == args
    requires FootBytes(w.c0, xP.env.foot(false, w.hins.id, args)) == FOk(beta)
    requires xP.om(c.h, ECall(w.hidx, false, w.hins.id, args, beta), Wh(c)) == RRet(v, wr)
    requires w.hc == HCtx(n, xP.env.foot(false, w.hins.id, args), ECall(w.hidx, false, w.hins.id, args, beta), v, wr)
    requires forall i | 0 <= i < |w.hc.addrs| :: FootIn(c, w.hc.addrs[i], ell(0))
    requires forall o: nat | o < STK && o as int - STK as int < ell(0) :: SAddr(0, o) as int !in wr
    requires w.sp.floor <= ell(0)
    ensures HelperOk(w)
  {
    assert Wh(w.c0) == Wh(c);
    forall i | 0 <= i < |w.hc.addrs| ensures
      match Classify(w.hc.addrs[i], 1, |w.c0.fr|, w.c0.L.mem.Keys)
      case InStack(d, o) => d == |w.c0.fr| - 1 ==> o >= STK as int + w.sp.floor
      case _ => true
    {
      assert FootIn(c, w.hc.addrs[i], ell(0));
    }
    assert FootTop(w.c0, w.hc.addrs, w.sp.floor);
    assert WrTop(w.c0, wr, w.sp.floor);
  }

  // The configurations after a site window and after the helper step of P are related.
  lemma {:isolate_assertions} SiteAfter(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
      w: Win, c: Cfg, er: set<nat>, c1: Cfg, c2: Cfg, sf: S.CState, j: nat, xP: Ctx)
    requires xP.m.MP?
    requires Inv1(c) && Corr(P, D, ell, live, c, w.c0, er) && Top(c).pc == j
    requires WinPre(w) && w.sp.helper == Helper(true, true) && w.sp.floor == Fl(P, ell, 0)
    requires w.s0 == S.InitState(R64(Top(w.c0)), Plain(Top(w.c0).stack))
    requires w.base + S.NumInsns(w.raw) == E(D, j + 1) && j + 1 < |P|
    requires Finish(xP, c.(h := c.h + [w.hc.eh]), w.hc.v, w.hc.wr) == Go(c1)
    requires BR(c2, sf, w.base) && Side(w, c2, sf) && FinalOk(w.sp, w.s0, sf) && sf.pc == S.NumInsns(w.raw)
    ensures Inv1(c1) && Corr(P, D, ell, live, c1, c2, {})
  {
    var c0 := w.c0;
    var wr := w.hc.wr;
    var v := w.hc.v;
    CorrElim1(P, D, ell, live, c, c0, er);
    var ch := c.(h := c.h + [w.hc.eh]);
    FinishFacts(xP, ch, v, wr);
    ApplyWAt(ch, wr);
    ApplyWAt(c0, wr);
    SideFacts(w, c2, sf);
    assert CountHelpers(sf.events) == 1;
    Side1(w, c2, sf);
    assert Top(ch) == Top(c);
    assert |c1.fr| == 1 && Top(c1) == c1.fr[0];
    assert |Top(c1).stack| == STK;
    assert Inv1(c1);
    assert Top(c2) == c2.fr[0] && |c2.fr| == 1;
    forall r | 0 <= r < NR ensures Rel(Reg(Top(c1), r), Reg(Top(c2), r)) {
      assert Top(c2).regs[r] == W(sf.regs[r]);
      if r == 0 {
        if v.W? { assert sf.regs[0] == HelperRet(sf.events) == v.w; }
      } else if r <= 5 {
        assert Top(c1).regs[r] == Und(xP, ch, r) == Bot;
      } else {
        assert Top(c1).regs[r] == Top(c).regs[r];
        assert sf.regs[r] == w.s0.regs[r] == R64(Top(c0))[r];
        assert Top(c0).regs[r] == W(R64(Top(c0))[r]);
        assert Rel(Reg(Top(c), r), Reg(Top(c0), r));
      }
    }
    assert RegRel(c1, c2, {}, live(Top(c1).pc));
    forall o | 0 <= o < STK && o - STK as int >= Fl(P, ell, 0) ensures RelB(Top(c1).stack[o], Top(c2).stack[o]) {
      assert Top(c1).stack[o] == ApplyF(Top(c), 0, wr).stack[o];
      assert Top(c2).stack[o] == B(sf.stack[o]);
      assert sf.stack[o] == UpperBase(sf.events, w.s0.stack)[o];
      assert Top(ApplyW(c0, wr)) == ApplyF(Top(c0), 0, wr);
      assert sf.stack[o] == Plain(ApplyF(Top(c0), 0, wr).stack)[o];
      assert RelB(Top(c).stack[o], Top(c0).stack[o]);
    }
    assert StkRel(c1, c2, Fl(P, ell, 0));
    assert c2.L == c1.L && c2.h == c1.h;
    assert Top(c1).pc == j + 1 && Top(c2).pc == w.base + sf.pc;
    assert 0 <= Top(c1).pc < |P| && Top(c2).pc == E(D, Top(c1).pc);
    assert Top(c2).kind == Top(c0).kind == Main && FrameOk(Top(c2));
    CorrIntro1(P, D, ell, live, c1, c2, {});
  }

  // The site lemma: the helper step of P at a site is matched by the run of its window.
  lemma {:isolate_assertions} SiteStep(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64,
      c: Cfg, c': Cfg, er: set<nat>, c1: Cfg)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A3b(env, tbl) && A5(obsv)
    requires Single(P, D) && Inv1(c)
    requires forall a | a in Acc(P, CtxP(P, env, sem, om), c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.site
    requires StepP(P, CtxP(P, env, sem, om), c) == Go(c1)
    ensures Inv1(c1)
    ensures exists k: nat, c1': Cfg :: ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Some(c1')
                                       && Corr(P, D, ell, live, c1, c1', {})
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    var j := Top(c).pc;
    CorrElim1(P, D, ell, live, c, c', er);
    assert PiecesOk(P, D);
    assert j < |P| && P[j].Hcall? && !P[j].kf;
    var id := P[j].id;
    assert StepP(P, xP, c) == HelperStep(xP, c, j, false, id, false);
    var nA, args, beta, v, wr := HelperGo(xP, c, j, id, c1);
    var addrs := env.foot(false, id, args);
    var e := ECall(j, false, id, args, beta);
    OwnerSingle(P, j);
    var fl := Fl(P, ell, j);
    assert fl == Floor8(ell(0)) == Fl(P, ell, 0);
    assert FloorsOk(P, ell) && 0 in FnSet(P);
    Floor8Bounds(ell(0));
    assert c.fr[0].fn == 0;
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
    assert StkRel(c, c', ell(0));
    FootRel(c, c', addrs, ell(0));
    // the window
    var hc := HCtx(nA, addrs, e, v, wr);
    var w := SiteWin(P, D, Pp, ell, xR, obsv, j, c', hc);
    assert Valid(w.raw, w.sp);
    assert Checker.Validate(w.raw, w.sp) == Checker.Validated by { reveal Valid(); }
    Soundness.ValidateOk(w.raw, w.sp);
    SiteWinAt(P, D, ell, live, tbl, w, j);
    HooksOkLayout(P, D, ell);
    SiteHelperOk(P, ell, w, c, xP, nA, args, beta, v, wr);
    assert BR(w.c0, w.s0, w.base);
    assert WinPre(w) by { reveal WinPreO(); }
    var k, c2, sf := RunWindow(w);
    NextE(P, D, j);
    SiteAfter(P, D, ell, live, w, c, er, c1, c2, sf, j, xP);
  }

  // ---------------- the entry prologue (P1) ----------------

  lemma InitInv(L: Local) ensures Inv1(InitP(L)) {}

  // Corr at e(0) for a P' state whose top frame kept r1, r10 and L, h of the input.
  lemma {:isolate_assertions} InitCorr(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, L: Local, c2: Cfg)
    requires 0 < |P| && |c2.fr| == 1 && FrameOk(Top(c2)) && Top(c2).kind == Main && Top(c2).pc == E(D, 0)
    requires Top(c2).regs[1] == W(CTX) && Top(c2).regs[10] == W(StackTop(0))
    requires c2.L == L && c2.h == []
    ensures Corr(P, D, ell, live, InitP(L), c2, {})
  {
    var c := InitP(L);
    InitInv(L);
    forall r | 0 <= r < NR ensures Rel(Reg(Top(c), r), Reg(Top(c2), r)) {
      assert Top(c).regs[r] == if r == 1 then W(CTX) else if r == 10 then W(StackTop(0)) else Bot;
    }
    forall o | 0 <= o < STK ensures RelB(Top(c).stack[o], Top(c2).stack[o]) { assert Top(c).stack[o] == BBot; }
    assert RegRel(c, c2, {}, live(Top(c).pc));
    assert StkRel(c, c2, Fl(P, ell, 0));
    CorrIntro1(P, D, ell, live, c, c2, {});
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
    assert Top(c0) == c0.fr[0];
    forall k | 0 <= k < NR ensures Top(c0).regs[k].W? {}
    forall o | 0 <= o < STK ensures Top(c0).stack[o].B? {}
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
      assert WinPre(w) by { reveal WinPreO(); }
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

