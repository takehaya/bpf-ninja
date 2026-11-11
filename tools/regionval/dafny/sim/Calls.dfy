// Function entries in P': the prologue FP(G) of P1b and P9 after a call or
// a callback invocation, and the pass load PL(i) of P9 before a call.
include "Classes.dfy"

module SimCalls {
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
  import opened SimClasses
  import SimFacts
  import Soundness
  import Checker
  import Api

  // ---------------- layout ----------------

  // FP(g) sits between fe(g) and e(g).
  lemma {:isolate_assertions} FPCode(P: seq<OInstr>, D: Decomp, g: nat)
    requires g < |P| && AllFnsWF(P, D) && g in D.fp
    ensures E(D, g) == FE(D, g) + NI(D.fp[g].code) && E(D, g) < |Layout(P, D).code|
    ensures forall r | 0 <= r < NI(D.fp[g].code) ::
      FE(D, g) + r < |Layout(P, D).code| && Layout(P, D).code[FE(D, g) + r] == N(Slice(D.fp[g].code, r))
    ensures forall r | 0 <= r < NI(D.fp[g].code) :: PlacedAt(Layout(P, D), FE(D, g), D.fp[g].code, r)
  {
    BlockParts(P, D, g);
    var fl := FnsLen(D, FnsAt(D, g));
    forall r | 0 <= r < NI(D.fp[g].code)
      ensures FE(D, g) + r < |Layout(P, D).code| && Layout(P, D).code[FE(D, g) + r] == N(Slice(D.fp[g].code, r))
      ensures PlacedAt(Layout(P, D), FE(D, g), D.fp[g].code, r)
    {
      CodeAt(P, D, g, fl + r);
    }
    CodeAt(P, D, g, fl + FPLen(D, g));
  }

  // PL(i) sits between e(i) and kappa(i), which holds the call.
  lemma {:isolate_assertions} PLCode(P: seq<OInstr>, D: Decomp, i: nat)
    requires i < |P| && AllFnsWF(P, D) && i in D.pl && i !in D.site && i !in D.wrap
    ensures K(D, i) == E(D, i) + NI(D.pl[i].code) && K(D, i) < |Layout(P, D).code|
    ensures forall r | 0 <= r < NI(D.pl[i].code) ::
      E(D, i) + r < |Layout(P, D).code| && Layout(P, D).code[E(D, i) + r] == N(Slice(D.pl[i].code, r))
    ensures Layout(P, D).code[K(D, i)] == O(Reloc(D, P[i]), i)
    ensures forall r | 0 <= r < NI(D.pl[i].code) :: PlacedAt(Layout(P, D), E(D, i), D.pl[i].code, r)
  {
    BlockParts(P, D, i);
    var fl := FnsLen(D, FnsAt(D, i));
    var fp := FPLen(D, i);
    forall r | 0 <= r < NI(D.pl[i].code)
      ensures E(D, i) + r < |Layout(P, D).code| && Layout(P, D).code[E(D, i) + r] == N(Slice(D.pl[i].code, r))
      ensures PlacedAt(Layout(P, D), E(D, i), D.pl[i].code, r)
    {
      CodeAt(P, D, i, fl + fp + r);
    }
    CodeAt(P, D, i, fl + fp + NI(D.pl[i].code));
  }

  ghost predicate PlacedAt(Pp: RwProg, base: int, raw: seq<bv8>, r: nat) {
    0 <= base + r < |Pp.code| && 8 * r + 8 <= |raw| && Pp.code[base + r] == N(Slice(raw, r))
  }

  // A window of inserted code only (no helper, no hook call) laid out at base.
  lemma {:isolate_assertions} PlainWinAt(P: seq<OInstr>, D: Decomp, w: Win)
    requires w.Pp == Layout(P, D) && |w.raw| % 8 == 0 && NoHelperIn(w.raw) && w.hp == -1 && !w.sp.hookCalls && 0 <= w.base
    requires w.base + NI(w.raw) <= |w.Pp.code|
    requires forall r | 0 <= r < NI(w.raw) :: PlacedAt(w.Pp, w.base, w.raw, r)
    ensures WinAt(w) && !HasHelper(w)
  {
    var n := S.NumInsns(w.raw);
    assert n == NI(w.raw);
    if n > 0 { assert PlacedAt(w.Pp, w.base, w.raw, n - 1); }
    forall r | 0 <= r < n ensures w.Pp.code[w.base + r] == N(S.InsnAt(w.raw, r)) && !IsHelperCall(S.InsnAt(w.raw, r)) {
      assert PlacedAt(w.Pp, w.base, w.raw, r);
      assert S.InsnAt(w.raw, r) == Slice(w.raw, r);
    }
  }

  // The registers a pass load keeps.
  lemma PassLoadRegs(f: int, G: nat, s0: S.CState, sf: S.CState)
    requires S.CWF(s0) && FinalOk(Api.PassLoadSpec(f, G), s0, sf)
    ensures S.CWF(sf) && forall k | 0 <= k <= 10 && k != G :: sf.regs[k] == s0.regs[k]
  {
    var sp := Api.PassLoadSpec(f, G);
    FinalFacts(sp, s0, sf);
    assert !R0Special(sp) && sp.free == {G};
  }

  // ---------------- the prologue of a function entry ----------------

  ghost function FPSpec(P: seq<OInstr>, D: Decomp, ell: nat -> int, g: nat): Spec requires g in D.fp {
    if D.fp[g].kind == FP1b then Api.CallbackPrologueSpec(Fl(P, ell, g)) else Api.PassPrologueSpec(Fl(P, ell, g))
  }

  // After the prologue: only r0 may differ (it is unreadable in P at an entry), bytes below the floor.
  lemma {:isolate_assertions} EnterAfter(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                         w: Win, c1: Cfg, c1': Cfg, er: set<nat>, c2: Cfg, sf: S.CState)
    requires 0 <= Top(c1).pc && Inv(P, c1) && PendK(P, D, ell, live, c1, c1', er) && w.c0 == c1'
    requires WinPre(w) && !HasHelper(w) && w.sp.helper.NoHelper? && !w.sp.exitMode && w.sp.free <= {0}
    requires w.sp.floor == Fl(P, ell, Top(c1).fn)
    requires w.s0 == S.InitState(R64(Top(c1')), Plain(Top(c1').stack))
    requires w.base + S.NumInsns(w.raw) == E(D, Top(c1).pc)
    requires BR(c2, sf, w.base) && Side(w, c2, sf) && FinalOk(w.sp, w.s0, sf) && sf.pc == S.NumInsns(w.raw)
    ensures Corr(P, D, ell, live, c1, c2, er)
  {
    reveal PendK();
    var g := Top(c1).pc;
    var c1x := Put(c1', Top(c1').(pc := E(D, g)));
    CorrElim(P, D, ell, live, c1, c1x, er);
    LowRelLen(P, D, ell, c1, c1x);
    assert |c1'.fr| == |c1x.fr| && Below(c1x) == Below(c1');
    SideFacts(w, c2, sf);
    assert CountHelpers(sf.events) == 0;
    Side0(w, c2, sf);
    LowRelSame(P, D, ell, c1, c1x, c1, c2);
    assert Top(c1x) == Top(c1').(pc := E(D, g));
    forall r | 0 <= r < NR ensures Rel(Reg(Top(c1), r), Reg(Top(c2), r)) || (r in er && 1 <= r <= 5 && r !in live(g)) {
      if r == 0 {
      } else {
        assert Top(c2).regs[r] == W(sf.regs[r]);
        assert r !in w.sp.free;
        assert sf.regs[r] == w.s0.regs[r] == R64(Top(c1'))[r];
        assert Top(c1').regs[r] == W(R64(Top(c1'))[r]);
        assert Reg(Top(c1x), r) == Reg(Top(c1'), r);
      }
    }
    assert RegRel(c1, c2, er, live(g));
    forall o | 0 <= o < STK && o - STK as int >= Fl(P, ell, Top(c1).fn) ensures RelB(Top(c1).stack[o], Top(c2).stack[o]) {
      assert Top(c2).stack[o] == Top(c1').stack[o] == Top(c1x).stack[o];
    }
    assert StkRel(c1, c2, Fl(P, ell, Top(c1).fn));
    assert TopRel(P, D, ell, live, c1, c2, er);
    CorrIntro(P, D, ell, live, c1, c2, er);
  }

  // P' runs FP(g) after a call or callback invocation and reaches e(g), related.
  lemma {:isolate_assertions} EnterFn(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64, c1: Cfg, c1': Cfg, er: set<nat>)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A5(obsv)
    requires Inv(P, c1) && PendK(P, D, ell, live, c1, c1', er)
    ensures exists k: nat, c2: Cfg :: ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c1', k) == Some(c2)
                                      && Corr(P, D, ell, live, c1, c2, er)
  {
    var xR := CtxR(Pp, env, sem, om, hv);
    reveal PendK();
    var g: nat := Top(c1).pc;
    InvIs(P, c1);
    OwnerFn(P, g);
    assert Top(c1).fn == g;
    assert PiecesOk(P, D) && Pp == Layout(P, D);
    AllFnsWFOk(P, D);
    if g !in D.fp {
      assert E(D, g) == FE(D, g);
      assert Top(c1').(pc := E(D, g)) == Top(c1');
      PutSame(c1');
      assert ReachR(Pp, xR, obsv, c1', 0) == Some(c1');
    } else {
      var code := D.fp[g].code;
      var sp := FPSpec(P, D, ell, g);
      FPCode(P, D, g);
      var c1x := Put(c1', Top(c1').(pc := E(D, g)));
      CorrElim(P, D, ell, live, c1, c1x, er);
      assert Top(c1x) == Top(c1').(pc := E(D, g));
      assert FrameOk(Top(c1'));
      LowRelLen(P, D, ell, c1, c1x);
      var s0 := S.InitState(R64(Top(c1')), Plain(Top(c1').stack));
      var w := Win(Pp, xR, obsv, code, sp, FE(D, g), -1, Exit, 0, HCtx(0, [], EMg(0), Bot, map[]), c1', s0);
      assert Valid(code, sp);
      assert Checker.Validate(w.raw, w.sp) == Checker.Validated by { reveal Valid(); }
      Soundness.ValidateOk(w.raw, w.sp);
      assert Bytes8(code) && NoHelperIn(code);
      PlainWinAt(P, D, w);
      HooksOkLayout(P, D, ell);
      assert FloorsOk(P, ell);
      FlFrame(P, ell, c1, |c1.fr| - 1);
      assert |c1'.fr| == |c1.fr| <= MAXF;
      assert Top(c1').pc == FE(D, g);
      assert Rel(Reg(Top(c1), 10), Reg(Top(c1x), 10));
      BRInit(c1', FE(D, g));
      WinPreIntro(w);
      var k, c2, sf := RunWindow(w);
      assert w.base + S.NumInsns(w.raw) == E(D, g);
      EnterAfter(P, D, ell, live, w, c1, c1', er, c2, sf);
    }
  }

  // ---------------- a call with a pass load (P9) ----------------

  lemma ReachChain(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, a: nat, c1: Cfg, b: nat, c2: Cfg)
    requires ReachR(Pp, x, obsv, c, a) == Some(c1) && ReachR(Pp, x, obsv, c1, b) == Some(c2)
    ensures ReachR(Pp, x, obsv, c, a + b) == Some(c2)
  { ReachAdd(Pp, x, obsv, c, a, b, c1); }

  // The registers after PL(j): only r_G changed.
  lemma {:isolate_assertions} PLRegs(c: Cfg, c': Cfg, c2: Cfg, sf: S.CState, s0: S.CState, G: nat, er: set<nat>,
                                     lvj: set<nat>, lvt: set<nat>)
    requires |Top(c).regs| == NR && FrameOk(Top(c')) && FrameOk(Top(c2)) && S.CWF(sf) && 1 <= G <= 5
    requires R64(Top(c2)) == sf.regs && s0.regs == R64(Top(c'))
    requires forall k | 0 <= k <= 10 && k != G :: sf.regs[k] == s0.regs[k]
    requires RegRel(c, c', er, lvj) && lvt * {1, 2, 3, 4, 5} <= lvj && G !in lvt
    ensures forall r | 6 <= r < NR :: Rel(Top(c).regs[r], Top(c2).regs[r])
    ensures forall r | 1 <= r <= 5 :: Rel(Reg(Top(c), r), Reg(Top(c2), r)) || (r in er + {G} && r !in lvt)
  {
    forall r | 0 <= r < NR && r != G ensures Reg(Top(c2), r) == Reg(Top(c'), r) {
      assert Top(c2).regs[r] == W(sf.regs[r]) && Top(c').regs[r] == W(s0.regs[r]);
    }
    forall r | 6 <= r < NR ensures Rel(Top(c).regs[r], Top(c2).regs[r]) { assert Rel(Reg(Top(c), r), Reg(Top(c'), r)); }
    forall r | 1 <= r <= 5 ensures Rel(Reg(Top(c), r), Reg(Top(c2), r)) || (r in er + {G} && r !in lvt) {
      if r != G && r in lvt { assert r in lvt * {1, 2, 3, 4, 5}; }
    }
  }

  // After PL(j): P' at the call at kappa(j), the caller related as a waiting frame.
  opaque ghost predicate PLDone(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, c: Cfg, c2: Cfg, er: set<nat>) {
    0 <= Top(c).pc < |P| && P[Top(c).pc].Call? && Top(c).pc in D.pl
    && LowRel(P, D, ell, c, c2) && WaitRel(P, D, ell, Top(c), Top(c2)) && c2.L == c.L && c2.h == c.h
    && Top(c2).pc == K(D, Top(c).pc)
    && forall r | 1 <= r <= 5 ::
      Rel(Reg(Top(c), r), Reg(Top(c2), r)) || (r in er + {D.pl[Top(c).pc].reg} && r !in live(P[Top(c).pc].t))
  }

  // P' runs PL(j) from e(j) and stands at the call at kappa(j), the caller related as a waiting frame.
  lemma {:isolate_assertions} CallPLWin(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64,
      c: Cfg, c': Cfg, er: set<nat>) returns (k1: nat, c2: Cfg)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A5(obsv)
    requires Inv(P, c) && CorrK(P, D, ell, live, c, c', er) && Top(c).pc in D.pl
    ensures ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k1) == Some(c2)
    ensures PLDone(P, D, ell, live, c, c2, er)
  {
    reveal PLDone();
    var xR := CtxR(Pp, env, sem, om, hv);
    var j: nat := Top(c).pc;
    reveal CorrK();
    CorrElim(P, D, ell, live, c, c', er);
    InvIs(P, c);
    LowRelLen(P, D, ell, c, c');
    assert PiecesOk(P, D) && Pp == Layout(P, D) && S10(P, D, live, tbl) && LiveOk(P, live, tbl);
    assert j < |P| && P[j].Call?;
    var t := P[j].t;
    var G := D.pl[j].reg;
    assert 1 <= G <= 5 && G !in live(t);
    assert ReadsL(P[j], live, tbl) == live(t) * {1, 2, 3, 4, 5} && ReadsL(P[j], live, tbl) <= live(j);
    assert j !in D.site && j !in D.wrap;
    AllFnsWFOk(P, D);
    PLCode(P, D, j);
    var code := D.pl[j].code;
    var fn := Top(c).fn;
    FlTop(P, ell, c);
    FlFrame(P, ell, c, |c.fr| - 1);
    var sp := Api.PassLoadSpec(Fl(P, ell, j), G);
    var s0 := S.InitState(R64(Top(c')), Plain(Top(c').stack));
    var w := Win(Pp, xR, obsv, code, sp, E(D, j), -1, Exit, 0, HCtx(0, [], EMg(0), Bot, map[]), c', s0);
    assert Valid(code, sp);
    assert Checker.Validate(w.raw, w.sp) == Checker.Validated by { reveal Valid(); }
    Soundness.ValidateOk(w.raw, w.sp);
    assert Bytes8(code) && NoHelperIn(code);
    PlainWinAt(P, D, w);
    HooksOkLayout(P, D, ell);
    assert Rel(Reg(Top(c), 10), Reg(Top(c'), 10));
    BRInit(c', E(D, j));
    WinPreIntro(w);
    var sf;
    k1, c2, sf := RunWindow(w);
    SideFacts(w, c2, sf);
    assert CountHelpers(sf.events) == 0;
    Side0(w, c2, sf);
    PassLoadRegs(Fl(P, ell, j), G, s0, sf);
    assert Top(c2).pc == K(D, j);
    LowRelSame(P, D, ell, c, c', c, c2);
    PLRegs(c, c', c2, sf, s0, G, er, live(j), live(t));
    forall o | 0 <= o < STK && o - STK as int >= Fl(P, ell, fn) ensures RelB(Top(c).stack[o], Top(c2).stack[o]) {
      assert Top(c2).stack[o] == Top(c').stack[o];
    }
    assert WaitRel(P, D, ell, Top(c), Top(c2));
  }

  opaque ghost predicate Reaches(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, k: nat, c2: Cfg) {
    ReachR(Pp, x, obsv, c, k) == Some(c2)
  }

  lemma Reach3(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, a: nat, c1: Cfg, c2: Cfg, b: nat, c3: Cfg) returns (k: nat)
    requires ReachR(Pp, x, obsv, c, a) == Some(c1) && StepR(Pp, x, obsv, c1) == Go(c2) && ReachR(Pp, x, obsv, c2, b) == Some(c3)
    ensures Reaches(Pp, x, obsv, c, k, c3)
  {
    k := a + 1 + b;
    reveal Reaches();
    ReachOne(Pp, x, obsv, c1, c2);
    ReachChain(Pp, x, obsv, c, a, c1, 1, c2);
    ReachChain(Pp, x, obsv, c, a + 1, c2, b, c3);
  }

  lemma EnterFnGet(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64, c1: Cfg, c1': Cfg, er: set<nat>)
    returns (k: nat, c2: Cfg)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A5(obsv)
    requires Inv(P, c1) && PendK(P, D, ell, live, c1, c1', er)
    ensures ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c1', k) == Some(c2) && CorrK(P, D, ell, live, c1, c2, er)
  {
    EnterFn(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c1, c1', er);
    k, c2 :| ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c1', k) == Some(c2) && Corr(P, D, ell, live, c1, c2, er);
    reveal CorrK();
  }

  // The call at kappa(j) after PL(j).
  lemma {:isolate_assertions} CallAfterPL(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64,
      c: Cfg, c': Cfg, er: set<nat>, c1: Cfg, c2: Cfg) returns (c3: Cfg)
    requires Structure(P, D, Pp, ell, live, tbl) && E0Shape(P)
    requires PairX(P, D, CtxP(P, env, sem, om), CtxR(Pp, env, sem, om, hv))
    requires Inv(P, c)
    requires StepP(P, CtxP(P, env, sem, om), c) == Go(c1)
    requires PLDone(P, D, ell, live, c, c2, er)
    ensures 0 <= Top(c).pc && Top(c).pc in D.pl
    ensures StepR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c2) == Go(c3)
    ensures Inv(P, c1) && PendK(P, D, ell, live, c1, c3, er + {D.pl[Top(c).pc].reg})
  {
    reveal PLDone();
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    var j: nat := Top(c).pc;
    var t := P[j].t;
    var er' := er + {D.pl[j].reg};
    assert Pp == Layout(P, D) && PiecesOk(P, D);
    AllFnsWFOk(P, D);
    assert j !in D.site && j !in D.wrap;
    PLCode(P, D, j);
    InvIs(P, c);
    assert StepP(P, xP, c) == Push(xP, c, t, t, Sub, CArgs(c));
    assert Pp.code[K(D, j)] == O(Call(FE(D, t)), j);
    LowRelLen(P, D, ell, c, c2);
    assert StepR(Pp, xR, obsv, c2) == Push(xR, c2, FE(D, t), FE(D, t), Sub, CArgs(c2));
    CallCore(P, D, ell, live, xP, xR, c, c2, er', t);
    assert Push(xP, c, t, t, Sub, CArgs(c)) == Go(c1);
    c3 := Push(xR, c2, FE(D, t), FE(D, t), Sub, CArgs(c2)).c;
  }

  lemma {:isolate_assertions} CallPLGo(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64,
      c: Cfg, c': Cfg, er: set<nat>, c1: Cfg) returns (k: nat, c1': Cfg, er': set<nat>)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A5(obsv)
    requires PairX(P, D, CtxP(P, env, sem, om), CtxR(Pp, env, sem, om, hv))
    requires Inv(P, c) && CorrK(P, D, ell, live, c, c', er) && Top(c).pc in D.pl
    requires StepP(P, CtxP(P, env, sem, om), c) == Go(c1)
    ensures Inv(P, c1)
    ensures Reaches(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k, c1')
    ensures CorrK(P, D, ell, live, c1, c1', er')
  {
    var k1, c2 := CallPLWin(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er);
    er' := er + {D.pl[Top(c).pc].reg};
    var c3 := CallAfterPL(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er, c1, c2);
    var k2, c4 := EnterFnGet(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c1, c3, er');
    c1' := c4;
    k := Reach3(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k1, c2, c3, k2, c4);
  }


  lemma CallPL(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64,
      c: Cfg, c': Cfg, er: set<nat>, c1: Cfg)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A5(obsv)
    requires PairX(P, D, CtxP(P, env, sem, om), CtxR(Pp, env, sem, om, hv))
    requires Inv(P, c) && Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.pl
    requires StepP(P, CtxP(P, env, sem, om), c) == Go(c1)
    ensures Inv(P, c1)
    ensures exists k: nat, c1': Cfg, er': set<nat> :: ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Some(c1')
                                       && Corr(P, D, ell, live, c1, c1', er')
  {
    assert CorrK(P, D, ell, live, c, c', er) by { reveal CorrK(); }
    var k, c1', er' := CallPLGo(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er, c1);
    reveal CorrK(), Reaches();
  }
}
