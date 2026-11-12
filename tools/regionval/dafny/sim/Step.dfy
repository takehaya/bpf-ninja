// The simulation step: one step of P from a reachable configuration is
// matched by finitely many steps of P', for any frame stack (calls,
// callbacks, returns, P1b and P9 entries) and every form (P1, P1b, P1c,
// P2 with MF, P3, P4, P5, P7, P8, P9).
include "Wrap.dfy"

module SimStep1 {
  import opened Bits
  import opened SimModel
  import opened SimRewrite
  import opened SimPremises
  import opened SimTheorem
  import opened SimBridge
  import opened SimLayoutFacts
  import opened SimFrames
  import opened SimSites
  import opened SimClasses
  import opened SimCalls
  import opened SimWrap

  lemma SuccOk(P: seq<OInstr>, live: nat -> set<nat>, tbl: bv32 -> set<nat>, j: nat)
    requires E0Shape(P) && LiveOk(P, live, tbl) && j < |P| && (!P[j].Exit? && !P[j].Ja? ==> j + 1 < |P|)
    ensures forall s | s in Succ(P, j) :: s < |P| && live(s) - WritesL(P[j]) <= live(j) && Owner(P, s) == Owner(P, j)
  {
    forall s | s in Succ(P, j) ensures Owner(P, s) == Owner(P, j) {
      if s == j + 1 && !(P[j].Ja? || P[j].Exit?) {
        assert j + 1 !in FnSet(P);
      }
    }
  }

  lemma RetOkProof(P: seq<OInstr>, D: Decomp)
    requires PiecesOk(P, D) && E0Shape(P)
    ensures RetOk(P, D)
  {
    forall i | 0 <= i < |P| && (P[i].Call? || P[i].CbCall?)
      ensures i + 1 < |P| && E(D, i + 1) == K(D, i) + 1 && Owner(P, i + 1) == Owner(P, i)
    {
      NextE(P, D, i);
      assert i !in D.site && i !in D.wrap;
      assert i + 1 !in FnSet(P);
    }
  }

  lemma PairXProof(P: seq<OInstr>, D: Decomp, Pp: RwProg, env: Env, sem: Sem, om: Oracle, hv: nat -> bv64)
    requires Pp == Layout(P, D) && PiecesOk(P, D) && E0Shape(P)
    ensures PairX(P, D, CtxP(P, env, sem, om), CtxR(Pp, env, sem, om, hv))
  {
    LayoutIs(P, D);
    RetOkProof(P, D);
    forall g | g in FnSet(P) ensures g < |P| {}
  }

  lemma {:isolate_assertions} ClassHyp(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, xP: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires Structure(P, D, Pp, ell, live, tbl) && E0Shape(P) && Inv(P, c)
    requires forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc !in D.site && Top(c).pc !in D.pl && Top(c).pc !in D.wrap
    ensures CHyp(P, D, ell, live, tbl, xP, c, c', er)
    ensures Top(c').pc == K(D, Top(c).pc) && Top(c').pc < |Pp.code| && Pp.code[Top(c').pc] == O(Reloc(D, P[Top(c).pc]), Top(c).pc)
  {
    var j := Top(c).pc;
    CorrElim(P, D, ell, live, c, c', er);
    assert PiecesOk(P, D) && LiveOk(P, live, tbl) && FloorsOk(P, ell);
    assert j !in D.wrap;
    AllFnsWFOk(P, D);
    PlainCode(P, D, j);
    if !P[j].Exit? && !P[j].Ja? { NextE(P, D, j); EK(D, j); }
    assert RegsOk(P[j]);
    SuccOk(P, live, tbl, j);
    RelCIntro(P, D, ell, c, c', er, live(j));
    CHypIntro(P, D, ell, live, tbl, xP, c, c', er);
  }

  // Every class without inserted code.
  lemma ClassAny(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                 xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && PairX(P, D, xP, xR) && A3b(xP.env, tbl)
    requires 0 <= Top(c).pc < |P|
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    match P[Top(c).pc] {
      case Alu(_, _, _) => ClassAlu(P, D, ell, live, tbl, xP, xR, c, c', er);
      case FRef(_, _) => ClassFRef(P, D, ell, live, tbl, xP, xR, c, c', er);
      case Ld(_, _, _, _, _) => ClassLd(P, D, ell, live, tbl, xP, xR, c, c', er);
      case St(_, _, _, _) => ClassSt(P, D, ell, live, tbl, xP, xR, c, c', er);
      case Atom(_, _, _, _, _, _, _) => ClassAtom(P, D, ell, live, tbl, xP, xR, c, c', er);
      case Legacy(_, _, _) => ClassLegacy(P, D, ell, live, tbl, xP, xR, c, c', er);
      case Jcc(_, _, _) => ClassJcc(P, D, ell, live, tbl, xP, xR, c, c', er);
      case Ja(_) => ClassJa(P, D, ell, live, tbl, xP, xR, c, c', er);
      case MayGoto(_) => ClassMayGoto(P, D, ell, live, tbl, xP, xR, c, c', er);
      case Hcall(_, _) => ClassHcall(P, D, ell, live, tbl, xP, xR, c, c', er);
      case Tail => ClassTail(P, D, ell, live, tbl, xP, xR, c, c', er);
      case CbCall(_) => ClassCbCall(P, D, ell, live, tbl, xP, xR, c, c', er);
      case Call(_) => ClassCall(P, D, ell, live, tbl, xP, xR, c, c', er);
      case Exit => ClassExit(P, D, ell, live, tbl, xP, xR, c, c', er);
    }
  }

  // The step result of P' at e(j), from the class lemma (and the callee's prologue).
  lemma {:isolate_assertions} PlainStep(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64, c: Cfg, c': Cfg, er: set<nat>)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A5(obsv)
    requires 0 <= Top(c).pc < |P| && |c.fr| > 0 && |c'.fr| > 0
    requires 0 <= Top(c').pc < |Pp.code| && Pp.code[Top(c').pc] == O(Reloc(D, P[Top(c).pc]), Top(c).pc)
    requires CRes(P, D, ell, live, CtxP(P, env, sem, om), CtxR(Pp, env, sem, om, hv), c, c', er)
    ensures StepP(P, CtxP(P, env, sem, om), c).Go? ==> Inv(P, StepP(P, CtxP(P, env, sem, om), c).c)
    ensures match StepP(P, CtxP(P, env, sem, om), c)
      case Go(c1) => exists k: nat, c1': Cfg, er': set<nat> ::
        ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', er')
      case Done(t) => exists k: nat :: RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t)
      case Stuck(_) => true
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    var j := Top(c).pc;
    assert StepP(P, xP, c) == OStep(xP, P[j], j, c);
    assert StepR(Pp, xR, obsv, c') == OStep(xR, Reloc(D, P[j]), j, c');
    match StepP(P, xP, c)
    case Go(c1) =>
      var c1' := StepR(Pp, xR, obsv, c').c;
      assert ReachR(Pp, xR, obsv, c', 1) == Bits.Some(c1');
      if CorrK(P, D, ell, live, c1, c1', er) {
        reveal CorrK();
        assert Corr(P, D, ell, live, c1, c1', er);
      } else {
        assert PendK(P, D, ell, live, c1, c1', er);
        EnterFn(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c1, c1', er);
        var k: nat, c2: Cfg :| ReachR(Pp, xR, obsv, c1', k) == Some(c2) && Corr(P, D, ell, live, c1, c2, er);
        SimBridge.ReachAdd(Pp, xR, obsv, c', 1, k, c1');
        assert ReachR(Pp, xR, obsv, c', 1 + k) == Some(c2);
      }
    case Done(t) =>
      assert RunR(Pp, xR, obsv, c', 1) == Fin(t);
    case Stuck(_) =>
  }

  // The site branch.
  lemma {:isolate_assertions} SiteBranch(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64, c: Cfg, c': Cfg, er: set<nat>)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A3b(env, tbl) && A5(obsv)
    requires Inv(P, c)
    requires forall a | a in Acc(P, CtxP(P, env, sem, om), c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.site && !P[Top(c).pc].Tail?
    ensures StepP(P, CtxP(P, env, sem, om), c).Go? ==> Inv(P, StepP(P, CtxP(P, env, sem, om), c).c)
    ensures match StepP(P, CtxP(P, env, sem, om), c)
      case Go(c1) => exists k: nat, c1': Cfg, er': set<nat> ::
        ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', er')
      case Done(t) => exists k: nat :: RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t)
      case Stuck(_) => true
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    var j := Top(c).pc;
    CorrElim(P, D, ell, live, c, c', er);
    InvIs(P, c);
    assert StepP(P, xP, c) == OStep(xP, P[j], j, c);
    assert PiecesOk(P, D);
    assert P[j].Hcall? && !P[j].kf;
    assert OStep(xP, P[j], j, c) == HelperStep(xP, c, j, false, P[j].id, false);
    SimClasses.HelperNotDone(xP, c, j, false, P[j].id);
    match StepP(P, xP, c)
    case Go(c1) =>
      SiteStep(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er, c1);
      var k: nat, c1': Cfg :| ReachR(Pp, xR, obsv, c', k) == Some(c1') && Corr(P, D, ell, live, c1, c1', {});
    case Done(t) =>
    case Stuck(_) =>
  }

  // The wrapper branch (P8).
  lemma {:isolate_assertions} WrapBranch(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64, c: Cfg, c': Cfg, er: set<nat>)
    requires Structure(P, D, Pp, ell, live, tbl) && Loadable(P, D) && AllValidated(P, D, ell) && E0Shape(P)
    requires A3b(env, tbl) && A5(obsv) && A8(om) && Inv(P, c)
    requires forall a | a in Acc(P, CtxP(P, env, sem, om), c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.wrap
    ensures StepP(P, CtxP(P, env, sem, om), c).Go? ==> Inv(P, StepP(P, CtxP(P, env, sem, om), c).c)
    ensures match StepP(P, CtxP(P, env, sem, om), c)
      case Go(c1) => exists k: nat, c1': Cfg, er': set<nat> ::
        ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', er')
      case Done(t) => exists k: nat :: RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t)
      case Stuck(_) => true
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    var j := Top(c).pc;
    CorrElim(P, D, ell, live, c, c', er);
    InvIs(P, c);
    assert StepP(P, xP, c) == OStep(xP, P[j], j, c);
    assert PiecesOk(P, D);
    assert P[j].Hcall? && !P[j].kf;
    assert OStep(xP, P[j], j, c) == HelperStep(xP, c, j, false, P[j].id, false);
    SimClasses.HelperNotDone(xP, c, j, false, P[j].id);
    match StepP(P, xP, c)
    case Go(c1) =>
      WrapStep(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er, c1);
      var k: nat, c1': Cfg :| ReachR(Pp, xR, obsv, c', k) == Some(c1') && Corr(P, D, ell, live, c1, c1', {});
    case Done(t) =>
    case Stuck(_) =>
  }

  // The pass-load branch (a call with PL(j), P9).
  lemma {:isolate_assertions} PassBranch(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64, c: Cfg, c': Cfg, er: set<nat>)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A5(obsv)
    requires Inv(P, c)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.pl
    ensures StepP(P, CtxP(P, env, sem, om), c).Go? ==> Inv(P, StepP(P, CtxP(P, env, sem, om), c).c)
    ensures match StepP(P, CtxP(P, env, sem, om), c)
      case Go(c1) => exists k: nat, c1': Cfg, er': set<nat> ::
        ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', er')
      case Done(t) => exists k: nat :: RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t)
      case Stuck(_) => true
  {
    var xP := CtxP(P, env, sem, om);
    var j := Top(c).pc;
    CorrElim(P, D, ell, live, c, c', er);
    InvIs(P, c);
    assert PiecesOk(P, D);
    assert P[j].Call?;
    assert StepP(P, xP, c) == Push(xP, c, P[j].t, P[j].t, Sub, CArgs(c));
    PushIs(xP, c, P[j].t, P[j].t, Sub, CArgs(c));
    PairXProof(P, D, Pp, env, sem, om, hv);
    match StepP(P, xP, c)
    case Go(c1) =>
      CallPL(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er, c1);
    case Done(t) =>
    case Stuck(_) =>
  }

  // A1a at one reachable configuration.
  lemma A1aAt(P: seq<OInstr>, env: Env, sem: Sem, Adm: (Local, Oracle) -> bool, ell: nat -> int,
              L: Local, om: Oracle, n: nat, c: Cfg)
    requires A1a(P, env, sem, Adm, ell) && Adm(L, om) && ReachP(P, CtxP(P, env, sem, om), InitP(L), n) == Bits.Some(c)
    ensures forall a | a in Acc(P, CtxP(P, env, sem, om), c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
  {}

  // One step of P from any reachable configuration (with the frame invariant).
  lemma {:isolate_assertions} SimStepGen(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                L: Local, om: Oracle, hv: nat -> bv64, n: nat, c: Cfg, c': Cfg, er: set<nat>)
    requires Hyp(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm) && A8(om) && Adm(L, om)
    requires Inv(P, c)
    requires ReachP(P, CtxP(P, env, sem, om), InitP(L), n) == Bits.Some(c)
    requires Corr(P, D, ell, live, c, c', er)
    ensures StepP(P, CtxP(P, env, sem, om), c).Go? ==> Inv(P, StepP(P, CtxP(P, env, sem, om), c).c)
    ensures match StepP(P, CtxP(P, env, sem, om), c)
      case Go(c1) => exists k: nat, c1': Cfg, er': set<nat> ::
        ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', er')
      case Done(t) => exists k: nat :: RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t)
      case Stuck(_) => true
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    assert Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A3b(env, tbl) && A5(obsv);
    A1aAt(P, env, sem, Adm, ell, L, om, n, c);
    InvIs(P, c);
    assert PiecesOk(P, D);
    if Top(c).pc in D.site && P[Top(c).pc].Tail? {
      TailStep(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er);
    } else if Top(c).pc in D.site {
      SiteBranch(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er);
    } else if Top(c).pc in D.wrap {
      WrapBranch(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er);
    } else if Top(c).pc in D.pl {
      PassBranch(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er);
    } else {
      ClassHyp(P, D, Pp, ell, live, tbl, xP, c, c', er);
      CorrElim(P, D, ell, live, c, c', er);
      assert PiecesOk(P, D);
      PairXProof(P, D, Pp, env, sem, om, hv);
      ClassAny(P, D, ell, live, tbl, xP, xR, c, c', er);
      LowRelLen(P, D, ell, c, c');
      PlainStep(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er);
    }
  }
}
