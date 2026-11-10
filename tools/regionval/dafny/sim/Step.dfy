// The simulation step for single-function programs: one step of P from a
// reachable configuration is matched by finitely many steps of P'.
include "Classes.dfy"

module SimStep1 {
  import opened Bits
  import opened SimModel
  import opened SimRewrite
  import opened SimPremises
  import opened SimTheorem
  import opened SimBridge
  import opened SimLayoutFacts
  import opened SimSites
  import opened SimClasses

  lemma SuccOk(P: seq<OInstr>, live: nat -> set<nat>, tbl: bv32 -> set<nat>, j: nat)
    requires E0Shape(P) && LiveOk(P, live, tbl) && j < |P| && (!P[j].Exit? && !P[j].Ja? ==> j + 1 < |P|)
    ensures forall s | s in Succ(P, j) :: s < |P| && live(s) - WritesL(P[j]) <= live(j)
  {}

  lemma {:isolate_assertions} ClassHyp(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, xP: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires Structure(P, D, Pp, ell, live, tbl) && E0Shape(P) && Single(P, D) && Inv1(c)
    requires forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc !in D.site
    ensures CHyp(P, D, ell, live, tbl, xP, c, c', er)
    ensures Top(c').pc == K(D, Top(c).pc) && Top(c').pc < |Pp.code| && Pp.code[Top(c').pc] == O(Reloc(D, P[Top(c).pc]), Top(c).pc)
  {
    var j := Top(c).pc;
    CorrElim1(P, D, ell, live, c, c', er);
    assert PiecesOk(P, D) && LiveOk(P, live, tbl) && FloorsOk(P, ell) && 0 in FnSet(P);
    assert j !in D.pl && j !in D.wrap;
    AllFnsWFOk(P, D);
    PlainCode(P, D, j);
    if !P[j].Exit? && !P[j].Ja? { NextE(P, D, j); EK(D, j); }
    assert RegsOk(P[j]);
    SuccOk(P, live, tbl, j);
    assert Inv1(c) && Top(c) == c.fr[0] && Top(c') == c'.fr[0];
    RelCIntro(P, ell, c, c', er, live(j));
    Floor8Bounds(ell(0));
    CHypIntro(P, D, ell, live, tbl, xP, c, c', er);
  }

  // Every class without inserted code.
  lemma ClassAny(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                 xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && A3b(xP.env, tbl)
    requires 0 <= Top(c).pc < |P| && !P[Top(c).pc].Call? && !P[Top(c).pc].CbCall?
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
      case Exit => ClassExit(P, D, ell, live, tbl, xP, xR, c, c', er);
    }
  }

  // The step result of P' at e(j), from the class lemma.
  lemma {:isolate_assertions} PlainStep(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                                        xP: Ctx, xR: Ctx, obsv: Observer, c: Cfg, c': Cfg, er: set<nat>)
    requires 0 <= Top(c).pc < |P| && |c.fr| > 0 && |c'.fr| > 0
    requires 0 <= Top(c').pc < |Pp.code| && Pp.code[Top(c').pc] == O(Reloc(D, P[Top(c).pc]), Top(c).pc)
    requires CRes(P, D, ell, live, xP, xR, c, c', er)
    ensures StepP(P, xP, c).Go? ==> Inv1(StepP(P, xP, c).c)
    ensures match StepP(P, xP, c)
      case Go(c1) => exists k: nat, c1': Cfg, er': set<nat> ::
        ReachR(Pp, xR, obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', er')
      case Done(t) => exists k: nat :: RunR(Pp, xR, obsv, c', k) == Fin(t)
      case Stuck(_) => true
  {
    var j := Top(c).pc;
    assert StepP(P, xP, c) == OStep(xP, P[j], j, c);
    assert StepR(Pp, xR, obsv, c') == OStep(xR, Reloc(D, P[j]), j, c');
    match StepP(P, xP, c)
    case Go(c1) =>
      var c1' := StepR(Pp, xR, obsv, c').c;
      reveal CorrK();
      assert ReachR(Pp, xR, obsv, c', 1) == Bits.Some(c1');
      assert Corr(P, D, ell, live, c1, c1', er);
    case Done(t) =>
      assert RunR(Pp, xR, obsv, c', 1) == Fin(t);
    case Stuck(_) =>
  }

  // The site branch.
  lemma {:isolate_assertions} SiteBranch(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, om: Oracle, hv: nat -> bv64, c: Cfg, c': Cfg, er: set<nat>)
    requires Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A3b(env, tbl) && A5(obsv)
    requires Single(P, D) && Inv1(c)
    requires forall a | a in Acc(P, CtxP(P, env, sem, om), c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires Corr(P, D, ell, live, c, c', er) && Top(c).pc in D.site
    ensures StepP(P, CtxP(P, env, sem, om), c).Go? ==> Inv1(StepP(P, CtxP(P, env, sem, om), c).c)
    ensures match StepP(P, CtxP(P, env, sem, om), c)
      case Go(c1) => exists k: nat, c1': Cfg, er': set<nat> ::
        ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', er')
      case Done(t) => exists k: nat :: RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t)
      case Stuck(_) => true
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    var j := Top(c).pc;
    CorrElim1(P, D, ell, live, c, c', er);
    assert StepP(P, xP, c) == OStep(xP, P[j], j, c);
    assert PiecesOk(P, D);
    assert P[j].Hcall? && !P[j].kf;
    assert OStep(xP, P[j], j, c) == HelperStep(xP, c, j, false, P[j].id, false);
    SimClasses.HelperNotDone(xP, c, j, false, P[j].id);
    match StepP(P, xP, c)
    case Go(c1) =>
      SiteStep(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er, c1);
      var k: nat, c1': Cfg :| ReachR(Pp, xR, obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', {});
    case Done(t) =>
    case Stuck(_) =>
  }

  // One step of P at an instruction with no inserted code, or at a site.
  lemma {:isolate_assertions} SimStepSingle(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                L: Local, om: Oracle, hv: nat -> bv64, n: nat, c: Cfg, c': Cfg, er: set<nat>)
    requires Hyp(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm) && A8(om) && Adm(L, om)
    requires Single(P, D) && Inv1(c)
    requires ReachP(P, CtxP(P, env, sem, om), InitP(L), n) == Bits.Some(c)
    requires Corr(P, D, ell, live, c, c', er)
    ensures StepP(P, CtxP(P, env, sem, om), c).Go? ==> Inv1(StepP(P, CtxP(P, env, sem, om), c).c)
    ensures match StepP(P, CtxP(P, env, sem, om), c)
      case Go(c1) => exists k: nat, c1': Cfg, er': set<nat> ::
        ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', er')
      case Done(t) => exists k: nat :: RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t)
      case Stuck(_) => true
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    assert Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell) && E0Shape(P) && A3b(env, tbl) && A5(obsv);
    assert A1a(P, env, sem, Adm, ell);
    assert forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn);
    if Top(c).pc in D.site {
      SiteBranch(P, D, Pp, ell, live, tbl, env, sem, obsv, om, hv, c, c', er);
    } else {
      ClassHyp(P, D, Pp, ell, live, tbl, xP, c, c', er);
      CorrElim1(P, D, ell, live, c, c', er);
      assert Pair(xP, xR);
      ClassAny(P, D, ell, live, tbl, xP, xR, c, c', er);
      PlainStep(P, D, Pp, ell, live, xP, xR, obsv, c, c', er);
    }
  }
}
