// The theorem: segment preservation for the whole-program model.
//
// SimStepGen (Step.dfy) proves the step for any configuration with the
// frame invariant Inv; ReachCorr carries Inv and Corr along every run of P,
// and the finite run of P (E0, A1b) is matched by a finite run of P'.
include "Step.dfy"

module SimMain {
  import opened Bits
  import opened SimModel
  import opened SimRewrite
  import opened SimPremises
  import opened SimTheorem
  import opened SimSites
  import opened SimFrames
  import opened SimStep1
  import SimBridge

  // Base: the run of P' passes Pro_0 and reaches e(0) related to init.
  lemma SimInit(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                L: Local, om: Oracle, hv: nat -> bv64)
    requires Hyp(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm) && A8(om) && Adm(L, om)
    ensures exists n: nat, c': Cfg ::
      ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, InitR(L, hv), n) == Bits.Some(c')
      && Corr(P, D, ell, live, InitP(L), c', {})
  {
    SimInitProof(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv);
  }

  // One step of P from a reachable configuration is matched by finitely
  // many steps of P' (one case per instruction class and form).
  lemma SimStep(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                L: Local, om: Oracle, hv: nat -> bv64, n: nat, c: Cfg, c': Cfg, er: set<nat>)
    requires Hyp(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm) && A8(om) && Adm(L, om)
    requires ReachP(P, CtxP(P, env, sem, om), InitP(L), n) == Bits.Some(c)
    requires Corr(P, D, ell, live, c, c', er)
    ensures match StepP(P, CtxP(P, env, sem, om), c)
      case Go(c1) => exists k: nat, c1': Cfg, er': set<nat> ::
        ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', er')
      case Done(t) => exists k: nat :: RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t)
      case Stuck(_) => true
  {
    HI(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om);
    ReachCorr(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, n);
    InvAt(P, env, sem, om, L, n, c);
    SimStepGen(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, n, c, c', er);
  }

  // ---------------- the induction over the run of P ----------------

  // All hypotheses with one input and oracle, folded.
  opaque ghost predicate H(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                           tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                           L: Local, om: Oracle) {
    Hyp(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm) && A8(om) && Adm(L, om)
  }

  lemma HI(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
           tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool, L: Local, om: Oracle)
    requires Hyp(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm) && A8(om) && Adm(L, om)
    ensures H(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om)
  { reveal H(); }

  // Inv of a reachable configuration (from ReachCorr).
  opaque ghost predicate InvR(P: seq<OInstr>, env: Env, sem: Sem, om: Oracle, L: Local, n: nat) {
    match ReachP(P, CtxP(P, env, sem, om), InitP(L), n)
    case Some(c) => Inv(P, c)
    case None => true
  }

  lemma InvAt(P: seq<OInstr>, env: Env, sem: Sem, om: Oracle, L: Local, n: nat, c: Cfg)
    requires InvR(P, env, sem, om, L, n) && ReachP(P, CtxP(P, env, sem, om), InitP(L), n) == Bits.Some(c)
    ensures Inv(P, c)
  { reveal InvR(); }

  // One step from a reachable configuration with Inv, folded.
  lemma {:isolate_assertions} GenStep(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                L: Local, om: Oracle, hv: nat -> bv64, n: nat, c: Cfg, c': Cfg, er: set<nat>, c1: Cfg)
    returns (k: nat, c1': Cfg, er': set<nat>)
    requires H(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om)
    requires ReachP(P, CtxP(P, env, sem, om), InitP(L), n) == Bits.Some(c) && Inv(P, c)
    requires SimClasses.CorrK(P, D, ell, live, c, c', er)
    requires StepP(P, CtxP(P, env, sem, om), c) == Go(c1)
    ensures Inv(P, c1)
    ensures ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Bits.Some(c1') && SimClasses.CorrK(P, D, ell, live, c1, c1', er')
  {
    reveal H(), SimClasses.CorrK();
    SimStepGen(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, n, c, c', er);
    k, c1', er' :| ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Bits.Some(c1') && Corr(P, D, ell, live, c1, c1', er');
  }

  lemma {:isolate_assertions} GenDone(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                L: Local, om: Oracle, hv: nat -> bv64, n: nat, c: Cfg, c': Cfg, er: set<nat>, t: Term)
    returns (k: nat)
    requires H(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om)
    requires ReachP(P, CtxP(P, env, sem, om), InitP(L), n) == Bits.Some(c) && Inv(P, c)
    requires SimClasses.CorrK(P, D, ell, live, c, c', er)
    requires StepP(P, CtxP(P, env, sem, om), c) == Done(t)
    ensures RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t)
  {
    reveal H(), SimClasses.CorrK();
    SimStepGen(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, n, c, c', er);
    k :| RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', k) == Fin(t);
  }

  lemma {:isolate_assertions} GenInit(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                L: Local, om: Oracle, hv: nat -> bv64) returns (k: nat, c': Cfg)
    requires H(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om)
    ensures ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, InitR(L, hv), k) == Bits.Some(c')
    ensures SimClasses.CorrK(P, D, ell, live, InitP(L), c', {}) && Inv(P, InitP(L))
  {
    reveal H(), SimClasses.CorrK();
    SimInitProof(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv);
    k, c' :| ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, InitR(L, hv), k) == Bits.Some(c') && Corr(P, D, ell, live, InitP(L), c', {});
    assert E0Shape(P);
    InvInit(P, L);
  }

  lemma ReachSnoc(P: seq<OInstr>, x: Ctx, c0: Cfg, n: nat, c: Cfg, c1: Cfg)
    requires ReachP(P, x, c0, n) == Bits.Some(c) && StepP(P, x, c) == Go(c1)
    ensures ReachP(P, x, c0, n + 1) == Bits.Some(c1)
    decreases n
  {
    if n > 0 {
      match StepP(P, x, c0)
      case Go(c') => ReachSnoc(P, x, c', n - 1, c, c1);
      case _ =>
    }
  }

  lemma ReachLast(P: seq<OInstr>, x: Ctx, c0: Cfg, n: nat, c1: Cfg) returns (c: Cfg)
    requires ReachP(P, x, c0, n + 1) == Bits.Some(c1)
    ensures ReachP(P, x, c0, n) == Bits.Some(c) && StepP(P, x, c) == Go(c1)
    decreases n
  {
    match StepP(P, x, c0)
    case Go(c') =>
      if n == 0 { c := c0; } else { c := ReachLast(P, x, c', n - 1, c1); }
  }

  // Every configuration P reaches has the frame invariant and a related configuration of P'.
  lemma {:isolate_assertions} ReachCorrK(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                  tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                  L: Local, om: Oracle, hv: nat -> bv64, n: nat, c: Cfg) returns (k: nat, c': Cfg, er: set<nat>)
    requires H(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om)
    requires ReachP(P, CtxP(P, env, sem, om), InitP(L), n) == Bits.Some(c)
    ensures Inv(P, c)
    ensures ReachR(Pp, CtxR(Pp, env, sem, om, hv), obsv, InitR(L, hv), k) == Bits.Some(c') && SimClasses.CorrK(P, D, ell, live, c, c', er)
    decreases n
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    if n == 0 {
      assert c == InitP(L);
      k, c' := GenInit(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv);
      er := {};
    } else {
      var n0: nat := n - 1;
      var c0 := ReachLast(P, xP, InitP(L), n0, c);
      var k0, c0', er0 := ReachCorrK(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, n0, c0);
      var k2, c1', er' := GenStep(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, n0, c0, c0', er0, c);
      SimBridge.ReachAdd(Pp, xR, obsv, InitR(L, hv), k0, k2, c0');
      k, c', er := k0 + k2, c1', er';
    }
  }

  lemma ReachCorr(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                  tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
                  L: Local, om: Oracle, hv: nat -> bv64, n: nat)
    requires H(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om)
    ensures InvR(P, env, sem, om, L, n)
  {
    reveal InvR();
    match ReachP(P, CtxP(P, env, sem, om), InitP(L), n)
    case None =>
    case Some(c) =>
      var k, c', er := ReachCorrK(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, n, c);
  }

  lemma RunPFrom(P: seq<OInstr>, x: Ctx, c: Cfg, m: nat, c1: Cfg)
    requires m > 0 && StepP(P, x, c) == Go(c1)
    ensures RunP(P, x, c, m) == RunP(P, x, c1, m - 1)
  {}

  lemma RunPDone(P: seq<OInstr>, x: Ctx, c: Cfg, m: nat, t: Term)
    requires RunP(P, x, c, m) == Fin(t)
    ensures m > 0 && (StepP(P, x, c).Go? || StepP(P, x, c) == Done(t))
  {}

  // A run of P that ends from a reachable configuration is matched by a run of P' that ends the same way.
  lemma {:isolate_assertions} RunFin(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
               tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
               L: Local, om: Oracle, hv: nat -> bv64, n: nat, c: Cfg, c': Cfg, er: set<nat>, m: nat, t: Term)
    returns (nR: nat)
    requires H(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om)
    requires ReachP(P, CtxP(P, env, sem, om), InitP(L), n) == Bits.Some(c) && Inv(P, c)
    requires SimClasses.CorrK(P, D, ell, live, c, c', er)
    requires RunP(P, CtxP(P, env, sem, om), c, m) == Fin(t)
    ensures RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, c', nR) == Fin(t)
    decreases m
  {
    var xP := CtxP(P, env, sem, om);
    var xR := CtxR(Pp, env, sem, om, hv);
    RunPDone(P, xP, c, m, t);
    if StepP(P, xP, c).Go? {
      var c1 := StepP(P, xP, c).c;
      RunPFrom(P, xP, c, m, c1);
      var k, c1', er' := GenStep(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, n, c, c', er, c1);
      ReachSnoc(P, xP, InitP(L), n, c, c1);
      var m1: nat := m - 1;
      var n1: nat := n + 1;
      var nR' := RunFin(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, n1, c1, c1', er', m1, t);
      SimBridge.RunAfterReach(Pp, xR, obsv, c', k, c1', nR', t);
      nR := k + nR';
    } else {
      nR := GenDone(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, n, c, c', er, t);
    }
  }

  // The run of P ends (E0), and not on an unreadable byte (A1b).
  lemma {:isolate_assertions} PEnds(P: seq<OInstr>, env: Env, sem: Sem, Adm: (Local, Oracle) -> bool, L: Local, om: Oracle)
    returns (nP: nat, t: Term)
    requires E0(P, env, sem, Adm) && A1b(P, env, sem, Adm) && Adm(L, om)
    ensures RunP(P, CtxP(P, env, sem, om), InitP(L), nP) == Fin(t)
  {
    nP :| var r := RunP(P, CtxP(P, env, sem, om), InitP(L), nP); r.Fin? || r == Stk(true);
    assert RunP(P, CtxP(P, env, sem, om), InitP(L), nP) != Stk(true);
    t := RunP(P, CtxP(P, env, sem, om), InitP(L), nP).t;
  }

  // The whole argument, with the hypotheses folded.
  lemma {:isolate_assertions} Preserve(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
      L: Local, om: Oracle, hv: nat -> bv64, nP: nat, t: Term) returns (nR: nat)
    requires H(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om)
    requires RunP(P, CtxP(P, env, sem, om), InitP(L), nP) == Fin(t)
    ensures RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, InitR(L, hv), nR) == Fin(t)
  {
    var xR := CtxR(Pp, env, sem, om, hv);
    var k, c' := GenInit(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv);
    assert ReachP(P, CtxP(P, env, sem, om), InitP(L), 0) == Bits.Some(InitP(L));
    var nR' := RunFin(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, 0, InitP(L), c', {}, nP, t);
    SimBridge.RunAfterReach(Pp, xR, obsv, InitR(L, hv), k, c', nR', t);
    nR := k + nR';
  }

  // Segment preservation: P' ends with the observation of P.
  lemma SegmentPreservation<Sigma>(
      P: seq<OInstr>, D: Decomp, Pp: RwProg,
      ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
      env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
      L: Local, om: Oracle, hv: nat -> bv64, Fin: seq<Ev> -> Sigma)
    // structural conditions the checker establishes
    requires S0(P)
    requires Structure(P, D, Pp, ell, live, tbl)
    // P' loads: at most 1000000 instructions (kernel limit)
    requires Loadable(P, D)
    // every inserted region is validated by the region validator
    requires AllValidated(P, D, ell)
    // premises
    requires E0Shape(P)
    requires E0(P, env, sem, Adm)
    requires A1a(P, env, sem, Adm, ell)
    requires A1b(P, env, sem, Adm)
    requires A3b(env, tbl)
    requires A5(obsv)
    requires A8(om)
    // an admissible input and oracle; hv picks one run of P'
    requires Adm(L, om)
    ensures exists nP: nat, nR: nat ::
      var rP := RunP(P, CtxP(P, env, sem, om), InitP(L), nP);
      var rR := RunR(Pp, CtxR(Pp, env, sem, om, hv), obsv, InitR(L, hv), nR);
      rP.Fin? && rR.Fin? && Observe(rR.t, Fin) == Observe(rP.t, Fin)
  {
    assert Hyp(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm);
    HI(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om);
    var nP, t := PEnds(P, env, sem, Adm, L, om);
    var nR := Preserve(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm, L, om, hv, nP, t);
  }
}
