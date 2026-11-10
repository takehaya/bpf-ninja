// The theorem: segment preservation for the whole-program model.
//
// SimStep and SegmentPreservation have no proof yet; make verify-sim fails
// on them until they do.  SimStepSingle (Step.dfy) proves SimStep for
// single-function programs without wrapper or tail-call sites.
include "Step.dfy"

module SimMain {
  import opened Bits
  import opened SimModel
  import opened SimRewrite
  import opened SimPremises
  import opened SimTheorem
  import opened SimSites

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

  // Segment preservation: P' ends with the observation of P.
  lemma SegmentPreservation<Sigma>(
      P: seq<OInstr>, D: Decomp, Pp: RwProg,
      ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
      env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool,
      L: Local, om: Oracle, hv: nat -> bv64, Fin: seq<Ev> -> Sigma)
    // structural conditions the checker establishes
    requires S0(P)
    requires Structure(P, D, Pp, ell, live, tbl)
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
}
