// Segment preservation for the whole-program model: the simulation
// relation and the hypotheses.  The theorem itself is in Main.dfy.
include "Premises.dfy"

module SimTheorem {
  import opened Bits
  import opened SimModel
  import opened SimRewrite
  import opened SimPremises

  // P' holds no unreadable value (it is a concrete machine).
  ghost predicate NoBot(c: Cfg) {
    forall k | 0 <= k < |c.fr| ::
      (forall r | 0 <= r < NR :: Reg(c.fr[k], r).W?)
      && (forall o | 0 <= o < |c.fr[k].stack| :: c.fr[k].stack[o].B?)
  }

  // The correspondence of P and P' at a synchronisation point of P', with
  // the pruned semantics P^flat folded in: er is the set of top-frame
  // registers whose P' value may differ although P's is readable; each is
  // one of r1-r5 and not live at the top frame's instruction.
  ghost predicate Corr(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                       c: Cfg, c': Cfg, er: set<nat>) {
    // R1 frames (no hook or wrapper frame in P')
    |c.fr| == |c'.fr| > 0
    && (forall k | 0 <= k < |c.fr| ::
          c'.fr[k].kind == c.fr[k].kind
          && |c.fr[k].regs| == NR && |c'.fr[k].regs| == NR
          && |c.fr[k].stack| == STK && |c'.fr[k].stack| == STK)
    // R2 control: the top frame at e(j), waiting frames at kappa(j)
    && 0 <= Top(c).pc < |P| && Top(c').pc == E(D, Top(c).pc)
    && (forall k | 0 <= k < |c.fr| - 1 :: 0 <= c.fr[k].pc < |P| && c'.fr[k].pc == K(D, c.fr[k].pc))
    // R3 registers
    && (forall r | 0 <= r < NR ::
          Rel(Reg(Top(c), r), Reg(Top(c'), r)) || (r in er && 1 <= r <= 5 && r !in live(Top(c).pc)))
    && (forall k, r | 0 <= k < |c.fr| - 1 && 6 <= r < NR :: Rel(Reg(c.fr[k], r), Reg(c'.fr[k], r)))
    // R4 stack at or above each frame's floor
    && (forall k, o | 0 <= k < |c.fr| && 0 <= o < STK && o - STK as int >= Fl(P, ell, c.fr[k].fn) ::
          RelB(c.fr[k].stack[o], c'.fr[k].stack[o]))
    // R5 local memory, R6 history
    && c'.L == c.L && c'.h == c.h
    && NoBot(c')
  }

  // All hypotheses of the theorem, for the lemmas below.
  ghost predicate Hyp(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int, live: nat -> set<nat>,
                      tbl: bv32 -> set<nat>, env: Env, sem: Sem, obsv: Observer, Adm: (Local, Oracle) -> bool) {
    S0(P) && Structure(P, D, Pp, ell, live, tbl) && AllValidated(P, D, ell)
    && E0Shape(P) && E0(P, env, sem, Adm) && A1a(P, env, sem, Adm, ell) && A1b(P, env, sem, Adm)
    && A3b(env, tbl) && A5(obsv)
  }
}
