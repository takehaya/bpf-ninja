// One step of an original instruction with no inserted code around it:
// P' runs the relocated instruction from e(j) and ends related to P's step
// (one lemma per instruction class).  Calls and callbacks end with P' at
// fe(G), before G's prologue (PendK); Calls.dfy runs the prologue.
include "Sites.dfy"

module SimClasses {
  import opened Bits
  import S = Semantics
  import opened SimModel
  import opened SimRewrite
  import opened SimPremises
  import opened SimTheorem
  import opened SimBridge
  import opened SimSites
  import SimFacts
  import opened SimFrames

  // ---------------- the relation without the pc ----------------

  opaque ghost predicate RelC(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>) {
    Inv(P, c) && LowRel(P, D, ell, c, c') && FrameOk(Top(c')) && Top(c').kind == Top(c).kind
    && RegRel(c, c', er, lv) && StkRel(c, c', Fl(P, ell, Top(c).fn)) && c'.L == c.L && c'.h == c.h
  }

  lemma RelCIs(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires RelC(P, D, ell, c, c', er, lv)
    ensures Inv(P, c) && LowRel(P, D, ell, c, c') && FrameOk(Top(c')) && Top(c').kind == Top(c).kind
    ensures RegRel(c, c', er, lv) && StkRel(c, c', Fl(P, ell, Top(c).fn)) && c'.L == c.L && c'.h == c.h
    ensures |c'.fr| == |c.fr| > 0 && FrInv(P, |c.fr| - 1, Top(c)) && Wh(c) == Wh(c')
    ensures Top(c) == c.fr[|c.fr| - 1] && Top(c') == c'.fr[|c'.fr| - 1]
  { reveal RelC(); InvIs(P, c); LowRelLen(P, D, ell, c, c'); }

  lemma RelCShape(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires RelC(P, D, ell, c, c', er, lv)
    ensures Inv(P, c) && |c'.fr| == |c.fr| > 0 && Top(c').kind == Top(c).kind && c'.L == c.L && c'.h == c.h
    ensures FrInv(P, |c.fr| - 1, Top(c)) && Wh(c) == Wh(c')
  { reveal RelC(); InvIs(P, c); LowRelLen(P, D, ell, c, c'); }

  // The frame-level facts of RelC, without the register and waiting-frame relations.
  lemma RelCFrame(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires RelC(P, D, ell, c, c', er, lv)
    ensures |c'.fr| == |c.fr| > 0 && |Top(c).regs| == NR && |Top(c).stack| == STK && FrameOk(Top(c'))
    ensures Top(c').kind == Top(c).kind && c'.L == c.L && c'.h == c.h && Wh(c) == Wh(c')
    ensures StkRel(c, c', Fl(P, ell, Top(c).fn))
  { reveal RelC(); InvIs(P, c); LowRelLen(P, D, ell, c, c'); }

  lemma RelCMem(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires RelC(P, D, ell, c, c', er, lv) && FloorsOk(P, ell)
    ensures MemRel(P, D, ell, c, c') && |c'.fr| == |c.fr| > 0 && c'.L == c.L
  { reveal RelC(); LowRelLen(P, D, ell, c, c'); MemRelI(P, D, ell, c, c'); }

  lemma RelCLow(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires RelC(P, D, ell, c, c', er, lv)
    ensures Inv(P, c) && LowRel(P, D, ell, c, c') && |c'.fr| == |c.fr| > 0 && c'.L == c.L && c'.h == c.h
  { reveal RelC(); LowRelLen(P, D, ell, c, c'); }

  lemma RelCRegs(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires RelC(P, D, ell, c, c', er, lv)
    ensures RegRel(c, c', er, lv)
  { reveal RelC(); }

  lemma RelCIntro(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires Inv(P, c) && LowRel(P, D, ell, c, c') && FrameOk(Top(c')) && Top(c').kind == Top(c).kind
    requires RegRel(c, c', er, lv) && StkRel(c, c', Fl(P, ell, Top(c).fn)) && c'.L == c.L && c'.h == c.h
    ensures RelC(P, D, ell, c, c', er, lv)
  { reveal RelC(); }

  lemma RelCH(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>, e: Ev)
    requires RelC(P, D, ell, c, c', er, lv)
    ensures RelC(P, D, ell, c.(h := c.h + [e]), c'.(h := c'.h + [e]), er, lv)
    ensures Top(c.(h := c.h + [e])) == Top(c) && Top(c'.(h := c'.h + [e])) == Top(c')
  {
    RelCIs(P, D, ell, c, c', er, lv);
    var a := c.(h := c.h + [e]);
    var a' := c'.(h := c'.h + [e]);
    InvFields(P, c, a);
    LowRelSame(P, D, ell, c, c', a, a');
    RelCIntro(P, D, ell, a, a', er, lv);
  }

  lemma RelCLocal(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>, p: bv64, bs: seq<bv8>)
    requires RelC(P, D, ell, c, c', er, lv)
    ensures RelC(P, D, ell, WriteLocal(c, p, bs), WriteLocal(c', p, bs), er, lv)
    ensures Top(WriteLocal(c, p, bs)) == Top(c) && Top(WriteLocal(c', p, bs)) == Top(c')
  {
    var a := WriteLocal(c, p, bs);
    var a' := WriteLocal(c', p, bs);
    RelCIs(P, D, ell, c, c', er, lv);
    assert a.fr == c.fr && a'.fr == c'.fr;
    assert a'.L.mem == WriteMem(c.L.mem, p, bs) == a.L.mem;
    InvFields(P, c, a);
    LowRelSame(P, D, ell, c, c', a, a');
    RelCIntro(P, D, ell, a, a', er, lv);
  }

  // The same write set applied in both runs.
  lemma {:isolate_assertions} RelCApply(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>, wr: map<int, bv8>)
    requires RelC(P, D, ell, c, c', er, lv)
    ensures |c.fr| > 0 && |c'.fr| > 0
    ensures RelC(P, D, ell, ApplyW(c, wr), ApplyW(c', wr), er, lv)
    ensures Top(ApplyW(c, wr)) == ApplyF(Top(c), |c.fr| - 1, wr) && Top(ApplyW(c', wr)) == ApplyF(Top(c'), |c'.fr| - 1, wr)
    ensures |ApplyW(c, wr).fr| == |c.fr| && |ApplyW(c', wr).fr| == |c'.fr|
  {
    RelCIs(P, D, ell, c, c', er, lv);
    ApplyTop(c, wr);
    ApplyTop(c', wr);
    var a := ApplyW(c, wr);
    var a' := ApplyW(c', wr);
    var n := |c.fr|;
    InvApply(P, c, wr);
    LowRelApply(P, D, ell, c, c', wr);
    assert forall r | 0 <= r < NR :: Reg(Top(a), r) == Reg(Top(c), r) && Reg(Top(a'), r) == Reg(Top(c'), r);
    assert RegRel(a, a', er, lv);
    assert StkRel(a, a', Fl(P, ell, Top(a).fn));
    assert FrameOk(Top(a'));
    RelCIntro(P, D, ell, a, a', er, lv);
  }

  lemma SuccJ(P: seq<OInstr>, j: nat)
    requires j < |P| && (P[j].Jcc? || P[j].MayGoto?)
    ensures Succ(P, j) == {P[j].t, j + 1}
  {}

  // The two runs share the environment, semantics and oracle.
  ghost predicate Pair(xP: Ctx, xR: Ctx) {
    xP.m.MP? && xR.m.MR? && xP.env == xR.env && xP.sem == xR.sem && xP.om == xR.om
  }

  // A call or callback helper at i resumes at e(i + 1) = kappa(i) + 1, in the same function.
  ghost predicate RetOk(P: seq<OInstr>, D: Decomp) {
    forall i | 0 <= i < |P| && (P[i].Call? || P[i].CbCall?) ::
      i + 1 < |P| && E(D, i + 1) == K(D, i) + 1 && Owner(P, i + 1) == Owner(P, i)
  }

  // Pair, and how both runs enter functions (calls, callbacks).
  ghost predicate PairX(P: seq<OInstr>, D: Decomp, xP: Ctx, xR: Ctx) {
    Pair(xP, xR) && xP.fns == FnSet(P) && xR.fns == FnSet(P)
    && (forall g | g in FnSet(P) :: g < |P| && xP.fentry(g) == g && xR.fentry(g) == FE(D, g))
    && RetOk(P, D)
  }

  // What a class step at j = Top(c).pc uses.
  opaque ghost predicate CHyp(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                       xP: Ctx, c: Cfg, c': Cfg, er: set<nat>) {
    var j := Top(c).pc;
    0 <= j < |P| && RelC(P, D, ell, c, c', er, live(j)) && Top(c').pc == E(D, j)
    && RegsOk(P[j]) && ReadsL(P[j], live, tbl) <= live(j)
    && (forall s | s in Succ(P, j) :: s < |P| && live(s) - WritesL(P[j]) <= live(j) && Owner(P, s) == Owner(P, j))
    && (!P[j].Exit? && !P[j].Ja? ==> j + 1 < |P| && E(D, j + 1) == E(D, j) + 1)
    && (forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn))
    && FloorsOk(P, ell) && K(D, j) == E(D, j)
  }

  // P' has just pushed a frame for function g = Top(c1).pc and stands at fe(g), before FP(g).
  opaque ghost predicate PendK(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, c1: Cfg, c1': Cfg, er: set<nat>) {
    |c1'.fr| > 0 && 0 <= Top(c1).pc && Top(c1).pc as nat in FnSet(P) && Top(c1').pc == FE(D, Top(c1).pc)
    && Reg(Top(c1), 0).Bot?
    && Corr(P, D, ell, live, c1, Put(c1', Top(c1').(pc := E(D, Top(c1).pc))), er)
  }

  ghost predicate CRes(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                       c: Cfg, c': Cfg, er: set<nat>)
    requires 0 <= Top(c).pc < |P|
  {
    var j := Top(c).pc;
    match OStep(xP, P[j], j, c)
    case Go(c1) => OStep(xR, Reloc(D, P[j]), j, c').Go? && Inv(P, c1)
                   && (CorrK(P, D, ell, live, c1, OStep(xR, Reloc(D, P[j]), j, c').c, er)
                       || PendK(P, D, ell, live, c1, OStep(xR, Reloc(D, P[j]), j, c').c, er))
    case Done(t) => OStep(xR, Reloc(D, P[j]), j, c') == Done(t)
    case Stuck(_) => true
  }

  lemma CResGo(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                c: Cfg, c': Cfg, er: set<nat>, c1: Cfg, c1': Cfg)
    requires 0 <= Top(c).pc < |P|
    requires OStep(xP, P[Top(c).pc], Top(c).pc, c) == Go(c1)
    requires OStep(xR, Reloc(D, P[Top(c).pc]), Top(c).pc, c') == Go(c1')
    requires Inv(P, c1) && CorrK(P, D, ell, live, c1, c1', er)
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {}

  lemma CResPend(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                 c: Cfg, c': Cfg, er: set<nat>, c1: Cfg, c1': Cfg)
    requires 0 <= Top(c).pc < |P|
    requires OStep(xP, P[Top(c).pc], Top(c).pc, c) == Go(c1)
    requires OStep(xR, Reloc(D, P[Top(c).pc]), Top(c).pc, c') == Go(c1')
    requires Inv(P, c1) && PendK(P, D, ell, live, c1, c1', er)
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {}

  lemma CResStuck(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                  c: Cfg, c': Cfg, er: set<nat>)
    requires 0 <= Top(c).pc < |P| && OStep(xP, P[Top(c).pc], Top(c).pc, c).Stuck?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {}

  lemma CResDone(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                 c: Cfg, c': Cfg, er: set<nat>, t: Term)
    requires 0 <= Top(c).pc < |P| && OStep(xP, P[Top(c).pc], Top(c).pc, c) == Done(t)
    requires OStep(xR, Reloc(D, P[Top(c).pc]), Top(c).pc, c') == Done(t)
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {}

  lemma AccMem(P: seq<OInstr>, xP: Ctx, c: Cfg, ell: nat -> int, p: bv64, w: nat)
    requires Acc(P, xP, c) == MemAcc(c, p, w)
    requires forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    ensures forall a | a in MemAcc(c, p, w) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
  {}

  lemma CHypFacts(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                  xP: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er)
    ensures var j := Top(c).pc;
      0 <= j < |P| && RelC(P, D, ell, c, c', er, live(j)) && Top(c').pc == E(D, j) && K(D, j) == E(D, j)
      && RegsOk(P[j]) && ReadsL(P[j], live, tbl) <= live(j)
      && (forall s | s in Succ(P, j) :: s < |P| && live(s) - WritesL(P[j]) <= live(j) && Owner(P, s) == Top(c).fn)
      && (!P[j].Exit? && !P[j].Ja? ==>
            j + 1 < |P| && E(D, j + 1) == E(D, j) + 1 && live(j + 1) - WritesL(P[j]) <= live(j) && Owner(P, j + 1) == Top(c).fn)
    ensures |c'.fr| == |c.fr| > 0 && Top(c) == c.fr[|c.fr| - 1] && Top(c') == c'.fr[|c'.fr| - 1]
    ensures |Top(c).regs| == NR && |Top(c').regs| == NR
    ensures FloorsOk(P, ell) && -(STK as int) <= Fl(P, ell, Top(c).fn) <= ell(Top(c).fn) <= 0
    ensures forall r | r in ReadsL(P[Top(c).pc], live, tbl) && r < NR :: Rel(Reg(Top(c), r), Reg(Top(c'), r))
    ensures Rel(Reg(Top(c), 0), Reg(Top(c'), 0))
    ensures P[Top(c).pc].Legacy? ==> forall r | 0 <= r <= 10 :: Rel(Reg(Top(c), r), Reg(Top(c'), r))
  {
    reveal CHyp();
    RelCIs(P, D, ell, c, c', er, live(Top(c).pc));
    if !P[Top(c).pc].Exit? && !P[Top(c).pc].Ja? { assert Top(c).pc + 1 in Succ(P, Top(c).pc); }
    if P[Top(c).pc].Legacy? {
      assert ReadsL(P[Top(c).pc], live, tbl) == {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      forall r | 0 <= r <= 10 ensures r in ReadsL(P[Top(c).pc], live, tbl) {
        assert r == 0 || r == 1 || r == 2 || r == 3 || r == 4 || r == 5 || r == 6 || r == 7 || r == 8 || r == 9 || r == 10;
      }
    }
    FlFrame(P, ell, c, |c.fr| - 1);
  }

  lemma CHypAcc(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                xP: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er)
    ensures forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
  { reveal CHyp(); }

  lemma CHypIntro(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                  xP: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires var j := Top(c).pc;
      0 <= j < |P| && RelC(P, D, ell, c, c', er, live(j)) && Top(c').pc == E(D, j)
      && RegsOk(P[j]) && ReadsL(P[j], live, tbl) <= live(j)
      && (forall s | s in Succ(P, j) :: s < |P| && live(s) - WritesL(P[j]) <= live(j) && Owner(P, s) == Owner(P, j))
      && (!P[j].Exit? && !P[j].Ja? ==> j + 1 < |P| && E(D, j + 1) == E(D, j) + 1)
      && (forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn))
      && FloorsOk(P, ell) && K(D, j) == E(D, j)
    ensures CHyp(P, D, ell, live, tbl, xP, c, c', er)
  { reveal CHyp(); }

  // ---------------- closing a step ----------------

  // Corr, kept folded in the class lemmas (it is unfolded once, in Step.dfy).
  opaque ghost predicate CorrK(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, c: Cfg, c': Cfg, er: set<nat>) {
    Corr(P, D, ell, live, c, c', er)
  }

  // Only the top frame changed (registers in ws, pc), with the waiting frames as in c.
  lemma {:isolate_assertions} Close(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                    c: Cfg, c': Cfg, er: set<nat>, c1: Cfg, c1': Cfg, ws: set<nat>)
    requires 0 <= Top(c).pc && RelC(P, D, ell, c, c', er, live(Top(c).pc))
    requires |c1.fr| == |c.fr| && |c1'.fr| == |c'.fr| && Below(c1) == Below(c) && Below(c1') == Below(c')
    requires Top(c1).fn == Top(c).fn && Top(c1).kind == Top(c).kind && Top(c1').kind == Top(c').kind
    requires |Top(c1).regs| == NR && |Top(c1).stack| == STK && FrameOk(Top(c1')) && 10 !in ws
    requires |Top(c).regs| == NR && |Top(c').regs| == NR
    requires forall r | 0 <= r < NR && r !in ws :: Top(c1).regs[r] == Top(c).regs[r] && Top(c1').regs[r] == Top(c').regs[r]
    requires forall r | 0 <= r < NR && r in ws :: Rel(Top(c1).regs[r], Top(c1').regs[r])
    requires 0 <= Top(c1).pc < |P| && Owner(P, Top(c1).pc) == Top(c1).fn && Top(c1').pc == E(D, Top(c1).pc)
    requires live(Top(c1).pc) - ws <= live(Top(c).pc)
    requires StkRel(c1, c1', Fl(P, ell, Top(c1).fn)) && c1'.L == c1.L && c1'.h == c1.h
    ensures Inv(P, c1) && CorrK(P, D, ell, live, c1, c1', er)
  {
    RelCIs(P, D, ell, c, c', er, live(Top(c).pc));
    assert Top(c1).regs[10] == Top(c).regs[10];
    assert FrInv(P, |c.fr| - 1, Top(c1));
    InvPut(P, c, c1);
    LowRelSame(P, D, ell, c, c', c1, c1');
    forall r | 0 <= r < NR
      ensures Rel(Reg(Top(c1), r), Reg(Top(c1'), r)) || (r in er && 1 <= r <= 5 && r !in live(Top(c1).pc))
    {
      if r !in ws {
        assert Reg(Top(c1), r) == Reg(Top(c), r) && Reg(Top(c1'), r) == Reg(Top(c'), r);
      }
    }
    assert RegRel(c1, c1', er, live(Top(c1).pc));
    assert TopRel(P, D, ell, live, c1, c1', er);
    CorrIntro(P, D, ell, live, c1, c1', er);
    reveal CorrK();
  }

  lemma SameStk(P: seq<OInstr>, ell: nat -> int, c: Cfg, c': Cfg, c1: Cfg, c1': Cfg)
    requires StkRel(c, c', Fl(P, ell, Top(c).fn)) && Top(c1).stack == Top(c).stack && Top(c1').stack == Top(c').stack
    requires Top(c1).fn == Top(c).fn
    ensures StkRel(c1, c1', Fl(P, ell, Top(c1).fn))
  {}

  // Both runs write the same register with the same value and go on to j + 1.
  lemma {:isolate_assertions} SetDstClose(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                          c: Cfg, c': Cfg, er: set<nat>, dst: nat, v: bv64)
    requires 0 <= Top(c).pc && RelC(P, D, ell, c, c', er, live(Top(c).pc)) && dst <= 9
    requires Top(c).pc + 1 < |P| && Top(c').pc + 1 == E(D, Top(c).pc + 1) && Owner(P, Top(c).pc + 1) == Top(c).fn
    requires live(Top(c).pc + 1) - {dst} <= live(Top(c).pc)
    ensures Inv(P, SetDst(c, dst, v).c) && CorrK(P, D, ell, live, SetDst(c, dst, v).c, SetDst(c', dst, v).c, er)
  {
    RelCFrame(P, D, ell, c, c', er, live(Top(c).pc));
    var c1 := SetDst(c, dst, v).c;
    var c1' := SetDst(c', dst, v).c;
    PutTop(c, Adv(SetR(Top(c), dst, W(v))));
    PutTop(c', Adv(SetR(Top(c'), dst, W(v))));
    SameStk(P, ell, c, c', c1, c1');
    assert FrameOk(Top(c1'));
    Close(P, D, ell, live, c, c', er, c1, c1', {dst});
  }

  // Both runs only advance (after the same change to L, h or the frame's bytes).
  lemma {:isolate_assertions} AdvClose(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                       c: Cfg, c': Cfg, er: set<nat>, cA: Cfg, cA': Cfg)
    requires 0 <= Top(c).pc
    requires RelC(P, D, ell, cA, cA', er, live(Top(c).pc)) && Top(cA).regs == Top(c).regs && Top(cA').regs == Top(c').regs
    requires Top(cA).pc == Top(c).pc && Top(cA').pc == Top(c').pc
    requires Top(c).pc + 1 < |P| && Top(c').pc + 1 == E(D, Top(c).pc + 1) && Owner(P, Top(c).pc + 1) == Top(cA).fn
    requires live(Top(c).pc + 1) <= live(Top(c).pc)
    ensures Inv(P, Put(cA, Adv(Top(cA)))) && CorrK(P, D, ell, live, Put(cA, Adv(Top(cA))), Put(cA', Adv(Top(cA'))), er)
  {
    var c1 := Put(cA, Adv(Top(cA)));
    var c1' := Put(cA', Adv(Top(cA')));
    RelCFrame(P, D, ell, cA, cA', er, live(Top(c).pc));
    PutTop(cA, Adv(Top(cA)));
    PutTop(cA', Adv(Top(cA')));
    SameStk(P, ell, cA, cA', c1, c1');
    Close(P, D, ell, live, cA, cA', er, c1, c1', {});
  }

  // Both runs set the pc only.
  lemma {:isolate_assertions} JumpClose(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                        c: Cfg, c': Cfg, er: set<nat>, cA: Cfg, cA': Cfg, t: int, t': int)
    requires 0 <= Top(c).pc && RelC(P, D, ell, cA, cA', er, live(Top(c).pc))
    requires Top(cA) == Top(c) && Top(cA') == Top(c')
    requires 0 <= t < |P| && t' == E(D, t) && live(t) <= live(Top(c).pc) && Owner(P, t) == Top(c).fn
    ensures Inv(P, Put(cA, Top(cA).(pc := t))) && CorrK(P, D, ell, live, Put(cA, Top(cA).(pc := t)), Put(cA', Top(cA').(pc := t')), er)
  {
    RelCFrame(P, D, ell, cA, cA', er, live(Top(c).pc));
    var c1 := Put(cA, Top(cA).(pc := t));
    var c1' := Put(cA', Top(cA').(pc := t'));
    PutTop(cA, Top(cA).(pc := t));
    PutTop(cA', Top(cA').(pc := t'));
    SameStk(P, ell, cA, cA', c1, c1');
    Close(P, D, ell, live, cA, cA', er, c1, c1', {});
  }

  lemma {:isolate_assertions} ClassAlu(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                       xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Alu?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var ins := P[j];
    assert Reloc(D, ins) == ins;
    assert OStep(xP, ins, j, c) == AluO(xP, c, ins.code, ins.dst, ins.srcs);
    assert OStep(xR, ins, j, c') == AluO(xR, c', ins.code, ins.dst, ins.srcs);
    if ins.dst < 10 && Rds(Top(c), ins.srcs).Some? {
      forall i | 0 <= i < |ins.srcs| ensures Rel(Reg(Top(c), ins.srcs[i]), Reg(Top(c'), ins.srcs[i])) {
        assert ins.srcs[i] in SetOf(ins.srcs) && ins.srcs[i] <= 10;
      }
      RdsRel(Top(c), Top(c'), ins.srcs);
      var v := xP.sem.alu(ins.code, Rds(Top(c), ins.srcs).value);
      assert AluO(xP, c, ins.code, ins.dst, ins.srcs) == SetDst(c, ins.dst, v) by { reveal AluO(); }
      assert AluO(xR, c', ins.code, ins.dst, ins.srcs) == SetDst(c', ins.dst, v) by { reveal AluO(); }
      SetDstClose(P, D, ell, live, c, c', er, ins.dst, v);
    } else {
      assert AluO(xP, c, ins.code, ins.dst, ins.srcs).Stuck? by { reveal AluO(); }
    }
  }

  lemma {:isolate_assertions} ClassFRef(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                        xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].FRef?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var ins := P[j];
    assert Reloc(D, ins) == ins;
    reveal FRefO();
    if ins.dst < 10 && ins.g < 0x1_0000_0000 {
      SetDstClose(P, D, ell, live, c, c', er, ins.dst, FuncAddr(ins.g));
    }
  }

  lemma JccIs(x: Ctx, c: Cfg, code: nat, srcs: seq<nat>, t: nat)
    requires Rds(Top(c), srcs).Some?
    ensures JccO(x, c, code, srcs, t) ==
      Go(Put(c, Top(c).(pc := if x.sem.cond(code, Rds(Top(c), srcs).value) then t else Top(c).pc + 1)))
  { reveal JccO(); }

  lemma {:isolate_assertions} ClassJcc(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                       xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Jcc?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var ins := P[j];
    var t := ins.t;
    assert Reloc(D, ins) == Jcc(ins.code, ins.srcs, E(D, t));
    SuccJ(P, j);
    assert t in Succ(P, j) && j + 1 in Succ(P, j);
    assert OStep(xP, ins, j, c) == JccO(xP, c, ins.code, ins.srcs, t);
    assert OStep(xR, Reloc(D, ins), j, c') == JccO(xR, c', ins.code, ins.srcs, E(D, t));
    if Rds(Top(c), ins.srcs).Some? {
      forall i | 0 <= i < |ins.srcs| ensures Rel(Reg(Top(c), ins.srcs[i]), Reg(Top(c'), ins.srcs[i])) {
        assert ins.srcs[i] in SetOf(ins.srcs) && ins.srcs[i] <= 10;
      }
      RdsRel(Top(c), Top(c'), ins.srcs);
      var b := xP.sem.cond(ins.code, Rds(Top(c), ins.srcs).value);
      var nt := if b then t else j + 1;
      var nt' := if b then E(D, t) else Top(c').pc + 1;
      JccIs(xP, c, ins.code, ins.srcs, t);
      JccIs(xR, c', ins.code, ins.srcs, E(D, t));
      assert xR.sem.cond(ins.code, Rds(Top(c'), ins.srcs).value) == b;
      JumpClose(P, D, ell, live, c, c', er, c, c', nt, nt');
    } else {
      assert JccO(xP, c, ins.code, ins.srcs, t).Stuck? by { reveal JccO(); }
    }
  }

  lemma {:isolate_assertions} ClassJa(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                      xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Ja?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var t := P[j].t;
    assert Reloc(D, P[j]) == Ja(E(D, t));
    assert t in Succ(P, j);
    JumpClose(P, D, ell, live, c, c', er, c, c', t, E(D, t));
  }

  lemma {:isolate_assertions} ClassMayGoto(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                           xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].MayGoto?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var t := P[j].t;
    assert Reloc(D, P[j]) == MayGoto(E(D, t));
    SuccJ(P, j);
    assert t in Succ(P, j) && j + 1 in Succ(P, j);
    var e := EMg(j);
    assert Wh(c) == Wh(c');
    var cA := c.(h := c.h + [e]);
    var cA' := c'.(h := c'.h + [e]);
    assert OStep(xP, P[j], j, c) == MayGotoO(xP, c, j, t);
    assert OStep(xR, Reloc(D, P[j]), j, c') == MayGotoO(xR, c', j, E(D, t));
    RelCH(P, D, ell, c, c', er, live(j), e);
    match xP.om(c.h, e, Wh(c))
    case RTaken =>
      assert MayGotoO(xP, c, j, t) == Go(Put(cA, Top(cA).(pc := t))) by { reveal MayGotoO(); }
      assert MayGotoO(xR, c', j, E(D, t)) == Go(Put(cA', Top(cA').(pc := E(D, t)))) by { reveal MayGotoO(); }
      JumpClose(P, D, ell, live, c, c', er, cA, cA', t, E(D, t));
    case RFall =>
      assert MayGotoO(xP, c, j, t) == Go(Put(cA, Adv(Top(cA)))) by { reveal MayGotoO(); }
      assert MayGotoO(xR, c', j, E(D, t)) == Go(Put(cA', Adv(Top(cA')))) by { reveal MayGotoO(); }
      AdvClose(P, D, ell, live, c, c', er, cA, cA');
    case _ =>
      assert MayGotoO(xP, c, j, t).Stuck? by { reveal MayGotoO(); }
  }

  lemma {:isolate_assertions} ClassExit(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                        xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && PairX(P, D, xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Exit?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    var j := Top(c).pc;
    assert Reloc(D, P[j]) == Exit;
    assert OStep(xP, Exit, j, c) == ExitO(xP, c);
    assert OStep(xR, Exit, j, c') == ExitO(xR, c');
    match Reg(Top(c), 0)
    case W(v) =>
      assert Reg(Top(c'), 0) == W(v);
      assert ExitO(xP, c) == ExitFrame(xP, c, v) by { reveal ExitO(); }
      assert ExitO(xR, c') == ExitFrame(xR, c', v) by { reveal ExitO(); }
      ExitSim(P, D, ell, live, xP, xR, c, c', er, v);
    case Bot =>
      assert ExitO(xP, c).Stuck? by { reveal ExitO(); }
  }

  // ---------------- memory ----------------

  lemma MemAccIn(c: Cfg, p: bv64, w: nat, d: nat, o: nat, k: nat)
    requires Classify(p, w, |c.fr|, c.L.mem.Keys) == InStack(d, o) && o <= k < o + w
    ensures (d, k) in MemAcc(c, p, w)
  {}

  // The stack bytes P reads at or above its floors are the same in P'.
  lemma {:isolate_assertions} StackBytesEq(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>,
                                           p: bv64, w: nat)
    requires RelC(P, D, ell, c, c', er, lv) && FloorsOk(P, ell) && Classify(p, w, |c.fr|, c.L.mem.Keys).InStack?
    requires forall a | a in MemAcc(c, p, w) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires AllDef(StackBytes(c, Classify(p, w, |c.fr|, c.L.mem.Keys).d, Classify(p, w, |c.fr|, c.L.mem.Keys).o, w))
    ensures var cl := Classify(p, w, |c.fr|, c.L.mem.Keys);
      cl.d < |c.fr| && cl.o + w <= STK && Classify(p, w, |c'.fr|, c'.L.mem.Keys) == cl
      && StackBytes(c', cl.d, cl.o, w) == StackBytes(c, cl.d, cl.o, w)
  {
    RelCMem(P, D, ell, c, c', er, lv);
    var cl := Classify(p, w, |c.fr|, c.L.mem.Keys);
    ClassifyStack(p, w, |c.fr|, c.L.mem.Keys);
    var d, o := cl.d, cl.o;
    MemRelE(P, D, ell, c, c');
    InvStack(P, c, d);
    LowRelLen(P, D, ell, c, c');
    StackBytesIs(c, d, o, w);
    if w > 0 {
      MemAccIn(c, p, w, d, o, o);
      ByteEq(P, D, ell, c, c', d, o);
    }
    var st := c.fr[d].stack;
    var st' := c'.fr[d].stack;
    assert |st'| == STK by { if w == 0 { if d < |c.fr| - 1 { LowRelAt(P, D, ell, c, c', d); } else { RelCFrame(P, D, ell, c, c', er, lv); assert c'.fr[d] == Top(c'); } } }
    forall i | o <= i < o + w ensures st'[i] == st[i] {
      MemAccIn(c, p, w, d, o, i);
      ByteEq(P, D, ell, c, c', d, i);
      assert StackBytes(c, d, o, w)[i - o] == st[i];
    }
    SliceEq(st, st', o, w);
    StackBytesIs(c', d, o, w);
  }

  lemma StackBytesIs(c: Cfg, d: nat, o: nat, w: nat)
    requires d < |c.fr| && o + w <= |c.fr[d].stack|
    ensures StackBytes(c, d, o, w) == c.fr[d].stack[o .. o + w]
  {}

  lemma SliceEq<T>(a: seq<T>, b: seq<T>, o: nat, w: nat)
    requires o + w <= |a| && o + w <= |b| && forall i | o <= i < o + w :: b[i] == a[i]
    ensures b[o .. o + w] == a[o .. o + w]
  {
    assert |b[o .. o + w]| == w == |a[o .. o + w]|;
    forall k | 0 <= k < w ensures b[o .. o + w][k] == a[o .. o + w][k] {
      assert b[o .. o + w][k] == b[o + k] && a[o .. o + w][k] == a[o + k];
    }
  }

  lemma WriteTop(c: Cfg, d: nat, o: nat, bs: seq<Byte>)
    requires d < |c.fr| && o + |bs| <= |c.fr[d].stack|
    ensures |WriteStack(c, d, o, bs).fr| == |c.fr| && WriteStack(c, d, o, bs).L == c.L && WriteStack(c, d, o, bs).h == c.h
    ensures d < |c.fr| - 1 ==> Top(WriteStack(c, d, o, bs)) == Top(c)
    ensures d == |c.fr| - 1 ==>
      Top(WriteStack(c, d, o, bs)) == Top(c).(stack := Top(c).stack[..o] + bs + Top(c).stack[o + |bs|..])
  {}

  lemma RegRelSame(c: Cfg, c': Cfg, a: Cfg, a': Cfg, er: set<nat>, lv: set<nat>)
    requires RegRel(c, c', er, lv) && Top(a).regs == Top(c).regs && Top(a').regs == Top(c').regs
    ensures RegRel(a, a', er, lv)
  {
    forall r | 0 <= r < NR ensures Rel(Reg(Top(a), r), Reg(Top(a'), r)) || (r in er && 1 <= r <= 5 && r !in lv) {
      assert Reg(Top(a), r) == Reg(Top(c), r) && Reg(Top(a'), r) == Reg(Top(c'), r);
    }
  }

  lemma FrameOkStack(f: Frame, st: seq<Byte>)
    requires FrameOk(f) && |st| == STK && forall i | 0 <= i < STK :: st[i].B?
    ensures FrameOk(f.(stack := st))
  {}

  lemma InvStack(P: seq<OInstr>, c: Cfg, d: nat)
    requires Inv(P, c) && d < |c.fr|
    ensures |c.fr[d].stack| == STK && |c.fr[d].regs| == NR
  { InvIs(P, c); }

  // Both runs write the same bytes to frame d.
  lemma {:isolate_assertions} WriteRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>,
                                       d: nat, o: nat, bs: seq<Byte>)
    requires RelC(P, D, ell, c, c', er, lv) && d < |c.fr| && o + |bs| <= STK && forall i | 0 <= i < |bs| :: bs[i].B?
    ensures RelC(P, D, ell, WriteStack(c, d, o, bs), WriteStack(c', d, o, bs), er, lv)
    ensures var a := WriteStack(c, d, o, bs); var a' := WriteStack(c', d, o, bs);
      Top(a).pc == Top(c).pc && Top(a').pc == Top(c').pc && Top(a).regs == Top(c).regs && Top(a').regs == Top(c').regs
      && Top(a).fn == Top(c).fn && Top(a).kind == Top(c).kind && Top(a').kind == Top(c').kind
  {
    RelCFrame(P, D, ell, c, c', er, lv);
    RelCLow(P, D, ell, c, c', er, lv);
    RelCRegs(P, D, ell, c, c', er, lv);
    var cA := WriteStack(c, d, o, bs);
    var cA' := WriteStack(c', d, o, bs);
    var n := |c.fr|;
    InvStack(P, c, d);
    if d < n - 1 { LowRelAt(P, D, ell, c, c', d); } else { assert c'.fr[d] == Top(c'); }
    assert |c'.fr[d].stack| == STK;
    LowRelWrite(P, D, ell, c, c', d, o, bs);
    InvWrite(P, c, d, o, bs);
    WriteTop(c, d, o, bs);
    WriteTop(c', d, o, bs);
    if d == n - 1 {
      assert Top(c) == c.fr[d] && Top(c') == c'.fr[d];
      SpliceRel(Top(c).stack, Top(c').stack, o, bs, Fl(P, ell, Top(c).fn));
      FrameOkStack(Top(c'), Top(cA').stack);
      assert StkRel(cA, cA', Fl(P, ell, Top(cA).fn));
    }
    RegRelSame(c, c', cA, cA', er, lv);
    RelCIntro(P, D, ell, cA, cA', er, lv);
  }

  lemma BytesB(bs: seq<bv8>) ensures |Bytes(bs)| == |bs| && forall i | 0 <= i < |Bytes(bs)| :: Bytes(bs)[i].B? {}

  function Ext(sx: bool, w: nat, v: bv64): bv64 { if sx then SextW(v, w) else v }

  // The same step after appending the same event, or writing the same local bytes.
  lemma HSetDst(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                c: Cfg, c': Cfg, er: set<nat>, j: nat, e: Ev, dst: nat, v: bv64)
    requires RelC(P, D, ell, c, c', er, live(j)) && Top(c).pc == j && dst <= 9
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && Owner(P, j + 1) == Top(c).fn && live(j + 1) - {dst} <= live(j)
    ensures Inv(P, SetDst(c.(h := c.h + [e]), dst, v).c)
    ensures CorrK(P, D, ell, live, SetDst(c.(h := c.h + [e]), dst, v).c, SetDst(c'.(h := c'.h + [e]), dst, v).c, er)
  {
    RelCH(P, D, ell, c, c', er, live(j), e);
    SetDstClose(P, D, ell, live, c.(h := c.h + [e]), c'.(h := c'.h + [e]), er, dst, v);
  }

  lemma HAdv(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
             c: Cfg, c': Cfg, er: set<nat>, j: nat, e: Ev)
    requires RelC(P, D, ell, c, c', er, live(j)) && Top(c).pc == j
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && Owner(P, j + 1) == Top(c).fn && live(j + 1) <= live(j)
    ensures var cA := c.(h := c.h + [e]); var cA' := c'.(h := c'.h + [e]);
      Inv(P, Put(cA, Adv(Top(cA)))) && CorrK(P, D, ell, live, Put(cA, Adv(Top(cA))), Put(cA', Adv(Top(cA'))), er)
  {
    var cA := c.(h := c.h + [e]);
    var cA' := c'.(h := c'.h + [e]);
    RelCH(P, D, ell, c, c', er, live(j), e);
    AdvClose(P, D, ell, live, cA, cA', er, cA, cA');
  }

  lemma LAdv(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
             c: Cfg, c': Cfg, er: set<nat>, j: nat, p: bv64, bs: seq<bv8>)
    requires RelC(P, D, ell, c, c', er, live(j)) && Top(c).pc == j
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && Owner(P, j + 1) == Top(c).fn && live(j + 1) <= live(j)
    ensures var cA := WriteLocal(c, p, bs); var cA' := WriteLocal(c', p, bs);
      Inv(P, Put(cA, Adv(Top(cA)))) && CorrK(P, D, ell, live, Put(cA, Adv(Top(cA))), Put(cA', Adv(Top(cA'))), er)
  {
    var cA := WriteLocal(c, p, bs);
    var cA' := WriteLocal(c', p, bs);
    RelCLocal(P, D, ell, c, c', er, live(j), p, bs);
    AdvClose(P, D, ell, live, cA, cA', er, cA, cA');
  }

  lemma SAdv(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
             c: Cfg, c': Cfg, er: set<nat>, j: nat, d: nat, o: nat, bs: seq<Byte>)
    requires RelC(P, D, ell, c, c', er, live(j)) && Top(c).pc == j && d < |c.fr| && o + |bs| <= STK && forall i | 0 <= i < |bs| :: bs[i].B?
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && Owner(P, j + 1) == Top(c).fn && live(j + 1) <= live(j)
    ensures var cA := WriteStack(c, d, o, bs); var cA' := WriteStack(c', d, o, bs);
      Inv(P, Put(cA, Adv(Top(cA)))) && CorrK(P, D, ell, live, Put(cA, Adv(Top(cA))), Put(cA', Adv(Top(cA'))), er)
  {
    var cA := WriteStack(c, d, o, bs);
    var cA' := WriteStack(c', d, o, bs);
    WriteRel(P, D, ell, c, c', er, live(j), d, o, bs);
    AdvClose(P, D, ell, live, cA, cA', er, cA, cA');
  }

  // bpf_tail_call failed: r0..r5 unreadable, next instruction.
  ghost function TailFail(x: Ctx, c: Cfg, e: Ev): Cfg {
    var cA := c.(h := c.h + [e]);
    var f := Top(c);
    var regs := seq(|f.regs|, k requires 0 <= k < |f.regs| => if k <= 5 then Und(x, cA, k) else f.regs[k]);
    Put(cA, f.(pc := f.pc + 1, regs := regs)).(hc := cA.hc + 6)
  }

  lemma TailIs(x: Ctx, c: Cfg, j: nat)
    requires Rds(Top(c), [1, 2, 3]).Some?
    ensures var args := Rds(Top(c), [1, 2, 3]).value; var e := ECall(j, false, 12, args, []);
      TailO(x, c, j) == match x.om(c.h, e, Wh(c))
        case RTailOk(q) => Done(TTail(q, args[0], c.L.(budget := if c.L.budget > 0 then c.L.budget - 1 else 0), c.h + [e]))
        case RTailFail => Go(TailFail(x, c, e))
        case _ => Stuck(false)
  { reveal TailO(); }

  lemma {:isolate_assertions} TailClose(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                                        c: Cfg, c': Cfg, er: set<nat>, j: nat, e: Ev)
    requires RelC(P, D, ell, c, c', er, live(j)) && Top(c).pc == j && Pair(xP, xR)
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && Owner(P, j + 1) == Top(c).fn && live(j + 1) - {0, 1, 2, 3, 4, 5} <= live(j)
    ensures Inv(P, TailFail(xP, c, e)) && CorrK(P, D, ell, live, TailFail(xP, c, e), TailFail(xR, c', e), er)
  {
    RelCIs(P, D, ell, c, c', er, live(j));
    var c1 := TailFail(xP, c, e);
    var c1' := TailFail(xR, c', e);
    var f := Top(c);
    var f' := Top(c');
    var cA := c.(h := c.h + [e]);
    var cA' := c'.(h := c'.h + [e]);
    var regs := seq(|f.regs|, k requires 0 <= k < |f.regs| => if k <= 5 then Und(xP, cA, k) else f.regs[k]);
    var regs' := seq(|f'.regs|, k requires 0 <= k < |f'.regs| => if k <= 5 then Und(xR, cA', k) else f'.regs[k]);
    assert Top(c1) == f.(pc := f.pc + 1, regs := regs) && Top(c1') == f'.(pc := f'.pc + 1, regs := regs');
    forall r | 0 <= r < NR && r in {0, 1, 2, 3, 4, 5} ensures Rel(Top(c1).regs[r], Top(c1').regs[r]) {
      assert Top(c1).regs[r] == Bot;
    }
    assert FrameOk(Top(c1'));
    SameStk(P, ell, c, c', c1, c1');
    Close(P, D, ell, live, c, c', er, c1, c1', {0, 1, 2, 3, 4, 5});
  }

  lemma {:isolate_assertions} LdStepRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                                        c: Cfg, c': Cfg, er: set<nat>, j: nat, dst: nat, p: bv64, w: nat, sx: bool)
    requires RelC(P, D, ell, c, c', er, live(j)) && Top(c).pc == j && Pair(xP, xR) && ValidW(w) && dst <= 9
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && Owner(P, j + 1) == Top(c).fn && live(j + 1) - {dst} <= live(j)
    requires forall a | a in MemAcc(c, p, w) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires FloorsOk(P, ell)
    ensures match LdStep(xP, c, j, dst, p, w, sx)
      case Go(c1) => LdStep(xR, c', j, dst, p, w, sx).Go? && Inv(P, c1)
                     && CorrK(P, D, ell, live, c1, LdStep(xR, c', j, dst, p, w, sx).c, er)
      case Done(_) => false
      case Stuck(_) => true
  {
    RelCShape(P, D, ell, c, c', er, live(j));
    var cl := Classify(p, w, |c.fr|, c.L.mem.Keys);
    assert Classify(p, w, |c'.fr|, c'.L.mem.Keys) == cl;
    match cl
    case InStack(d, o) =>
      if AllDef(StackBytes(c, d, o, w)) {
        StackBytesEq(P, D, ell, c, c', er, live(j), p, w);
        var v := Ext(sx, w, LE(Plain(StackBytes(c, d, o, w))));
        assert LdStep(xP, c, j, dst, p, w, sx) == SetDst(c, dst, v) by { reveal LdStep(); }
        assert LdStep(xR, c', j, dst, p, w, sx) == SetDst(c', dst, v) by { reveal LdStep(); }
        SetDstClose(P, D, ell, live, c, c', er, dst, v);
      } else {
        assert LdStep(xP, c, j, dst, p, w, sx).Stuck? by { reveal LdStep(); }
      }
    case InLocal =>
      var v := Ext(sx, w, LE(LBytes(c.L.mem, p, w)));
      assert LdStep(xP, c, j, dst, p, w, sx) == SetDst(c, dst, v) by { reveal LdStep(); }
      assert LdStep(xR, c', j, dst, p, w, sx) == SetDst(c', dst, v) by { reveal LdStep(); }
      SetDstClose(P, D, ell, live, c, c', er, dst, v);
    case Shared =>
      var e := ELoad(j, p, w);
      assert Wh(c) == Wh(c');
      var cA := c.(h := c.h + [e]);
      var cA' := c'.(h := c'.h + [e]);
      match xP.om(c.h, e, Wh(c)) {
      case RVal(u) =>
        var v := Ext(sx, w, Trunc(u, w));
        assert LdStep(xP, c, j, dst, p, w, sx) == SetDst(cA, dst, v) by { reveal LdStep(); }
        assert LdStep(xR, c', j, dst, p, w, sx) == SetDst(cA', dst, v) by { reveal LdStep(); }
        HSetDst(P, D, ell, live, c, c', er, j, e, dst, v);
      case _ =>
        assert LdStep(xP, c, j, dst, p, w, sx).Stuck? by { reveal LdStep(); }
      }
    case Bad =>
      assert LdStep(xP, c, j, dst, p, w, sx).Stuck? by { reveal LdStep(); }
  }

  lemma {:isolate_assertions} ClassLd(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                      xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Ld?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var ins := P[j];
    assert Reloc(D, ins) == ins;
    var dst, base, off, w, sx := ins.dst, ins.base, ins.off, ins.w, ins.sx;
    assert OStep(xP, ins, j, c) == LdO(xP, c, j, dst, base, off, w, sx);
    assert OStep(xR, ins, j, c') == LdO(xR, c', j, dst, base, off, w, sx);
    if dst < 10 && ValidW(w) && Reg(Top(c), base).W? {
      assert base in ReadsL(ins, live, tbl);
      var p := AddrK(Reg(Top(c), base).w, off);
      assert LdO(xP, c, j, dst, base, off, w, sx) == LdStep(xP, c, j, dst, p, w, sx) by { reveal LdO(); }
      assert LdO(xR, c', j, dst, base, off, w, sx) == LdStep(xR, c', j, dst, p, w, sx) by { reveal LdO(); }
      CHypAcc(P, D, ell, live, tbl, xP, c, c', er);
      assert Acc(P, xP, c) == MemAcc(c, p, w);
      AccMem(P, xP, c, ell, p, w);
      assert j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1);
      assert Owner(P, j + 1) == Top(c).fn;
      assert FloorsOk(P, ell) && Top(c).pc == j;
      LdStepRel(P, D, ell, live, xP, xR, c, c', er, j, dst, p, w, sx);
      var r := LdStep(xP, c, j, dst, p, w, sx);
      if r.Go? { CResGo(P, D, ell, live, xP, xR, c, c', er, r.c, LdStep(xR, c', j, dst, p, w, sx).c); }
      else { CResStuck(P, D, ell, live, xP, xR, c, c', er); }
    } else {
      assert LdO(xP, c, j, dst, base, off, w, sx).Stuck? by { reveal LdO(); }
      CResStuck(P, D, ell, live, xP, xR, c, c', er);
    }
  }

  lemma {:isolate_assertions} StStepRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                                        c: Cfg, c': Cfg, er: set<nat>, j: nat, p: bv64, w: nat, v: bv64)
    requires RelC(P, D, ell, c, c', er, live(j)) && Top(c).pc == j && Pair(xP, xR) && ValidW(w)
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && Owner(P, j + 1) == Top(c).fn && live(j + 1) <= live(j)
    ensures match StStep(xP, c, j, p, w, v)
      case Go(c1) => StStep(xR, c', j, p, w, v).Go? && Inv(P, c1) && CorrK(P, D, ell, live, c1, StStep(xR, c', j, p, w, v).c, er)
      case Done(_) => false
      case Stuck(_) => true
  {
    RelCShape(P, D, ell, c, c', er, live(j));
    var cl := Classify(p, w, |c.fr|, c.L.mem.Keys);
    assert Classify(p, w, |c'.fr|, c'.L.mem.Keys) == cl;
    match cl
    case InStack(d, o) =>
      ClassifyStack(p, w, |c.fr|, c.L.mem.Keys);
      var bs := Bytes(BytesOf(v, w));
      BytesB(BytesOf(v, w));
      var cA := WriteStack(c, d, o, bs);
      var cA' := WriteStack(c', d, o, bs);
      assert StStep(xP, c, j, p, w, v) == Go(Put(cA, Adv(Top(cA)))) by { reveal StStep(); }
      assert StStep(xR, c', j, p, w, v) == Go(Put(cA', Adv(Top(cA')))) by { reveal StStep(); }
      SAdv(P, D, ell, live, c, c', er, j, d, o, bs);
    case InLocal =>
      var cA := WriteLocal(c, p, BytesOf(v, w));
      var cA' := WriteLocal(c', p, BytesOf(v, w));
      assert StStep(xP, c, j, p, w, v) == Go(Put(cA, Adv(Top(cA)))) by { reveal StStep(); }
      assert StStep(xR, c', j, p, w, v) == Go(Put(cA', Adv(Top(cA')))) by { reveal StStep(); }
      LAdv(P, D, ell, live, c, c', er, j, p, BytesOf(v, w));
    case Shared =>
      var e := EStore(j, p, w, v);
      assert Wh(c) == Wh(c');
      var cA := c.(h := c.h + [e]);
      var cA' := c'.(h := c'.h + [e]);
      match xP.om(c.h, e, Wh(c)) {
      case RUnit =>
        assert StStep(xP, c, j, p, w, v) == Go(Put(cA, Adv(Top(cA)))) by { reveal StStep(); }
        assert StStep(xR, c', j, p, w, v) == Go(Put(cA', Adv(Top(cA')))) by { reveal StStep(); }
        HAdv(P, D, ell, live, c, c', er, j, e);
      case _ =>
        assert StStep(xP, c, j, p, w, v).Stuck? by { reveal StStep(); }
      }
    case Bad =>
      assert StStep(xP, c, j, p, w, v).Stuck? by { reveal StStep(); }
  }

  lemma {:isolate_assertions} ClassSt(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                      xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].St?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var ins := P[j];
    assert Reloc(D, ins) == ins;
    var base, off, w, src := ins.base, ins.off, ins.w, ins.src;
    var f := Top(c);
    var f' := Top(c');
    assert OStep(xP, ins, j, c) == StO(xP, c, j, base, off, w, src);
    assert OStep(xR, ins, j, c') == StO(xR, c', j, base, off, w, src);
    var sv := if src.SR? then Reg(f, src.r) else W(src.k);
    if ValidW(w) && Reg(f, base).W? && sv.W? {
      assert base in ReadsL(ins, live, tbl);
      if src.SR? { assert src.r in ReadsL(ins, live, tbl); }
      var sv' := if src.SR? then Reg(f', src.r) else W(src.k);
      assert sv' == sv;
      var p := AddrK(Reg(f, base).w, off);
      var v := Trunc(sv.w, w);
      assert StO(xP, c, j, base, off, w, src) == StStep(xP, c, j, p, w, v) by { reveal StO(); }
      assert StO(xR, c', j, base, off, w, src) == StStep(xR, c', j, p, w, v) by { reveal StO(); }
      assert j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1);
      assert Owner(P, j + 1) == Top(c).fn;
      assert FloorsOk(P, ell) && Top(c).pc == j;
      StStepRel(P, D, ell, live, xP, xR, c, c', er, j, p, w, v);
      var r := StStep(xP, c, j, p, w, v);
      if r.Go? { CResGo(P, D, ell, live, xP, xR, c, c', er, r.c, StStep(xR, c', j, p, w, v).c); }
      else { CResStuck(P, D, ell, live, xP, xR, c, c', er); }
    } else {
      assert StO(xP, c, j, base, off, w, src).Stuck? by { reveal StO(); }
      CResStuck(P, D, ell, live, xP, xR, c, c', er);
    }
  }

  lemma {:isolate_assertions} AtomRegsRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                          cA: Cfg, cA': Cfg, er: set<nat>, j: nat, rs: nat, fetch: bool, cmpx: bool, vold: bv64)
    requires RelC(P, D, ell, cA, cA', er, live(j)) && Top(cA).pc == j && rs <= 9
    requires j + 1 < |P| && Top(cA').pc + 1 == E(D, j + 1) && Owner(P, j + 1) == Top(cA).fn && live(j + 1) <= live(j)
    ensures AtomRegs(cA, rs, fetch, cmpx, vold).Go? && AtomRegs(cA', rs, fetch, cmpx, vold).Go?
    ensures Inv(P, AtomRegs(cA, rs, fetch, cmpx, vold).c)
    ensures CorrK(P, D, ell, live, AtomRegs(cA, rs, fetch, cmpx, vold).c, AtomRegs(cA', rs, fetch, cmpx, vold).c, er)
  {
    if cmpx { SetDstClose(P, D, ell, live, cA, cA', er, 0, vold); }
    else if fetch { SetDstClose(P, D, ell, live, cA, cA', er, rs, vold); }
    else { AdvClose(P, D, ell, live, cA, cA', er, cA, cA'); }
  }

  lemma {:isolate_assertions} AtomStepRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                                          c: Cfg, c': Cfg, er: set<nat>, j: nat, op: nat, p: bv64, w: nat, rs: nat,
                                          fetch: bool, cmpx: bool, n: bv64, xv: Option<bv64>)
    requires RelC(P, D, ell, c, c', er, live(j)) && Top(c).pc == j && Pair(xP, xR) && (w == 4 || w == 8) && rs <= 9
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && Owner(P, j + 1) == Top(c).fn && live(j + 1) <= live(j)
    requires forall a | a in MemAcc(c, p, w) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires FloorsOk(P, ell)
    ensures match AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv)
      case Go(c1) => AtomStep(xR, c', j, op, p, w, rs, fetch, cmpx, n, xv).Go? && Inv(P, c1)
                     && CorrK(P, D, ell, live, c1, AtomStep(xR, c', j, op, p, w, rs, fetch, cmpx, n, xv).c, er)
      case Done(_) => false
      case Stuck(_) => true
  {
    RelCShape(P, D, ell, c, c', er, live(j));
    var cl := Classify(p, w, |c.fr|, c.L.mem.Keys);
    assert Classify(p, w, |c'.fr|, c'.L.mem.Keys) == cl;
    match cl
    case InStack(d, o) =>
      if AllDef(StackBytes(c, d, o, w)) {
        StackBytesEq(P, D, ell, c, c', er, live(j), p, w);
        var vold := LE(Plain(StackBytes(c, d, o, w)));
        var bs := Bytes(BytesOf(xP.sem.rmw(op, w, vold, n, xv), w));
        BytesB(BytesOf(xP.sem.rmw(op, w, vold, n, xv), w));
        var cA := WriteStack(c, d, o, bs);
        var cA' := WriteStack(c', d, o, bs);
        assert AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv) == AtomRegs(cA, rs, fetch, cmpx, vold) by { reveal AtomStep(); }
        assert AtomStep(xR, c', j, op, p, w, rs, fetch, cmpx, n, xv) == AtomRegs(cA', rs, fetch, cmpx, vold) by { reveal AtomStep(); }
        WriteRel(P, D, ell, c, c', er, live(j), d, o, bs);
        AtomRegsRel(P, D, ell, live, cA, cA', er, j, rs, fetch, cmpx, vold);
      } else {
        assert AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv).Stuck? by { reveal AtomStep(); }
      }
    case InLocal =>
      var vold := LE(LBytes(c.L.mem, p, w));
      var cA := WriteLocal(c, p, BytesOf(xP.sem.rmw(op, w, vold, n, xv), w));
      var cA' := WriteLocal(c', p, BytesOf(xP.sem.rmw(op, w, vold, n, xv), w));
      assert AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv) == AtomRegs(cA, rs, fetch, cmpx, vold) by { reveal AtomStep(); }
      assert AtomStep(xR, c', j, op, p, w, rs, fetch, cmpx, n, xv) == AtomRegs(cA', rs, fetch, cmpx, vold) by { reveal AtomStep(); }
      RelCLocal(P, D, ell, c, c', er, live(j), p, BytesOf(xP.sem.rmw(op, w, vold, n, xv), w));
      AtomRegsRel(P, D, ell, live, cA, cA', er, j, rs, fetch, cmpx, vold);
    case Shared =>
      var e := ERmw(j, op, p, w, n, xv);
      assert Wh(c) == Wh(c');
      var cA := c.(h := c.h + [e]);
      var cA' := c'.(h := c'.h + [e]);
      match xP.om(c.h, e, Wh(c)) {
      case RVal(vo) =>
        assert AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv) == AtomRegs(cA, rs, fetch, cmpx, Trunc(vo, w)) by { reveal AtomStep(); }
        assert AtomStep(xR, c', j, op, p, w, rs, fetch, cmpx, n, xv) == AtomRegs(cA', rs, fetch, cmpx, Trunc(vo, w)) by { reveal AtomStep(); }
        RelCH(P, D, ell, c, c', er, live(j), e);
        AtomRegsRel(P, D, ell, live, cA, cA', er, j, rs, fetch, cmpx, Trunc(vo, w));
      case _ =>
        assert AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv).Stuck? by { reveal AtomStep(); }
      }
    case Bad =>
      assert AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv).Stuck? by { reveal AtomStep(); }
  }

  lemma {:isolate_assertions} ClassAtom(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                        xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Atom?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var ins := P[j];
    assert Reloc(D, ins) == ins;
    var op, base, off, w, rs, fetch, cmpx := ins.op, ins.base, ins.off, ins.w, ins.rs, ins.fetch, ins.cmpx;
    var f := Top(c);
    var f' := Top(c');
    assert OStep(xP, ins, j, c) == AtomO(xP, c, j, op, base, off, w, rs, fetch, cmpx);
    assert OStep(xR, ins, j, c') == AtomO(xR, c', j, op, base, off, w, rs, fetch, cmpx);
    if (w == 4 || w == 8) && rs < 10 && Reg(f, base).W? && Reg(f, rs).W? && !(cmpx && Reg(f, 0).Bot?) {
      assert base in ReadsL(ins, live, tbl) && rs in ReadsL(ins, live, tbl);
      assert Reg(f', base) == Reg(f, base) && Reg(f', rs) == Reg(f, rs);
      var p := AddrK(Reg(f, base).w, off);
      var n := Trunc(Reg(f, rs).w, w);
      var xv := if cmpx then Some(Trunc(Reg(f, 0).w, w)) else None;
      assert cmpx ==> Reg(f', 0) == Reg(f, 0);
      assert AtomO(xP, c, j, op, base, off, w, rs, fetch, cmpx) == AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv) by { reveal AtomO(); }
      assert AtomO(xR, c', j, op, base, off, w, rs, fetch, cmpx) == AtomStep(xR, c', j, op, p, w, rs, fetch, cmpx, n, xv) by { reveal AtomO(); }
      CHypAcc(P, D, ell, live, tbl, xP, c, c', er);
      assert Acc(P, xP, c) == MemAcc(c, p, w);
      AccMem(P, xP, c, ell, p, w);
      assert j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1);
      assert Owner(P, j + 1) == Top(c).fn;
      assert FloorsOk(P, ell) && Top(c).pc == j;
      AtomStepRel(P, D, ell, live, xP, xR, c, c', er, j, op, p, w, rs, fetch, cmpx, n, xv);
      var r := AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv);
      if r.Go? { CResGo(P, D, ell, live, xP, xR, c, c', er, r.c, AtomStep(xR, c', j, op, p, w, rs, fetch, cmpx, n, xv).c); }
      else { CResStuck(P, D, ell, live, xP, xR, c, c', er); }
    } else {
      assert AtomO(xP, c, j, op, base, off, w, rs, fetch, cmpx).Stuck? by { reveal AtomO(); }
      CResStuck(P, D, ell, live, xP, xR, c, c', er);
    }
  }

  // ---------------- helpers, legacy loads, tail calls ----------------

  // Both runs resume after a helper with the same result and write set.
  lemma {:isolate_assertions} FinishClose(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                                          cA: Cfg, cA': Cfg, er: set<nat>, j: nat, v: Val, wr: map<int, bv8>)
    requires RelC(P, D, ell, cA, cA', er, live(j)) && Top(cA).pc == j && Pair(xP, xR)
    requires j + 1 < |P| && Top(cA').pc + 1 == E(D, j + 1) && Owner(P, j + 1) == Top(cA).fn
    requires live(j + 1) - {0, 1, 2, 3, 4, 5} <= live(j)
    ensures Finish(xP, cA, v, wr).Go? && Finish(xR, cA', v, wr).Go?
    ensures Inv(P, Finish(xP, cA, v, wr).c) && CorrK(P, D, ell, live, Finish(xP, cA, v, wr).c, Finish(xR, cA', v, wr).c, er)
  {
    RelCFrame(P, D, ell, cA, cA', er, live(j));
    FinishFacts(xP, cA, v, wr);
    FinishFacts(xR, cA', v, wr);
    RelCApply(P, D, ell, cA, cA', er, live(j), wr);
    var a := ApplyW(cA, wr);
    var a' := ApplyW(cA', wr);
    RelCFrame(P, D, ell, a, a', er, live(j));
    var c1 := Finish(xP, cA, v, wr).c;
    var c1' := Finish(xR, cA', v, wr).c;
    assert Top(c1).stack == Top(a).stack && Top(c1').stack == Top(a').stack;
    SameStk(P, ell, a, a', c1, c1');
    forall k | 0 <= k <= 5 ensures Und(xR, cA', k).W? { UndW(xR, cA', k); }
    forall k | 0 <= k < NR ensures Top(c1').regs[k].W? {
      if 6 <= k { assert Top(c1').regs[k] == Top(cA').regs[k]; }
    }
    forall o | 0 <= o < STK ensures Top(c1').stack[o].B? { assert Top(c1').stack[o] == Top(a').stack[o]; }
    assert FrameOk(Top(c1'));
    forall r | 0 <= r < NR && r in {0, 1, 2, 3, 4, 5} ensures Rel(Top(c1).regs[r], Top(c1').regs[r]) {
      if r == 0 { assert Top(c1).regs[0] == (if v.W? then v else Bot); }
      else { assert Top(c1).regs[r] == Und(xP, cA, r) == Bot; }
    }
    assert forall r | 0 <= r < NR && r !in {0, 1, 2, 3, 4, 5} :: Top(c1).regs[r] == Top(a).regs[r] && Top(c1').regs[r] == Top(a').regs[r];
    Close(P, D, ell, live, a, a', er, c1, c1', {0, 1, 2, 3, 4, 5});
  }

  lemma HelperGoK(x: Ctx, c: Cfg, idx: nat, kf: bool, id: bv32, c1: Cfg)
    returns (n: nat, args: seq<bv64>, beta: seq<bv8>, v: Val, wr: map<int, bv8>)
    requires HelperStep(x, c, idx, kf, id, false) == Go(c1)
    ensures n == x.env.arity(kf, id) && n <= 5 && Rds(Top(c), Upto(1, n)) == Some(args)
    ensures FootBytes(c, x.env.foot(kf, id, args)) == FOk(beta)
    ensures x.om(c.h, ECall(idx, kf, id, args, beta), Wh(c)) == RRet(v, wr)
    ensures Finish(x, c.(h := c.h + [ECall(idx, kf, id, args, beta)]), v, wr) == Go(c1)
  {
    reveal HelperStep();
    n := x.env.arity(kf, id);
    args := Rds(Top(c), Upto(1, n)).value;
    beta := FootBytes(c, x.env.foot(kf, id, args)).bs;
    var r := x.om(c.h, ECall(idx, kf, id, args, beta), Wh(c));
    v := r.v;
    wr := r.wr;
  }

  // Footprint addresses of the helper (or callback helper) at the top lie at or above l_F of their frames (A1a).
  lemma {:isolate_assertions} FootFloor(P: seq<OInstr>, x: Ctx, c: Cfg, ell: nat -> int, kf: bool, id: bv32,
                                        n: nat, args: seq<bv64>)
    requires 0 <= Top(c).pc < |P| && (P[Top(c).pc] == Hcall(kf, id) || (!kf && P[Top(c).pc] == CbCall(id)))
    requires |c.fr| > 0
    requires forall a | a in Acc(P, x, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires n == x.env.arity(kf, id) && Rds(Top(c), Upto(1, n)) == Some(args)
    ensures forall i | 0 <= i < |x.env.foot(kf, id, args)| :: FootInF(ell, c, x.env.foot(kf, id, args)[i])
  {
    var addrs := x.env.foot(kf, id, args);
    assert Acc(P, x, c) == HelperAcc(x, c, Top(c).pc, kf, id);
    assert FootAcc(c, addrs) <= Acc(P, x, c);
    forall i | 0 <= i < |addrs| ensures FootInF(ell, c, addrs[i]) {
      if Classify(addrs[i], 1, |c.fr|, c.L.mem.Keys).InStack? { FootAccHas(c, addrs, i); }
    }
  }

  lemma HelperNotDone(x: Ctx, c: Cfg, idx: nat, kf: bool, id: bv32)
    ensures !HelperStep(x, c, idx, kf, id, false).Done?
  { reveal HelperStep(), Finish(); }

  // The frame Push creates.
  ghost function PFrame(x: Ctx, c: Cfg, fn: nat, pc: int, kind: Kind, args: seq<Val>): Frame
    requires |c.fr| < MAXF_RW
  {
    Frame(fn, pc, seq(NR, k requires 0 <= k < NR =>
            if 1 <= k <= 5 && k - 1 < |args| && args[k - 1].W? then args[k - 1]
            else if k == 10 then W(StackTop(|c.fr|)) else Und(x, c, k)),
          kind, seq(STK, i requires 0 <= i < STK => UndB(x, c, NR + i)))
  }

  lemma PushIs(x: Ctx, c: Cfg, fn: nat, pc: int, kind: Kind, args: seq<Val>)
    ensures |c.fr| >= Limit(x) ==> Push(x, c, fn, pc, kind, args) == Stuck(false)
    ensures |c.fr| < Limit(x) ==>
      (|c.fr| < MAXF_RW
       && Push(x, c, fn, pc, kind, args) == Go(c.(fr := c.fr + [PFrame(x, c, fn, pc, kind, args)], hc := c.hc + NR + STK)))
  { reveal Push(); }

  lemma PFrameFacts(x: Ctx, c: Cfg, fn: nat, pc: int, kind: Kind, args: seq<Val>)
    requires |c.fr| < MAXF_RW
    ensures var f := PFrame(x, c, fn, pc, kind, args);
      f.fn == fn && f.pc == pc && f.kind == kind && |f.regs| == NR && |f.stack| == STK
      && f.regs[10] == W(StackTop(|c.fr|))
      && (forall k | 1 <= k <= 5 && k - 1 < |args| && args[k - 1].W? :: f.regs[k] == args[k - 1])
      && (x.m.MP? ==> PFrameBot(f, args))
      && (x.m.MR? ==> FrameOk(f))
  {
    var f := PFrame(x, c, fn, pc, kind, args);
    if x.m.MP? { PFrameP(x, c, fn, pc, kind, args); }
    if x.m.MR? { PFrameR(x, c, fn, pc, kind, args); }
  }

  // In P, every register but the arguments and r10, and every stack byte, is unreadable.
  ghost predicate PFrameBot(f: Frame, args: seq<Val>) {
    |f.regs| == NR && |f.stack| == STK
    && (forall k | 0 <= k < NR && !(1 <= k <= 5 && k - 1 < |args| && args[k - 1].W?) && k != 10 :: f.regs[k] == Bot)
    && (forall i | 0 <= i < STK :: f.stack[i] == BBot)
  }

  lemma PFrameP(x: Ctx, c: Cfg, fn: nat, pc: int, kind: Kind, args: seq<Val>)
    requires |c.fr| < MAXF_RW && x.m.MP?
    ensures PFrameBot(PFrame(x, c, fn, pc, kind, args), args)
  {
    var f := PFrame(x, c, fn, pc, kind, args);
    forall k | 0 <= k < NR && !(1 <= k <= 5 && k - 1 < |args| && args[k - 1].W?) && k != 10 ensures f.regs[k] == Bot {
      assert f.regs[k] == Und(x, c, k);
    }
    forall i | 0 <= i < STK ensures f.stack[i] == BBot { assert f.stack[i] == UndB(x, c, NR + i); }
  }

  lemma PFrameR(x: Ctx, c: Cfg, fn: nat, pc: int, kind: Kind, args: seq<Val>)
    requires |c.fr| < MAXF_RW && x.m.MR?
    ensures FrameOk(PFrame(x, c, fn, pc, kind, args))
  {
    var f := PFrame(x, c, fn, pc, kind, args);
    forall k | 0 <= k < NR ensures f.regs[k].W? {
      if !(1 <= k <= 5 && k - 1 < |args| && args[k - 1].W?) && k != 10 { assert f.regs[k] == Und(x, c, k); }
    }
    forall i | 0 <= i < STK ensures f.stack[i].B? { assert f.stack[i] == UndB(x, c, NR + i); }
  }

  // Both runs pushed a frame for function g; P' stands at fe(g).
  lemma {:isolate_assertions} EnterRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                       cB: Cfg, cB': Cfg, c1: Cfg, c1': Cfg, F: Frame, F': Frame, er: set<nat>, g: nat)
    requires Inv(P, cB) && LowRel(P, D, ell, cB, cB') && WaitRel(P, D, ell, Top(cB), Top(cB'))
    requires c1.fr == cB.fr + [F] && c1'.fr == cB'.fr + [F'] && |cB.fr| < MAXF
    requires c1.L == cB.L && c1'.L == cB'.L && c1.h == cB.h && c1'.h == cB'.h && cB'.L == cB.L && cB'.h == cB.h
    requires g in FnSet(P) && g < |P| && F.fn == g && F.pc == g && F'.pc == FE(D, g) && F'.kind == F.kind
    requires (F.kind.Sub? || F.kind.Cb?) && Waits(P, Top(cB), F.kind)
    requires |F.regs| == NR && |F.stack| == STK && F.regs[10] == W(StackTop(|cB.fr|)) && F.regs[0] == Bot && FrameOk(F')
    requires forall i | 0 <= i < STK :: F.stack[i] == BBot
    requires forall r | 0 <= r < NR :: Rel(F.regs[r], F'.regs[r]) || (r in er && 1 <= r <= 5 && r !in live(g))
    ensures Inv(P, c1) && PendK(P, D, ell, live, c1, c1', er)
  {
    OwnerFn(P, g);
    assert FrInv(P, |cB.fr|, F);
    InvPush(P, cB, c1, F);
    assert Top(c1) == F && Top(c1') == F';
    var Fx := F'.(pc := E(D, g));
    var c1x := Put(c1', Fx);
    assert c1x.fr == cB'.fr + [Fx];
    LowRelPush(P, D, ell, cB, cB', c1, c1x, F, Fx);
    assert Top(c1x) == Fx;
    assert RegRel(c1, c1x, er, live(g)) by {
      forall r | 0 <= r < NR ensures Rel(Reg(Top(c1), r), Reg(Top(c1x), r)) || (r in er && 1 <= r <= 5 && r !in live(g)) {
        assert Reg(Top(c1), r) == F.regs[r] && Reg(Top(c1x), r) == F'.regs[r];
      }
    }
    assert StkRel(c1, c1x, Fl(P, ell, g));
    assert TopRel(P, D, ell, live, c1, c1x, er);
    CorrIntro(P, D, ell, live, c1, c1x, er);
    reveal PendK();
  }

  // The top frame of RelC as a waiting frame, when P' is at kappa(pc).
  lemma WaitFromRelC(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires RelC(P, D, ell, c, c', er, lv) && 0 <= Top(c).pc < |P| && Top(c').pc == K(D, Top(c).pc)
    ensures WaitRel(P, D, ell, Top(c), Top(c'))
  {
    RelCIs(P, D, ell, c, c', er, lv);
    forall r | 6 <= r < NR ensures Rel(Top(c).regs[r], Top(c').regs[r]) { assert Rel(Reg(Top(c), r), Reg(Top(c'), r)); }
  }

  // The callback at cv is invoked in both runs, from the frame waiting at i.
  lemma {:isolate_assertions} InvokeSim(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                                        cB: Cfg, cB': Cfg, er: set<nat>, i: nat, cv: bv64, u: seq<Val>)
    requires Inv(P, cB) && LowRel(P, D, ell, cB, cB') && WaitRel(P, D, ell, Top(cB), Top(cB'))
    requires cB'.L == cB.L && cB'.h == cB.h && PairX(P, D, xP, xR) && Waits(P, Top(cB), Cb(i))
    ensures match Invoke(xP, cB, i, cv, u)
      case Go(c1) => Invoke(xR, cB', i, cv, u).Go? && Inv(P, c1) && PendK(P, D, ell, live, c1, Invoke(xR, cB', i, cv, u).c, er)
      case Done(_) => false
      case Stuck(_) => true
  {
    reveal Invoke();
    LowRelLen(P, D, ell, cB, cB');
    InvIs(P, cB);
    var g := cv as int - CODE0;
    if g >= 0 && g in xP.fns {
      var gn: nat := g;
      assert gn in FnSet(P) && xR.fns == xP.fns;
      assert xP.fentry(gn) == gn && xR.fentry(gn) == FE(D, gn) && gn < |P|;
      assert Invoke(xP, cB, i, cv, u) == Push(xP, cB, gn, gn, Cb(i), u);
      assert Invoke(xR, cB', i, cv, u) == Push(xR, cB', FE(D, gn), FE(D, gn), Cb(i), u);
      PushIs(xP, cB, gn, gn, Cb(i), u);
      PushIs(xR, cB', FE(D, gn), FE(D, gn), Cb(i), u);
      if |cB.fr| < MAXF {
        var F := PFrame(xP, cB, gn, gn, Cb(i), u);
        var F' := PFrame(xR, cB', FE(D, gn), FE(D, gn), Cb(i), u);
        PFrameFacts(xP, cB, gn, gn, Cb(i), u);
        PFrameFacts(xR, cB', FE(D, gn), FE(D, gn), Cb(i), u);
        var c1 := cB.(fr := cB.fr + [F], hc := cB.hc + NR + STK);
        var c1' := cB'.(fr := cB'.fr + [F'], hc := cB'.hc + NR + STK);
        forall r | 0 <= r < NR ensures Rel(F.regs[r], F'.regs[r]) {
          if 1 <= r <= 5 && r - 1 < |u| && u[r - 1].W? { } else if r == 10 { } else { assert F.regs[r] == Bot; }
        }
        EnterRel(P, D, ell, live, cB, cB', c1, c1', F, F', er, gn);
      }
    }
  }

  ghost function CArgs(c: Cfg): seq<Val> { seq(5, k requires 0 <= k < 5 => Reg(Top(c), k + 1)) }

  // A BPF-to-BPF call at Top(c).pc, made in P' from c2 (P' at kappa(pc), the caller's r1..r5 as stated).
  lemma {:isolate_assertions} CallCore(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                                       c: Cfg, c2: Cfg, er: set<nat>, t: nat)
    requires Inv(P, c) && LowRel(P, D, ell, c, c2) && WaitRel(P, D, ell, Top(c), Top(c2))
    requires c2.L == c.L && c2.h == c.h && PairX(P, D, xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc] == Call(t)
    requires forall k | 1 <= k <= 5 :: Rel(Reg(Top(c), k), Reg(Top(c2), k)) || (k in er && k !in live(t))
    ensures match Push(xP, c, t, t, Sub, CArgs(c))
      case Go(c1) => Push(xR, c2, FE(D, t), FE(D, t), Sub, CArgs(c2)).Go? && Inv(P, c1)
                     && PendK(P, D, ell, live, c1, Push(xR, c2, FE(D, t), FE(D, t), Sub, CArgs(c2)).c, er)
      case Done(_) => false
      case Stuck(_) => true
  {
    LowRelLen(P, D, ell, c, c2);
    InvIs(P, c);
    var j := Top(c).pc;
    assert t in FnSet(P) by { assert P[j].Call? && P[j].t == t; }
    assert t < |P|;
    PushIs(xP, c, t, t, Sub, CArgs(c));
    PushIs(xR, c2, FE(D, t), FE(D, t), Sub, CArgs(c2));
    if |c.fr| < MAXF {
      var F := PFrame(xP, c, t, t, Sub, CArgs(c));
      var F' := PFrame(xR, c2, FE(D, t), FE(D, t), Sub, CArgs(c2));
      PFrameFacts(xP, c, t, t, Sub, CArgs(c));
      PFrameFacts(xR, c2, FE(D, t), FE(D, t), Sub, CArgs(c2));
      var c1 := c.(fr := c.fr + [F], hc := c.hc + NR + STK);
      var c1' := c2.(fr := c2.fr + [F'], hc := c2.hc + NR + STK);
      assert FrameOk(Top(c2)) && |Top(c2).regs| == NR;
      forall r | 0 <= r < NR ensures Rel(F.regs[r], F'.regs[r]) || (r in er && 1 <= r <= 5 && r !in live(t)) {
        if 1 <= r <= 5 {
          assert CArgs(c)[r - 1] == Reg(Top(c), r) && CArgs(c2)[r - 1] == Reg(Top(c2), r);
          assert Reg(Top(c2), r).W?;
        } else if r != 10 { assert F.regs[r] == Bot; }
      }
      assert Waits(P, Top(c), Sub);
      EnterRel(P, D, ell, live, c, c2, c1, c1', F, F', er, t);
    }
  }

  lemma CallReads(P: seq<OInstr>, j: nat, live: nat -> set<nat>, tbl: bv32 -> set<nat>, k: nat)
    requires j < |P| && P[j].Call? && 1 <= k <= 5 && k in live(P[j].t)
    ensures k in ReadsL(P[j], live, tbl)
  {}

  lemma {:isolate_assertions} ClassCall(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                        xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && PairX(P, D, xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Call?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCIs(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var t := P[j].t;
    assert Reloc(D, P[j]) == Call(FE(D, t));
    assert OStep(xP, P[j], j, c) == Push(xP, c, t, t, Sub, CArgs(c));
    assert OStep(xR, Call(FE(D, t)), j, c') == Push(xR, c', FE(D, t), FE(D, t), Sub, CArgs(c'));
    WaitFromRelC(P, D, ell, c, c', er, live(j));
    forall k | 1 <= k <= 5 ensures Rel(Reg(Top(c), k), Reg(Top(c'), k)) || (k in er && k !in live(t)) {
      if k in live(t) { CallReads(P, j, live, tbl, k); }
    }
    CallCore(P, D, ell, live, xP, xR, c, c', er, t);
    match Push(xP, c, t, t, Sub, CArgs(c))
    case Go(c1) => CResPend(P, D, ell, live, xP, xR, c, c', er, c1, Push(xR, c', FE(D, t), FE(D, t), Sub, CArgs(c')).c);
    case Stuck(_) => CResStuck(P, D, ell, live, xP, xR, c, c', er);
  }

  // The helper step of a callback helper that went on.
  lemma CbGo(x: Ctx, c: Cfg, idx: nat, id: bv32, c1: Cfg) returns (n: nat, args: seq<bv64>, beta: seq<bv8>, r: Resp)
    requires HelperStep(x, c, idx, false, id, true) == Go(c1)
    ensures n == x.env.arity(false, id) && n <= 5 && Rds(Top(c), Upto(1, n)) == Some(args)
    ensures FootBytes(c, x.env.foot(false, id, args)) == FOk(beta)
    ensures x.om(c.h, ECall(idx, false, id, args, beta), Wh(c)) == r && (r.RRet? || r.RInvoke?)
    ensures var cA := c.(h := c.h + [ECall(idx, false, id, args, beta)]);
      (r.RRet? ==> Finish(x, cA, r.v, r.wr) == Go(c1)) && (r.RInvoke? ==> Invoke(x, cA, idx, r.c, r.u) == Go(c1))
  {
    reveal HelperStep();
    n := x.env.arity(false, id);
    args := Rds(Top(c), Upto(1, n)).value;
    beta := FootBytes(c, x.env.foot(false, id, args)).bs;
    r := x.om(c.h, ECall(idx, false, id, args, beta), Wh(c));
  }

  lemma CbSame(x: Ctx, c: Cfg, idx: nat, id: bv32, n: nat, args: seq<bv64>, beta: seq<bv8>, r: Resp)
    requires n == x.env.arity(false, id) && n <= 5 && Rds(Top(c), Upto(1, n)) == Some(args)
    requires FootBytes(c, x.env.foot(false, id, args)) == FOk(beta)
    requires x.om(c.h, ECall(idx, false, id, args, beta), Wh(c)) == r && (r.RRet? || r.RInvoke?)
    ensures var cA := c.(h := c.h + [ECall(idx, false, id, args, beta)]);
      HelperStep(x, c, idx, false, id, true) == if r.RRet? then Finish(x, cA, r.v, r.wr) else Invoke(x, cA, idx, r.c, r.u)
  { reveal HelperStep(); }

  lemma CbNotDone(x: Ctx, c: Cfg, idx: nat, id: bv32)
    ensures !HelperStep(x, c, idx, false, id, true).Done?
  { reveal HelperStep(), Finish(), Invoke(), Push(); }

  lemma {:isolate_assertions} ClassCbCall(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                          xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && PairX(P, D, xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].CbCall?
    requires A3b(xP.env, tbl)
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCIs(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var ins := P[j];
    var id := ins.id;
    assert Reloc(D, ins) == ins;
    assert OStep(xP, ins, j, c) == HelperStep(xP, c, j, false, id, true);
    assert OStep(xR, ins, j, c') == HelperStep(xR, c', j, false, id, true);
    CbNotDone(xP, c, j, id);
    if HelperStep(xP, c, j, false, id, true).Go? {
      var c1 := HelperStep(xP, c, j, false, id, true).c;
      var n, args, beta, r := CbGo(xP, c, j, id, c1);
      forall i | 0 <= i < |Upto(1, n)| ensures Rel(Reg(Top(c), Upto(1, n)[i]), Reg(Top(c'), Upto(1, n)[i])) {
        UptoAt(1, n, i);
        assert 1 + i in tbl(id);
        assert 1 + i in ReadsL(ins, live, tbl);
      }
      RdsRel(Top(c), Top(c'), Upto(1, n));
      var addrs := xP.env.foot(false, id, args);
      CHypAcc(P, D, ell, live, tbl, xP, c, c', er);
      FootFloor(P, xP, c, ell, false, id, n, args);
      RelCMem(P, D, ell, c, c', er, live(j));
      FootRelG(P, D, ell, c, c', addrs);
      var e := ECall(j, false, id, args, beta);
      var cA := c.(h := c.h + [e]);
      var cA' := c'.(h := c'.h + [e]);
      CbSame(xR, c', j, id, n, args, beta, r);
      RelCH(P, D, ell, c, c', er, live(j), e);
      if r.RRet? {
        FinishClose(P, D, ell, live, xP, xR, cA, cA', er, j, r.v, r.wr);
        CResGo(P, D, ell, live, xP, xR, c, c', er, c1, Finish(xR, cA', r.v, r.wr).c);
      } else {
        RelCIs(P, D, ell, cA, cA', er, live(j));
        WaitFromRelC(P, D, ell, cA, cA', er, live(j));
        InvokeSim(P, D, ell, live, xP, xR, cA, cA', er, j, r.c, r.u);
        CResPend(P, D, ell, live, xP, xR, c, c', er, c1, Invoke(xR, cA', j, r.c, r.u).c);
      }
    } else {
      CResStuck(P, D, ell, live, xP, xR, c, c', er);
    }
  }

  // The frame below a returning frame, in both runs.
  lemma {:isolate_assertions} ResumeBase(P: seq<OInstr>, D: Decomp, ell: nat -> int, c: Cfg, c': Cfg, cB: Cfg, cB': Cfg)
    requires Inv(P, c) && LowRel(P, D, ell, c, c') && |c.fr| > 1
    requires cB.fr == Pop(c).fr && cB'.fr == Pop(c').fr
    ensures Inv(P, cB) && LowRel(P, D, ell, cB, cB') && WaitRel(P, D, ell, Top(cB), Top(cB'))
    ensures |cB.fr| == |c.fr| - 1 > 0 && |cB'.fr| == |cB.fr| && FrInv(P, |cB.fr| - 1, Top(cB))
    ensures P[Top(cB).pc].Call? || P[Top(cB).pc].CbCall?
  {
    InvIs(P, c);
    LowRelLen(P, D, ell, c, c');
    var n := |c.fr|;
    InvPop(P, c);
    LowRelPop(P, D, ell, c, c');
    InvFields(P, Pop(c), cB);
    LowRelSame(P, D, ell, Pop(c), Pop(c'), cB, cB');
    assert Top(cB) == c.fr[n - 2] == Top(Pop(c)) && Top(cB') == Top(Pop(c'));
    assert Waits(P, Top(cB), Top(c).kind);
    InvIs(P, cB);
  }

  // The resumed top frame, from its waiting frame and the finish in both runs.
  lemma {:isolate_assertions} ResumeTop(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                        f: Frame, f': Frame, c1: Cfg, c1': Cfg, v: Val, wr: map<int, bv8>, d: nat, er: set<nat>)
    requires WaitRel(P, D, ell, f, f') && f.pc + 1 < |P| && E(D, f.pc + 1) == K(D, f.pc) + 1
    requires |c1.fr| > 0 && |c1'.fr| > 0
    requires Top(c1).kind == f.kind && Top(c1').kind == f'.kind && |Top(c1).regs| == NR && |Top(c1').regs| == NR
    requires Top(c1).fn == f.fn && Top(c1).pc == f.pc + 1 && Top(c1').pc == f'.pc + 1
    requires Top(c1).regs[0] == (if v.W? then v else Bot) && Top(c1').regs[0].W? && (v.W? ==> Top(c1').regs[0] == v)
    requires forall k | 1 <= k <= 5 :: Top(c1).regs[k] == Bot && Top(c1').regs[k].W?
    requires forall k | 6 <= k < NR :: Top(c1).regs[k] == f.regs[k] && Top(c1').regs[k] == f'.regs[k]
    requires Top(c1).stack == ApplyF(f, d, wr).stack && Top(c1').stack == ApplyF(f', d, wr).stack
    requires c1'.L == c1.L && c1'.h == c1.h
    ensures TopRel(P, D, ell, live, c1, c1', er)
  {
    forall k | 0 <= k < NR ensures Top(c1').regs[k].W? {}
    forall o | 0 <= o < STK ensures Top(c1').stack[o].B? {}
    assert FrameOk(Top(c1'));
    forall r | 0 <= r < NR ensures Rel(Reg(Top(c1), r), Reg(Top(c1'), r)) {}
    assert RegRel(c1, c1', er, live(Top(c1).pc));
    assert StkRel(c1, c1', Fl(P, ell, Top(c1).fn));
  }

  // The frame below the top resumes after its call or callback helper, with result v and write set wr.
  lemma {:isolate_assertions} ResumeClose(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                                          c: Cfg, c': Cfg, er: set<nat>, cB: Cfg, cB': Cfg, v: Val, wr: map<int, bv8>)
    requires 0 <= Top(c).pc && RelC(P, D, ell, c, c', er, live(Top(c).pc)) && PairX(P, D, xP, xR) && |c.fr| > 1
    requires cB.fr == Pop(c).fr && cB'.fr == Pop(c').fr && cB'.L == cB.L && cB'.h == cB.h
    ensures Finish(xP, cB, v, wr).Go? && Finish(xR, cB', v, wr).Go?
    ensures Inv(P, Finish(xP, cB, v, wr).c) && CorrK(P, D, ell, live, Finish(xP, cB, v, wr).c, Finish(xR, cB', v, wr).c, er)
  {
    RelCLow(P, D, ell, c, c', er, live(Top(c).pc));
    ResumeBase(P, D, ell, c, c', cB, cB');
    var f := Top(cB);
    var f' := Top(cB');
    var i := f.pc;
    assert RetOk(P, D);
    assert i + 1 < |P| && E(D, i + 1) == K(D, i) + 1 && Owner(P, i + 1) == Owner(P, i);
    FinishFacts(xP, cB, v, wr);
    FinishFacts(xR, cB', v, wr);
    ApplyTop(cB, wr);
    ApplyTop(cB', wr);
    var c1 := Finish(xP, cB, v, wr).c;
    var c1' := Finish(xR, cB', v, wr).c;
    AfterFrames(P, D, ell, cB, cB', cB, wr, c1, c1');
    forall k | 0 <= k <= 5 ensures Und(xR, cB', k).W? { UndW(xR, cB', k); }
    ResumeTop(P, D, ell, live, f, f', c1, c1', v, wr, |cB.fr| - 1, er);
    CorrIntro(P, D, ell, live, c1, c1', er);
    reveal CorrK();
  }

  lemma ExitCbIs(x: Ctx, c: Cfg, v: bv64, i: nat)
    requires Top(c).kind == Cb(i) && |c.fr| > 1
    ensures var e := ECbRet(i, v); var c2 := Pop(c).(h := c.h + [e]);
      ExitFrame(x, c, v) == match x.om(c.h, e, Wh(Pop(c)))
        case RInvoke(cv, u) => Invoke(x, c2, i, cv, u)
        case RRet(v', wr) => Finish(x, c2, v', wr)
        case _ => Stuck(false)
  { reveal ExitFrame(); }

  // exit of the top frame with r0 = v, in both runs.
  lemma {:isolate_assertions} ExitSim(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                                      c: Cfg, c': Cfg, er: set<nat>, v: bv64)
    requires 0 <= Top(c).pc && RelC(P, D, ell, c, c', er, live(Top(c).pc)) && PairX(P, D, xP, xR)
    ensures match ExitFrame(xP, c, v)
      case Go(c1) => ExitFrame(xR, c', v).Go? && Inv(P, c1)
                     && (CorrK(P, D, ell, live, c1, ExitFrame(xR, c', v).c, er) || PendK(P, D, ell, live, c1, ExitFrame(xR, c', v).c, er))
      case Done(t) => ExitFrame(xR, c', v) == Done(t)
      case Stuck(_) => true
  {
    RelCIs(P, D, ell, c, c', er, live(Top(c).pc));
    InvIs(P, c);
    var n := |c.fr|;
    match Top(c).kind
    case Main => reveal ExitFrame();
    case Sub =>
      assert ExitFrame(xP, c, v) == Finish(xP, Pop(c), W(v), map[]) by { reveal ExitFrame(); }
      assert ExitFrame(xR, c', v) == Finish(xR, Pop(c'), W(v), map[]) by { reveal ExitFrame(); }
      ResumeClose(P, D, ell, live, xP, xR, c, c', er, Pop(c), Pop(c'), W(v), map[]);
    case Cb(i) =>
      InvPop(P, c);
      LowRelPop(P, D, ell, c, c');
      var c1 := Pop(c);
      var c1' := Pop(c');
      assert Wh(c1) == Wh(c1');
      var e := ECbRet(i, v);
      var c2 := c1.(h := c.h + [e]);
      var c2' := c1'.(h := c'.h + [e]);
      ExitCbIs(xP, c, v, i);
      ExitCbIs(xR, c', v, i);
      match xP.om(c.h, e, Wh(c1)) {
      case RInvoke(cv, u) =>
        InvFields(P, c1, c2);
        LowRelSame(P, D, ell, c1, c1', c2, c2');
        assert Top(c2) == Top(c1) == c.fr[n - 2] && Top(c2') == Top(c1');
        InvokeSim(P, D, ell, live, xP, xR, c2, c2', er, i, cv, u);
      case RRet(v', wr) =>
        ResumeClose(P, D, ell, live, xP, xR, c, c', er, c2, c2', v', wr);
      case _ =>
      }
  }

  lemma {:isolate_assertions} ClassHcall(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                         xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Hcall? && A3b(xP.env, tbl)
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCIs(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var ins := P[j];
    var kf, id := ins.kf, ins.id;
    assert Reloc(D, ins) == ins;
    assert OStep(xP, ins, j, c) == HelperStep(xP, c, j, kf, id, false);
    assert OStep(xR, ins, j, c') == HelperStep(xR, c', j, kf, id, false);
    HelperNotDone(xP, c, j, kf, id);
    if HelperStep(xP, c, j, kf, id, false).Go? {
      var c1 := HelperStep(xP, c, j, kf, id, false).c;
      var n, args, beta, v, wr := HelperGoK(xP, c, j, kf, id, c1);
      forall i | 0 <= i < |Upto(1, n)| ensures Rel(Reg(Top(c), Upto(1, n)[i]), Reg(Top(c'), Upto(1, n)[i])) {
        UptoAt(1, n, i);
        var r := 1 + i;
        if kf { assert r in {1, 2, 3, 4, 5}; } else { assert r in tbl(id); }
        assert r in ReadsL(ins, live, tbl);
      }
      RdsRel(Top(c), Top(c'), Upto(1, n));
      var addrs := xP.env.foot(kf, id, args);
      CHypAcc(P, D, ell, live, tbl, xP, c, c', er);
      FootFloor(P, xP, c, ell, kf, id, n, args);
      RelCMem(P, D, ell, c, c', er, live(j));
      FootRelG(P, D, ell, c, c', addrs);
      var e := ECall(j, kf, id, args, beta);
      var cA := c.(h := c.h + [e]);
      var cA' := c'.(h := c'.h + [e]);
      assert HelperStep(xR, c', j, kf, id, false) == Finish(xR, cA', v, wr) by { reveal HelperStep(); }
      RelCH(P, D, ell, c, c', er, live(j), e);
      FinishClose(P, D, ell, live, xP, xR, cA, cA', er, j, v, wr);
    }
  }

  lemma {:isolate_assertions} ClassLegacy(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                          xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && PairX(P, D, xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Legacy?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var ins := P[j];
    var w, ix, off := ins.w, ins.ix, ins.off;
    assert Reloc(D, ins) == ins;
    var f := Top(c);
    var f' := Top(c');
    assert OStep(xP, ins, j, c) == LegacyO(xP, c, w, ix, off);
    assert OStep(xR, ins, j, c') == LegacyO(xR, c', w, ix, off);
    var iv := if ix.Some? then Reg(f, ix.value) else W(0);
    if Reg(f, 6).W? && iv.W? {
      assert Reg(f', 6) == Reg(f, 6);
      if ix.Some? {
        assert ix.value <= 10;
        assert Reg(f', ix.value) == Reg(f, ix.value);
      }
      var r := xP.sem.legacy(c.L, Reg(f, 6).w, if ix.Some? then Some(iv.w) else None, off, w);
      match r
      case Some(v) =>
        assert LegacyO(xP, c, w, ix, off) == Finish(xP, c, W(v), map[]) by { reveal LegacyO(); }
        assert LegacyO(xR, c', w, ix, off) == Finish(xR, c', W(v), map[]) by { reveal LegacyO(); }
        FinishClose(P, D, ell, live, xP, xR, c, c', er, j, W(v), map[]);
      case None =>
        assert LegacyO(xP, c, w, ix, off) == ExitFrame(xP, c, 0) by { reveal LegacyO(); }
        assert LegacyO(xR, c', w, ix, off) == ExitFrame(xR, c', 0) by { reveal LegacyO(); }
        ExitSim(P, D, ell, live, xP, xR, c, c', er, 0);
    } else {
      assert LegacyO(xP, c, w, ix, off).Stuck? by { reveal LegacyO(); }
    }
  }

  lemma {:isolate_assertions} ClassTail(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                        xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Tail? && A3b(xP.env, tbl)
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, D, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    var ins := P[j];
    assert Reloc(D, ins) == ins;
    assert WritesL(ins) == {0, 1, 2, 3, 4, 5};
    var f := Top(c);
    var f' := Top(c');
    assert OStep(xP, ins, j, c) == TailO(xP, c, j);
    assert OStep(xR, ins, j, c') == TailO(xR, c', j);
    if Rds(f, [1, 2, 3]).Some? {
      forall i | 0 <= i < 3 ensures Rel(Reg(f, [1, 2, 3][i]), Reg(f', [1, 2, 3][i])) {
        assert [1, 2, 3][i] in tbl(12);
        assert [1, 2, 3][i] in ReadsL(ins, live, tbl);
      }
      RdsRel(f, f', [1, 2, 3]);
      var args := Rds(f, [1, 2, 3]).value;
      var e := ECall(j, false, 12, args, []);
      TailIs(xP, c, j);
      TailIs(xR, c', j);
      match xP.om(c.h, e, Wh(c)) {
        case RTailOk(q) =>
          var t := TTail(q, args[0], c.L.(budget := if c.L.budget > 0 then c.L.budget - 1 else 0), c.h + [e]);
          CResDone(P, D, ell, live, xP, xR, c, c', er, t);
        case RTailFail =>
          TailClose(P, D, ell, live, xP, xR, c, c', er, j, e);
          CResGo(P, D, ell, live, xP, xR, c, c', er, TailFail(xP, c, e), TailFail(xR, c', e));
        case _ =>
          CResStuck(P, D, ell, live, xP, xR, c, c', er);
      }
    } else {
      assert TailO(xP, c, j).Stuck? by { reveal TailO(); }
      CResStuck(P, D, ell, live, xP, xR, c, c', er);
    }
  }

}

