// One step of an original instruction with no inserted code around it, in
// a single-function program: P' runs the relocated instruction from e(j)
// and ends related to P's step (one lemma per instruction class).
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

  // ---------------- the relation without the pc ----------------

  opaque ghost predicate RelC(P: seq<OInstr>, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>) {
    Inv1(c) && |c'.fr| == 1 && FrameOk(Top(c')) && Top(c').kind == Main
    && RegRel(c, c', er, lv) && StkRel(c, c', Fl(P, ell, 0)) && c'.L == c.L && c'.h == c.h
  }

  lemma RelCIs(P: seq<OInstr>, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires RelC(P, ell, c, c', er, lv)
    ensures Inv1(c) && |c'.fr| == 1 && FrameOk(Top(c')) && Top(c').kind == Main
    ensures RegRel(c, c', er, lv) && StkRel(c, c', Fl(P, ell, 0)) && c'.L == c.L && c'.h == c.h
    ensures Top(c) == c.fr[0] && Top(c') == c'.fr[0]
  { reveal RelC(); }

  lemma RelCShape(P: seq<OInstr>, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires RelC(P, ell, c, c', er, lv)
    ensures Inv1(c) && |c'.fr| == 1 && Top(c').kind == Main && c'.L == c.L && c'.h == c.h
    ensures Top(c) == c.fr[0] && Top(c') == c'.fr[0] && Wh(c) == Wh(c')
  { reveal RelC(); }

  lemma RelCIntro(P: seq<OInstr>, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>)
    requires Inv1(c) && |c'.fr| == 1 && FrameOk(Top(c')) && Top(c').kind == Main
    requires RegRel(c, c', er, lv) && StkRel(c, c', Fl(P, ell, 0)) && c'.L == c.L && c'.h == c.h
    ensures RelC(P, ell, c, c', er, lv)
  { reveal RelC(); }

  lemma RelCH(P: seq<OInstr>, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>, e: Ev)
    requires RelC(P, ell, c, c', er, lv)
    ensures RelC(P, ell, c.(h := c.h + [e]), c'.(h := c'.h + [e]), er, lv)
    ensures Top(c.(h := c.h + [e])) == Top(c) && Top(c'.(h := c'.h + [e])) == Top(c')
  { reveal RelC(); }

  lemma RelCLocal(P: seq<OInstr>, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>, p: bv64, bs: seq<bv8>)
    requires RelC(P, ell, c, c', er, lv)
    ensures RelC(P, ell, WriteLocal(c, p, bs), WriteLocal(c', p, bs), er, lv)
    ensures Top(WriteLocal(c, p, bs)) == Top(c) && Top(WriteLocal(c', p, bs)) == Top(c')
  {
    var a := WriteLocal(c, p, bs);
    var a' := WriteLocal(c', p, bs);
    assert a.fr == c.fr && a'.fr == c'.fr && a.h == c.h && a'.h == c'.h;
    assert Top(a) == Top(c) && Top(a') == Top(c');
    RelCIs(P, ell, c, c', er, lv);
    assert a'.L.mem == WriteMem(c.L.mem, p, bs) == a.L.mem;
    assert a'.L == a.L;
    assert Inv1(a) && RegRel(a, a', er, lv) && StkRel(a, a', Fl(P, ell, 0));
    RelCIntro(P, ell, a, a', er, lv);
  }

  lemma SuccJ(P: seq<OInstr>, j: nat)
    requires j < |P| && (P[j].Jcc? || P[j].MayGoto?)
    ensures Succ(P, j) == {P[j].t, j + 1}
  {}

  // The two runs share the environment, semantics and oracle.
  ghost predicate Pair(xP: Ctx, xR: Ctx) {
    xP.m.MP? && xR.m.MR? && xP.env == xR.env && xP.sem == xR.sem && xP.om == xR.om
  }

  // What a class step at j = Top(c).pc uses.
  opaque ghost predicate CHyp(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                       xP: Ctx, c: Cfg, c': Cfg, er: set<nat>) {
    var j := Top(c).pc;
    0 <= j < |P| && RelC(P, ell, c, c', er, live(j)) && Top(c').pc == E(D, j)
    && RegsOk(P[j]) && ReadsL(P[j], live, tbl) <= live(j)
    && (forall s | s in Succ(P, j) :: s < |P| && live(s) - WritesL(P[j]) <= live(j))
    && (!P[j].Exit? && !P[j].Ja? ==> j + 1 < |P| && E(D, j + 1) == E(D, j) + 1)
    && (forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn))
    && -(STK as int) <= ell(0) <= 0
  }

  ghost predicate CRes(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                       c: Cfg, c': Cfg, er: set<nat>)
    requires 0 <= Top(c).pc < |P|
  {
    var j := Top(c).pc;
    match OStep(xP, P[j], j, c)
    case Go(c1) => OStep(xR, Reloc(D, P[j]), j, c').Go? && Inv1(c1)
                   && CorrK(P, D, ell, live, c1, OStep(xR, Reloc(D, P[j]), j, c').c, er)
    case Done(t) => OStep(xR, Reloc(D, P[j]), j, c') == Done(t)
    case Stuck(_) => true
  }

  lemma CResGo(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                c: Cfg, c': Cfg, er: set<nat>, c1: Cfg, c1': Cfg)
    requires 0 <= Top(c).pc < |P|
    requires OStep(xP, P[Top(c).pc], Top(c).pc, c) == Go(c1)
    requires OStep(xR, Reloc(D, P[Top(c).pc]), Top(c).pc, c') == Go(c1')
    requires Inv1(c1) && CorrK(P, D, ell, live, c1, c1', er)
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
    requires Inv1(c) && Acc(P, xP, c) == MemAcc(c, p, w)
    requires forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    ensures forall a | a in MemAcc(c, p, w) :: a.1 as int - STK as int >= ell(0)
  {}

  lemma CHypFacts(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                  xP: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er)
    ensures var j := Top(c).pc;
      0 <= j < |P| && RelC(P, ell, c, c', er, live(j)) && Top(c').pc == E(D, j)
      && RegsOk(P[j]) && ReadsL(P[j], live, tbl) <= live(j)
      && (forall s | s in Succ(P, j) :: s < |P| && live(s) - WritesL(P[j]) <= live(j))
      && (!P[j].Exit? && !P[j].Ja? ==> j + 1 < |P| && E(D, j + 1) == E(D, j) + 1 && live(j + 1) - WritesL(P[j]) <= live(j))
    ensures |c.fr| == 1 && |c'.fr| == 1 && Top(c) == c.fr[0] && Top(c') == c'.fr[0]
    ensures |Top(c).regs| == NR && |Top(c').regs| == NR
    ensures -(STK as int) <= ell(0) <= 0 && Fl(P, ell, 0) <= ell(0)
    ensures forall r | r in ReadsL(P[Top(c).pc], live, tbl) && r < NR :: Rel(Reg(Top(c), r), Reg(Top(c'), r))
    ensures Rel(Reg(Top(c), 0), Reg(Top(c'), 0))
    ensures P[Top(c).pc].Legacy? ==> forall r | 0 <= r <= 10 :: Rel(Reg(Top(c), r), Reg(Top(c'), r))
  {
    reveal CHyp();
    RelCIs(P, ell, c, c', er, live(Top(c).pc));
    if !P[Top(c).pc].Exit? && !P[Top(c).pc].Ja? { assert Top(c).pc + 1 in Succ(P, Top(c).pc); }
    if P[Top(c).pc].Legacy? {
      assert ReadsL(P[Top(c).pc], live, tbl) == {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
      forall r | 0 <= r <= 10 ensures r in ReadsL(P[Top(c).pc], live, tbl) {
        assert r == 0 || r == 1 || r == 2 || r == 3 || r == 4 || r == 5 || r == 6 || r == 7 || r == 8 || r == 9 || r == 10;
      }
    }
    Floor8Bounds(ell(0));
    assert Fl(P, ell, 0) == Floor8(ell(0));
  }

  lemma CHypAcc(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                xP: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er)
    ensures forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
  { reveal CHyp(); }

  lemma CHypIntro(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                  xP: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires var j := Top(c).pc;
      0 <= j < |P| && RelC(P, ell, c, c', er, live(j)) && Top(c').pc == E(D, j)
      && RegsOk(P[j]) && ReadsL(P[j], live, tbl) <= live(j)
      && (forall s | s in Succ(P, j) :: s < |P| && live(s) - WritesL(P[j]) <= live(j))
      && (!P[j].Exit? && !P[j].Ja? ==> j + 1 < |P| && E(D, j + 1) == E(D, j) + 1)
      && (forall a | a in Acc(P, xP, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn))
      && -(STK as int) <= ell(0) <= 0
    ensures CHyp(P, D, ell, live, tbl, xP, c, c', er)
  { reveal CHyp(); }

  // ---------------- closing a step ----------------

  // Corr, kept folded in the class lemmas (it is unfolded once, in Step.dfy).
  opaque ghost predicate CorrK(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, c: Cfg, c': Cfg, er: set<nat>) {
    Corr(P, D, ell, live, c, c', er)
  }

  lemma {:isolate_assertions} Close(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                    c: Cfg, c': Cfg, er: set<nat>, c1: Cfg, c1': Cfg, ws: set<nat>)
    requires 0 <= Top(c).pc && RelC(P, ell, c, c', er, live(Top(c).pc))
    requires |c1.fr| == 1 && |c1'.fr| == 1 && Top(c1).fn == 0 && Top(c1).kind == Main && Top(c1').kind == Main
    requires |Top(c1).regs| == NR && FrameOk(Top(c1')) && 10 !in ws
    requires |Top(c).regs| == NR && |Top(c').regs| == NR
    requires forall r | 0 <= r < NR && r !in ws :: Top(c1).regs[r] == Top(c).regs[r] && Top(c1').regs[r] == Top(c').regs[r]
    requires forall r | 0 <= r < NR && r in ws :: Rel(Top(c1).regs[r], Top(c1').regs[r])
    requires 0 <= Top(c1).pc < |P| && Top(c1').pc == E(D, Top(c1).pc)
    requires live(Top(c1).pc) - ws <= live(Top(c).pc)
    requires StkRel(c1, c1', Fl(P, ell, 0)) && c1'.L == c1.L && c1'.h == c1.h
    ensures Inv1(c1) && CorrK(P, D, ell, live, c1, c1', er)
  {
    RelCIs(P, ell, c, c', er, live(Top(c).pc));
    assert Top(c1) == c1.fr[0];
    assert Top(c1).regs[10] == Top(c).regs[10];
    assert Inv1(c1);
    forall r | 0 <= r < NR
      ensures Rel(Reg(Top(c1), r), Reg(Top(c1'), r)) || (r in er && 1 <= r <= 5 && r !in live(Top(c1).pc))
    {
      if r !in ws {
        assert Reg(Top(c1), r) == Reg(Top(c), r) && Reg(Top(c1'), r) == Reg(Top(c'), r);
      }
    }
    assert RegRel(c1, c1', er, live(Top(c1).pc));
    CorrIntro1(P, D, ell, live, c1, c1', er);
    reveal CorrK();
  }

  lemma SameStk(P: seq<OInstr>, ell: nat -> int, c: Cfg, c': Cfg, c1: Cfg, c1': Cfg)
    requires StkRel(c, c', Fl(P, ell, 0)) && Top(c1).stack == Top(c).stack && Top(c1').stack == Top(c').stack
    ensures StkRel(c1, c1', Fl(P, ell, 0))
  {}

  // Both runs write the same register with the same value and go on to j + 1.
  lemma {:isolate_assertions} SetDstClose(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                          c: Cfg, c': Cfg, er: set<nat>, dst: nat, v: bv64)
    requires 0 <= Top(c).pc && RelC(P, ell, c, c', er, live(Top(c).pc)) && dst <= 9
    requires Top(c).pc + 1 < |P| && Top(c').pc + 1 == E(D, Top(c).pc + 1)
    requires live(Top(c).pc + 1) - {dst} <= live(Top(c).pc)
    ensures Inv1(SetDst(c, dst, v).c) && CorrK(P, D, ell, live, SetDst(c, dst, v).c, SetDst(c', dst, v).c, er)
  {
    RelCIs(P, ell, c, c', er, live(Top(c).pc));
    var c1 := SetDst(c, dst, v).c;
    var c1' := SetDst(c', dst, v).c;
    PutTop(c, Adv(SetR(Top(c), dst, W(v))));
    PutTop(c', Adv(SetR(Top(c'), dst, W(v))));
    RelCIs(P, ell, c, c', er, live(Top(c).pc));
    SameStk(P, ell, c, c', c1, c1');
    Close(P, D, ell, live, c, c', er, c1, c1', {dst});
  }

  // Both runs only advance (after the same change to L, h or the frame's bytes).
  lemma {:isolate_assertions} AdvClose(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                       c: Cfg, c': Cfg, er: set<nat>, cA: Cfg, cA': Cfg)
    requires 0 <= Top(c).pc && RelC(P, ell, c, c', er, live(Top(c).pc))
    requires RelC(P, ell, cA, cA', er, live(Top(c).pc)) && Top(cA).regs == Top(c).regs && Top(cA').regs == Top(c').regs
    requires Top(cA).pc == Top(c).pc && Top(cA').pc == Top(c').pc
    requires 0 <= Top(c).pc && Top(c).pc + 1 < |P| && Top(c').pc + 1 == E(D, Top(c).pc + 1)
    requires live(Top(c).pc + 1) <= live(Top(c).pc)
    ensures Inv1(Put(cA, Adv(Top(cA)))) && CorrK(P, D, ell, live, Put(cA, Adv(Top(cA))), Put(cA', Adv(Top(cA'))), er)
  {
    var c1 := Put(cA, Adv(Top(cA)));
    var c1' := Put(cA', Adv(Top(cA')));
    RelCIs(P, ell, cA, cA', er, live(Top(c).pc));
    PutTop(cA, Adv(Top(cA)));
    PutTop(cA', Adv(Top(cA')));
    RelCIs(P, ell, c, c', er, live(Top(c).pc));
    SameStk(P, ell, cA, cA', c1, c1');
    Close(P, D, ell, live, c, c', er, c1, c1', {});
  }

  // Both runs set the pc only.
  lemma {:isolate_assertions} JumpClose(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                                        c: Cfg, c': Cfg, er: set<nat>, cA: Cfg, cA': Cfg, t: int, t': int)
    requires 0 <= Top(c).pc && RelC(P, ell, c, c', er, live(Top(c).pc))
    requires |cA.fr| == 1 && |cA'.fr| == 1 && Top(cA) == Top(c) && Top(cA') == Top(c') && cA'.L == cA.L && cA'.h == cA.h
    requires 0 <= t < |P| && t' == E(D, t) && live(t) <= live(Top(c).pc)
    ensures Inv1(Put(cA, Top(cA).(pc := t))) && CorrK(P, D, ell, live, Put(cA, Top(cA).(pc := t)), Put(cA', Top(cA').(pc := t')), er)
  {
    RelCIs(P, ell, c, c', er, live(Top(c).pc));
    var c1 := Put(cA, Top(cA).(pc := t));
    var c1' := Put(cA', Top(cA').(pc := t'));
    PutTop(cA, Top(cA).(pc := t));
    PutTop(cA', Top(cA').(pc := t'));
    RelCIs(P, ell, c, c', er, live(Top(c).pc));
    SameStk(P, ell, c, c', c1, c1');
    Close(P, D, ell, live, c, c', er, c1, c1', {});
  }

  // ---------------- register classes ----------------

  lemma {:isolate_assertions} ClassAlu(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                       xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Alu?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
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
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
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
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
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
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
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
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
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
    RelCH(P, ell, c, c', er, live(j), e);
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
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Exit?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
    var j := Top(c).pc;
    assert Reloc(D, P[j]) == Exit;
    reveal ExitO(), ExitFrame();
  }

  // ---------------- memory ----------------

  // The stack bytes P reads at or above its floor are the same in P'.
  lemma {:isolate_assertions} StackBytesEq(P: seq<OInstr>, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>,
                                           p: bv64, w: nat)
    requires RelC(P, ell, c, c', er, lv) && Classify(p, w, |c.fr|, c.L.mem.Keys).InStack?
    requires forall a | a in MemAcc(c, p, w) :: a.1 as int - STK as int >= ell(0)
    requires Fl(P, ell, 0) <= ell(0)
    requires AllDef(StackBytes(c, Classify(p, w, |c.fr|, c.L.mem.Keys).d, Classify(p, w, |c.fr|, c.L.mem.Keys).o, w))
    ensures var cl := Classify(p, w, |c.fr|, c.L.mem.Keys);
      cl.d == 0 && cl.o + w <= STK && Classify(p, w, |c'.fr|, c'.L.mem.Keys) == cl
      && StackBytes(c', cl.d, cl.o, w) == StackBytes(c, cl.d, cl.o, w)
  {
    RelCIs(P, ell, c, c', er, lv);
    var cl := Classify(p, w, |c.fr|, c.L.mem.Keys);
    ClassifyStack(p, w, |c.fr|, c.L.mem.Keys);
    var o := cl.o;
    assert MemAcc(c, p, w) == set k | o <= k < o + w :: (0, k);
    forall k | 0 <= k < w ensures c'.fr[0].stack[o + k] == c.fr[0].stack[o + k] {
      assert (0, o + k) in MemAcc(c, p, w);
      assert StackBytes(c, 0, o, w)[k] == c.fr[0].stack[o + k];
      assert RelB(c.fr[0].stack[o + k], c'.fr[0].stack[o + k]);
    }
    assert o + w <= |c.fr[0].stack| && o + w <= |c'.fr[0].stack|;
    assert StackBytes(c, 0, o, w) == c.fr[0].stack[o .. o + w];
    assert StackBytes(c', 0, o, w) == c'.fr[0].stack[o .. o + w];
    assert forall k | 0 <= k < w :: c'.fr[0].stack[o .. o + w][k] == c.fr[0].stack[o .. o + w][k];
    assert c'.fr[0].stack[o .. o + w] == c.fr[0].stack[o .. o + w];
  }

  // Both runs write the same bytes to the frame.
  lemma {:isolate_assertions} WriteRel(P: seq<OInstr>, ell: nat -> int, c: Cfg, c': Cfg, er: set<nat>, lv: set<nat>,
                                       o: nat, bs: seq<Byte>)
    requires RelC(P, ell, c, c', er, lv) && o + |bs| <= STK && forall i | 0 <= i < |bs| :: bs[i].B?
    ensures RelC(P, ell, WriteStack(c, 0, o, bs), WriteStack(c', 0, o, bs), er, lv)
    ensures Top(WriteStack(c, 0, o, bs)).pc == Top(c).pc && Top(WriteStack(c', 0, o, bs)).pc == Top(c').pc
  {
    RelCIs(P, ell, c, c', er, lv);
    var cA := WriteStack(c, 0, o, bs);
    var cA' := WriteStack(c', 0, o, bs);
    assert Top(cA) == cA.fr[0] && Top(cA') == cA'.fr[0];
    var st := c.fr[0].stack;
    var st' := c'.fr[0].stack;
    assert cA.fr[0].stack == st[..o] + bs + st[o + |bs|..];
    assert cA'.fr[0].stack == st'[..o] + bs + st'[o + |bs|..];
    forall i | 0 <= i < STK ensures RelB(cA.fr[0].stack[i], cA'.fr[0].stack[i]) || i - STK as int < Fl(P, ell, 0)
    {
      if o <= i < o + |bs| {
        assert cA.fr[0].stack[i] == bs[i - o] == cA'.fr[0].stack[i];
      } else {
        assert cA.fr[0].stack[i] == st[i] && cA'.fr[0].stack[i] == st'[i];
      }
    }
    forall i | 0 <= i < STK ensures cA'.fr[0].stack[i].B? {
      if o <= i < o + |bs| { assert cA'.fr[0].stack[i] == bs[i - o]; } else { assert cA'.fr[0].stack[i] == st'[i]; }
    }
    assert RegRel(cA, cA', er, lv);
    assert StkRel(cA, cA', Fl(P, ell, 0));
    RelCIntro(P, ell, cA, cA', er, lv);
  }

  lemma BytesB(bs: seq<bv8>) ensures |Bytes(bs)| == |bs| && forall i | 0 <= i < |Bytes(bs)| :: Bytes(bs)[i].B? {}

  function Ext(sx: bool, w: nat, v: bv64): bv64 { if sx then SextW(v, w) else v }

  // The same step after appending the same event, or writing the same local bytes.
  lemma HSetDst(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
                c: Cfg, c': Cfg, er: set<nat>, j: nat, e: Ev, dst: nat, v: bv64)
    requires RelC(P, ell, c, c', er, live(j)) && Top(c).pc == j && dst <= 9
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && live(j + 1) - {dst} <= live(j)
    ensures Inv1(SetDst(c.(h := c.h + [e]), dst, v).c)
    ensures CorrK(P, D, ell, live, SetDst(c.(h := c.h + [e]), dst, v).c, SetDst(c'.(h := c'.h + [e]), dst, v).c, er)
  {
    RelCH(P, ell, c, c', er, live(j), e);
    SetDstClose(P, D, ell, live, c.(h := c.h + [e]), c'.(h := c'.h + [e]), er, dst, v);
  }

  lemma HAdv(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
             c: Cfg, c': Cfg, er: set<nat>, j: nat, e: Ev)
    requires RelC(P, ell, c, c', er, live(j)) && Top(c).pc == j
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && live(j + 1) <= live(j)
    ensures var cA := c.(h := c.h + [e]); var cA' := c'.(h := c'.h + [e]);
      Inv1(Put(cA, Adv(Top(cA)))) && CorrK(P, D, ell, live, Put(cA, Adv(Top(cA))), Put(cA', Adv(Top(cA'))), er)
  {
    var cA := c.(h := c.h + [e]);
    var cA' := c'.(h := c'.h + [e]);
    RelCH(P, ell, c, c', er, live(j), e);
    AdvClose(P, D, ell, live, cA, cA', er, cA, cA');
  }

  lemma LAdv(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
             c: Cfg, c': Cfg, er: set<nat>, j: nat, p: bv64, bs: seq<bv8>)
    requires RelC(P, ell, c, c', er, live(j)) && Top(c).pc == j
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && live(j + 1) <= live(j)
    ensures var cA := WriteLocal(c, p, bs); var cA' := WriteLocal(c', p, bs);
      Inv1(Put(cA, Adv(Top(cA)))) && CorrK(P, D, ell, live, Put(cA, Adv(Top(cA))), Put(cA', Adv(Top(cA'))), er)
  {
    var cA := WriteLocal(c, p, bs);
    var cA' := WriteLocal(c', p, bs);
    RelCLocal(P, ell, c, c', er, live(j), p, bs);
    AdvClose(P, D, ell, live, cA, cA', er, cA, cA');
  }

  lemma SAdv(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>,
             c: Cfg, c': Cfg, er: set<nat>, j: nat, o: nat, bs: seq<Byte>)
    requires RelC(P, ell, c, c', er, live(j)) && Top(c).pc == j && o + |bs| <= STK && forall i | 0 <= i < |bs| :: bs[i].B?
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && live(j + 1) <= live(j)
    ensures var cA := WriteStack(c, 0, o, bs); var cA' := WriteStack(c', 0, o, bs);
      Inv1(Put(cA, Adv(Top(cA)))) && CorrK(P, D, ell, live, Put(cA, Adv(Top(cA))), Put(cA', Adv(Top(cA'))), er)
  {
    var cA := WriteStack(c, 0, o, bs);
    var cA' := WriteStack(c', 0, o, bs);
    WriteRel(P, ell, c, c', er, live(j), o, bs);
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
    requires RelC(P, ell, c, c', er, live(j)) && Top(c).pc == j && Pair(xP, xR)
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && live(j + 1) - {0, 1, 2, 3, 4, 5} <= live(j)
    ensures Inv1(TailFail(xP, c, e)) && CorrK(P, D, ell, live, TailFail(xP, c, e), TailFail(xR, c', e), er)
  {
    RelCIs(P, ell, c, c', er, live(j));
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
    requires RelC(P, ell, c, c', er, live(j)) && Top(c).pc == j && Pair(xP, xR) && ValidW(w) && dst <= 9
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && live(j + 1) - {dst} <= live(j)
    requires forall a | a in MemAcc(c, p, w) :: a.1 as int - STK as int >= ell(0)
    requires Fl(P, ell, 0) <= ell(0)
    ensures match LdStep(xP, c, j, dst, p, w, sx)
      case Go(c1) => LdStep(xR, c', j, dst, p, w, sx).Go? && Inv1(c1)
                     && CorrK(P, D, ell, live, c1, LdStep(xR, c', j, dst, p, w, sx).c, er)
      case Done(_) => false
      case Stuck(_) => true
  {
    RelCShape(P, ell, c, c', er, live(j));
    var cl := Classify(p, w, |c.fr|, c.L.mem.Keys);
    assert Classify(p, w, |c'.fr|, c'.L.mem.Keys) == cl;
    match cl
    case InStack(d, o) =>
      if AllDef(StackBytes(c, d, o, w)) {
        StackBytesEq(P, ell, c, c', er, live(j), p, w);
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
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
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
    requires RelC(P, ell, c, c', er, live(j)) && Top(c).pc == j && Pair(xP, xR) && ValidW(w)
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && live(j + 1) <= live(j)
    ensures match StStep(xP, c, j, p, w, v)
      case Go(c1) => StStep(xR, c', j, p, w, v).Go? && Inv1(c1) && CorrK(P, D, ell, live, c1, StStep(xR, c', j, p, w, v).c, er)
      case Done(_) => false
      case Stuck(_) => true
  {
    RelCShape(P, ell, c, c', er, live(j));
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
      SAdv(P, D, ell, live, c, c', er, j, o, bs);
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
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
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
    requires RelC(P, ell, cA, cA', er, live(j)) && Top(cA).pc == j && rs <= 9
    requires j + 1 < |P| && Top(cA').pc + 1 == E(D, j + 1) && live(j + 1) <= live(j)
    ensures AtomRegs(cA, rs, fetch, cmpx, vold).Go? && AtomRegs(cA', rs, fetch, cmpx, vold).Go?
    ensures Inv1(AtomRegs(cA, rs, fetch, cmpx, vold).c)
    ensures CorrK(P, D, ell, live, AtomRegs(cA, rs, fetch, cmpx, vold).c, AtomRegs(cA', rs, fetch, cmpx, vold).c, er)
  {
    if cmpx { SetDstClose(P, D, ell, live, cA, cA', er, 0, vold); }
    else if fetch { SetDstClose(P, D, ell, live, cA, cA', er, rs, vold); }
    else { AdvClose(P, D, ell, live, cA, cA', er, cA, cA'); }
  }

  lemma {:isolate_assertions} AtomStepRel(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, xP: Ctx, xR: Ctx,
                                          c: Cfg, c': Cfg, er: set<nat>, j: nat, op: nat, p: bv64, w: nat, rs: nat,
                                          fetch: bool, cmpx: bool, n: bv64, xv: Option<bv64>)
    requires RelC(P, ell, c, c', er, live(j)) && Top(c).pc == j && Pair(xP, xR) && (w == 4 || w == 8) && rs <= 9
    requires j + 1 < |P| && Top(c').pc + 1 == E(D, j + 1) && live(j + 1) <= live(j)
    requires forall a | a in MemAcc(c, p, w) :: a.1 as int - STK as int >= ell(0)
    requires Fl(P, ell, 0) <= ell(0)
    ensures match AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv)
      case Go(c1) => AtomStep(xR, c', j, op, p, w, rs, fetch, cmpx, n, xv).Go? && Inv1(c1)
                     && CorrK(P, D, ell, live, c1, AtomStep(xR, c', j, op, p, w, rs, fetch, cmpx, n, xv).c, er)
      case Done(_) => false
      case Stuck(_) => true
  {
    RelCShape(P, ell, c, c', er, live(j));
    var cl := Classify(p, w, |c.fr|, c.L.mem.Keys);
    assert Classify(p, w, |c'.fr|, c'.L.mem.Keys) == cl;
    match cl
    case InStack(d, o) =>
      if AllDef(StackBytes(c, d, o, w)) {
        StackBytesEq(P, ell, c, c', er, live(j), p, w);
        var vold := LE(Plain(StackBytes(c, d, o, w)));
        var bs := Bytes(BytesOf(xP.sem.rmw(op, w, vold, n, xv), w));
        BytesB(BytesOf(xP.sem.rmw(op, w, vold, n, xv), w));
        var cA := WriteStack(c, d, o, bs);
        var cA' := WriteStack(c', d, o, bs);
        assert AtomStep(xP, c, j, op, p, w, rs, fetch, cmpx, n, xv) == AtomRegs(cA, rs, fetch, cmpx, vold) by { reveal AtomStep(); }
        assert AtomStep(xR, c', j, op, p, w, rs, fetch, cmpx, n, xv) == AtomRegs(cA', rs, fetch, cmpx, vold) by { reveal AtomStep(); }
        WriteRel(P, ell, c, c', er, live(j), o, bs);
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
      RelCLocal(P, ell, c, c', er, live(j), p, BytesOf(xP.sem.rmw(op, w, vold, n, xv), w));
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
        RelCH(P, ell, c, c', er, live(j), e);
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
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
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
    requires RelC(P, ell, cA, cA', er, live(j)) && Top(cA).pc == j && Pair(xP, xR)
    requires j + 1 < |P| && Top(cA').pc + 1 == E(D, j + 1) && live(j + 1) - {0, 1, 2, 3, 4, 5} <= live(j)
    ensures Finish(xP, cA, v, wr).Go? && Finish(xR, cA', v, wr).Go?
    ensures Inv1(Finish(xP, cA, v, wr).c) && CorrK(P, D, ell, live, Finish(xP, cA, v, wr).c, Finish(xR, cA', v, wr).c, er)
  {
    RelCIs(P, ell, cA, cA', er, live(j));
    FinishFacts(xP, cA, v, wr);
    FinishFacts(xR, cA', v, wr);
    ApplyWAt(cA, wr);
    ApplyWAt(cA', wr);
    var c1 := Finish(xP, cA, v, wr).c;
    var c1' := Finish(xR, cA', v, wr).c;
    assert Top(c1) == c1.fr[0] && Top(c1') == c1'.fr[0];
    forall o | 0 <= o < STK ensures (RelB(Top(c1).stack[o], Top(c1').stack[o]) || o - STK as int < Fl(P, ell, 0)) && Top(c1').stack[o].B? {
      assert Top(c1).stack[o] == ApplyF(Top(cA), 0, wr).stack[o];
      assert Top(c1').stack[o] == ApplyF(Top(cA'), 0, wr).stack[o];
    }
    assert StkRel(c1, c1', Fl(P, ell, 0));
    forall k | 0 <= k < NR ensures Top(c1').regs[k].W? {
      if 6 <= k { assert Top(c1').regs[k] == Top(cA').regs[k]; }
    }
    forall r | 0 <= r < NR && r in {0, 1, 2, 3, 4, 5} ensures Rel(Top(c1).regs[r], Top(c1').regs[r]) {
      if r == 0 { assert Top(c1).regs[0] == (if v.W? then v else Bot); }
      else { assert Top(c1).regs[r] == Und(xP, cA, r) == Bot; }
    }
    assert c1'.L == c1.L && c1'.h == c1.h;
    assert |c1.fr| == 1 && |c1'.fr| == 1 && Top(c1).fn == 0 && Top(c1).kind == Main && Top(c1').kind == Main;
    assert |Top(c1).regs| == NR && FrameOk(Top(c1'));
    assert forall r | 0 <= r < NR && r !in {0, 1, 2, 3, 4, 5} :: Top(c1).regs[r] == Top(cA).regs[r] && Top(c1').regs[r] == Top(cA').regs[r];
    assert 0 <= Top(c1).pc < |P| && Top(c1').pc == E(D, Top(c1).pc);
    assert live(Top(c1).pc) - {0, 1, 2, 3, 4, 5} <= live(Top(cA).pc);
    Close(P, D, ell, live, cA, cA', er, c1, c1', {0, 1, 2, 3, 4, 5});
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

  lemma {:isolate_assertions} FootFloor(P: seq<OInstr>, x: Ctx, c: Cfg, ell: nat -> int, kf: bool, id: bv32,
                                        n: nat, args: seq<bv64>)
    requires Inv1(c) && 0 <= Top(c).pc < |P| && P[Top(c).pc] == Hcall(kf, id)
    requires forall a | a in Acc(P, x, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
    requires n == x.env.arity(kf, id) && Rds(Top(c), Upto(1, n)) == Some(args)
    ensures forall i | 0 <= i < |x.env.foot(kf, id, args)| :: FootIn(c, x.env.foot(kf, id, args)[i], ell(0))
  {
    var addrs := x.env.foot(kf, id, args);
    assert Acc(P, x, c) == HelperAcc(x, c, Top(c).pc, kf, id);
    assert FootAcc(c, addrs) <= Acc(P, x, c);
    forall i | 0 <= i < |addrs| ensures FootIn(c, addrs[i], ell(0)) {
      if Classify(addrs[i], 1, |c.fr|, c.L.mem.Keys).InStack? { FootAccHas(c, addrs, i); }
    }
  }

  lemma HelperNotDone(x: Ctx, c: Cfg, idx: nat, kf: bool, id: bv32)
    ensures !HelperStep(x, c, idx, kf, id, false).Done?
  { reveal HelperStep(), Finish(); }

  lemma {:isolate_assertions} ClassHcall(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                         xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Hcall? && A3b(xP.env, tbl)
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCIs(P, ell, c, c', er, live(Top(c).pc));
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
      assert StkRel(c, c', ell(0));
      FootRel(c, c', addrs, ell(0));
      var e := ECall(j, kf, id, args, beta);
      assert Wh(c) == Wh(c');
      var cA := c.(h := c.h + [e]);
      var cA' := c'.(h := c'.h + [e]);
      assert HelperStep(xR, c', j, kf, id, false) == Finish(xR, cA', v, wr) by { reveal HelperStep(); }
      RelCH(P, ell, c, c', er, live(j), e);
      FinishClose(P, D, ell, live, xP, xR, cA, cA', er, j, v, wr);
    }
  }

  lemma {:isolate_assertions} ClassLegacy(P: seq<OInstr>, D: Decomp, ell: nat -> int, live: nat -> set<nat>, tbl: bv32 -> set<nat>,
                                          xP: Ctx, xR: Ctx, c: Cfg, c': Cfg, er: set<nat>)
    requires CHyp(P, D, ell, live, tbl, xP, c, c', er) && Pair(xP, xR) && 0 <= Top(c).pc < |P| && P[Top(c).pc].Legacy?
    ensures CRes(P, D, ell, live, xP, xR, c, c', er)
  {
    CHypFacts(P, D, ell, live, tbl, xP, c, c', er);
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
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
        reveal ExitFrame();
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
    RelCShape(P, ell, c, c', er, live(Top(c).pc));
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

