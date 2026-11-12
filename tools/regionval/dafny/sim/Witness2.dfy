// Non-vacuity for calls and callbacks: an instance with a BPF-to-BPF call
// with a P9 pass load and pass prologue, and a bpf_loop callback with the
// P1b prologue: every hypothesis of the theorem holds for it.
include "Witness.dfy"
include "Calls.dfy"

module SimWitness2 {
  import opened Bits
  import opened Semantics
  import opened Terms
  import opened Obligations
  import opened Checker
  import Api
  import M = SimModel
  import R = SimRewrite
  import Pr = SimPremises
  import T = SimTheorem
  import F = SimFacts
  import LF = SimLayoutFacts
  import B = SimBridge
  import Cl = SimClasses
  import Ca = SimCalls
  import W1 = SimWitness

  // PL(0): r2 = 0   (mov64 imm: 0xb7, dst r2)
  const PLL: seq<seq<bv8>> := PLLLit()
  opaque function PLLLit(): seq<seq<bv8>> { [[0xb7, 0x02, 0, 0, 0, 0, 0, 0]] }
  const PLP: seq<Instr> := [Alu(true, Mov, 2, Imm(0))]

  // FP(4), P9: st [r10-8], r2
  const F9L: seq<seq<bv8>> := F9LLit()
  opaque function F9LLit(): seq<seq<bv8>> { [[0x7b, 0x2a, 0xf8, 0xff, 0, 0, 0, 0]] }
  const F9P: seq<Instr> := [Stx(8, 10, 2, 0xfff8)]

  // FP(6), P1b: ld r0, [r2+0]; st [r10-8], r0
  const FBL: seq<seq<bv8>> := FBLLit()
  opaque function FBLLit(): seq<seq<bv8>> { [[0x79, 0x20, 0, 0, 0, 0, 0, 0], [0x7b, 0x0a, 0xf8, 0xff, 0, 0, 0, 0]] }
  const FBP: seq<Instr> := [Ldx(8, 0, 2, 0), Stx(8, 10, 0, 0xfff8)]

  lemma Shapes2()
    ensures |PLL| == 1 && |F9L| == 1 && |FBL| == 2 && W1.All8(PLL) && W1.All8(F9L) && W1.All8(FBL)
  { reveal PLLLit(), F9LLit(), FBLLit(); }

  lemma PLValid() ensures Validate(W1.Cat(PLL), Api.PassLoadSpec(0, 2)) == Validated
  {
    reveal PLLLit();
    assert Decode(PLL[0]) == Some(PLP[0]);
    W1.DecodeCat(PLL, PLP, 0);
    var sp := Api.PassLoadSpec(0, 2);
    var s0 := SInit();
    assert SymStep(sp, PLP[0], s0).SOk?;
    var s1 := SymStep(sp, PLP[0], s0).ss;
    reveal SymExec();
    assert SymExec(PLP, sp, 1, s1, Top) == Validated;
    assert SymExec(PLP, sp, 0, s0, Top) == Validated;
  }

  lemma F9Valid() ensures Validate(W1.Cat(F9L), Api.PassPrologueSpec(0)) == Validated
  {
    reveal F9LLit();
    assert Decode(F9L[0]) == Some(F9P[0]);
    W1.DecodeCat(F9L, F9P, 0);
    var sp := Api.PassPrologueSpec(0);
    var s0 := SInit();
    reveal Signed64();
    assert FpOff(AddrTerm(s0, 10, 0xfff8)) == Some(0xffff_ffff_ffff_fff8);
    assert SymStep(sp, F9P[0], s0).SOk?;
    var s1 := SymStep(sp, F9P[0], s0).ss;
    reveal SymExec();
    assert SymExec(F9P, sp, 1, s1, Top) == Validated;
    assert SymExec(F9P, sp, 0, s0, Top) == Validated;
  }

  lemma FBValid() ensures Validate(W1.Cat(FBL), Api.CallbackPrologueSpec(0)) == Validated
  {
    reveal FBLLit();
    assert Decode(FBL[0]) == Some(FBP[0]);
    assert Decode(FBL[1]) == Some(FBP[1]);
    W1.DecodeCat(FBL, FBP, 0);
    var sp := Api.CallbackPrologueSpec(0);
    var s0 := SInit();
    reveal Signed64();
    assert SymStep(sp, FBP[0], s0).SOk?;
    var s1 := SymStep(sp, FBP[0], s0).ss;
    assert FpOff(AddrTerm(s1, 10, 0xfff8)) == Some(0xffff_ffff_ffff_fff8);
    assert SymStep(sp, FBP[1], s1).SOk?;
    var s2 := SymStep(sp, FBP[1], s1).ss;
    reveal SymExec();
    assert SymExec(FBP, sp, 2, s2, Top) == Validated;
    assert SymExec(FBP, sp, 1, s1, Top) == Validated;
    assert SymExec(FBP, sp, 0, s0, Top) == Validated;
  }

  // ================= the instance =================

  //   0: call 4        PL(0) = r2 = 0          (P9, r_G = r2)
  //   1: r3 = &fn6
  //   2: bpf_loop      the oracle invokes fn 6 once, then returns 0
  //   3: exit
  //   4: r0 = <alu 0>  FP(4) = st [r10-8], r2  (P9 prologue)
  //   5: exit
  //   6: r0 = <alu 0>  FP(6) = ld r0, [r2]; st [r10-8], r0  (P1b)
  //   7: exit
  const PW2: seq<M.OInstr> := [M.Call(4), M.FRef(3, 6), M.CbCall(181), M.Exit, M.Alu(0, 0, []), M.Exit, M.Alu(0, 0, []), M.Exit]
  opaque function DW2(): R.Decomp {
    R.Decomp([], map[4 := R.FProl(R.FP9, W1.Cat(F9L)), 6 := R.FProl(R.FP1b, W1.Cat(FBL))],
             map[0 := R.PassLoad(2, W1.Cat(PLL))], map[], map[], map[], [])
  }
  function EllW2(g: nat): int { 0 }
  function LiveW2(j: nat): set<nat> { if j == 3 || j == 5 || j == 7 then {0} else {} }
  function TblW2(id: bv32): set<nat> { if id == 12 then {1, 2, 3} else {} }
  function EnvW2(): M.Env { M.Env((kf: bool, id: bv32) => 0, (kf: bool, id: bv32, a: seq<bv64>) => []) }
  // The callback address of fn 6, (code(6), 0) = FuncAddr(6), as a literal.
  const CB6: bv64 := 0xC000_0000_0000_0006
  const RInv: M.Resp := M.RInvoke(CB6, [])
  function OmW2(h: seq<M.Ev>, e: M.Ev, w: M.Where): M.Resp { if e.ECall? then RInv else W1.R0 }
  ghost predicate AdmW2(l: M.Local, om: M.Oracle) { l == W1.L0 && forall h, e, w :: om(h, e, w) == OmW2(h, e, w) }

  lemma FnSetW2() ensures M.FnSet(PW2) == {0, 4, 6}
  {
    var A := set j | 0 <= j < |PW2| && PW2[j].Call? :: PW2[j].t;
    var B := set j | 0 <= j < |PW2| && PW2[j].FRef? :: PW2[j].g;
    assert PW2[0].Call? && PW2[0].t == 4 && PW2[1].FRef? && PW2[1].g == 6;
    assert 4 in A && 6 in B;
    forall a | a in A ensures a == 4 { var j :| 0 <= j < |PW2| && PW2[j].Call? && PW2[j].t == a; }
    forall b | b in B ensures b == 6 { var j :| 0 <= j < |PW2| && PW2[j].FRef? && PW2[j].g == b; }
    assert A == {4} && B == {6};
  }

  // ---------------- P' = Layout(P, D) ----------------

  lemma {:isolate_assertions} PosW2()
    ensures R.NI(W1.Cat(PLL)) == 1 && R.NI(W1.Cat(F9L)) == 1 && R.NI(W1.Cat(FBL)) == 2
    ensures R.E(DW2(), 0) == 0 && R.K(DW2(), 0) == 1 && R.E(DW2(), 1) == 2 && R.E(DW2(), 2) == 3 && R.E(DW2(), 3) == 4
    ensures R.FE(DW2(), 4) == 5 && R.E(DW2(), 4) == 6 && R.E(DW2(), 5) == 7
    ensures R.FE(DW2(), 6) == 8 && R.E(DW2(), 6) == 10 && R.E(DW2(), 7) == 11 && R.Start(DW2(), 8) == 12
    ensures forall i | 0 <= i < 8 && i != 0 :: R.K(DW2(), i) == R.E(DW2(), i)
  {
    reveal DW2();
    Shapes2();
    W1.CatLen(PLL); W1.CatLen(F9L); W1.CatLen(FBL);
    var D := DW2();
    assert R.FnsLen(D, []) == 0;
    assert forall i :: R.FnsAt(D, i) == [];
    assert R.BlockLen(D, 0) == 2 && R.BlockLen(D, 1) == 1 && R.BlockLen(D, 2) == 1 && R.BlockLen(D, 3) == 1;
    assert R.BlockLen(D, 4) == 2 && R.BlockLen(D, 5) == 1 && R.BlockLen(D, 6) == 3 && R.BlockLen(D, 7) == 1;
    assert R.Start(D, 1) == 2 && R.Start(D, 2) == 3 && R.Start(D, 3) == 4 && R.Start(D, 4) == 5;
    assert R.Start(D, 5) == 7 && R.Start(D, 6) == 8 && R.Start(D, 7) == 11 && R.Start(D, 8) == 12;
  }

  lemma AllFnsEmpty(D: R.Decomp, n: nat, i: nat)
    requires D.fns == map[] && D.tail == []
    ensures R.AllFnsFrom(D, n, i) == []
    decreases n - i
  {
    if i < n { AllFnsEmpty(D, n, i + 1); assert R.FnsAt(D, i) == []; }
  }

  lemma AllFnsW2() ensures R.AllFns(PW2, DW2()) == [] && R.Hooks(PW2, DW2()) == {}
  {
    reveal DW2();
    AllFnsEmpty(DW2(), 8, 0);
  }

  lemma WFW2() ensures LF.AllFnsWF(PW2, DW2()) { reveal DW2(); }

  lemma {:isolate_assertions} CodeTable2()
    ensures |R.Layout(PW2, DW2()).code| == 12 && |PLL| == 1 && |F9L| == 1 && |FBL| == 2
    ensures var code := R.Layout(PW2, DW2()).code;
      code[0] == M.N(PLL[0]) && code[5] == M.N(F9L[0]) && code[8] == M.N(FBL[0]) && code[9] == M.N(FBL[1])
      && (forall p | 0 <= p < 12 && p !in {0, 5, 8, 9} :: code[p].O?)
  {
    var D := DW2();
    WFW2(); PosW2(); Shapes2(); AllFnsW2();
    LF.CodeLen(PW2, D);
    assert R.FnsLen(D, D.tail) == 0 by { reveal DW2(); }
    assert 0 in D.pl && 4 in D.fp && 6 in D.fp && D.site == map[] && D.wrap == map[] by { reveal DW2(); }
    assert D.pl[0].code == W1.Cat(PLL) && D.fp[4].code == W1.Cat(F9L) && D.fp[6].code == W1.Cat(FBL) by { reveal DW2(); }
    Ca.PLCode(PW2, D, 0);
    W1.CatAt(PLL, 0);
    assert R.Slice(W1.Cat(PLL), 0) == PLL[0];
    assert R.Layout(PW2, D).code[R.E(D, 0) + 0] == M.N(R.Slice(D.pl[0].code, 0));
    Ca.FPCode(PW2, D, 4);
    W1.CatAt(F9L, 0);
    assert R.Slice(W1.Cat(F9L), 0) == F9L[0];
    assert R.Layout(PW2, D).code[R.FE(D, 4) + 0] == M.N(R.Slice(D.fp[4].code, 0));
    Ca.FPCode(PW2, D, 6);
    W1.CatAt(FBL, 0); W1.CatAt(FBL, 1);
    assert R.Slice(W1.Cat(FBL), 0) == FBL[0] && R.Slice(W1.Cat(FBL), 1) == FBL[1];
    assert R.Layout(PW2, D).code[R.FE(D, 6) + 0] == M.N(R.Slice(D.fp[6].code, 0));
    assert R.Layout(PW2, D).code[R.FE(D, 6) + 1] == M.N(R.Slice(D.fp[6].code, 1));
    forall i | 1 <= i < 8 ensures R.K(D, i) < |R.Layout(PW2, D).code| && R.Layout(PW2, D).code[R.K(D, i)].O? {
      assert i !in D.pl by { reveal DW2(); }
      LF.PlainCode(PW2, D, i);
    }
    var code := R.Layout(PW2, D).code;
    assert code[1].O? && code[2].O? && code[3].O? && code[4].O?;
    assert code[6].O? && code[7].O? && code[10].O? && code[11].O?;
  }

  lemma {:isolate_assertions} DecodesW2()
    ensures |PLL| == 1 && |F9L| == 1 && |FBL| == 2 && W1.All8(PLL) && W1.All8(F9L) && W1.All8(FBL)
    ensures Decode(PLL[0]) == Some(PLP[0]) && Decode(F9L[0]) == Some(F9P[0])
    ensures Decode(FBL[0]) == Some(FBP[0]) && Decode(FBL[1]) == Some(FBP[1])
  { reveal PLLLit(), F9LLit(), FBLLit(); }

  lemma {:isolate_assertions} CallsW2() ensures Pr.CallsOk(DW2(), R.Layout(PW2, DW2()))
  {
    CodeTable2(); DecodesW2();
  }

  lemma {:isolate_assertions} PiecesW2() ensures Pr.PiecesOk(PW2, DW2())
  {
    reveal DW2();
    Shapes2(); DecodesW2(); AllFnsW2(); FnSetW2();
    W1.NoHelperCat(PLL); W1.NoHelperCat(F9L); W1.NoHelperCat(FBL);
    assert W1.Cat([]) == [] by { reveal W1.Cat(); }
  }

  lemma {:isolate_assertions} StructW2() ensures Pr.Structure(PW2, DW2(), R.Layout(PW2, DW2()), EllW2, LiveW2, TblW2)
  {
    reveal DW2();
    PiecesW2(); CallsW2(); FnSetW2();
    assert Pr.LiveOk(PW2, LiveW2, TblW2);
    assert Pr.FloorsOk(PW2, EllW2);
    assert Pr.S10(PW2, DW2(), LiveW2, TblW2);
  }

  lemma {:isolate_assertions} ShapeW2() ensures Pr.E0Shape(PW2) && Pr.S0(PW2)
  {
    FnSetW2();
    assert forall j | 0 <= j < |PW2| :: Pr.RegsOk(PW2[j]);
  }

  lemma FlW2(i: nat) ensures R.Fl(PW2, EllW2, i) == 0 {}

  lemma {:isolate_assertions} ValidW2() ensures R.AllValidated(PW2, DW2(), EllW2)
  {
    reveal DW2();
    AllFnsW2();
    PLValid(); F9Valid(); FBValid();
    FlW2(0); FlW2(4); FlW2(6);
    reveal R.Valid();
    var D := DW2();
    assert D.fp.Keys == {4, 6} && D.pl.Keys == {0} && D.site == map[] && D.wrap == map[] && |D.pro0| == 0;
  }

  // ---------------- the run of P ----------------

  ghost predicate AdmOm(om: M.Oracle) { forall h, e, w :: om(h, e, w) == OmW2(h, e, w) }
  ghost function X(om: M.Oracle): M.Ctx { M.CtxP(PW2, EnvW2(), W1.SemW(), om) }
  const E1: M.Ev := M.ECall(2, false, 181, [], [])
  const E2: M.Ev := M.ECbRet(2, 0)
  ghost function C0(): M.Cfg { M.InitP(W1.L0) }
  ghost function GoC(r: M.StepRes): M.Cfg { if r.Go? then r.c else M.InitP(W1.L0) }
  ghost function C1(om: M.Oracle): M.Cfg { GoC(M.Push(X(om), C0(), 4, 4, M.Sub, Cl.CArgs(C0()))) }
  ghost function C2(om: M.Oracle): M.Cfg { M.SetDst(C1(om), 0, 0).c }
  ghost function C3(om: M.Oracle): M.Cfg { GoC(M.Finish(X(om), M.Pop(C2(om)), M.W(0), map[])) }
  ghost function C4(om: M.Oracle): M.Cfg { M.SetDst(C3(om), 3, M.FuncAddr(6)).c }
  ghost function C4h(om: M.Oracle): M.Cfg { C4(om).(h := C4(om).h + [E1]) }
  ghost function C5(om: M.Oracle): M.Cfg { GoC(M.Push(X(om), C4h(om), 6, 6, M.Cb(2), [])) }
  ghost function C6(om: M.Oracle): M.Cfg { M.SetDst(C5(om), 0, 0).c }
  ghost function C6b(om: M.Oracle): M.Cfg { M.Pop(C6(om)).(h := C6(om).h + [E2]) }
  ghost function C7(om: M.Oracle): M.Cfg { GoC(M.Finish(X(om), C6b(om), M.W(0), map[])) }
  ghost function TW2(): M.Term { M.TRet(0, W1.L0, [E1, E2]) }

  lemma CB6Is() ensures CB6 as int - M.CODE0 == 6 {}

  // r0 = <alu 0>() at the top frame.
  lemma AluStep(om: M.Oracle, c: M.Cfg, j: nat)
    requires |c.fr| > 0 && 0 <= M.Top(c).pc < |PW2| && M.Top(c).pc == j && PW2[j] == M.Alu(0, 0, [])
    ensures M.StepP(PW2, X(om), c) == M.SetDst(c, 0, 0)
  {
    assert M.StepP(PW2, X(om), c) == M.AluO(X(om), c, 0, 0, []);
    assert M.Rds(M.Top(c), []) == Some([]);
    reveal M.AluO();
  }

  lemma SetDstFacts(c: M.Cfg, dst: nat, v: bv64)
    requires |c.fr| > 0 && dst < |M.Top(c).regs|
    ensures var c1 := M.SetDst(c, dst, v).c;
      |c1.fr| == |c.fr| && B.Below(c1) == B.Below(c) && c1.h == c.h && c1.L == c.L
      && M.Top(c1).pc == M.Top(c).pc + 1 && M.Top(c1).kind == M.Top(c).kind && M.Top(c1).regs[dst] == M.W(v)
      && |M.Top(c1).regs| == |M.Top(c).regs| && M.Top(c1).stack == M.Top(c).stack && M.Top(c1).fn == M.Top(c).fn
  {
    B.PutTop(c, M.Adv(M.SetR(M.Top(c), dst, M.W(v))));
  }

  lemma {:isolate_assertions} Run0(om: M.Oracle)
    ensures |C1(om).fr| == 2 && M.Top(C1(om)).pc == 4 && M.Top(C1(om)).kind == M.Sub && |M.Top(C1(om)).regs| == M.NR
    ensures B.Below(C1(om)) == C0().fr && C1(om).h == [] && C1(om).L == W1.L0
    ensures M.StepP(PW2, X(om), C0()) == M.Go(C1(om))
  {
    Cl.PushIs(X(om), C0(), 4, 4, M.Sub, Cl.CArgs(C0()));
    Cl.PFrameFacts(X(om), C0(), 4, 4, M.Sub, Cl.CArgs(C0()));
    assert M.StepP(PW2, X(om), C0()) == M.Push(X(om), C0(), 4, 4, M.Sub, Cl.CArgs(C0()));
  }

  lemma {:isolate_assertions} Run12(om: M.Oracle)
    ensures M.StepP(PW2, X(om), C1(om)) == M.Go(C2(om))
    ensures M.StepP(PW2, X(om), C2(om)) == M.Go(C3(om))
    ensures |C3(om).fr| == 1 && M.Top(C3(om)).pc == 1 && M.Top(C3(om)).kind == M.Main && |M.Top(C3(om)).regs| == M.NR
    ensures C3(om).h == [] && C3(om).L == W1.L0 && M.Top(C3(om)).stack == C0().fr[0].stack
  {
    Run0(om);
    AluStep(om, C1(om), 4);
    SetDstFacts(C1(om), 0, 0);
    var c2 := C2(om);
    assert M.Top(c2).pc == 5 && M.Reg(M.Top(c2), 0) == M.W(0);
    assert M.StepP(PW2, X(om), c2) == M.ExitO(X(om), c2);
    assert M.ExitO(X(om), c2) == M.ExitFrame(X(om), c2, 0) by { reveal M.ExitO(); }
    assert M.Pop(c2).fr == C0().fr;
    assert M.ExitFrame(X(om), c2, 0) == M.Finish(X(om), M.Pop(c2), M.W(0), map[]) by { reveal M.ExitFrame(); }
    assert M.Top(M.Pop(c2)) == C0().fr[0];
    B.FinishFacts(X(om), M.Pop(c2), M.W(0), map[]);
    F.ApplyNone(M.Pop(c2));
  }

  lemma {:isolate_assertions} Run34(om: M.Oracle)
    requires AdmOm(om)
    ensures M.StepP(PW2, X(om), C3(om)) == M.Go(C4(om))
    ensures M.StepP(PW2, X(om), C4(om)) == M.Go(C5(om))
    ensures |C5(om).fr| == 2 && M.Top(C5(om)).pc == 6 && M.Top(C5(om)).kind == M.Cb(2) && |M.Top(C5(om)).regs| == M.NR
    ensures B.Below(C5(om)) == C4(om).fr && |C4(om).fr| == 1 && M.Top(C4(om)).pc == 2 && M.Top(C4(om)).kind == M.Main
    ensures C5(om).h == [E1] && C5(om).L == W1.L0 && |M.Top(C4(om)).regs| == M.NR && M.Top(C4(om)).stack == C0().fr[0].stack
  {
    Run12(om);
    var x := X(om);
    var c3 := C3(om);
    assert M.StepP(PW2, x, c3) == M.FRefO(c3, 3, 6);
    assert M.FRefO(c3, 3, 6) == M.SetDst(c3, 3, M.FuncAddr(6)) by { reveal M.FRefO(); }
    SetDstFacts(c3, 3, M.FuncAddr(6));
    var c4 := C4(om);
    assert M.StepP(PW2, x, c4) == M.HelperStep(x, c4, 2, false, 181, true);
    assert M.Upto(1, 0) == [];
    assert M.Rds(M.Top(c4), []) == Some([]);
    assert M.FootBytes(c4, []) == M.FOk([]) by { reveal M.FootBytes(); }
    assert om(c4.h, E1, M.Wh(c4)) == RInv;
    Cl.CbSame(x, c4, 2, 181, 0, [], [], RInv);
    assert C4h(om) == c4.(h := c4.h + [M.ECall(2, false, 181, [], [])]);
    CB6Is();
    FnSetW2();
    assert M.Invoke(x, C4h(om), 2, CB6, []) == M.Push(x, C4h(om), 6, 6, M.Cb(2), []) by { reveal M.Invoke(); }
    Cl.PushIs(x, C4h(om), 6, 6, M.Cb(2), []);
    Cl.PFrameFacts(x, C4h(om), 6, 6, M.Cb(2), []);
  }

  lemma {:isolate_assertions} Run56(om: M.Oracle)
    requires AdmOm(om)
    ensures M.StepP(PW2, X(om), C5(om)) == M.Go(C6(om))
    ensures M.StepP(PW2, X(om), C6(om)) == M.Go(C7(om))
    ensures |C7(om).fr| == 1 && M.Top(C7(om)).pc == 3 && M.Top(C7(om)).kind == M.Main && M.Reg(M.Top(C7(om)), 0) == M.W(0)
    ensures C7(om).h == [E1, E2] && C7(om).L == W1.L0
  {
    Run34(om);
    var x := X(om);
    AluStep(om, C5(om), 6);
    SetDstFacts(C5(om), 0, 0);
    var c6 := C6(om);
    assert M.Top(c6).pc == 7 && M.Reg(M.Top(c6), 0) == M.W(0) && M.Top(c6).kind == M.Cb(2) && |c6.fr| == 2;
    assert M.StepP(PW2, x, c6) == M.ExitO(x, c6);
    assert M.ExitO(x, c6) == M.ExitFrame(x, c6, 0) by { reveal M.ExitO(); }
    Cl.ExitCbIs(x, c6, 0, 2);
    assert om(c6.h, E2, M.Wh(M.Pop(c6))) == W1.R0;
    assert M.Pop(c6).fr == C4(om).fr;
    assert M.Top(C6b(om)) == C4(om).fr[0];
    B.FinishFacts(x, C6b(om), M.W(0), map[]);
    F.ApplyNone(C6b(om));
  }

  lemma {:isolate_assertions} Run7(om: M.Oracle)
    requires AdmOm(om)
    ensures M.StepP(PW2, X(om), C7(om)) == M.Done(TW2())
  {
    Run56(om);
    var c7 := C7(om);
    assert M.StepP(PW2, X(om), c7) == M.ExitO(X(om), c7);
    reveal M.ExitO(), M.ExitFrame();
  }

  // What every step reads of the stack: nothing.
  lemma {:isolate_assertions} AccW2(om: M.Oracle)
    requires AdmOm(om)
    ensures Pr.Acc(PW2, X(om), C0()) == {} && Pr.Acc(PW2, X(om), C1(om)) == {} && Pr.Acc(PW2, X(om), C2(om)) == {}
    ensures Pr.Acc(PW2, X(om), C3(om)) == {} && Pr.Acc(PW2, X(om), C4(om)) == {} && Pr.Acc(PW2, X(om), C5(om)) == {}
    ensures Pr.Acc(PW2, X(om), C6(om)) == {} && Pr.Acc(PW2, X(om), C7(om)) == {}
  {
    Run0(om); Run12(om); Run34(om); Run56(om);
    SetDstFacts(C1(om), 0, 0);
    SetDstFacts(C5(om), 0, 0);
    var x := X(om);
    assert M.Upto(1, 0) == [];
    assert M.Rds(M.Top(C4(om)), []) == Some([]);
    assert M.FootBytes(C4(om), []) == M.FOk([]) by { reveal M.FootBytes(); }
    assert Pr.FootAcc(C4(om), []) == {};
    assert Pr.HelperAcc(x, C4(om), 2, false, 181) == {};
    assert M.Top(C2(om)).kind == M.Sub;
    assert Pr.WrAcc(M.Pop(C6(om)), map[]) == {};
    assert M.Top(C6(om)).kind == M.Cb(2) && M.Reg(M.Top(C6(om)), 0) == M.W(0);
    assert om(C6(om).h, M.ECbRet(2, 0), M.Wh(M.Pop(C6(om)))) == W1.R0;
    assert Pr.ExitAcc(x, C6(om), 0) == {};
  }

  lemma {:isolate_assertions} RunsW2(om: M.Oracle)
    requires AdmOm(om)
    ensures forall n: nat :: M.RunP(PW2, X(om), C0(), n) == (if n >= 8 then M.Fin(TW2()) else M.NoFuel)
    ensures forall n: nat :: match M.ReachP(PW2, X(om), C0(), n) case None => true case Some(c) => Pr.Acc(PW2, X(om), c) == {}
  {
    var x := X(om);
    Run0(om); Run12(om); Run34(om); Run56(om); Run7(om); AccW2(om);
    var cs := [C0(), C1(om), C2(om), C3(om), C4(om), C5(om), C6(om), C7(om)];
    forall n: nat ensures M.RunP(PW2, x, C0(), n) == (if n >= 8 then M.Fin(TW2()) else M.NoFuel) {
      RunFrom(om, cs, 0, n);
    }
    forall n: nat ensures match M.ReachP(PW2, x, C0(), n) case None => true case Some(c) => Pr.Acc(PW2, x, c) == {} {
      ReachFrom(om, cs, 0, n);
    }
  }

  // The run from the k-th configuration of a chain of steps.
  lemma RunFrom(om: M.Oracle, cs: seq<M.Cfg>, k: nat, n: nat)
    requires |cs| == 8 && k < 8
    requires forall i | 0 <= i < 7 :: M.StepP(PW2, X(om), cs[i]) == M.Go(cs[i + 1])
    requires M.StepP(PW2, X(om), cs[7]) == M.Done(TW2())
    ensures M.RunP(PW2, X(om), cs[k], n) == (if n >= 8 - k then M.Fin(TW2()) else M.NoFuel)
    decreases n
  {
    if n > 0 && k < 7 { RunFrom(om, cs, k + 1, n - 1); }
  }

  lemma ReachFrom(om: M.Oracle, cs: seq<M.Cfg>, k: nat, n: nat)
    requires |cs| == 8 && k < 8
    requires forall i | 0 <= i < 7 :: M.StepP(PW2, X(om), cs[i]) == M.Go(cs[i + 1])
    requires M.StepP(PW2, X(om), cs[7]) == M.Done(TW2())
    requires forall i | 0 <= i < 8 :: Pr.Acc(PW2, X(om), cs[i]) == {}
    ensures match M.ReachP(PW2, X(om), cs[k], n) case None => true case Some(c) => Pr.Acc(PW2, X(om), c) == {}
    decreases n
  {
    if n > 0 && k < 7 { ReachFrom(om, cs, k + 1, n - 1); }
  }

  lemma {:isolate_assertions} PremW2()
    ensures Pr.E0(PW2, EnvW2(), W1.SemW(), AdmW2) && Pr.A1b(PW2, EnvW2(), W1.SemW(), AdmW2)
    ensures Pr.A1a(PW2, EnvW2(), W1.SemW(), AdmW2, EllW2)
  {
    forall l, om | AdmW2(l, om)
      ensures exists n: nat :: var r := M.RunP(PW2, M.CtxP(PW2, EnvW2(), W1.SemW(), om), M.InitP(l), n); r.Fin? || r == M.Stk(true)
    {
      RunsW2(om);
      assert M.InitP(l) == C0() && M.CtxP(PW2, EnvW2(), W1.SemW(), om) == X(om);
      assert M.RunP(PW2, X(om), C0(), 8) == M.Fin(TW2());
    }
    forall l, om, n: nat | AdmW2(l, om) ensures M.RunP(PW2, M.CtxP(PW2, EnvW2(), W1.SemW(), om), M.InitP(l), n) != M.Stk(true)
    {
      RunsW2(om);
      assert M.InitP(l) == C0() && M.CtxP(PW2, EnvW2(), W1.SemW(), om) == X(om);
      assert M.RunP(PW2, X(om), C0(), n) == (if n >= 8 then M.Fin(TW2()) else M.NoFuel);
    }
    forall l, om, n: nat | AdmW2(l, om)
      ensures var x := M.CtxP(PW2, EnvW2(), W1.SemW(), om);
        match M.ReachP(PW2, x, M.InitP(l), n)
        case None => true
        case Some(c) => forall a | a in Pr.Acc(PW2, x, c) :: a.0 < |c.fr| && a.1 as int - M.STK as int >= EllW2(c.fr[a.0].fn)
    {
      RunsW2(om);
      assert M.InitP(l) == C0() && M.CtxP(PW2, EnvW2(), W1.SemW(), om) == X(om);
      var r := M.ReachP(PW2, X(om), C0(), n);
      if r.Some? { assert Pr.Acc(PW2, X(om), r.value) == {}; }
    }
  }

  lemma A3bW2() ensures Pr.A3b(EnvW2(), TblW2) {}
  lemma A5W2() ensures Pr.A5(W1.ObsvW) {}

  // Non-vacuity: every hypothesis of SegmentPreservation holds for this instance.
  lemma {:isolate_assertions} Witness2()
    ensures T.Hyp(PW2, DW2(), R.Layout(PW2, DW2()), EllW2, LiveW2, TblW2, EnvW2(), W1.SemW(), W1.ObsvW, AdmW2)
    ensures Pr.A8(OmW2) && AdmW2(W1.L0, OmW2)
  {
    ValidW2(); PremW2(); StructW2(); ShapeW2();
    A3bW2();
    A5W2();
    assert Pr.S0(PW2) && Pr.E0Shape(PW2);
    assert Pr.Structure(PW2, DW2(), R.Layout(PW2, DW2()), EllW2, LiveW2, TblW2);
    LoadW();
    assert R.AllValidated(PW2, DW2(), EllW2);
    assert Pr.E0(PW2, EnvW2(), W1.SemW(), AdmW2) && Pr.A1b(PW2, EnvW2(), W1.SemW(), AdmW2);
    assert Pr.A1a(PW2, EnvW2(), W1.SemW(), AdmW2, EllW2);
    HypI(PW2, DW2(), R.Layout(PW2, DW2()), EllW2, LiveW2, TblW2, EnvW2(), W1.SemW(), W1.ObsvW, AdmW2);
    assert Pr.A8(OmW2);
    assert AdmW2(W1.L0, OmW2);
  }

  lemma HypI(P: seq<M.OInstr>, D: R.Decomp, Pp: M.RwProg, ell: nat -> int, live: nat -> set<nat>,
             tbl: bv32 -> set<nat>, env: M.Env, sem: M.Sem, obsv: M.Observer, Adm: (M.Local, M.Oracle) -> bool)
    requires Pr.S0(P) && Pr.Structure(P, D, Pp, ell, live, tbl) && Pr.Loadable(P, D) && R.AllValidated(P, D, ell)
    requires Pr.E0Shape(P) && Pr.E0(P, env, sem, Adm) && Pr.A1a(P, env, sem, Adm, ell) && Pr.A1b(P, env, sem, Adm)
    requires Pr.A3b(env, tbl) && Pr.A5(obsv)
    ensures T.Hyp(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm)
  {}

  lemma LoadW() ensures Pr.Loadable(PW2, DW2()) { CodeTable2(); }
}
