// Non-vacuity for P4: a program with a bpf_tail_call site whose window is
// the tail call alone (empty prelude and postlude); every hypothesis of the
// theorem holds for it.
include "Witness.dfy"

module SimWitness4 {
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
  import W1 = SimWitness

  const TAILB: seq<bv8> := TAILBLit()
  opaque function TAILBLit(): seq<bv8> { [0x85, 0, 0, 0, 12, 0, 0, 0] }

  lemma TailValid() ensures Validate(TAILB, Api.TailSiteSpec(0)) == Validated
  {
    reveal TAILBLit();
    var sp := Api.TailSiteSpec(0);
    assert Decode(TAILB) == Some(CallHelper(12));
    assert InsnAt(TAILB, 0) == TAILB;
    assert DecodeFrom(TAILB, 0) == DOk([CallHelper(12)]);
    var prog := [CallHelper(12)];
    assert CountBranches(prog) == 0;
    var s0 := SInit();
    assert s0.regs[1..6] == [Entry(1), Entry(2), Entry(3), Entry(4), Entry(5)];
    assert SymStep(sp, prog[0], s0).SOk?;
    var s1 := SymStep(sp, prog[0], s0).ss;
    assert forall k :: 6 <= k <= 10 ==> s1.regs[k] == Entry(k);
    assert Final(sp, s1, 1) == Validated;
    reveal SymExec();
    assert SymExec(prog, sp, 1, s1, Top) == Validated;
    assert SymExec(prog, sp, 0, s0, Top) == Validated;
  }

  // ================= the instance =================

  // r2 = <alu 0>(r10); r3 = <alu 0>(r10); bpf_tail_call(r1, r2, r3); r0 = <alu 0>(); exit
  const PW4: seq<M.OInstr> := [M.Alu(0, 2, [10]), M.Alu(0, 3, [10]), M.Tail, M.Alu(0, 0, []), M.Exit]
  opaque function D4(): R.Decomp { R.Decomp([], map[], map[], map[2 := R.Site([], [], [])], map[], map[], []) }
  const RF: M.Resp := M.RTailFail
  function OmW4(h: seq<M.Ev>, e: M.Ev, w: M.Where): M.Resp { RF }
  ghost predicate AdmW4(l: M.Local, om: M.Oracle) { l == W1.L0 && forall h, e, w :: om(h, e, w) == RF }

  // ---------------- the run of P ----------------

  ghost function RegsT(): seq<M.Val> {
    seq(M.NR, k requires 0 <= k < M.NR => if k <= 5 then M.Bot else W1.Regs0()[k])
  }
  const EV4: M.Ev := M.ECall(2, false, 12, [M.CTX, 0, 0], [])
  ghost function C(k: nat): M.Cfg {
    if k == 0 then M.InitP(W1.L0)
    else if k == 1 then M.Cfg([W1.Fr(1, W1.Regs0()[2 := M.W(0)])], W1.L0, [], 0, [])
    else if k == 2 then M.Cfg([W1.Fr(2, W1.Regs0()[2 := M.W(0)][3 := M.W(0)])], W1.L0, [], 0, [])
    else if k == 3 then M.Cfg([W1.Fr(3, RegsT())], W1.L0, [EV4], 6, [])
    else M.Cfg([W1.Fr(4, RegsT()[0 := M.W(0)])], W1.L0, [EV4], 6, [])
  }

  lemma AluD(x: M.Ctx, c: M.Cfg, d: nat, t: bv64)
    requires M.Rds(M.Top(c), [10]) == Some([t]) && x.sem == W1.SemW() && d < 10
    ensures M.AluO(x, c, 0, d, [10]) == M.SetDst(c, d, 0)
  { reveal M.AluO(); }

  lemma {:isolate_assertions} Step01(om: M.Oracle)
    ensures M.StepP(PW4, M.CtxP(PW4, W1.EnvW(), W1.SemW(), om), C(0)) == M.Go(C(1))
    ensures M.StepP(PW4, M.CtxP(PW4, W1.EnvW(), W1.SemW(), om), C(1)) == M.Go(C(2))
  {
    var x := M.CtxP(PW4, W1.EnvW(), W1.SemW(), om);
    var t := M.StackTop(0);
    assert W1.Regs0()[10] == M.W(t);
    F.RdsAll(M.Top(C(0)), [10]);
    assert F.Words(M.Top(C(0)), [10]) == [t];
    assert M.StepP(PW4, x, C(0)) == M.AluO(x, C(0), 0, 2, [10]);
    AluD(x, C(0), 2, t);
    F.RdsAll(M.Top(C(1)), [10]);
    assert F.Words(M.Top(C(1)), [10]) == [t];
    assert M.StepP(PW4, x, C(1)) == M.AluO(x, C(1), 0, 3, [10]);
    AluD(x, C(1), 3, t);
  }

  lemma {:isolate_assertions} Step2(om: M.Oracle)
    requires forall h, e, w :: om(h, e, w) == RF
    ensures M.StepP(PW4, M.CtxP(PW4, W1.EnvW(), W1.SemW(), om), C(2)) == M.Go(C(3))
  {
    var x := M.CtxP(PW4, W1.EnvW(), W1.SemW(), om);
    var c := C(2);
    var f := M.Top(c);
    assert W1.Regs0()[1] == M.W(M.CTX);
    assert M.Reg(f, 1) == M.W(M.CTX) && M.Reg(f, 2) == M.W(0) && M.Reg(f, 3) == M.W(0);
    F.RdsAll(f, [1, 2, 3]);
    assert F.Words(f, [1, 2, 3]) == [M.CTX, 0, 0];
    assert M.Rds(f, [1, 2, 3]) == Some([M.CTX, 0, 0]);
    assert om(c.h, EV4, M.Wh(c)) == RF;
    var c1 := c.(h := c.h + [EV4]);
    var regs := seq(|f.regs|, k requires 0 <= k < |f.regs| => if k <= 5 then M.Und(x, c1, k) else f.regs[k]);
    assert regs == RegsT();
    assert M.StepP(PW4, x, c) == M.TailO(x, c, 2);
    assert M.TailO(x, c, 2) == M.Go(C(3)) by { reveal M.TailO(); }
  }

  lemma {:isolate_assertions} Step34(om: M.Oracle)
    ensures M.StepP(PW4, M.CtxP(PW4, W1.EnvW(), W1.SemW(), om), C(3)) == M.Go(C(4))
    ensures M.StepP(PW4, M.CtxP(PW4, W1.EnvW(), W1.SemW(), om), C(4)) == M.Done(M.TRet(0, W1.L0, [EV4]))
  {
    assert RegsT()[0 := M.W(0)][0] == M.W(0);
    reveal M.AluO(), M.ExitO(), M.ExitFrame();
  }

  lemma {:isolate_assertions} RunW4(om: M.Oracle)
    requires forall h, e, w :: om(h, e, w) == RF
    ensures M.RunP(PW4, M.CtxP(PW4, W1.EnvW(), W1.SemW(), om), M.InitP(W1.L0), 5) == M.Fin(M.TRet(0, W1.L0, [EV4]))
    ensures forall n: nat :: M.RunP(PW4, M.CtxP(PW4, W1.EnvW(), W1.SemW(), om), M.InitP(W1.L0), n) != M.Stk(true)
    ensures forall n: nat :: var x := M.CtxP(PW4, W1.EnvW(), W1.SemW(), om);
      match M.ReachP(PW4, x, M.InitP(W1.L0), n) case None => true case Some(c) => Pr.Acc(PW4, x, c) == {}
  {
    var x := M.CtxP(PW4, W1.EnvW(), W1.SemW(), om);
    Step01(om); Step2(om); Step34(om);
    assert M.InitP(W1.L0) == C(0);
    forall n: nat ensures M.RunP(PW4, x, M.InitP(W1.L0), n) != M.Stk(true) {
      if n >= 1 { assert M.RunP(PW4, x, C(0), n) == M.RunP(PW4, x, C(1), n - 1); }
      if n >= 2 { assert M.RunP(PW4, x, C(1), n - 1) == M.RunP(PW4, x, C(2), n - 2); }
      if n >= 3 { assert M.RunP(PW4, x, C(2), n - 2) == M.RunP(PW4, x, C(3), n - 3); }
      if n >= 4 { assert M.RunP(PW4, x, C(3), n - 3) == M.RunP(PW4, x, C(4), n - 4); }
      if n >= 5 { assert M.RunP(PW4, x, C(4), n - 4) == M.Fin(M.TRet(0, W1.L0, [EV4])); }
    }
    assert Pr.Acc(PW4, x, C(0)) == {} && Pr.Acc(PW4, x, C(1)) == {} && Pr.Acc(PW4, x, C(2)) == {};
    assert Pr.Acc(PW4, x, C(3)) == {};
    assert Pr.Acc(PW4, x, C(4)) == {};
    forall n: nat ensures match M.ReachP(PW4, x, M.InitP(W1.L0), n) case None => true case Some(c) => Pr.Acc(PW4, x, c) == {} {
      if n >= 1 { assert M.ReachP(PW4, x, C(0), n) == M.ReachP(PW4, x, C(1), n - 1); }
      if n >= 2 { assert M.ReachP(PW4, x, C(1), n - 1) == M.ReachP(PW4, x, C(2), n - 2); }
      if n >= 3 { assert M.ReachP(PW4, x, C(2), n - 2) == M.ReachP(PW4, x, C(3), n - 3); }
      if n >= 4 { assert M.ReachP(PW4, x, C(3), n - 3) == M.ReachP(PW4, x, C(4), n - 4); }
      if n >= 5 { assert M.ReachP(PW4, x, C(4), n - 4) == None; }
    }
  }

  lemma {:isolate_assertions} RunsW4()
    ensures Pr.E0(PW4, W1.EnvW(), W1.SemW(), AdmW4) && Pr.A1b(PW4, W1.EnvW(), W1.SemW(), AdmW4)
    ensures Pr.A1a(PW4, W1.EnvW(), W1.SemW(), AdmW4, W1.EllW)
  {
    forall l, om | AdmW4(l, om)
      ensures exists n: nat :: var r := M.RunP(PW4, M.CtxP(PW4, W1.EnvW(), W1.SemW(), om), M.InitP(l), n); r.Fin? || r == M.Stk(true)
    { RunW4(om); }
    forall l, om, n: nat | AdmW4(l, om) ensures M.RunP(PW4, M.CtxP(PW4, W1.EnvW(), W1.SemW(), om), M.InitP(l), n) != M.Stk(true)
    { RunW4(om); }
    forall l, om, n: nat | AdmW4(l, om)
      ensures var x := M.CtxP(PW4, W1.EnvW(), W1.SemW(), om);
        match M.ReachP(PW4, x, M.InitP(l), n)
        case None => true
        case Some(c) => forall a | a in Pr.Acc(PW4, x, c) :: a.0 < |c.fr| && a.1 as int - M.STK as int >= W1.EllW(c.fr[a.0].fn)
    { RunW4(om); }
  }

  // ---------------- P' = Layout(P, D) ----------------

  lemma {:isolate_assertions} BlockW4(j: nat)
    requires j < 5
    ensures R.FnsAt(D4(), j) == [] && R.BlockLen(D4(), j) == 1 && R.FPLen(D4(), j) == 0 && R.PLLen(D4(), j) == 0
    ensures R.PreLen(D4(), j) == 0 && R.PostLen(D4(), j) == 0
  {
    reveal D4();
    var D := D4();
    assert R.FnsLen(D, []) == 0;
    assert R.NI([]) == 0;
  }

  lemma {:isolate_assertions} StartW4()
    ensures R.Start(D4(), 0) == 0 && R.Start(D4(), 1) == 1 && R.Start(D4(), 2) == 2
    ensures R.Start(D4(), 3) == 3 && R.Start(D4(), 4) == 4 && R.Start(D4(), 5) == 5
  {
    assert R.NI(D4().pro0) == 0 by { reveal D4(); }
    BlockW4(0); BlockW4(1); BlockW4(2); BlockW4(3); BlockW4(4);
  }

  lemma LensW4(j: nat)
    requires j < 5
    ensures R.FnsAt(D4(), j) == [] && R.Start(D4(), j) == j && R.E(D4(), j) == j && R.K(D4(), j) == j
    ensures R.Start(D4(), 5) == 5 && R.PostLen(D4(), j) == 0
  {
    StartW4(); BlockW4(j);
    assert R.FnsLen(D4(), []) == 0;
  }

  lemma AllFnsEmpty4(D: R.Decomp, n: nat, i: nat)
    requires D.fns == map[] && D.tail == []
    ensures R.AllFnsFrom(D, n, i) == []
    decreases n - i
  {
    if i < n { AllFnsEmpty4(D, n, i + 1); assert R.FnsAt(D, i) == []; }
  }

  lemma AllFnsW4() ensures R.AllFns(PW4, D4()) == []
  {
    reveal D4();
    AllFnsEmpty4(D4(), 5, 0);
  }

  lemma WFW4() ensures LF.AllFnsWF(PW4, D4()) && R.FnsLen(D4(), D4().tail) == 0 { reveal D4(); }

  lemma LenW4() ensures |R.Layout(PW4, D4()).code| == 5 { WFW4(); StartW4(); LF.CodeLen(PW4, D4()); }

  lemma {:isolate_assertions} CodeW4(j: nat)
    requires j < 5
    ensures |R.Layout(PW4, D4()).code| == 5 && R.Layout(PW4, D4()).code[j] == M.O(PW4[j], j)
  {
    WFW4(); LensW4(j); LenW4();
    var D := D4();
    assert j !in D.pl && j !in D.wrap && (j in D.site <==> j == 2) by { reveal D4(); }
    if j == 2 {
      assert D.site[2].pre == [] && D.site[2].post == [] by { reveal D4(); }
      LF.SiteCode(PW4, D, 2);
    } else { LF.PlainCode(PW4, D, j); }
    assert R.Reloc(D, PW4[j]) == PW4[j];
  }

  // ---------------- the premises ----------------

  lemma FnSetW4() ensures M.FnSet(PW4) == {0} {}

  lemma {:isolate_assertions} PiecesW4() ensures Pr.PiecesOk(PW4, D4())
  {
    reveal D4();
    AllFnsW4(); FnSetW4();
    assert Pr.NoHelperIn([]) && Pr.Bytes8([]);
  }

  lemma {:isolate_assertions} CallsW4() ensures Pr.CallsOk(D4(), R.Layout(PW4, D4()))
  {
    var Pp := R.Layout(PW4, D4());
    LenW4();
    forall p | 0 <= p < |Pp.code| ensures Pp.code[p].O? { CodeW4(p); }
  }

  lemma {:isolate_assertions} ValidW4() ensures R.AllValidated(PW4, D4(), W1.EllW)
  {
    reveal D4();
    var D := D4();
    TailValid(); AllFnsW4();
    assert R.Fl(PW4, W1.EllW, 2) == 0;
    assert R.Enc(PW4[2]) == R.EncHelper(12);
    assert R.EncHelper(12) == TAILB by { reveal TAILBLit(); }
    assert D.site[2].pre + R.Enc(PW4[2]) + D.site[2].post == TAILB;
    assert R.SiteSpecFor(PW4[2], 0, []) == Api.TailSiteSpec(0);
    assert R.Valid(TAILB, Api.TailSiteSpec(0)) by { reveal R.Valid(); }
    assert D.fp == map[] && D.pl == map[] && D.wrap == map[] && D.site.Keys == {2} && |D.pro0| == 0;
  }

  lemma {:isolate_assertions} StructW4() ensures Pr.Structure(PW4, D4(), R.Layout(PW4, D4()), W1.EllW, W1.LiveW, W1.TblW)
  {
    reveal D4();
    PiecesW4(); CallsW4(); FnSetW4();
    assert Pr.LiveOk(PW4, W1.LiveW, W1.TblW);
    assert Pr.FloorsOk(PW4, W1.EllW);
    assert Pr.S10(PW4, D4(), W1.LiveW, W1.TblW);
  }

  lemma {:isolate_assertions} ShapeW4() ensures Pr.E0Shape(PW4) && Pr.S0(PW4)
  {
    FnSetW4();
    assert forall j | 0 <= j < |PW4| :: Pr.RegsOk(PW4[j]);
  }

  lemma LoadW4() ensures Pr.Loadable(PW4, D4()) { LenW4(); }

  // Non-vacuity: every hypothesis of SegmentPreservation holds for this P4 instance.
  lemma {:isolate_assertions} Witness4()
    ensures T.Hyp(PW4, D4(), R.Layout(PW4, D4()), W1.EllW, W1.LiveW, W1.TblW, W1.EnvW(), W1.SemW(), W1.ObsvW, AdmW4)
    ensures Pr.A8(OmW4) && AdmW4(W1.L0, OmW4)
    ensures 2 in D4().site && PW4[2].Tail?
  {
    ValidW4(); RunsW4(); StructW4(); ShapeW4(); LoadW4();
    W1.A3bW();
    W1.A5W();
    W1.HypI(PW4, D4(), R.Layout(PW4, D4()), W1.EllW, W1.LiveW, W1.TblW, W1.EnvW(), W1.SemW(), W1.ObsvW, AdmW4);
    assert Pr.A8(OmW4);
    assert AdmW4(W1.L0, OmW4);
    assert 2 in D4().site by { reveal D4(); }
  }
}
