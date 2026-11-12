// Non-vacuity for P8: the program of Witness.dfy with its lookup wrapped
// (WP empty, call W at kappa(1), W = [call lookup; exit] after the last
// original instruction): every hypothesis of the theorem holds for it.
include "Witness.dfy"

module SimWitness3 {
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

  // W: call map_lookup_elem; exit
  const WBL: seq<seq<bv8>> := WBLLit()
  opaque function WBLLit(): seq<seq<bv8>> { [[0x85, 0, 0, 0, 1, 0, 0, 0], [0x95, 0, 0, 0, 0, 0, 0, 0]] }
  const WBP: seq<Instr> := [CallHelper(1), Exit]
  // call W with offset 2 (W at 4, kappa(1) = 1)
  const CALLW: seq<bv8> := R.EncCallLocal(2)

  function Imm4(b: seq<bv8>): bv32 requires |b| == 4 {
    (b[0] as bv32) | ((b[1] as bv32) << 8) | ((b[2] as bv32) << 16) | ((b[3] as bv32) << 24)
  }
  lemma ImmLow(u: bv64) ensures Imm4([ByteOf(u, 0), ByteOf(u, 1), ByteOf(u, 2), ByteOf(u, 3)]) == (u & 0xffff_ffff) as bv32 {}
  lemma Narrow(u: bv64) requires u < 0x1_0000_0000 ensures ((u & 0xffff_ffff) as bv32) as int == u as int {}
  lemma RT(n: int) requires 0 <= n < TWO64 ensures (n as bv64) as int == n {}
  lemma B4Signed(v: int)
    requires -0x8000_0000 <= v < 0x8000_0000
    ensures Signed32(Imm4(R.B4(v))) == v
  {
    var m := v % 0x1_0000_0000;
    var u := m as bv64;
    RT(m);
    assert u < 0x1_0000_0000;
    ImmLow(u);
    Narrow(u);
  }
  lemma DecodeCallW(v: int)
    requires -0x8000_0000 <= v < 0x8000_0000
    ensures |R.EncCallLocal(v)| == 8 && Decode(R.EncCallLocal(v)).Some? && Decode(R.EncCallLocal(v)).value.CallLocal?
    ensures Signed32(Decode(R.EncCallLocal(v)).value.imm) == v
  {
    var b := R.EncCallLocal(v);
    var q := R.B4(v);
    assert b == [0x85, 0x10, 0, 0, q[0], q[1], q[2], q[3]];
    assert Decode(b) == Some(CallLocal(Imm4(q)));
    B4Signed(v);
  }

  lemma Shapes3()
    ensures |WBL| == 2 && W1.All8(WBL) && |CALLW| == 8 && WBL[0] == W1.LOOKUP
    ensures Decode(WBL[0]) == Some(WBP[0]) && Decode(WBL[1]) == Some(WBP[1])
    ensures Decode(CALLW).Some? && Decode(CALLW).value.CallLocal?
  { reveal WBLLit(), W1.LOOKUPLit(); DecodeCallW(2); }

  lemma DecodeOne(b: seq<bv8>)
    requires |b| == 8 && Decode(b).Some?
    ensures DecodeFrom(b, 0) == DOk([Decode(b).value])
  {
    assert NumInsns(b) == 1;
    assert InsnAt(b, 0) == b;
  }

  function WSpec(): Spec { Api.WithBinds(Api.WrapSiteSpec(0, W1.Cat(WBL), W1.LOOKUP), []) }

  lemma {:isolate_assertions} WrapValid() ensures Validate(CALLW, WSpec()) == Validated
  {
    Shapes3();
    W1.DecodeCat(WBL, WBP, 0);
    var sp := WSpec();
    reveal HelperIdOf();
    assert HelperIdOf(W1.LOOKUP) == Some(1) by { reveal W1.LOOKUPLit(); }
    assert SpecWF(sp);
    var imm := Decode(CALLW).value.imm;
    DecodeOne(CALLW);
    var prog := [CallLocal(imm)];
    assert forall j :: 0 <= j < |WBP| ==> WInsnOk(WBP[j], sp);
    assert CountHelperCalls(WBP) == 1;
    assert CountBranches(prog) + CountBranches(WBP) == 0;
    var s0 := SInit();
    var e := EnterWS(s0);
    assert WrapArgsSym(1, e.regs);
    assert SymStep(sp, WBP[0], e).SOk?;
    var s1 := SymStep(sp, WBP[0], e).ss;
    assert s1.regs[0] == s1.ret;
    var r := ReturnS(s1, s0.regs);
    assert forall k :: 6 <= k <= 10 ==> r.regs[k] == Entry(k);
    assert Final(sp, r, 1) == Validated;
    reveal SymExec();
    assert SymExec(WBP, sp, 1, s1, WBody(s0.regs)) == Validated;
    assert SymExec(WBP, sp, 0, e, WBody(s0.regs)) == Validated;
    assert SymExec(prog[..0], sp, 0, s0, WP(WBP)) == Validated;
    assert ValidateWrap(prog, sp) == Validated;
  }

  // ================= the instance =================

  opaque function D3(): R.Decomp {
    R.Decomp([], map[], map[], map[], map[1 := R.Wrap([], W1.Cat(WBL), [])], map[], [R.WrapFn(1)])
  }

  lemma LensW3()
    ensures R.NI(W1.Cat(WBL)) == 2
    ensures R.Start(D3(), 0) == 0 && R.Start(D3(), 1) == 1 && R.Start(D3(), 2) == 2
    ensures R.Start(D3(), 3) == 3 && R.Start(D3(), 4) == 4
    ensures R.E(D3(), 1) == 1 && R.K(D3(), 1) == 1
    ensures forall j | 0 <= j < 4 :: R.FnsAt(D3(), j) == [] && R.E(D3(), j) == j && R.K(D3(), j) == j && R.FE(D3(), j) == j
  {
    reveal D3();
    Shapes3();
    W1.CatLen(WBL);
    var D := D3();
    assert R.FnsLen(D, []) == 0;
    assert R.FnsAt(D, 0) == [] && R.FnsAt(D, 1) == [] && R.FnsAt(D, 2) == [] && R.FnsAt(D, 3) == [];
    assert R.BlockLen(D, 0) == 1 && R.BlockLen(D, 1) == 1 && R.BlockLen(D, 2) == 1 && R.BlockLen(D, 3) == 1;
  }

  lemma {:isolate_assertions} AllFnsW3() ensures R.AllFns(W1.PW, D3()) == [(R.WrapFn(1), 4)]
  {
    reveal D3();
    LensW3();
    var D := D3();
    assert R.FnStarts(D, [], 0) == [];
    assert R.AllFnsFrom(D, 4, 4) == R.FnStarts(D, D.tail, 4);
    assert R.FnStarts(D, D.tail, 4) == [(R.WrapFn(1), 4)] + R.FnStarts(D, [], 4 + R.FnLen(D, R.WrapFn(1)));
    assert R.AllFnsFrom(D, 4, 3) == R.AllFnsFrom(D, 4, 4);
    assert R.AllFnsFrom(D, 4, 2) == R.AllFnsFrom(D, 4, 3);
    assert R.AllFnsFrom(D, 4, 1) == R.AllFnsFrom(D, 4, 2);
    assert R.AllFnsFrom(D, 4, 0) == R.AllFnsFrom(D, 4, 1);
  }

  lemma WStartW3() ensures R.WStart(W1.PW, D3(), 1) == 4 { AllFnsW3(); }

  lemma WFW3() ensures LF.AllFnsWF(W1.PW, D3()) && R.FnsLen(D3(), D3().tail) == 2
  {
    reveal D3();
    LensW3();
    var D := D3();
    assert LF.FnsWF(W1.PW, D, D.tail);
    assert R.FnsLen(D, []) == 0;
    assert R.FnsLen(D, D.tail) == R.FnLen(D, D.tail[0]) + R.FnsLen(D, D.tail[1..]);
    assert D.tail[1..] == [];
  }

  lemma LenW3() ensures |R.Layout(W1.PW, D3()).code| == 6 { WFW3(); LensW3(); LF.CodeLen(W1.PW, D3()); }

  lemma {:isolate_assertions} CodeW3K(j: nat)
    requires j < 4 && j != 1
    ensures |R.Layout(W1.PW, D3()).code| == 6 && R.Layout(W1.PW, D3()).code[j] == M.O(W1.PW[j], j)
  {
    LenW3();
    reveal D3();
    WFW3(); LensW3();
    var D := D3();
    assert j !in D.pl && j !in D.wrap && j !in D.site;
    LF.PlainCode(W1.PW, D, j);
    assert R.Reloc(D, W1.PW[j]) == W1.PW[j];
  }

  lemma {:isolate_assertions} CodeW3Call() ensures |R.Layout(W1.PW, D3()).code| == 6 && R.Layout(W1.PW, D3()).code[1] == M.N(CALLW)
  {
    LenW3();
    reveal D3();
    WFW3(); LensW3(); WStartW3();
    var D := D3();
    LF.BlockParts(W1.PW, D, 1);
    LF.CodeAt(W1.PW, D, 1, 0);
    assert R.PreLen(D, 1) == 0 && R.FPLen(D, 1) == 0 && R.PLLen(D, 1) == 0;
    assert R.KappaTI(W1.PW, D, 1) == M.N(R.EncCallLocal(2));
  }

  lemma {:isolate_assertions} CodeW3W(k: nat)
    requires k < 2
    ensures |R.Layout(W1.PW, D3()).code| == 6 && |WBL| == 2
    ensures R.Layout(W1.PW, D3()).code[4 + k] == (if k == 0 then M.O(W1.PW[1], 1) else M.N(WBL[1]))
  {
    LenW3();
    reveal D3();
    WFW3(); LensW3(); Shapes3();
    var D := D3();
    LF.CodeTail(W1.PW, D, k);
    assert R.FnsCode(W1.PW, D, []) == [];
    assert R.FnsCode(W1.PW, D, D.tail) == R.WCode(W1.PW, D, 1) + R.FnsCode(W1.PW, D, []);
    W1.CatAt(WBL, k);
    assert R.Slice(W1.Cat(WBL), k) == WBL[k];
  }

  lemma CodeTable3()
    ensures |R.Layout(W1.PW, D3()).code| == 6 && |WBL| == 2
    ensures var code := R.Layout(W1.PW, D3()).code;
      code[0] == M.O(W1.PW[0], 0) && code[1] == M.N(CALLW) && code[2] == M.O(W1.PW[2], 2)
      && code[3] == M.O(W1.PW[3], 3) && code[4] == M.O(W1.PW[1], 1) && code[5] == M.N(WBL[1])
  {
    LenW3(); CodeW3K(0); CodeW3K(2); CodeW3K(3); CodeW3Call(); CodeW3W(0); CodeW3W(1);
  }

  lemma {:isolate_assertions} HooksW3() ensures R.Layout(W1.PW, D3()).hooks == {}
  {
    LF.LayoutIs(W1.PW, D3()); AllFnsW3();
    forall t | t in R.Hooks(W1.PW, D3()) ensures false {
      var k :| 0 <= k < |R.AllFns(W1.PW, D3())| && R.AllFns(W1.PW, D3())[k].0.HookFn? && R.AllFns(W1.PW, D3())[k].1 == t;
    }
  }

  // ---------------- the premises ----------------

  lemma {:isolate_assertions} PiecesW3() ensures Pr.PiecesOk(W1.PW, D3())
  {
    reveal D3();
    Shapes3(); AllFnsW3(); W1.FnSetW();
    W1.CatLen(WBL);
    var D := D3();
    assert Pr.NoHelperIn([]);
    var A := R.AllFns(W1.PW, D);
    assert (set k | 0 <= k < |A| && A[k].0 == R.WrapFn(1)) == {0};
  }

  lemma {:isolate_assertions} CallsW3() ensures Pr.CallsOk(D3(), R.Layout(W1.PW, D3()))
  {
    CodeTable3(); Shapes3(); LensW3();
    reveal D3();
    var Pp := R.Layout(W1.PW, D3());
    forall p | 0 <= p < |Pp.code| && Pp.code[p].N?
      ensures var b := Pp.code[p].b;
        (|b| == 8 && Decode(b).Some? && Decode(b).value.CallLocal? && !(exists i :: i in D3().wrap && p == R.K(D3(), i)))
        ==> p + 1 + Signed32(Decode(b).value.imm) in Pp.hooks
    {
      if p == 1 { assert 1 in D3().wrap && 1 == R.K(D3(), 1); }
      else { assert p == 5; }
    }
  }

  lemma {:isolate_assertions} ValidW3() ensures R.AllValidated(W1.PW, D3(), W1.EllW)
  {
    reveal D3();
    var D := D3();
    WrapValid(); WStartW3(); LensW3(); AllFnsW3();
    W1.EncW();
    W1.FlW(1);
    assert R.WStart(W1.PW, D, 1) - R.K(D, 1) - 1 == 2;
    assert D.wrap[1].wp + R.EncCallLocal(2) == CALLW;
    assert R.Valid(CALLW, WSpec()) by { reveal R.Valid(); }
    assert D.fp == map[] && D.pl == map[] && D.site == map[] && |D.pro0| == 0;
  }

  lemma {:isolate_assertions} StructW3() ensures Pr.Structure(W1.PW, D3(), R.Layout(W1.PW, D3()), W1.EllW, W1.LiveW, W1.TblW)
  {
    reveal D3();
    PiecesW3(); CallsW3(); W1.FnSetW();
    assert Pr.LiveOk(W1.PW, W1.LiveW, W1.TblW);
    assert Pr.FloorsOk(W1.PW, W1.EllW);
    assert Pr.S10(W1.PW, D3(), W1.LiveW, W1.TblW);
  }

  lemma LoadW3() ensures Pr.Loadable(W1.PW, D3()) { LenW3(); }

  // Non-vacuity: every hypothesis of SegmentPreservation holds for this P8 instance.
  lemma {:isolate_assertions} Witness3()
    ensures T.Hyp(W1.PW, D3(), R.Layout(W1.PW, D3()), W1.EllW, W1.LiveW, W1.TblW, W1.EnvW(), W1.SemW(), W1.ObsvW, W1.AdmW)
    ensures Pr.A8(W1.OmW) && W1.AdmW(W1.L0, W1.OmW)
    ensures 1 in D3().wrap
  {
    ValidW3(); W1.RunsW(); StructW3(); W1.ShapeW(); LoadW3();
    W1.A3bW();
    W1.A5W();
    W1.HypI(W1.PW, D3(), R.Layout(W1.PW, D3()), W1.EllW, W1.LiveW, W1.TblW, W1.EnvW(), W1.SemW(), W1.ObsvW, W1.AdmW);
    assert Pr.A8(W1.OmW);
    assert W1.AdmW(W1.L0, W1.OmW);
    assert 1 in D3().wrap by { reveal D3(); }
  }
}
