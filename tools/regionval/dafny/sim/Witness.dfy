include "Facts.dfy"
include "LayoutFacts.dfy"

module SimWitness {
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

  // ---------------- windows as lists of 8-byte instructions ----------------

  opaque function Cat(l: seq<seq<bv8>>): seq<bv8> { if |l| == 0 then [] else l[0] + Cat(l[1..]) }

  predicate All8(l: seq<seq<bv8>>) { forall i | 0 <= i < |l| :: |l[i]| == 8 }

  lemma CatLen(l: seq<seq<bv8>>) requires All8(l) ensures |Cat(l)| == 8 * |l| {
    reveal Cat();
    if |l| > 0 { CatLen(l[1..]); }
  }

  lemma CatAt(l: seq<seq<bv8>>, k: nat) requires All8(l) && k < |l|
    ensures |Cat(l)| == 8 * |l| && InsnAt(Cat(l), k) == l[k]
  {
    CatLen(l);
    reveal Cat();
    if k > 0 {
      CatAt(l[1..], k - 1);
      assert Cat(l) == l[0] + Cat(l[1..]);
      assert Cat(l)[8 * k .. 8 * k + 8] == Cat(l[1..])[8 * (k - 1) .. 8 * (k - 1) + 8];
    }
  }

  lemma DecodeCat(l: seq<seq<bv8>>, prog: seq<Instr>, i: nat)
    requires All8(l) && |prog| == |l| && i <= |l|
    requires forall k | 0 <= k < |l| :: Decode(l[k]) == Some(prog[k])
    ensures |Cat(l)| == 8 * |l| && DecodeFrom(Cat(l), i) == DOk(prog[i..])
    decreases |l| - i
  {
    CatLen(l);
    if i < |l| {
      CatAt(l, i);
      DecodeCat(l, prog, i + 1);
      assert prog[i..] == [prog[i]] + prog[i + 1..];
    }
  }

  // ---------------- a typed hook body ----------------

  // ldxw r0,[r1+0]; if r4 == 0 goto +1; ldxb r0,[r4+0]; r0 = 0; exit
  const HOOKL: seq<seq<bv8>> := HOOKLLit()
  opaque function HOOKLLit(): seq<seq<bv8>> { [[0x61, 0x10, 0, 0, 0, 0, 0, 0],
                                 [0x15, 0x04, 1, 0, 0, 0, 0, 0],
                                 [0x71, 0x40, 0, 0, 0, 0, 0, 0],
                                 [0xb7, 0x00, 0, 0, 0, 0, 0, 0],
                                 [0x95, 0x00, 0, 0, 0, 0, 0, 0]] }
  const HOOKP: seq<Instr> := [Ldx(4, 0, 1, 0), Jcond(JEq, 4, 0, 1), Ldx(1, 0, 4, 0), Alu(true, Mov, 0, Imm(0)), Exit]

  lemma HookValid() ensures Validate(Cat(HOOKL), Api.HookBodySpec()) == Validated
  {
    reveal HOOKLLit(), PROLLit(), PRELLit(), LOOKUPLit(), POSTLLit();
    assert Decode(HOOKL[0]) == Some(HOOKP[0]);
    assert Decode(HOOKL[1]) == Some(HOOKP[1]);
    assert Decode(HOOKL[2]) == Some(HOOKP[2]);
    assert Decode(HOOKL[3]) == Some(HOOKP[3]);
    assert Decode(HOOKL[4]) == Some(HOOKP[4]);
    DecodeCat(HOOKL, HOOKP, 0);
    var sp := Api.HookBodySpec();
    assert CountBranches(HOOKP) == 1;
    var s0 := SInit();
    var s1 := SymStep(sp, HOOKP[0], s0).ss;
    var s3 := SymStep(sp, HOOKP[2], s1).ss;
    var s4 := SymStep(sp, HOOKP[3], s3).ss;
    var s4b := SymStep(sp, HOOKP[3], s1).ss;
    reveal SymExec();
    assert SymExec(HOOKP, sp, 4, s4, Top) == Validated;
    assert SymExec(HOOKP, sp, 3, s3, Top) == Validated;
    assert SymExec(HOOKP, sp, 2, s1, Top) == Validated;
    assert SymExec(HOOKP, sp, 4, s4b, Top) == Validated;
    assert SymExec(HOOKP, sp, 3, s1, Top) == Validated;
    assert SymExec(HOOKP, sp, 1, s1, Top) == Validated;
    assert SymExec(HOOKP, sp, 0, s0, Top) == Validated;
  }

  // ---------------- the entry prologue (P1, spill only) ----------------

  // st [r10-8], r1   (stxdw: 0x7b, dst r10, src r1, off -8)
  const PROL: seq<seq<bv8>> := PROLLit()
  opaque function PROLLit(): seq<seq<bv8>> { [[0x7b, 0x1a, 0xf8, 0xff, 0, 0, 0, 0]] }
  const PROP: seq<Instr> := [Stx(8, 10, 1, 0xfff8)]

  lemma ProValid() ensures Validate(Cat(PROL), Api.EntryPrologueSpec(0)) == Validated
  {
    reveal HOOKLLit(), PROLLit(), PRELLit(), LOOKUPLit(), POSTLLit();
    assert Decode(PROL[0]) == Some(PROP[0]);
    DecodeCat(PROL, PROP, 0);
    var sp := Api.EntryPrologueSpec(0);
    var s0 := SInit();
    reveal Signed64();
    assert FpOff(AddrTerm(s0, 10, 0xfff8)) == Some(0xffff_ffff_ffff_fff8);
    assert SymStep(sp, PROP[0], s0).SOk?;
    var s1 := SymStep(sp, PROP[0], s0).ss;
    reveal SymExec();
    assert SymExec(PROP, sp, 1, s1, Top) == Validated;
    assert SymExec(PROP, sp, 0, s0, Top) == Validated;
  }

  // ---------------- the P2 site window: B(1) . call lookup . post(1) ----------------

  // pre: st [r10-16], r2.  post (hit only): st [r10-24], r0; if r0 == 0 goto +5;
  // ld r1, [r10-8]; w2 = 1; ld r3, [r10-16]; r4 = r0; call H; ld r0, [r10-24]
  const PREL: seq<seq<bv8>> := PRELLit()
  opaque function PRELLit(): seq<seq<bv8>> { [[0x7b, 0x2a, 0xf0, 0xff, 0, 0, 0, 0]] }
  const LOOKUP: seq<bv8> := LOOKUPLit()
  opaque function LOOKUPLit(): seq<bv8> { [0x85, 0, 0, 0, 1, 0, 0, 0] }
  const POSTL: seq<seq<bv8>> := POSTLLit()
  opaque function POSTLLit(): seq<seq<bv8>> { [[0x7b, 0x0a, 0xe8, 0xff, 0, 0, 0, 0],
                                 [0x15, 0x00, 5, 0, 0, 0, 0, 0],
                                 [0x79, 0xa1, 0xf8, 0xff, 0, 0, 0, 0],
                                 [0xb4, 0x02, 0, 0, 1, 0, 0, 0],
                                 [0x79, 0xa3, 0xf0, 0xff, 0, 0, 0, 0],
                                 [0xbf, 0x04, 0, 0, 0, 0, 0, 0],
                                 [0x85, 0x10, 0, 0, 3, 0, 0, 0],
                                 [0x79, 0xa0, 0xe8, 0xff, 0, 0, 0, 0]] }
  const SITEL: seq<seq<bv8>> := PREL + [LOOKUP] + POSTL
  const SITEP: seq<Instr> := [Stx(8, 10, 2, 0xfff0), CallHelper(1), Stx(8, 10, 0, 0xffe8), Jcond(JEq, 0, 0, 5),
                              Ldx(8, 1, 10, 0xfff8), Alu(false, Mov, 2, Imm(1)), Ldx(8, 3, 10, 0xfff0),
                              Alu(true, Mov, 4, Reg(0)), CallLocal(3), Ldx(8, 0, 10, 0xffe8)]
  // the hook's value argument is the result, and it runs only on a hit
  const BINDS: seq<Bind> := [Bind(8, 4, ValueArg), Bind(8, 4, HitCall)]

  lemma {:isolate_assertions} SiteValid() ensures Validate(Cat(SITEL), Api.WithBinds(Api.SiteSpec(0), BINDS)) == Validated
  {
    reveal HOOKLLit(), PROLLit(), PRELLit(), LOOKUPLit(), POSTLLit();
    assert SITEL == [PREL[0], LOOKUP] + POSTL;
    assert Decode(PREL[0]) == Some(SITEP[0]);
    assert Decode(LOOKUP) == Some(SITEP[1]);
    assert Decode(POSTL[0]) == Some(SITEP[2]);
    assert Decode(POSTL[1]) == Some(SITEP[3]);
    assert Decode(POSTL[2]) == Some(SITEP[4]);
    assert Decode(POSTL[3]) == Some(SITEP[5]);
    assert Decode(POSTL[4]) == Some(SITEP[6]);
    assert Decode(POSTL[5]) == Some(SITEP[7]);
    assert Decode(POSTL[6]) == Some(SITEP[8]);
    assert Decode(POSTL[7]) == Some(SITEP[9]);
    assert forall k | 2 <= k < 10 :: SITEL[k] == POSTL[k - 2];
    DecodeCat(SITEL, SITEP, 0);
    var sp := Api.WithBinds(Api.SiteSpec(0), BINDS);
    assert SpecWF(sp);
    assert CountBranches(SITEP) == 1;
    reveal Signed64();
    var s0 := SInit();
    var s1 := SymStep(sp, SITEP[0], s0).ss;
    var s2 := SymStep(sp, SITEP[1], s1).ss;
    var s3 := SymStep(sp, SITEP[2], s2).ss;
    // fall-through arm: the result is non-NULL
    var a4 := Refine(s3, JEq, 0, 0, false);
    var a5 := SymStep(sp, SITEP[4], a4).ss;
    var a6 := SymStep(sp, SITEP[5], a5).ss;
    var a7 := SymStep(sp, SITEP[6], a6).ss;
    var a8 := SymStep(sp, SITEP[7], a7).ss;
    var a9 := SymStep(sp, SITEP[8], a8).ss;
    var a10 := SymStep(sp, SITEP[9], a9).ss;
    // taken arm: straight to the restore
    var b9 := Refine(s3, JEq, 0, 0, true);
    var b10 := SymStep(sp, SITEP[9], b9).ss;
    assert s2.ret == Fresh(0);
    assert s2.regs[0] == Fresh(0);
    assert s3.stack == WriteBT(s2.stack, 488, StoreBytes(Fresh(0), 8));
    assert s3.stack[488 .. 496] == StoreBytes(Fresh(0), 8);
    assert a9.stack == s3.stack;
    assert b9.stack == s3.stack;
    assert a10.regs[0] == Fresh(0);
    assert b10.regs[0] == Fresh(0);
    reveal SymExec();
    assert SymExec(SITEP, sp, 10, a10, Top) == Validated;
    assert SymExec(SITEP, sp, 9, a9, Top) == Validated;
    assert BindFail(sp, 8, a8) == "";
    assert SymExec(SITEP, sp, 8, a8, Top) == Validated;
    assert SymExec(SITEP, sp, 7, a7, Top) == Validated;
    assert SymExec(SITEP, sp, 6, a6, Top) == Validated;
    assert SymExec(SITEP, sp, 5, a5, Top) == Validated;
    assert SymExec(SITEP, sp, 4, a4, Top) == Validated;
    assert SymExec(SITEP, sp, 10, b10, Top) == Validated;
    assert SymExec(SITEP, sp, 9, b9, Top) == Validated;
    assert SymExec(SITEP, sp, 3, s3, Top) == Validated;
    assert SymExec(SITEP, sp, 2, s2, Top) == Validated;
    assert SymExec(SITEP, sp, 1, s1, Top) == Validated;
    assert SymExec(SITEP, sp, 0, s0, Top) == Validated;
  }

  lemma Shapes()
    ensures |HOOKL| == 5 && |PROL| == 1 && |PREL| == 1 && |POSTL| == 8 && |LOOKUP| == 8
    ensures All8(HOOKL) && All8(PROL) && All8(PREL) && All8(POSTL)
  { reveal HOOKLLit(), PROLLit(), PRELLit(), LOOKUPLit(), POSTLLit(); }

  // ================= the instance =================

  // r2 = <alu 0>(r10); r0 = map_lookup_elem(r1, r2); r0 = <alu 0>(); exit
  const PW: seq<M.OInstr> := [M.Alu(0, 2, [10]), M.Hcall(false, 1), M.Alu(0, 0, []), M.Exit]
  opaque function DW(): R.Decomp {
    R.Decomp(Cat(PROL), map[], map[], map[1 := R.Site(Cat(PREL), Cat(POSTL), BINDS)], map[], map[],
             [R.HookFn(Cat(HOOKL))])
  }
  function EllW(g: nat): int { 0 }
  function LiveW(j: nat): set<nat> { {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10} }
  function TblW(id: bv32): set<nat> { {1, 2, 3, 4, 5} }
  function EnvW(): M.Env { M.Env((kf: bool, id: bv32) => 2, (kf: bool, id: bv32, a: seq<bv64>) => []) }
  function SemW(): M.Sem {
    M.Sem((c: nat, vs: seq<bv64>) => 0, (c: nat, vs: seq<bv64>) => false,
          (op: nat, w: nat, o: bv64, n: bv64, x: Option<bv64>) => 0,
          (l: M.Local, r6: bv64, ix: Option<bv64>, off: int, w: nat) => None)
  }
  const R0: M.Resp := M.RRet(M.W(0), map[])
  function OmW(h: seq<M.Ev>, e: M.Ev, w: M.Where): M.Resp { R0 }
  function ObsvW(c: M.Cfg, a: seq<bv64>): M.Cfg { c }
  const L0: M.Local := M.Local(map[], 0)
  ghost predicate AdmW(l: M.Local, om: M.Oracle) { l == L0 && forall h, e, w :: om(h, e, w) == R0 }

  // ---------------- the run of P ----------------

  ghost function Regs0(): seq<M.Val> { M.InitP(L0).fr[0].regs }
  ghost function Regs2(): seq<M.Val> {
    seq(M.NR, k requires 0 <= k < M.NR => if k == 0 then M.W(0) else if k <= 5 then M.Bot else Regs0()[k])
  }
  ghost function Fr(pc: int, regs: seq<M.Val>): M.Frame { M.Frame(0, pc, regs, M.Main, M.InitP(L0).fr[0].stack) }
  const EV: M.Ev := M.ECall(1, false, 1, [M.CTX, 0], [])
  ghost function C(k: nat): M.Cfg {
    if k == 0 then M.InitP(L0)
    else if k == 1 then M.Cfg([Fr(1, Regs0()[2 := M.W(0)])], L0, [], 0, [])
    else if k == 2 then M.Cfg([Fr(2, Regs2())], L0, [EV], 6, [])
    else M.Cfg([Fr(3, Regs2())], L0, [EV], 6, [])
  }

  lemma Step0(om: M.Oracle)
    ensures M.StepP(PW, M.CtxP(PW, EnvW(), SemW(), om), C(0)) == M.Go(C(1))
  {
    assert Regs0()[10] == M.W(M.StackTop(0));
    F.RdsAll(M.Top(C(0)), [10]);
    assert F.Words(M.Top(C(0)), [10]) == [M.StackTop(0)];
    assert M.Rds(M.Top(C(0)), [10]) == Some([M.StackTop(0)]);
    reveal M.AluO();
  }

  lemma ApplyNone(c: M.Cfg) requires forall k | 0 <= k < |c.fr| :: |c.fr[k].stack| == M.STK
    ensures M.ApplyW(c, map[]) == c
  {
    reveal M.ApplyW();
    var c' := M.ApplyW(c, map[]);
    forall d | 0 <= d < |c.fr| ensures c'.fr[d] == c.fr[d] {
      assert c'.fr[d].stack == c.fr[d].stack;
    }
    assert c'.fr == c.fr;
    assert c'.L.mem.Keys == c.L.mem.Keys;
    assert c'.L.mem == c.L.mem;
    assert c'.L == c.L;
  }

  lemma {:isolate_assertions} Step1(om: M.Oracle)
    requires forall h, e, w :: om(h, e, w) == R0
    ensures M.StepP(PW, M.CtxP(PW, EnvW(), SemW(), om), C(1)) == M.Go(C(2))
  {
    var x := M.CtxP(PW, EnvW(), SemW(), om);
    var c1 := C(1);
    assert M.Upto(1, 2) == [1, 2];
    assert Regs0()[1] == M.W(M.CTX);
    assert M.Reg(M.Top(c1), 2) == M.W(0) && M.Reg(M.Top(c1), 1) == M.W(M.CTX);
    F.RdsAll(M.Top(c1), [1, 2]);
    assert F.Words(M.Top(c1), [1, 2]) == [M.CTX, 0];
    assert M.Rds(M.Top(c1), [1, 2]) == Some([M.CTX, 0]);
    assert M.FootBytes(c1, []) == M.FOk([]) by { reveal M.FootBytes(); }
    var c1h := c1.(h := [EV]);
    ApplyNone(c1h);
    var f := M.Top(c1h);
    var regs := seq(|f.regs|, k requires 0 <= k < |f.regs| =>
      if k == 0 then M.W(0) else if k <= 5 then M.Und(x, c1h, k) else f.regs[k]);
    assert regs == Regs2();
    assert M.Finish(x, c1h, M.W(0), map[]) == M.Go(C(2)) by { reveal M.Finish(); }
    assert x.env.arity(false, 1) == 2;
    assert x.env.foot(false, 1, [M.CTX, 0]) == [];
    assert c1.(h := c1.h + [EV]) == c1h;
    assert om(c1.h, EV, M.Wh(c1)) == R0;
    assert M.HelperStep(x, c1, 1, false, 1, false) == M.Go(C(2)) by { reveal M.HelperStep(); }
  }

  lemma Step23(om: M.Oracle)
    ensures M.StepP(PW, M.CtxP(PW, EnvW(), SemW(), om), C(2)) == M.Go(C(3))
    ensures M.StepP(PW, M.CtxP(PW, EnvW(), SemW(), om), C(3)) == M.Done(M.TRet(0, L0, [EV]))
  {
    assert Regs2()[0 := M.W(0)] == Regs2();
    assert Regs2()[0] == M.W(0);
    reveal M.AluO(), M.ExitO(), M.ExitFrame();
  }

  // ---------------- P' = Layout(P, D) ----------------

  lemma NsCat(l: seq<seq<bv8>>) requires All8(l)
    ensures R.Ns(Cat(l)) == seq(|l|, k requires 0 <= k < |l| => M.N(l[k]))
  {
    CatLen(l);
    forall k | 0 <= k < |l| ensures R.Slice(Cat(l), k) == l[k] { CatAt(l, k); }
  }

  lemma LensW()
    ensures R.NI(Cat(PROL)) == 1 && R.NI(Cat(PREL)) == 1 && R.NI(Cat(POSTL)) == 8 && R.NI(Cat(HOOKL)) == 5
    ensures R.Start(DW(), 0) == 1 && R.Start(DW(), 1) == 2 && R.Start(DW(), 2) == 12
    ensures R.Start(DW(), 3) == 13 && R.Start(DW(), 4) == 14
    ensures R.E(DW(), 0) == 1 && R.FE(DW(), 0) == 1 && R.E(DW(), 1) == 2 && R.K(DW(), 1) == 3
  {
    reveal DW();
    Shapes();
    CatLen(PROL); CatLen(PREL); CatLen(POSTL); CatLen(HOOKL);
    var D := DW();
    assert R.FnsAt(D, 0) == [] && R.FnsAt(D, 1) == [] && R.FnsAt(D, 2) == [] && R.FnsAt(D, 3) == [];
    assert R.FnsLen(D, []) == 0;
    assert R.BlockLen(D, 0) == 1 && R.BlockLen(D, 1) == 10 && R.BlockLen(D, 2) == 1 && R.BlockLen(D, 3) == 1;
  }

  lemma {:isolate_assertions} AllFnsW() ensures R.AllFns(PW, DW()) == [(R.HookFn(Cat(HOOKL)), 14)]
  {
    reveal DW();
    Shapes();
    LensW();
    var D := DW();
    assert R.FnStarts(D, [], 0) == [];
    assert R.AllFnsFrom(D, 4, 4) == R.FnStarts(D, D.tail, 14);
    assert R.FnStarts(D, D.tail, 14) == [(R.HookFn(Cat(HOOKL)), 14)];
    assert R.AllFnsFrom(D, 4, 3) == R.AllFnsFrom(D, 4, 4);
    assert R.AllFnsFrom(D, 4, 2) == R.AllFnsFrom(D, 4, 3);
    assert R.AllFnsFrom(D, 4, 1) == R.AllFnsFrom(D, 4, 2);
    assert R.AllFnsFrom(D, 4, 0) == R.AllFnsFrom(D, 4, 1);
  }

  lemma FnSetW() ensures M.FnSet(PW) == {0} {}

  lemma WFW1() ensures LF.AllFnsWF(PW, DW())
  {
    reveal DW();
    var D := DW();
    assert D.tail == [R.HookFn(Cat(HOOKL))];
    assert LF.FnsWF(PW, D, D.tail);
  }

  lemma WFW2() ensures R.FnsLen(DW(), DW().tail) == 5
  {
    reveal DW();
    Shapes(); CatLen(HOOKL);
    var D := DW();
    assert D.tail == [R.HookFn(Cat(HOOKL))];
    assert R.FnsLen(D, []) == 0;
    assert R.FnsLen(D, D.tail) == R.FnLen(D, D.tail[0]) + R.FnsLen(D, D.tail[1..]);
    assert D.tail[1..] == [];
  }

  lemma WFW() ensures LF.AllFnsWF(PW, DW()) && R.FnsLen(DW(), DW().tail) == 5 { WFW1(); WFW2(); }

  lemma LenW() ensures |R.Layout(PW, DW()).code| == 19 { WFW(); LensW(); LF.CodeLen(PW, DW()); }

  lemma {:isolate_assertions} CodeW0()
    ensures |R.Layout(PW, DW()).code| == 19 && |PROL| == 1 && All8(PROL) && R.Layout(PW, DW()).code[0] == M.N(PROL[0])
  {
    reveal DW();
    Shapes(); WFW(); LensW(); NsCat(PROL); LenW();
    LF.CodePro(PW, DW(), 0);
    CatAt(PROL, 0);
  }

  lemma {:isolate_assertions} CodeWK(j: nat)
    requires j < 4
    ensures R.K(DW(), j) < |R.Layout(PW, DW()).code| && R.Layout(PW, DW()).code[R.K(DW(), j)] == M.O(PW[j], j)
  {
    reveal DW();
    WFW1();
    var D := DW();
    assert j !in D.pl && j !in D.wrap;
    if j == 0 {
      LF.PlainCode(PW, D, 0);
      assert R.Reloc(D, PW[0]) == PW[0];
    } else if j == 1 {
      LF.SiteCode(PW, D, 1);
      assert R.Reloc(D, PW[1]) == PW[1];
    } else if j == 2 {
      LF.PlainCode(PW, D, 2);
      assert R.Reloc(D, PW[2]) == PW[2];
    } else {
      LF.PlainCode(PW, D, 3);
      assert R.Reloc(D, PW[3]) == PW[3];
    }
  }

  lemma {:isolate_assertions} CodeWSite()
    ensures |PREL| == 1 && |POSTL| == 8
    ensures R.E(DW(), 1) < |R.Layout(PW, DW()).code| && R.Layout(PW, DW()).code[R.E(DW(), 1)] == M.N(PREL[0])
    ensures forall k | 0 <= k < 8 :: R.K(DW(), 1) + 1 + k < |R.Layout(PW, DW()).code|
                                     && R.Layout(PW, DW()).code[R.K(DW(), 1) + 1 + k] == M.N(POSTL[k])
  {
    reveal DW();
    Shapes(); WFW1();
    var D := DW();
    CatLen(PREL); CatLen(POSTL);
    assert 1 !in D.pl && 1 !in D.wrap && 1 in D.site;
    LF.SiteCode(PW, D, 1);
    CatAt(PREL, 0);
    assert R.Layout(PW, D).code[R.E(D, 1) + 0] == M.N(R.Slice(Cat(PREL), 0));
    forall k | 0 <= k < 8 ensures R.Slice(Cat(POSTL), k) == POSTL[k] { CatAt(POSTL, k); }
  }

  lemma {:isolate_assertions} CodeWHook(k: nat)
    requires k < 5
    ensures |HOOKL| == 5
    ensures R.Start(DW(), 4) + k < |R.Layout(PW, DW()).code| && R.Layout(PW, DW()).code[R.Start(DW(), 4) + k] == M.N(HOOKL[k])
  {
    reveal DW();
    Shapes(); WFW1(); WFW2();
    var D := DW();
    LF.CodeTail(PW, D, k);
    assert R.FnsCode(PW, D, []) == [];
    assert R.FnsCode(PW, D, D.tail) == R.Ns(Cat(HOOKL)) + R.FnsCode(PW, D, []);
    CatLen(HOOKL);
    CatAt(HOOKL, k);
  }

  lemma {:isolate_assertions} EKW(j: nat)
    requires j < 4
    ensures R.E(DW(), j) == R.Start(DW(), j) && R.K(DW(), j) == R.Start(DW(), j) + (if j == 1 then 1 else 0)
  {
    reveal DW();
    var D := DW();
    assert R.FnsAt(D, j) == [] && R.FnsLen(D, []) == 0;
    assert j !in D.fp && j !in D.pl && j !in D.wrap;
    if j == 1 { Shapes(); CatLen(PREL); } else { assert j !in D.site; }
  }

  lemma StartW()
    ensures R.Start(DW(), 0) == 1 && R.Start(DW(), 1) == 2 && R.Start(DW(), 2) == 12
    ensures R.Start(DW(), 3) == 13 && R.Start(DW(), 4) == 14
  { LensW(); }

  lemma PosW()
    ensures R.K(DW(), 0) == 1 && R.E(DW(), 1) == 2 && R.K(DW(), 1) == 3
    ensures R.K(DW(), 2) == 12 && R.K(DW(), 3) == 13 && R.Start(DW(), 4) == 14
  {
    StartW(); EKW(0); EKW(1); EKW(2); EKW(3);
  }

  lemma CodeHooks()
    ensures |HOOKL| == 5 && |R.Layout(PW, DW()).code| == 19
    ensures forall k | 0 <= k < 5 :: R.Layout(PW, DW()).code[14 + k] == M.N(HOOKL[k])
  {
    StartW(); LenW(); CodeWHook(0);
    forall k | 0 <= k < 5 ensures R.Layout(PW, DW()).code[14 + k] == M.N(HOOKL[k]) { CodeWHook(k); }
  }

  // What P' holds at each position.
  lemma {:isolate_assertions} CodeTable()
    ensures |R.Layout(PW, DW()).code| == 19 && |PROL| == 1 && |PREL| == 1 && |POSTL| == 8 && |HOOKL| == 5
    ensures var code := R.Layout(PW, DW()).code;
      code[0] == M.N(PROL[0]) && code[1] == M.O(PW[0], 0) && code[2] == M.N(PREL[0]) && code[3] == M.O(PW[1], 1)
      && (forall k | 0 <= k < 8 :: code[4 + k] == M.N(POSTL[k]))
      && code[12] == M.O(PW[2], 2) && code[13] == M.O(PW[3], 3)
      && (forall k | 0 <= k < 5 :: code[14 + k] == M.N(HOOKL[k]))
  {
    PosW(); LenW(); CodeW0();
    CodeWK(0); CodeWK(1); CodeWK(2); CodeWK(3);
    CodeWSite();
    CodeHooks();
  }

  lemma {:isolate_assertions} HooksW() ensures R.Layout(PW, DW()).hooks == {14} && R.Layout(PW, DW()).fns == {0}
  {
    reveal DW();
    LF.LayoutIs(PW, DW()); AllFnsW(); FnSetW();
    var A := R.AllFns(PW, DW());
    assert |A| == 1 && A[0].0.HookFn? && A[0].1 == 14;
    assert 14 in R.Hooks(PW, DW());
    forall t | t in R.Hooks(PW, DW()) ensures t == 14 {
      var k :| 0 <= k < |A| && A[k].0.HookFn? && A[k].1 == t;
    }
    assert R.Hooks(PW, DW()) == {14};
  }

  // ---------------- the premises ----------------

  lemma CatApp(a: seq<seq<bv8>>, b: seq<seq<bv8>>) ensures Cat(a + b) == Cat(a) + Cat(b) decreases |a| {
    if |a| > 0 {
      assert (a + b)[1..] == a[1..] + b;
      CatApp(a[1..], b);
      assert Cat(a + b) == (a + b)[0] + Cat((a + b)[1..]) by { reveal Cat(); }
      assert Cat(a) == a[0] + Cat(a[1..]) by { reveal Cat(); }
    } else {
      assert a + b == b;
      assert Cat(a) == [] by { reveal Cat(); }
    }
  }

  lemma NoHelperCat(l: seq<seq<bv8>>)
    requires All8(l) && forall k | 0 <= k < |l| :: !(Decode(l[k]).Some? && Decode(l[k]).value.CallHelper?)
    ensures Pr.NoHelperIn(Cat(l)) && Pr.Bytes8(Cat(l))
  {
    CatLen(l);
    forall k | 0 <= k < R.NI(Cat(l)) ensures R.Slice(Cat(l), k) == l[k] { CatAt(l, k); }
  }

  lemma {:isolate_assertions} DecodesW()
    ensures |HOOKL| == 5 && |PROL| == 1 && |PREL| == 1 && |POSTL| == 8
    ensures All8(HOOKL) && All8(PROL) && All8(PREL) && All8(POSTL)
    ensures Decode(PROL[0]) == Some(PROP[0]) && Decode(PREL[0]) == Some(SITEP[0])
    ensures forall k | 0 <= k < 8 :: Decode(POSTL[k]) == Some(SITEP[k + 2])
    ensures forall k | 0 <= k < 5 :: Decode(HOOKL[k]) == Some(HOOKP[k])
  {
    reveal HOOKLLit(), PROLLit(), PRELLit(), LOOKUPLit(), POSTLLit();
    assert Decode(POSTL[0]) == Some(SITEP[2]);
    assert Decode(POSTL[1]) == Some(SITEP[3]);
    assert Decode(POSTL[2]) == Some(SITEP[4]);
    assert Decode(POSTL[3]) == Some(SITEP[5]);
    assert Decode(POSTL[4]) == Some(SITEP[6]);
    assert Decode(POSTL[5]) == Some(SITEP[7]);
    assert Decode(POSTL[6]) == Some(SITEP[8]);
    assert Decode(POSTL[7]) == Some(SITEP[9]);
    assert Decode(HOOKL[0]) == Some(HOOKP[0]);
    assert Decode(HOOKL[1]) == Some(HOOKP[1]);
    assert Decode(HOOKL[2]) == Some(HOOKP[2]);
    assert Decode(HOOKL[3]) == Some(HOOKP[3]);
    assert Decode(HOOKL[4]) == Some(HOOKP[4]);
  }

  lemma {:isolate_assertions} PiecesW() ensures Pr.PiecesOk(PW, DW())
  {
    reveal DW();
    Shapes();
    DecodesW(); AllFnsW(); FnSetW();
    NoHelperCat(PROL); NoHelperCat(PREL); NoHelperCat(POSTL); NoHelperCat(HOOKL);
  }

  lemma {:isolate_assertions} CallsW() ensures Pr.CallsOk(DW(), R.Layout(PW, DW()))
  {
    DecodesW(); HooksW(); CodeTable();
    var Pp := R.Layout(PW, DW());
    forall p | 0 <= p < |Pp.code| && Pp.code[p].N?
      ensures var b := Pp.code[p].b;
        (|b| == 8 && Decode(b).Some? && Decode(b).value.CallLocal? && !(exists i :: i in DW().wrap && p == R.K(DW(), i)))
        ==> p + 1 + Signed32(Decode(b).value.imm) in Pp.hooks
    {
      if p == 0 { }
      else if p == 2 { }
      else if 4 <= p < 12 {
        assert Pp.code[p] == M.N(POSTL[p - 4]);
        if p == 10 { assert Decode(POSTL[6]) == Some(CallLocal(3)); assert Signed32(3) == 3; }
        else { assert Decode(POSTL[p - 4]) == Some(SITEP[p - 2]); }
      } else if 14 <= p {
        assert Pp.code[p] == M.N(HOOKL[p - 14]);
        assert Decode(HOOKL[p - 14]) == Some(HOOKP[p - 14]);
      } else {
        assert p == 1 || p == 3 || p == 12 || p == 13;
      }
    }
  }

  lemma {:isolate_assertions} A1aEtc(om: M.Oracle)
    requires forall h, e, w :: om(h, e, w) == R0
    ensures M.RunP(PW, M.CtxP(PW, EnvW(), SemW(), om), M.InitP(L0), 4) == M.Fin(M.TRet(0, L0, [EV]))
    ensures forall n: nat :: M.RunP(PW, M.CtxP(PW, EnvW(), SemW(), om), M.InitP(L0), n) != M.Stk(true)
    ensures forall n: nat :: var x := M.CtxP(PW, EnvW(), SemW(), om);
      match M.ReachP(PW, x, M.InitP(L0), n) case None => true case Some(c) => Pr.Acc(PW, x, c) == {}
  {
    var x := M.CtxP(PW, EnvW(), SemW(), om);
    Step0(om); Step1(om); Step23(om);
    assert M.InitP(L0) == C(0);
    forall n: nat ensures M.RunP(PW, x, M.InitP(L0), n) != M.Stk(true) {
      if n >= 1 { assert M.RunP(PW, x, C(0), n) == M.RunP(PW, x, C(1), n - 1); }
      if n >= 2 { assert M.RunP(PW, x, C(1), n - 1) == M.RunP(PW, x, C(2), n - 2); }
      if n >= 3 { assert M.RunP(PW, x, C(2), n - 2) == M.RunP(PW, x, C(3), n - 3); }
      if n >= 4 { assert M.RunP(PW, x, C(3), n - 3) == M.Fin(M.TRet(0, L0, [EV])); }
    }
    assert M.FootBytes(C(1), []) == M.FOk([]) by { reveal M.FootBytes(); }
    assert M.Upto(1, 2) == [1, 2];
    F.RdsAll(M.Top(C(1)), [1, 2]);
    assert F.Words(M.Top(C(1)), [1, 2]) == [M.CTX, 0];
    assert M.Rds(M.Top(C(1)), [1, 2]) == Some([M.CTX, 0]);
    assert Pr.WrAcc(C(1), map[]) == {};
    assert Pr.Acc(PW, x, C(1)) == {};
    assert Pr.Acc(PW, x, C(0)) == {} && Pr.Acc(PW, x, C(2)) == {};
    assert Pr.Acc(PW, x, C(3)) == {};
    forall n: nat ensures match M.ReachP(PW, x, M.InitP(L0), n) case None => true case Some(c) => Pr.Acc(PW, x, c) == {} {
      if n >= 1 { assert M.ReachP(PW, x, C(0), n) == M.ReachP(PW, x, C(1), n - 1); }
      if n >= 2 { assert M.ReachP(PW, x, C(1), n - 1) == M.ReachP(PW, x, C(2), n - 2); }
      if n >= 3 { assert M.ReachP(PW, x, C(2), n - 2) == M.ReachP(PW, x, C(3), n - 3); }
      if n >= 4 { assert M.ReachP(PW, x, C(3), n - 3) == None; }
    }
  }

  lemma FlW(i: nat) ensures R.Fl(PW, EllW, i) == 0 {}

  lemma EncW() ensures R.Enc(PW[1]) == LOOKUP { reveal LOOKUPLit(); }

  lemma ValidPro() ensures R.Valid(DW().pro0, Api.EntryPrologueSpec(R.Fl(PW, EllW, 0)))
  {
    reveal DW();
    FlW(0);
    ProValid();
    reveal R.Valid();
  }

  lemma {:isolate_assertions} SiteRawW() ensures 1 in DW().site && DW().site[1].pre + R.Enc(PW[1]) + DW().site[1].post == Cat(SITEL)
  {
    reveal DW();
    EncW();
    CatApp(PREL, [LOOKUP]); CatApp(PREL + [LOOKUP], POSTL);
    assert Cat([LOOKUP]) == LOOKUP by { reveal Cat(); }
  }

  lemma ValidSite()
    ensures 1 in DW().site
    ensures R.Valid(DW().site[1].pre + R.Enc(PW[1]) + DW().site[1].post,
                    R.SiteSpecFor(PW[1], R.Fl(PW, EllW, 1), DW().site[1].binds))
  {
    reveal DW();
    FlW(1);
    SiteRawW();
    assert R.SiteSpecFor(PW[1], 0, BINDS) == Api.WithBinds(Api.SiteSpec(0), BINDS);
    SiteValid();
    reveal R.Valid();
  }

  lemma ValidHook()
    ensures forall k | 0 <= k < |R.AllFns(PW, DW())| && R.AllFns(PW, DW())[k].0.HookFn? ::
      R.Valid(R.AllFns(PW, DW())[k].0.body, Api.HookBodySpec())
  {
    reveal DW();
    AllFnsW();
    HookValid();
    reveal R.Valid();
  }

  lemma {:isolate_assertions} ValidW() ensures R.AllValidated(PW, DW(), EllW)
  {
    reveal DW();
    ValidPro(); ValidSite(); ValidHook();
    var D := DW();
    assert D.fp == map[] && D.pl == map[] && D.wrap == map[] && D.site.Keys == {1};
  }

  lemma {:isolate_assertions} RunsW()
    ensures Pr.E0(PW, EnvW(), SemW(), AdmW) && Pr.A1b(PW, EnvW(), SemW(), AdmW) && Pr.A1a(PW, EnvW(), SemW(), AdmW, EllW)
  {
    forall l, om | AdmW(l, om)
      ensures exists n: nat :: var r := M.RunP(PW, M.CtxP(PW, EnvW(), SemW(), om), M.InitP(l), n); r.Fin? || r == M.Stk(true)
    { A1aEtc(om); }
    forall l, om, n: nat | AdmW(l, om) ensures M.RunP(PW, M.CtxP(PW, EnvW(), SemW(), om), M.InitP(l), n) != M.Stk(true)
    { A1aEtc(om); }
    forall l, om, n: nat | AdmW(l, om)
      ensures var x := M.CtxP(PW, EnvW(), SemW(), om);
        match M.ReachP(PW, x, M.InitP(l), n)
        case None => true
        case Some(c) => forall a | a in Pr.Acc(PW, x, c) :: a.0 < |c.fr| && a.1 as int - M.STK as int >= EllW(c.fr[a.0].fn)
    { A1aEtc(om); }
  }

  lemma {:isolate_assertions} StructW() ensures Pr.Structure(PW, DW(), R.Layout(PW, DW()), EllW, LiveW, TblW)
  {
    reveal DW();
    PiecesW(); CallsW(); FnSetW();
    assert Pr.LiveOk(PW, LiveW, TblW);
    assert Pr.FloorsOk(PW, EllW);
    assert Pr.S10(PW, DW(), LiveW, TblW);
  }

  lemma {:isolate_assertions} ShapeW() ensures Pr.E0Shape(PW) && Pr.S0(PW)
  {
    FnSetW();
    assert forall j | 0 <= j < |PW| :: Pr.RegsOk(PW[j]);
  }

  // Non-vacuity: every hypothesis of SegmentPreservation holds for this instance.
  lemma {:isolate_assertions} Witness()
    ensures T.Hyp(PW, DW(), R.Layout(PW, DW()), EllW, LiveW, TblW, EnvW(), SemW(), ObsvW, AdmW)
    ensures Pr.A8(OmW) && AdmW(L0, OmW)
  {
    ValidW(); RunsW(); StructW(); ShapeW();
    assert Pr.A3b(EnvW(), TblW);
    assert Pr.A5(ObsvW);
    assert Pr.S0(PW) && Pr.E0Shape(PW);
    assert Pr.Structure(PW, DW(), R.Layout(PW, DW()), EllW, LiveW, TblW);
    assert R.AllValidated(PW, DW(), EllW);
    assert Pr.E0(PW, EnvW(), SemW(), AdmW) && Pr.A1b(PW, EnvW(), SemW(), AdmW);
    assert Pr.A1a(PW, EnvW(), SemW(), AdmW, EllW);
    HypI(PW, DW(), R.Layout(PW, DW()), EllW, LiveW, TblW, EnvW(), SemW(), ObsvW, AdmW);
    assert Pr.A8(OmW);
    assert AdmW(L0, OmW);
  }

  lemma HypI(P: seq<M.OInstr>, D: R.Decomp, Pp: M.RwProg, ell: nat -> int, live: nat -> set<nat>,
             tbl: bv32 -> set<nat>, env: M.Env, sem: M.Sem, obsv: M.Observer, Adm: (M.Local, M.Oracle) -> bool)
    requires Pr.S0(P) && Pr.Structure(P, D, Pp, ell, live, tbl) && R.AllValidated(P, D, ell)
    requires Pr.E0Shape(P) && Pr.E0(P, env, sem, Adm) && Pr.A1a(P, env, sem, Adm, ell) && Pr.A1b(P, env, sem, Adm)
    requires Pr.A3b(env, tbl) && Pr.A5(obsv)
    ensures T.Hyp(P, D, Pp, ell, live, tbl, env, sem, obsv, Adm)
  {}

}
