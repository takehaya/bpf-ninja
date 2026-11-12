// The hypotheses of the theorem: one named predicate per premise or
// structural condition that the model can express.  Premises about the
// kernel that are not statements about runs of the model (A2', A3a, A4, A6,
// B) are the semantics of Model.dfy itself.
include "Rewrite.dfy"

module SimPremises {
  import opened Bits
  import S = Semantics
  import opened Obligations
  import opened SimModel
  import opened SimRewrite

  // ================= external premises on P and the kernel =================

  // E0, shape part: P is a program the verifier accepts, as far as the
  // proof uses it: register numbers are in range and r10 is never written,
  // branches stay inside their function, calls and function references go
  // to instructions of P, and no instruction falls through into another
  // function or off the end.
  ghost predicate RegsOk(ins: OInstr) {
    match ins
    case Alu(_, dst, srcs) => dst <= 9 && forall r <- srcs :: r <= 10
    case FRef(dst, _) => dst <= 9
    case Ld(dst, base, _, _, _) => dst <= 9 && base <= 10
    case St(base, _, _, src) => base <= 10 && (src.SR? ==> src.r <= 10)
    case Atom(_, base, _, _, rs, _, _) => base <= 10 && rs <= 9
    case Legacy(_, ix, _) => ix.Some? ==> ix.value <= 10
    case Jcc(_, srcs, _) => forall r <- srcs :: r <= 10
    case _ => true
  }

  ghost predicate E0Shape(P: seq<OInstr>) {
    0 < |P| < 0x1_0000_0000
    && (forall j | 0 <= j < |P| :: RegsOk(P[j]))
    && (forall j | 0 <= j < |P| && (P[j].Jcc? || P[j].Ja? || P[j].MayGoto?) ::
          P[j].t < |P| && Owner(P, P[j].t) == Owner(P, j))
    && (forall j | 0 <= j < |P| && P[j].Call? :: P[j].t < |P|)
    && (forall j | 0 <= j < |P| && P[j].FRef? :: P[j].g < |P|)
    && (forall j | 0 <= j < |P| && (j + 1 == |P| || j + 1 in FnSet(P)) :: P[j].Exit? || P[j].Ja?)
  }

  // E0, run part: every admissible run of P ends (not stuck other than on
  // an unreadable stack byte, which A1b excludes).  Adm is the admissible
  // inputs and oracles; the theorem holds for any set on which E0, A1a and
  // A1b hold.
  ghost predicate E0(P: seq<OInstr>, env: Env, sem: Sem, Adm: (Local, Oracle) -> bool) {
    forall L, om :: Adm(L, om) ==>
      exists n: nat :: var r := RunP(P, CtxP(P, env, sem, om), InitP(L), n); r.Fin? || r == Stk(true)
  }

  // A1b: P reads no unreadable stack byte.
  ghost predicate A1b(P: seq<OInstr>, env: Env, sem: Sem, Adm: (Local, Oracle) -> bool) {
    forall L, om, n: nat :: Adm(L, om) ==> RunP(P, CtxP(P, env, sem, om), InitP(L), n) != Stk(true)
  }

  // ---- the stack bytes a step of P touches (for A1a) ----

  ghost function MemAcc(c: Cfg, p: bv64, w: nat): set<(nat, nat)> {
    match Classify(p, w, |c.fr|, c.L.mem.Keys)
    case InStack(d, o) => set k | o <= k < o + w :: (d, k)
    case _ => {}
  }
  ghost function FootAcc(c: Cfg, addrs: seq<bv64>): set<(nat, nat)> decreases |addrs| {
    if |addrs| == 0 then {} else MemAcc(c, addrs[0], 1) + FootAcc(c, addrs[1..])
  }
  ghost function WrAcc(c: Cfg, wr: map<int, bv8>): set<(nat, nat)> {
    set d: nat, o: nat | d < |c.fr| && d < MAXF_RW && o < STK && SAddr(d, o) as int in wr :: (d, o)
  }
  ghost function RespAcc(c: Cfg, r: Resp): set<(nat, nat)> { if r.RRet? then WrAcc(c, r.wr) else {} }

  ghost function HelperAcc(x: Ctx, c: Cfg, idx: nat, kf: bool, id: bv32): set<(nat, nat)> {
    var n := x.env.arity(kf, id);
    match Rds(Top(c), Upto(1, n))
    case None => {}
    case Some(args) =>
      var addrs := x.env.foot(kf, id, args);
      FootAcc(c, addrs)
      + (match FootBytes(c, addrs)
         case FOk(beta) => RespAcc(c, x.om(c.h, ECall(idx, kf, id, args, beta), Wh(c)))
         case _ => {})
  }
  // The exit of a callback frame finishes its helper with the response's write set.
  ghost function ExitAcc(x: Ctx, c: Cfg, v: bv64): set<(nat, nat)> {
    if Top(c).kind.Cb? then RespAcc(Pop(c), x.om(c.h, ECbRet(Top(c).kind.idx, v), Wh(Pop(c)))) else {}
  }

  // (depth, byte index 0..511) of every stack byte the next step of P reads or writes.
  ghost function Acc(P: seq<OInstr>, x: Ctx, c: Cfg): set<(nat, nat)> {
    var f := Top(c);
    if |c.fr| == 0 || f.pc < 0 || f.pc >= |P| then {}
    else match P[f.pc]
      case Ld(_, base, off, w, _) => if Reg(f, base).W? then MemAcc(c, AddrK(Reg(f, base).w, off), w) else {}
      case St(base, off, w, _) => if Reg(f, base).W? then MemAcc(c, AddrK(Reg(f, base).w, off), w) else {}
      case Atom(_, base, off, w, _, _, _) => if Reg(f, base).W? then MemAcc(c, AddrK(Reg(f, base).w, off), w) else {}
      case Hcall(kf, id) => HelperAcc(x, c, f.pc, kf, id)
      case CbCall(id) => HelperAcc(x, c, f.pc, false, id)
      case Exit => if Reg(f, 0).W? then ExitAcc(x, c, Reg(f, 0).w) else {}
      case Legacy(w, ix, off) =>
        if Reg(f, 6).W? && (ix.None? || Reg(f, ix.value).W?)
           && x.sem.legacy(c.L, Reg(f, 6).w, if ix.Some? then Bits.Some(Reg(f, ix.value).w) else Bits.None, off, w).None?
        then ExitAcc(x, c, 0) else {}
      case _ => {}
  }

  // A1a: every stack access of an admissible run of P (by an instruction,
  // through a pointer, or by a helper through its footprint or write set)
  // lies in [l_F, 0) of the frame it touches, F that frame's function.
  ghost predicate A1a(P: seq<OInstr>, env: Env, sem: Sem, Adm: (Local, Oracle) -> bool, ell: nat -> int) {
    forall L, om, n: nat :: Adm(L, om) ==>
      var x := CtxP(P, env, sem, om);
      match ReachP(P, x, InitP(L), n)
      case None => true
      case Some(c) => forall a | a in Acc(P, x, c) :: a.0 < |c.fr| && a.1 as int - STK as int >= ell(c.fr[a.0].fn)
  }

  // A3b: a helper reads r1..r_n with r1..r_n within the checker's table
  // (helpers.go:6-26, a set of argument registers); a kfunc reads at most
  // r1-r5; the lookups (ids 1, 195) do not read r4; tail_call's table entry
  // has r1-r3.  That no helper reads r0 is the model (args start at r1).
  ghost predicate A3b(env: Env, tbl: bv32 -> set<nat>) {
    (forall id :: tbl(id) <= {1, 2, 3, 4, 5})
    && (forall id, r: nat :: 1 <= r <= env.arity(false, id) ==> r in tbl(id))
    && (forall id :: env.arity(true, id) <= 5)
    && env.arity(false, 1) <= 2 && env.arity(false, 195) <= 3
    && {1, 2, 3} <= tbl(12)
  }

  // A5: an observer changes nothing but its own state.  (It terminates:
  // it is a total function.)
  ghost predicate A5(obsv: Observer) {
    forall c: Cfg, a: seq<bv64> :: obsv(c, a).(os := c.os) == c
  }

  // A8: the response to a lookup does not depend on where it is issued
  // (frame depth, inside a wrapper).
  ghost predicate A8(om: Oracle) {
    forall h: seq<Ev>, e: Ev, w1: Where, w2: Where :: e.ECall? && !e.kf && IsLookup(e.id) ==> om(h, e, w1) == om(h, e, w2)
  }

  // ================= premise on the original program =================

  // S0, the part the model can name: callbacks only through bpf_loop (181)
  // and bpf_for_each_map_elem (164), which are CbCall; no plain helper call
  // is tail_call (12), one of those, timer_set_callback (170), find_vma
  // (180) or user_ringbuf_drain (209).  Register-source jumps and calls,
  // arena accesses and P6 have no form in the model.
  ghost predicate S0(P: seq<OInstr>) {
    forall j | 0 <= j < |P| ::
      (P[j].CbCall? ==> P[j].id == 164 || P[j].id == 181)
      && (P[j].Hcall? && !P[j].kf ==> P[j].id !in {12, 164, 170, 180, 181, 209})
  }

  // ================= structural conditions (checker) =================

  // Floors (check.go:237-247): one per function, in [-512, 0].
  ghost predicate FloorsOk(P: seq<OInstr>, ell: nat -> int) {
    forall g | g in FnSet(P) :: -(STK as int) <= ell(g) <= 0
  }

  ghost predicate Bytes8(b: seq<bv8>) { |b| % 8 == 0 }

  // Each slice of an inserted piece; W bodies are excluded (their helper is I_i).
  ghost predicate NoHelperIn(b: seq<bv8>) {
    forall k | 0 <= k < NI(b) :: !(S.Decode(Slice(b, k)).Some? && S.Decode(Slice(b, k)).value.CallHelper?)
  }

  // S2, S6, S9: the pieces sit where their form allows.
  ghost predicate PiecesOk(P: seq<OInstr>, D: Decomp) {
    Bytes8(D.pro0) && NoHelperIn(D.pro0)
    && (forall g | g in D.fp :: g in FnSet(P) && 0 < g < |P| && Bytes8(D.fp[g].code) && NoHelperIn(D.fp[g].code))
    && (forall i | i in D.pl :: i < |P| && P[i].Call? && Bytes8(D.pl[i].code) && NoHelperIn(D.pl[i].code))
    && (forall i | i in D.site :: i < |P| && i !in D.wrap && (P[i].Tail? || (P[i].Hcall? && !P[i].kf))
          && Bytes8(D.site[i].pre) && Bytes8(D.site[i].post)
          && NoHelperIn(D.site[i].pre) && NoHelperIn(D.site[i].post))
    && (forall i | i in D.wrap :: i < |P| && P[i].Hcall? && !P[i].kf && IsLookup(P[i].id)
          && Bytes8(D.wrap[i].wp) && Bytes8(D.wrap[i].body) && NoHelperIn(D.wrap[i].wp))
    && (forall i | i in D.fns :: 0 < i < |P| && (P[i - 1].Exit? || P[i - 1].Ja?))
    && (forall k | 0 <= k < |AllFns(P, D)| ::
          match AllFns(P, D)[k].0
          case HookFn(b) => Bytes8(b) && NoHelperIn(b)
          case WrapFn(s) => s in D.wrap)
    && (forall i | i in D.wrap :: |set k | 0 <= k < |AllFns(P, D)| && AllFns(P, D)[k].0 == WrapFn(i)| == 1)
  }

  // S8: every inserted pseudo call targets a hook, except call W_i at kappa(i).
  ghost predicate CallsOk(D: Decomp, Pp: RwProg) {
    forall p | 0 <= p < |Pp.code| && Pp.code[p].N? ::
      var b := Pp.code[p].b;
      (|b| == 8 && S.Decode(b).Some? && S.Decode(b).value.CallLocal? && !(exists i :: i in D.wrap && p == K(D, i)))
      ==> p + 1 + Signed32(S.Decode(b).value.imm) in Pp.hooks
  }

  // ---- S10: the pass premise, with the checker's liveness ----

  ghost function SetOf(rs: seq<nat>): set<nat> { set r | r in rs }

  // reads(j) and writes(j) of effects.go:387-454 (helper reads from tbl).
  ghost function ReadsL(ins: OInstr, live: nat -> set<nat>, tbl: bv32 -> set<nat>): set<nat> {
    match ins
    case Alu(_, _, srcs) => SetOf(srcs)
    case Ld(_, base, _, _, _) => {base}
    case St(base, _, _, src) => {base} + (if src.SR? then {src.r} else {})
    case Atom(_, base, _, _, rs, _, _) => {base, rs}
    case Legacy(_, _, _) => {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
    case Jcc(_, srcs, _) => SetOf(srcs)
    case Hcall(kf, id) => if kf then {1, 2, 3, 4, 5} else tbl(id)
    case CbCall(id) => tbl(id)
    case Tail => tbl(12)
    case Call(t) => live(t) * {1, 2, 3, 4, 5}
    case Exit => {0}
    case _ => {}
  }
  ghost function WritesL(ins: OInstr): set<nat> {
    match ins
    case Alu(_, dst, _) => {dst}
    case FRef(dst, _) => {dst}
    case Ld(dst, _, _, _, _) => {dst}
    case Legacy(_, _, _) => {0}
    case Hcall(_, _) => {0, 1, 2, 3, 4, 5}
    case CbCall(_) => {0, 1, 2, 3, 4, 5}
    case Tail => {0, 1, 2, 3, 4, 5}
    case Call(_) => {0, 1, 2, 3, 4, 5}
    case _ => {}
  }
  ghost function Succ(P: seq<OInstr>, j: nat): set<nat> requires j < |P| {
    match P[j]
    case Ja(t) => {t}
    case Exit => {}
    case Jcc(_, _, t) => {t, j + 1}
    case MayGoto(t) => {t, j + 1}
    case _ => {j + 1}
  }

  // live is a solution of the liveness inequations (the checker's least
  // solution is one).
  ghost predicate LiveOk(P: seq<OInstr>, live: nat -> set<nat>, tbl: bv32 -> set<nat>) {
    forall j | 0 <= j < |P| ::
      ReadsL(P[j], live, tbl) <= live(j)
      && forall s | s in Succ(P, j) :: live(s) - WritesL(P[j]) <= live(j)
  }

  // S10: a pass load writes one of r1-r5, sits before a call, and that
  // register is not live at the callee's entry.
  ghost predicate S10(P: seq<OInstr>, D: Decomp, live: nat -> set<nat>, tbl: bv32 -> set<nat>) {
    LiveOk(P, live, tbl)
    && forall i | i in D.pl :: i < |P| && P[i].Call? && 1 <= D.pl[i].reg <= 5 && D.pl[i].reg !in live(P[i].t)
  }

  // L(P'), the length part: P' must load, and the kernel refuses a program
  // longer than BPF_COMPLEXITY_LIMIT_INSNS (1000000, the privileged insn_cnt
  // cap of bpf_prog_load).  The proof uses it only to bound the offset of
  // call W_i (32 bits, EncCallLocal) at a wrapped site.
  ghost predicate Loadable(P: seq<OInstr>, D: Decomp) {
    |Layout(P, D).code| <= 1000000
  }

  // All structural conditions the checker establishes.
  ghost predicate Structure(P: seq<OInstr>, D: Decomp, Pp: RwProg, ell: nat -> int,
                            live: nat -> set<nat>, tbl: bv32 -> set<nat>) {
    Pp == Layout(P, D)      // S1, S2, S3, S9: P' is P with the pieces of D in place
    && PiecesOk(P, D) && CallsOk(D, Pp) && FloorsOk(P, ell) && S10(P, D, live, tbl)
  }
}
