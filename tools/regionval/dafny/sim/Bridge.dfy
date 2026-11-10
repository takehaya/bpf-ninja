// The connection between whole runs of P' and the region-level runs of
// Semantics.dfy: a window of P', run inside the whole model, is a run of
// Semantics.Run on the window's bytes for some oracle.  The obligations that
// Soundness.Soundness proves for every oracle then describe the whole run.
include "Region.dfy"

module SimBridge {
  import opened Bits
  import S = Semantics
  import opened Obligations
  import opened SimModel
  import opened SimRegion
  import SimFacts
  import Soundness
  import Checker
  import Api
  import SimPremises

  // ---------------- the region-level view of the top frame ----------------

  ghost predicate FrameOk(f: Frame) {
    |f.regs| == NR && |f.stack| == STK
    && (forall k | 0 <= k < NR :: f.regs[k].W?)
    && (forall o | 0 <= o < STK :: f.stack[o].B?)
  }

  // c's top frame is the region state s; the window starts at base.
  ghost predicate BR(c: Cfg, s: S.CState, base: int) {
    var f := Top(c);
    0 < |c.fr| <= MAXF_RW && S.CWF(s) && FrameOk(f)
    && f.pc == base + s.pc
    && R64(f) == s.regs && Plain(f.stack) == s.stack
    && s.regs[10] == StackTop(|c.fr| - 1)
  }

  // Everything but the top frame.
  ghost function Below(c: Cfg): seq<Frame> { if |c.fr| > 0 then c.fr[..|c.fr| - 1] else [] }

  // ---------------- small facts about the whole model ----------------

  lemma ReachAdd(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, a: nat, b: nat, c1: Cfg)
    requires ReachR(Pp, x, obsv, c, a) == Some(c1)
    ensures ReachR(Pp, x, obsv, c, a + b) == ReachR(Pp, x, obsv, c1, b)
    decreases a
  {
    if a > 0 {
      match StepR(Pp, x, obsv, c)
      case Go(c') => ReachAdd(Pp, x, obsv, c', a - 1, b, c1);
      case _ =>
    }
  }

  lemma ReachOne(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, c1: Cfg)
    requires StepR(Pp, x, obsv, c) == Go(c1)
    ensures ReachR(Pp, x, obsv, c, 1) == Some(c1)
  {}

  lemma R64Set(f: Frame, dst: nat, v: bv64)
    requires |f.regs| == NR && dst < NR
    ensures R64(SetR(f, dst, W(v))) == R64(f)[dst := v]
  {}

  // An access the region sees inside the top frame is the same bytes of the top frame.
  lemma InFrameClassify(c: Cfg, a: bv64, w: nat)
    requires 0 < |c.fr| <= MAXF_RW
    requires S.InFrame(S.Rel(a, StackTop(|c.fr| - 1)), w)
    ensures Classify(a, w, |c.fr|, c.L.mem.Keys) == InStack(|c.fr| - 1, S.Rel(a, StackTop(|c.fr| - 1)) + STK)
  {
    reveal Classify();
  }

  // ---------------- one inserted step, region and whole ----------------

  ghost predicate AtIns(Pp: RwProg, c: Cfg, ins: S.Instr) {
    0 <= Top(c).pc < |Pp.code| && Pp.code[Top(c).pc].N? && |Pp.code[Top(c).pc].b| == 8
    && S.Decode(Pp.code[Top(c).pc].b) == Some(ins)
  }

  lemma StepIns(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, ins: S.Instr)
    requires |c.fr| > 0 && AtIns(Pp, c, ins)
    ensures StepR(Pp, x, obsv, c) == IExec(x, Pp.hooks, obsv, ins, c)
  {}

  // Only the top frame's registers and pc changed.
  ghost predicate TopOnly(c: Cfg, c': Cfg) {
    |c'.fr| == |c.fr| && Below(c') == Below(c) && c'.L == c.L && c'.h == c.h
    && Top(c').stack == Top(c).stack && Top(c').kind == Top(c).kind && Top(c').fn == Top(c).fn
  }

  lemma PutTop(c: Cfg, f: Frame)
    requires |c.fr| > 0
    ensures Top(Put(c, f)) == f && Below(Put(c, f)) == Below(c) && |Put(c, f).fr| == |c.fr|
    ensures Put(c, f).L == c.L && Put(c, f).h == c.h && Put(c, f).hc == c.hc && Put(c, f).os == c.os
  {}

  lemma {:isolate_assertions} AluSim(c: Cfg, s: S.CState, base: int, floor: int,
                                      is64: bool, op: S.AluOp, dst: nat, opnd: S.Operand, oracle: seq<bv64>)
    requires BR(c, s, base) && dst < 10 && -(S.STACK as int) <= floor <= 0
    ensures S.Step(floor, S.Alu(is64, op, dst, opnd), s, oracle).Next?
    ensures var s' := S.Step(floor, S.Alu(is64, op, dst, opnd), s, oracle).s;
      IAlu(c, is64, op, dst, opnd).Go? && BR(IAlu(c, is64, op, dst, opnd).c, s', base)
      && TopOnly(c, IAlu(c, is64, op, dst, opnd).c) && s'.events == s.events && s'.oc == s.oc
  {
    StepAluEq(floor, is64, op, dst, opnd, s, oracle);
    reveal IAlu();
    var f := Top(c);
    var v := S.AluVal(is64, op, s.regs[dst], S.OperandVal(is64, opnd, s.regs));
    var f' := Adv(SetR(f, dst, W(v)));
    PutTop(c, f');
    R64Set(f, dst, v);
    assert R64(f') == s.regs[dst := v];
  }

  lemma {:isolate_assertions} JaSim(c: Cfg, s: S.CState, base: int, floor: int, off: bv16, oracle: seq<bv64>)
    requires BR(c, s, base) && -(S.STACK as int) <= floor <= 0
    ensures S.Step(floor, S.Ja(off), s, oracle).Next?
    ensures var s' := S.Step(floor, S.Ja(off), s, oracle).s;
      var c' := Put(c, Top(c).(pc := Top(c).pc + 1 + Signed16(off)));
      BR(c', s', base) && TopOnly(c, c') && s'.events == s.events && s'.oc == s.oc
  {
    Soundness.StepEq(floor, S.Ja(off), s, oracle);
    PutTop(c, Top(c).(pc := Top(c).pc + 1 + Signed16(off)));
  }

  lemma {:isolate_assertions} JcondSim(c: Cfg, s: S.CState, base: int, floor: int,
                                        cnd: S.Cond, dst: nat, imm: bv32, off: bv16, oracle: seq<bv64>)
    requires BR(c, s, base) && dst <= 10 && -(S.STACK as int) <= floor <= 0
    ensures S.Step(floor, S.Jcond(cnd, dst, imm, off), s, oracle).Next?
    ensures var s' := S.Step(floor, S.Jcond(cnd, dst, imm, off), s, oracle).s;
      IJcond(c, cnd, dst, imm, off).Go? && BR(IJcond(c, cnd, dst, imm, off).c, s', base)
      && TopOnly(c, IJcond(c, cnd, dst, imm, off).c) && s'.events == s.events && s'.oc == s.oc
  {
    Soundness.StepEq(floor, S.Jcond(cnd, dst, imm, off), s, oracle);
    reveal IJcond();
    var f := Top(c);
    PutTop(c, f.(pc := if S.CondHolds(cnd, R64(f)[dst], imm) then f.pc + 1 + Signed16(off) else f.pc + 1));
  }

  // ---------------- loads and stores ----------------

  lemma PlainSlice(st: seq<Byte>, o: nat, w: nat)
    requires o + w <= |st|
    ensures Plain(st[o .. o + w]) == Plain(st)[o .. o + w]
  {}

  // The value an inserted load gets in the whole model.
  ghost function LoadedW(x: Ctx, c: Cfg, a: bv64, w: nat): bv64 requires w <= 8 { InsLoad(x, c, a, w).0 }

  // The region's loaded value is the whole model's.
  lemma LdxVal(x: Ctx, c: Cfg, s: S.CState, base: int, a: bv64, w: nat, oracle: seq<bv64>)
    requires BR(c, s, base) && (w == 1 || w == 2 || w == 4 || w == 8)
    requires !S.InFrame(S.Rel(a, s.regs[10]), w) ==> S.Orc(oracle, s.oc) == LoadedW(x, c, a, w)
    ensures S.LoadVal(s, a, w, oracle) == LoadedW(x, c, a, w)
  {
    reveal InsLoad(), S.LoadVal();
    if S.InFrame(S.Rel(a, s.regs[10]), w) {
      InFrameClassify(c, a, w);
      var o := S.Rel(a, s.regs[10]) + STK;
      PlainSlice(Top(c).stack, o, w);
    } else {
      match Classify(a, w, |c.fr|, c.L.mem.Keys)
      case InStack(d, o) => BytesOfLE(Plain(StackBytes(c, d, o, w)));
      case InLocal => BytesOfLE(LBytes(c.L.mem, a, w));
      case _ => BytesOfLE(BytesOf(HV(x, c), w));
    }
  }

  lemma ILdxEq(x: Ctx, c: Cfg, w: nat, dst: nat, rb: nat, off: bv16, a: bv64)
    requires dst < 10 && rb <= 10 && w <= 8 && a == R64(Top(c))[rb] + Sext16(off)
    ensures ILdx(x, c, w, dst, rb, off) == SetDst(c.(hc := c.hc + InsLoad(x, c, a, w).1), dst, InsLoad(x, c, a, w).0)
  { reveal ILdx(); }

  lemma {:isolate_assertions} LdxSim(x: Ctx, c: Cfg, s: S.CState, base: int, floor: int,
                                      w: nat, dst: nat, rb: nat, off: bv16, oracle: seq<bv64>)
    requires BR(c, s, base) && dst < 10 && rb <= 10 && (w == 1 || w == 2 || w == 4 || w == 8)
    requires -(S.STACK as int) <= floor <= 0
    requires var a := s.regs[rb] + Sext16(off);
      !S.InFrame(S.Rel(a, s.regs[10]), w) ==> S.Orc(oracle, s.oc) == LoadedW(x, c, a, w)
    ensures S.Step(floor, S.Ldx(w, dst, rb, off), s, oracle).Next?
    ensures var s' := S.Step(floor, S.Ldx(w, dst, rb, off), s, oracle).s;
      ILdx(x, c, w, dst, rb, off).Go? && BR(ILdx(x, c, w, dst, rb, off).c, s', base)
      && TopOnly(c, ILdx(x, c, w, dst, rb, off).c) && s'.events == s.events
      && s'.oc == s.oc + (if S.InFrame(S.Rel(s.regs[rb] + Sext16(off), s.regs[10]), w) then 0 else 1)
  {
    StepLdx(floor, w, dst, rb, off, s, oracle);
    var a := s.regs[rb] + Sext16(off);
    var f := Top(c);
    assert R64(f)[rb] + Sext16(off) == a;
    LdxVal(x, c, s, base, a, w, oracle);
    var vw := LoadedW(x, c, a, w);
    var k := InsLoad(x, c, a, w).1;
    ILdxEq(x, c, w, dst, rb, off, a);
    var c1 := c.(hc := c.hc + k);
    PutTop(c1, Adv(SetR(f, dst, W(vw))));
    R64Set(f, dst, vw);
  }

  lemma WriteBytesPlain(st: seq<Byte>, o: nat, bs: seq<bv8>)
    requires o + |bs| <= |st|
    ensures Plain(st[..o] + Bytes(bs) + st[o + |bs|..]) == S.WriteBytes(Plain(st), o, bs)
  {}

  // A store the region places in the frame writes the same bytes of the top frame.
  lemma {:isolate_assertions} StoreSim(c: Cfg, s: S.CState, base: int, a: bv64, w: nat, v: bv64)
    requires BR(c, s, base) && 0 < w <= 8 && S.InFrame(S.Rel(a, s.regs[10]), w)
    ensures var o := S.Rel(a, s.regs[10]) + STK;
      var s' := S.StoreStep(s, a, w, v).s;
      S.StoreStep(s, a, w, v).Next? && InsStore(c, a, w, v).Go?
      && BR(InsStore(c, a, w, v).c, s', base)
      && s'.events == s.events + [S.EStore(a, w)] && s'.oc == s.oc
      && var c' := InsStore(c, a, w, v).c;
         |c'.fr| == |c.fr| && Below(c') == Below(c) && c'.L == c.L && c'.h == c.h
         && Top(c').kind == Top(c).kind && Top(c').fn == Top(c).fn
         && (forall i | 0 <= i < STK && !(o <= i < o + w) :: Top(c').stack[i] == Top(c).stack[i])
  {
    reveal InsStore();
    InFrameClassify(c, a, w);
    var o := S.Rel(a, s.regs[10]) + STK;
    var f := Top(c);
    var bs := Bytes(BytesOf(v, w));
    var c1 := WriteStack(c, |c.fr| - 1, o, bs);
    assert Top(c1) == f.(stack := f.stack[..o] + bs + f.stack[o + w..]);
    WriteBytesPlain(f.stack, o, BytesOf(v, w));
    PutTop(c1, Adv(Top(c1)));
  }

  // ================= the window bridge =================

  // The helper the window's centre issues, computed from the window's entry.
  datatype HCtx = HCtx(n: nat, addrs: seq<bv64>, eh: Ev, v: Val, wr: map<int, bv8>)

  // A window of P': raw bytes at base; hp is the position of the central
  // helper (an original instruction), or outside the window if none.
  datatype Win = Win(Pp: RwProg, x: Ctx, obsv: Observer, raw: seq<bv8>, sp: Spec, base: int,
                     hp: int, hins: OInstr, hidx: nat, hc: HCtx, c0: Cfg, s0: S.CState)

  ghost predicate HasHelper(w: Win) { 0 <= w.hp < S.NumInsns(w.raw) }

  ghost predicate IsHelperCall(b: seq<bv8>) { |b| == 8 && S.Decode(b).Some? && S.Decode(b).value.CallHelper? }

  ghost predicate WinAt(w: Win) {
    var n := S.NumInsns(w.raw);
    |w.raw| % 8 == 0 && 0 <= w.base && w.base + n <= |w.Pp.code|
    && (forall r | 0 <= r < n && r != w.hp ::
          w.Pp.code[w.base + r] == N(S.InsnAt(w.raw, r)) && !IsHelperCall(S.InsnAt(w.raw, r))
          && (w.sp.hookCalls && S.Decode(S.InsnAt(w.raw, r)).Some? && S.Decode(S.InsnAt(w.raw, r)).value.CallLocal? ==>
                w.base + r + 1 + Signed32(S.Decode(S.InsnAt(w.raw, r)).value.imm) in w.Pp.hooks))
    && (HasHelper(w) ==>
          w.hins.Hcall? && !w.hins.kf && w.Pp.code[w.base + w.hp] == O(w.hins, w.hidx)
          && S.Decode(S.InsnAt(w.raw, w.hp)) == Some(S.CallHelper(w.hins.id)))
  }

  // A hook body laid out at t and validated as a P7 body.
  ghost predicate HookAt(Pp: RwProg, t: nat, body: seq<bv8>) {
    |body| % 8 == 0 && t + S.NumInsns(body) <= |Pp.code|
    && (forall r | 0 <= r < S.NumInsns(body) ::
          Pp.code[t + r] == N(S.InsnAt(body, r)) && !IsHelperCall(S.InsnAt(body, r)))
    && Checker.Validate(body, Api.HookBodySpec()) == Checker.Validated
  }
  ghost predicate HooksOk(Pp: RwProg) { forall t | t in Pp.hooks :: exists body :: HookAt(Pp, t, body) }

  // Stack bytes of the top frame a footprint or write set touches lie at or above the floor.
  ghost predicate FootTop(c: Cfg, addrs: seq<bv64>, floor: int) {
    forall i | 0 <= i < |addrs| ::
      match Classify(addrs[i], 1, |c.fr|, c.L.mem.Keys)
      case InStack(d, o) => d == |c.fr| - 1 ==> o >= STK as int + floor
      case _ => true
  }
  ghost predicate WrTop(c: Cfg, wr: map<int, bv8>, floor: int) {
    0 < |c.fr| <= MAXF_RW &&
    forall o: nat | o < STK && o < STK as int + floor :: SAddr(|c.fr| - 1, o) as int !in wr
  }

  ghost predicate HelperOk(w: Win) {
    var args := SimFacts.Words(Top(w.c0), Upto(1, w.hc.n));
    w.hins.Hcall? && w.hc.n == w.x.env.arity(false, w.hins.id) && w.hc.n <= 5
    && w.hc.addrs == w.x.env.foot(false, w.hins.id, args)
    && FootBytes(w.c0, w.hc.addrs).FOk?
    && w.hc.eh == ECall(w.hidx, false, w.hins.id, args, FootBytes(w.c0, w.hc.addrs).bs)
    && w.x.om(w.c0.h, w.hc.eh, Wh(w.c0)) == RRet(w.hc.v, w.hc.wr)
    && FootTop(w.c0, w.hc.addrs, w.sp.floor) && WrTop(w.c0, w.hc.wr, w.sp.floor)
  }

  // What the window may have changed, before and after its helper.
  opaque ghost predicate Side(w: Win, c: Cfg, s: S.CState) {
    var c0 := w.c0;
    var lo := STK as int + w.sp.floor;
    |c.fr| == |c0.fr| && Top(c).kind == Top(c0).kind && Top(c).fn == Top(c0).fn
    && |Top(c).stack| == STK && |Top(c0).stack| == STK
    && (CountHelpers(s.events) == 0 ==>
          Below(c) == Below(c0) && c.L == c0.L && c.h == c0.h
          && forall i | 0 <= i && lo <= i < STK :: Top(c).stack[i] == Top(c0).stack[i])
    && (CountHelpers(s.events) == 1 ==>
          var a := ApplyW(c0, w.hc.wr);
          Below(c) == Below(a) && c.L == a.L && c.h == c0.h + [w.hc.eh]
          && (w.hc.v.W? ==> HelperRet(s.events) == w.hc.v.w)
          && |UpperBase(s.events, w.s0.stack)| == STK && |Top(a).stack| == STK
          && forall i | 0 <= i && lo <= i < STK :: UpperBase(s.events, w.s0.stack)[i] == Plain(Top(a).stack)[i])
    && CountHelpers(s.events) <= 1
  }

  lemma SideFacts(w: Win, c: Cfg, s: S.CState)
    requires Side(w, c, s)
    ensures |c.fr| == |w.c0.fr| && Top(c).kind == Top(w.c0).kind && Top(c).fn == Top(w.c0).fn
    ensures |Top(c).stack| == STK && |Top(w.c0).stack| == STK && CountHelpers(s.events) <= 1
  { reveal Side(); }

  lemma Side0(w: Win, c: Cfg, s: S.CState)
    requires Side(w, c, s) && CountHelpers(s.events) == 0
    ensures Below(c) == Below(w.c0) && c.L == w.c0.L && c.h == w.c0.h
    ensures |Top(c).stack| == STK && |Top(w.c0).stack| == STK
      && forall i | 0 <= i && STK as int + w.sp.floor <= i < STK :: Top(c).stack[i] == Top(w.c0).stack[i]
  { reveal Side(); }

  lemma Side1(w: Win, c: Cfg, s: S.CState)
    requires Side(w, c, s) && CountHelpers(s.events) == 1
    ensures var a := ApplyW(w.c0, w.hc.wr);
      Below(c) == Below(a) && c.L == a.L && c.h == w.c0.h + [w.hc.eh]
      && (w.hc.v.W? ==> HelperRet(s.events) == w.hc.v.w)
      && |UpperBase(s.events, w.s0.stack)| == STK && |Top(a).stack| == STK
      && forall i | 0 <= i && STK as int + w.sp.floor <= i < STK :: UpperBase(s.events, w.s0.stack)[i] == Plain(Top(a).stack)[i]
  { reveal Side(); }

  lemma SideInit(w: Win)
    requires |Top(w.c0).stack| == STK && w.s0.events == []
    ensures Side(w, w.c0, w.s0)
  { reveal Side(); }

  // A step with no helper event that leaves the frames, L, h and the bytes at or above the floor.
  lemma SideStep(w: Win, c: Cfg, s: S.CState, c': Cfg, s': S.CState)
    requires Side(w, c, s)
    requires CountHelpers(s'.events) == CountHelpers(s.events) && HelperRet(s'.events) == HelperRet(s.events)
    requires UpperBase(s'.events, w.s0.stack) == UpperBase(s.events, w.s0.stack)
    requires |c'.fr| == |c.fr| && Top(c').kind == Top(c).kind && Top(c').fn == Top(c).fn
    requires Below(c') == Below(c) && c'.L == c.L && c'.h == c.h && |Top(c').stack| == STK && |Top(c).stack| == STK
    requires forall i | 0 <= i && STK as int + w.sp.floor <= i < STK :: Top(c').stack[i] == Top(c).stack[i]
    ensures Side(w, c', s')
  { reveal Side(); }

  lemma SideEvent(w: Win, c: Cfg, s: S.CState, c': Cfg, s': S.CState, e: S.Event)
    requires Side(w, c, s) && s'.events == s.events + [e] && !e.EHelper?
    requires |c'.fr| == |c.fr| && Top(c').kind == Top(c).kind && Top(c').fn == Top(c).fn
    requires Below(c') == Below(c) && c'.L == c.L && c'.h == c.h && |Top(c').stack| == STK && |Top(c).stack| == STK
    requires forall i | 0 <= i && STK as int + w.sp.floor <= i < STK :: Top(c').stack[i] == Top(c).stack[i]
    ensures Side(w, c', s')
  {
    Soundness.EventsSnoc(s.events, e, w.s0.stack);
    SideStep(w, c, s, c', s');
  }

  ghost predicate WinPre(w: Win) { WinPreO(w) && -(S.STACK as int) <= w.sp.floor <= 0 && S.CWF(w.s0) }

  opaque ghost predicate WinPreO(w: Win) {
    w.x.m.MR? && SimPremises.A5(w.obsv) && SpecWF(w.sp) && w.sp.wrap.NoWrap?
    && WinAt(w) && HooksOk(w.Pp)
    && BR(w.c0, w.s0, w.base) && w.s0 == S.InitState(w.s0.regs, w.s0.stack)
    && (HasHelper(w) ==> HelperOk(w) && w.sp.helper.Helper? && w.sp.helper.checkArgs)
  }

  lemma WinPreFacts(w: Win)
    requires WinPre(w)
    ensures w.x.m.MR? && SimPremises.A5(w.obsv) && SpecWF(w.sp) && w.sp.wrap.NoWrap?
    ensures -(S.STACK as int) <= w.sp.floor <= 0
    ensures BR(w.c0, w.s0, w.base) && w.s0 == S.InitState(w.s0.regs, w.s0.stack)
    ensures HasHelper(w) ==> w.sp.helper.Helper? && w.sp.helper.checkArgs
  { reveal WinPreO(); }

  lemma WinPreAt(w: Win) requires WinPre(w) ensures WinAt(w) && HooksOk(w.Pp) { reveal WinPreO(); }
  lemma WinPreHelper(w: Win) requires WinPre(w) && HasHelper(w) ensures HelperOk(w) { reveal WinPreO(); }

  ghost predicate Pre(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>) {
    WinPre(w) && BR(c, s, w.base) && s.oc == |prefix| && Side(w, c, s)
    && (w.sp.hookCalls ==> |c.fr| < MAXF_RW)
  }

  // FinalOk, folded: the bridge only passes it through.
  opaque ghost predicate FinalOkO(sp: Spec, s0: S.CState, s: S.CState) requires S.CWF(s0) { FinalOk(sp, s0, s) }

  ghost predicate Post(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, rest: seq<bv64>)
    requires WinPre(w) && S.CWF(s)
  {
    var O := S.Run(w.raw, w.sp.floor, s, prefix + rest, fuel);
    ((O.Done? || O.Exited?) && FinalOkO(w.sp, w.s0, O.s)) ==> Ends(w, c, O.s, O.Exited?)
  }

  // From c the whole run reaches a configuration whose top frame is the region state sf.
  opaque ghost predicate Ends(w: Win, c: Cfg, sf: S.CState, exited: bool) {
    exists k: nat, c2: Cfg :: ReachR(w.Pp, w.x, w.obsv, c, k) == Some(c2)
      && BR(c2, sf, w.base) && Side(w, c2, sf) && (exited ==> AtIns(w.Pp, c2, S.Exit))
  }

  lemma EndsHere(w: Win, c: Cfg, sf: S.CState, exited: bool)
    requires BR(c, sf, w.base) && Side(w, c, sf) && (exited ==> AtIns(w.Pp, c, S.Exit))
    ensures Ends(w, c, sf, exited)
  {
    reveal Ends();
    assert ReachR(w.Pp, w.x, w.obsv, c, 0) == Some(c);
  }

  lemma EndsPrefix(w: Win, c: Cfg, k: nat, c': Cfg, sf: S.CState, exited: bool)
    requires ReachR(w.Pp, w.x, w.obsv, c, k) == Some(c') && Ends(w, c', sf, exited)
    ensures Ends(w, c, sf, exited)
  {
    reveal Ends();
    var k2: nat, c2: Cfg :| ReachR(w.Pp, w.x, w.obsv, c', k2) == Some(c2)
      && BR(c2, sf, w.base) && Side(w, c2, sf) && (exited ==> AtIns(w.Pp, c2, S.Exit));
    ReachAdd(w.Pp, w.x, w.obsv, c, k, k2, c');
  }

  lemma EndsGet(w: Win, c: Cfg, sf: S.CState, exited: bool) returns (k: nat, c2: Cfg)
    requires Ends(w, c, sf, exited)
    ensures ReachR(w.Pp, w.x, w.obsv, c, k) == Some(c2)
    ensures BR(c2, sf, w.base) && Side(w, c2, sf) && (exited ==> AtIns(w.Pp, c2, S.Exit))
  {
    reveal Ends();
    k, c2 :| ReachR(w.Pp, w.x, w.obsv, c, k) == Some(c2)
      && BR(c2, sf, w.base) && Side(w, c2, sf) && (exited ==> AtIns(w.Pp, c2, S.Exit));
  }

  // ---------------- glue ----------------

  // A step the region model cannot take ends the window run outside the obligations.
  lemma StuckPost(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr)
    requires WinPre(w) && S.CWF(s) && 0 <= s.pc < S.NumInsns(w.raw) && fuel > 0
    requires S.Decode(S.InsnAt(w.raw, s.pc)) == Some(ins) && S.Step(w.sp.floor, ins, s, prefix) == S.Stuck
    ensures Post(w, c, s, prefix, fuel, [])
  {
    WinPreFacts(w);
    assert prefix + [] == prefix;
    Soundness.RunAt(w.raw, w.sp.floor, s, prefix, fuel, ins);
  }

  // A step whose event breaks the obligations: no run through it meets them.
  lemma BadPost(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr, s': S.CState)
    requires WinPre(w) && S.CWF(s) && 0 <= s.pc < S.NumInsns(w.raw) && fuel > 0
    requires S.Decode(S.InsnAt(w.raw, s.pc)) == Some(ins) && S.Step(w.sp.floor, ins, s, prefix) == S.Next(s') && S.CWF(s')
    requires (|s'.events| > |s.events| && !EventOk(w.sp, w.s0, s'.events[|s.events|]))
             || CountHelpers(s'.events) > 1
    ensures Post(w, c, s, prefix, fuel, [])
  {
    reveal FinalOkO();
    WinPreFacts(w);
    assert prefix + [] == prefix;
    Soundness.RunNext(w.raw, w.sp.floor, s, prefix, fuel, ins, s');
    RunEventsGrow(w.raw, w.sp.floor, s', prefix, fuel - 1);
    var O := S.Run(w.raw, w.sp.floor, s', prefix, fuel - 1);
    SimFacts.CountHelpersMono(s'.events, O.s.events);
    if |s'.events| > |s.events| && !EventOk(w.sp, w.s0, s'.events[|s.events|]) {
      assert O.s.events[|s.events|] == s'.events[|s.events|];
    }
  }

  // A good step to (c', s') after k whole steps, consuming vals; the rest of the window follows.
  // The region run from s with the whole run's values is the run from s' after them.
  lemma AdvanceRun(w: Win, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr, vals: seq<bv64>,
                   s': S.CState, rest': seq<bv64>)
    requires -(S.STACK as int) <= w.sp.floor <= 0 && S.CWF(s) && S.CWF(s') && 0 <= s.pc < S.NumInsns(w.raw) && fuel > 0
    requires S.Decode(S.InsnAt(w.raw, s.pc)) == Some(ins)
    requires s.oc + Need(w.sp.floor, ins, s) <= |prefix + vals|
    requires S.Step(w.sp.floor, ins, s, prefix + vals) == S.Next(s')
    ensures S.Run(w.raw, w.sp.floor, s, prefix + (vals + rest'), fuel) == S.Run(w.raw, w.sp.floor, s', (prefix + vals) + rest', fuel - 1)
  {
    var rest := vals + rest';
    assert prefix + rest == (prefix + vals) + rest';
    assert SameUpTo(prefix + rest, prefix + vals, s.oc + Need(w.sp.floor, ins, s));
    StepOracleLocal(w.sp.floor, ins, s, prefix + rest, prefix + vals);
    Soundness.RunNext(w.raw, w.sp.floor, s, prefix + rest, fuel, ins, s');
  }

  lemma {:isolate_assertions} Advance(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr,
                vals: seq<bv64>, k: nat, c': Cfg, s': S.CState) returns (rest: seq<bv64>)
    requires Pre(w, c, s, prefix) && 0 <= s.pc < S.NumInsns(w.raw) && fuel > 0
    requires S.Decode(S.InsnAt(w.raw, s.pc)) == Some(ins)
    requires s.oc + Need(w.sp.floor, ins, s) <= |prefix + vals|
    requires S.Step(w.sp.floor, ins, s, prefix + vals) == S.Next(s')
    requires ReachR(w.Pp, w.x, w.obsv, c, k) == Some(c') && Pre(w, c', s', prefix + vals)
    ensures Post(w, c, s, prefix, fuel, rest)
    decreases (if w.sp.hookCalls then 1 else 0), fuel, 0
  {
    WinPreFacts(w);
    var rest' := Bridge(w, c', s', prefix + vals, fuel - 1);
    rest := vals + rest';
    AdvanceRun(w, s, prefix, fuel, ins, vals, s', rest');
    var O := S.Run(w.raw, w.sp.floor, s, prefix + rest, fuel);
    if (O.Done? || O.Exited?) && FinalOkO(w.sp, w.s0, O.s) {
      EndsPrefix(w, c, k, c', O.s, O.Exited?);
    }
  }


  // ---------------- the bridge ----------------

  lemma Bridge(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat) returns (rest: seq<bv64>)
    requires Pre(w, c, s, prefix)
    ensures Post(w, c, s, prefix, fuel, rest)
    decreases (if w.sp.hookCalls then 1 else 0), fuel, 3
  {
    WinPreFacts(w);
    var n := S.NumInsns(w.raw);
    if s.pc == n {
      Soundness.RunEnd(w.raw, w.sp.floor, s, prefix, fuel);
      rest := [];
      assert prefix + rest == prefix;
      EndsHere(w, c, s, false);
      return;
    }
    if s.pc < 0 || s.pc > n || fuel == 0 {
      reveal S.Run();
      rest := [];
      assert prefix + rest == prefix;
      return;
    }
    if s.pc == w.hp {
      rest := BHelper(w, c, s, prefix, fuel);
      return;
    }
    match S.Decode(S.InsnAt(w.raw, s.pc))
    case None =>
      reveal S.Run();
      rest := [];
      assert prefix + rest == prefix;
    case Some(ins) =>
      rest := BIns(w, c, s, prefix, fuel, ins);
  }

  // A step that changed only the top frame's registers and pc keeps Pre.
  lemma PreKeep(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, c': Cfg, s': S.CState, vals: seq<bv64>)
    requires Pre(w, c, s, prefix) && BR(c', s', w.base) && TopOnly(c, c')
    requires s'.events == s.events && s'.oc == s.oc + |vals|
    ensures Pre(w, c', s', prefix + vals)
  {
    SideFacts(w, c, s);
    SideStep(w, c, s, c', s');
  }

  lemma StepGo(w: Win, c: Cfg, ins: S.Instr, r: StepRes)
    requires |c.fr| > 0 && AtIns(w.Pp, c, ins) && IExec(w.x, w.Pp.hooks, w.obsv, ins, c) == r && r.Go?
    ensures ReachR(w.Pp, w.x, w.obsv, c, 1) == Some(r.c)
  {
    StepIns(w.Pp, w.x, w.obsv, c, ins);
  }

  lemma AtFromWin(w: Win, c: Cfg, s: S.CState, ins: S.Instr)
    requires WinPre(w) && BR(c, s, w.base) && 0 <= s.pc < S.NumInsns(w.raw) && s.pc != w.hp
    requires S.Decode(S.InsnAt(w.raw, s.pc)) == Some(ins)
    ensures AtIns(w.Pp, c, ins)
  { WinPreAt(w); }

  lemma {:isolate_assertions} BIns(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr) returns (rest: seq<bv64>)
    requires Pre(w, c, s, prefix) && 0 <= s.pc < S.NumInsns(w.raw) && s.pc != w.hp && fuel > 0
    requires S.Decode(S.InsnAt(w.raw, s.pc)) == Some(ins)
    ensures Post(w, c, s, prefix, fuel, rest)
    decreases (if w.sp.hookCalls then 1 else 0), fuel, 2
  {
    WinPreAt(w);
    WinPreFacts(w);
    var fl := w.sp.floor;
    AtFromWin(w, c, s, ins);
    match ins
    case Alu(is64, op, dst, opnd) =>
      if dst >= 10 {
        assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
        StuckPost(w, c, s, prefix, fuel, ins); rest := [];
      } else {
        AluSim(c, s, w.base, fl, is64, op, dst, opnd, prefix);
        var r := IAlu(c, is64, op, dst, opnd);
        StepGo(w, c, ins, r);
        var s' := S.Step(fl, ins, s, prefix).s;
        assert prefix + [] == prefix;
        PreKeep(w, c, s, prefix, r.c, s', []);
        rest := Advance(w, c, s, prefix, fuel, ins, [], 1, r.c, s');
      }
    case Ja(off) =>
      JaSim(c, s, w.base, fl, off, prefix);
      var c' := Put(c, Top(c).(pc := Top(c).pc + 1 + Signed16(off)));
      StepGo(w, c, ins, Go(c'));
      var s' := S.Step(fl, ins, s, prefix).s;
      assert prefix + [] == prefix;
      PreKeep(w, c, s, prefix, c', s', []);
      rest := Advance(w, c, s, prefix, fuel, ins, [], 1, c', s');
    case Jcond(cnd, dst, imm, off) =>
      if dst > 10 {
        assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
        StuckPost(w, c, s, prefix, fuel, ins); rest := [];
      } else {
        JcondSim(c, s, w.base, fl, cnd, dst, imm, off, prefix);
        var r := IJcond(c, cnd, dst, imm, off);
        StepGo(w, c, ins, r);
        var s' := S.Step(fl, ins, s, prefix).s;
        assert prefix + [] == prefix;
        PreKeep(w, c, s, prefix, r.c, s', []);
        rest := Advance(w, c, s, prefix, fuel, ins, [], 1, r.c, s');
      }
    case Ldx(wd, dst, rb, off) =>
      rest := BLdx(w, c, s, prefix, fuel, wd, dst, rb, off);
    case Stx(wd, rb, src, off) =>
      if rb > 10 || src > 10 || wd > 8 {
        assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
        StuckPost(w, c, s, prefix, fuel, ins); rest := [];
      } else {
        StepStx(fl, wd, rb, src, off, s, prefix);
        rest := BStore(w, c, s, prefix, fuel, ins, s.regs[rb] + Sext16(off), wd, s.regs[src]);
      }
    case St(wd, rb, off, imm) =>
      if rb > 10 || wd > 8 {
        assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
        StuckPost(w, c, s, prefix, fuel, ins); rest := [];
      } else {
        StepSt(fl, wd, rb, off, imm, s, prefix);
        rest := BStore(w, c, s, prefix, fuel, ins, s.regs[rb] + Sext16(off), wd, Sext32(imm));
      }
    case CallHelper(_) =>
      assert false;   // WinAt: only the centre is a helper call
    case CallLocal(imm) =>
      rest := BHook(w, c, s, prefix, fuel, imm);
    case Exit =>
      StepExit(fl, s, prefix);
      Soundness.RunAt(w.raw, fl, s, prefix, fuel, ins);
      rest := [];
      assert prefix + rest == prefix;
      EndsHere(w, c, s, true);
  }

  // Memory instructions decode with a width of 1, 2, 4 or 8.
  lemma DecodeWidth(b: seq<bv8>)
    requires |b| == 8 && S.Decode(b).Some?
    ensures var i := S.Decode(b).value;
      (i.Ldx? ==> i.size in {1, 2, 4, 8}) && (i.Stx? ==> i.size in {1, 2, 4, 8}) && (i.St? ==> i.size in {1, 2, 4, 8})
  {}

  lemma {:isolate_assertions} BLdx(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, wd: nat, dst: nat, rb: nat, off: bv16)
    returns (rest: seq<bv64>)
    requires Pre(w, c, s, prefix) && 0 <= s.pc < S.NumInsns(w.raw) && s.pc != w.hp && fuel > 0
    requires S.Decode(S.InsnAt(w.raw, s.pc)) == Some(S.Ldx(wd, dst, rb, off))
    ensures Post(w, c, s, prefix, fuel, rest)
    decreases (if w.sp.hookCalls then 1 else 0), fuel, 1
  {
    WinPreFacts(w);
    var fl := w.sp.floor;
    var ins := S.Ldx(wd, dst, rb, off);
    AtFromWin(w, c, s, ins);
    DecodeWidth(S.InsnAt(w.raw, s.pc));
    if dst >= 10 || rb > 10 {
      assert S.Step(fl, ins, s, prefix) == S.Stuck by { reveal S.Step(); }
      StuckPost(w, c, s, prefix, fuel, ins); rest := [];
      return;
    }
    var a := s.regs[rb] + Sext16(off);
    var inF := S.InFrame(S.Rel(a, s.regs[10]), wd);
    var vals: seq<bv64> := if inF then [] else [LoadedW(w.x, c, a, wd)];
    assert !inF ==> S.Orc(prefix + vals, s.oc) == LoadedW(w.x, c, a, wd);
    LdxSim(w.x, c, s, w.base, fl, wd, dst, rb, off, prefix + vals);
    var r := ILdx(w.x, c, wd, dst, rb, off);
    StepGo(w, c, ins, r);
    var s' := S.Step(fl, ins, s, prefix + vals).s;
    PreKeep(w, c, s, prefix, r.c, s', vals);
    NeedLdx(fl, wd, dst, rb, off, s);
    assert s.oc + Need(fl, ins, s) <= |prefix + vals|;
    assert S.Step(fl, ins, s, prefix + vals) == S.Next(s');
    assert Pre(w, r.c, s', prefix + vals);
    rest := Advance(w, c, s, prefix, fuel, ins, vals, 1, r.c, s');
  }

  lemma NeedLdx(fl: int, wd: nat, dst: nat, rb: nat, off: bv16, s: S.CState)
    requires S.CWF(s) && dst < 10 && rb <= 10 && wd <= 8
    ensures Need(fl, S.Ldx(wd, dst, rb, off), s) == if S.InFrame(S.Rel(s.regs[rb] + Sext16(off), s.regs[10]), wd) then 0 else 1
  {}

  lemma {:isolate_assertions} BStore(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, ins: S.Instr, a: bv64, wd: nat, v: bv64)
    returns (rest: seq<bv64>)
    requires Pre(w, c, s, prefix) && 0 <= s.pc < S.NumInsns(w.raw) && s.pc != w.hp && fuel > 0
    requires S.Decode(S.InsnAt(w.raw, s.pc)) == Some(ins) && (ins.Stx? || ins.St?)
    requires wd == ins.size && wd <= 8
    requires ins.Stx? ==> ins.base <= 10 && ins.src <= 10 && a == s.regs[ins.base] + Sext16(ins.off) && v == s.regs[ins.src]
    requires ins.St? ==> ins.base <= 10 && a == s.regs[ins.base] + Sext16(ins.off) && v == Sext32(ins.imm)
    requires S.Step(w.sp.floor, ins, s, prefix) == S.StoreStep(s, a, wd, v)
    ensures Post(w, c, s, prefix, fuel, rest)
    decreases (if w.sp.hookCalls then 1 else 0), fuel, 1
  {
    WinPreFacts(w);
    var fl := w.sp.floor;
    AtFromWin(w, c, s, ins);
    DecodeWidth(S.InsnAt(w.raw, s.pc));
    var s' := S.StoreStep(s, a, wd, v).s;
    var e := S.EStore(a, wd);
    assert s'.events == s.events + [e];
    if !EventOk(w.sp, w.s0, e) {
      BadPost(w, c, s, prefix, fuel, ins, s'); rest := [];
      return;
    }
    SideFacts(w, c, s);
    assert w.s0.regs[10] == s.regs[10];
    assert S.InFrame(S.Rel(a, s.regs[10]), wd);
    StoreSim(c, s, w.base, a, wd, v);
    var c' := InsStore(c, a, wd, v).c;
    var o := S.Rel(a, s.regs[10]) + STK;
    assert o + wd <= STK as int + fl;
    SideEvent(w, c, s, c', s', e);
    assert IExec(w.x, w.Pp.hooks, w.obsv, ins, c) == InsStore(c, a, wd, v);
    StepGo(w, c, ins, Go(c'));
    assert prefix + [] == prefix;
    assert Pre(w, c', s', prefix + []);
    rest := Advance(w, c, s, prefix, fuel, ins, [], 1, c', s');
  }

  // ---------------- hook calls ----------------

  lemma {:isolate_assertions} BHook(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat, imm: bv32) returns (rest: seq<bv64>)
    requires Pre(w, c, s, prefix) && 0 <= s.pc < S.NumInsns(w.raw) && s.pc != w.hp && fuel > 0
    requires S.Decode(S.InsnAt(w.raw, s.pc)) == Some(S.CallLocal(imm))
    ensures Post(w, c, s, prefix, fuel, rest)
    decreases (if w.sp.hookCalls then 1 else 0), fuel, 1
  {
    WinPreFacts(w); WinPreAt(w);
    var fl := w.sp.floor;
    var ins := S.CallLocal(imm);
    AtFromWin(w, c, s, ins);
    var e := S.EHook(s.pc, s.regs[1..6], s.regs[0], s.regs[10]);
    StepHook(fl, imm, s, prefix);
    if !w.sp.hookCalls {
      BadPost(w, c, s, prefix, fuel, ins, S.HookStep(s, prefix).s); rest := [];
      return;
    }
    var k, c2 := HookRun(w.Pp, w.x, w.obsv, c, imm);
    var vals := R64(Top(c2))[0..6];
    StepHook(fl, imm, s, prefix + vals);
    var s' := S.HookStep(s, prefix + vals).s;
    forall j | 0 <= j < 6 ensures S.Orc(prefix + vals, s.oc + j) == vals[j] {}
    assert s'.regs == R64(Top(c2));
    assert s'.events == s.events + [e];
    SideFacts(w, c, s);
    SideEvent(w, c, s, c2, s', e);
    assert BR(c2, s', w.base);
    assert Pre(w, c2, s', prefix + vals);
    rest := Advance(w, c, s, prefix, fuel, ins, vals, k, c2, s');
  }

  lemma UndW(x: Ctx, c: Cfg, k: nat) requires x.m.MR? ensures Und(x, c, k).W? {}

  // The frame a hook call pushes, after the observer ran.
  ghost function HookEntry(x: Ctx, obsv: Observer, c: Cfg, imm: bv32): Cfg {
    var f := Top(c);
    var t := f.pc + 1 + Signed32(imm);
    if t < 0 then c
    else match Push(x, c, t, t, Ins, seq(5, k requires 0 <= k < 5 => Reg(f, k + 1)))
      case Go(c1) => obsv(c1, R64(f)[1..6])
      case _ => c
  }

  lemma {:isolate_assertions} HookEnter(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, imm: bv32)
    requires x.m.MR? && SimPremises.A5(obsv) && 0 < |c.fr| < MAXF_RW && AtIns(Pp, c, S.CallLocal(imm))
    requires Top(c).pc + 1 + Signed32(imm) in Pp.hooks
    ensures var cH := HookEntry(x, obsv, c, imm);
      ReachR(Pp, x, obsv, c, 1) == Some(cH)
      && |cH.fr| == |c.fr| + 1 && Below(cH) == c.fr && cH.L == c.L && cH.h == c.h
      && FrameOk(Top(cH)) && Top(cH).pc == Top(c).pc + 1 + Signed32(imm) && Top(cH).kind == Ins
      && Top(cH).regs[10] == W(StackTop(|c.fr|))
  {
    var f := Top(c);
    var t := f.pc + 1 + Signed32(imm);
    var args := seq(5, k requires 0 <= k < 5 => Reg(f, k + 1));
    reveal Push(), ICall();
    var c1 := Push(x, c, t, t, Ins, args).c;
    assert Push(x, c, t, t, Ins, args).Go?;
    assert ICall(x, Pp.hooks, obsv, c, imm) == Go(obsv(c1, R64(f)[1..6]));
    StepIns(Pp, x, obsv, c, S.CallLocal(imm));
    var cH := obsv(c1, R64(f)[1..6]);
    assert t >= 0;
    assert HookEntry(x, obsv, c, imm) == cH;
    assert cH == c1.(os := cH.os);
    assert Top(cH) == Top(c1);
    var st := seq(STK, i requires 0 <= i < STK => UndB(x, c, NR + i));
    assert Top(c1).stack == st;
    forall o | 0 <= o < STK ensures st[o].B? { assert st[o] == UndB(x, c, NR + o); assert !x.m.MP?; }
  }

  lemma {:isolate_assertions} HookRun(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, imm: bv32) returns (k: nat, c2: Cfg)
    requires x.m.MR? && SimPremises.A5(obsv) && HooksOk(Pp) && 0 < |c.fr| < MAXF_RW && FrameOk(Top(c))
    requires AtIns(Pp, c, S.CallLocal(imm)) && Top(c).pc + 1 + Signed32(imm) in Pp.hooks
    ensures ReachR(Pp, x, obsv, c, k) == Some(c2)
    ensures |c2.fr| == |c.fr| && Below(c2) == Below(c) && c2.L == c.L && c2.h == c.h
    ensures FrameOk(Top(c2)) && Top(c2).pc == Top(c).pc + 1 && Top(c2).stack == Top(c).stack
    ensures Top(c2).kind == Top(c).kind && Top(c2).fn == Top(c).fn
    ensures forall r | 6 <= r < NR :: Top(c2).regs[r] == Top(c).regs[r]
    decreases 1, 0, 0
  {
    var t: nat := Top(c).pc + 1 + Signed32(imm);
    HookEnter(Pp, x, obsv, c, imm);
    var cH := HookEntry(x, obsv, c, imm);
    var body :| HookAt(Pp, t, body);
    var sp := Api.HookBodySpec();
    var s0 := S.InitState(R64(Top(cH)), Plain(Top(cH).stack));
    var w := Win(Pp, x, obsv, body, sp, t, -1, Exit, 0, HCtx(0, [], EMg(0), Bot, map[]), cH, s0);
    assert WinPre(w) by { reveal WinPreO(); }
    var fuel := S.NumInsns(body) + 1;
    SideInit(w);
    var rest := Bridge(w, cH, s0, [], fuel);
    Soundness.Soundness(body, sp, s0.regs, s0.stack, rest, fuel);
    var O := S.Run(body, sp.floor, s0, [] + rest, fuel);
    assert [] + rest == rest;
    assert O.Exited? && FinalOk(sp, s0, O.s);
    assert FinalOkO(sp, s0, O.s) by { reveal FinalOkO(); }
    var kE: nat, cE: Cfg := EndsGet(w, cH, O.s, true);
    // the hook's exit returns to the caller
    SideFacts(w, cE, O.s);
    assert CountHelpers(O.s.events) == 0;
    Side0(w, cE, O.s);
    assert Below(cE) == c.fr && cE.L == c.L && cE.h == c.h && Top(cE).kind == Ins && FrameOk(Top(cE));
    c2 := HookReturn(Pp, x, obsv, c, cE);
    ReachAdd(Pp, x, obsv, c, 1, kE, cH);
    ReachAdd(Pp, x, obsv, c, 1 + kE, 1, cE);
    k := 1 + kE + 1;
  }

  // The exit of a hook frame resumes the caller with r0..r5 replaced.
  lemma {:isolate_assertions} HookReturn(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, cE: Cfg) returns (c2: Cfg)
    requires x.m.MR? && 0 < |c.fr| && FrameOk(Top(c))
    requires |cE.fr| == |c.fr| + 1 && Below(cE) == c.fr && Top(cE).kind == Ins && FrameOk(Top(cE))
    requires AtIns(Pp, cE, S.Exit)
    ensures ReachR(Pp, x, obsv, cE, 1) == Some(c2)
    ensures |c2.fr| == |c.fr| && Below(c2) == Below(c) && c2.L == cE.L && c2.h == cE.h
    ensures FrameOk(Top(c2)) && Top(c2).pc == Top(c).pc + 1 && Top(c2).stack == Top(c).stack
    ensures Top(c2).kind == Top(c).kind && Top(c2).fn == Top(c).fn
    ensures forall r | 6 <= r < NR :: Top(c2).regs[r] == Top(c).regs[r]
  {
    var v := Top(cE).regs[0].w;
    assert Reg(Top(cE), 0) == W(v);
    StepIns(Pp, x, obsv, cE, S.Exit);
    var cP := Pop(cE);
    assert cP.fr == Below(cE) == c.fr;
    assert Top(cP) == Top(c);
    assert ExitO(x, cE) == ExitFrame(x, cE, v) by { reveal ExitO(); }
    assert ExitFrame(x, cE, v) == Finish(x, cP, W(v), map[]) by { reveal ExitFrame(); }
    FinishFacts(x, cP, W(v), map[]);
    SimFacts.ApplyNone(cP);
    ApplyWAt(cP, map[]);
    var r := Finish(x, cP, W(v), map[]);
    c2 := r.c;
    assert StepR(Pp, x, obsv, cE) == r;
    assert ApplyF(Top(cP), |cP.fr| - 1, map[]) == Top(cP);
    assert Top(c2).stack == Top(c).stack;
    forall k | 0 <= k < NR ensures Top(c2).regs[k].W? {
      if k == 0 { assert Top(c2).regs[0] == W(v); }
      else if k <= 5 { UndW(x, cP, k); assert Top(c2).regs[k] == Und(x, cP, k); }
      else { assert Top(c2).regs[k] == Top(c).regs[k]; }
    }
    assert FrameOk(Top(c2));
  }

  // ---------------- the central helper ----------------

  ghost function ApplyF(f: Frame, d: nat, wr: map<int, bv8>): Frame {
    f.(stack := seq(|f.stack|, o requires 0 <= o < |f.stack| =>
      if d < MAXF_RW && o < STK && SAddr(d, o) as int in wr then B(wr[SAddr(d, o) as int]) else f.stack[o]))
  }
  ghost function ApplyL(l: Local, wr: map<int, bv8>): Local {
    l.(mem := map a | a in l.mem :: if a in wr && !InStackArea(a) then wr[a] else l.mem[a])
  }

  lemma ApplyWAt(c: Cfg, wr: map<int, bv8>)
    ensures |ApplyW(c, wr).fr| == |c.fr| && ApplyW(c, wr).L == ApplyL(c.L, wr)
    ensures forall d | 0 <= d < |c.fr| :: ApplyW(c, wr).fr[d] == ApplyF(c.fr[d], d, wr)
    ensures ApplyW(c, wr).h == c.h && ApplyW(c, wr).hc == c.hc && ApplyW(c, wr).os == c.os
  { reveal ApplyW(); }

  lemma FootSame(c: Cfg, c0: Cfg, addrs: seq<bv64>, floor: int)
    requires |c.fr| == |c0.fr| > 0 && c.L == c0.L && Below(c) == Below(c0)
    requires |Top(c).stack| == STK && |Top(c0).stack| == STK
    requires forall i | 0 <= i && STK as int + floor <= i < STK :: Top(c).stack[i] == Top(c0).stack[i]
    requires FootTop(c0, addrs, floor)
    ensures FootBytes(c, addrs) == FootBytes(c0, addrs)
    decreases |addrs|
  {
    reveal FootBytes();
    if |addrs| > 0 {
      assert FootTop(c0, addrs[1..], floor) by {
        forall i | 0 <= i < |addrs[1..]| ensures
          match Classify(addrs[1..][i], 1, |c0.fr|, c0.L.mem.Keys)
          case InStack(d, o) => d == |c0.fr| - 1 ==> o >= STK as int + floor
          case _ => true
        { assert addrs[1..][i] == addrs[i + 1]; }
      }
      FootSame(c, c0, addrs[1..], floor);
      match Classify(addrs[0], 1, |c.fr|, c.L.mem.Keys)
      case InStack(d, o) =>
        if d < |c.fr| - 1 { assert c.fr[d] == Below(c)[d] == Below(c0)[d] == c0.fr[d]; }
        else if d == |c.fr| - 1 && o < STK { assert StackBytes(c, d, o, 1) == StackBytes(c0, d, o, 1); }
      case _ =>
    }
  }

  // The resumption after a helper, in either run.
  lemma {:isolate_assertions} FinishFacts(x: Ctx, c: Cfg, v: Val, wr: map<int, bv8>)
    requires |c.fr| > 0 && |Top(c).regs| == NR
    ensures Finish(x, c, v, wr).Go?
    ensures var c' := Finish(x, c, v, wr).c; var a := ApplyW(c, wr); var t := |c.fr| - 1;
      |c'.fr| == |c.fr| && Below(c') == Below(a) && c'.L == a.L && c'.h == c.h && c'.hc == c.hc + 6 && c'.os == c.os
      && Top(c').pc == Top(c).pc + 1 && Top(c').kind == Top(c).kind && Top(c').fn == Top(c).fn
      && |Top(c').regs| == NR
      && Top(c').regs[0] == (if v.W? then v else Und(x, c, 0))
      && (forall k | 1 <= k <= 5 :: Top(c').regs[k] == Und(x, c, k))
      && (forall k | 6 <= k < NR :: Top(c').regs[k] == Top(c).regs[k])
      && Top(c').stack == ApplyF(Top(c), t, wr).stack
  {
    reveal Finish();
    ApplyWAt(c, wr);
    var a := ApplyW(c, wr);
    var t := |c.fr| - 1;
    assert Top(a) == ApplyF(Top(c), t, wr);
    var f := Top(a);
    var regs := seq(|f.regs|, k requires 0 <= k < |f.regs| =>
      if k == 0 then (if v.W? then v else Und(x, a, 0)) else if k <= 5 then Und(x, a, k) else f.regs[k]);
    PutTop(a, f.(pc := f.pc + 1, regs := regs));
  }

  lemma {:isolate_assertions} HelperWhole(w: Win, c: Cfg, s: S.CState) returns (c': Cfg)
    requires WinPre(w) && HasHelper(w) && BR(c, s, w.base) && Side(w, c, s) && CountHelpers(s.events) == 0
    requires s.pc == w.hp && s.regs[1..6] == w.s0.regs[1..6]
    ensures StepR(w.Pp, w.x, w.obsv, c) == Go(c')
    ensures |c'.fr| == |c.fr| && FrameOk(Top(c')) && Top(c').pc == Top(c).pc + 1
    ensures Top(c').kind == Top(c).kind && Top(c').fn == Top(c).fn
    ensures forall k | 6 <= k < NR :: Top(c').regs[k] == Top(c).regs[k]
    ensures w.hc.v.W? ==> Top(c').regs[0] == w.hc.v
    ensures forall o | 0 <= o < STK :: Top(c').stack[o] == ApplyF(Top(c), |c.fr| - 1, w.hc.wr).stack[o]
    ensures forall o | 0 <= o < STK && o < STK as int + w.sp.floor :: Top(c').stack[o] == Top(c).stack[o]
    ensures Below(c') == Below(ApplyW(c, w.hc.wr)) && c'.L == ApplyL(c.L, w.hc.wr) && c'.h == c.h + [w.hc.eh]
  {
    WinPreFacts(w); WinPreAt(w); WinPreHelper(w);
    SideFacts(w, c, s); Side0(w, c, s);
    var x := w.x;
    var id := w.hins.id;
    var n := w.hc.n;
    var f := Top(c);
    var f0 := Top(w.c0);
    assert w.Pp.code[f.pc] == O(Hcall(false, id), w.hidx);
    assert StepR(w.Pp, x, w.obsv, c) == HelperStep(x, c, w.hidx, false, id, false);
    // the arguments are the entry's
    forall i | 0 <= i < |Upto(1, n)| ensures Reg(f, Upto(1, n)[i]).W? && Reg(f, Upto(1, n)[i]) == Reg(f0, Upto(1, n)[i]) {
      UptoAt(1, n, i);
      var r := Upto(1, n)[i];
      assert R64(f)[r] == s.regs[r] == w.s0.regs[r] == R64(f0)[r];
    }
    SimFacts.RdsAll(f, Upto(1, n));
    var args := SimFacts.Words(f, Upto(1, n));
    assert args == SimFacts.Words(f0, Upto(1, n));
    FootSame(c, w.c0, w.hc.addrs, w.sp.floor);
    assert Wh(c) == Wh(w.c0);
    var c1 := c.(h := c.h + [w.hc.eh]);
    assert HelperStep(x, c, w.hidx, false, id, false) == Finish(x, c1, w.hc.v, w.hc.wr) by { reveal HelperStep(); }
    FinishFacts(x, c1, w.hc.v, w.hc.wr);
    c' := Finish(x, c1, w.hc.v, w.hc.wr).c;
    ApplyWAt(c1, w.hc.wr);
    ApplyWAt(c, w.hc.wr);
    assert Below(ApplyW(c1, w.hc.wr)) == Below(ApplyW(c, w.hc.wr));
    var t := |c.fr| - 1;
    assert t == |w.c0.fr| - 1;
    forall o | 0 <= o < STK && o < STK as int + w.sp.floor ensures Top(c').stack[o] == Top(c).stack[o] {
      assert SAddr(t, o) as int !in w.hc.wr;
    }
    forall k | 0 <= k < NR ensures Top(c').regs[k].W? {
      if 6 <= k { assert Top(c').regs[k] == f.regs[k]; }
    }
    forall o | 0 <= o < STK ensures Top(c').stack[o].B? {}
  }

  // The region's helper step from the whole model's result.
  lemma {:isolate_assertions} HelperBR(fl: int, id: bv32, c: Cfg, s: S.CState, base: int, c': Cfg, prefix: seq<bv64>)
    returns (vals: seq<bv64>, s': S.CState)
    requires BR(c, s, base) && -(S.STACK as int) <= fl <= 0 && s.oc == |prefix|
    requires |c'.fr| == |c.fr| && FrameOk(Top(c')) && Top(c').pc == Top(c).pc + 1
    requires forall k | 6 <= k < NR :: Top(c').regs[k] == Top(c).regs[k]
    requires forall o | 0 <= o < STK && o < STK as int + fl :: Top(c').stack[o] == Top(c).stack[o]
    ensures S.Step(fl, S.CallHelper(id), s, prefix + vals) == S.Next(s') && S.CWF(s')
    ensures BR(c', s', base) && s'.oc == |prefix + vals| && s.oc + Need(fl, S.CallHelper(id), s) <= |prefix + vals|
    ensures s'.events == s.events + [S.EHelper(s.regs[1..6], s'.regs[0], s'.stack, id)]
    ensures s'.regs == R64(Top(c')) && s'.stack == Plain(Top(c').stack)
  {
    var f2 := Top(c');
    var lo := STK as int + fl;
    var up := -fl;
    vals := R64(f2)[0..6] + seq(up, j requires 0 <= j < up => Zext8(Plain(f2.stack)[lo + j]));
    StepHelper(fl, id, s, prefix + vals);
    s' := S.HelperStep(fl, s, prefix + vals, id).s;
    forall j | 0 <= j < 6 + up ensures S.Orc(prefix + vals, s.oc + j) == vals[j] {}
    assert s'.regs == S.HavocRegs(s.regs, prefix + vals, s.oc, 6);
    assert s'.stack == S.HelperStack(fl, s, prefix + vals);
    forall k | 0 <= k < NR ensures s'.regs[k] == R64(f2)[k] {
      if k >= 6 { assert s'.regs[k] == s.regs[k]; assert R64(f2)[k] == R64(Top(c))[k]; }
      else { assert s'.regs[k] == S.Orc(prefix + vals, s.oc + k) == vals[k]; }
    }
    forall i | 0 <= i < S.STACK ensures s'.stack[i] == Plain(f2.stack)[i] {
      if i >= lo {
        assert s'.stack[i] == ByteOf(S.Orc(prefix + vals, s.oc + 6 + (i - lo)), 0);
        assert S.Orc(prefix + vals, s.oc + 6 + (i - lo)) == vals[6 + (i - lo)] == Zext8(Plain(f2.stack)[i]);
        ByteOfZext(Plain(f2.stack)[i]);
      } else {
        assert s'.stack[i] == s.stack[i];
        assert f2.stack[i] == Top(c).stack[i];
      }
    }
    assert s'.regs == R64(f2);
    assert s'.stack == Plain(f2.stack);
  }

  lemma {:isolate_assertions} SideHelper(w: Win, c: Cfg, s: S.CState, c': Cfg, s': S.CState)
    requires WinPre(w) && Side(w, c, s) && CountHelpers(s.events) == 0
    requires |Top(c').stack| == STK && |Top(c).stack| == STK && |Top(c').regs| == NR
    requires |c'.fr| == |c.fr| && Top(c').kind == Top(c).kind && Top(c').fn == Top(c).fn
    requires forall o | 0 <= o < STK :: Top(c').stack[o] == ApplyF(Top(c), |c.fr| - 1, w.hc.wr).stack[o]
    requires Below(c') == Below(ApplyW(c, w.hc.wr)) && c'.L == ApplyL(c.L, w.hc.wr) && c'.h == c.h + [w.hc.eh]
    requires |Top(c').stack| == STK
    requires exists e :: s'.events == s.events + [e] && e.EHelper? && e.stackAfter == Plain(Top(c').stack) && e.ret == R64(Top(c'))[0]
    requires w.hc.v.W? ==> Top(c').regs[0] == w.hc.v
    ensures Side(w, c', s')
  {
    SideFacts(w, c, s); Side0(w, c, s);
    var e :| s'.events == s.events + [e] && e.EHelper? && e.stackAfter == Plain(Top(c').stack) && e.ret == R64(Top(c'))[0];
    Soundness.EventsSnoc(s.events, e, w.s0.stack);
    var a := ApplyW(w.c0, w.hc.wr);
    ApplyWAt(w.c0, w.hc.wr);
    ApplyWAt(c, w.hc.wr);
    var t := |c.fr| - 1;
    forall d | 0 <= d < t ensures Below(c')[d] == Below(a)[d] {
      assert c.fr[d] == Below(c)[d] == Below(w.c0)[d] == w.c0.fr[d];
    }
    assert Top(a) == ApplyF(Top(w.c0), t, w.hc.wr);
    forall i | 0 <= i && STK as int + w.sp.floor <= i < STK
      ensures UpperBase(s'.events, w.s0.stack)[i] == Plain(Top(a).stack)[i]
    {
      assert Top(c).stack[i] == Top(w.c0).stack[i];
    }
    reveal Side();
  }

  lemma UptoAt(lo: nat, hi: nat, i: nat)
    requires i < |Upto(lo, hi)|
    ensures |Upto(lo, hi)| == (if lo > hi then 0 else hi - lo + 1) && Upto(lo, hi)[i] == lo + i
    decreases hi - lo
  {
    if lo <= hi && i > 0 { UptoAt(lo + 1, hi, i - 1); }
  }

  lemma {:isolate_assertions} BHelper(w: Win, c: Cfg, s: S.CState, prefix: seq<bv64>, fuel: nat) returns (rest: seq<bv64>)
    requires Pre(w, c, s, prefix) && s.pc == w.hp && 0 <= s.pc < S.NumInsns(w.raw) && fuel > 0
    ensures Post(w, c, s, prefix, fuel, rest)
    decreases (if w.sp.hookCalls then 1 else 0), fuel, 1
  {
    WinPreFacts(w); WinPreAt(w);
    var fl := w.sp.floor;
    var id := w.hins.id;
    var ins := S.CallHelper(id);
    assert HasHelper(w);
    assert S.Decode(S.InsnAt(w.raw, s.pc)) == Some(ins);
    StepHelper(fl, id, s, prefix);
    var sB := S.HelperStep(fl, s, prefix, id).s;
    var eB := S.EHelper(s.regs[1..6], S.HavocRegs(s.regs, prefix, s.oc, 6)[0], S.HelperStack(fl, s, prefix), id);
    assert sB.events == s.events + [eB];
    Soundness.EventsSnoc(s.events, eB, w.s0.stack);
    if CountHelpers(s.events) != 0 {
      BadPost(w, c, s, prefix, fuel, ins, sB); rest := [];
      return;
    }
    if s.regs[1..6] != w.s0.regs[1..6] {
      assert !EventOk(w.sp, w.s0, eB);
      BadPost(w, c, s, prefix, fuel, ins, sB); rest := [];
      return;
    }
    var c' := HelperWhole(w, c, s);
    var vals, s' := HelperBR(fl, id, c, s, w.base, c', prefix);
    var e := S.EHelper(s.regs[1..6], s'.regs[0], s'.stack, id);
    assert s'.events == s.events + [e];
    SideFacts(w, c, s);
    SideHelper(w, c, s, c', s');
    assert Pre(w, c', s', prefix + vals);
    ReachOne(w.Pp, w.x, w.obsv, c, c');
    rest := Advance(w, c, s, prefix, fuel, ins, vals, 1, c', s');
  }
}
