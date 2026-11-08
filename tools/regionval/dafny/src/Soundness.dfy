// Soundness of the checker:
//   if Validate(region) == Validated then, for every concrete initial state
//   and every concrete execution (every oracle), the obligations hold.
//
// Structure:
//   - Sim: the symbolic state denotes the concrete state under the
//       assignment Env(entry regs, entry stack, sigma), where sigma is the
//       list of every value the run obtained from outside.  Fresh symbol n
//       stands for sigma[n], so havoc covers every concrete value.
//   - StepSim: each symbolic step agrees with the concrete step.
//   - Terms.Mk*Eval: the normaliser preserves evaluation.
//   - ExecSound: the concrete run follows one of the enumerated paths
//       (for P8 through WP, call W, W's body and the return);
//       path conditions are not used, so every path was checked.
//   - Fail-closed: an undecodable instruction makes the run Escaped, which
//       violates the obligations; Validate never accepts such a region.
include "Checker.dfy"

module Soundness {
  import opened Bits
  import opened Semantics
  import opened Terms
  import opened Obligations
  import opened Checker

  function EnvOf(s0: CState, sigma: seq<bv64>): Env { Env(s0.regs, s0.stack, sigma) }

  function LogOf(o: Outcome): seq<bv64> { o.s.log }

  predicate HelperStacksWF(evs: seq<Event>) {
    forall i :: 0 <= i < |evs| && evs[i].EHelper? ==> |evs[i].stackAfter| == STACK
  }

  // ---------------- simulation relation ----------------

  predicate Sim(sp: Spec, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>) {
    SWF(ss) && CWF(cs) && CWF(s0)
    && (forall k :: 0 <= k < NREGS ==> Eval(ss.regs[k], EnvOf(s0, sigma)) == cs.regs[k])
    && (forall i :: 0 <= i < STACK ==> EvalB(ss.stack[i], EnvOf(s0, sigma)) == cs.stack[i])
    && HelperStacksWF(cs.events) && |UpperBase(cs.events, s0.stack)| == STACK
    && (forall i :: 0 <= i < STACK ==> EvalB(ss.snap[i], EnvOf(s0, sigma)) == UpperBase(cs.events, s0.stack)[i])
    && ss.next == |cs.log| && cs.log <= sigma
    && ss.helpers == CountHelpers(cs.events) && ss.hooks == CountHooks(cs.events)
    && ss.helpers <= 1 && ss.hooks <= 1
    && Eval(ss.ret, EnvOf(s0, sigma)) == HelperRet(cs.events)
    && Eval(ss.hkey, EnvOf(s0, sigma)) == HelperKey(cs.events)
    && AllBound(sp, cs.events)
    && (forall i :: 0 <= i < |cs.events| ==> EventOk(sp, s0, cs.events[i]))
    && cs.regs[10] == s0.regs[10]
  }

  // ---------------- facts about event lists ----------------

  lemma EventsSnoc(evs: seq<Event>, e: Event, entry: seq<bv8>)
    ensures CountHelpers(evs + [e]) == CountHelpers(evs) + (if e.EHelper? then 1 else 0)
    ensures CountHooks(evs + [e]) == CountHooks(evs) + (if e.EHook? then 1 else 0)
    ensures HelperRet(evs + [e]) == if e.EHelper? then e.ret else HelperRet(evs)
    ensures HelperKey(evs + [e]) == if e.EHelper? then (if |e.args| >= 2 then e.args[1] else 0) else HelperKey(evs)
    ensures UpperBase(evs + [e], entry) == if e.EHelper? then e.stackAfter else UpperBase(evs, entry)
  {
    assert (evs + [e])[..|evs|] == evs;
  }

  // Appending an event that meets its Bind keeps AllBound (earlier events
  // keep their prefixes).
  lemma BoundSnoc(sp: Spec, evs: seq<Event>, e: Event)
    requires AllBound(sp, evs) && BindOk(sp, evs, e)
    ensures AllBound(sp, evs + [e])
  {
    var es := evs + [e];
    forall i | 0 <= i < |es| ensures BindOk(sp, es[..i], es[i]) {
      if i < |evs| {
        assert es[..i] == evs[..i] && es[i] == evs[i];
      } else {
        assert es[..i] == evs && es[i] == e;
      }
    }
  }

  lemma UpperBaseLen(evs: seq<Event>, entry: seq<bv8>)
    requires HelperStacksWF(evs) && |entry| == STACK
    ensures |UpperBase(evs, entry)| == STACK
  {
    if |evs| > 0 && !evs[|evs|-1].EHelper? {
      UpperBaseLen(evs[..|evs|-1], entry);
    }
  }

  // Appending an event that satisfies EventOk and is not a helper call keeps
  // every event-related conjunct of Sim.
  lemma SnocPlain(sp: Spec, s0: CState, evs: seq<Event>, e: Event)
    requires CWF(s0) && !e.EHelper? && EventOk(sp, s0, e)
    requires HelperStacksWF(evs) && (forall i :: 0 <= i < |evs| ==> EventOk(sp, s0, evs[i]))
    requires AllBound(sp, evs) && BindOk(sp, evs, e)
    ensures HelperStacksWF(evs + [e])
    ensures forall i :: 0 <= i < |evs + [e]| ==> EventOk(sp, s0, (evs + [e])[i])
    ensures CountHelpers(evs + [e]) == CountHelpers(evs)
    ensures HelperRet(evs + [e]) == HelperRet(evs)
    ensures HelperKey(evs + [e]) == HelperKey(evs)
    ensures AllBound(sp, evs + [e])
    ensures UpperBase(evs + [e], s0.stack) == UpperBase(evs, s0.stack)
  {
    EventsSnoc(evs, e, s0.stack);
    BoundSnoc(sp, evs, e);
  }

  // The same for the helper-call event, whose stack has the right length.
  lemma SnocHelper(sp: Spec, s0: CState, evs: seq<Event>, e: Event)
    requires CWF(s0) && e.EHelper? && |e.stackAfter| == STACK && EventOk(sp, s0, e)
    requires HelperStacksWF(evs) && (forall i :: 0 <= i < |evs| ==> EventOk(sp, s0, evs[i]))
    requires AllBound(sp, evs)
    ensures HelperStacksWF(evs + [e])
    ensures forall i :: 0 <= i < |evs + [e]| ==> EventOk(sp, s0, (evs + [e])[i])
    ensures AllBound(sp, evs + [e])
  {
    BoundSnoc(sp, evs, e);
  }

  // ---------------- unfolding equations for the opaque functions ----------------

  lemma StepEq(floor: int, ins: Instr, s: CState, oracle: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0
    ensures Step(floor, ins, s, oracle) ==
      match ins
      case Alu(is64, op, dst, opnd) => if dst >= 10 then Stuck else AluStep(s, is64, op, dst, opnd)
      case Ldx(w, dst, base, off) => if dst >= 10 || base > 10 || w > 8 then Stuck else LdxStep(s, w, dst, base, off, oracle)
      case Stx(w, base, src, off) =>
        if base > 10 || src > 10 || w > 8 then Stuck else StoreStep(s, s.regs[base] + Sext16(off), w, s.regs[src])
      case St(w, base, off, imm) =>
        if base > 10 || w > 8 then Stuck else StoreStep(s, s.regs[base] + Sext16(off), w, Sext32(imm))
      case Ja(off) => Next(s.(pc := s.pc + 1 + Signed16(off)))
      case Jcond(c, dst, imm, off) =>
        if dst > 10 then Stuck
        else Next(s.(pc := if CondHolds(c, s.regs[dst], imm) then s.pc + 1 + Signed16(off) else s.pc + 1))
      case CallHelper(id) => HelperStep(floor, s, oracle, id)
      case CallLocal(_) => HookStep(s, oracle)
      case Exit => Halt(s)
  { reveal Step(); }

  lemma RunEnd(raw: seq<bv8>, floor: int, s: CState, oracle: seq<bv64>, fuel: nat)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && s.pc == NumInsns(raw)
    ensures Run(raw, floor, s, oracle, fuel) == Done(s)
  { reveal Run(); }

  lemma RunAt(raw: seq<bv8>, floor: int, s: CState, oracle: seq<bv64>, fuel: nat, ins: Instr)
    requires CWF(s) && -(STACK as int) <= floor <= 0
    requires 0 <= s.pc < NumInsns(raw) && fuel > 0 && Decode(InsnAt(raw, s.pc)) == Some(ins)
    ensures Run(raw, floor, s, oracle, fuel) ==
      match Step(floor, ins, s, oracle)
      case Stuck => Escaped(s)
      case Halt(s') => Exited(s')
      case Next(s') => if CWF(s') then Run(raw, floor, s', oracle, fuel - 1) else Escaped(s')
  { reveal Run(); }

  // One concrete step that stays in the window: the run continues from there.
  lemma RunNext(raw: seq<bv8>, floor: int, s: CState, oracle: seq<bv64>, fuel: nat, ins: Instr, s': CState)
    requires CWF(s) && -(STACK as int) <= floor <= 0
    requires 0 <= s.pc < NumInsns(raw) && fuel > 0 && Decode(InsnAt(raw, s.pc)) == Some(ins)
    requires Step(floor, ins, s, oracle) == Next(s') && CWF(s')
    ensures Run(raw, floor, s, oracle, fuel) == Run(raw, floor, s', oracle, fuel - 1)
  { reveal Run(); }

  lemma RunHalt(raw: seq<bv8>, floor: int, s: CState, oracle: seq<bv64>, fuel: nat)
    requires CWF(s) && -(STACK as int) <= floor <= 0
    requires 0 <= s.pc < NumInsns(raw) && fuel > 0 && Decode(InsnAt(raw, s.pc)) == Some(Exit)
    ensures Run(raw, floor, s, oracle, fuel) == Exited(s)
  { reveal Run(); reveal Step(); }

  lemma SymExecEnd(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState, m: Mode)
    requires pc == |prog| && SWF(ss) && SpecWF(sp) && SymExec(prog, sp, pc, ss, m) == Validated
    ensures m.Top? ==> !sp.exitMode && Final(sp, ss, pc) == Validated
    ensures m.WP? ==> (forall k :: 0 <= k <= 9 && k != 4 ==> ss.regs[k] == Entry(k))
                      && SymExec(m.wprog, sp, 0, EnterWS(ss), WBody(ss.regs)) == Validated
    ensures !m.WBody?
  { reveal SymExec(); }

  lemma SymExecExit(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState, m: Mode)
    requires pc < |prog| && prog[pc].Exit? && SWF(ss) && SpecWF(sp) && SymExec(prog, sp, pc, ss, m) == Validated
    ensures m.Top? ==> sp.exitMode && Final(sp, ss, pc) == Validated
    ensures m.WBody? ==> ss.regs[0] == ss.ret && |m.caller| == NREGS && Final(sp, ReturnS(ss, m.caller), pc) == Validated
    ensures !m.WP?
  { reveal SymExec(); }

  lemma SymExecJa(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState, m: Mode)
    requires pc < |prog| && prog[pc].Ja? && SWF(ss) && SpecWF(sp) && SymExec(prog, sp, pc, ss, m) == Validated
    ensures var t := Target(pc, prog[pc].off);
            pc < t <= |prog| && SymExec(prog, sp, t, ss, m) == Validated
  { reveal SymExec(); }

  lemma SymExecJcond(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState, m: Mode)
    requires pc < |prog| && prog[pc].Jcond? && SWF(ss) && SpecWF(sp) && SymExec(prog, sp, pc, ss, m) == Validated
    ensures var t := Target(pc, prog[pc].off);
            prog[pc].dst < NREGS && pc < t <= |prog|
            && SymExec(prog, sp, pc + 1, ss, m) == Validated && SymExec(prog, sp, t, ss, m) == Validated
  { reveal SymExec(); }

  lemma SymExecStep(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState, m: Mode)
    requires pc < |prog| && !prog[pc].Exit? && !prog[pc].Ja? && !prog[pc].Jcond?
    requires SWF(ss) && SpecWF(sp) && SymExec(prog, sp, pc, ss, m) == Validated
    ensures SymStep(sp, prog[pc], ss).SOk? && SWF(SymStep(sp, prog[pc], ss).ss)
            && SymExec(prog, sp, pc + 1, SymStep(sp, prog[pc], ss).ss, m) == Validated
    ensures prog[pc].CallLocal? ==> BindFail(sp, pc, ss) == ""
  { reveal SymExec(); }

  // ---------------- (2) each symbolic step agrees with the concrete step ----------------

  lemma AluTermEval(is64: bool, op: AluOp, a: Term, b: Term, e: Env)
    ensures Eval(AluTerm(is64, op, a, b), e) == AluVal(is64, op, Eval(a, e), Eval(b, e))
  {
    var x, y := Eval(a, e), Eval(b, e);
    if is64 {
      match op
      case Add => MkAddEval(a, b, e);
      case And => EvAnd(a, b, e);
      case Or => EvOr(a, b, e);
      case Lsh => EvLsh(a, b, e);
      case Mov =>
    } else {
      match op
      case Add => MkAddEval(a, b, e); MkZextEval(AddT(a, b), e); MkZextEval(MkAdd(a, b), e);
      case And => EvAnd(a, b, e); MkZextEval(AndT(a, b), e);
      case Or => EvOr(a, b, e); MkZextEval(OrT(a, b), e);
      case Lsh =>
        EvConst(31, e); EvAnd(b, Const(31), e); EvLsh(a, AndT(b, Const(31)), e);
        MkZextEval(LshT(a, AndT(b, Const(31))), e);
        MaskMask(y);
      case Mov => MkZextEval(b, e);
    }
  }

  lemma MaskMask(y: bv64)
    ensures (y & 31) & 63 == y & 31
  {}

  lemma {:isolate_assertions} OperandEval(is64: bool, o: Operand, ss: SState, cs: CState, e: Env)
    requires SWF(ss) && CWF(cs)
    requires forall k :: 0 <= k < NREGS ==> Eval(ss.regs[k], e) == cs.regs[k]
    ensures Eval(SymOperand(is64, o, ss.regs), e) == OperandVal(is64, o, cs.regs)
  {
    match o
    case Reg(r) =>
      if r >= NREGS {
        EvConst(0, e);
      } else {
        assert SymOperand(is64, o, ss.regs) == ss.regs[r];
        assert OperandVal(is64, o, cs.regs) == cs.regs[r];
      }
    case Imm(k) =>
      var c := if is64 then Sext32(k) else k as bv64;
      assert SymOperand(is64, o, ss.regs) == Const(c);
      assert OperandVal(is64, o, cs.regs) == c;
      EvConst(c, e);
  }

  // Address r[base] + off: its value, and when it is r10 + c, its frame offset.
  lemma {:isolate_assertions} AddrEval(ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, base: nat, off: bv16)
    requires SWF(ss) && CWF(cs) && CWF(s0) && base < NREGS && cs.regs[10] == s0.regs[10]
    requires forall k :: 0 <= k < NREGS ==> Eval(ss.regs[k], EnvOf(s0, sigma)) == cs.regs[k]
    ensures Eval(AddrTerm(ss, base, off), EnvOf(s0, sigma)) == cs.regs[base] + Sext16(off)
    ensures FpOff(AddrTerm(ss, base, off)).Some? ==>
              Rel(cs.regs[base] + Sext16(off), cs.regs[10]) == Signed64(FpOff(AddrTerm(ss, base, off)).value)
  {
    var e := EnvOf(s0, sigma);
    var t := AddrTerm(ss, base, off);
    MkAddEval(ss.regs[base], Const(Sext16(off)), e);
    EvConst(Sext16(off), e);
    if FpOff(t).Some? {
      FpOffEval(t, e);
      SubOfAdd(s0.regs[10], FpOff(t).value);
    }
  }

  lemma AluSim(sp: Spec, ins: Instr, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, oracle: seq<bv64>)
    requires SpecWF(sp) && Sim(sp, ss, cs, s0, sigma) && ins.Alu?
    requires SymStep(sp, ins, ss).SOk?
    ensures var r := Step(sp.floor, ins, cs, oracle);
            r.Next? && r.s.pc == cs.pc + 1 && CWF(r.s) && r.s.log == cs.log
            && Sim(sp, SymStep(sp, ins, ss).ss, r.s, s0, sigma)
  {
    StepEq(sp.floor, ins, cs, oracle);
    var e := EnvOf(s0, sigma);
    var a := SymOperand(ins.is64, ins.opnd, ss.regs);
    OperandEval(ins.is64, ins.opnd, ss, cs, e);
    AluTermEval(ins.is64, ins.op, ss.regs[ins.dst], a, e);
  }

  lemma LoadValEq(s: CState, addr: bv64, w: nat, oracle: seq<bv64>)
    requires CWF(s) && w <= 8
    ensures var rel := Rel(addr, s.regs[10]);
            InFrame(rel, w) ==> LoadVal(s, addr, w, oracle) == LE(s.stack[rel + 512 .. rel + 512 + w])
  { reveal LoadVal(); }

  lemma {:isolate_assertions} LdxStepFacts(s: CState, w: nat, dst: nat, base: nat, off: bv16, oracle: seq<bv64>)
    requires CWF(s) && w <= 8 && dst < 10 && base <= 10
    ensures LdxStep(s, w, dst, base, off, oracle).Next?
    ensures LdxStep(s, w, dst, base, off, oracle).s.pc == s.pc + 1
    ensures LdxStep(s, w, dst, base, off, oracle).s.regs == s.regs[dst := LoadVal(s, s.regs[base] + Sext16(off), w, oracle)]
    ensures LdxStep(s, w, dst, base, off, oracle).s.stack == s.stack
    ensures LdxStep(s, w, dst, base, off, oracle).s.log == s.log + [LoadVal(s, s.regs[base] + Sext16(off), w, oracle)]
    ensures LdxStep(s, w, dst, base, off, oracle).s.events == s.events
  {}

  lemma {:isolate_assertions} LdxSim(sp: Spec, ins: Instr, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, oracle: seq<bv64>)
    requires SpecWF(sp) && Sim(sp, ss, cs, s0, sigma) && ins.Ldx?
    requires SymStep(sp, ins, ss).SOk?
    ensures var r := Step(sp.floor, ins, cs, oracle);
            r.Next? && r.s.pc == cs.pc + 1 && CWF(r.s) && cs.log <= r.s.log
            && (r.s.log <= sigma ==> Sim(sp, SymStep(sp, ins, ss).ss, r.s, s0, sigma))
  {
    StepEq(sp.floor, ins, cs, oracle);
    var e := EnvOf(s0, sigma);
    var w, dst, base, off := ins.size, ins.dst, ins.base, ins.off;
    var ss' := SymStep(sp, ins, ss).ss;
    var r := Step(sp.floor, ins, cs, oracle);
    AddrEval(ss, cs, s0, sigma, base, off);
    var addr := cs.regs[base] + Sext16(off);
    var rel := Rel(addr, cs.regs[10]);
    var v := LoadVal(cs, addr, w, oracle);
    assert dst < 10 && base < NREGS && w <= 8;
    assert r == LdxStep(cs, w, dst, base, off, oracle);
    LdxStepFacts(cs, w, dst, base, off, oracle);
    if r.s.log <= sigma {
      var t := AddrTerm(ss, base, off);
      var vt := ss'.regs[dst];
      if FpOff(t).Some? && InFrame(Signed64(FpOff(t).value), w) {
        var idx := rel + 512;
        var sl := ss.stack[idx .. idx + w];
        assert rel == Signed64(FpOff(t).value);
        assert vt == MkBytes(sl);
        MkBytesEval(sl, e);
        forall j | 0 <= j < w ensures EvalBs(sl, e)[j] == cs.stack[idx .. idx + w][j] {
          assert sl[j] == ss.stack[idx + j];
          assert EvalB(ss.stack[idx + j], e) == cs.stack[idx + j];
        }
        assert EvalBs(sl, e) == cs.stack[idx .. idx + w];
        LoadValEq(cs, addr, w, oracle);
        assert v == LE(cs.stack[idx .. idx + w]);
        assert Eval(vt, e) == v;
      } else {
        assert vt == Fresh(ss.next);
        EvFresh(ss.next, e);
        assert sigma[ss.next] == v;
        assert Eval(vt, e) == v;
      }
    }
  }

  lemma {:isolate_assertions} StoreSim(sp: Spec, ins: Instr, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, oracle: seq<bv64>)
    requires SpecWF(sp) && Sim(sp, ss, cs, s0, sigma) && (ins.Stx? || ins.St?)
    requires SymStep(sp, ins, ss).SOk?
    ensures var r := Step(sp.floor, ins, cs, oracle);
            r.Next? && r.s.pc == cs.pc + 1 && CWF(r.s) && r.s.log == cs.log
            && Sim(sp, SymStep(sp, ins, ss).ss, r.s, s0, sigma)
  {
    StepEq(sp.floor, ins, cs, oracle);
    var e := EnvOf(s0, sigma);
    var w, base, off := ins.size, ins.base, ins.off;
    var vt := if ins.Stx? then ss.regs[ins.src] else Const(Sext32(ins.imm));
    var v := if ins.Stx? then cs.regs[ins.src] else Sext32(ins.imm);
    if ins.St? { EvConst(Sext32(ins.imm), e); }
    assert Eval(vt, e) == v;
    assert SymStep(sp, ins, ss) == SymStore(sp, ss, base, off, w, vt);
    var t := AddrTerm(ss, base, off);
    AddrEval(ss, cs, s0, sigma, base, off);
    var c := FpOff(t).value;
    var o := Signed64(c);
    var addr := cs.regs[base] + Sext16(off);
    assert Rel(addr, cs.regs[10]) == o;
    assert InFrame(o, w);
    var r := Step(sp.floor, ins, cs, oracle);
    assert r == StoreStep(cs, addr, w, v);
    var ss' := SymStep(sp, ins, ss).ss;
    assert ss'.stack == WriteBT(ss.stack, o + STACK, StoreBytes(vt, w));
    assert r.s.stack == WriteBytes(cs.stack, o + 512, BytesOf(v, w));
    forall i | 0 <= i < STACK
      ensures EvalB(ss'.stack[i], e) == r.s.stack[i]
    {
      if o + 512 <= i < o + 512 + w {
        EvBOf(vt, i - (o + 512), e);
      }
    }
    var ev := EStore(addr, w);
    assert EventOk(sp, s0, ev);
    SnocPlain(sp, s0, cs.events, ev);
    EventsSnoc(cs.events, ev, s0.stack);
  }

  lemma {:isolate_assertions} HelperSim(sp: Spec, ins: Instr, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, oracle: seq<bv64>)
    requires SpecWF(sp) && Sim(sp, ss, cs, s0, sigma) && ins.CallHelper?
    requires SymStep(sp, ins, ss).SOk?
    ensures var r := Step(sp.floor, ins, cs, oracle);
            r.Next? && r.s.pc == cs.pc + 1 && CWF(r.s) && cs.log <= r.s.log
            && (r.s.log <= sigma ==> Sim(sp, SymStep(sp, ins, ss).ss, r.s, s0, sigma))
  {
    StepEq(sp.floor, ins, cs, oracle);
    var e := EnvOf(s0, sigma);
    var r := Step(sp.floor, ins, cs, oracle);
    var ss' := SymStep(sp, ins, ss).ss;
    var lo := STACK as int + sp.floor;
    var up := -sp.floor;
    var regs' := HavocRegs(cs.regs, oracle, cs.oc, 6);
    var newVals := regs'[0..6] + seq(up, j requires 0 <= j < up => Zext8(r.s.stack[lo + j]));
    assert r.s.log == cs.log + newVals;
    var ev := EHelper(cs.regs[1..6], regs'[0], r.s.stack, ins.id);
    assert r.s.events == cs.events + [ev];
    if r.s.log <= sigma {
      var n := ss.next;
      assert forall m :: 0 <= m < |newVals| ==> sigma[n + m] == newVals[m];
      // registers: r0..r5 are fresh symbols n..n+5, the rest unchanged
      forall k | 0 <= k < NREGS
        ensures Eval(ss'.regs[k], e) == r.s.regs[k]
      {
        if k < 6 { EvFresh(n + k, e); }
      }
      // stack: [f,0) holds fresh bytes n+6.., the rest unchanged
      forall i | 0 <= i < STACK
        ensures EvalB(ss'.stack[i], e) == r.s.stack[i]
      {
        if i >= lo {
          var m := n + 6 + (i - lo);
          assert ss'.stack[i] == BOf(Fresh(m), 0);
          assert newVals[6 + (i - lo)] == Zext8(r.s.stack[i]);
          assert m < |sigma| && sigma[m] == Zext8(r.s.stack[i]);
          HelperByteSim(m, r.s.stack[i], e);
        } else {
          assert ss'.stack[i] == ss.stack[i] && r.s.stack[i] == cs.stack[i];
        }
      }
      EventsSnoc(cs.events, ev, s0.stack);
      assert ss'.snap == ss'.stack;
      assert UpperBase(r.s.events, s0.stack) == r.s.stack;
      EvFresh(n, e);
      assert Eval(ss'.ret, e) == HelperRet(r.s.events);
      assert ss'.hkey == ss.regs[2] && ev.args[1] == cs.regs[2];
      assert Eval(ss'.hkey, e) == HelperKey(r.s.events);
      // the site rule: r1..r5 at the call are the entry values
      if sp.helper.checkArgs {
        var args := [Entry(1), Entry(2), Entry(3), Entry(4), Entry(5)];
        HelperArgsChecked(sp, ins, ss);
        forall k | 1 <= k < 6 ensures cs.regs[k] == s0.regs[k] {
          assert ss.regs[k] == ss.regs[1..6][k - 1] == args[k - 1] == Entry(k);
          EvEntry(k, e);
        }
        assert cs.regs[1..6] == s0.regs[1..6];
      }
      // P8 (rule R15): O[i], and r1, r2, r3, r5 (r4 unless a lookup) are the entry values
      if sp.wrap.Wrap? {
        HelperWrapChecked(sp, ins, ss);
        forall k | 1 <= k < 6 && ss.regs[k] == Entry(k) ensures cs.regs[k] == s0.regs[k] { EvEntry(k, e); }
      }
      assert EventOk(sp, s0, ev);
      SnocHelper(sp, s0, cs.events, ev);
      assert forall i :: 0 <= i < |r.s.events| ==> EventOk(sp, s0, r.s.events[i]);
      assert HelperStacksWF(r.s.events);
      assert Sim(sp, ss', r.s, s0, sigma);
    }
  }

  // A byte the helper wrote is the low byte of the fresh symbol that names it.
  lemma HelperByteSim(m: nat, b: bv8, e: Env)
    requires m < |e.log| && e.log[m] == Zext8(b)
    ensures EvalB(BOf(Fresh(m), 0), e) == b
  {
    EvBOf(Fresh(m), 0, e);
    EvFresh(m, e);
    ByteOfZext(b);
  }

  // SymStep accepted the helper call, so r1..r5 were syntactically the entry symbols.
  lemma HelperArgsChecked(sp: Spec, ins: Instr, ss: SState)
    requires ins.CallHelper? && SWF(ss) && SpecWF(sp) && SymStep(sp, ins, ss).SOk? && sp.helper.Helper? && sp.helper.checkArgs
    ensures ss.regs[1..6] == [Entry(1), Entry(2), Entry(3), Entry(4), Entry(5)]
  {}

  lemma HelperWrapChecked(sp: Spec, ins: Instr, ss: SState)
    requires ins.CallHelper? && SWF(ss) && SpecWF(sp) && SymStep(sp, ins, ss).SOk? && sp.wrap.Wrap?
    ensures Some(ins.id) == HelperIdOf(sp.wrap.helper) && WrapArgsSym(ins.id, ss.regs)
  {}

  // BindFail found nothing: every Bind at pc holds symbolically.
  lemma BindFailOk(bs: seq<Bind>, pc: nat, ss: SState, j: nat)
    requires SWF(ss) && BindFailFrom(bs, pc, ss, j) == ""
    ensures forall i :: j <= i < |bs| && bs[i].pc == pc ==>
              ss.helpers == 1 && 1 <= bs[i].reg <= 5
              && (bs[i].role.KeyArg? ==> ss.regs[bs[i].reg] == ss.hkey)
              && (bs[i].role.ValueArg? ==> ss.regs[bs[i].reg] == ss.ret)
              && (bs[i].role.CopyArg? ==> CopyHolds(ss.regs[bs[i].reg], bs[i].role.off, ss))
    decreases |bs| - j
  {
    if j < |bs| { BindFailOk(bs, pc, ss, j + 1); }
  }

  lemma {:isolate_assertions} HookSim(sp: Spec, ins: Instr, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, oracle: seq<bv64>)
    requires SpecWF(sp) && Sim(sp, ss, cs, s0, sigma) && ins.CallLocal?
    requires SymStep(sp, ins, ss).SOk?
    requires cs.pc >= 0 && BindFail(sp, cs.pc, ss) == ""
    ensures var r := Step(sp.floor, ins, cs, oracle);
            r.Next? && r.s.pc == cs.pc + 1 && CWF(r.s) && cs.log <= r.s.log
            && (r.s.log <= sigma ==> Sim(sp, SymStep(sp, ins, ss).ss, r.s, s0, sigma))
  {
    StepEq(sp.floor, ins, cs, oracle);
    var e := EnvOf(s0, sigma);
    var r := Step(sp.floor, ins, cs, oracle);
    var ss' := SymStep(sp, ins, ss).ss;
    var regs' := HavocRegs(cs.regs, oracle, cs.oc, 6);
    assert r.s.log == cs.log + regs'[0..6];
    if r.s.log <= sigma {
      var n := ss.next;
      forall k | 0 <= k < NREGS
        ensures Eval(ss'.regs[k], e) == r.s.regs[k]
      {
        if k < 6 { EvFresh(n + k, e); assert sigma[n + k] == regs'[k]; }
      }
      var ev := EHook(cs.pc, cs.regs[1..6], cs.regs[0], cs.regs[10]);
      assert r.s.events == cs.events + [ev];
      BindFailOk(sp.binds, cs.pc, ss, 0);
      forall j | 0 <= j < |sp.binds| && sp.binds[j].pc == ev.pc
        ensures var b := sp.binds[j];
                CountHelpers(cs.events) == 1 && 1 <= b.reg <= 5 && |ev.args| == 5
                && match b.role
                   case KeyArg => ev.args[b.reg - 1] == HelperKey(cs.events)
                   case ValueArg => ev.args[b.reg - 1] == HelperRet(cs.events)
                   case CopyArg(off) => Rel(ev.args[b.reg - 1], ev.fp) == off && ev.r0 == HelperRet(cs.events)
      {
        var b := sp.binds[j];
        assert ev.args[b.reg - 1] == cs.regs[b.reg];
        if b.role.CopyArg? {
          var t := ss.regs[b.reg];
          FpOffEval(t, e);
          EvEntry(10, e);
          SubOfAdd(s0.regs[10], FpOff(t).value);
          assert cs.regs[b.reg] == s0.regs[10] + FpOff(t).value;
        }
      }
      assert BindOk(sp, cs.events, ev);
      SnocPlain(sp, s0, cs.events, ev);
      EventsSnoc(cs.events, ev, s0.stack);
      assert Sim(sp, ss', r.s, s0, sigma);
    }
  }

  lemma StepSim(sp: Spec, ins: Instr, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, oracle: seq<bv64>)
    requires SpecWF(sp) && Sim(sp, ss, cs, s0, sigma)
    requires SymStep(sp, ins, ss).SOk?
    requires ins.CallLocal? ==> cs.pc >= 0 && BindFail(sp, cs.pc, ss) == ""
    ensures !ins.Ja? && !ins.Jcond? && !ins.Exit?
    ensures var r := Step(sp.floor, ins, cs, oracle);
            r.Next? && r.s.pc == cs.pc + 1 && CWF(r.s) && cs.log <= r.s.log
            && (r.s.log <= sigma ==> Sim(sp, SymStep(sp, ins, ss).ss, r.s, s0, sigma))
  {
    match ins
    case Alu(_, _, _, _) => AluSim(sp, ins, ss, cs, s0, sigma, oracle);
    case Ldx(_, _, _, _) => LdxSim(sp, ins, ss, cs, s0, sigma, oracle);
    case Stx(_, _, _, _) => StoreSim(sp, ins, ss, cs, s0, sigma, oracle);
    case St(_, _, _, _) => StoreSim(sp, ins, ss, cs, s0, sigma, oracle);
    case CallHelper(_) => HelperSim(sp, ins, ss, cs, s0, sigma, oracle);
    case CallLocal(_) => HookSim(sp, ins, ss, cs, s0, sigma, oracle);
  }

  // ---------------- the value log only grows ----------------

  lemma StepLogGrows(floor: int, ins: Instr, cs: CState, oracle: seq<bv64>)
    requires CWF(cs) && -(STACK as int) <= floor <= 0
    ensures var r := Step(floor, ins, cs, oracle);
            (r.Next? || r.Halt?) ==> cs.log <= r.s.log
  {
    StepEq(floor, ins, cs, oracle);
  }

  lemma LogPrefix(raw: seq<bv8>, floor: int, cs: CState, oracle: seq<bv64>, fuel: nat)
    requires CWF(cs) && -(STACK as int) <= floor <= 0
    ensures cs.log <= LogOf(Run(raw, floor, cs, oracle, fuel))
    decreases fuel
  {
    reveal Run();
    if 0 <= cs.pc < NumInsns(raw) && fuel > 0 {
      match Decode(InsnAt(raw, cs.pc))
      case None =>
      case Some(ins) =>
        StepLogGrows(floor, ins, cs, oracle);
        match Step(floor, ins, cs, oracle)
        case Stuck =>
        case Halt(_) =>
        case Next(s') => if CWF(s') { LogPrefix(raw, floor, s', oracle, fuel - 1); }
    }
  }

  // ---------------- obligations at the end of a path ----------------

  lemma FinalSound(sp: Spec, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, pc: int)
    requires SpecWF(sp) && Sim(sp, ss, cs, s0, sigma)
    requires Final(sp, ss, pc) == Validated
    ensures FinalOk(sp, s0, cs)
  {
    var e := EnvOf(s0, sigma);
    forall k | 0 <= k < NREGS && ss.regs[k] == Entry(k) ensures cs.regs[k] == s0.regs[k] {
      EvEntry(k, e);
    }
    if sp.exitMode { EvConst(0, e); }
    UpperBaseLen(cs.events, s0.stack);
  }

  // ---------------- (1)(4) every concrete run follows a checked path ----------------

  predicate Decoded(raw: seq<bv8>, prog: seq<Instr>) {
    |raw| % 8 == 0 && |prog| == NumInsns(raw)
    && forall j :: 0 <= j < |prog| ==> Decode(InsnAt(raw, j)) == Some(prog[j])
  }

  // A window's run is one Run over some code followed by some glue (Post):
  //   PTop: the whole window; no glue.
  //   PWP:  WP of a P8 window (WPart); then call W (CallW, with fuel F).
  //   PW:   W's body, entered from the caller state s1; then the return.
  // caller: the symbolic registers at call W.
  datatype Phase = PTop | PWP(wraw: seq<bv8>, wprog: seq<Instr>, F: nat) | PW(wraw: seq<bv8>, s1: CState, caller: seq<Term>)

  function ModeOf(ph: Phase): Mode {
    match ph
    case PTop => Top
    case PWP(_, wprog, _) => WP(wprog)
    case PW(_, _, caller) => WBody(caller)
  }

  function CodeOf(raw: seq<bv8>, ph: Phase): seq<bv8> {
    match ph
    case PTop => raw
    case PWP(_, _, _) => if NumInsns(raw) >= 1 then WPart(raw) else raw
    case PW(wraw, _, _) => wraw
  }

  function Post(raw: seq<bv8>, sp: Spec, ph: Phase, oracle: seq<bv64>, o: Outcome): Outcome
    requires -(STACK as int) <= sp.floor <= 0
  {
    match ph
    case PTop => o
    case PWP(wraw, _, F) => if NumInsns(raw) >= 1 then WPPost(raw, wraw, sp.floor, oracle, F, o) else o
    case PW(_, s1, _) => WPost(s1, oracle, o)
  }

  // The rest of the window's run from cs in phase ph.
  function Out(raw: seq<bv8>, sp: Spec, ph: Phase, cs: CState, oracle: seq<bv64>, fuel: nat): Outcome
    requires CWF(cs) && -(STACK as int) <= sp.floor <= 0
  {
    Post(raw, sp, ph, oracle, Run(CodeOf(raw, ph), sp.floor, cs, oracle, fuel))
  }

  function Rank(ph: Phase): nat { if ph.PWP? then 1 else 0 }

  predicate PhaseOk(raw: seq<bv8>, sp: Spec, ph: Phase, s0: CState, sigma: seq<bv64>) {
    match ph
    case PTop => sp.wrap.NoWrap?
    case PWP(wraw, wprog, F) =>
      sp.wrap.Wrap? && sp.wrap.body == wraw && WrapStatic(raw, sp) && Decoded(wraw, wprog) && F > |wprog|
    case PW(_, s1, caller) =>
      sp.wrap.Wrap? && WrapStatic(raw, sp) && CWF(s1) && CWF(s0) && |caller| == NREGS
      && s1.pc == NumInsns(raw) - 1 && s1.regs[10] == s0.regs[10]
      && (forall k :: 0 <= k < NREGS ==> Eval(caller[k], EnvOf(s0, sigma)) == s1.regs[k])
  }

  // What every Exec* lemma assumes.  sigma is the value log of the whole window run.
  predicate ExecPre(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat) {
    SpecWF(sp) && Decoded(CodeOf(raw, ph), prog)
    && pc <= |prog| && SWF(ss) && SymExec(prog, sp, pc, ss, ModeOf(ph)) == Validated
    && CWF(cs) && CWF(s0) && cs.pc == pc && fuel > |prog| - pc
    && PhaseOk(raw, sp, ph, s0, LogOf(Out(raw, sp, ph, cs, oracle, fuel)))
    && Sim(sp, ss, cs, s0, LogOf(Out(raw, sp, ph, cs, oracle, fuel)))
  }

  // By induction on the phase and the distance to the end of the code; one lemma per case.
  lemma ExecSound(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                  cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires ExecPre(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel)
    ensures ObligationsHold(raw, sp, s0, Out(raw, sp, ph, cs, oracle, fuel))
    decreases Rank(ph), |prog| - pc, 3
  {
    if pc == |prog| {
      ExecEnd(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel);
    } else if prog[pc].Exit? {
      ExecExit(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel);
    } else if prog[pc].Ja? {
      ExecJa(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel);
    } else if prog[pc].Jcond? {
      ExecJcond(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel);
    } else {
      ExecStep(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel);
    }
  }

  // At the end of the code: the window ends (PTop), or call W is next (PWP).
  // W's body never falls off its end (SymExec rejects that).
  lemma ExecEnd(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires ExecPre(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel) && pc == |prog|
    ensures ObligationsHold(raw, sp, s0, Out(raw, sp, ph, cs, oracle, fuel))
    decreases Rank(ph), 0, 2
  {
    SymExecEnd(prog, sp, pc, ss, ModeOf(ph));
    if ph.PTop? {
      RunEnd(raw, sp.floor, cs, oracle, fuel);
      FinalSound(sp, ss, cs, s0, LogOf(Out(raw, sp, ph, cs, oracle, fuel)), pc);
    } else if ph.PWP? {
      ExecCallW(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel);
    }
  }

  // EXIT: the end of a hook body (PTop) or the return from W (PW); never in WP.
  lemma ExecExit(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                 cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires ExecPre(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel) && pc < |prog| && prog[pc].Exit?
    ensures ObligationsHold(raw, sp, s0, Out(raw, sp, ph, cs, oracle, fuel))
  {
    SymExecExit(prog, sp, pc, ss, ModeOf(ph));
    assert Decode(InsnAt(CodeOf(raw, ph), pc)) == Some(prog[pc]);
    RunHalt(CodeOf(raw, ph), sp.floor, cs, oracle, fuel);
    if ph.PTop? {
      FinalSound(sp, ss, cs, s0, LogOf(Out(raw, sp, ph, cs, oracle, fuel)), pc);
    } else if ph.PW? {
      ExecRetW(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel);
    }
  }

  // Sim does not mention pc: moving pc keeps it.
  lemma SimPc(sp: Spec, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, t: int)
    requires Sim(sp, ss, cs, s0, sigma)
    ensures Sim(sp, ss, cs.(pc := t), s0, sigma)
  {}

  // A jump to t: the run continues from cs.(pc := t) with the same value log.
  lemma {:isolate_assertions} JumpAdvance(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat, t: int)
    returns (cs': CState)
    requires ExecPre(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel)
    requires pc < |prog| && (prog[pc].Ja? || prog[pc].Jcond?)
    requires Step(sp.floor, prog[pc], cs, oracle) == Next(cs.(pc := t))
    ensures CWF(cs') && cs'.pc == t
    ensures Out(raw, sp, ph, cs, oracle, fuel) == Out(raw, sp, ph, cs', oracle, fuel - 1)
    ensures Sim(sp, ss, cs', s0, LogOf(Out(raw, sp, ph, cs', oracle, fuel - 1)))
  {
    cs' := cs.(pc := t);
    var code := CodeOf(raw, ph);
    assert Decode(InsnAt(code, pc)) == Some(prog[pc]);
    assert CWF(cs');
    RunNext(code, sp.floor, cs, oracle, fuel, prog[pc], cs');
    var sigma := LogOf(Out(raw, sp, ph, cs, oracle, fuel));
    assert sigma == LogOf(Out(raw, sp, ph, cs', oracle, fuel - 1));
    SimPc(sp, ss, cs, s0, sigma, t);
  }

  // Unconditional jump: the only successor was checked.
  lemma ExecJa(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
               cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires ExecPre(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel) && pc < |prog| && prog[pc].Ja?
    ensures ObligationsHold(raw, sp, s0, Out(raw, sp, ph, cs, oracle, fuel))
    decreases Rank(ph), |prog| - pc, 0
  {
    var ins := prog[pc];
    SymExecJa(prog, sp, pc, ss, ModeOf(ph));
    var t := Target(pc, ins.off);
    StepEq(sp.floor, ins, cs, oracle);
    var cs' := JumpAdvance(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel, t);
    ExecSound(raw, ph, prog, sp, t, ss, cs', s0, oracle, fuel - 1);
  }

  // Conditional jump: the run takes one arm; both arms were checked.
  lemma ExecJcond(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                  cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires ExecPre(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel) && pc < |prog| && prog[pc].Jcond?
    ensures ObligationsHold(raw, sp, s0, Out(raw, sp, ph, cs, oracle, fuel))
    decreases Rank(ph), |prog| - pc, 0
  {
    var ins := prog[pc];
    SymExecJcond(prog, sp, pc, ss, ModeOf(ph));
    var t := if CondHolds(ins.cond, cs.regs[ins.dst], ins.imm) then Target(pc, ins.off) else pc + 1;
    assert pc < t <= |prog|;
    assert SymExec(prog, sp, t, ss, ModeOf(ph)) == Validated;
    StepEq(sp.floor, ins, cs, oracle);
    var cs' := JumpAdvance(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel, t);
    ExecSound(raw, ph, prog, sp, t, ss, cs', s0, oracle, fuel - 1);
  }

  // Other instructions: one symbolic step simulates one concrete step, and
  // the relation holds again for the rest of the run.
  lemma {:isolate_assertions} StepAdvance(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    returns (ss': SState, cs': CState)
    requires ExecPre(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel)
    requires pc < |prog| && !prog[pc].Exit? && !prog[pc].Ja? && !prog[pc].Jcond?
    // The successor states are returned as values so that callers never see
    // the SymStep/Step terms (keeps ExecStep's proof obligation small).
    ensures SWF(ss') && SymExec(prog, sp, pc + 1, ss', ModeOf(ph)) == Validated
    ensures CWF(cs') && cs'.pc == pc + 1
    ensures Out(raw, sp, ph, cs, oracle, fuel) == Out(raw, sp, ph, cs', oracle, fuel - 1)
    ensures Sim(sp, ss', cs', s0, LogOf(Out(raw, sp, ph, cs', oracle, fuel - 1)))
  {
    var ins := prog[pc];
    var code := CodeOf(raw, ph);
    assert Decode(InsnAt(code, pc)) == Some(ins);
    var sigma := LogOf(Out(raw, sp, ph, cs, oracle, fuel));
    SymExecStep(prog, sp, pc, ss, ModeOf(ph));
    StepSim(sp, ins, ss, cs, s0, sigma, oracle);
    ss' := SymStep(sp, ins, ss).ss;
    cs' := Step(sp.floor, ins, cs, oracle).s;
    assert Step(sp.floor, ins, cs, oracle) == Next(cs') && CWF(cs') && cs'.pc == pc + 1;
    RunNext(code, sp.floor, cs, oracle, fuel, ins, cs');
    assert sigma == LogOf(Out(raw, sp, ph, cs', oracle, fuel - 1));
    OutLog(raw, sp, ph, cs', oracle, fuel - 1);
    assert cs'.log <= sigma;
    assert Sim(sp, ss', cs', s0, sigma);
  }

  lemma ExecStep(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                 cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires ExecPre(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel)
    requires pc < |prog| && !prog[pc].Exit? && !prog[pc].Ja? && !prog[pc].Jcond?
    ensures ObligationsHold(raw, sp, s0, Out(raw, sp, ph, cs, oracle, fuel))
    decreases Rank(ph), |prog| - pc, 0
  {
    var ss', cs' := StepAdvance(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel);
    ExecSound(raw, ph, prog, sp, pc + 1, ss', cs', s0, oracle, fuel - 1);
  }

  // ---------------- the value log of the rest of the run only grows ----------------

  lemma WPostLog(s1: CState, oracle: seq<bv64>, o: Outcome)
    ensures LogOf(o) <= LogOf(WPost(s1, oracle, o))
  {}

  lemma CallWLog(raw: seq<bv8>, wraw: seq<bv8>, floor: int, s1: CState, oracle: seq<bv64>, fuel: nat)
    requires -(STACK as int) <= floor <= 0 && NumInsns(raw) >= 1
    ensures s1.log <= LogOf(CallW(raw, wraw, floor, s1, oracle, fuel))
  {
    if CWF(s1) && s1.pc == NumInsns(raw) - 1 {
      var c := EnterW(s1, oracle);
      LogPrefix(wraw, floor, c, oracle, fuel);
      WPostLog(s1, oracle, Run(wraw, floor, c, oracle, fuel));
    }
  }

  lemma OutLog(raw: seq<bv8>, sp: Spec, ph: Phase, cs: CState, oracle: seq<bv64>, fuel: nat)
    requires CWF(cs) && -(STACK as int) <= sp.floor <= 0
    ensures cs.log <= LogOf(Out(raw, sp, ph, cs, oracle, fuel))
  {
    var o := Run(CodeOf(raw, ph), sp.floor, cs, oracle, fuel);
    LogPrefix(CodeOf(raw, ph), sp.floor, cs, oracle, fuel);
    match ph
    case PTop =>
    case PW(_, s1, _) => WPostLog(s1, oracle, o);
    case PWP(wraw, _, F) =>
      if NumInsns(raw) >= 1 && o.Done? { CallWLog(raw, wraw, sp.floor, o.s, oracle, F); }
  }

  // ---------------- P8: call W and the return ----------------

  // Entering W keeps Sim; the five undefined registers are the next fresh symbols.
  lemma {:isolate_assertions} EnterSim(sp: Spec, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, oracle: seq<bv64>)
    requires SpecWF(sp) && sp.wrap.Wrap? && Sim(sp, ss, cs, s0, sigma)
    requires forall k :: 0 <= k <= 9 && k != 4 ==> ss.regs[k] == Entry(k)
    requires EnterW(cs, oracle).log <= sigma
    ensures Sim(sp, EnterWS(ss), EnterW(cs, oracle), s0, sigma)
  {
    var e := EnvOf(s0, sigma);
    var c := EnterW(cs, oracle);
    var ss' := EnterWS(ss);
    var n := ss.next;
    assert |cs.log| == n;
    forall k | 0 <= k < NREGS ensures Eval(ss'.regs[k], e) == c.regs[k] {
      if !(1 <= k <= 5 || k == 10) {
        var j := if k == 0 then 0 else k - 5;
        assert ss'.regs[k] == Fresh(n + j);
        assert c.log[n + j] == c.regs[k];
        EvFresh(n + j, e);
      }
    }
    var ev := ECallW(cs.regs);
    forall k | 0 <= k <= 9 && k != 4 ensures cs.regs[k] == s0.regs[k] { EvEntry(k, e); }
    assert EventOk(sp, s0, ev);
    SnocPlain(sp, s0, cs.events, ev);
    EventsSnoc(cs.events, ev, s0.stack);
    assert Sim(sp, ss', c, s0, sigma);
  }

  // Returning from W keeps Sim: r0 is W's r0, r1..r5 fresh, r6..r10 the caller's.
  lemma {:isolate_assertions} ReturnSim(sp: Spec, ss: SState, cs: CState, s1: CState, caller: seq<Term>,
                                        s0: CState, sigma: seq<bv64>, oracle: seq<bv64>)
    requires SpecWF(sp) && sp.wrap.Wrap? && Sim(sp, ss, cs, s0, sigma) && CWF(s1) && |caller| == NREGS
    requires s1.regs[10] == s0.regs[10]
    requires forall k :: 0 <= k < NREGS ==> Eval(caller[k], EnvOf(s0, sigma)) == s1.regs[k]
    requires ReturnW(s1, cs, oracle).log <= sigma
    ensures Sim(sp, ReturnS(ss, caller), ReturnW(s1, cs, oracle), s0, sigma)
  {
    var e := EnvOf(s0, sigma);
    var r := ReturnW(s1, cs, oracle);
    var ss' := ReturnS(ss, caller);
    var n := ss.next;
    assert |cs.log| == n;
    forall k | 0 <= k < NREGS ensures Eval(ss'.regs[k], e) == r.regs[k] {
      if 1 <= k <= 5 {
        assert ss'.regs[k] == Fresh(n + (k - 1));
        assert r.log == cs.log + r.regs[1..6];
        assert r.log[n + (k - 1)] == r.regs[1..6][k - 1] == r.regs[k];
        EvFresh(n + (k - 1), e);
      }
    }
    var ev := ERet(cs.regs[0]);
    assert EventOk(sp, s0, ev);
    SnocPlain(sp, s0, cs.events, ev);
    EventsSnoc(cs.events, ev, s0.stack);
    assert Sim(sp, ss', r, s0, sigma);
  }

  // The end of WP: the run enters W, whose paths were all checked from EnterWS.
  lemma ExecCallW(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                                        cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires ExecPre(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel) && pc == |prog| && ph.PWP?
    ensures ObligationsHold(raw, sp, s0, Out(raw, sp, ph, cs, oracle, fuel))
    decreases Rank(ph), 0, 1
  {
    var wraw, wprog, F := ph.wraw, ph.wprog, ph.F;
    var n := NumInsns(raw);
    SymExecEnd(prog, sp, pc, ss, ModeOf(ph));
    assert NumInsns(WPart(raw)) == n - 1;
    RunEnd(WPart(raw), sp.floor, cs, oracle, fuel);
    assert Decode(InsnAt(raw, n - 1)).Some? && Decode(InsnAt(raw, n - 1)).value.CallLocal?;
    var c := EnterW(cs, oracle);
    var ph' := PW(wraw, cs, ss.regs);
    assert Out(raw, sp, ph, cs, oracle, fuel) == CallW(raw, wraw, sp.floor, cs, oracle, F);
    assert Out(raw, sp, ph, cs, oracle, fuel) == Out(raw, sp, ph', c, oracle, F);
    var sigma := LogOf(Out(raw, sp, ph, cs, oracle, fuel));
    OutLog(raw, sp, ph', c, oracle, F);
    EnterSim(sp, ss, cs, s0, sigma, oracle);
    assert PhaseOk(raw, sp, ph', s0, sigma);
    ExecSound(raw, ph', wprog, sp, 0, EnterWS(ss), c, s0, oracle, F);
  }

  // EXIT in W: the window ends right after the return; W returned the helper result.
  lemma ExecRetW(raw: seq<bv8>, ph: Phase, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                                       cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires ExecPre(raw, ph, prog, sp, pc, ss, cs, s0, oracle, fuel) && pc < |prog| && prog[pc].Exit? && ph.PW?
    requires Run(CodeOf(raw, ph), sp.floor, cs, oracle, fuel) == Exited(cs)
    ensures ObligationsHold(raw, sp, s0, Out(raw, sp, ph, cs, oracle, fuel))
  {
    var s1, caller := ph.s1, ph.caller;
    SymExecExit(prog, sp, pc, ss, ModeOf(ph));
    var r := ReturnW(s1, cs, oracle);
    assert Out(raw, sp, ph, cs, oracle, fuel) == Done(r);
    var sigma := r.log;
    var e := EnvOf(s0, sigma);
    ReturnSim(sp, ss, cs, s1, caller, s0, sigma, oracle);
    FinalSound(sp, ReturnS(ss, caller), r, s0, sigma, pc);
    assert r.events[..|r.events| - 1] == cs.events;
    assert Eval(ss.regs[0], e) == cs.regs[0] && Eval(ss.ret, e) == HelperRet(cs.events);
    assert WRetOk(r.events);
  }

  // ---------------- decoding ----------------

  lemma DecodeFromOk(raw: seq<bv8>, i: nat)
    requires i <= NumInsns(raw) && DecodeFrom(raw, i).DOk?
    ensures var p := DecodeFrom(raw, i).prog;
            |p| == NumInsns(raw) - i && forall j :: 0 <= j < |p| ==> Decode(InsnAt(raw, i + j)) == Some(p[j])
    decreases NumInsns(raw) - i
  {
    if i < NumInsns(raw) { DecodeFromOk(raw, i + 1); }
  }

  // What Validated tells us about the inputs.
  lemma ValidateOk(raw: seq<bv8>, sp: Spec)
    requires Validate(raw, sp) == Validated
    ensures SpecWF(sp) && |raw| % 8 == 0 && DecodeFrom(raw, 0).DOk?
    ensures Decoded(raw, DecodeFrom(raw, 0).prog)
    ensures sp.wrap.NoWrap? ==> SymExec(DecodeFrom(raw, 0).prog, sp, 0, SInit(), Top) == Validated
    ensures sp.wrap.Wrap? ==> ValidateWrap(DecodeFrom(raw, 0).prog, sp) == Validated
  {
    DecodeFromOk(raw, 0);
  }

  // What ValidateWrap == Validated tells us (P8).
  lemma ValidateWrapOk(raw: seq<bv8>, sp: Spec, prog: seq<Instr>) returns (wprog: seq<Instr>)
    requires SpecWF(sp) && sp.wrap.Wrap? && Decoded(raw, prog) && ValidateWrap(prog, sp) == Validated
    ensures |prog| >= 1 && Decoded(sp.wrap.body, wprog) && WrapStatic(raw, sp)
    ensures Decoded(WPart(raw), prog[..|prog| - 1])
    ensures SymExec(prog[..|prog| - 1], sp, 0, SInit(), WP(wprog)) == Validated
  {
    wprog := ValidateWrapFacts(prog, sp);
    WPStatic(raw, prog);
    WBodyStatic(sp, wprog);
    WPartDecoded(raw, prog);
  }

  // The checks ValidateWrap made, as facts about prog and W's decoded body.
  lemma ValidateWrapFacts(prog: seq<Instr>, sp: Spec) returns (wprog: seq<Instr>)
    requires SpecWF(sp) && sp.wrap.Wrap? && ValidateWrap(prog, sp) == Validated
    ensures |prog| >= 1 && prog[|prog| - 1].CallLocal?
    ensures forall j :: 0 <= j < |prog| - 1 ==> Writes(prog[j]) <= {4}
    ensures Decoded(sp.wrap.body, wprog) && forall j :: 0 <= j < |wprog| ==> WInsnOk(wprog[j], sp)
    ensures SymExec(prog[..|prog| - 1], sp, 0, SInit(), WP(wprog)) == Validated
  {
    wprog := DecodeFrom(sp.wrap.body, 0).prog;
    DecodeFromOk(sp.wrap.body, 0);
  }

  lemma WPStatic(raw: seq<bv8>, prog: seq<Instr>)
    requires Decoded(raw, prog) && |prog| >= 1 && prog[|prog| - 1].CallLocal?
    requires forall j :: 0 <= j < |prog| - 1 ==> Writes(prog[j]) <= {4}
    ensures NumInsns(raw) >= 1 && Decode(InsnAt(raw, NumInsns(raw) - 1)).Some?
            && Decode(InsnAt(raw, NumInsns(raw) - 1)).value.CallLocal?
    ensures forall j :: 0 <= j < NumInsns(raw) - 1 ==>
              Decode(InsnAt(raw, j)).Some? && Writes(Decode(InsnAt(raw, j)).value) <= {4}
  {
    assert Decode(InsnAt(raw, |prog| - 1)) == Some(prog[|prog| - 1]);
    forall j | 0 <= j < NumInsns(raw) - 1
      ensures Decode(InsnAt(raw, j)).Some? && Writes(Decode(InsnAt(raw, j)).value) <= {4}
    {
      assert Decode(InsnAt(raw, j)) == Some(prog[j]);
    }
  }

  lemma WBodyStatic(sp: Spec, wprog: seq<Instr>)
    requires sp.wrap.Wrap? && Decoded(sp.wrap.body, wprog) && forall j :: 0 <= j < |wprog| ==> WInsnOk(wprog[j], sp)
    ensures |sp.wrap.body| % 8 == 0
    ensures forall j :: 0 <= j < NumInsns(sp.wrap.body) ==>
              Decode(InsnAt(sp.wrap.body, j)).Some? && WInsnOk(Decode(InsnAt(sp.wrap.body, j)).value, sp)
  {
    forall j | 0 <= j < NumInsns(sp.wrap.body)
      ensures Decode(InsnAt(sp.wrap.body, j)).Some? && WInsnOk(Decode(InsnAt(sp.wrap.body, j)).value, sp)
    {
      assert Decode(InsnAt(sp.wrap.body, j)) == Some(wprog[j]);
    }
  }

  // WP's code decodes to the window's instructions without the last one.
  lemma WPartDecoded(raw: seq<bv8>, prog: seq<Instr>)
    requires Decoded(raw, prog) && |prog| >= 1
    ensures Decoded(WPart(raw), prog[..|prog| - 1])
  {
    var n := |prog|;
    forall j | 0 <= j < n - 1 ensures Decode(InsnAt(WPart(raw), j)) == Some(prog[..n - 1][j]) {
      WPartInsn(raw, j);
      assert Decode(InsnAt(raw, j)) == Some(prog[j]);
    }
  }

  lemma WPartInsn(raw: seq<bv8>, j: nat)
    requires NumInsns(raw) >= 1 && j < NumInsns(raw) - 1
    ensures NumInsns(WPart(raw)) == NumInsns(raw) - 1 && InsnAt(WPart(raw), j) == InsnAt(raw, j)
  {
    var wp := WPart(raw);
    assert |wp| == 8 * (NumInsns(raw) - 1);
    assert wp[8 * j .. 8 * j + 8] == raw[8 * j .. 8 * j + 8];
  }

  // At entry the symbolic state denotes the concrete one under any sigma.
  lemma {:isolate_assertions} SimInit(sp: Spec, s0: CState, sigma: seq<bv64>)
    requires CWF(s0) && s0.log == [] && s0.events == []
    ensures Sim(sp, SInit(), s0, s0, sigma)
  {
    var e := EnvOf(s0, sigma);
    var ss := SInit();
    forall k | 0 <= k < NREGS ensures Eval(ss.regs[k], e) == s0.regs[k] { EvEntry(k, e); }
    forall i | 0 <= i < STACK ensures EvalB(ss.stack[i], e) == s0.stack[i] { EvBEntry(i, e); }
    forall i | 0 <= i < STACK ensures EvalB(ss.snap[i], e) == UpperBase(s0.events, s0.stack)[i] { EvBEntry(i, e); }
    EvConst(0, e);
    assert ss.ret == Const(0) && ss.hkey == Const(0);
    assert HelperRet(s0.events) == 0 && HelperKey(s0.events) == 0;
    assert AllBound(sp, s0.events);
  }

  // ---------------- facts that tie trusted definitions to the semantics ----------------

  // Writes(ins) is exactly what Step may change among the registers.
  lemma StepWrites(floor: int, ins: Instr, s: CState, oracle: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && Step(floor, ins, s, oracle).Next?
    ensures |Step(floor, ins, s, oracle).s.regs| == NREGS
    ensures forall k :: 0 <= k < NREGS && k !in Writes(ins) ==> Step(floor, ins, s, oracle).s.regs[k] == s.regs[k]
  {
    StepEq(floor, ins, s, oracle);
  }

  // A helper call is determined by its id: two 8-byte instructions that
  // decode to the same helper call are equal in every field (P8-helper-id).
  lemma CallHelperBytes(b: seq<bv8>, b': seq<bv8>, id: bv32)
    requires |b| == 8 && |b'| == 8 && Decode(b) == Some(CallHelper(id)) && Decode(b') == Some(CallHelper(id))
    ensures b == b'
  {
    ImmInj(b[4], b[5], b[6], b[7], b'[4], b'[5], b'[6], b'[7]);
    OffInj(b[2], b[3]);
    OffInj(b'[2], b'[3]);
    RegsZero(b[1]);
    RegsZero(b'[1]);
  }

  lemma ImmInj(a0: bv8, a1: bv8, a2: bv8, a3: bv8, c0: bv8, c1: bv8, c2: bv8, c3: bv8)
    requires (a0 as bv32) | ((a1 as bv32) << 8) | ((a2 as bv32) << 16) | ((a3 as bv32) << 24)
          == (c0 as bv32) | ((c1 as bv32) << 8) | ((c2 as bv32) << 16) | ((c3 as bv32) << 24)
    ensures a0 == c0 && a1 == c1 && a2 == c2 && a3 == c3
  {}

  lemma OffInj(a0: bv8, a1: bv8)
    ensures (a0 as bv16) | ((a1 as bv16) << 8) == 0 <==> a0 == 0 && a1 == 0
  {}

  lemma RegsZero(a: bv8)
    ensures (a & 0x0f) as nat == 0 && (a >> 4) as nat == 0 <==> a == 0
  {}

  // ================= main theorem =================

  // If the checker validates a window, then for every initial register file,
  // every initial stack, every oracle (= every execution) and enough fuel,
  // the run satisfies all obligations of the window.  For a P8 window the
  // run is RunWrap: WP, then W's body as a second frame, then the return.
  lemma Soundness(raw: seq<bv8>, sp: Spec, regs: seq<bv64>, stack: seq<bv8>, oracle: seq<bv64>, fuel: nat)
    requires Validate(raw, sp) == Validated
    requires |regs| == NREGS && |stack| == STACK
    requires fuel > NumInsns(raw) + WrapLen(sp)
    ensures SpecWF(sp)
    ensures ObligationsHold(raw, sp, InitState(regs, stack), WindowRun(raw, sp, InitState(regs, stack), oracle, fuel))
  {
    var s0 := InitState(regs, stack);
    ValidateOk(raw, sp);
    var prog := DecodeFrom(raw, 0).prog;
    if sp.wrap.NoWrap? {
      var ph := PTop;
      assert Out(raw, sp, ph, s0, oracle, fuel) == WindowRun(raw, sp, s0, oracle, fuel);
      SimInit(sp, s0, LogOf(Out(raw, sp, ph, s0, oracle, fuel)));
      ExecSound(raw, ph, prog, sp, 0, SInit(), s0, s0, oracle, fuel);
    } else {
      var wprog := ValidateWrapOk(raw, sp, prog);
      var ph := PWP(sp.wrap.body, wprog, fuel);
      assert Out(raw, sp, ph, s0, oracle, fuel) == WindowRun(raw, sp, s0, oracle, fuel);
      SimInit(sp, s0, LogOf(Out(raw, sp, ph, s0, oracle, fuel)));
      ExecSound(raw, ph, prog[..|prog| - 1], sp, 0, SInit(), s0, s0, oracle, fuel);
    }
  }
}
