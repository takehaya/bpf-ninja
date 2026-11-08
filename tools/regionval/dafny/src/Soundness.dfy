// Soundness of the checker:
//   if Validate(region) == Validated then, for every concrete initial state
//   and every concrete execution (every oracle), the obligations hold.
//
// Structure (numbers refer to the addendum):
//   (2) Sim: the symbolic state denotes the concrete state under the
//       assignment Env(entry regs, entry stack, sigma), where sigma is the
//       list of every value the run obtained from outside.  Fresh symbol n
//       stands for sigma[n], so havoc covers every concrete value.
//   (2) StepSim: each symbolic step agrees with the concrete step.
//   (3) Terms.Mk*Eval: the normaliser preserves evaluation.
//   (1)(4) ExecSound: the concrete run follows one of the enumerated paths;
//       path conditions are not used, so every path was checked.
//   (5) Fail-closed: an undecodable instruction makes the run Escaped, which
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
    && (forall i :: 0 <= i < |cs.events| ==> EventOk(sp, s0, cs.events[i]))
    && cs.regs[10] == s0.regs[10]
  }

  // ---------------- facts about event lists ----------------

  lemma EventsSnoc(evs: seq<Event>, e: Event, entry: seq<bv8>)
    ensures CountHelpers(evs + [e]) == CountHelpers(evs) + (if e.EHelper? then 1 else 0)
    ensures CountHooks(evs + [e]) == CountHooks(evs) + (if e.EHook? then 1 else 0)
    ensures HelperRet(evs + [e]) == if e.EHelper? then e.ret else HelperRet(evs)
    ensures UpperBase(evs + [e], entry) == if e.EHelper? then e.stackAfter else UpperBase(evs, entry)
  {
    assert (evs + [e])[..|evs|] == evs;
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
    ensures HelperStacksWF(evs + [e])
    ensures forall i :: 0 <= i < |evs + [e]| ==> EventOk(sp, s0, (evs + [e])[i])
    ensures CountHelpers(evs + [e]) == CountHelpers(evs)
    ensures HelperRet(evs + [e]) == HelperRet(evs)
    ensures UpperBase(evs + [e], s0.stack) == UpperBase(evs, s0.stack)
  {
    EventsSnoc(evs, e, s0.stack);
  }

  // The same for the helper-call event, whose stack has the right length.
  lemma SnocHelper(sp: Spec, s0: CState, evs: seq<Event>, e: Event)
    requires CWF(s0) && e.EHelper? && |e.stackAfter| == STACK && EventOk(sp, s0, e)
    requires HelperStacksWF(evs) && (forall i :: 0 <= i < |evs| ==> EventOk(sp, s0, evs[i]))
    ensures HelperStacksWF(evs + [e])
    ensures forall i :: 0 <= i < |evs + [e]| ==> EventOk(sp, s0, (evs + [e])[i])
  {}

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
      case CallHelper(_) => HelperStep(floor, s, oracle)
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

  lemma SymExecEnd(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState)
    requires pc == |prog| && SWF(ss) && SpecWF(sp) && SymExec(prog, sp, pc, ss) == Validated
    ensures !sp.exitMode && Final(sp, ss, pc) == Validated
  { reveal SymExec(); }

  lemma SymExecExit(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState)
    requires pc < |prog| && prog[pc].Exit? && SWF(ss) && SpecWF(sp) && SymExec(prog, sp, pc, ss) == Validated
    ensures sp.exitMode && Final(sp, ss, pc) == Validated
  { reveal SymExec(); }

  lemma SymExecJa(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState)
    requires pc < |prog| && prog[pc].Ja? && SWF(ss) && SpecWF(sp) && SymExec(prog, sp, pc, ss) == Validated
    ensures var t := Target(pc, prog[pc].off);
            pc < t <= |prog| && SymExec(prog, sp, t, ss) == Validated
  { reveal SymExec(); }

  lemma SymExecJcond(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState)
    requires pc < |prog| && prog[pc].Jcond? && SWF(ss) && SpecWF(sp) && SymExec(prog, sp, pc, ss) == Validated
    ensures var t := Target(pc, prog[pc].off);
            prog[pc].dst < NREGS && pc < t <= |prog|
            && SymExec(prog, sp, pc + 1, ss) == Validated && SymExec(prog, sp, t, ss) == Validated
  { reveal SymExec(); }

  lemma SymExecStep(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState)
    requires pc < |prog| && !prog[pc].Exit? && !prog[pc].Ja? && !prog[pc].Jcond?
    requires SWF(ss) && SpecWF(sp) && SymExec(prog, sp, pc, ss) == Validated
    ensures SymStep(sp, prog[pc], ss).SOk? && SWF(SymStep(sp, prog[pc], ss).ss)
            && SymExec(prog, sp, pc + 1, SymStep(sp, prog[pc], ss).ss) == Validated
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
    var ev := EHelper(cs.regs[1..6], regs'[0], r.s.stack);
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

  lemma {:isolate_assertions} HookSim(sp: Spec, ins: Instr, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, oracle: seq<bv64>)
    requires SpecWF(sp) && Sim(sp, ss, cs, s0, sigma) && ins.CallLocal?
    requires SymStep(sp, ins, ss).SOk?
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
      SnocPlain(sp, s0, cs.events, EHook);
      EventsSnoc(cs.events, EHook, s0.stack);
      assert Sim(sp, ss', r.s, s0, sigma);
    }
  }

  lemma StepSim(sp: Spec, ins: Instr, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, oracle: seq<bv64>)
    requires SpecWF(sp) && Sim(sp, ss, cs, s0, sigma)
    requires SymStep(sp, ins, ss).SOk?
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

  // By induction on the distance to the end of the window; one lemma per case.
  lemma ExecSound(raw: seq<bv8>, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires SpecWF(sp) && Decoded(raw, prog)
    requires pc <= |prog| && SWF(ss) && SymExec(prog, sp, pc, ss) == Validated
    requires CWF(cs) && CWF(s0) && cs.pc == pc && fuel > |prog| - pc
    requires Sim(sp, ss, cs, s0, LogOf(Run(raw, sp.floor, cs, oracle, fuel)))
    ensures ObligationsHold(raw, sp, s0, Run(raw, sp.floor, cs, oracle, fuel))
    decreases |prog| - pc, 1
  {
    if pc == |prog| {
      ExecEnd(raw, prog, sp, pc, ss, cs, s0, oracle, fuel);
    } else if prog[pc].Exit? {
      ExecExit(raw, prog, sp, pc, ss, cs, s0, oracle, fuel);
    } else if prog[pc].Ja? {
      ExecJa(raw, prog, sp, pc, ss, cs, s0, oracle, fuel);
    } else if prog[pc].Jcond? {
      ExecJcond(raw, prog, sp, pc, ss, cs, s0, oracle, fuel);
    } else {
      ExecStep(raw, prog, sp, pc, ss, cs, s0, oracle, fuel);
    }
  }

  // At the end of the window: the run is Done and the final checks give the obligations.
  lemma ExecEnd(raw: seq<bv8>, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires SpecWF(sp) && Decoded(raw, prog)
    requires pc <= |prog| && SWF(ss) && SymExec(prog, sp, pc, ss) == Validated
    requires CWF(cs) && CWF(s0) && cs.pc == pc && fuel > |prog| - pc
    requires Sim(sp, ss, cs, s0, LogOf(Run(raw, sp.floor, cs, oracle, fuel)))
    ensures ObligationsHold(raw, sp, s0, Run(raw, sp.floor, cs, oracle, fuel))
    requires pc == |prog|
  {
    RunEnd(raw, sp.floor, cs, oracle, fuel);
    SymExecEnd(prog, sp, pc, ss);
    FinalSound(sp, ss, cs, s0, LogOf(Run(raw, sp.floor, cs, oracle, fuel)), pc);
  }

  // EXIT (hook bodies): the run is Exited.
  lemma ExecExit(raw: seq<bv8>, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires SpecWF(sp) && Decoded(raw, prog)
    requires pc <= |prog| && SWF(ss) && SymExec(prog, sp, pc, ss) == Validated
    requires CWF(cs) && CWF(s0) && cs.pc == pc && fuel > |prog| - pc
    requires Sim(sp, ss, cs, s0, LogOf(Run(raw, sp.floor, cs, oracle, fuel)))
    ensures ObligationsHold(raw, sp, s0, Run(raw, sp.floor, cs, oracle, fuel))
    requires pc < |prog| && prog[pc].Exit?
  {
    assert Decode(InsnAt(raw, pc)) == Some(prog[pc]);
    RunHalt(raw, sp.floor, cs, oracle, fuel);
    SymExecExit(prog, sp, pc, ss);
    FinalSound(sp, ss, cs, s0, LogOf(Run(raw, sp.floor, cs, oracle, fuel)), pc);
  }

  // Sim does not mention pc: moving pc keeps it.
  lemma SimPc(sp: Spec, ss: SState, cs: CState, s0: CState, sigma: seq<bv64>, t: int)
    requires Sim(sp, ss, cs, s0, sigma)
    ensures Sim(sp, ss, cs.(pc := t), s0, sigma)
  {}

  // A jump to t: the run continues from cs.(pc := t) with the same value log.
  lemma {:isolate_assertions} JumpAdvance(raw: seq<bv8>, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat, t: int)
    returns (cs': CState)
    requires SpecWF(sp) && Decoded(raw, prog)
    requires pc < |prog| && (prog[pc].Ja? || prog[pc].Jcond?) && SWF(ss)
    requires CWF(cs) && CWF(s0) && cs.pc == pc && fuel > |prog| - pc
    requires Step(sp.floor, prog[pc], cs, oracle) == Next(cs.(pc := t))
    requires Sim(sp, ss, cs, s0, LogOf(Run(raw, sp.floor, cs, oracle, fuel)))
    ensures CWF(cs') && cs'.pc == t
    ensures Run(raw, sp.floor, cs, oracle, fuel) == Run(raw, sp.floor, cs', oracle, fuel - 1)
    ensures Sim(sp, ss, cs', s0, LogOf(Run(raw, sp.floor, cs', oracle, fuel - 1)))
  {
    cs' := cs.(pc := t);
    assert Decode(InsnAt(raw, pc)) == Some(prog[pc]);
    assert CWF(cs');
    RunNext(raw, sp.floor, cs, oracle, fuel, prog[pc], cs');
    var sigma := LogOf(Run(raw, sp.floor, cs, oracle, fuel));
    assert sigma == LogOf(Run(raw, sp.floor, cs', oracle, fuel - 1));
    SimPc(sp, ss, cs, s0, sigma, t);
  }

  // Unconditional jump: the only successor was checked.
  lemma ExecJa(raw: seq<bv8>, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires SpecWF(sp) && Decoded(raw, prog)
    requires pc <= |prog| && SWF(ss) && SymExec(prog, sp, pc, ss) == Validated
    requires CWF(cs) && CWF(s0) && cs.pc == pc && fuel > |prog| - pc
    requires Sim(sp, ss, cs, s0, LogOf(Run(raw, sp.floor, cs, oracle, fuel)))
    requires pc < |prog| && prog[pc].Ja?
    ensures ObligationsHold(raw, sp, s0, Run(raw, sp.floor, cs, oracle, fuel))
    decreases |prog| - pc, 0
  {
    var ins := prog[pc];
    SymExecJa(prog, sp, pc, ss);
    var t := Target(pc, ins.off);
    StepEq(sp.floor, ins, cs, oracle);
    var cs' := JumpAdvance(raw, prog, sp, pc, ss, cs, s0, oracle, fuel, t);
    ExecSound(raw, prog, sp, t, ss, cs', s0, oracle, fuel - 1);
  }

  // Conditional jump: the run takes one arm; both arms were checked.
  lemma ExecJcond(raw: seq<bv8>, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires SpecWF(sp) && Decoded(raw, prog)
    requires pc <= |prog| && SWF(ss) && SymExec(prog, sp, pc, ss) == Validated
    requires CWF(cs) && CWF(s0) && cs.pc == pc && fuel > |prog| - pc
    requires Sim(sp, ss, cs, s0, LogOf(Run(raw, sp.floor, cs, oracle, fuel)))
    requires pc < |prog| && prog[pc].Jcond?
    ensures ObligationsHold(raw, sp, s0, Run(raw, sp.floor, cs, oracle, fuel))
    decreases |prog| - pc, 0
  {
    var ins := prog[pc];
    SymExecJcond(prog, sp, pc, ss);
    var t := if CondHolds(ins.cond, cs.regs[ins.dst], ins.imm) then Target(pc, ins.off) else pc + 1;
    assert pc < t <= |prog|;
    assert SymExec(prog, sp, t, ss) == Validated;
    StepEq(sp.floor, ins, cs, oracle);
    var cs' := JumpAdvance(raw, prog, sp, pc, ss, cs, s0, oracle, fuel, t);
    ExecSound(raw, prog, sp, t, ss, cs', s0, oracle, fuel - 1);
  }

  // Other instructions: one symbolic step simulates one concrete step, and
  // the relation holds again for the rest of the run.
  lemma {:isolate_assertions} StepAdvance(raw: seq<bv8>, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    returns (ss': SState, cs': CState)
    requires SpecWF(sp) && Decoded(raw, prog)
    requires pc < |prog| && !prog[pc].Exit? && !prog[pc].Ja? && !prog[pc].Jcond?
    requires SWF(ss) && SymExec(prog, sp, pc, ss) == Validated
    requires CWF(cs) && CWF(s0) && cs.pc == pc && fuel > |prog| - pc
    requires Sim(sp, ss, cs, s0, LogOf(Run(raw, sp.floor, cs, oracle, fuel)))
    // The successor states are returned as values so that callers never see
    // the SymStep/Step terms (keeps ExecStep's proof obligation small).
    ensures SWF(ss') && SymExec(prog, sp, pc + 1, ss') == Validated
    ensures CWF(cs') && cs'.pc == pc + 1
    ensures Run(raw, sp.floor, cs, oracle, fuel) == Run(raw, sp.floor, cs', oracle, fuel - 1)
    ensures Sim(sp, ss', cs', s0, LogOf(Run(raw, sp.floor, cs', oracle, fuel - 1)))
  {
    var ins := prog[pc];
    assert Decode(InsnAt(raw, pc)) == Some(ins);
    var sigma := LogOf(Run(raw, sp.floor, cs, oracle, fuel));
    SymExecStep(prog, sp, pc, ss);
    StepSim(sp, ins, ss, cs, s0, sigma, oracle);
    ss' := SymStep(sp, ins, ss).ss;
    cs' := Step(sp.floor, ins, cs, oracle).s;
    assert Step(sp.floor, ins, cs, oracle) == Next(cs') && CWF(cs') && cs'.pc == pc + 1;
    RunNext(raw, sp.floor, cs, oracle, fuel, ins, cs');
    assert sigma == LogOf(Run(raw, sp.floor, cs', oracle, fuel - 1));
    LogPrefix(raw, sp.floor, cs', oracle, fuel - 1);
    assert cs'.log <= sigma;
    assert Sim(sp, ss', cs', s0, sigma);
  }

  lemma ExecStep(raw: seq<bv8>, prog: seq<Instr>, sp: Spec, pc: nat, ss: SState,
                    cs: CState, s0: CState, oracle: seq<bv64>, fuel: nat)
    requires SpecWF(sp) && Decoded(raw, prog)
    requires pc <= |prog| && SWF(ss) && SymExec(prog, sp, pc, ss) == Validated
    requires CWF(cs) && CWF(s0) && cs.pc == pc && fuel > |prog| - pc
    requires Sim(sp, ss, cs, s0, LogOf(Run(raw, sp.floor, cs, oracle, fuel)))
    requires pc < |prog| && !prog[pc].Exit? && !prog[pc].Ja? && !prog[pc].Jcond?
    ensures ObligationsHold(raw, sp, s0, Run(raw, sp.floor, cs, oracle, fuel))
    decreases |prog| - pc, 0
  {
    var ss', cs' := StepAdvance(raw, prog, sp, pc, ss, cs, s0, oracle, fuel);
    ExecSound(raw, prog, sp, pc + 1, ss', cs', s0, oracle, fuel - 1);
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
    ensures SymExec(DecodeFrom(raw, 0).prog, sp, 0, SInit()) == Validated
  {
    DecodeFromOk(raw, 0);
  }

  // At entry the symbolic state denotes the concrete one under any sigma.
  lemma SimInit(sp: Spec, s0: CState, sigma: seq<bv64>)
    requires CWF(s0) && s0.log == [] && s0.events == []
    ensures Sim(sp, SInit(), s0, s0, sigma)
  {
    var e := EnvOf(s0, sigma);
    var ss := SInit();
    forall k | 0 <= k < NREGS ensures Eval(ss.regs[k], e) == s0.regs[k] { EvEntry(k, e); }
    forall i | 0 <= i < STACK ensures EvalB(ss.stack[i], e) == s0.stack[i] { EvBEntry(i, e); }
    forall i | 0 <= i < STACK ensures EvalB(ss.snap[i], e) == UpperBase(s0.events, s0.stack)[i] { EvBEntry(i, e); }
    EvConst(0, e);
  }

  // ================= main theorem =================

  // If the checker validates a region, then for every initial register file,
  // every initial stack, every oracle (= every execution) and enough fuel,
  // the run satisfies all obligations of the window.
  lemma Soundness(raw: seq<bv8>, sp: Spec, regs: seq<bv64>, stack: seq<bv8>, oracle: seq<bv64>, fuel: nat)
    requires Validate(raw, sp) == Validated
    requires |regs| == NREGS && |stack| == STACK
    requires fuel > NumInsns(raw)
    ensures SpecWF(sp)
    ensures ObligationsHold(raw, sp, InitState(regs, stack), Run(raw, sp.floor, InitState(regs, stack), oracle, fuel))
  {
    var s0 := InitState(regs, stack);
    ValidateOk(raw, sp);
    var prog := DecodeFrom(raw, 0).prog;
    SimInit(sp, s0, LogOf(Run(raw, sp.floor, s0, oracle, fuel)));
    ExecSound(raw, prog, sp, 0, SInit(), s0, s0, oracle, fuel);
  }
}
