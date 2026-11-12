// Facts about the region-level semantics (Semantics.dfy) that the
// connection to whole runs needs: events only grow along a run, and a step
// reads the oracle only at the positions it consumes.
include "Facts.dfy"

module SimRegion {
  import opened Bits
  import opened Semantics
  import opened Obligations
  import Soundness

  // ---------------- events only grow ----------------

  lemma StepEventsGrow(floor: int, ins: Instr, s: CState, oracle: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0
    ensures var r := Step(floor, ins, s, oracle); (r.Next? || r.Halt?) ==> s.events <= r.s.events
  {
    Soundness.StepEq(floor, ins, s, oracle);
  }

  lemma RunEventsGrow(raw: seq<bv8>, floor: int, s: CState, oracle: seq<bv64>, fuel: nat)
    requires CWF(s) && -(STACK as int) <= floor <= 0
    ensures s.events <= Run(raw, floor, s, oracle, fuel).s.events
    decreases fuel
  {
    reveal Run();
    if 0 <= s.pc < NumInsns(raw) && fuel > 0 {
      match Decode(InsnAt(raw, s.pc))
      case None =>
      case Some(ins) =>
        StepEventsGrow(floor, ins, s, oracle);
        match Step(floor, ins, s, oracle)
        case Stuck =>
        case Halt(_) =>
        case Next(s') => if CWF(s') { RunEventsGrow(raw, floor, s', oracle, fuel - 1); }
    }
  }

  // An event of a prefix stays in the run's final events.
  lemma EventKept(raw: seq<bv8>, floor: int, s: CState, oracle: seq<bv64>, fuel: nat, i: nat)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && i < |s.events|
    ensures i < |Run(raw, floor, s, oracle, fuel).s.events|
    ensures Run(raw, floor, s, oracle, fuel).s.events[i] == s.events[i]
  {
    RunEventsGrow(raw, floor, s, oracle, fuel);
  }

  // ---------------- a step reads only the oracle values it consumes ----------------

  // Number of oracle values the step at s consumes.
  function Need(floor: int, ins: Instr, s: CState): nat
    requires CWF(s)
  {
    match ins
    case Ldx(w, dst, base, off) =>
      if dst >= 10 || base > 10 || w > 8 then 0
      else if InFrame(Rel(s.regs[base] + Sext16(off), s.regs[10]), w) then 0 else 1
    case CallHelper(_) => 6 + (if floor <= 0 then -floor else 0)
    case CallLocal(_) => 6
    case _ => 0
  }

  predicate SameUpTo(o1: seq<bv64>, o2: seq<bv64>, n: nat) {
    forall i | 0 <= i < n :: Orc(o1, i) == Orc(o2, i)
  }

  lemma StepOracleLocal(floor: int, ins: Instr, s: CState, o1: seq<bv64>, o2: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0
    requires SameUpTo(o1, o2, s.oc + Need(floor, ins, s))
    ensures Step(floor, ins, s, o1) == Step(floor, ins, s, o2)
  {
    if ins.Ldx? { SOLdx(floor, ins, s, o1, o2); }
    else if ins.CallHelper? { SOHelper(floor, ins, s, o1, o2); }
    else if ins.CallLocal? { SOHook(floor, ins, s, o1, o2); }
    else { SOOther(floor, ins, s, o1, o2); }
  }

  lemma SOLdx(floor: int, ins: Instr, s: CState, o1: seq<bv64>, o2: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && ins.Ldx?
    requires SameUpTo(o1, o2, s.oc + Need(floor, ins, s))
    ensures Step(floor, ins, s, o1) == Step(floor, ins, s, o2)
  {
    Soundness.StepEq(floor, ins, s, o1);
    Soundness.StepEq(floor, ins, s, o2);
    if !(ins.dst >= 10 || ins.base > 10 || ins.size > 8) { LdxLocal(s, ins.size, ins.dst, ins.base, ins.off, o1, o2); }
  }

  lemma SOHelper(floor: int, ins: Instr, s: CState, o1: seq<bv64>, o2: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && ins.CallHelper?
    requires SameUpTo(o1, o2, s.oc + Need(floor, ins, s))
    ensures Step(floor, ins, s, o1) == Step(floor, ins, s, o2)
  {
    Soundness.StepEq(floor, ins, s, o1);
    Soundness.StepEq(floor, ins, s, o2);
    HelperLocal(floor, s, ins.id, o1, o2);
  }

  lemma SOHook(floor: int, ins: Instr, s: CState, o1: seq<bv64>, o2: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && ins.CallLocal?
    requires SameUpTo(o1, o2, s.oc + Need(floor, ins, s))
    ensures Step(floor, ins, s, o1) == Step(floor, ins, s, o2)
  {
    Soundness.StepEq(floor, ins, s, o1);
    Soundness.StepEq(floor, ins, s, o2);
    HavocLocal(s, o1, o2);
  }

  lemma SOOther(floor: int, ins: Instr, s: CState, o1: seq<bv64>, o2: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && !ins.Ldx? && !ins.CallHelper? && !ins.CallLocal?
    ensures Step(floor, ins, s, o1) == Step(floor, ins, s, o2)
  {
    Soundness.StepEq(floor, ins, s, o1);
    Soundness.StepEq(floor, ins, s, o2);
  }

  lemma {:isolate_assertions} LdxLocal(s: CState, w: nat, dst: nat, base: nat, off: bv16, o1: seq<bv64>, o2: seq<bv64>)
    requires CWF(s) && w <= 8 && dst < 10 && base <= 10
    requires SameUpTo(o1, o2, s.oc + (if InFrame(Rel(s.regs[base] + Sext16(off), s.regs[10]), w) then 0 else 1))
    ensures LdxStep(s, w, dst, base, off, o1) == LdxStep(s, w, dst, base, off, o2)
  {
    reveal LoadVal();
    var a := s.regs[base] + Sext16(off);
    if !InFrame(Rel(a, s.regs[10]), w) { assert Orc(o1, s.oc) == Orc(o2, s.oc); }
    assert LoadVal(s, a, w, o1) == LoadVal(s, a, w, o2);
  }

  lemma HavocLocal(s: CState, o1: seq<bv64>, o2: seq<bv64>)
    requires CWF(s) && SameUpTo(o1, o2, s.oc + 6)
    ensures HavocRegs(s.regs, o1, s.oc, 6) == HavocRegs(s.regs, o2, s.oc, 6)
    ensures HookStep(s, o1) == HookStep(s, o2)
  {
  }

  lemma HelperLocal(floor: int, s: CState, id: bv32, o1: seq<bv64>, o2: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && SameUpTo(o1, o2, s.oc + 6 - floor)
    ensures HelperStep(floor, s, o1, id) == HelperStep(floor, s, o2, id)
  {
    HavocLocal(s, o1, o2);
    forall i | 0 <= i < STACK ensures HelperStack(floor, s, o1)[i] == HelperStack(floor, s, o2)[i] {
      if i >= 512 + floor { assert Orc(o1, s.oc + 6 + (i - (512 + floor))) == Orc(o2, s.oc + 6 + (i - (512 + floor))); }
    }
    assert HelperStack(floor, s, o1) == HelperStack(floor, s, o2);
  }

  // A prefix of known values and any continuation agree on the prefix.
  lemma SameUpToConcat(a: seq<bv64>, r1: seq<bv64>, r2: seq<bv64>)
    ensures SameUpTo(a + r1, a + r2, |a|)
  {}

  // ---------------- bytes ----------------

  lemma ByteOfCons(b: bv8, y: bv64, i: nat)
    requires i < 7
    ensures ByteOf((b as bv64) | (y << 8), 0) == b
    ensures ByteOf((b as bv64) | (y << 8), i + 1) == ByteOf(y, i)
  {}

  // The little-endian value of up to 8 bytes gives those bytes back.
  lemma BytesOfLE(bs: seq<bv8>)
    requires |bs| <= 8
    ensures BytesOf(LE(bs), |bs|) == bs
    decreases |bs|
  {
    if |bs| > 0 {
      BytesOfLE(bs[1..]);
      var y := LE(bs[1..]);
      assert LE(bs) == (bs[0] as bv64) | (y << 8);
      forall i | 0 <= i < |bs| ensures ByteOf(LE(bs), i) == bs[i] {
        if i == 0 { ByteOfCons(bs[0], y, 0); }
        else { ByteOfCons(bs[0], y, i - 1); assert ByteOf(y, i - 1) == BytesOf(y, |bs| - 1)[i - 1]; }
      }
    }
  }

  // ---------------- one equation per instruction class ----------------

  lemma StepLdx(floor: int, w: nat, dst: nat, b: nat, off: bv16, s: CState, o: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && dst < 10 && b <= 10 && w <= 8
    ensures Step(floor, Ldx(w, dst, b, off), s, o) == LdxStep(s, w, dst, b, off, o)
  { reveal Step(); }

  lemma StepAluEq(floor: int, is64: bool, op: AluOp, dst: nat, opnd: Operand, s: CState, o: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && dst < 10
    ensures Step(floor, Alu(is64, op, dst, opnd), s, o) == AluStep(s, is64, op, dst, opnd)
  { reveal Step(); }

  lemma StepStx(floor: int, w: nat, b: nat, src: nat, off: bv16, s: CState, o: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && b <= 10 && src <= 10 && w <= 8
    ensures Step(floor, Stx(w, b, src, off), s, o) == StoreStep(s, s.regs[b] + Sext16(off), w, s.regs[src])
  { reveal Step(); }

  lemma StepSt(floor: int, w: nat, b: nat, off: bv16, imm: bv32, s: CState, o: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0 && b <= 10 && w <= 8
    ensures Step(floor, St(w, b, off, imm), s, o) == StoreStep(s, s.regs[b] + Sext16(off), w, Sext32(imm))
  { reveal Step(); }

  lemma StepHelper(floor: int, id: bv32, s: CState, o: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0
    ensures Step(floor, CallHelper(id), s, o) == HelperStep(floor, s, o, id)
  { reveal Step(); }

  lemma StepHook(floor: int, imm: bv32, s: CState, o: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0
    ensures Step(floor, CallLocal(imm), s, o) == HookStep(s, o)
  { reveal Step(); }

  lemma StepExit(floor: int, s: CState, o: seq<bv64>)
    requires CWF(s) && -(STACK as int) <= floor <= 0
    ensures Step(floor, Exit, s, o) == Halt(s)
  { reveal Step(); }
}
