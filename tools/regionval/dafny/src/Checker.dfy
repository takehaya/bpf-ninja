// The checker: symbolic step, path enumeration, obligation checks.
// Not trusted: Soundness.dfy proves that Validated implies the obligations.
include "Terms.dfy"
include "Obligations.dfy"

module Checker {
  import opened Bits
  import opened Semantics
  import opened Terms
  import opened Obligations

  const MAX_INSNS: nat := 4096
  const MAX_BRANCHES: nat := 10     // at most 2^10 = 1024 paths; the Go core limits paths, not branches

  // Symbolic state.  snap: the stack at [f,0) the region must leave as is;
  // next: number of fresh symbols used; ret: the helper result symbol.
  datatype SState = SState(regs: seq<Term>, stack: seq<BTerm>, snap: seq<BTerm>,
                           next: nat, helpers: nat, hooks: nat, ret: Term)

  predicate SWF(ss: SState) {
    |ss.regs| == NREGS && |ss.stack| == STACK && |ss.snap| == STACK
  }

  function SInit(): SState {
    var st := seq(STACK, (i: nat) => BEntry(i));
    SState(seq(NREGS, (k: nat) => Entry(k)), st, st, 0, 0, 0, Const(0))
  }

  datatype Verdict = Validated | NotValidated(pc: int, reason: string)
  datatype SR = SOk(ss: SState) | SFail(reason: string)

  // ---------------- symbolic step ----------------

  function SymOperand(is64: bool, o: Operand, regs: seq<Term>): Term
    requires |regs| == NREGS
  {
    match o
    case Reg(r) => if r < NREGS then regs[r] else Const(0)
    case Imm(k) => Const(if is64 then Sext32(k) else k as bv64)
  }

  // Term built for each ALU row (mirrors Semantics.AluVal).
  function AluTerm(is64: bool, op: AluOp, a: Term, b: Term): Term {
    if is64 then
      match op
      case Add => MkAdd(a, b)
      case And => AndT(a, b)
      case Or  => OrT(a, b)
      case Lsh => LshT(a, b)
      case Mov => b
    else
      match op
      case Add => MkZext(MkAdd(a, b))
      case And => MkZext(AndT(a, b))
      case Or  => MkZext(OrT(a, b))
      case Lsh => MkZext(LshT(a, AndT(b, Const(31))))
      case Mov => MkZext(b)
  }

  function AddrTerm(ss: SState, base: nat, off: bv16): Term
    requires SWF(ss) && base < NREGS
  {
    MkAdd(ss.regs[base], Const(Sext16(off)))
  }

  function FreshRegs(regs: seq<Term>, next: nat): seq<Term>
    requires |regs| == NREGS
  {
    seq(NREGS, k requires 0 <= k < NREGS => if k < 6 then Fresh(next + k) else regs[k])
  }

  function WriteBT(st: seq<BTerm>, idx: nat, bs: seq<BTerm>): seq<BTerm>
    requires idx + |bs| <= |st|
  {
    seq(|st|, i requires 0 <= i < |st| => if idx <= i < idx + |bs| then bs[i - idx] else st[i])
  }

  function StoreBytes(v: Term, w: nat): seq<BTerm>
    requires w <= 8
  {
    seq(w, j requires 0 <= j < w => BOf(v, j))
  }

  // C1: stores only at r10 + o with -512 <= o and o + w <= f.
  function SymStore(sp: Spec, ss: SState, base: nat, off: bv16, w: nat, v: Term): SR
    requires SWF(ss) && SpecWF(sp)
  {
    if !sp.allowStore then SFail("store not allowed in this window")
    else if base >= NREGS || w > 8 then SFail("malformed store")
    else match FpOff(AddrTerm(ss, base, off))
      case None => SFail("store address is not r10+const")
      case Some(c) =>
        var o := Signed64(c);
        if !(-(STACK as int) <= o && o + w <= sp.floor) then SFail("store not below the floor")
        else SOk(ss.(stack := WriteBT(ss.stack, o + STACK, StoreBytes(v, w))))
  }

  function SymStep(sp: Spec, ins: Instr, ss: SState): SR
    requires SWF(ss) && SpecWF(sp)
  {
    match ins
    case Alu(is64, op, dst, opnd) =>
      if dst >= 10 then SFail("write to r10")
      else SOk(ss.(regs := ss.regs[dst := AluTerm(is64, op, ss.regs[dst], SymOperand(is64, opnd, ss.regs))]))
    case Ldx(w, dst, base, off) =>
      if dst >= 10 || base >= NREGS || w > 8 then SFail("malformed load")
      else
        var v := match FpOff(AddrTerm(ss, base, off))
                 case Some(c) =>
                   if InFrame(Signed64(c), w) then MkBytes(ss.stack[Signed64(c) + 512 .. Signed64(c) + 512 + w])
                   else Fresh(ss.next)
                 case None => Fresh(ss.next);   // other memory, or an unknown stack slot
        SOk(ss.(regs := ss.regs[dst := v], next := ss.next + 1))
    case Stx(w, base, src, off) =>
      if src >= NREGS then SFail("malformed store") else SymStore(sp, ss, base, off, w, ss.regs[src])
    case St(w, base, off, imm) => SymStore(sp, ss, base, off, w, Const(Sext32(imm)))
    case CallHelper(_) =>
      if !sp.helper.Helper? then SFail("helper call outside a site window")
      else if ss.helpers != 0 then SFail("second helper call on a path")
      else if sp.helper.checkArgs && ss.regs[1..6] != [Entry(1), Entry(2), Entry(3), Entry(4), Entry(5)]
      then SFail("r1-r5 changed before the helper call")
      else
        // r0 <- v, r1..r5 <- havoc, stack [f,0) <- havoc (original helper), rest kept
        var lo := STACK as int + sp.floor;
        var st := seq(STACK, i requires 0 <= i < STACK =>
                        if i >= lo then BOf(Fresh(ss.next + 6 + (i - lo)), 0) else ss.stack[i]);
        SOk(SState(FreshRegs(ss.regs, ss.next), st, st, ss.next + 6 + (-sp.floor), 1, ss.hooks, Fresh(ss.next)))
    case CallLocal(_) =>
      // hook call (trusted calling convention): r0..r5 <- havoc; r6..r10 and the stack preserved
      if !sp.hookCalls then SFail("call not allowed in this window")
      else if ss.hooks != 0 then SFail("second hook call on a path")
      else SOk(ss.(regs := FreshRegs(ss.regs, ss.next), next := ss.next + 6, hooks := 1))
    case _ => SFail("control instruction")
  }

  // ---------------- obligations at the end of a path ----------------

  function Final(sp: Spec, ss: SState, pc: int): Verdict
    requires SWF(ss) && SpecWF(sp)
  {
    if ss.helpers != (if sp.helper.Helper? then 1 else 0) then NotValidated(pc, "helper call count")
    else if !(forall k :: 6 <= k <= 10 ==> ss.regs[k] == Entry(k)) then NotValidated(pc, "r6-r10 not preserved")
    else if !(forall k :: 0 <= k <= 5 && k !in sp.free && !(k == 0 && R0Special(sp)) ==> ss.regs[k] == Entry(k))
    then NotValidated(pc, "register not preserved")
    else if sp.helper.Helper? && sp.helper.restoreR0 && ss.regs[0] != ss.ret
    then NotValidated(pc, "r0 not restored to the helper result")
    else if sp.exitMode && ss.regs[0] != Const(0) then NotValidated(pc, "r0 != 0 at exit")
    else if !(forall i :: STACK as int + sp.floor <= i < STACK ==> ss.stack[i] == ss.snap[i])
    then NotValidated(pc, "stack at or above the floor changed")
    else Validated
  }

  // ---------------- path enumeration ----------------

  function Target(pc: nat, off: bv16): int { pc + 1 + Signed16(off) }

  // Every syntactic path from pc; both arms of each conditional branch.
  opaque function SymExec(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState): Verdict
    requires pc <= |prog| && SWF(ss) && SpecWF(sp)
    decreases |prog| - pc
  {
    if pc == |prog| then
      if sp.exitMode then NotValidated(pc, "hook body falls through") else Final(sp, ss, pc)
    else match prog[pc]
      case Exit =>
        if !sp.exitMode then NotValidated(pc, "exit outside a hook body") else Final(sp, ss, pc)
      case Ja(off) =>
        if Signed16(off) < 0 || Target(pc, off) > |prog| then NotValidated(pc, "jump not forward within the window")
        else SymExec(prog, sp, Target(pc, off), ss)
      case Jcond(_, dst, _, off) =>
        if dst >= NREGS || Signed16(off) < 0 || Target(pc, off) > |prog|
        then NotValidated(pc, "branch not forward within the window")
        else
          var r := SymExec(prog, sp, pc + 1, ss);
          if r.NotValidated? then r else SymExec(prog, sp, Target(pc, off), ss)
      case _ =>
        match SymStep(sp, prog[pc], ss)
        case SFail(m) => NotValidated(pc, m)
        case SOk(ss') => if SWF(ss') then SymExec(prog, sp, pc + 1, ss') else NotValidated(pc, "internal")
  }

  // ---------------- entry point ----------------

  datatype DR = DOk(prog: seq<Instr>) | DBad(pc: nat)

  function DecodeFrom(raw: seq<bv8>, i: nat): DR
    requires i <= NumInsns(raw)
    decreases NumInsns(raw) - i
  {
    if i == NumInsns(raw) then DOk([])
    else match Decode(InsnAt(raw, i))
      case None => DBad(i)
      case Some(ins) =>
        match DecodeFrom(raw, i + 1)
        case DBad(p) => DBad(p)
        case DOk(rest) => DOk([ins] + rest)
  }

  function CountBranches(prog: seq<Instr>): nat {
    if |prog| == 0 then 0 else (if prog[0].Jcond? then 1 else 0) + CountBranches(prog[1..])
  }

  // The only function that can return Validated for a region.
  function Validate(raw: seq<bv8>, sp: Spec): Verdict {
    if !SpecWF(sp) then NotValidated(-1, "bad window parameters")
    else if |raw| % 8 != 0 then NotValidated(-1, "length not a multiple of 8")
    else if NumInsns(raw) > MAX_INSNS then NotValidated(-1, "window too long")
    else match DecodeFrom(raw, 0)
      case DBad(p) => NotValidated(p, "instruction outside the allowlist")
      case DOk(prog) =>
        if CountBranches(prog) > MAX_BRANCHES then NotValidated(-1, "too many branches")
        else SymExec(prog, sp, 0, SInit())
  }
}
