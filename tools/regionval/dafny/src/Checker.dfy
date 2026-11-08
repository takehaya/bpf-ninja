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
  // next: number of fresh symbols used; ret: the helper result symbol;
  // hkey: r2 at the helper call (the key pointer of a lookup).
  datatype SState = SState(regs: seq<Term>, stack: seq<BTerm>, snap: seq<BTerm>,
                           next: nat, helpers: nat, hooks: nat, ret: Term, hkey: Term)

  predicate SWF(ss: SState) {
    |ss.regs| == NREGS && |ss.stack| == STACK && |ss.snap| == STACK
  }

  function SInit(): SState {
    var st := seq(STACK, (i: nat) => BEntry(i));
    SState(seq(NREGS, (k: nat) => Entry(k)), st, st, 0, 0, 0, Const(0), Const(0))
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
      // r10 + c outside the frame: fail closed (as the Go core's rule model)
      else if FpOff(AddrTerm(ss, base, off)).Some? && !InFrame(Signed64(FpOff(AddrTerm(ss, base, off)).value), w)
      then SFail("stack load outside the frame")
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
    case CallHelper(id) =>
      if !sp.helper.Helper? then SFail("helper call outside a site window")
      else if ss.helpers != 0 then SFail("second helper call on a path")
      else if sp.helper.checkArgs && ss.regs[1..6] != [Entry(1), Entry(2), Entry(3), Entry(4), Entry(5)]
      then SFail("r1-r5 changed before the helper call")
      else if sp.wrap.Wrap? && !(Some(id) == HelperIdOf(sp.wrap.helper) && WrapArgsSym(id, ss.regs))
      then SFail("W's helper call is not O[i] with the site's r1-r5")
      else
        // r0 <- v, r1..r5 <- havoc, stack [f,0) <- havoc (original helper), rest kept
        var lo := STACK as int + sp.floor;
        var st := seq(STACK, i requires 0 <= i < STACK =>
                        if i >= lo then BOf(Fresh(ss.next + 6 + (i - lo)), 0) else ss.stack[i]);
        SOk(SState(FreshRegs(ss.regs, ss.next), st, st, ss.next + 6 + (-sp.floor), 1, ss.hooks, Fresh(ss.next), ss.regs[2]))
    case CallLocal(_) =>
      // hook call (trusted calling convention): r0..r5 <- havoc; r6..r10 and the stack preserved
      if !sp.hookCalls then SFail("call not allowed in this window")
      else if ss.hooks != 0 then SFail("second hook call on a path")
      else SOk(ss.(regs := FreshRegs(ss.regs, ss.next), next := ss.next + 6, hooks := 1))
    case _ => SFail("control instruction")
  }

  // P8 (rule R15): r1, r2, r3, r5, and r4 unless a lookup, are the entry symbols.
  predicate WrapArgsSym(id: bv32, regs: seq<Term>)
    requires |regs| == NREGS
  {
    regs[1] == Entry(1) && regs[2] == Entry(2) && regs[3] == Entry(3) && regs[5] == Entry(5)
    && (!IsLookup(id) ==> regs[4] == Entry(4))
  }

  // P8 frames (mirror Semantics.EnterW / ReturnW).
  function EnterWS(ss: SState): SState
    requires SWF(ss)
  {
    ss.(regs := seq(NREGS, k requires 0 <= k < NREGS =>
                      if 1 <= k <= 5 || k == 10 then ss.regs[k] else Fresh(ss.next + (if k == 0 then 0 else k - 5))),
        next := ss.next + 5)
  }

  function ReturnS(ss: SState, caller: seq<Term>): SState
    requires SWF(ss) && |caller| == NREGS
  {
    ss.(regs := seq(NREGS, k requires 0 <= k < NREGS =>
                      if k == 0 then ss.regs[0] else if k <= 5 then Fresh(ss.next + (k - 1)) else caller[k]),
        next := ss.next + 5)
  }

  // RB at the hook call at pc: every Bind there names a register that holds
  // the helper's key symbol or its result symbol, after the helper call.
  // Returns "" or why a Bind fails.
  function BindFail(sp: Spec, pc: nat, ss: SState): string
    requires SWF(ss)
  {
    BindFailFrom(sp.binds, pc, ss, 0)
  }

  function BindFailFrom(bs: seq<Bind>, pc: nat, ss: SState, j: nat): string
    requires SWF(ss)
    decreases |bs| - j
  {
    if j >= |bs| then ""
    else if bs[j].pc != pc then BindFailFrom(bs, pc, ss, j + 1)
    else if ss.helpers != 1 then "record binding: hook call before the helper call"
    else if !(1 <= bs[j].reg <= 5) then "record binding: bad register"
    else if bs[j].role.KeyArg? && ss.regs[bs[j].reg] != ss.hkey
    then "record binding: key argument is not the helper's key pointer"
    else if bs[j].role.ValueArg? && ss.regs[bs[j].reg] != ss.ret
    then "record binding: value argument is not the helper's result"
    else BindFailFrom(bs, pc, ss, j + 1)
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

  // What prog is: the whole window (Top), WP of a P8 window, whose end is
  // call W (WP), or W's body, entered with the caller's registers (WBody).
  datatype Mode = Top | WP(wprog: seq<Instr>) | WBody(caller: seq<Term>)

  // Every syntactic path from pc; both arms of each conditional branch.
  opaque function SymExec(prog: seq<Instr>, sp: Spec, pc: nat, ss: SState, m: Mode): Verdict
    requires pc <= |prog| && SWF(ss) && SpecWF(sp)
    decreases if m.WP? then 1 else 0, |prog| - pc
  {
    if pc == |prog| then
      match m
      case Top => if sp.exitMode then NotValidated(pc, "hook body falls through") else Final(sp, ss, pc)
      case WP(wprog) =>
        if !(forall k :: 0 <= k <= 9 && k != 4 ==> ss.regs[k] == Entry(k))
        then NotValidated(pc, "a register other than r4 changed before call W")
        else SymExec(wprog, sp, 0, EnterWS(ss), WBody(ss.regs))
      case WBody(_) => NotValidated(pc, "falls off the end of W")
    else match prog[pc]
      case Exit =>
        (match m
         case Top => if !sp.exitMode then NotValidated(pc, "exit outside a hook body") else Final(sp, ss, pc)
         case WP(_) => NotValidated(pc, "exit in WP")
         case WBody(caller) =>
           if ss.regs[0] != ss.ret then NotValidated(pc, "W does not return the helper result")
           else if |caller| != NREGS then NotValidated(pc, "internal")
           else Final(sp, ReturnS(ss, caller), pc))
      case Ja(off) =>
        if Signed16(off) < 0 || Target(pc, off) > |prog| then NotValidated(pc, "jump not forward within the window")
        else SymExec(prog, sp, Target(pc, off), ss, m)
      case Jcond(_, dst, _, off) =>
        if dst >= NREGS || Signed16(off) < 0 || Target(pc, off) > |prog|
        then NotValidated(pc, "branch not forward within the window")
        else
          var r := SymExec(prog, sp, pc + 1, ss, m);
          if r.NotValidated? then r else SymExec(prog, sp, Target(pc, off), ss, m)
      case _ =>
        match SymStep(sp, prog[pc], ss)
        case SFail(msg) => NotValidated(pc, msg)
        case SOk(ss') =>
          if !SWF(ss') then NotValidated(pc, "internal")
          // RB after the step's own checks (C5): it is about the record
          else if prog[pc].CallLocal? && BindFail(sp, pc, ss) != "" then NotValidated(pc, BindFail(sp, pc, ss))
          else SymExec(prog, sp, pc + 1, ss', m)
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

  function CountHelperCalls(prog: seq<Instr>): nat {
    if |prog| == 0 then 0 else (if prog[0].CallHelper? then 1 else 0) + CountHelperCalls(prog[1..])
  }

  // The only function that can return Validated for a region.
  function Validate(raw: seq<bv8>, sp: Spec): Verdict {
    if !SpecWF(sp) then NotValidated(-1, "bad window parameters")
    else if |raw| % 8 != 0 then NotValidated(-1, "length not a multiple of 8")
    else if NumInsns(raw) > MAX_INSNS then NotValidated(-1, "window too long")
    else match DecodeFrom(raw, 0)
      case DBad(p) => NotValidated(p, "instruction outside the allowlist")
      case DOk(prog) =>
        if sp.wrap.Wrap? then ValidateWrap(prog, sp)
        else if CountBranches(prog) > MAX_BRANCHES then NotValidated(-1, "too many branches")
        else SymExec(prog, sp, 0, SInit(), Top)
  }

  // P8: prog = WP . call W.  WP is checked statically (writes at most r4)
  // and symbolically up to call W; there W's body is entered (Mode WP).
  function ValidateWrap(prog: seq<Instr>, sp: Spec): Verdict
    requires SpecWF(sp) && sp.wrap.Wrap?
  {
    var n := |prog|;
    var body := sp.wrap.body;
    if n == 0 || !prog[n - 1].CallLocal? then NotValidated(-1, "P8 window does not end in call W")
    else if !(forall j :: 0 <= j < n - 1 ==> Writes(prog[j]) <= {4}) then NotValidated(-1, "WP writes a register other than r4")
    else if |body| % 8 != 0 || NumInsns(body) > MAX_INSNS then NotValidated(-1, "bad W body")
    else match DecodeFrom(body, 0)
      case DBad(p) => NotValidated(p, "W instruction outside the allowlist")
      case DOk(wprog) =>
        if !(forall j :: 0 <= j < |wprog| ==> WInsnOk(wprog[j], sp)) then NotValidated(-1, "W names r10 or calls a helper other than O[i]")
        else if CountHelperCalls(wprog) != 1 then NotValidated(-1, "W does not contain exactly one helper call (rule P8)")
        else if CountBranches(prog) + CountBranches(wprog) > MAX_BRANCHES then NotValidated(-1, "too many branches")
        else SymExec(prog[..n - 1], sp, 0, SInit(), WP(wprog))
  }
}
