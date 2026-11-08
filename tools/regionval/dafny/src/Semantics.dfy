// TRUSTED SPECIFICATION: wire decoder and concrete semantics of the
// instruction subset allowed in inserted regions (README.md, Allowed instructions).
//
// Sources: RFC 9669 (BPF ISA) section 3 (encoding), 4.1 (ALU), 4.3 (jumps),
// 5.1 (regular load/store); calling convention as in README.md, What it trusts.
// Anything the decoder does not accept is not modelled: the concrete step on
// it is Stuck, so no obligation can hold on a path that reaches it.
include "Bits.dfy"

module Semantics {
  import opened Bits

  const NREGS: nat := 11
  const STACK: nat := 512

  datatype AluOp = Add | And | Or | Lsh | Mov
  datatype Operand = Reg(r: nat) | Imm(k: bv32)
  datatype Cond = JEq | JNe | JSge32

  datatype Instr =
    | Alu(is64: bool, op: AluOp, dst: nat, opnd: Operand)
    | Ldx(size: nat, dst: nat, base: nat, off: bv16)
    | Stx(size: nat, base: nat, src: nat, off: bv16)
    | St(size: nat, base: nat, off: bv16, imm: bv32)
    | Ja(off: bv16)
    | Jcond(cond: Cond, dst: nat, imm: bv32, off: bv16)
    | CallHelper(id: bv32)
    | CallLocal(imm: bv32)        // BPF_PSEUDO_CALL: hook (or wrapper) call
    | Exit

  // Registers an instruction writes (Alu, Ldx: dst; a call: r0..r5).
  // StepWrites (Soundness.dfy) proves Step changes no other register.
  function Writes(ins: Instr): set<nat> {
    match ins
    case Alu(_, _, dst, _) => {dst}
    case Ldx(_, dst, _, _) => {dst}
    case CallHelper(_) => {0, 1, 2, 3, 4, 5}
    case CallLocal(_) => {0, 1, 2, 3, 4, 5}
    case _ => {}
  }

  // The instruction names r10 as a register operand.
  predicate NamesR10(ins: Instr) {
    match ins
    case Alu(_, _, dst, o) => dst == 10 || o == Reg(10)
    case Ldx(_, dst, base, _) => dst == 10 || base == 10
    case Stx(_, base, src, _) => base == 10 || src == 10
    case St(_, base, _, _) => base == 10
    case Jcond(_, dst, _, _) => dst == 10
    case _ => false
  }

  // ---------------- wire decoder (RFC 9669 section 3) ----------------

  // Size field of LDX/STX/ST (RFC 9669 5.1): W=0x00 H=0x08 B=0x10 DW=0x18.
  function SizeOf(op: bv8): nat {
    var s := op & 0x18;
    if s == 0x00 then 4 else if s == 0x08 then 2 else if s == 0x10 then 1 else 8
  }

  function AluOpOf(code: bv8): Option<AluOp> {
    if code == 0x00 then Some(Add)
    else if code == 0x40 then Some(Or)
    else if code == 0x50 then Some(And)
    else if code == 0x60 then Some(Lsh)
    else if code == 0xb0 then Some(Mov)
    else None
  }

  // Decode one 8-byte instruction.  Every field not used by the
  // instruction must be zero (reserved fields, RFC 9669 3); otherwise None.
  // Registers written must be r0..r9 (r10 is read-only).
  function Decode(b: seq<bv8>): Option<Instr>
    requires |b| == 8
  {
    var op := b[0];
    var dst := (b[1] & 0x0f) as nat;
    var src := (b[1] >> 4) as nat;
    var off := (b[2] as bv16) | ((b[3] as bv16) << 8);
    var imm := (b[4] as bv32) | ((b[5] as bv32) << 8) | ((b[6] as bv32) << 16) | ((b[7] as bv32) << 24);
    var cls := op & 0x07;
    if dst > 10 || src > 10 then None
    // ALU (class 4) and ALU64 (class 7), RFC 9669 4.1
    else if cls == 0x04 || cls == 0x07 then
      var is64 := cls == 0x07;
      var aop := AluOpOf(op & 0xf0);
      if aop.None? || off != 0 || dst == 10 then None
      else if op & 0x08 == 0 then
        // K source: src field must be 0; shift count must be < width
        if src != 0 then None
        else if aop.value == Lsh && imm >= (if is64 then 64 else 32) then None
        else Some(Alu(is64, aop.value, dst, Imm(imm)))
      else
        // X source only for mov/and/or (add and lsh take an immediate)
        if imm != 0 || aop.value == Add || aop.value == Lsh then None
        else Some(Alu(is64, aop.value, dst, Reg(src)))
    // LDX MEM: 0x61 0x69 0x71 0x79
    else if op == 0x61 || op == 0x69 || op == 0x71 || op == 0x79 then
      if imm != 0 || dst == 10 then None else Some(Ldx(SizeOf(op), dst, src, off))
    // STX MEM: 0x63 0x6b 0x73 0x7b
    else if op == 0x63 || op == 0x6b || op == 0x73 || op == 0x7b then
      if imm != 0 then None else Some(Stx(SizeOf(op), dst, src, off))
    // ST MEM (0x62 0x6a 0x72 0x7a) is not in the allowlist: it does not occur
    // in inserted regions (the same set as core/allow.go).
    // JA (JMP class, 0x05)
    else if op == 0x05 then
      if dst != 0 || src != 0 || imm != 0 then None else Some(Ja(off))
    // JEQ K 0x15, JNE K 0x55 (JMP class); JSGE K 0x76 (JMP32 class)
    else if op == 0x15 || op == 0x55 || op == 0x76 then
      if src != 0 then None
      else Some(Jcond(if op == 0x15 then JEq else if op == 0x55 then JNe else JSge32, dst, imm, off))
    // CALL 0x85: src 0 = helper, src 1 = BPF_PSEUDO_CALL; others rejected
    else if op == 0x85 then
      if dst != 0 || off != 0 then None
      else if src == 0 then Some(CallHelper(imm))
      else if src == 1 then Some(CallLocal(imm))
      else None
    // EXIT 0x95
    else if op == 0x95 then
      if dst != 0 || src != 0 || off != 0 || imm != 0 then None else Some(Exit)
    else None
  }

  function NumInsns(raw: seq<bv8>): nat { |raw| / 8 }

  function InsnAt(raw: seq<bv8>, pc: nat): seq<bv8>
    requires pc < NumInsns(raw)
  {
    raw[8 * pc .. 8 * pc + 8]
  }

  // ---------------- concrete state ----------------

  // An event records what the region did that the obligations talk about.
  datatype Event =
    | EStore(addr: bv64, width: nat)
    | EHelper(args: seq<bv64>, ret: bv64, stackAfter: seq<bv8>, id: bv32)
    | EHook
    | ECallW(regs: seq<bv64>)     // P8: call W; the caller's registers at the call
    | ERet(r0: bv64)              // P8: EXIT in W; W's r0

  // regs: r0..r10.  stack: the 512 bytes [r10-512, r10), index i is r10-512+i.
  // log: every value the region obtained from outside (loads, call results);
  //      the checker names these values with fresh symbols (see Terms).
  // oc:  how many oracle values have been consumed.
  datatype CState = CState(pc: int, regs: seq<bv64>, stack: seq<bv8>,
                           log: seq<bv64>, oc: nat, events: seq<Event>)

  predicate CWF(s: CState) { |s.regs| == NREGS && |s.stack| == STACK }

  // The environment's choices (values of other memory, helper and hook
  // results) are read from an oracle sequence.  Quantifying over every
  // oracle quantifies over every execution.
  function Orc(oracle: seq<bv64>, i: nat): bv64 { if i < |oracle| then oracle[i] else 0 }

  // Offset of address a relative to the frame pointer fp.
  function Rel(a: bv64, fp: bv64): int { Signed64(a - fp) }

  predicate InFrame(rel: int, w: nat) { -(STACK as int) <= rel && rel + w <= 0 }

  // ---------------- concrete step (one per instruction class) ----------------

  function AluVal(is64: bool, op: AluOp, a: bv64, b: bv64): bv64 {
    if is64 then
      match op
      case Add => a + b
      case And => a & b
      case Or  => a | b
      case Lsh => a << (b & 63)
      case Mov => b
    else
      // ALU32: operate on the low 32 bits, zero-extend the result (RFC 9669 4.1)
      match op
      case Add => Low32(a + b)
      case And => Low32(a & b)
      case Or  => Low32(a | b)
      case Lsh => Low32(a << (b & 31))
      case Mov => Low32(b)
  }

  // ALU64 sign-extends imm; ALU32 uses its 32 bits (RFC 9669 4.1).
  function OperandVal(is64: bool, o: Operand, regs: seq<bv64>): bv64
    requires |regs| == NREGS
  {
    match o
    case Reg(r) => if r < NREGS then regs[r] else 0
    case Imm(k) => if is64 then Sext32(k) else k as bv64
  }

  function CondHolds(c: Cond, v: bv64, imm: bv32): bool {
    match c
    case JEq => v == Sext32(imm)
    case JNe => v != Sext32(imm)
    case JSge32 => Signed32((v & 0xffff_ffff) as bv32) >= Signed32(imm)
  }

  function SetReg(regs: seq<bv64>, r: nat, v: bv64): seq<bv64>
    requires |regs| == NREGS && r < NREGS
  {
    regs[r := v]
  }

  function WriteBytes(st: seq<bv8>, idx: nat, bs: seq<bv8>): seq<bv8>
    requires idx + |bs| <= |st|
  {
    seq(|st|, i requires 0 <= i < |st| => if idx <= i < idx + |bs| then bs[i - idx] else st[i])
  }

  // Havoc of n registers starting at r0 from the oracle.
  function HavocRegs(regs: seq<bv64>, oracle: seq<bv64>, oc: nat, n: nat): seq<bv64>
    requires |regs| == NREGS && n <= NREGS
  {
    seq(NREGS, k requires 0 <= k < NREGS => if k < n then Orc(oracle, oc + k) else regs[k])
  }

  datatype StepRes = Next(s: CState) | Halt(s: CState) | Stuck

  // Dispatch on the instruction class.  floor: the function's floor f.
  opaque function Step(floor: int, ins: Instr, s: CState, oracle: seq<bv64>): StepRes
    requires CWF(s) && -(STACK as int) <= floor <= 0
  {
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
  }

  // ALU rows (RFC 9669 4.1).
  function AluStep(s: CState, is64: bool, op: AluOp, dst: nat, opnd: Operand): StepRes
    requires CWF(s) && dst < 10
  {
    var v := AluVal(is64, op, s.regs[dst], OperandVal(is64, opnd, s.regs));
    Next(s.(pc := s.pc + 1, regs := SetReg(s.regs, dst, v)))
  }

  // LDX MEM (RFC 9669 5.1): stack bytes if the access lies in the frame,
  // else other memory (an oracle value).  The loaded value is logged.
  opaque function LoadVal(s: CState, addr: bv64, w: nat, oracle: seq<bv64>): bv64
    requires CWF(s) && w <= 8
  {
    var rel := Rel(addr, s.regs[10]);
    if InFrame(rel, w) then LE(s.stack[rel + 512 .. rel + 512 + w]) else LE(BytesOf(Orc(oracle, s.oc), w))
  }

  function LdxStep(s: CState, w: nat, dst: nat, base: nat, off: bv16, oracle: seq<bv64>): StepRes
    requires CWF(s) && w <= 8 && dst < 10 && base <= 10
  {
    var addr := s.regs[base] + Sext16(off);
    var v := LoadVal(s, addr, w, oracle);
    var oc' := if InFrame(Rel(addr, s.regs[10]), w) then s.oc else s.oc + 1;
    Next(s.(pc := s.pc + 1, regs := SetReg(s.regs, dst, v), log := s.log + [v], oc := oc'))
  }

  // STX / ST MEM (RFC 9669 5.1); every store is recorded as an event.
  function StoreStep(s: CState, addr: bv64, w: nat, v: bv64): StepRes
    requires CWF(s) && w <= 8
  {
    var rel := Rel(addr, s.regs[10]);
    var stack' := if InFrame(rel, w) then WriteBytes(s.stack, rel + 512, BytesOf(v, w)) else s.stack;
    Next(s.(pc := s.pc + 1, stack := stack', events := s.events + [EStore(addr, w)]))
  }

  // Central helper call: r0 <- result, r1..r5 clobbered,
  // stack [f,0) may be written by the helper; r6..r10 and the stack below
  // f preserved.
  function HelperStack(floor: int, s: CState, oracle: seq<bv64>): seq<bv8>
    requires CWF(s) && -(STACK as int) <= floor <= 0
  {
    var lo := 512 + floor;
    seq(STACK, i requires 0 <= i < STACK => if i >= lo then ByteOf(Orc(oracle, s.oc + 6 + (i - lo)), 0) else s.stack[i])
  }

  function HelperStep(floor: int, s: CState, oracle: seq<bv64>, id: bv32): StepRes
    requires CWF(s) && -(STACK as int) <= floor <= 0
  {
    var regs' := HavocRegs(s.regs, oracle, s.oc, 6);
    var up := -floor;
    var lo := 512 + floor;
    var stack' := HelperStack(floor, s, oracle);
    var newVals := regs'[0..6] + seq(up, j requires 0 <= j < up => Zext8(stack'[lo + j]));
    Next(s.(pc := s.pc + 1, regs := regs', stack := stack', log := s.log + newVals, oc := s.oc + 6 + up,
            events := s.events + [EHelper(s.regs[1..6], regs'[0], stack', id)]))
  }

  // Hook call (trusted calling convention): r0..r5 clobbered, r6..r10 and the whole stack preserved.
  function HookStep(s: CState, oracle: seq<bv64>): StepRes
    requires CWF(s)
  {
    var regs' := HavocRegs(s.regs, oracle, s.oc, 6);
    Next(s.(pc := s.pc + 1, regs := regs', log := s.log + regs'[0..6], oc := s.oc + 6, events := s.events + [EHook]))
  }

  // ---------------- runs over a region ----------------

  datatype Outcome =
    | Done(s: CState)        // fell through to the instruction just after the region
    | Exited(s: CState)      // executed EXIT (hook bodies)
    | Escaped(s: CState)     // control left the region elsewhere, or undecodable insn
    | OutOfFuel(s: CState)

  opaque function Run(raw: seq<bv8>, floor: int, s: CState, oracle: seq<bv64>, fuel: nat): Outcome
    requires CWF(s) && -(STACK as int) <= floor <= 0
    decreases fuel
  {
    if s.pc == NumInsns(raw) then Done(s)
    else if s.pc < 0 || s.pc > NumInsns(raw) then Escaped(s)
    else if fuel == 0 then OutOfFuel(s)
    else match Decode(InsnAt(raw, s.pc))
      case None => Escaped(s)
      case Some(ins) =>
        match Step(floor, ins, s, oracle)
        case Stuck => Escaped(s)
        case Halt(s') => Exited(s')
        case Next(s') => if CWF(s') then Run(raw, floor, s', oracle, fuel - 1) else Escaped(s')
  }

  // ---------------- P8: the window WP . call W ----------------
  //
  // The last instruction of a P8 window is the BPF_PSEUDO_CALL to the
  // wrapper W.  W's body (wraw) runs as a second frame (depth 1) on the same
  // Step, and EXIT in W returns to the caller (as interp's call and exit,
  // and the kernel verifier's set_callee_state).
  //  - entry: W's r1..r5 are the caller's; W's r0, r6..r9 are undefined
  //    (oracle values, in this order).  W's r10 slot holds frame 0's base:
  //    the model places stack accesses relative to r10 and models frame 0
  //    only.  W's own frame is not modelled; a validated W never names r10
  //    (ObligationsHold), so it has no way to reach that frame.
  //  - return: the caller's r0 = W's r0; r1..r5 undefined (oracle);
  //    r6..r10 kept; pc = the instruction after call W (= window end).
  //  - falling off the end of W escapes.

  function WPart(raw: seq<bv8>): seq<bv8>
    requires NumInsns(raw) >= 1
  {
    raw[..8 * (NumInsns(raw) - 1)]
  }

  function EnterW(s: CState, oracle: seq<bv64>): CState
    requires CWF(s)
  {
    var regs := seq(NREGS, k requires 0 <= k < NREGS =>
                      if 1 <= k <= 5 || k == 10 then s.regs[k] else Orc(oracle, s.oc + (if k == 0 then 0 else k - 5)));
    CState(0, regs, s.stack, s.log + [regs[0], regs[6], regs[7], regs[8], regs[9]], s.oc + 5, s.events + [ECallW(s.regs)])
  }

  function ReturnW(s1: CState, t: CState, oracle: seq<bv64>): CState
    requires CWF(s1) && CWF(t)
  {
    var regs := seq(NREGS, k requires 0 <= k < NREGS =>
                      if k == 0 then t.regs[0] else if k <= 5 then Orc(oracle, t.oc + (k - 1)) else s1.regs[k]);
    CState(s1.pc + 1, regs, t.stack, t.log + regs[1..6], t.oc + 5, t.events + [ERet(t.regs[0])])
  }

  // W's body has run from EnterW(s1) with outcome o.
  function WPost(s1: CState, oracle: seq<bv64>, o: Outcome): Outcome {
    match o
    case Exited(t) => if CWF(s1) && CWF(t) then Done(ReturnW(s1, t, oracle)) else Escaped(t)
    case Done(t) => Escaped(t)        // fell off the end of W
    case _ => o
  }

  // s1 is at call W.
  function CallW(raw: seq<bv8>, wraw: seq<bv8>, floor: int, s1: CState, oracle: seq<bv64>, fuel: nat): Outcome
    requires -(STACK as int) <= floor <= 0 && NumInsns(raw) >= 1
  {
    if !CWF(s1) || s1.pc != NumInsns(raw) - 1 then Escaped(s1)
    else match Decode(InsnAt(raw, s1.pc))
      case Some(CallLocal(_)) => WPost(s1, oracle, Run(wraw, floor, EnterW(s1, oracle), oracle, fuel))
      case _ => Escaped(s1)
  }

  // WP (the window without call W) has run with outcome o.
  function WPPost(raw: seq<bv8>, wraw: seq<bv8>, floor: int, oracle: seq<bv64>, fuel: nat, o: Outcome): Outcome
    requires -(STACK as int) <= floor <= 0 && NumInsns(raw) >= 1
  {
    match o
    case Done(s1) => CallW(raw, wraw, floor, s1, oracle, fuel)
    case Escaped(s1) => if s1.pc == NumInsns(raw) then Done(s1) else o   // a jump over call W to the window end
    case _ => o
  }

  function RunWrap(raw: seq<bv8>, wraw: seq<bv8>, floor: int, s: CState, oracle: seq<bv64>, fuel: nat): Outcome
    requires CWF(s) && -(STACK as int) <= floor <= 0
  {
    if NumInsns(raw) == 0 then Escaped(s)
    else WPPost(raw, wraw, floor, oracle, fuel, Run(WPart(raw), floor, s, oracle, fuel))
  }

  function InitState(regs: seq<bv64>, stack: seq<bv8>): CState {
    CState(0, regs, stack, [], 0, [])
  }
}
