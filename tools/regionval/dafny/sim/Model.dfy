// Whole-program model of one XDP/tc execution segment, for the original
// program P and for its rewrite P'.
//
// TRUSTED SPECIFICATION, like Semantics.dfy: this file says what a run of P
// and of P' is.  Inserted instructions are decoded and computed with the
// region-level definitions of Semantics.dfy; original instructions are
// abstract classes whose value computations are parameters (Sem), so the
// theorem holds for every choice of them.
include "../src/Api.dfy"

module SimModel {
  import opened Bits
  import S = Semantics

  const NR: nat := 11
  const STK: nat := 512
  // The kernel's MAX_CALL_FRAMES: P gets stuck when it would push a ninth
  // frame.  P' may have a wrapper and a hook frame on top of that.
  const MAXF: nat := 8
  const MAXF_RW: nat := 10

  // ---------------- values and the logical address map ----------------

  // A register holds a word or is unreadable (verifier NOT_INIT).
  datatype Val = Bot | W(w: bv64)
  datatype Byte = BBot | B(b: bv8)

  // v of P and v' of P' agree: v is unreadable, or v' equals it.
  ghost predicate Rel(v: Val, v': Val) { v.Bot? || v' == v }
  ghost predicate RelB(b: Byte, b': Byte) { b.BBot? || b' == b }

  // The identification rho: an address names a logical object.  The frame
  // at depth d (0 = entry) has its 512 bytes just below StackTop(d) in both
  // runs; frames are STRIDE apart, so no access straddles two of them.
  const TOP0: int := 0x4000_0000_0000_0000
  const STRIDE: int := 0x1000
  const CTX: bv64 := 0x2000_0000_0000_0000
  const CODE0: int := 0xC000_0000_0000_0000

  function StackTop(d: nat): bv64 requires d < MAXF_RW { (TOP0 - d * STRIDE) as bv64 }

  // Address of byte o (0 <= o < 512, o = 512 + offset from r10) of frame d.
  function SAddr(d: nat, o: nat): bv64 requires d < MAXF_RW && o < STK {
    (TOP0 - d * STRIDE - STK + o) as bv64
  }

  // A function address (code(G), 0) is the same word in both runs.
  function FuncAddr(g: nat): bv64 requires g < 0x1_0000_0000 { (CODE0 + g) as bv64 }

  function AddrK(p: bv64, k: int): bv64 { ((p as int + k) % TWO64) as bv64 }

  ghost predicate InStackArea(a: bv64) { TOP0 - MAXF_RW * STRIDE <= a as int < TOP0 }

  // Where the w bytes at p are.  InStack(d, o): bytes o..o+w of live frame d.
  // Bad: partly inside a stack window, outside a live frame's 512 bytes, or
  // partly segment-local; the model has no rule for such an access.
  datatype Loc = InStack(d: nat, o: nat) | InLocal | Shared | Bad

  ghost function Classify(p: bv64, w: nat, nfr: nat, dom: set<bv64>): Loc {
    var a := p as int;
    if a + w > TOP0 - MAXF_RW * STRIDE && a < TOP0 then
      var d := (TOP0 - 1 - a) / STRIDE;
      var top := TOP0 - d * STRIDE;
      if d < nfr && top - STK <= a && a + w <= top then InStack(d, a - (top - STK)) else Bad
    else if forall k :: 0 <= k < w ==> AddrK(p, k) in dom then InLocal
    else if exists k :: 0 <= k < w && AddrK(p, k) in dom then Bad
    else Shared
  }

  // ---------------- segment-local memory ----------------

  // Packet, metadata, context and helper state H as bytes at fixed
  // addresses (the input decides them), and the tail-call budget.
  datatype Local = Local(mem: map<bv64, bv8>, budget: nat)

  // ---------------- original instructions (Table 1 classes) ----------------

  datatype Src = SR(r: nat) | SK(k: bv64)

  // Targets are absolute instruction indices.  In P' they are relocated
  // (SimRewrite.Reloc); FRef keeps the logical function and P' enters it
  // at fentry(g).
  datatype OInstr =
    | Alu(code: nat, dst: nat, srcs: seq<nat>)            // ALU, LD_IMM64 of a scalar or map
    | FRef(dst: nat, g: nat)                              // LD_IMM64 of a function address
    | Ld(dst: nat, base: nat, off: int, w: nat, sx: bool) // LDX, load-acquire
    | St(base: nat, off: int, w: nat, src: Src)           // ST, STX, store-release
    | Atom(op: nat, base: nat, off: int, w: nat, rs: nat, fetch: bool, cmpx: bool)
    | Legacy(w: nat, ix: Bits.Option<nat>, off: int)      // LD_ABS, LD_IND
    | Jcc(code: nat, srcs: seq<nat>, t: nat)              // conditional jump
    | Ja(t: nat)                                          // ja, gotol
    | MayGoto(t: nat)
    | Hcall(kf: bool, id: bv32)                           // helper (not tail_call, no callback) or kfunc
    | Tail                                                // bpf_tail_call (helper 12)
    | CbCall(id: bv32)                                    // bpf_loop, bpf_for_each_map_elem
    | Call(t: nat)                                        // BPF-to-BPF call, immediate target
    | Exit

  // The value computations of the original classes.  They are parameters:
  // the theorem holds for every choice.
  datatype Sem = Sem(
    alu: (nat, seq<bv64>) -> bv64,
    cond: (nat, seq<bv64>) -> bool,
    rmw: (nat, nat, bv64, bv64, Bits.Option<bv64>) -> bv64,       // op, w, vold, new operand, expected -> stored
    legacy: (Local, bv64, Bits.Option<bv64>, int, nat) -> Bits.Option<bv64>)  // None: out of bounds

  // Which registers r1..r_n a helper or kfunc reads, and the addresses it
  // reads through its pointer arguments (its footprint beta).
  datatype Env = Env(arity: (bool, bv32) -> nat, foot: (bool, bv32, seq<bv64>) -> seq<bv64>)

  // ---------------- external events and the oracle ----------------

  // i is always the index in P of the original instruction.
  datatype Ev =
    | ECall(i: nat, kf: bool, id: bv32, args: seq<bv64>, foot: seq<bv8>)
    | ELoad(i: nat, p: bv64, w: nat)
    | EStore(i: nat, p: bv64, w: nat, v: bv64)
    | ERmw(i: nat, op: nat, p: bv64, w: nat, n: bv64, x: Bits.Option<bv64>)
    | EMg(i: nat)
    | ECbRet(i: nat, v: bv64)

  datatype Resp =
    | RRet(v: Val, wr: map<bv64, bv8>)   // v = Bot for RET_VOID; wr: write set on segment-local memory
    | RInvoke(c: bv64, u: seq<Val>)      // run the callback at c with r1..r5 = u
    | RTailOk(q: bv64) | RTailFail
    | RVal(val: bv64) | RUnit | RTaken | RFall

  // Where the event is issued: frame depth, and whether the frame is an
  // inserted function (a wrapper).  Premise A8 says lookups ignore it.
  datatype Where = Where(depth: nat, inIns: bool)

  type Oracle = (seq<Ev>, Ev, Where) -> Resp

  // ---------------- configurations ----------------

  // fn: entry position of the frame's function in its program.
  datatype Kind = Main | Sub | Cb(idx: nat) | Ins
  datatype Frame = Frame(fn: nat, pc: int, regs: seq<Val>, kind: Kind, stack: seq<Byte>)
  // os: observer state (removed by pi_P).  hc: havoc values used so far.
  datatype Cfg = Cfg(fr: seq<Frame>, L: Local, h: seq<Ev>, hc: nat, os: seq<bv64>)
  datatype Term = TRet(v: bv64, L: Local, h: seq<Ev>) | TTail(q: bv64, c: bv64, L: Local, h: seq<Ev>)
  // Stuck(true): the step read an unreadable stack byte (A1b); Stuck(false): any other stuck step.
  datatype StepRes = Go(c: Cfg) | Done(t: Term) | Stuck(bot: bool)

  // P is deterministic given the oracle.  P' is a concrete machine: every
  // value P leaves unreadable is a havoc value hv(k) in P'.
  datatype Mode = MP | MR(hv: nat -> bv64)

  type Observer = (Cfg, seq<bv64>) -> Cfg

  // fentry(g): where a call or callback of function g enters (P: g; P': fe(g)).
  // fns: the function starts Fn(P).
  datatype Ctx = Ctx(m: Mode, env: Env, sem: Sem, om: Oracle, fentry: nat -> nat, fns: set<nat>)

  ghost function Limit(x: Ctx): nat { if x.m.MP? then MAXF else MAXF_RW }

  // k-th fresh unreadable value of the step.
  ghost function Und(x: Ctx, c: Cfg, k: nat): Val { if x.m.MP? then Bot else W(x.m.hv(c.hc + k)) }
  ghost function UndB(x: Ctx, c: Cfg, k: nat): Byte { if x.m.MP? then BBot else B(ByteOf(x.m.hv(c.hc + k), 0)) }
  ghost function HV(x: Ctx, c: Cfg): bv64 { if x.m.MR? then x.m.hv(c.hc) else 0 }

  ghost function Reg(f: Frame, r: nat): Val { if r < |f.regs| then f.regs[r] else Bot }
  ghost function SetR(f: Frame, r: nat, v: Val): Frame { if r < |f.regs| then f.(regs := f.regs[r := v]) else f }
  ghost function Adv(f: Frame): Frame { f.(pc := f.pc + 1) }
  ghost function Top(c: Cfg): Frame { if |c.fr| > 0 then c.fr[|c.fr| - 1] else Frame(0, 0, [], Main, []) }
  ghost function Put(c: Cfg, f: Frame): Cfg { if |c.fr| > 0 then c.(fr := c.fr[|c.fr| - 1 := f]) else c }
  ghost function Wh(c: Cfg): Where { Where(|c.fr|, Top(c).kind.Ins?) }

  // Values of registers rs; None if one is unreadable.
  ghost function Rds(f: Frame, rs: seq<nat>): Bits.Option<seq<bv64>> decreases |rs| {
    if |rs| == 0 then Bits.Some([])
    else match (Reg(f, rs[0]), Rds(f, rs[1..]))
      case (W(v), Some(vs)) => Bits.Some([v] + vs)
      case _ => Bits.None
  }

  function Upto(lo: nat, hi: nat): seq<nat> decreases hi - lo {
    if lo > hi then [] else [lo] + Upto(lo + 1, hi)
  }

  function ValidW(w: nat): bool { w == 1 || w == 2 || w == 4 || w == 8 }
  function Trunc(v: bv64, w: nat): bv64 requires w <= 8 { LE(BytesOf(v, w)) }
  function SextW(v: bv64, w: nat): bv64 {
    if w == 1 then (if v & 0x80 == 0 then v & 0xff else v | 0xffff_ffff_ffff_ff00)
    else if w == 2 then (if v & 0x8000 == 0 then v & 0xffff else v | 0xffff_ffff_ffff_0000)
    else if w == 4 then (if v & 0x8000_0000 == 0 then v & 0xffff_ffff else v | 0xffff_ffff_0000_0000)
    else v
  }

  // ---------------- memory ----------------

  ghost function StackBytes(c: Cfg, d: nat, o: nat, w: nat): seq<Byte> {
    if d < |c.fr| && o + w <= |c.fr[d].stack| then c.fr[d].stack[o .. o + w] else seq(w, _ => BBot)
  }
  ghost predicate AllDef(bs: seq<Byte>) { forall i :: 0 <= i < |bs| ==> bs[i].B? }
  ghost function Plain(bs: seq<Byte>): seq<bv8> { seq(|bs|, i requires 0 <= i < |bs| => if bs[i].B? then bs[i].b else 0) }
  ghost function LBytes(m: map<bv64, bv8>, p: bv64, w: nat): seq<bv8> {
    seq(w, k requires 0 <= k < w => if AddrK(p, k) in m then m[AddrK(p, k)] else 0)
  }

  ghost function WriteStack(c: Cfg, d: nat, o: nat, bs: seq<Byte>): Cfg {
    if d < |c.fr| && o + |bs| <= |c.fr[d].stack| then
      var st := c.fr[d].stack;
      c.(fr := c.fr[d := c.fr[d].(stack := st[..o] + bs + st[o + |bs|..])])
    else c
  }
  ghost function WriteMem(m: map<bv64, bv8>, p: bv64, bs: seq<bv8>): map<bv64, bv8> decreases |bs| {
    if |bs| == 0 then m else WriteMem(m[p := bs[0]], AddrK(p, 1), bs[1..])
  }
  ghost function WriteLocal(c: Cfg, p: bv64, bs: seq<bv8>): Cfg { c.(L := c.L.(mem := WriteMem(c.L.mem, p, bs))) }
  ghost function Bytes(bs: seq<bv8>): seq<Byte> { seq(|bs|, i requires 0 <= i < |bs| => B(bs[i])) }

  // A helper's write set: bytes of live frames and of segment-local memory.
  ghost function ApplyW(c: Cfg, wr: map<bv64, bv8>): Cfg {
    var fr' := seq(|c.fr|, d requires 0 <= d < |c.fr| =>
      c.fr[d].(stack := seq(|c.fr[d].stack|, o requires 0 <= o < |c.fr[d].stack| =>
        if d < MAXF_RW && o < STK && SAddr(d, o) in wr then B(wr[SAddr(d, o)]) else c.fr[d].stack[o])));
    var mem' := map a | a in c.L.mem :: if a in wr && !InStackArea(a) then wr[a] else c.L.mem[a];
    c.(fr := fr', L := c.L.(mem := mem'))
  }

  // The footprint bytes: segment-local bytes at the addresses; shared ones are left to the oracle.
  datatype FootRes = FOk(bs: seq<bv8>) | FBot | FBad
  ghost function FootBytes(c: Cfg, addrs: seq<bv64>): FootRes decreases |addrs| {
    if |addrs| == 0 then FOk([])
    else
      var rest := FootBytes(c, addrs[1..]);
      match Classify(addrs[0], 1, |c.fr|, c.L.mem.Keys)
      case Bad => FBad
      case Shared => rest
      case InLocal => if rest.FOk? then FOk(LBytes(c.L.mem, addrs[0], 1) + rest.bs) else rest
      case InStack(d, o) =>
        var b := StackBytes(c, d, o, 1);
        if !AllDef(b) then FBot else if rest.FOk? then FOk(Plain(b) + rest.bs) else rest
  }

  // ---------------- frames ----------------

  // Push a frame entering at pc with r1..r5 = args (unreadable ones become
  // fresh), r10 = its stack top, and a fresh stack.
  ghost function Push(x: Ctx, c: Cfg, fn: nat, pc: int, kind: Kind, args: seq<Val>): StepRes {
    var d := |c.fr|;
    if d >= Limit(x) then Stuck(false)
    else
      var regs := seq(NR, k requires 0 <= k < NR =>
        if 1 <= k <= 5 && k - 1 < |args| && args[k - 1].W? then args[k - 1]
        else if k == 10 then W(StackTop(d)) else Und(x, c, k));
      var st := seq(STK, i requires 0 <= i < STK => UndB(x, c, NR + i));
      Go(c.(fr := c.fr + [Frame(fn, pc, regs, kind, st)], hc := c.hc + NR + STK))
  }

  // The top frame resumes after a helper (or a return): apply the write
  // set, r0 := v, r1..r5 unreadable, next instruction.
  ghost function Finish(x: Ctx, c: Cfg, v: Val, wr: map<bv64, bv8>): StepRes {
    var c1 := ApplyW(c, wr);
    var f := Top(c1);
    var regs := seq(|f.regs|, k requires 0 <= k < |f.regs| =>
      if k == 0 then (if v.W? then v else Und(x, c1, 0)) else if k <= 5 then Und(x, c1, k) else f.regs[k]);
    Go(Put(c1, f.(pc := f.pc + 1, regs := regs)).(hc := c1.hc + 6))
  }

  ghost function Invoke(x: Ctx, c: Cfg, i: nat, cv: bv64, u: seq<Val>): StepRes {
    var g := cv as int - CODE0;
    if g >= 0 && g in x.fns then Push(x, c, x.fentry(g), x.fentry(g), Cb(i), u) else Stuck(false)
  }

  ghost function Pop(c: Cfg): Cfg { if |c.fr| > 0 then c.(fr := c.fr[..|c.fr| - 1]) else c }

  // exit of the top frame with r0 = v.
  ghost function ExitFrame(x: Ctx, c: Cfg, v: bv64): StepRes {
    match Top(c).kind
    case Main => Done(TRet(v, c.L, c.h))
    case Cb(i) =>
      var c1 := Pop(c);
      var e := ECbRet(i, v);
      var c2 := c1.(h := c.h + [e]);
      if |c1.fr| == 0 then Stuck(false)
      else (match x.om(c.h, e, Wh(c1))
        case RInvoke(cv, u) => Invoke(x, c2, i, cv, u)
        case RRet(v', wr) => Finish(x, c2, v', wr)
        case _ => Stuck(false))
    case _ =>
      var c1 := Pop(c);
      if |c1.fr| == 0 then Stuck(false) else Finish(x, c1, W(v), map[])
  }

  // ---------------- one step of an original instruction ----------------

  ghost function SetDst(c: Cfg, dst: nat, v: bv64): StepRes { Go(Put(c, Adv(SetR(Top(c), dst, W(v))))) }

  ghost function OStep(x: Ctx, ins: OInstr, idx: nat, c: Cfg): StepRes {
    var f := Top(c);
    match ins
    case Alu(code, dst, srcs) =>
      if dst >= 10 then Stuck(false)
      else (match Rds(f, srcs)
        case Some(vs) => SetDst(c, dst, x.sem.alu(code, vs))
        case None => Stuck(false))
    case FRef(dst, g) =>
      if dst >= 10 || g >= 0x1_0000_0000 then Stuck(false) else SetDst(c, dst, FuncAddr(g))
    case Ld(dst, base, off, w, sx) =>
      if dst >= 10 || !ValidW(w) then Stuck(false)
      else (match Reg(f, base)
        case Bot => Stuck(false)
        case W(bv) => LdStep(x, c, idx, dst, AddrK(bv, off), w, sx))
    case St(base, off, w, src) =>
      if !ValidW(w) then Stuck(false)
      else (match (Reg(f, base), if src.SR? then Reg(f, src.r) else W(src.k))
        case (W(bv), W(v)) => StStep(x, c, idx, AddrK(bv, off), w, Trunc(v, w))
        case _ => Stuck(false))
    case Atom(op, base, off, w, src, fetch, cmpx) =>
      if !(w == 4 || w == 8) || src >= 10 then Stuck(false)
      else (match (Reg(f, base), Reg(f, src), Reg(f, 0))
        case (W(bv), W(sv), r0) =>
          if cmpx && r0.Bot? then Stuck(false)
          else AtomStep(x, c, idx, op, AddrK(bv, off), w, src, fetch, cmpx, Trunc(sv, w),
                        if cmpx then Bits.Some(Trunc(r0.w, w)) else Bits.None)
        case _ => Stuck(false))
    case Legacy(w, ix, off) =>
      (match (Reg(f, 6), if ix.Some? then Reg(f, ix.value) else W(0))
        case (W(r6), W(iv)) =>
          (match x.sem.legacy(c.L, r6, if ix.Some? then Bits.Some(iv) else Bits.None, off, w)
           case Some(v) => Finish(x, c, W(v), map[])  // r0 := v, r1..r5 unreadable
           case None => ExitFrame(x, c, 0))           // out of bounds: r0 := 0 and exit the frame
        case _ => Stuck(false))
    case Jcc(code, srcs, t) =>
      (match Rds(f, srcs)
       case Some(vs) => Go(Put(c, f.(pc := if x.sem.cond(code, vs) then t else f.pc + 1)))
       case None => Stuck(false))
    case Ja(t) => Go(Put(c, f.(pc := t)))
    case MayGoto(t) =>
      var e := EMg(idx);
      var c1 := c.(h := c.h + [e]);
      (match x.om(c.h, e, Wh(c))
       case RTaken => Go(Put(c1, f.(pc := t)))
       case RFall => Go(Put(c1, Adv(f)))
       case _ => Stuck(false))
    case Hcall(kf, id) => HelperStep(x, c, idx, kf, id, false)
    case CbCall(id) => HelperStep(x, c, idx, false, id, true)
    case Tail =>
      (match Rds(f, [1, 2, 3])
       case None => Stuck(false)
       case Some(args) =>
         var e := ECall(idx, false, 12, args, []);
         var c1 := c.(h := c.h + [e]);
         match x.om(c.h, e, Wh(c))
         case RTailOk(q) =>
           Done(TTail(q, args[0], c.L.(budget := if c.L.budget > 0 then c.L.budget - 1 else 0), c1.h))
         case RTailFail =>
           var regs := seq(|f.regs|, k requires 0 <= k < |f.regs| => if k <= 5 then Und(x, c1, k) else f.regs[k]);
           Go(Put(c1, f.(pc := f.pc + 1, regs := regs)).(hc := c1.hc + 6))
         case _ => Stuck(false))
    case Call(t) =>
      Push(x, c, t, t, Sub, seq(5, k requires 0 <= k < 5 => Reg(f, k + 1)))
    case Exit =>
      match Reg(f, 0)
      case W(v) => ExitFrame(x, c, v)
      case Bot => Stuck(false)
  }

  ghost function LdStep(x: Ctx, c: Cfg, idx: nat, dst: nat, p: bv64, w: nat, sx: bool): StepRes
    requires ValidW(w)
  {
    var ext := (v: bv64) => if sx then SextW(v, w) else v;
    match Classify(p, w, |c.fr|, c.L.mem.Keys)
    case Bad => Stuck(false)
    case InStack(d, o) =>
      var bs := StackBytes(c, d, o, w);
      if !AllDef(bs) then Stuck(true) else SetDst(c, dst, ext(LE(Plain(bs))))
    case InLocal => SetDst(c, dst, ext(LE(LBytes(c.L.mem, p, w))))
    case Shared =>
      var e := ELoad(idx, p, w);
      match x.om(c.h, e, Wh(c))
      case RVal(v) => SetDst(c.(h := c.h + [e]), dst, ext(Trunc(v, w)))
      case _ => Stuck(false)
  }

  ghost function StStep(x: Ctx, c: Cfg, idx: nat, p: bv64, w: nat, v: bv64): StepRes
    requires ValidW(w)
  {
    match Classify(p, w, |c.fr|, c.L.mem.Keys)
    case Bad => Stuck(false)
    case InStack(d, o) => var c1 := WriteStack(c, d, o, Bytes(BytesOf(v, w))); Go(Put(c1, Adv(Top(c1))))
    case InLocal => var c1 := WriteLocal(c, p, BytesOf(v, w)); Go(Put(c1, Adv(Top(c1))))
    case Shared =>
      var e := EStore(idx, p, w, v);
      match x.om(c.h, e, Wh(c))
      case RUnit => var c1 := c.(h := c.h + [e]); Go(Put(c1, Adv(Top(c1))))
      case _ => Stuck(false)
  }

  // Registers after an atomic: cmpxchg sets r0, the fetch variants and xchg set src.
  ghost function AtomRegs(c: Cfg, src: nat, fetch: bool, cmpx: bool, vold: bv64): StepRes {
    if cmpx then SetDst(c, 0, vold) else if fetch then SetDst(c, src, vold) else Go(Put(c, Adv(Top(c))))
  }

  ghost function AtomStep(x: Ctx, c: Cfg, idx: nat, op: nat, p: bv64, w: nat, src: nat, fetch: bool, cmpx: bool,
                          n: bv64, xv: Bits.Option<bv64>): StepRes
    requires w == 4 || w == 8
  {
    match Classify(p, w, |c.fr|, c.L.mem.Keys)
    case Bad => Stuck(false)
    case InStack(d, o) =>
      var bs := StackBytes(c, d, o, w);
      if !AllDef(bs) then Stuck(true)
      else
        var vold := LE(Plain(bs));
        AtomRegs(WriteStack(c, d, o, Bytes(BytesOf(x.sem.rmw(op, w, vold, n, xv), w))), src, fetch, cmpx, vold)
    case InLocal =>
      var vold := LE(LBytes(c.L.mem, p, w));
      AtomRegs(WriteLocal(c, p, BytesOf(x.sem.rmw(op, w, vold, n, xv), w)), src, fetch, cmpx, vold)
    case Shared =>
      var e := ERmw(idx, op, p, w, n, xv);
      match x.om(c.h, e, Wh(c))
      case RVal(vo) => AtomRegs(c.(h := c.h + [e]), src, fetch, cmpx, Trunc(vo, w))
      case _ => Stuck(false)
  }

  // Helper, kfunc or callback helper: reads r1..r_n and its footprint,
  // issues the call event, and finishes, or starts a callback.
  ghost function HelperStep(x: Ctx, c: Cfg, idx: nat, kf: bool, id: bv32, cb: bool): StepRes {
    var n := x.env.arity(kf, id);
    if n > 5 then Stuck(false)
    else match Rds(Top(c), Upto(1, n))
      case None => Stuck(false)
      case Some(args) =>
        match FootBytes(c, x.env.foot(kf, id, args))
        case FBad => Stuck(false)
        case FBot => Stuck(true)
        case FOk(beta) =>
          var e := ECall(idx, kf, id, args, beta);
          var c1 := c.(h := c.h + [e]);
          match x.om(c.h, e, Wh(c))
          case RRet(v, wr) => Finish(x, c1, v, wr)
          case RInvoke(cv, u) => if cb then Invoke(x, c1, idx, cv, u) else Stuck(false)
          case _ => Stuck(false)
  }

  // ---------------- one step of an inserted instruction (P' only) ----------------

  // Registers as words for the region-level ALU (P' holds no Bot; see NoBot).
  ghost function R64(f: Frame): seq<bv64> {
    seq(NR, k requires 0 <= k < NR => if Reg(f, k).W? then Reg(f, k).w else 0)
  }

  // Inserted code reads segment-local memory as it is; any other load
  // returns an unconstrained value and issues no event (A2').
  ghost function InsLoad(x: Ctx, c: Cfg, p: bv64, w: nat): (bv64, nat) requires w <= 8 {
    match Classify(p, w, |c.fr|, c.L.mem.Keys)
    case InStack(d, o) => (LE(Plain(StackBytes(c, d, o, w))), 0)
    case InLocal => (LE(LBytes(c.L.mem, p, w)), 0)
    case _ => (Trunc(HV(x, c), w), 1)
  }

  // Inserted stores write segment-local memory; the model has no rule for others.
  ghost function InsStore(c: Cfg, p: bv64, w: nat, v: bv64): StepRes requires w <= 8 {
    match Classify(p, w, |c.fr|, c.L.mem.Keys)
    case InStack(d, o) => var c1 := WriteStack(c, d, o, Bytes(BytesOf(v, w))); Go(Put(c1, Adv(Top(c1))))
    case InLocal => var c1 := WriteLocal(c, p, BytesOf(v, w)); Go(Put(c1, Adv(Top(c1))))
    case _ => Stuck(false)
  }

  // hooks: entry positions of hook functions; a call to one first runs the observer.
  ghost function IStep(x: Ctx, hooks: set<nat>, obsv: Observer, b: seq<bv8>, c: Cfg): StepRes {
    var f := Top(c);
    var rs := R64(f);
    if |b| != 8 then Stuck(false)
    else match S.Decode(b)
      case None => Stuck(false)
      case Some(ins) =>
        match ins
        case Alu(is64, op, dst, opnd) =>
          if dst >= 10 then Stuck(false)
          else SetDst(c, dst, S.AluVal(is64, op, rs[dst], S.OperandVal(is64, opnd, rs)))
        case Ldx(w, dst, base, off) =>
          if dst >= 10 || base > 10 || w > 8 then Stuck(false)
          else
            var (v, k) := InsLoad(x, c, rs[base] + Sext16(off), w);
            SetDst(c.(hc := c.hc + k), dst, v)
        case Stx(w, base, src, off) =>
          if base > 10 || src > 10 || w > 8 then Stuck(false) else InsStore(c, rs[base] + Sext16(off), w, rs[src])
        case St(w, base, off, imm) =>
          if base > 10 || w > 8 then Stuck(false) else InsStore(c, rs[base] + Sext16(off), w, Sext32(imm))
        case Ja(off) => Go(Put(c, f.(pc := f.pc + 1 + Signed16(off))))
        case Jcond(cnd, dst, imm, off) =>
          if dst > 10 then Stuck(false)
          else Go(Put(c, f.(pc := if S.CondHolds(cnd, rs[dst], imm) then f.pc + 1 + Signed16(off) else f.pc + 1)))
        case CallHelper(_) => Stuck(false)
        case CallLocal(imm) =>
          var t := f.pc + 1 + Signed32(imm);
          if t < 0 then Stuck(false)
          else (match Push(x, c, t, t, Ins, seq(5, k requires 0 <= k < 5 => Reg(f, k + 1)))
            case Go(c1) => if t in hooks then Go(obsv(c1, rs[1..6])) else Go(c1)
            case r => r)
        case Exit =>
          match Reg(f, 0)
          case W(v) => ExitFrame(x, c, v)
          case Bot => Stuck(false)
  }

  // ---------------- programs and runs ----------------

  // P' instructions: an original (relocated, with its index in P) or an
  // inserted 8-byte instruction in wire format.
  datatype TI = O(ins: OInstr, idx: nat) | N(b: seq<bv8>)
  // fentry: entry position of each original function; hooks: entry
  // positions of hook functions; fns: Fn(P).
  datatype RwProg = RwProg(code: seq<TI>, fentry: map<nat, nat>, hooks: set<nat>, fns: set<nat>)

  ghost function FnSet(P: seq<OInstr>): set<nat> {
    {0} + (set j | 0 <= j < |P| && P[j].Call? :: P[j].t) + (set j | 0 <= j < |P| && P[j].FRef? :: P[j].g)
  }

  ghost function CtxP(P: seq<OInstr>, env: Env, sem: Sem, om: Oracle): Ctx {
    Ctx(MP, env, sem, om, g => g, FnSet(P))
  }
  ghost function CtxR(Pp: RwProg, env: Env, sem: Sem, om: Oracle, hv: nat -> bv64): Ctx {
    Ctx(MR(hv), env, sem, om, g => if g in Pp.fentry then Pp.fentry[g] else 0, Pp.fns)
  }

  ghost function StepP(P: seq<OInstr>, x: Ctx, c: Cfg): StepRes {
    var pc := Top(c).pc;
    if |c.fr| == 0 || pc < 0 || pc >= |P| then Stuck(false) else OStep(x, P[pc], pc, c)
  }

  ghost function StepR(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg): StepRes {
    var pc := Top(c).pc;
    if |c.fr| == 0 || pc < 0 || pc >= |Pp.code| then Stuck(false)
    else match Pp.code[pc]
      case O(ins, idx) => OStep(x, ins, idx, c)
      case N(b) => IStep(x, Pp.hooks, obsv, b, c)
  }

  datatype RunRes = Fin(t: Term) | Stk(bot: bool) | NoFuel

  ghost function RunP(P: seq<OInstr>, x: Ctx, c: Cfg, n: nat): RunRes decreases n {
    if n == 0 then NoFuel
    else match StepP(P, x, c)
      case Go(c1) => RunP(P, x, c1, n - 1)
      case Done(t) => Fin(t)
      case Stuck(b) => Stk(b)
  }

  ghost function RunR(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, n: nat): RunRes decreases n {
    if n == 0 then NoFuel
    else match StepR(Pp, x, obsv, c)
      case Go(c1) => RunR(Pp, x, obsv, c1, n - 1)
      case Done(t) => Fin(t)
      case Stuck(b) => Stk(b)
  }

  // The configuration after n steps, if the run is still going.
  ghost function ReachP(P: seq<OInstr>, x: Ctx, c: Cfg, n: nat): Bits.Option<Cfg> decreases n {
    if n == 0 then Bits.Some(c)
    else match StepP(P, x, c)
      case Go(c1) => ReachP(P, x, c1, n - 1)
      case _ => Bits.None
  }

  ghost function ReachR(Pp: RwProg, x: Ctx, obsv: Observer, c: Cfg, n: nat): Bits.Option<Cfg> decreases n {
    if n == 0 then Bits.Some(c)
    else match StepR(Pp, x, obsv, c)
      case Go(c1) => ReachR(Pp, x, obsv, c1, n - 1)
      case _ => Bits.None
  }

  // init(i, sigma): one main frame, r1 = ctx, r10 = its stack top, all else
  // unreadable (P) or havoc (P'); L is the input.
  ghost function InitP(L: Local): Cfg {
    Cfg([Frame(0, 0, seq(NR, k requires 0 <= k < NR => if k == 1 then W(CTX) else if k == 10 then W(StackTop(0)) else Bot),
               Main, seq(STK, _ => BBot))], L, [], 0, [])
  }
  ghost function InitR(L: Local, hv: nat -> bv64): Cfg {
    Cfg([Frame(0, 0, seq(NR, k requires 0 <= k < NR => if k == 1 then W(CTX) else if k == 10 then W(StackTop(0)) else W(hv(k))),
               Main, seq(STK, i requires 0 <= i < STK => B(ByteOf(hv(NR + i), 0))))], L, [], NR + STK, [])
  }

  // ---------------- observations ----------------

  // Endpoint, output (all of L: packet, metadata, context, H, budget), the
  // final map state Fin(h), and the trace h (with omega, the responses).
  datatype Observation<Sigma> =
    | ObsRet(v: bv64, out: Local, fin: Sigma, trace: seq<Ev>)
    | ObsTail(q: bv64, c: bv64, out: Local, fin: Sigma, trace: seq<Ev>)

  ghost function Observe<Sigma>(t: Term, Fin: seq<Ev> -> Sigma): Observation<Sigma> {
    match t
    case TRet(v, L, h) => ObsRet(v, L, Fin(h), h)
    case TTail(q, c, L, h) => ObsTail(q, c, L, Fin(h), h)
  }
}
