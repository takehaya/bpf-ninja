// TRUSTED SPECIFICATION: what "Validated" promises (README.md, Obligations).
// Stated only over concrete runs (Semantics), never over symbolic terms.
include "Semantics.dfy"

module Obligations {
  import opened Bits
  import opened Semantics

  // How the window treats the central original helper call.
  //   checkArgs:  r1..r5 at the call equal their entry values (site windows)
  //   restoreR0:  r0 at exit equals the helper's result on every path
  datatype HelperMode = NoHelper | Helper(checkArgs: bool, restoreR0: bool)

  // P8 (wrapper site WP . call W): body = W's instructions (wire format),
  // helper = the original helper call O[i] (8 bytes).  NoWrap for all other kinds.
  datatype WrapMode = NoWrap | Wrap(body: seq<bv8>, helper: seq<bv8>)

  // The helper id of an 8-byte helper call instruction.  (Opaque only to keep
  // Decode out of the solver's way; no proof needs its body.)
  opaque function HelperIdOf(b: seq<bv8>): Option<bv32> {
    if |b| != 8 then None
    else match Decode(b)
      case Some(CallHelper(id)) => Some(id)
      case _ => None
  }

  // Map lookups do not read r4 (trusted; core/oblig.go isLookup).
  predicate IsLookup(id: bv32) { id == 1 || id == 195 }

  // Record binding (rule RB), separate from the preservation obligations:
  // at the hook call at pc, register reg (r1..r5) holds the key pointer the
  // central helper received (its r2) or the value the helper returned (r0).
  // pc counts instructions of the window, or of W for a wrapper site, whose
  // hook calls are all in W.  CopyArg(off) is a value passed as a stack
  // copy (CopyReadOnly): the register holds r10 + off, and r0 still holds
  // the helper's result at the call.  That the bytes at off are a copy of
  // the value is not stated here (dafny/contract checks the copy's shape).
  // Which hook parameters get a Bind is the caller's choice
  // (dafny/contract), as is the rest of the Spec.
  datatype Role = KeyArg | ValueArg | CopyArg(off: int)
  datatype Bind = Bind(pc: nat, reg: nat, role: Role)

  // Per-window parameters.  Presets for each window kind are in Api.dfy.
  //   floor:      f, -512 <= f <= 0 (from the stack report; trusted)
  //   free:       registers among r0..r5 whose exit value is unconstrained
  //   allowStore: whether the window may store at all
  //   hookCalls:  whether one BPF_PSEUDO_CALL (hook call) per path is allowed
  //   exitMode:   hook body: must end in EXIT with r0 == 0
  //   wrap:       P8 wrapper site (W's body and O[i]); the run is RunWrap
  //   binds:      record binding of hook arguments (empty: none)
  datatype Spec = Spec(floor: int, free: set<nat>, helper: HelperMode,
                       allowStore: bool, hookCalls: bool, exitMode: bool, wrap: WrapMode,
                       binds: seq<Bind>)

  predicate SpecWF(sp: Spec) {
    -(STACK as int) <= sp.floor <= 0
    && (forall k :: k in sp.free ==> k <= 5)
    && (sp.exitMode ==> sp.helper.NoHelper?)
    && (sp.wrap.Wrap? ==> HelperIdOf(sp.wrap.helper).Some? && sp.helper == Helper(false, true)
                          && !sp.allowStore && !sp.exitMode)
    && (|sp.binds| > 0 ==> sp.helper.Helper? && sp.hookCalls)
    && (forall b :: b in sp.binds ==> 1 <= b.reg <= 5)
  }

  // The concrete run of the window.
  function WindowRun(raw: seq<bv8>, sp: Spec, s: CState, oracle: seq<bv64>, fuel: nat): Outcome
    requires CWF(s) && -(STACK as int) <= sp.floor <= 0
  {
    if sp.wrap.Wrap? then RunWrap(raw, sp.wrap.body, sp.floor, s, oracle, fuel)
    else Run(raw, sp.floor, s, oracle, fuel)
  }

  function WrapLen(sp: Spec): nat { if sp.wrap.Wrap? then NumInsns(sp.wrap.body) else 0 }

  // r0 has its own exit obligation (helper result, or 0 for hook bodies).
  predicate R0Special(sp: Spec) {
    sp.exitMode || (sp.helper.Helper? && sp.helper.restoreR0)
  }

  // C1 (store target r10+o with -512 <= o, o + width <= f), C5 (which calls
  // are allowed), and the site rule "r1..r5 at the helper call are unchanged".
  predicate EventOk(sp: Spec, s0: CState, e: Event)
    requires CWF(s0)
  {
    match e
    case EStore(a, w) =>
      sp.allowStore && -(STACK as int) <= Rel(a, s0.regs[10]) && Rel(a, s0.regs[10]) + w <= sp.floor
    case EHelper(args, _, _, id) =>
      sp.helper.Helper? && (sp.helper.checkArgs ==> args == s0.regs[1..6])
      // P8: the helper is O[i]; r1, r2, r3, r5 (and r4 unless a lookup) are the site's entry values
      && (sp.wrap.Wrap? ==> Some(id) == HelperIdOf(sp.wrap.helper) && |args| == 5
                            && args[0] == s0.regs[1] && args[1] == s0.regs[2] && args[2] == s0.regs[3]
                            && args[4] == s0.regs[5] && (!IsLookup(id) ==> args[3] == s0.regs[4]))
    case EHook(_, _, _, _) => sp.hookCalls
    // P8: at call W, every register but r4 has its entry value
    case ECallW(regs) =>
      sp.wrap.Wrap? && |regs| == NREGS && (forall k :: 0 <= k <= 9 && k != 4 ==> regs[k] == s0.regs[k])
    case ERet(_) => sp.wrap.Wrap?
  }

  function CountHelpers(evs: seq<Event>): nat {
    if |evs| == 0 then 0 else CountHelpers(evs[..|evs|-1]) + (if evs[|evs|-1].EHelper? then 1 else 0)
  }

  function CountHooks(evs: seq<Event>): nat {
    if |evs| == 0 then 0 else CountHooks(evs[..|evs|-1]) + (if evs[|evs|-1].EHook? then 1 else 0)
  }

  // Result of the (last) helper call; 0 if there was none.
  function HelperRet(evs: seq<Event>): bv64 {
    if |evs| == 0 then 0
    else if evs[|evs|-1].EHelper? then evs[|evs|-1].ret
    else HelperRet(evs[..|evs|-1])
  }

  // The key pointer (r2) of the (last) helper call; 0 if there was none.
  function HelperKey(evs: seq<Event>): bv64 {
    if |evs| == 0 then 0
    else if evs[|evs|-1].EHelper? then (if |evs[|evs|-1].args| >= 2 then evs[|evs|-1].args[1] else 0)
    else HelperKey(evs[..|evs|-1])
  }

  // RB: a hook call e, after the events prior, meets every Bind at its pc:
  // the helper has run, and the bound register holds its key or its result.
  predicate BindOk(sp: Spec, prior: seq<Event>, e: Event) {
    e.EHook? ==>
      forall j :: 0 <= j < |sp.binds| && sp.binds[j].pc == e.pc ==>
        var b := sp.binds[j];
        CountHelpers(prior) == 1 && 1 <= b.reg <= 5 && |e.args| == 5
        && match b.role
           case KeyArg => e.args[b.reg - 1] == HelperKey(prior)
           case ValueArg => e.args[b.reg - 1] == HelperRet(prior)
           case CopyArg(off) => Rel(e.args[b.reg - 1], e.fp) == off && e.r0 == HelperRet(prior)
  }

  predicate AllBound(sp: Spec, evs: seq<Event>) {
    forall i :: 0 <= i < |evs| ==> BindOk(sp, evs[..i], evs[i])
  }

  // The stack the region must leave untouched at [f, 0): the entry stack, or
  // the stack right after the helper call (the helper is original code).
  function UpperBase(evs: seq<Event>, entry: seq<bv8>): seq<bv8> {
    if |evs| == 0 then entry
    else if evs[|evs|-1].EHelper? then evs[|evs|-1].stackAfter
    else UpperBase(evs[..|evs|-1], entry)
  }

  predicate FinalOk(sp: Spec, s0: CState, s: CState)
    requires CWF(s0)
  {
    CWF(s)
    // C1, C5 kinds, site argument rule
    && (forall i :: 0 <= i < |s.events| ==> EventOk(sp, s0, s.events[i]))
    // C5 counts: the helper exactly once if the window has one; at most one hook call
    && CountHelpers(s.events) == (if sp.helper.Helper? then 1 else 0)
    && CountHooks(s.events) <= 1
    // C2: r6..r10 preserved
    && (forall k :: 6 <= k <= 10 ==> s.regs[k] == s0.regs[k])
    // window-specific: registers not declared free are preserved
    && (forall k :: 0 <= k <= 5 && k !in sp.free && !(k == 0 && R0Special(sp)) ==> s.regs[k] == s0.regs[k])
    // site: r0 restored to the helper result
    && (sp.helper.Helper? && sp.helper.restoreR0 ==> s.regs[0] == HelperRet(s.events))
    // hook body: r0 = 0 at exit
    && (sp.exitMode ==> s.regs[0] == 0)
    // RB: record binding of hook arguments
    && AllBound(sp, s.events)
    // C3: stack at or above the floor untouched by the region
    && |UpperBase(s.events, s0.stack)| == STACK
    && (forall i :: 0 <= i < STACK && STACK as int + sp.floor <= i ==> s.stack[i] == UpperBase(s.events, s0.stack)[i])
  }

  // P8, instructions of W: no r10 operand, and no helper call other than O[i].
  predicate WInsnOk(ins: Instr, sp: Spec) {
    !NamesR10(ins) && (ins.CallHelper? ==> sp.wrap.Wrap? && Some(ins.id) == HelperIdOf(sp.wrap.helper))
  }

  // P8, static part: the window is WP . call W; every instruction of WP
  // writes at most r4 (so WP calls nothing: a call writes r0..r5); W decodes
  // and every instruction of W satisfies WInsnOk.
  predicate WrapStatic(raw: seq<bv8>, sp: Spec)
    requires sp.wrap.Wrap?
  {
    var n := NumInsns(raw);
    var body := sp.wrap.body;
    n >= 1 && Decode(InsnAt(raw, n - 1)).Some? && Decode(InsnAt(raw, n - 1)).value.CallLocal?
    && (forall j :: 0 <= j < n - 1 ==> Decode(InsnAt(raw, j)).Some? && Writes(Decode(InsnAt(raw, j)).value) <= {4})
    && |body| % 8 == 0
    && (forall j :: 0 <= j < NumInsns(body) ==> Decode(InsnAt(body, j)).Some? && WInsnOk(Decode(InsnAt(body, j)).value, sp))
  }

  // P8: the run ends with the return from W, and W returned the helper result.
  predicate WRetOk(evs: seq<Event>) {
    |evs| > 0 && evs[|evs| - 1].ERet? && evs[|evs| - 1].r0 == HelperRet(evs[..|evs| - 1])
  }

  // C4 is the shape of the outcome: the run reaches the point just after the
  // window (or EXIT for hook bodies) and never leaves the window elsewhere.
  predicate ObligationsHold(raw: seq<bv8>, sp: Spec, s0: CState, out: Outcome)
    requires CWF(s0)
  {
    match out
    case Done(s) => !sp.exitMode && FinalOk(sp, s0, s)
                    && (sp.wrap.Wrap? ==> WrapStatic(raw, sp) && WRetOk(s.events))
    case Exited(s) => sp.exitMode && FinalOk(sp, s0, s)
    case Escaped(_) => false
    case OutOfFuel(_) => false
  }
}
