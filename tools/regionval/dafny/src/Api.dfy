// Entry points compiled to Go.  Validate is Checker.Validate (the theorem in
// Soundness.dfy is about exactly that function).  The presets map the window
// kinds (README.md, Windows) to Spec values.  The theorem holds for any Spec;
// whether a preset asks enough of its kind is outside the proof and trusted
// (README.md, What it trusts).
include "Soundness.dfy"

module Api {
  import opened Bits
  import opened Semantics
  import opened Obligations
  import Checker

  // site: r1..r5 unchanged at the helper call, r0 = helper result at exit, r1..r5 free at exit.
  function SiteSpec(floor: int): Spec {
    Spec(floor, {1, 2, 3, 4, 5}, Helper(true, true), true, true, false, NoWrap, [])
  }

  // tail-call site (P4): r1..r5 unchanged at bpf_tail_call; r0..r5 free at exit.
  function TailSiteSpec(floor: int): Spec {
    Spec(floor, {0, 1, 2, 3, 4, 5}, Helper(true, false), true, true, false, NoWrap, [])
  }

  // entry prologue (P1): r1 preserved; r0, r2..r5 free (bottom at entry);
  // at most one hook call per path.
  function EntryPrologueSpec(floor: int): Spec {
    Spec(floor, {0, 2, 3, 4, 5}, NoHelper, true, true, false, NoWrap, [])
  }

  // callback prologue (P1b): only r0 may change.
  function CallbackPrologueSpec(floor: int): Spec {
    Spec(floor, {0}, NoHelper, true, false, false, NoWrap, [])
  }

  // only rG may change; stores below the floor are allowed.  The windows
  // prologue-P9 and passload-P9 use CustomSpec (README.md, Dafny core).
  function PassSpec(floor: int, g: nat): Spec {
    Spec(floor, {g}, NoHelper, true, false, false, NoWrap, [])
  }

  // hook body (P7): no store, no call, ends in EXIT with r0 = 0; r6..r9 kept.
  function HookBodySpec(): Spec {
    Spec(0, {0, 1, 2, 3, 4, 5}, NoHelper, false, false, true, NoWrap, [])
  }

  // wrapper site (P8): WP . call W.  body = W's instructions, helper = O[i]
  // (8 bytes).  r0 = helper result at exit, r1..r5 free; no store.
  function WrapSiteSpec(floor: int, body: seq<bv8>, helper: seq<bv8>): Spec {
    Spec(floor, {1, 2, 3, 4, 5}, Helper(false, true), false, true, false, Wrap(body, helper), [])
  }

  // The same spec with the record-binding obligation RB for its hook calls.
  function WithBinds(sp: Spec, binds: seq<Bind>): Spec { sp.(binds := binds) }

  function Validate(raw: seq<bv8>, sp: Spec): Checker.Verdict {
    Checker.Validate(raw, sp)
  }

  // One concrete step at s.pc (reference interpreter for differential tests).
  function ConcreteStep(raw: seq<bv8>, floor: int, s: CState, oracle: seq<bv64>): StepRes {
    if !CWF(s) || !(-(STACK as int) <= floor <= 0) || s.pc < 0 || s.pc >= NumInsns(raw) then Stuck
    else match Decode(InsnAt(raw, s.pc))
      case None => Stuck
      case Some(ins) => Step(floor, ins, s, oracle)
  }

  // A whole run over the region (fuel > number of instructions suffices for
  // validated regions, which only jump forward).
  function ConcreteRun(raw: seq<bv8>, floor: int, s: CState, oracle: seq<bv64>, fuel: nat): Outcome {
    if !CWF(s) || !(-(STACK as int) <= floor <= 0) then Escaped(s)
    else Run(raw, floor, s, oracle, fuel)
  }

  // The window's run as the theorem states it (RunWrap for P8, else Run).
  function ConcreteWindowRun(raw: seq<bv8>, sp: Spec, s: CState, oracle: seq<bv64>, fuel: nat): Outcome {
    if !CWF(s) || !(-(STACK as int) <= sp.floor <= 0) then Escaped(s)
    else WindowRun(raw, sp, s, oracle, fuel)
  }
}
