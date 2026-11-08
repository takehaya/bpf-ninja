// Package regionvaldafny is a thin wrapper around the Go code that Dafny
// generates from ../../src (gen-go/).  It only converts between Go values and
// Dafny runtime values; every decision is made by the verified Dafny code.
//
//   - Validate: Checker.Validate, the function covered by Soundness.Soundness.
//   - ConcreteStep / ConcreteRun: the concrete semantics (reference interpreter).
//   - ObligationsHold: the obligation predicate, for differential tests.
package regionvaldafny

import (
	_dafny "github.com/dafny-lang/DafnyRuntimeGo/v4/dafny"
	api "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Api"
	obl "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Obligations"
	sem "github.com/takehaya/bpf-ninja/tools/regionval/dafny/gen-go/Semantics"
)

const (
	NRegs = 11
	Stack = 512
)

// Spec is the per-window parameter set (Obligations.Spec).  Build it with one
// of the presets or with CustomSpec.
type Spec struct{ d obl.Spec }

func SiteSpec(floor int) Spec { return Spec{api.Companion_Default___.SiteSpec(_dafny.IntOf(floor))} }
func TailSiteSpec(floor int) Spec {
	return Spec{api.Companion_Default___.TailSiteSpec(_dafny.IntOf(floor))}
}
func EntryPrologueSpec(floor int) Spec {
	return Spec{api.Companion_Default___.EntryPrologueSpec(_dafny.IntOf(floor))}
}
func CallbackPrologueSpec(floor int) Spec {
	return Spec{api.Companion_Default___.CallbackPrologueSpec(_dafny.IntOf(floor))}
}
func PassSpec(floor, g int) Spec {
	return Spec{api.Companion_Default___.PassSpec(_dafny.IntOf(floor), _dafny.IntOf(g))}
}
func HookBodySpec() Spec { return Spec{api.Companion_Default___.HookBodySpec()} }

// CustomSpec builds an arbitrary Spec.  helper=false means no central helper
// call (checkArgs and restoreR0 are then ignored).
func CustomSpec(floor int, free []int, helper, checkArgs, restoreR0, allowStore, hookCalls, exitMode bool) Spec {
	fs := make([]interface{}, len(free))
	for i, k := range free {
		fs[i] = _dafny.IntOf(k)
	}
	hm := obl.Companion_HelperMode_.Create_NoHelper_()
	if helper {
		hm = obl.Companion_HelperMode_.Create_Helper_(checkArgs, restoreR0)
	}
	return Spec{obl.Companion_Spec_.Create_Spec_(_dafny.IntOf(floor), _dafny.SetOf(fs...), hm, allowStore, hookCalls, exitMode)}
}

// Verdict of Validate.  PC is the window-relative instruction index the
// reason refers to (-1 for whole-window reasons).
type Verdict struct {
	Validated bool
	PC        int
	Reason    string
}

// Validate checks one window (raw 8-byte instructions, wire format) against spec.
func Validate(insns []byte, sp Spec) Verdict {
	v := api.Companion_Default___.Validate(_dafny.SeqOfBytes(insns), sp.d)
	if v.Is_Validated() {
		return Verdict{Validated: true}
	}
	return Verdict{PC: int(v.Dtor_pc().Int64()), Reason: _dafny.SequenceVerbatimString(v.Dtor_reason(), false)}
}

// ---------------- concrete semantics ----------------

type EventKind int

const (
	EvStore EventKind = iota
	EvHelper
	EvHook
)

type Event struct {
	Kind       EventKind
	Addr       uint64      // EvStore
	Width      int         // EvStore
	Args       [5]uint64   // EvHelper: r1..r5 at the call
	Ret        uint64      // EvHelper
	StackAfter [Stack]byte // EvHelper
}

// State is Semantics.CState.  Stack[i] is the byte at r10-512+i.  Log holds
// every value the window obtained from outside; OC counts oracle values used.
type State struct {
	PC     int
	Regs   [NRegs]uint64
	Stack  [Stack]byte
	Log    []uint64
	OC     int
	Events []Event
}

type StepKind int

const (
	StepNext  StepKind = iota
	StepHalt           // EXIT
	StepStuck          // undecodable / outside the model
)

type OutcomeKind int

const (
	Done OutcomeKind = iota // reached the instruction just after the window
	Exited
	Escaped
	OutOfFuel
)

func u64seq(xs []uint64) _dafny.Sequence {
	a := make([]interface{}, len(xs))
	for i, x := range xs {
		a[i] = x
	}
	return _dafny.SeqOf(a...)
}

func toD(s State) sem.CState {
	evs := make([]interface{}, len(s.Events))
	for i, e := range s.Events {
		switch e.Kind {
		case EvStore:
			evs[i] = sem.Companion_Event_.Create_EStore_(e.Addr, _dafny.IntOf(e.Width))
		case EvHelper:
			evs[i] = sem.Companion_Event_.Create_EHelper_(u64seq(e.Args[:]), e.Ret, _dafny.SeqOfBytes(e.StackAfter[:]))
		default:
			evs[i] = sem.Companion_Event_.Create_EHook_()
		}
	}
	return sem.Companion_CState_.Create_CState_(_dafny.IntOf(s.PC), u64seq(s.Regs[:]), _dafny.SeqOfBytes(s.Stack[:]),
		u64seq(s.Log), _dafny.IntOf(s.OC), _dafny.SeqOf(evs...))
}

func fromD(c sem.CState) State {
	var s State
	s.PC = int(c.Dtor_pc().Int64())
	s.OC = int(c.Dtor_oc().Int64())
	regs, st, log, evs := c.Dtor_regs(), c.Dtor_stack(), c.Dtor_log(), c.Dtor_events()
	for i := uint32(0); i < regs.Cardinality() && i < NRegs; i++ {
		s.Regs[i] = regs.Select(i).(uint64)
	}
	for i := uint32(0); i < st.Cardinality() && i < Stack; i++ {
		s.Stack[i] = st.Select(i).(uint8)
	}
	for i := uint32(0); i < log.Cardinality(); i++ {
		s.Log = append(s.Log, log.Select(i).(uint64))
	}
	for i := uint32(0); i < evs.Cardinality(); i++ {
		e := evs.Select(i).(sem.Event)
		switch {
		case e.Is_EStore():
			s.Events = append(s.Events, Event{Kind: EvStore, Addr: e.Dtor_addr(), Width: int(e.Dtor_width().Int64())})
		case e.Is_EHelper():
			ev := Event{Kind: EvHelper, Ret: e.Dtor_ret()}
			a, sa := e.Dtor_args(), e.Dtor_stackAfter()
			for j := uint32(0); j < a.Cardinality() && j < 5; j++ {
				ev.Args[j] = a.Select(j).(uint64)
			}
			for j := uint32(0); j < sa.Cardinality() && j < Stack; j++ {
				ev.StackAfter[j] = sa.Select(j).(uint8)
			}
			s.Events = append(s.Events, ev)
		default:
			s.Events = append(s.Events, Event{Kind: EvHook})
		}
	}
	return s
}

// InitState is the state at window entry (pc 0, nothing logged).
func InitState(regs [NRegs]uint64, stack [Stack]byte) State {
	return State{Regs: regs, Stack: stack}
}

// ConcreteStep executes the instruction at s.PC.  oracle supplies the
// environment's choices (other-memory loads, helper/hook results), indexed by s.OC.
func ConcreteStep(insns []byte, floor int, s State, oracle []uint64) (State, StepKind) {
	r := api.Companion_Default___.ConcreteStep(_dafny.SeqOfBytes(insns), _dafny.IntOf(floor), toD(s), u64seq(oracle))
	switch {
	case r.Is_Next():
		return fromD(r.Dtor_s()), StepNext
	case r.Is_Halt():
		return fromD(r.Dtor_s()), StepHalt
	default:
		return s, StepStuck
	}
}

func outcome(o sem.Outcome) (State, OutcomeKind) {
	k := OutOfFuel
	switch {
	case o.Is_Done():
		k = Done
	case o.Is_Exited():
		k = Exited
	case o.Is_Escaped():
		k = Escaped
	}
	return fromD(o.Dtor_s()), k
}

// ConcreteRun runs the window from s for at most fuel steps.
func ConcreteRun(insns []byte, floor int, s State, oracle []uint64, fuel int) (State, OutcomeKind) {
	return outcome(api.Companion_Default___.ConcreteRun(_dafny.SeqOfBytes(insns), _dafny.IntOf(floor), toD(s), u64seq(oracle), _dafny.IntOf(fuel)))
}

// RunAndCheck runs the window from InitState(regs, stack) with fuel
// len(insns)/8+1 and evaluates the obligation predicate on the outcome.
// For a validated window the theorem says ok is always true.
func RunAndCheck(insns []byte, sp Spec, regs [NRegs]uint64, stack [Stack]byte, oracle []uint64) (final State, kind OutcomeKind, ok bool) {
	raw := _dafny.SeqOfBytes(insns)
	s0 := toD(InitState(regs, stack))
	floor := sp.d.Dtor_floor()
	if floor.Cmp(_dafny.IntOf(-Stack)) < 0 || floor.Sign() > 0 {
		return State{}, Escaped, false
	}
	out := api.Companion_Default___.ConcreteRun(raw, floor, s0, u64seq(oracle), _dafny.IntOf(len(insns)/8+1))
	ok = obl.Companion_Default___.ObligationsHold(raw, sp.d, s0, out)
	final, kind = outcome(out)
	return
}
