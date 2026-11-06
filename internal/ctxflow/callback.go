package ctxflow

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Callback says how a synchronous callback reaches the program context: Param,
// the register the callback receives callback_ctx in, equals the entry frame's
// R10+Arg at every call that passes it.
type Callback struct {
	Helper asm.BuiltinFunc
	Param  asm.Register
	Arg    int16
}

// writesImplicitly reports an instruction whose register writes its store or
// load form does not show: an atomic (a fetch writes Src, cmpxchg R0, and a
// load-acquire, encoded as a store, writes Dst) or a legacy packet load, which
// clobbers R0-R5 like a call. Atomics that write no register count too.
func writesImplicitly(ins asm.Instruction) bool {
	cls := ins.OpCode.Class()
	return cls == asm.StXClass && ins.OpCode.Mode() != asm.MemMode || cls == asm.LdClass && ins.OpCode.Mode() != asm.ImmMode
}

// CallbackCall follows the function-pointer load at index i to the helper that
// takes it. The pointer must stay in R2 up to the first call, with no branch
// in between, so that helper is its only use. The helper's R3 must be formed
// as R10 plus a constant by straight-line code: `r3 = r10` and then constant
// adds, with nothing else writing R3 before the call. It returns the callback,
// the indices of `r3 = r10` and of the call, or why not. It reads no BTF: the
// offline checker runs it too. It does not see a branch landing between
// `r3 = r10` and the call; proveCallback and the checker both refuse one.
func CallbackCall(insns asm.Instructions, i int) (Callback, int, int, string) {
	if insns[i].Dst != asm.R2 {
		return Callback{}, 0, 0, "the function pointer is not loaded into the helper's callback argument"
	}
	call := i + 1
	for ; ; call++ {
		if call >= len(insns) {
			return Callback{}, 0, 0, "the function pointer reaches no call"
		}
		ins, op := &insns[call], insns[call].OpCode
		if op.Class().IsJump() && op.JumpOp() == asm.Call {
			break
		}
		if op.Class().IsJump() {
			return Callback{}, 0, 0, "a branch separates the function pointer from its call"
		}
		// An ld_imm64's Src is a pseudo source, not a register.
		if ins.Dst == asm.R2 || ins.Src == asm.R2 && op.Class() != asm.LdClass || writesImplicitly(*ins) {
			return Callback{}, 0, 0, "the function pointer is copied, stored or overwritten before its call"
		}
	}
	out := Callback{Helper: asm.BuiltinFunc(insns[call].Constant)}
	switch {
	case !insns[call].IsBuiltinCall():
		return Callback{}, 0, 0, "the function pointer goes to a call that is not a helper"
	case out.Helper == asm.FnLoop:
		out.Param = asm.R2
	case out.Helper == asm.FnForEachMapElem:
		out.Param = asm.R4
	case out.Helper == asm.FnTimerSetCallback:
		return Callback{}, 0, 0, "asynchronous callback (bpf_timer_set_callback): the caller's frame is gone when it runs"
	default:
		return Callback{}, 0, 0, fmt.Sprintf("the callback goes to %s, not bpf_loop or bpf_for_each_map_elem", out.Helper)
	}
	offset := int64(0)
	for j := call - 1; ; j-- {
		if j < 0 {
			return Callback{}, 0, 0, "the callback context is not R10 plus a constant"
		}
		ins, op := &insns[j], insns[j].OpCode
		cls := op.Class()
		switch {
		case cls.IsJump():
			return Callback{}, 0, 0, "the callback context is not R10 plus a constant in the helper's block"
		case writesImplicitly(*ins):
			return Callback{}, 0, 0, "an atomic or legacy packet load may overwrite the callback context before the helper"
		case cls.IsStore() || ins.Dst != asm.R3:
			continue
		case op == asm.Add.Imm(asm.R3, 0).OpCode:
			offset += ins.Constant
			continue
		case op == asm.Mov.Reg(asm.R3, asm.RFP).OpCode && ins.Src == asm.RFP && ins.Offset == 0:
			if offset > -8 || offset < -512 {
				return Callback{}, 0, 0, fmt.Sprintf("the callback context R10%+d is outside the frame", offset)
			}
			out.Arg = int16(offset)
			return out, j, call, ""
		case op == asm.Mov.Imm(asm.R3, 0).OpCode && ins.Constant == 0 && offset == 0:
			return Callback{}, 0, 0, "the callback context is NULL"
		}
		return Callback{}, 0, 0, "the callback context is not R10 plus a constant"
	}
}

// proveCallback discharges the callback context premise for fn. entry is the
// proof of the entry function, whose reserved context slot the callback reads:
// the entry spill dominates every call in it, and no original access reaches
// below the floor, so nothing else writes the slot. An original slot would not
// do, since the callback can write it through its own pointer. The floor
// must cover the callback's writes through that pointer.
func (p *flowProgram) proveCallback(fn function, entry Proof) (*Callback, string) {
	if fn.Linkage != btf.StaticFunc {
		return nil, "callback: not a static function"
	}
	if len(p.callers[fn.Start]) != 0 {
		return nil, "callback: the function is also called directly"
	}
	if !entry.Proven {
		return nil, "callback: the program entry is not analyzed (" + entry.Reason + ")"
	}
	var out *Callback
	for _, ref := range p.refs[fn.Start] {
		if ref.caller != 0 {
			return nil, fmt.Sprintf("callback: a caller does not hold the context in a reserved slot (%s@%d)", p.funcs[ref.caller].Name, ref.pc)
		}
		use, from, call, why := CallbackCall(p.insns, p.at[ref.pc])
		if why != "" {
			return nil, "callback: " + why
		}
		fromPC, callPC := p.pc(from), p.pc(call)
		// The checker sees R3 only in straight-line code, so a merge there is
		// refused even when every path sets the same R3.
		if at, ok := p.landingIn(fromPC, callPC); ok {
			return nil, fmt.Sprintf("callback: a branch lands at instruction %d, between the callback context and the helper call", at)
		}
		state, ok := entry.States[callPC]
		if !ok {
			return nil, fmt.Sprintf("callback: no state for the helper call at instruction %d", callPC)
		}
		if k := state.state.reg(asm.R3); k.t != ctxFrame || k.off != use.Arg {
			return nil, fmt.Sprintf("callback: the callback context varies across paths to the helper call at instruction %d", callPC)
		}
		if out != nil && *out != use {
			return nil, "callback: calls pass different callback contexts or use different helpers"
		}
		out = &use
	}
	return out, ""
}

// landingIn returns a branch target in the raw pc range (from, to], or false.
// An unresolved symbolic branch counts as landing anywhere.
func (p *flowProgram) landingIn(from, to int) (int, bool) {
	pc := 0
	for i := range p.insns {
		ins := &p.insns[i]
		if op := ins.OpCode; op.Class().IsJump() && op.JumpOp() != asm.Call && op.JumpOp() != asm.Exit {
			target, _ := p.target(pc, ins)
			if _, known := p.symbols[ins.Reference()]; ins.Reference() != "" && !known || target > from && target <= to {
				return target, true
			}
		}
		pc += int(ins.Size() / asm.InstructionSize)
	}
	return 0, false
}

func (p *flowProgram) pc(index int) int {
	pc := 0
	for i := range p.insns[:index] {
		pc += int(p.insns[i].Size() / asm.InstructionSize)
	}
	return pc
}
