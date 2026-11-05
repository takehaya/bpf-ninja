package ctxflow

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Function is one BTF-described function in an instruction stream. CtxParam
// is the zero-based context parameter, or -1 when the prototype has none.
type Function struct {
	Name     string
	Start    int
	End      int
	Linkage  btf.FuncLinkage
	CtxParam int
}

// State is the context provenance immediately before an instruction.
type State struct{ state ctxState }

// Proof describes whether every direct call path from the entry passes the
// program context to a function, and the states proved inside that function.
type Proof struct {
	Proven bool
	Reason string
	States map[int]State
}

// Functions returns the BTF function ranges and identifies parameters whose
// pointee is ctxStruct. Malformed or duplicate metadata is left for Prove to
// refuse; this function only describes ranges it can see.
func Functions(insns asm.Instructions, ctxStruct btf.Type) []Function {
	ctxStruct = pointee(ctxStruct)
	var out []Function
	for it := insns.Iterate(); it.Next(); {
		fn := btf.FuncMetadata(it.Ins)
		if fn == nil {
			continue
		}
		f := Function{Name: fn.Name, Start: int(it.Offset), Linkage: fn.Linkage, CtxParam: -1}
		if proto, ok := fn.Type.(*btf.FuncProto); ok {
			for i, param := range proto.Params {
				if sameType(pointee(param.Type), ctxStruct) {
					f.CtxParam = i
					break
				}
			}
		}
		out = append(out, f)
	}
	for i := range out {
		out[i].End = int(insns.Size() / asm.InstructionSize)
		if i+1 < len(out) {
			out[i].End = out[i+1].Start
		}
	}
	return out
}

func pointee(typ btf.Type) btf.Type {
	if typ == nil {
		return nil
	}
	typ = btf.UnderlyingType(typ)
	if ptr, ok := typ.(*btf.Pointer); ok {
		return btf.UnderlyingType(ptr.Target)
	}
	return typ
}

func sameType(a, b btf.Type) bool {
	if a == nil || b == nil {
		return false
	}
	return a == b
}

type flowProgram struct {
	insns          asm.Instructions
	funcs          []Function
	at             map[int]int
	symbols        map[string]int
	starts         map[int]int
	callback       map[int]bool
	callers        map[int][]callSite
	writeFree      map[int]bool
	fnPtrElsewhere bool
}

type callSite struct {
	caller int
	pc     int
}

// Prove establishes context provenance for each BTF function. It fails closed
// on callbacks, stack arguments, indirect jumps, malformed calls and control
// flow outside the containing function.
func Prove(insns asm.Instructions, ctxStruct btf.Type) map[int]Proof {
	p := newFlowProgram(insns, ctxStruct)
	out := make(map[int]Proof, len(p.funcs))
	if len(p.funcs) == 0 || p.funcs[0].Start != 0 {
		return out
	}

	for _, fn := range p.funcs {
		proof := Proof{States: map[int]State{}}
		switch {
		case fn.CtxParam < 0 || fn.CtxParam >= 5:
			proof.Reason = "function has no context parameter"
		case fn.Start == p.funcs[0].Start && fn.CtxParam != 0:
			proof.Reason = "entry function has no context first parameter"
		case p.callback[fn.Start]:
			proof.Reason = "function is used as a callback"
		}
		out[fn.Start] = proof
	}

	remaining := len(p.funcs)
	for progress := true; progress && remaining > 0; {
		progress = false
		for i, fn := range p.funcs {
			proof := out[fn.Start]
			if proof.Proven || proof.Reason != "" {
				continue
			}
			if i == 0 {
				states, reason := p.analyze(fn)
				proof.States, proof.Reason = states, reason
				proof.Proven = reason == ""
				out[fn.Start] = proof
				progress, remaining = true, remaining-1
				continue
			}
			callers := p.callers[fn.Start]
			if len(callers) == 0 {
				proof.Reason = "function has no direct caller"
				out[fn.Start], progress, remaining = proof, true, remaining-1
				continue
			}
			ready, bad := true, ""
			for _, call := range callers {
				callerProof := out[p.funcs[call.caller].Start]
				if !callerProof.Proven {
					if callerProof.Reason == "" {
						ready = false
						break
					}
					bad = fmt.Sprintf("a caller does not pass the context (%s@%d)", p.funcs[call.caller].Name, call.pc)
					break
				}
				state, ok := callerProof.States[call.pc]
				reg := asm.R1 + asm.Register(fn.CtxParam)
				if !ok || state.state.reg(reg).t != ctxValue {
					bad = fmt.Sprintf("a caller does not pass the context (%s@%d)", p.funcs[call.caller].Name, call.pc)
					break
				}
			}
			if !ready {
				continue
			}
			if bad != "" {
				proof.Reason = bad
			} else {
				proof.States, proof.Reason = p.analyze(fn)
				proof.Proven = proof.Reason == ""
			}
			out[fn.Start], progress, remaining = proof, true, remaining-1
		}
	}
	for _, fn := range p.funcs {
		proof := out[fn.Start]
		if !proof.Proven && proof.Reason == "" {
			callers := p.callers[fn.Start]
			if len(callers) != 0 {
				call := callers[0]
				proof.Reason = fmt.Sprintf("a caller does not pass the context (%s@%d)", p.funcs[call.caller].Name, call.pc)
			} else {
				proof.Reason = "function has no direct caller"
			}
			out[fn.Start] = proof
		}
	}
	return out
}

// CallsRefusal reports why calls to name are not proved to pass the program
// context in R1. The target's first BTF parameter supplies the context type.
func CallsRefusal(insns asm.Instructions, name string) string {
	target, ctxStruct, found := -1, btf.Type(nil), false
	for it := insns.Iterate(); it.Next(); {
		fn := btf.FuncMetadata(it.Ins)
		if fn == nil || fn.Name != name {
			continue
		}
		if found {
			return "the target function name is ambiguous"
		}
		found, target = true, int(it.Offset)
		proto, ok := fn.Type.(*btf.FuncProto)
		if !ok || len(proto.Params) == 0 {
			return "the target has no BTF context pointer in its first parameter"
		}
		param := btf.UnderlyingType(proto.Params[0].Type)
		ptr, ok := param.(*btf.Pointer)
		if !ok || ptr.Target == nil {
			return "the target has no BTF context pointer in its first parameter"
		}
		ctxStruct = btf.UnderlyingType(ptr.Target)
	}
	if !found {
		return "the target function is absent from BTF function metadata"
	}
	proof, ok := Prove(insns, ctxStruct)[target]
	if !ok {
		return "the target function is outside the proved function graph"
	}
	if !proof.Proven {
		return proof.Reason
	}
	return ""
}

func newFlowProgram(insns asm.Instructions, ctxStruct btf.Type) *flowProgram {
	p := &flowProgram{insns: insns, funcs: Functions(insns, ctxStruct), at: map[int]int{}, symbols: map[string]int{},
		starts: map[int]int{}, callback: map[int]bool{}, callers: map[int][]callSite{}, writeFree: map[int]bool{}}
	for i, fn := range p.funcs {
		p.starts[fn.Start] = i
	}
	for it := insns.Iterate(); it.Next(); {
		pc := int(it.Offset)
		p.at[pc] = it.Index
		if symbol := it.Ins.Symbol(); symbol != "" {
			p.symbols[symbol] = pc
		}
	}
	for i, fn := range p.funcs {
		p.writeFree[fn.Start] = p.functionWriteFree(fn)
		for pc := fn.Start; pc < fn.End; {
			idx, ok := p.at[pc]
			if !ok {
				break
			}
			ins := &insns[idx]
			if ins.IsLoadOfFunctionPointer() {
				if target, ok := p.target(pc, ins); ok {
					p.callback[target] = true
				}
				p.fnPtrElsewhere = p.fnPtrElsewhere || i > 0
			}
			if ins.IsFunctionCall() {
				if target, ok := p.target(pc, ins); ok {
					p.callers[target] = append(p.callers[target], callSite{i, pc})
				}
			}
			pc += int(ins.Size() / asm.InstructionSize)
		}
	}
	return p
}

func (p *flowProgram) target(pc int, ins *asm.Instruction) (int, bool) {
	if ref := ins.Reference(); ref != "" {
		target, ok := p.symbols[ref]
		return target, ok
	}
	rel := int(ins.Offset)
	if ins.IsLoadOfFunctionPointer() || ins.OpCode.Class() == asm.Jump32Class && ins.OpCode.JumpOp() == asm.Ja {
		rel = int(int32(ins.Constant))
	}
	target := pc + 1 + rel
	_, ok := p.starts[target]
	return target, ok
}

func (p *flowProgram) functionWriteFree(fn Function) bool {
	for pc := fn.Start; pc < fn.End; {
		idx, ok := p.at[pc]
		if !ok {
			return false
		}
		ins, cls := &p.insns[idx], p.insns[idx].OpCode.Class()
		if ins.OpCode.JumpOp() == asm.Call || (cls == asm.StXClass || cls == asm.StClass && ins.OpCode.Mode() != asm.AtomicMode) && ins.Dst != asm.RFP {
			return false
		}
		pc += int(ins.Size() / asm.InstructionSize)
	}
	return true
}

func (p *flowProgram) analyze(fn Function) (map[int]State, string) {
	var initial ctxState
	initial.regs[asm.R1+asm.Register(fn.CtxParam)] = ctxKind{t: ctxValue}
	in, work := map[int]ctxState{fn.Start: initial}, []int{fn.Start}
	merge := func(pc int, state ctxState) {
		if old, seen := in[pc]; seen {
			if state = old.join(state); state == old {
				return
			}
		}
		in[pc] = state
		work = append(work, pc)
	}
	for len(work) != 0 {
		pc := work[len(work)-1]
		work = work[:len(work)-1]
		state := in[pc]
		for {
			idx, ok := p.at[pc]
			if !ok || pc < fn.Start || pc >= fn.End {
				return nil, "control leaves the function or lands inside an instruction"
			}
			ins := &p.insns[idx]
			if ins.OpCode.Class().IsStore() && ins.Dst == regParams {
				return nil, "function passes a stack argument through r11"
			}
			in[pc] = state
			next := pc + int(ins.Size()/asm.InstructionSize)
			succ := []int{next}
			op := ins.OpCode
			switch {
			case op.Class().IsJump() && op.JumpOp() == asm.Call:
				keep := state.regs
				callee, direct := -1, false
				if ins.IsFunctionCall() {
					callee, direct = p.target(pc, ins)
					if !direct {
						return nil, fmt.Sprintf("the call at instruction %d does not reach a function start", pc)
					}
				}
				state.call(!direct, direct && p.writeFree[callee], p.fnPtrElsewhere)
				if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnGetSmpProcessorId) {
					for reg := asm.R1; reg <= asm.R5; reg++ {
						state.regs[reg] = joinCtx(keep[reg], ctxKind{})
					}
				}
			case op.Class().IsJump() && op.JumpOp() == asm.Ja && op.Source() == asm.RegSource:
				return nil, fmt.Sprintf("the indirect jump at instruction %d is not followed", pc)
			case op.Class().IsJump() && op.JumpOp() == asm.Exit:
				succ = nil
			case op.Class().IsJump():
				var target int
				if ref := ins.Reference(); ref != "" {
					var ok bool
					target, ok = p.symbols[ref]
					if !ok {
						return nil, fmt.Sprintf("the jump at instruction %d has no target", pc)
					}
				} else {
					target = pc + 1 + int(ins.Offset)
					if op.Class() == asm.Jump32Class && op.JumpOp() == asm.Ja {
						target = pc + 1 + int(int32(ins.Constant))
					}
				}
				succ = []int{target}
				if op.JumpOp() != asm.Ja {
					succ = append(succ, next)
				}
			default:
				state.step(*ins)
			}
			if len(succ) == 1 && succ[0] == next {
				pc = next
				continue
			}
			for _, target := range succ {
				if target < fn.Start || target >= fn.End {
					return nil, "control leaves the function or lands inside an instruction"
				}
				merge(target, state)
			}
			break
		}
	}
	states := make(map[int]State, len(in))
	for pc, state := range in {
		states[pc] = State{state}
	}
	return states, ""
}

// HeldAt returns a context held in R6-R9, preferring the lowest register, or
// otherwise in the shallowest aligned 8-byte stack slot.
func HeldAt(state State) (reg asm.Register, slot int16, ok bool) {
	for reg = asm.R6; reg <= asm.R9; reg++ {
		if state.state.reg(reg).t == ctxValue {
			return reg, 0, true
		}
	}
	for i, kind := range state.state.slots {
		if kind.t == ctxValue {
			return 0, int16(-8 * (i + 1)), true
		}
	}
	return 0, 0, false
}

// FunctionAt returns the function containing pc.
func FunctionAt(functions []Function, pc int) (Function, bool) {
	for _, fn := range functions {
		if pc >= fn.Start && pc < fn.End {
			return fn, true
		}
	}
	return Function{}, false
}
