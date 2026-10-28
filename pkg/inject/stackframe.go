package inject

import "github.com/cilium/ebpf/asm"

// stackFrameDepth bounds this frame, independently of its callers' frames.
// Track constant R10 aliases only inside basic blocks. Count pointer formation
// too: the allowed helpers access memory forward from their pointer arguments,
// so its offset bounds their deepest access regardless of the buffer size.
// An escaping or unsupported alias restores the caller-certified bound for the
// whole frame. In particular, a callee may subtract from a passed stack pointer,
// and a spilled pointer may later be reloaded: neither is followed here.
func stackFrameDepth(insns asm.Instructions, lowest int16) int {
	depth := 0
	bySymbol := map[string]int{}
	targets := map[int]bool{}
	it := insns.Iterate()
	for it.Next() {
		ins := it.Ins
		bySymbol[ins.Symbol()] = int(it.Offset)
		class := ins.OpCode.Class()
		if (class == asm.LdXClass && ins.Src == asm.RFP) ||
			((class == asm.StClass || class == asm.StXClass) && ins.Dst == asm.RFP) {
			depth = max(depth, -int(ins.Offset))
		}
	}
	it = insns.Iterate()
	for it.Next() {
		ins, op := it.Ins, it.Ins.OpCode
		if op.Class().IsJump() && op.JumpOp() != asm.Call && op.JumpOp() != asm.Exit {
			target := int(it.Offset) + 1 + int(ins.Offset)
			if op.Class() == asm.Jump32Class && op.JumpOp() == asm.Ja {
				target = int(it.Offset) + 1 + int(ins.Constant)
			}
			if ref := ins.Reference(); ref != "" {
				var ok bool
				target, ok = bySymbol[ref]
				if !ok {
					return max(depth, -int(lowest))
				}
			}
			targets[target] = true
		}
	}

	type alias struct {
		stack bool
		off   int64
	}
	var regs [asm.R10 + 1]alias
	regs[asm.RFP].stack = true
	live := func() bool {
		for _, p := range regs[:asm.RFP] {
			if p.stack {
				return true
			}
		}
		return false
	}
	precise := true
	count := func(off int64) {
		if off < -512 || off > 0 {
			precise = false
			return
		}
		depth = max(depth, -int(off))
	}
	it = insns.Iterate()
	for precise && it.Next() {
		ins, op := it.Ins, it.Ins.OpCode
		class := op.Class()
		if targets[int(it.Offset)] && live() {
			precise = false
			break
		}
		switch {
		case class == asm.ALU64Class && op.ALUOp() == asm.Mov && op.Source() == asm.RegSource && ins.Offset == 0:
			regs[ins.Dst] = regs[ins.Src]
		case class == asm.ALU64Class && (op.ALUOp() == asm.Add || op.ALUOp() == asm.Sub) && op.Source() == asm.ImmSource:
			if p := &regs[ins.Dst]; p.stack {
				if op.ALUOp() == asm.Add {
					p.off += ins.Constant
				} else {
					p.off -= ins.Constant
				}
				count(p.off)
			}
		case class.IsALU():
			// Only a plain immediate MOV can discard an alias safely here.
			if op.ALUOp() != asm.Mov || op.Source() != asm.ImmSource {
				precise = !regs[ins.Dst].stack && (op.Source() != asm.RegSource || !regs[ins.Src].stack)
			}
			regs[ins.Dst] = alias{}
		case op == asm.LoadImmOp(asm.DWord):
			regs[ins.Dst] = alias{}
		case class == asm.LdXClass && op.Mode() == asm.MemMode:
			if p := regs[ins.Src]; p.stack {
				count(p.off + int64(ins.Offset))
			}
			regs[ins.Dst] = alias{}
		case (class == asm.StClass || class == asm.StXClass) && op.Mode() == asm.MemMode:
			if p := regs[ins.Dst]; p.stack {
				count(p.off + int64(ins.Offset))
			}
			if class == asm.StXClass && regs[ins.Src].stack {
				precise = false // pointer escape, including a stack spill
			}
		case class.IsJump() && op.JumpOp() == asm.Call:
			for r := asm.R1; r <= asm.R5; r++ {
				if p := regs[r]; p.stack {
					if !ins.IsBuiltinCall() || !forwardStackArg(asm.BuiltinFunc(ins.Constant), r) {
						precise = false
					}
					count(p.off)
				}
			}
			for r := asm.R0; r <= asm.R5; r++ {
				regs[r] = alias{}
			}
		case class.IsJump() && op.JumpOp() == asm.Exit:
			precise = !regs[asm.R0].stack // do not return a pointer into this frame
			clear(regs[:asm.RFP])
		case class.IsJump():
			precise = !live()
		default:
			precise = !live() && ins.Src != asm.RFP && ins.Dst != asm.RFP
		}
	}
	if !precise {
		depth = max(depth, -int(lowest))
	}
	return depth
}

// These helpers neither retain stack pointers nor return them, and access
// only [arg, arg+size). Unknown helpers and all BPF/kfunc calls use the audit.
func forwardStackArg(fn asm.BuiltinFunc, reg asm.Register) bool {
	switch fn {
	case asm.FnMapLookupElem, asm.FnMapDeleteElem:
		return reg == asm.R2
	case asm.FnMapUpdateElem:
		return reg == asm.R2 || reg == asm.R3
	case asm.FnXdpLoadBytes:
		return reg == asm.R3
	default:
		return false
	}
}
