package program

import (
	"fmt"
	"math"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// checkStaticCtxArg refuses a static function unless every call passes the
// program's context in R1. Once the kernel has discarded the prototype nothing
// checks args[0], and reading another pointer as the context would capture
// unrelated kernel memory as packets.
func checkStaticCtxArg(target *ebpf.Program, name string) error {
	info, err := target.Info()
	var insns asm.Instructions
	if err == nil {
		insns, err = info.Instructions()
	}
	if err != nil {
		return fmt.Errorf("static function %q: reading the target's translated instructions to check its context argument: %w; "+
			"lower kernel.kptr_restrict or net.core.bpf_jit_harden, or capture at its caller or at a global function", name, err)
	}
	if !ctxReachesCalls(insns, name) {
		return fmt.Errorf("static function %q: cannot show that every call passes the program context as its first argument, "+
			"which a context read with bpf_probe_read_kernel relies on; only calls from the entry function, "+
			"with the context in a register or an 8-byte stack spill, are accepted; capture at its caller or at a global function", name)
	}
	return nil
}

// What a register or 8-byte stack slot may hold: a value the verifier never
// lets point into this frame, the entry context, a pointer into this frame
// (at off), or possibly such a pointer at an unknown offset.
const (
	ctxOther uint8 = iota
	ctxValue
	ctxFrame
	ctxAny
)

type ctxKind struct {
	t   uint8
	off int16
}

type ctxState struct {
	regs  [10]ctxKind
	slots [64]ctxKind // fp-8 .. fp-512
	floor int16       // lowest offset passed to a helper, which may return an alias of it (a dynptr slice buffer)
}

func joinCtx(a, b ctxKind) ctxKind {
	switch {
	case a == b:
		return a
	case a.t <= ctxValue && b.t <= ctxValue:
		return ctxKind{}
	}
	return ctxKind{t: ctxAny}
}

func (s ctxState) join(o ctxState) ctxState {
	for i := range s.regs {
		s.regs[i] = joinCtx(s.regs[i], o.regs[i])
	}
	for i := range s.slots {
		s.slots[i] = joinCtx(s.slots[i], o.slots[i])
	}
	s.floor = min(s.floor, o.floor)
	return s
}

func (s *ctxState) reg(r asm.Register) ctxKind {
	switch {
	case r == asm.RFP:
		return ctxKind{t: ctxFrame}
	case r < asm.RFP:
		return s.regs[r]
	}
	return ctxKind{t: ctxAny} // verifier scratch registers in translated code
}

func (s *ctxState) set(r asm.Register, k ctxKind) {
	if r < asm.RFP {
		s.regs[r] = k
	}
}

// fill sets every slot overlapping frame bytes [lo, hi).
func (s *ctxState) fill(lo, hi int, k ctxKind) {
	for i := range s.slots {
		if off := -8 * (i + 1); off < hi && lo < off+8 {
			s.slots[i] = k
		}
	}
}

func ctxSlot(off int) (int, bool) { return -off/8 - 1, off <= -8 && off >= -512 && off%8 == 0 }

func (s *ctxState) store(base ctxKind, off, size int, k ctxKind) {
	switch base.t {
	case ctxFrame:
		at := int(base.off) + off
		if i, ok := ctxSlot(at); ok && size == 8 {
			s.slots[i] = k
			return
		}
		if k.t != ctxAny {
			k = ctxKind{} // a partial write leaves a scalar
		}
		s.fill(at, at+size, k)
	case ctxAny:
		s.fill(-512, 0, ctxKind{t: ctxAny})
	default:
		s.fill(int(s.floor), 0, ctxKind{})
	}
}

func (s *ctxState) step(ins asm.Instruction) {
	op, other := ins.OpCode, ctxKind{}
	switch cls := op.Class(); {
	case cls == asm.ALU64Class && op.ALUOp() == asm.Mov && ins.Offset == 0:
		if op.Source() == asm.RegSource {
			other = s.reg(ins.Src)
		}
		s.set(ins.Dst, other)
	case cls == asm.ALU64Class && (op.ALUOp() == asm.Add || op.ALUOp() == asm.Sub):
		d := s.reg(ins.Dst)
		switch {
		case op.Source() == asm.ImmSource && d.t == ctxFrame:
			off := int64(d.off) + ins.Constant
			if op.ALUOp() == asm.Sub {
				off = int64(d.off) - ins.Constant
			}
			other = ctxKind{t: ctxAny}
			if off >= -512 && off <= 0 {
				other = ctxKind{t: ctxFrame, off: int16(off)}
			}
		case d.t >= ctxFrame || op.Source() == asm.RegSource && s.reg(ins.Src).t >= ctxFrame:
			other = ctxKind{t: ctxAny}
		}
		s.set(ins.Dst, other)
	case cls.IsALU():
		s.set(ins.Dst, other)
	case cls == asm.LdXClass:
		base := s.reg(ins.Src)
		if base.t == ctxAny {
			other = base
		} else if i, ok := ctxSlot(int(base.off) + int(ins.Offset)); ok && base.t == ctxFrame && op.Mode() == asm.MemMode && op.Size() == asm.DWord {
			other = s.slots[i]
		}
		s.set(ins.Dst, other)
	case cls == asm.LdClass && op.Mode() == asm.ImmMode:
		s.set(ins.Dst, other)
	case cls == asm.LdClass: // LD_ABS/IND clobber R0-R5 like a call
		for r := asm.R0; r <= asm.R5; r++ {
			s.set(r, other)
		}
	case cls == asm.StClass && op.Mode() == asm.AtomicMode: // BPF_NOSPEC
	case cls == asm.StClass || cls == asm.StXClass:
		atomic := cls == asm.StXClass && op.Mode() != asm.MemMode // PROBE_ATOMIC too, in translated code
		k := other
		if atomic {
			k = ctxKind{t: ctxAny}
		} else if cls == asm.StXClass && op.Size() == asm.DWord {
			k = s.reg(ins.Src)
		}
		s.store(s.reg(ins.Dst), int(ins.Offset), int(op.Size().Sizeof()), k)
		if atomic {
			// cmpxchg writes R0, a fetch Src and load-acquire Dst; the old value
			// can point into the frame only if the memory is the frame.
			loaded := ctxKind{}
			if s.reg(ins.Dst).t >= ctxFrame || s.reg(ins.Src).t >= ctxFrame {
				loaded = ctxKind{t: ctxAny}
			}
			for _, r := range []asm.Register{asm.R0, ins.Src, ins.Dst} {
				s.set(r, joinCtx(s.reg(r), loaded))
			}
		}
	}
}

// call applies a call's effect. A helper writes only forward of a frame
// pointer it gets; a BPF function may write anywhere in the frame through
// one unless it stores only to its own stack and calls nothing, and so may a
// callback a helper runs. shortcut: an extension that later replaces a
// write-free callee is not modelled, since that needs the privileges to
// replace the program itself; bound the write with the callee's BTF if not.
func (s *ctxState) call(helper, writeFree, callbacks bool) {
	exposed := false
	for r := asm.R1; r <= asm.R5; r++ {
		k := s.regs[r]
		if k.t < ctxFrame {
			continue
		}
		exposed = true
		if helper {
			lo := int16(-512)
			if k.t == ctxFrame {
				lo = k.off
			}
			s.floor = min(s.floor, lo)
		}
	}
	s.fill(int(s.floor), 0, ctxKind{})
	if exposed && (helper && callbacks || !helper && !writeFree) {
		s.fill(-512, 0, ctxKind{t: ctxAny})
	}
	for r := asm.R0; r <= asm.R5; r++ {
		s.regs[r] = ctxKind{}
	}
	if exposed && !helper && !writeFree {
		s.regs[asm.R0] = ctxKind{t: ctxAny} // may alias a caller buffer (a dynptr slice)
	}
}

// ctxReachesCalls reports whether R1 holds the entry context at every call to
// the function name in the translated (or raw) instructions. It follows
// registers and 8-byte stack slots through the entry function and refuses
// what it cannot follow.
func ctxReachesCalls(insns asm.Instructions, name string) bool {
	at, sym := map[int]int{}, map[string]int{}
	var starts []int
	target := -1
	for it := insns.Iterate(); it.Next(); {
		pc := int(it.Offset)
		at[pc] = it.Index
		if s := it.Ins.Symbol(); s != "" {
			sym[s] = pc
		}
		if fn := btf.FuncMetadata(it.Ins); fn != nil {
			starts = append(starts, pc)
			if fn.Name == name {
				if target >= 0 {
					return false
				}
				target = pc
			}
		}
	}
	if target <= 0 || insns.Size()/asm.InstructionSize > math.MaxInt16 {
		return false // the dump keeps call offsets in 16 bits
	}
	end := func(pc int) int {
		for _, s := range starts {
			if s > pc {
				return s
			}
		}
		return int(insns.Size() / asm.InstructionSize)
	}
	jump := func(pc int, ins *asm.Instruction) int {
		if ref := ins.Reference(); ref != "" {
			if t, ok := sym[ref]; ok {
				return t
			}
			return -1
		}
		rel := int(ins.Offset)
		if ins.IsLoadOfFunctionPointer() || ins.OpCode.Class() == asm.Jump32Class && ins.OpCode.JumpOp() == asm.Ja {
			rel = int(int32(ins.Constant))
		}
		return pc + 1 + rel
	}
	isCall := func(ins *asm.Instruction) bool { return ins.OpCode.Class().IsJump() && ins.OpCode.JumpOp() == asm.Call }
	entryEnd, callbacks, targets := end(0), false, map[int]bool{}
	for it := insns.Iterate(); it.Next(); {
		pc, ins := int(it.Offset), it.Ins
		fnPtr := ins.IsLoadOfFunctionPointer()
		if (fnPtr || ins.IsFunctionCall()) && jump(pc, ins) == target && (fnPtr || pc >= entryEnd) {
			// shortcut: calls from other functions are refused; prove their callers in turn if needed.
			return false
		}
		if pc < entryEnd {
			callbacks = callbacks || fnPtr
			if ins.OpCode.Class().IsJump() && !isCall(ins) && ins.OpCode.JumpOp() != asm.Exit {
				targets[jump(pc, ins)] = true
			}
		}
	}
	writeFree := func(start int) bool {
		for pc, stop := start, end(start); pc < stop; {
			i, ok := at[pc]
			if !ok {
				return false
			}
			ins, cls := &insns[i], insns[i].OpCode.Class()
			if isCall(ins) || (cls == asm.StXClass || cls == asm.StClass && ins.OpCode.Mode() != asm.AtomicMode) && ins.Dst != asm.RFP {
				return false
			}
			pc += int(ins.Size() / asm.InstructionSize)
		}
		return true
	}
	var start ctxState
	start.regs[asm.R1] = ctxKind{t: ctxValue}
	in, work := map[int]ctxState{0: start}, []int{0}
	merge := func(pc int, s ctxState) {
		if old, seen := in[pc]; seen {
			if s = old.join(s); s == old {
				return
			}
		}
		in[pc] = s
		work = append(work, pc)
	}
	for len(work) > 0 {
		pc := work[len(work)-1]
		work = work[:len(work)-1]
		s := in[pc]
		for {
			i, ok := at[pc]
			if !ok || pc >= entryEnd {
				return false
			}
			ins := &insns[i]
			op, next := ins.OpCode, pc+int(ins.Size()/asm.InstructionSize)
			succ := []int{next}
			switch {
			case isCall(ins):
				callee := -1
				if ins.IsFunctionCall() {
					if callee = jump(pc, ins); !slices.Contains(starts, callee) {
						return false
					}
				}
				if callee == target && s.regs[asm.R1].t != ctxValue {
					return false
				}
				s.call(callee < 0, callee >= 0 && writeFree(callee), callbacks)
			case op.Class().IsJump() && op.JumpOp() == asm.Ja && op.Source() == asm.RegSource:
				return false // gotox: jump-table targets are not followed
			case op.Class().IsJump() && op.JumpOp() == asm.Exit:
				succ = nil
			case op.Class().IsJump():
				succ = []int{jump(pc, ins)}
				if op.JumpOp() != asm.Ja {
					succ = append(succ, next)
				}
			default:
				s.step(*ins)
			}
			if len(succ) == 1 && succ[0] == next && !targets[next] {
				pc = next
				continue
			}
			for _, n := range succ {
				merge(n, s)
			}
			break
		}
	}
	return true
}
