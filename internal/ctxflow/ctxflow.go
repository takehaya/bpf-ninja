// Package ctxflow tracks a BPF program context through registers and stack
// slots without relying on target-specific instruction patterns.
package ctxflow

import (
	"fmt"
	"math"
	"slices"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// regParams is BPF_REG_PARAMS, through which Linux 7.2+ passes arguments past
// the fifth. Before 7.2 R11 is BPF_REG_AX, which is never a store target.
const regParams = asm.Register(11)

// What a register or 8-byte stack slot may hold: a value the verifier never
// lets point into this frame (and never a function pointer), the entry
// context, possibly a function pointer (still not into this frame), a pointer
// into this frame (at off), or anything, including such a pointer at an
// unknown offset. The kinds are ordered so that <=ctxValue is a non-frame
// scalar, <=ctxFunc adds a possible function pointer, and >=ctxFrame is a
// frame pointer, exact or not. ctxOther means "none of the above in the
// verifier's view", so joining into it, not resetting to it, is what keeps a
// tracked function or frame pointer across an untracked write (see clobber).
const (
	ctxOther uint8 = iota
	ctxValue
	ctxFunc
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
	case a.t <= ctxFunc && b.t <= ctxFunc:
		return ctxKind{t: ctxFunc}
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

// fill sets every slot overlapping frame bytes [lo, hi) to k. Use it for a
// write the model can place exactly (a partial store through a frame
// pointer), or with k = ctxAny for a write that may reach any byte.
func (s *ctxState) fill(lo, hi int, k ctxKind) {
	for i := range s.slots {
		if off := -8 * (i + 1); off < hi && lo < off+8 {
			s.slots[i] = k
		}
	}
}

// clobber joins every slot overlapping [lo, 0) with ctxOther. Use it for a
// write the model cannot place: a helper's write somewhere in its buffers, or
// a dynptr-slice alias write. The verifier keeps a slot such a write misses,
// pointer type included, so resetting it would lose a frame or function
// pointer. The join costs precision: a frame pointer in such a slot becomes
// ctxAny, and a later store through it refuses the program.
func (s *ctxState) clobber(lo int) {
	for i := range s.slots {
		if off := -8 * (i + 1); lo < off+8 {
			s.slots[i] = joinCtx(s.slots[i], ctxKind{})
		}
	}
}

// ctxSlot maps a frame offset to a tracked 8-byte slot. Only fp-8..fp-512 are
// tracked. shortcut: an inlined bpf_loop in a frame deeper than 488 bytes
// spills R6-R8 below fp-512 and restores them after the loop; this stays sound
// only because the always-emitted E2BIG bypass (fixups.c) joins the original
// R6-R8 at the end label, so a frame or function pointer kept there widens
// instead of becoming the ctxOther an untracked restore reads.
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
		// A store through a map value, a slice or any other non-frame pointer:
		// the only bytes it can reach that we must model are the floor region,
		// where a dynptr-slice alias may write. shortcut: an alias write that
		// replaces a spilled non-stack pointer with a frame address is not
		// modelled; covering it would refuse the real Calico hooks.
		s.clobber(int(s.floor))
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
		case d.t >= ctxFunc || op.Source() == asm.RegSource && s.reg(ins.Src).t >= ctxFunc:
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
		if ins.IsLoadOfFunctionPointer() {
			other = ctxKind{t: ctxFunc}
		}
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
// synchronous callback a helper or kfunc runs. The verifier runs such a
// callback only when it is passed as a function pointer argument, so a call
// with no function pointer in R1-R5 runs none (an async timer callback runs
// later, not during the call). shortcut: an extension that later replaces a
// write-free callee is not modelled, since that needs the privileges to
// replace the program itself; bound the write with the callee's BTF if not.
func (s *ctxState) call(helper, writeFree, fnPtrElsewhere bool) {
	exposed, callback := false, false
	for r := asm.R1; r <= asm.R5; r++ {
		k := s.regs[r]
		callback = callback || k.t == ctxFunc || k.t == ctxAny
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
	s.clobber(int(s.floor))
	if exposed && (helper && callback || !helper && !writeFree) {
		s.fill(-512, 0, ctxKind{t: ctxAny})
	}
	for r := asm.R0; r <= asm.R5; r++ {
		s.regs[r] = ctxKind{}
	}
	if !helper {
		if callback || fnPtrElsewhere {
			s.regs[asm.R0] = ctxKind{t: ctxFunc} // a static callee may return a function pointer
		}
		if exposed {
			s.regs[asm.R0] = ctxKind{t: ctxAny} // or alias a caller buffer (a dynptr slice)
		}
	}
}

// Refusal reports why R1 does not hold the entry context at every call to name,
// or returns an empty string when it does. It accepts translated or raw code.
// holds the context at every call. It follows registers and 8-byte stack
// slots through the entry function and refuses what it cannot follow.
func Refusal(insns asm.Instructions, name string) string {
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
					return "the program defines the function more than once"
				}
				target = pc
			}
		}
	}
	if target <= 0 {
		return "the function is the entry or is missing from the translated instructions"
	}
	if insns.Size()/asm.InstructionSize > math.MaxInt16 {
		return "the program has more than 32,767 instructions" // the dump keeps call offsets in 16 bits
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
	entryEnd, targets, fnPtrElsewhere := end(0), map[int]bool{}, false
	for it := insns.Iterate(); it.Next(); {
		pc, ins := int(it.Offset), it.Ins
		fnPtr := ins.IsLoadOfFunctionPointer()
		if (fnPtr || ins.IsFunctionCall()) && jump(pc, ins) == target && (fnPtr || pc >= entryEnd) {
			// shortcut: calls from other functions are refused; prove their callers in turn if needed.
			return "it is called from another function or used as a function pointer"
		}
		// A function pointer loaded outside the entry can reach the target as a
		// static callee's R0, so its return may be a callback there (see call).
		fnPtrElsewhere = fnPtrElsewhere || (fnPtr && pc >= entryEnd)
		if pc < entryEnd {
			if ins.OpCode.Class().IsStore() && ins.Dst == regParams {
				// shortcut: a stack argument reaches the callee's frame unmodelled.
				return "the entry passes a stack argument through r11"
			}
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
				return "control leaves the entry function or lands inside an instruction"
			}
			ins := &insns[i]
			op, next := ins.OpCode, pc+int(ins.Size()/asm.InstructionSize)
			succ := []int{next}
			switch {
			case isCall(ins):
				callee := -1
				if ins.IsFunctionCall() {
					if callee = jump(pc, ins); !slices.Contains(starts, callee) {
						return fmt.Sprintf("the call at instruction %d does not reach a function start", pc)
					}
				}
				if callee == target && s.regs[asm.R1].t != ctxValue {
					return fmt.Sprintf("R1 may not hold the context at the call at instruction %d", pc)
				}
				keep := s.regs
				s.call(callee < 0, callee >= 0 && writeFree(callee), fnPtrElsewhere)
				// bpf_get_smp_processor_id, the only fastcall helper in 6.12-7.3,
				// carries no arguments, and a JIT that inlines it (arm64, riscv and
				// powerpc, plus s390 and loongarch from 7.2) keeps R1-R5; the
				// verifier dropped the spill/fill pair.
				// The dump shows its ID only with bpf_dump_raw_ok; without it
				// hidesHelperIDs refuses first. A raw call does clobber R1-R5,
				// so join rather than restore.
				if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnGetSmpProcessorId) {
					for r := asm.R1; r <= asm.R5; r++ {
						s.regs[r] = joinCtx(keep[r], ctxKind{})
					}
				}
			case op.Class().IsJump() && op.JumpOp() == asm.Ja && op.Source() == asm.RegSource:
				return fmt.Sprintf("the indirect jump at instruction %d is not followed", pc) // gotox: jump-table targets
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
	return ""
}
