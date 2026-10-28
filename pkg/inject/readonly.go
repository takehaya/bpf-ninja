package inject

import (
	"maps"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// pointerState is what readOnlyPointers knows about one register.
type pointerState struct {
	readOnly bool // may point into the value of a BPF_F_RDONLY_PROG map
	roMap    bool // is a BPF_F_RDONLY_PROG map
	stack    stackKind
	off      int64 // the offset from R10 when stack is stackKnown
}

type stackKind uint8

const (
	notStack stackKind = iota
	stackKnown
	stackUnknown // a stack pointer whose offset is not followed
)

// readOnlyState is the state before one instruction of the entry function.
type readOnlyState struct {
	regs [asm.R10 + 1]pointerState
	// slots are the 8-byte stack slots, by offset from R10, that may hold a
	// spilled read-only pointer; anySlot means any slot may.
	slots   map[int64]bool
	anySlot bool
}

func (s readOnlyState) equal(o readOnlyState) bool {
	return s.regs == o.regs && s.anySlot == o.anySlot && maps.Equal(s.slots, o.slots)
}

// join merges o into s: what may hold on either path may hold after both.
func (s readOnlyState) join(o readOnlyState) readOnlyState {
	out := readOnlyState{slots: maps.Clone(s.slots), anySlot: s.anySlot || o.anySlot}
	for r := range s.regs {
		a, b := s.regs[r], o.regs[r]
		p := pointerState{readOnly: a.readOnly || b.readOnly, roMap: a.roMap || b.roMap, stack: a.stack, off: a.off}
		if a.stack != b.stack || a.off != b.off {
			p.stack, p.off = notStack, 0
			if a.stack != notStack || b.stack != notStack {
				p.stack = stackUnknown
			}
		}
		out.regs[r] = p
	}
	for off, ro := range o.slots {
		if ro {
			if out.slots == nil {
				out.slots = map[int64]bool{}
			}
			out.slots[off] = true
		}
	}
	return out
}

// readOnlyPointers returns, for each reachable instruction of the entry
// function, which registers may point into a BPF_F_RDONLY_PROG map's value:
// a map-value load of such a map, a lookup in it, and the values they reach through registers, constant offsets,
// stack spills and joining paths. A pointer the verifier sees as a scalar,
// such as one loaded from map memory, does not count. A subprogram call
// that is passed a stack pointer may store such a pointer in the caller's
// stack, and may return one, when a subprogram references such a map.
//
// Without a BPF_F_RDONLY_PROG map in the program nothing is marked, and a
// read-only inner map reached only through a map-in-map is not seen.
func readOnlyPointers(insns asm.Instructions, indices map[int]int, resolve lookupMapResolver) (map[int]readOnlyState, error) {
	readOnlyMap := func(ins *asm.Instruction) bool {
		_, m := resolve(ins)
		return m != nil && m.Flags&bpfFRdonlyProg != 0
	}
	// Subprograms follow the entry function.
	any, inSubprog, subprogReadOnly := false, false, false
	it := insns.Iterate()
	for it.Next() {
		inSubprog = inSubprog || it.Offset > 0 && btf.FuncMetadata(it.Ins) != nil
		if it.Ins.IsLoadFromMap() && readOnlyMap(it.Ins) {
			any, subprogReadOnly = true, subprogReadOnly || inSubprog
		}
	}
	before := map[int]readOnlyState{}
	if !any {
		return before, nil
	}

	entry := readOnlyState{}
	entry.regs[asm.RFP] = pointerState{stack: stackKnown}
	before[0] = entry
	work := []int{0}
	reach := func(pc int, s readOnlyState) {
		if old, seen := before[pc]; seen {
			s = old.join(s)
			if s.equal(old) {
				return
			}
		}
		before[pc] = s
		work = append(work, pc)
	}
	for len(work) > 0 {
		pc := work[len(work)-1]
		work = work[:len(work)-1]
		idx, ok := indices[pc]
		if !ok {
			continue
		}
		ins := &insns[idx]
		s := before[pc]
		s.slots = maps.Clone(s.slots)
		readOnlyStep(&s, ins, readOnlyMap, subprogReadOnly)
		next := pc + int(ins.Size()/asm.InstructionSize)
		op := ins.OpCode
		switch {
		case op.JumpOp() == asm.Exit:
			continue
		case !op.Class().IsJump() || op.JumpOp() == asm.Call:
			reach(next, s)
			continue
		}
		target, relative, function, err := relocTarget(ins, pc, indices, insns)
		if err != nil {
			return nil, err
		}
		if relative && !function {
			reach(target, s)
		}
		if op.JumpOp() != asm.Ja {
			reach(next, s)
		}
	}
	return before, nil
}

// readOnlyStep applies ins to s (see readOnlyPointers).
func readOnlyStep(s *readOnlyState, ins *asm.Instruction, readOnlyMap func(*asm.Instruction) bool, subprogReadOnly bool) {
	op, class := ins.OpCode, ins.OpCode.Class()
	regs := &s.regs
	clearSlots := func(off int64, size int64) {
		for slot := off &^ 7; slot < off+size; slot += 8 {
			delete(s.slots, slot)
		}
	}
	switch {
	case ins.IsBuiltinCall() || ins.IsKfuncCall():
		ret := pointerState{}
		fn := asm.BuiltinFunc(ins.Constant)
		if ins.IsKfuncCall() || (fn == asm.FnMapLookupElem || fn == asm.FnMapLookupPercpuElem) && regs[asm.R1].roMap {
			ret.readOnly = true
		}
		for r := asm.R0; r <= asm.R5; r++ {
			regs[r] = pointerState{}
		}
		regs[asm.R0] = ret
	case ins.IsFunctionCall():
		ret := pointerState{readOnly: subprogReadOnly}
		for r := asm.R1; r <= asm.R5; r++ {
			ret.readOnly = ret.readOnly || regs[r].readOnly
			if regs[r].stack != notStack && subprogReadOnly {
				s.anySlot = true
			}
		}
		for r := asm.R0; r <= asm.R5; r++ {
			regs[r] = pointerState{}
		}
		regs[asm.R0] = ret
	case class.IsJump():
	case class == asm.LdClass && op != asm.LoadImmOp(asm.DWord):
		// A legacy packet load sets R0 and clobbers R1-R5.
		for r := asm.R0; r <= asm.R5; r++ {
			regs[r] = pointerState{}
		}
	case op == asm.LoadImmOp(asm.DWord):
		p := pointerState{}
		switch {
		case ins.IsLoadFromMap() && ins.Src == asm.PseudoMapValue:
			p.readOnly = readOnlyMap(ins)
		case ins.IsLoadFromMap():
			p.roMap = readOnlyMap(ins)
		}
		regs[ins.Dst] = p
	case class == asm.ALU64Class && op.ALUOp() == asm.Mov && op.Source() == asm.RegSource && ins.Offset == 0:
		regs[ins.Dst] = regs[ins.Src]
	case class == asm.ALU64Class && (op.ALUOp() == asm.Add || op.ALUOp() == asm.Sub):
		p := regs[ins.Dst]
		p.roMap = false
		switch {
		case p.stack == stackKnown && op.Source() == asm.ImmSource && op.ALUOp() == asm.Add:
			p.off += int64(ins.Constant)
		case p.stack == stackKnown && op.Source() == asm.ImmSource:
			p.off -= int64(ins.Constant)
		case p.stack == stackKnown:
			p.stack, p.off = stackUnknown, 0
		}
		regs[ins.Dst] = p
	case class.IsALU():
		regs[ins.Dst] = pointerState{}
	case class == asm.LdXClass:
		p, base := pointerState{}, regs[ins.Src]
		if op.Size() == asm.DWord {
			switch base.stack {
			case stackKnown:
				p.readOnly = s.anySlot || s.slots[base.off+int64(ins.Offset)]
			case stackUnknown:
				p.readOnly = s.anySlot || len(s.slots) > 0
			}
		}
		regs[ins.Dst] = p
	case class == asm.StXClass && op.Mode() == asm.AtomicMode:
		if base := regs[ins.Dst]; base.stack == stackKnown {
			clearSlots(base.off+int64(ins.Offset), int64(op.Size().Sizeof()))
		}
		regs[ins.Src], regs[asm.R0] = pointerState{}, pointerState{}
	case class == asm.StXClass || class == asm.StClass:
		base := regs[ins.Dst]
		ro := class == asm.StXClass && op.Size() == asm.DWord && regs[ins.Src].readOnly
		switch base.stack {
		case stackKnown:
			off := base.off + int64(ins.Offset)
			clearSlots(off, int64(op.Size().Sizeof()))
			if ro && off%8 == 0 {
				if s.slots == nil {
					s.slots = map[int64]bool{}
				}
				s.slots[off] = true
			}
		case stackUnknown:
			s.anySlot = s.anySlot || ro
		}
	}
	regs[asm.RFP] = pointerState{stack: stackKnown}
}
