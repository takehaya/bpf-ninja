package inject

import (
	"maps"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// pointerState is what readOnlyPointers knows about one register.
type pointerState struct {
	readOnly   bool // may point into the value of a BPF_F_RDONLY_PROG map
	roMap      bool // is a BPF_F_RDONLY_PROG value map
	innerROMap bool // is a map-in-map whose inner-map template is BPF_F_RDONLY_PROG
	devMap     bool // is a devmap or devmap hash, whose lookups return read-only values
	stack      stackKind
	off        int64 // the offset from R10 when stack is stackKnown
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
	// slots are tracked 8-byte stack spills by offset from R10. anySlot is
	// state that an unknown slot may hold.
	slots   map[int64]pointerState
	anySlot pointerState
}

func (s readOnlyState) equal(o readOnlyState) bool {
	return s.regs == o.regs && s.anySlot == o.anySlot && maps.Equal(s.slots, o.slots)
}

func joinPointer(a, b pointerState) pointerState {
	p := pointerState{readOnly: a.readOnly || b.readOnly, roMap: a.roMap || b.roMap,
		innerROMap: a.innerROMap || b.innerROMap, devMap: a.devMap || b.devMap, stack: a.stack, off: a.off}
	if a.stack != b.stack || a.off != b.off {
		p.stack, p.off = notStack, 0
		if a.stack != notStack || b.stack != notStack {
			p.stack = stackUnknown
		}
	}
	return p
}

func joinTracked(a, b pointerState) pointerState {
	if a == (pointerState{}) {
		return b
	}
	if b == (pointerState{}) {
		return a
	}
	return joinPointer(a, b)
}

// join merges o into s: what may hold on either path may hold after both.
func (s readOnlyState) join(o readOnlyState) readOnlyState {
	out := readOnlyState{slots: maps.Clone(s.slots), anySlot: joinTracked(s.anySlot, o.anySlot)}
	for r := range s.regs {
		out.regs[r] = joinPointer(s.regs[r], o.regs[r])
	}
	for off, p := range o.slots {
		if out.slots == nil {
			out.slots = map[int64]pointerState{}
		}
		out.slots[off] = joinTracked(out.slots[off], p)
	}
	return out
}

// readOnlyPointers returns, for each reachable instruction of the entry
// function, which registers may point into a BPF_F_RDONLY_PROG map's value:
// a map-value load of such a map, a lookup in it, and the values they reach through registers, constant offsets,
// tracked pointer spills and joining paths. A pointer the verifier sees as a scalar,
// such as one loaded from map memory, does not count. A subprogram call
// that is passed a stack pointer may store such a pointer in the caller's
// stack, and may return one, when a subprogram references such a map.
//
// A map-in-map's inner-map template and cilium/ebpf's unresolved .kconfig
// map-value loads count too. Without any such load nothing is marked.
//
// A devmap's value is read-only to programs too (see progFlags), but its
// pointer reaches the value only through a lookup: only that lookup's result
// is marked, kfunc results stay unmarked unless another such map is
// referenced, and a subprogram makes calls return read-only memory only when
// it both references a devmap and looks up or calls something it could pass it to,
// or when a devmap pointer already reaches the call through an argument or the stack.
// A subprogram that references a devmap may still hand the pointer back, so a
// call may return a devmap pointer, or store one through a stack argument.
func readOnlyPointers(insns asm.Instructions, indices map[int]int, resolve lookupMapResolver) (map[int]readOnlyState, error) {
	mapPointer := func(ins *asm.Instruction) pointerState {
		_, m := resolve(ins)
		if m == nil {
			// cilium/ebpf represents a .kconfig extern as an unresolved
			// PseudoMapValue load whose private metadata creates the map later.
			if ins.IsLoadFromMap() && ins.Src == asm.PseudoMapValue {
				return pointerState{roMap: true}
			}
			return pointerState{}
		}
		if m.Type == ebpf.DevMap || m.Type == ebpf.DevMapHash {
			return pointerState{devMap: true}
		}
		mapInMap := m.Type == ebpf.HashOfMaps || m.Type == ebpf.ArrayOfMaps
		return pointerState{roMap: !mapInMap && m.Flags&bpfFRdonlyProg != 0,
			innerROMap: mapInMap && m.InnerFlags&bpfFRdonlyProg != 0}
	}
	// Subprograms follow the entry function. devLoad and devUse are whether
	// the current subprogram loads a devmap pointer and looks something up or
	// makes a call that could. subprogDevMap is whether any subprogram loads one.
	roMaps, devMaps, inSubprog, subprogReadOnly, subprogDevMap := false, false, false, false, false
	devLoad, devUse := false, false
	endFunc := func() { subprogReadOnly = subprogReadOnly || inSubprog && devLoad && devUse }
	it := insns.Iterate()
	for it.Next() {
		if it.Offset > 0 && btf.FuncMetadata(it.Ins) != nil {
			endFunc()
			inSubprog, devLoad, devUse = true, false, false
		}
		if it.Ins.IsLoadFromMap() {
			switch p := mapPointer(it.Ins); {
			case p.devMap:
				devMaps, devLoad, subprogDevMap = true, true, subprogDevMap || inSubprog
			case p != (pointerState{}):
				roMaps, subprogReadOnly = true, subprogReadOnly || inSubprog
			}
		}
		fn := asm.BuiltinFunc(it.Ins.Constant)
		devUse = devUse || it.Ins.IsFunctionCall() ||
			it.Ins.IsBuiltinCall() && (fn == asm.FnMapLookupElem || fn == asm.FnMapLookupPercpuElem || takesCallback(fn))
	}
	endFunc()
	before := map[int]readOnlyState{}
	if !roMaps && !devMaps {
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
		readOnlyStep(&s, ins, mapPointer, subprogReadOnly, subprogDevMap, roMaps)
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

// readOnlyStep applies ins to s (see readOnlyPointers). kfuncReadOnly marks
// kfunc results.
func readOnlyStep(s *readOnlyState, ins *asm.Instruction, mapPointer func(*asm.Instruction) pointerState, subprogReadOnly, subprogDevMap, kfuncReadOnly bool) {
	op, class := ins.OpCode, ins.OpCode.Class()
	regs := &s.regs
	clearSlots := func(off int64, size int64) {
		for slot := off &^ 7; slot < off+size; slot += 8 {
			delete(s.slots, slot)
		}
	}
	// load and store access ins.Offset from a base register; only 8-byte
	// accesses move a pointer.
	load := func(base pointerState) pointerState {
		if op.Size() != asm.DWord {
			return pointerState{}
		}
		switch base.stack {
		case stackKnown:
			return joinTracked(s.anySlot, s.slots[base.off+int64(ins.Offset)])
		case stackUnknown:
			p := s.anySlot
			for _, slot := range s.slots {
				p = joinTracked(p, slot)
			}
			return p
		}
		return pointerState{}
	}
	store := func(p pointerState) {
		if op.Size() != asm.DWord {
			p = pointerState{}
		}
		switch base := regs[ins.Dst]; base.stack {
		case stackKnown:
			off := base.off + int64(ins.Offset)
			clearSlots(off, int64(op.Size().Sizeof()))
			if p != (pointerState{}) && off%8 == 0 {
				if s.slots == nil {
					s.slots = map[int64]pointerState{}
				}
				s.slots[off] = p
			}
		case stackUnknown:
			s.anySlot = joinTracked(s.anySlot, p)
		}
	}
	switch {
	case ins.IsBuiltinCall() || ins.IsKfuncCall():
		ret := pointerState{}
		fn := asm.BuiltinFunc(ins.Constant)
		if ins.IsKfuncCall() || takesCallback(fn) {
			// The callback is a subprogram and may write through a stack argument.
			subprogCall(s, subprogReadOnly, subprogDevMap)
		}
		if ins.IsKfuncCall() && kfuncReadOnly || (fn == asm.FnMapLookupElem || fn == asm.FnMapLookupPercpuElem) && (regs[asm.R1].roMap || regs[asm.R1].devMap) {
			ret.readOnly = true
		}
		if (fn == asm.FnMapLookupElem || fn == asm.FnMapLookupPercpuElem) && regs[asm.R1].innerROMap {
			ret.roMap = true
		}
		for r := asm.R0; r <= asm.R5; r++ {
			regs[r] = pointerState{}
		}
		regs[asm.R0] = ret
	case ins.IsFunctionCall():
		ret := subprogCall(s, subprogReadOnly, subprogDevMap)
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
			// The verifier refuses a devmap value load; mark one anyway.
			mp := mapPointer(ins)
			p.readOnly = mp.roMap || mp.devMap
		case ins.IsLoadFromMap():
			p = mapPointer(ins)
		}
		regs[ins.Dst] = p
	case class == asm.ALU64Class && op.ALUOp() == asm.Mov && op.Source() == asm.RegSource && ins.Offset == 0:
		regs[ins.Dst] = regs[ins.Src]
	case class == asm.ALU64Class && (op.ALUOp() == asm.Add || op.ALUOp() == asm.Sub):
		p := regs[ins.Dst]
		p.roMap, p.devMap = false, false
		if src := regs[ins.Src]; op.ALUOp() == asm.Add && op.Source() == asm.RegSource {
			// scalar += pointer makes a pointer.
			p.readOnly = p.readOnly || src.readOnly
			if src.stack != notStack && p.stack == notStack {
				p.stack = stackUnknown
			}
		}
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
		regs[ins.Dst] = load(regs[ins.Src])
	case class == asm.StXClass && op.AtomicOp() == atomicLoadAcquire:
		regs[ins.Dst] = load(regs[ins.Src])
	case class == asm.StXClass && op.AtomicOp() == atomicStoreRelease:
		store(regs[ins.Src])
	case class == asm.StXClass && op.Mode() == asm.AtomicMode:
		// A fetch returns the old value, which may be a spilled pointer; the
		// slot is left holding a scalar.
		old := load(regs[ins.Dst])
		if base := regs[ins.Dst]; base.stack == stackKnown {
			clearSlots(base.off+int64(ins.Offset), int64(op.Size().Sizeof()))
		}
		switch atomic := op.AtomicOp(); {
		case atomic == asm.CmpXchg:
			regs[asm.R0] = old
		case atomic&atomicFetch != 0:
			regs[ins.Src] = old
		}
	case class == asm.StXClass:
		store(regs[ins.Src])
	case class == asm.StClass:
		store(pointerState{})
	}
	regs[asm.RFP] = pointerState{stack: stackKnown}
}

// subprogCall applies a call to a subprogram, or a callback a helper calls,
// to s before the call clobbers R0-R5. The subprogram may return what its
// arguments reach and store it through a stack argument; with subprogDevMap
// that includes a devmap pointer it loads itself.
func subprogCall(s *readOnlyState, subprogReadOnly, subprogDevMap bool) pointerState {
	ret := pointerState{readOnly: subprogReadOnly, roMap: subprogReadOnly, innerROMap: subprogReadOnly, devMap: subprogDevMap}
	stackArg := false
	for r := asm.R1; r <= asm.R5; r++ {
		p := s.regs[r]
		ret = joinTracked(ret, p)
		ret.readOnly = ret.readOnly || p.roMap || p.innerROMap || p.devMap
		stackArg = stackArg || p.stack != notStack
	}
	if stackArg {
		for _, p := range s.slots {
			ret = joinTracked(ret, p)
			ret.readOnly = ret.readOnly || p.roMap || p.innerROMap || p.devMap
		}
		ret = joinTracked(ret, s.anySlot)
		ret.readOnly = ret.readOnly || s.anySlot.roMap || s.anySlot.innerROMap || s.anySlot.devMap
		s.anySlot = joinTracked(s.anySlot, ret)
	}
	return ret
}

// takesCallback reports whether helper fn calls a subprogram of the program.
func takesCallback(fn asm.BuiltinFunc) bool {
	switch fn {
	case asm.FnLoop, asm.FnForEachMapElem, asm.FnTimerSetCallback, asm.FnFindVma, asm.FnUserRingbufDrain:
		return true
	}
	return false
}

// Atomic forms cilium/ebpf does not export: load-acquire reads into Dst from
// Src, store-release writes Src through Dst, and the fetch bit returns the old
// value in Src.
const (
	atomicFetch        asm.AtomicOp = 0x0100
	atomicLoadAcquire  asm.AtomicOp = 0x1_0000
	atomicStoreRelease asm.AtomicOp = 0x1_1000
)
