package inject

import (
	"maps"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// uncloneReason says why kernelAddedCalls lists bpf_skb_pull_data.
const uncloneReason = "not hookable, added by the kernel at load: the verifier puts bpf_skb_pull_data(skb, 0) in front of a tc program " +
	"that writes packet data directly, as this one may, and it runs when the skb is cloned"

// kernelAddedCalls lists, without a site, each Calls name that the kernel
// may also call from instructions it adds to this program at load, after the
// rewrite: no hook can follow such a call. For sched_cls and sched_act, the
// verifier adds bpf_unclone_prologue (net/core/filter.c) for direct packet
// writes; it calls bpf_skb_pull_data only for a cloned skb. Checked on 6.12
// and 7.0.
func kernelAddedCalls(insns asm.Instructions, typ ebpf.ProgramType, req LookupRequest) ([]LookupSite, error) {
	if typ != ebpf.SchedCLS && typ != ebpf.SchedACT || !slices.Contains(req.Calls, "bpf_skb_pull_data") {
		return nil, nil
	}
	if writes, err := writesPacket(insns, req.Kernel, req.Modules); !writes || err != nil {
		return nil, err
	}
	return []LookupSite{{Call: "bpf_skb_pull_data", Reason: uncloneReason, KernelAdded: true}}, nil
}

// What a register or stack slot may hold, for writesPacket.
const (
	holdsCtx uint8 = 1 << iota
	holdsPacket
	holdsStack
)

// packetValue follows pointer kinds and, when known, a stack frame and offset.
// stackKind is shared with the read-only pointer analysis.
type packetValue struct {
	kind  uint8
	stack stackKind
	frame int
	off   int64
}

func joinPacket(a, b packetValue) packetValue {
	if a == (packetValue{}) {
		return b
	}
	if b == (packetValue{}) {
		return a
	}
	out := a
	out.kind |= b.kind
	if a.stack != b.stack || a.frame != b.frame || a.off != b.off {
		out.stack, out.frame, out.off = notStack, 0, 0
		if out.kind&holdsStack != 0 {
			out.stack = stackUnknown
		}
	}
	return out
}

type packetSlot struct {
	frame int
	off   int64
}

// packetState is the state before one instruction, with exact local spills.
type packetState struct {
	regs  [asm.R10 + 1]packetValue
	slots map[int64]packetValue
}

func (s packetState) join(o packetState) packetState {
	out := packetState{slots: maps.Clone(s.slots)}
	for r := range s.regs {
		out.regs[r] = joinPacket(s.regs[r], o.regs[r])
	}
	for off, k := range o.slots {
		if out.slots == nil {
			out.slots = map[int64]packetValue{}
		}
		out.slots[off] = joinPacket(out.slots[off], k)
	}
	return out
}

// writesPacket reports whether a tc program may write packet data directly,
// which makes the verifier set seen_direct_write (may_access_direct_pkt_data
// in kernel/bpf/verifier.c): a store through a pointer derived from the
// context's data or data_meta, or a call of bpf_dynptr_slice_rdwr. Both
// successors of every conditional jump count. Pointers follow moves, additions,
// spills to R10 and stack aliases, bpf-to-bpf arguments and results, and callback inputs.
// Constant stack offsets retain their frame through aliases and call arguments.
// Cross-frame slots have per-slot summaries; unknown targets share a summary.
func writesPacket(insns asm.Instructions, kernel *btf.Spec, modules map[int16]*btf.Spec) (bool, error) {
	const skbData, skbDataMeta = 76, 140 // offsets in struct __sk_buff
	indices := map[int]int{}
	funcOf := map[int]int{} // pc to the pc of its function's first instruction
	symbols := map[string]int{}
	var starts []int
	it := insns.Iterate()
	for it.Next() {
		pc := int(it.Offset)
		if btf.FuncMetadata(it.Ins) != nil || pc == 0 {
			starts = append(starts, pc)
		}
		if sym := it.Ins.Symbol(); sym != "" {
			symbols[sym] = pc
		}
		indices[pc], funcOf[pc] = it.Index, starts[len(starts)-1]
	}
	// Resolve address-taken functions for helper and kfunc callbacks.
	callbacks := map[int]bool{}
	for pc, idx := range indices {
		if ins := &insns[idx]; ins.IsLoadOfFunctionPointer() {
			target, _, _, err := relocTarget(ins, pc, indices, insns)
			if err != nil {
				return false, err
			}
			callbacks[target] = true
		}
	}
	// Summaries grow across passes, including stores into a caller's frame.
	rets := map[int]packetValue{}
	slots, crossStores := map[packetSlot]packetValue{}, map[packetSlot]packetValue{}
	var spilled, aliasedStores packetValue
	framePointer := func(frame int) packetValue { return packetValue{kind: holdsStack, stack: stackKnown, frame: frame} }
	for {
		oldSpilled, oldAliasedStores := spilled, aliasedStores
		oldSlots, oldCrossStores := maps.Clone(slots), maps.Clone(crossStores)
		before := map[int]packetState{}
		var work []int
		reach := func(pc int, s packetState) {
			if _, ok := indices[pc]; !ok {
				return
			}
			if old, seen := before[pc]; seen {
				if s = old.join(s); s.regs == old.regs && maps.Equal(s.slots, old.slots) {
					return
				}
			}
			before[pc] = s
			work = append(work, pc)
		}
		// Callers and helper arguments add inputs to these initial states.
		for _, start := range starts {
			s := packetState{}
			s.regs[asm.R10] = framePointer(start)
			if start == 0 {
				s.regs[asm.R1] = packetValue{kind: holdsCtx}
			}
			reach(start, s)
		}
		found := map[int]packetValue{}
		for len(work) > 0 {
			pc := work[len(work)-1]
			work = work[:len(work)-1]
			ins := &insns[indices[pc]]
			s := before[pc]
			s.regs[asm.R10] = framePointer(funcOf[pc])
			s.slots = maps.Clone(s.slots)
			next := pc + int(ins.Size()/asm.InstructionSize)
			op, class := ins.OpCode, ins.OpCode.Class()
			load := func(base asm.Register) packetValue {
				var value packetValue
				p := s.regs[base]
				if p.kind&holdsCtx != 0 && (ins.Offset == skbData || ins.Offset == skbDataMeta) {
					value.kind |= holdsPacket
				}
				if op.Size() == asm.DWord && p.kind&holdsStack != 0 {
					switch p.stack {
					case stackKnown:
						slot := packetSlot{p.frame, p.off + int64(ins.Offset)}
						k := slots[slot]
						if p.frame == funcOf[pc] {
							k = joinPacket(s.slots[slot.off], crossStores[slot])
						}
						value = joinPacket(value, joinPacket(k, aliasedStores))
					case stackUnknown:
						value = joinPacket(value, spilled)
					}
				}
				return value
			}
			store := func(value packetValue) {
				p := s.regs[ins.Dst]
				if p.kind&holdsStack == 0 {
					return
				}
				spilled = joinPacket(spilled, value)
				if p.stack != stackKnown {
					aliasedStores = joinPacket(aliasedStores, value)
					return
				}
				off := p.off + int64(ins.Offset)
				if p.frame == funcOf[pc] {
					// Only R10 certainly targets this slot; aliases may also hold untracked pointers.
					if ins.Dst == asm.R10 {
						for slot := off &^ 7; slot < off+int64(op.Size().Sizeof()); slot += 8 {
							delete(s.slots, slot)
						}
					}
					if value != (packetValue{}) && off%8 == 0 {
						if s.slots == nil {
							s.slots = map[int64]packetValue{}
						}
						s.slots[off] = joinPacket(s.slots[off], value)
					}
				}
				if value != (packetValue{}) && off%8 == 0 {
					slot := packetSlot{p.frame, off}
					slots[slot] = joinPacket(slots[slot], value)
					if p.frame != funcOf[pc] {
						crossStores[slot] = joinPacket(crossStores[slot], value)
					}
				}
			}
			switch {
			case op.JumpOp() == asm.Exit:
				found[funcOf[pc]] = joinPacket(found[funcOf[pc]], s.regs[asm.R0])
				continue
			case ins.IsKfuncCall():
				if _, name, named := callee(ins, kernel, modules); name == "bpf_dynptr_slice_rdwr" || !named && ins.Offset == 0 {
					return true, nil
				}
				fallthrough
			case ins.IsBuiltinCall():
				// Callback signatures differ: any helper argument may reach any
				// callback parameter, including a pointer to a caller's stack.
				var input packetValue
				for _, k := range s.regs[asm.R1 : asm.R5+1] {
					input = joinPacket(input, k)
				}
				for target := range callbacks {
					args := packetState{}
					for r := asm.R1; r <= asm.R5; r++ {
						args.regs[r] = input
					}
					args.regs[asm.R10] = framePointer(target)
					reach(target, args)
				}
				clear(s.regs[asm.R0 : asm.R5+1])
				reach(next, s)
				continue
			case ins.IsFunctionCall():
				target, ok := symbols[ins.Reference()]
				if ins.Reference() == "" {
					_, ok = indices[pc+1+int(ins.Constant)]
					target = pc + 1 + int(ins.Constant)
				}
				r0 := packetValue{kind: holdsCtx | holdsPacket | holdsStack, stack: stackUnknown}
				if ok {
					args := packetState{}
					args.regs[asm.R10] = framePointer(target)
					copy(args.regs[asm.R1:asm.R5+1], s.regs[asm.R1:asm.R5+1])
					reach(target, args)
					r0 = rets[target]
				}
				clear(s.regs[asm.R0 : asm.R5+1])
				s.regs[asm.R0] = r0
				reach(next, s)
				continue
			case class == asm.StXClass && op.AtomicOp() == atomicLoadAcquire:
				s.regs[ins.Dst] = load(ins.Src)
			case class == asm.StXClass && op.Mode() == asm.AtomicMode && op.AtomicOp() != atomicStoreRelease:
				// A fetch returns the old slot value, including spilled pointers.
				old := load(ins.Dst)
				store(packetValue{})
				switch atomic := op.AtomicOp(); {
				case atomic == asm.CmpXchg:
					s.regs[asm.R0] = old
				case atomic&atomicFetch != 0:
					s.regs[ins.Src] = old
				}
			case class.IsStore():
				if s.regs[ins.Dst].kind&holdsPacket != 0 && ins.OpCode.Mode() == asm.MemMode {
					return true, nil
				}
				value := packetValue{}
				if class == asm.StXClass && (op.Mode() == asm.MemMode || op.AtomicOp() == atomicStoreRelease) && op.Size() == asm.DWord {
					value = s.regs[ins.Src]
				}
				store(value)
			case class.IsLoad():
				if class == asm.LdXClass {
					s.regs[ins.Dst] = load(ins.Src)
				} else {
					s.regs[ins.Dst] = packetValue{}
				}
			case class == asm.ALU64Class:
				switch src := (packetValue{}); op.ALUOp() {
				case asm.Mov:
					if op.Source() == asm.RegSource {
						src = s.regs[ins.Src]
					}
					s.regs[ins.Dst] = src
				case asm.Add, asm.Sub:
					if op.ALUOp() == asm.Add && op.Source() == asm.RegSource {
						src = s.regs[ins.Src]
					}
					p := joinPacket(s.regs[ins.Dst], src)
					switch {
					case p.stack == stackKnown && op.Source() == asm.ImmSource:
						if op.ALUOp() == asm.Add {
							p.off += ins.Constant
						} else {
							p.off -= ins.Constant
						}
					case p.kind&holdsStack != 0:
						p.stack, p.frame, p.off = stackUnknown, 0, 0
					}
					s.regs[ins.Dst] = p
				default:
					s.regs[ins.Dst] = packetValue{}
				}
			case class == asm.ALUClass:
				s.regs[ins.Dst] = packetValue{}
			}
			if !class.IsJump() {
				reach(next, s)
				continue
			}
			target, relative, _, err := relocTarget(ins, pc, indices, insns)
			if err != nil {
				return false, err
			}
			if relative {
				reach(target, s)
			}
			if op.JumpOp() != asm.Ja {
				reach(next, s)
			}
		}
		delete(found, 0)
		if maps.Equal(found, rets) && spilled == oldSpilled && aliasedStores == oldAliasedStores && maps.Equal(slots, oldSlots) && maps.Equal(crossStores, oldCrossStores) {
			return false, nil
		}
		rets = found
	}
}
