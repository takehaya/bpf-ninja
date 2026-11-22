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
// verifier's prologue (bpf_unclone_prologue in net/core/filter.c, kernels 6.12
// and 7.0) calls bpf_skb_pull_data when the program writes packet data directly.
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

// packetState is the state before one instruction: registers and the 8-byte
// slots spilled at R10 plus a constant in the current frame.
type packetState struct {
	regs  [asm.R10 + 1]uint8
	slots map[int16]uint8
}

func (s packetState) join(o packetState) packetState {
	out := packetState{slots: maps.Clone(s.slots)}
	for r := range s.regs {
		out.regs[r] = s.regs[r] | o.regs[r]
	}
	for off, k := range o.slots {
		if out.slots == nil {
			out.slots = map[int16]uint8{}
		}
		out.slots[off] |= k
	}
	return out
}

// writesPacket reports whether a tc program may write packet data directly,
// which makes the verifier set seen_direct_write (may_access_direct_pkt_data
// in kernel/bpf/verifier.c): a store through a pointer derived from the
// context's data or data_meta, or a call of bpf_dynptr_slice_rdwr. Every
// path counts, reachable or not. Pointers follow moves, additions, spills to
// R10 and stack aliases, bpf-to-bpf arguments and results, and callback inputs.
// Aliased stack accesses share a summary across frames; literal R10 slots stay
// precise except for possible writes through aliases.
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
	rets := map[int]uint8{}
	var spilled, aliasedStores uint8
	for {
		oldSpilled, oldAliasedStores := spilled, aliasedStores
		before := map[int]packetState{}
		var work []int
		reach := func(pc int, s packetState) {
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
			s.regs[asm.R10] = holdsStack
			if start == 0 {
				s.regs[asm.R1] = holdsCtx
			}
			reach(start, s)
		}
		found := map[int]uint8{}
		for len(work) > 0 {
			pc := work[len(work)-1]
			work = work[:len(work)-1]
			ins := &insns[indices[pc]]
			s := before[pc]
			s.slots = maps.Clone(s.slots)
			next := pc + int(ins.Size()/asm.InstructionSize)
			op, class := ins.OpCode, ins.OpCode.Class()
			switch {
			case op.JumpOp() == asm.Exit:
				found[funcOf[pc]] |= s.regs[asm.R0]
				continue
			case ins.IsKfuncCall():
				if _, name, _ := callee(ins, kernel, modules); name == "bpf_dynptr_slice_rdwr" {
					return true, nil
				}
				fallthrough
			case ins.IsBuiltinCall():
				// Callback signatures differ: any helper argument may reach any
				// callback parameter, including a pointer to a caller's stack.
				var input uint8
				for _, k := range s.regs[asm.R1 : asm.R5+1] {
					input |= k
				}
				for target := range callbacks {
					args := packetState{}
					for r := asm.R1; r <= asm.R5; r++ {
						args.regs[r] = input
					}
					args.regs[asm.R10] = holdsStack
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
				r0 := holdsCtx | holdsPacket | holdsStack
				if ok {
					args := packetState{}
					args.regs[asm.R10] = holdsStack
					copy(args.regs[asm.R1:asm.R5+1], s.regs[asm.R1:asm.R5+1])
					reach(target, args)
					r0 = rets[target]
				}
				clear(s.regs[asm.R0 : asm.R5+1])
				s.regs[asm.R0] = r0
				reach(next, s)
				continue
			case class.IsStore():
				if s.regs[ins.Dst]&holdsPacket != 0 && ins.OpCode.Mode() == asm.MemMode {
					return true, nil
				}
				if s.regs[ins.Dst]&holdsStack != 0 && class == asm.StXClass && ins.OpCode.Mode() == asm.MemMode && ins.OpCode.Size() == asm.DWord {
					spilled |= s.regs[ins.Src]
					if ins.Dst != asm.R10 {
						aliasedStores |= s.regs[ins.Src]
					}
				}
				if ins.Dst == asm.R10 {
					delete(s.slots, ins.Offset&^7)
					if class == asm.StXClass && ins.OpCode.Mode() == asm.MemMode && ins.OpCode.Size() == asm.DWord && s.regs[ins.Src] != 0 {
						if s.slots == nil {
							s.slots = map[int16]uint8{}
						}
						s.slots[ins.Offset] = s.regs[ins.Src]
					}
				}
			case class.IsLoad():
				var k uint8
				if class == asm.LdXClass && s.regs[ins.Src]&holdsCtx != 0 && (ins.Offset == skbData || ins.Offset == skbDataMeta) {
					k |= holdsPacket
				}
				switch {
				case class == asm.LdXClass && ins.Src == asm.R10 && ins.OpCode.Size() == asm.DWord:
					k |= s.slots[ins.Offset] | aliasedStores
				case class == asm.LdXClass && s.regs[ins.Src]&holdsStack != 0 && ins.OpCode.Size() == asm.DWord:
					k |= spilled
				}
				s.regs[ins.Dst] = k
			case class == asm.ALU64Class:
				switch src := uint8(0); op.ALUOp() {
				case asm.Mov:
					if op.Source() == asm.RegSource {
						src = s.regs[ins.Src]
					}
					s.regs[ins.Dst] = src
				case asm.Add, asm.Sub:
					if op.ALUOp() == asm.Add && op.Source() == asm.RegSource {
						src = s.regs[ins.Src]
					}
					s.regs[ins.Dst] |= src
				default:
					s.regs[ins.Dst] = 0
				}
			case class == asm.ALUClass:
				s.regs[ins.Dst] = 0
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
		if maps.Equal(found, rets) && spilled == oldSpilled && aliasedStores == oldAliasedStores {
			return false, nil
		}
		rets = found
	}
}
