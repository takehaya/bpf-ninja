package core

// Liveness for the P9 rule (README.md, Obligations): which of r1-r5 an
// original function may read before writing, on some path from its entry.
// A standard backward may-liveness over the original stream O, computed
// as the least fixed point (Aho et al. §9.2.5).
// Every approximation errs towards "live" (fail-closed for P9): an
// instruction outside the table below reads every register and makes its
// function's entry fully live; leaving a function except by exit, or a
// branch target outside the function, counts as reading everything.
//
// Calling convention (C-1/C-2; verifier
// clear_caller_saved_regs): a call reads its arguments and leaves r0-r5
// written (r1-r5 are NOT_INIT afterwards, so a valid O never reads
// them before writing them again).

const allRegs = 0x7ff // r0-r10

// ArgRegs is the mask of r1-r5.
const ArgRegs uint16 = 0x3e

// helperArgs is the number of arguments of a helper, from the prototypes in
// include/uapi/linux/bpf.h (v7.0, "long bpf_<name>(...)" comments). A helper
// not listed reads r1-r5 (conservative). Only helpers seen in the original
// streams of the corpus and the export are listed.
var helperArgs = map[int32]int{
	1:   2, // map_lookup_elem(map, key)
	2:   4, // map_update_elem(map, key, value, flags)
	3:   2, // map_delete_elem(map, key)
	5:   0, // ktime_get_ns()
	8:   0, // get_smp_processor_id()
	44:  2, // xdp_adjust_head(xdp_md, delta)
	164: 4, // for_each_map_elem(map, callback_fn, callback_ctx, flags)
	181: 4, // loop(nr_loops, callback_fn, callback_ctx, flags)
}

func bit(r uint8) uint16 { return 1 << r }

// LiveIn returns, for each function of o (starts: decoded index of each
// function's first instruction, increasing, starts[0] == 0), the mask of
// r1-r5 live at its entry.
func LiveIn(o []Insn, starts []int) []uint16 {
	n := len(o)
	fn := make([]int, n) // function of each instruction
	for f := range starts {
		end := n
		if f+1 < len(starts) {
			end = starts[f+1]
		}
		for i := starts[f]; i < end && i < n; i++ {
			fn[i] = f
		}
	}
	idx := map[int]int{} // raw slot -> decoded index
	for i, x := range o {
		idx[x.Raw] = i
	}
	funcAt := map[int]int{} // raw slot of a function start -> function
	for f, s := range starts {
		if s < n {
			funcAt[o[s].Raw] = f
		}
	}
	in := make([]uint16, n)
	fin := make([]uint16, len(starts))
	for changed := true; changed; {
		changed = false
		for i := n - 1; i >= 0; i-- {
			x := o[i]
			use, def, fall := uint16(0), uint16(0), true
			var succ []int
			c, code, isX := x.Class(), x.Op&0xf0, x.Op&0x08 != 0
			switch {
			case c == ClassALU || c == ClassALU64:
				if code != 0xb0 { // every op but mov reads dst
					use |= bit(x.Dst)
				}
				if isX {
					use |= bit(x.Src)
				}
				def = bit(x.Dst)
			case c == ClassLDX:
				use, def = bit(x.Src), bit(x.Dst)
			case c == ClassST:
				use = bit(x.Dst)
			case c == ClassSTX: // plain and atomic stores; atomics may read r0, written registers ignored
				use = bit(x.Dst) | bit(x.Src) | 1
			case x.Op == OpLdImm64:
				def = bit(x.Dst)
			case x.IsHelperCall():
				k, ok := helperArgs[x.Imm]
				if !ok {
					k = 5
				}
				for r := 1; r <= k; r++ {
					use |= 1 << r
				}
				def = 0x3f
			case x.IsPseudoCall():
				use = ArgRegs
				if g, ok := funcAt[x.CallTarget()]; ok {
					use = fin[g]
				}
				def = 0x3f
			case x.Op == OpExit:
				use, fall = 1, false
			case x.IsJump() && (code == 0x00 && !isX || code >= 0x10 && code <= 0x70 || code >= 0xa0 && code <= 0xd0):
				if code != 0x00 { // conditional (RFC §4.3 Table 5): reads its operands
					use |= bit(x.Dst)
					if isX {
						use |= bit(x.Src)
					}
				} else { // ja (JMP32 ja takes imm, JumpTarget)
					fall = false
				}
				t, ok := idx[x.JumpTarget()]
				if !ok || fn[t] != fn[i] {
					use = allRegs
				} else {
					succ = append(succ, t)
				}
			default: // ld_abs/ld_ind, kfunc and indirect calls, anything else
				use = allRegs
			}
			if fall {
				if i+1 < n && fn[i+1] == fn[i] {
					succ = append(succ, i+1)
				} else {
					use = allRegs // falls off its function
				}
			}
			var out uint16
			for _, t := range succ {
				out |= in[t]
			}
			if v := use | out&^def; v != in[i] {
				in[i], changed = v, true
			}
		}
		for f, s := range starts {
			if s < n && in[s]&ArgRegs != fin[f] {
				fin[f], changed = in[s]&ArgRegs, true
			}
		}
	}
	return fin
}
