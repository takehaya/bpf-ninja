package ctxflow

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Pass says how a static function gets the program context into its own
// reserved slot: it stores Reg there on entry. If Saved, Reg is its proved
// context parameter. Otherwise every direct call to it sets Reg, an argument
// register the function never reads before writing it, to the context its
// caller keeps in its reserved slot. Start is the function's raw pc, Index its
// decoded index.
type Pass struct {
	Name  string
	Start int
	Index int
	Reg   asm.Register
	Saved bool
}

// helperArgs is the argument count of helpers 0-211, from the prototypes in
// libbpf's bpf_helper_defs.h (Linux 7.0). A helper reads only these
// registers; an unknown helper counts as reading R1-R5. bpf_trace_printk (6)
// is variadic and reads R1-R5.
const helperArgs = "0" +
	"2423050055533002131442215435333231032322103231125434424352242243254544444434141024255132244" +
	"311111155433344421553333210445113053124322221111144434233541421242020315453413231111341454" +
	"332101144533231442255333220442"

// ArgReads returns, as a bit set over R1-R5 (bit r for Rr), the argument
// registers that some path from the function starting at decoded index start
// reads before writing. A helper call reads its arguments, a kfunc call R1-R5,
// a bpf-to-bpf call what its callee reads before writing, or R1-R5 when the
// callee's BTF says it is not static: the verifier checks a global callee's
// arguments against its prototype. A call or a legacy packet load writes
// R0-R5. An atomic counts as reading R0 and its operands and writing nothing.
// It needs no other BTF, and an offline checker without function metadata
// accepts at least what it accepts here. It fails on a jump or call that does
// not resolve to an instruction.
func ArgReads(insns asm.Instructions, start int) (uint8, error) {
	pcs, index, symbols := make([]int, len(insns)), map[int]int{}, map[string]int{}
	pc := 0
	for i := range insns {
		pcs[i], index[pc] = pc, i
		if sym := insns[i].Symbol(); sym != "" {
			symbols[sym] = i
		}
		pc += int(insns[i].Size() / asm.InstructionSize)
	}
	target := func(i int) (int, error) {
		ins := &insns[i]
		if ref := ins.Reference(); ref != "" {
			if t, ok := symbols[ref]; ok {
				return t, nil
			}
			return 0, fmt.Errorf("instruction %d references unknown symbol %q", i, ref)
		}
		rel := int(ins.Offset)
		if ins.IsFunctionCall() || ins.OpCode.Class() == asm.Jump32Class && ins.OpCode.JumpOp() == asm.Ja {
			rel = int(int32(ins.Constant))
		}
		if t, ok := index[pcs[i]+1+rel]; ok {
			return t, nil
		}
		return 0, fmt.Errorf("instruction %d targets no instruction", i)
	}
	memo, busy := map[int]uint8{}, map[int]bool{}
	var reads func(int) (uint8, error)
	reads = func(start int) (uint8, error) {
		if r, ok := memo[start]; ok {
			return r, nil
		}
		if busy[start] {
			return 0, fmt.Errorf("recursive call to instruction %d", start)
		}
		busy[start] = true
		defer delete(busy, start)
		// written[i] is the set every path from start has written before i.
		written, work, out := map[int]uint8{start: 0}, []int{start}, uint8(0)
		for len(work) > 0 {
			i := work[len(work)-1]
			work = work[:len(work)-1]
			if i < 0 || i >= len(insns) {
				return 0, fmt.Errorf("control leaves the program at %d", i)
			}
			ins, w := &insns[i], written[i]
			use, def := operands(ins)
			if ins.IsFunctionCall() {
				t, err := target(i)
				if err != nil {
					return 0, err
				}
				if fn := btf.FuncMetadata(&insns[t]); fn != nil && fn.Linkage != btf.StaticFunc {
					use = 0b111110
				} else if use, err = reads(t); err != nil {
					return 0, err
				}
			}
			out |= use &^ w
			w |= def
			var succ []int
			op := ins.OpCode
			switch {
			case op.Class().IsJump() && op.JumpOp() == asm.Exit:
			case op.Class().IsJump() && op.JumpOp() != asm.Call:
				t, err := target(i)
				if err != nil {
					return 0, err
				}
				succ = append(succ, t)
				if op.JumpOp() != asm.Ja {
					succ = append(succ, i+1)
				}
			default:
				succ = append(succ, i+1)
			}
			for _, s := range succ {
				next := w
				if old, seen := written[s]; seen {
					if next &= old; next == old {
						continue
					}
				}
				written[s] = next
				work = append(work, s)
			}
		}
		memo[start] = out
		return out, nil
	}
	r, err := reads(start)
	return r &^ 1, err
}

// operands returns the registers R0-R5 an instruction reads and writes,
// reading more and writing fewer when unsure. A bpf-to-bpf call's reads come
// from its callee (see ArgReads).
func operands(ins *asm.Instruction) (use, def uint8) {
	bit := func(r asm.Register) uint8 {
		if r <= asm.R5 {
			return 1 << r
		}
		return 0
	}
	const args = 0b111110
	op := ins.OpCode
	src := op.Source() == asm.RegSource
	switch cls := op.Class(); {
	case cls.IsALU():
		switch op.ALUOp() {
		case asm.Mov:
		case asm.Neg, asm.Swap:
			src = false
			use = bit(ins.Dst)
		default:
			use = bit(ins.Dst)
		}
		if src {
			use |= bit(ins.Src)
		}
		return use, bit(ins.Dst)
	case cls == asm.LdXClass:
		return bit(ins.Src), bit(ins.Dst)
	case cls == asm.LdClass && op == asm.LoadImmOp(asm.DWord):
		return 0, bit(ins.Dst)
	case cls == asm.LdClass:
		return bit(ins.Src) | args, 0b111111
	case cls == asm.StClass:
		return bit(ins.Dst), 0
	case cls == asm.StXClass && op.Mode() == asm.MemMode:
		return bit(ins.Dst) | bit(ins.Src), 0
	case cls == asm.StXClass:
		return bit(ins.Dst) | bit(ins.Src) | 1, 0
	case op.JumpOp() == asm.Exit:
		return 1, 0
	case op.JumpOp() == asm.Call:
		use = args
		if ins.IsBuiltinCall() && ins.Constant >= 0 && ins.Constant < int64(len(helperArgs)) {
			use = uint8(1<<(helperArgs[ins.Constant]-'0'+1)-1) &^ 1
		}
		return use, 0b111111
	case op.JumpOp() == asm.Ja:
		return 0, 0
	case cls.IsJump():
		use = bit(ins.Dst)
		if src {
			use |= bit(ins.Src)
		}
		return use, 0
	}
	return 0b111111, 0
}

// FreeArg returns the highest argument register in R1-R5 not in reads, or 0.
func FreeArg(reads uint8) asm.Register {
	for r := asm.R5; r >= asm.R1; r-- {
		if reads&(1<<r) == 0 {
			return r
		}
	}
	return 0
}

// passes returns, for each function but the entry, the functions that pass the
// context down to it: itself first, then every function on a call chain from
// the entry up to one that saves its proved context parameter, each once.
// Otherwise it gives the reason the function cannot get the context passed.
func (p *flowProgram) passes(proofs map[int]Proof) (map[int][]Pass, map[int]string) {
	out, why, busy := map[int][]Pass{}, map[int]string{}, map[int]bool{}
	var resolve func(fn function) ([]Pass, string)
	resolve = func(fn function) ([]Pass, string) {
		if chain, ok := out[fn.Start]; ok {
			return chain, ""
		}
		if reason, ok := why[fn.Start]; ok {
			return nil, reason
		}
		if busy[fn.Start] {
			return nil, "ctx pass: the function is reached recursively"
		}
		busy[fn.Start] = true
		chain, reason := p.pass(fn, proofs[fn.Start].Proven, resolve)
		delete(busy, fn.Start)
		if reason != "" {
			why[fn.Start] = reason
		} else {
			out[fn.Start] = chain
		}
		return chain, reason
	}
	for _, fn := range p.funcs[1:] {
		resolve(fn)
	}
	return out, why
}

func (p *flowProgram) pass(fn function, proven bool, resolve func(function) ([]Pass, string)) ([]Pass, string) {
	switch {
	case fn.Linkage != btf.StaticFunc:
		return nil, "ctx pass: not a static function"
	case p.callback[fn.Start]:
		return nil, "ctx pass: the function is used as a callback"
	case proven:
		return []Pass{{Name: fn.Name, Start: fn.Start, Index: p.at[fn.Start], Reg: asm.R1 + asm.Register(fn.CtxParam), Saved: true}}, ""
	case len(p.callers[fn.Start]) == 0:
		return nil, "ctx pass: the function has no direct caller"
	}
	reads, err := ArgReads(p.insns, p.at[fn.Start])
	if err != nil {
		return nil, "ctx pass: " + err.Error()
	}
	reg := FreeArg(reads)
	if reg == 0 {
		return nil, "ctx pass: every argument register is read before written"
	}
	chain, seen := []Pass{{Name: fn.Name, Start: fn.Start, Index: p.at[fn.Start], Reg: reg}}, map[int]bool{fn.Start: true}
	for _, call := range p.callers[fn.Start] {
		if call.caller == 0 {
			continue
		}
		caller := p.funcs[call.caller]
		up, why := resolve(caller)
		if why != "" {
			return nil, fmt.Sprintf("ctx pass: a caller cannot pass the context (%s@%d)", caller.Name, call.pc)
		}
		for _, pass := range up {
			if !seen[pass.Start] {
				seen[pass.Start] = true
				chain = append(chain, pass)
			}
		}
	}
	return chain, ""
}
